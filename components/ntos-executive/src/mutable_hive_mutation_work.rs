//! Ordered hosted hive edits across the native WAL and paired anchor.

use crate::*;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_hive_core::{CellId, OwnedPreparedSetKeySecurity, OwnedPreparedSetValue,
    RegistryValueType, ResolvedHiveKey, SetKeySecurityError, SetValueError};
use nt_process::native_handle::NativeThreadProcessReference;
use nt_process::RegistryKeyHandlePublication;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;
use nt_thread_start::amd64_context::UserApcContinuation;

const STATUS_INVALID_HANDLE: u32 = nt_fs::STATUS_INVALID_HANDLE;

enum Phase {
    Prepare, Begin, Poll, Publish, Install, ReadyReply, ReplyEntered, ReplySent,
    RevokeReply, RetypeReply, ReconcileRuntime,
}

enum Pending {
    Value { key: CellId, path: String, name: String,
        value_type: RegistryValueType, data: Vec<u8> },
    Security { key: CellId, path: String, information: u32, modification: Vec<u8> },
}

enum Prepared {
    Value(OwnedPreparedSetValue),
    Security(OwnedPreparedSetKeySecurity),
}

impl Prepared {
    fn record(&self) -> &[u8] {
        match self {
            Self::Value(value) => value.record(), Self::Security(security) => security.record(),
        }
    }

    unsafe fn mark_entered(&mut self) {
        match self {
            Self::Value(value) => value.mark_entered(), Self::Security(security) => security.mark_entered(),
        }
    }
}

struct HostedCaller {
    tid: u64,
    badge: u64,
    reply: u64,
    logical: ProviderLogicalCaller,
    reference: NativeThreadProcessReference,
    key_owner: Option<RegistryKeyHandlePublication>,
    _continuation: UserApcContinuation,
}

struct Work {
    order: u64,
    hive: u32,
    log_path: String,
    pending: Option<Pending>,
    prepared: Option<Prepared>,
    journal_id: Option<u64>,
    receipt: Option<writable_fs::hive_wal::NativeHiveJournalReceipt>,
    installation: Option<(nt_fs::RegistryWalContinuation, nt_fs::VerifiedPairedWalSnapshot)>,
    caller: HostedCaller,
    phase: Phase,
    status: u32,
    cancelled: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static EXECUTING_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
static EXECUTING_TID: AtomicU64 = AtomicU64::new(0);
static PENDING: AtomicU64 = AtomicU64::new(0);
static NEXT_ORDER: AtomicU64 = AtomicU64::new(1);
static NEXT: AtomicU64 = AtomicU64::new(0);
static TRANSFERRED: AtomicBool = AtomicBool::new(false);
const RETRY_DELAY: u64 = 10_000_000;
const POLL_DELAY: u64 = 100_000;

fn prepare_error(error: SetValueError) -> u32 {
    match error {
        SetValueError::KeyNotFound => STATUS_INVALID_HANDLE,
        SetValueError::InsufficientResources => 0xC000_009A,
        SetValueError::RetainedPublication => 0xC000_00A3,
    }
}

fn security_error(error: SetKeySecurityError) -> u32 {
    match error {
        SetKeySecurityError::KeyNotFound => STATUS_INVALID_HANDLE,
        SetKeySecurityError::KeyMustBeDurable => 0xC000_0181,
        SetKeySecurityError::InsufficientResources => 0xC000_009A,
        SetKeySecurityError::RetainedPublication => 0xC000_00A3,
    }
}

fn release_key_owner(handler: &mut ExecNtHandler, mut owner: RegistryKeyHandlePublication) {
    if let Some(target) = owner.abort(&mut handler.pm)
        .expect("retained mutable Key release") {
        handler.release_registry_key_target(target);
    }
}

fn reserve_order() -> Result<u64, u32> {
    NEXT_ORDER.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |order|
        order.checked_add(1)).map_err(|_| 0xC000_009A)
}

/// Caller and Reply ownership transfer before queued preparation or physical WAL entry.
pub(crate) unsafe fn submit_hosted_set_value(
    handler: &mut ExecNtHandler, key_ref: KeyRef, key: ResolvedHiveKey,
    name: String, value_type: RegistryValueType, data: Vec<u8>,
) -> Result<(), u32> {
    submit_hosted_existing_edit(handler, key_ref, key,
        ExistingEdit::SetValue { name, value_type, data })
}

pub(crate) unsafe fn submit_hosted_set_security(
    handler: &mut ExecNtHandler, key_ref: KeyRef, key: ResolvedHiveKey,
    information: u32, modification: Vec<u8>,
) -> Result<(), u32> {
    submit_hosted_existing_edit(handler, key_ref, key,
        ExistingEdit::SetSecurity { information, modification })
}

enum ExistingEdit {
    SetValue { name: String, value_type: RegistryValueType, data: Vec<u8> },
    SetSecurity { information: u32, modification: Vec<u8> },
}

unsafe fn submit_hosted_existing_edit(
    handler: &mut ExecNtHandler, key_ref: KeyRef, key: ResolvedHiveKey, edit: ExistingEdit,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let path = handler.mutable_key_relative_path(key).ok_or(STATUS_INVALID_HANDLE)?;
    let pending = match edit {
        ExistingEdit::SetValue { name, value_type, data } =>
            Pending::Value { key: key.key, path, name, value_type, data },
        ExistingEdit::SetSecurity { information, modification } =>
            Pending::Security { key: key.key, path, information, modification },
    };
    let mut log_path = handler.mutable_hive_checkpoint_path_owned(key.hive)
        .ok_or(STATUS_INVALID_HANDLE)?;
    log_path.try_reserve(4).map_err(|_| 0xC000_009Au32)?;
    log_path.push_str(".LOG");
    let tcb = handler.hosted_thread_tcb(handler.current_tid).ok_or(STATUS_INVALID_HANDLE)?;
    let logical = handler.capture_provider_logical_caller(
        handler.pi, handler.current_tid, handler.current_badge, tcb,
    ).ok_or(STATUS_INVALID_HANDLE)?;
    if u64::from(logical.thread().thread_id()) != handler.current_tid {
        return Err(STATUS_INVALID_HANDLE);
    }
    let park = root_reply_park::RootReplyPark::prepare().ok_or(0xC000_009Au32)?;
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = rows.iter().enumerate().find_map(|(index, row)|
        (row.is_none() && EXECUTING_INDEX.load(Ordering::Relaxed) != index as u64)
            .then_some(index));
    if index.is_none() { rows.try_reserve(1).map_err(|_| 0xC000_009Au32)?; }
    let tid = u32::try_from(handler.current_tid).map_err(|_| STATUS_INVALID_HANDLE)?;
    let lifetime = handler.pm.thread_lifetime(tid).ok_or(STATUS_INVALID_HANDLE)?;
    let key_caller = handler.pm.capture_native_handle_caller(
        lifetime, nt_types::AccessMode::UserMode)?;
    let mut key_owner = handler.pm.reserve_native_registry_key_handle(key_caller, 0)?;
    if let Err(status) = key_owner.bind(&mut handler.pm, key_ref, 0) {
        release_key_owner(handler, key_owner);
        return Err(status);
    }
    let requestor = match handler.pm.capture_native_handle_caller(
        logical.thread(), nt_types::AccessMode::KernelMode) {
        Ok(requestor) => requestor,
        Err(status) => {
            release_key_owner(handler, key_owner);
            return Err(status);
        }
    };
    let mut reference = match handler.pm.reference_native_requestor(requestor) {
        Ok(reference) => reference,
        Err(status) => {
            release_key_owner(handler, key_owner);
            return Err(status);
        }
    };
    let order = match reserve_order() {
        Ok(order) => order,
        Err(status) => {
            reference.release(&mut handler.pm).expect("unsubmitted mutable caller");
            release_key_owner(handler, key_owner);
            return Err(status);
        }
    };
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(reply, 0);
    let work = Work {
        order, hive: key.hive, log_path,
        pending: Some(pending),
        prepared: None, journal_id: None, receipt: None,
        installation: None,
        caller: HostedCaller {
            tid: handler.current_tid, badge: handler.current_badge, reply, logical,
            reference, key_owner: Some(key_owner),
            _continuation: if handler.current_native_call_transport {
                UserApcContinuation::NativeCall
            } else {
                UserApcContinuation::Fault {
                    resume_ip: handler.current_resume_ip,
                    resume_sp: handler.current_sp,
                    resume_flags: handler.current_flags,
                }
            },
        },
        phase: Phase::Prepare, status: 0, cancelled: false,
    };
    match index { Some(index) => rows[index] = Some(work), None => rows.push(Some(work)) }
    park.commit();
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

pub(crate) fn take_transferred() -> bool { TRANSFERRED.swap(false, Ordering::AcqRel) }
pub(crate) fn next_deadline() -> Option<u64> {
    (PENDING.load(Ordering::Acquire) != 0).then(|| NEXT.load(Ordering::Acquire))
}
pub(crate) fn has_thread(tid: u64) -> bool {
    EXECUTING_TID.load(Ordering::Acquire) == tid || unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten()
        .any(|work| !matches!(work.phase, Phase::ReconcileRuntime)
            && work.caller.tid == tid) }
}

/// Called only when the exact HiveTicket's native WAL command physically entered.
pub(crate) unsafe fn mark_prepared_entered(journal_id: u64) -> Result<(), u32> {
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let work = rows.iter_mut().flatten().find(|work| work.journal_id == Some(journal_id))
        .ok_or(STATUS_INVALID_HANDLE)?;
    let prepared = work.prepared.as_mut().ok_or(STATUS_INVALID_HANDLE)?;
    prepared.mark_entered();
    Ok(())
}

unsafe fn release_pre_entry(handler: &mut ExecNtHandler, work: &mut Work, status: u32)
    -> Result<(), u32>
{
    if let Some(id) = work.journal_id {
        if writable_fs::hive_wal::native_hive_journal_has_entered_wal(id) {
            return Err(status);
        }
        writable_fs::hive_wal::abort_unentered_native_hive_journal(id)?;
    }
    if let Some(prepared) = work.prepared.take() {
        match prepared {
            Prepared::Value(prepared) => {
                if let Err((_, prepared)) = handler.mutable_hives.release_unentered_owned_set_value(prepared) {
                    work.prepared = Some(Prepared::Value(prepared));
                    return Err(status);
                }
            }
            Prepared::Security(prepared) => {
                if let Err((_, prepared)) = handler.mutable_hives.release_unentered_owned_set_key_security(prepared) {
                    work.prepared = Some(Prepared::Security(prepared));
                    return Err(status);
                }
            }
        }
    }
    work.status = status;
    work.phase = Phase::ReadyReply;
    Ok(())
}

unsafe fn caller_cancelled(handler: &ExecNtHandler, caller: &HostedCaller) -> bool {
    spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(caller.reply)
        || handler.pm.thread(caller.logical.thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler.pm.process(caller.logical.process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
        || !handler.validate_provider_logical_caller(caller.logical)
}

unsafe fn advance(
    handler: &mut ExecNtHandler, queue: &mut nt_delay_execution::Queue, work: &mut Work,
    earlier_unpublished: bool,
) -> Result<bool, u32> {
    work.cancelled |= caller_cancelled(handler, &work.caller);
    match work.phase {
        Phase::Prepare => {
            if work.cancelled {
                work.status = 0xC000_0120;
                work.pending.take();
                work.phase = Phase::ReadyReply;
            } else if !earlier_unpublished
                && !handler.mutable_hives.has_retained_publication(work.hive) {
                let pending = work.pending.take().expect("unprepared mutable edit");
                let prepared = match pending {
                    Pending::Value { key, path, name, value_type, data } =>
                        handler.mutable_hives.prepare_owned_set_value(
                            work.hive, key, &path, &name, value_type, data,
                        ).map(Prepared::Value).map_err(prepare_error),
                    Pending::Security { key, path, information, modification } => (|| {
                        let current = handler.mutable_registry_key_security_descriptor(
                            ResolvedHiveKey { hive: work.hive, key },
                        ).unwrap_or_else(|| Vec::from(&nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR[..]));
                        let descriptor = nt_security::set_security_descriptor_bytes(
                            &current, information, &modification,
                        )?;
                        handler.mutable_hives.prepare_owned_set_key_security(
                            work.hive, key, &path, descriptor,
                        ).map(Prepared::Security).map_err(security_error)
                    })(),
                };
                match prepared {
                    Ok(prepared) => { work.prepared = Some(prepared); work.phase = Phase::Begin; }
                    Err(status) => { work.status = status; work.phase = Phase::ReadyReply; }
                }
            }
        }
        Phase::Begin => {
            if work.cancelled {
                release_pre_entry(handler, work, 0xC000_0120)?;
                return Ok(false);
            }
            match writable_fs::hive_wal::begin_native_hive_journal(
                &work.log_path, work.prepared.as_ref().unwrap().record(),
            ) {
                Ok(id) => { work.journal_id = Some(id); work.phase = Phase::Poll; },
                Err(status) if writable_fs::native_snapshot_io::admission_busy(status) => {},
                Err(status) => { release_pre_entry(handler, work, status)?; },
            }
        }
        Phase::Poll => {
            let id = work.journal_id.expect("retained hive journal");
            match writable_fs::hive_wal::poll_native_hive_journal(id) {
                Ok(Some(receipt)) => { work.receipt = Some(receipt); work.phase = Phase::Publish; },
                Ok(None) => {},
                Err(status) => { release_pre_entry(handler, work, status)?; },
            }
        }
        Phase::Publish => {
            let receipt = work.receipt.take().expect("anchored hive receipt");
            let prepared = work.prepared.take().expect("retained hive edit");
            let (continuation, pair) = match prepared {
                Prepared::Value(prepared) => match nt_fs::publish_anchored_hive_value(
                    &mut handler.mutable_hives, prepared, receipt.anchored,
                    receipt.file_id, receipt.expected_log_len, &receipt.log_path,
                ) {
                    Ok((_, continuation, pair)) => (continuation, pair),
                    Err((_, prepared, anchored)) => {
                        work.prepared = Some(Prepared::Value(prepared));
                        work.receipt = Some(writable_fs::hive_wal::NativeHiveJournalReceipt {
                            anchored, ..receipt
                        });
                        return Err(0xC000_003Eu32);
                    }
                },
                Prepared::Security(prepared) => match nt_fs::publish_anchored_hive_security(
                    &mut handler.mutable_hives, prepared, receipt.anchored,
                    receipt.file_id, receipt.expected_log_len, &receipt.log_path,
                ) {
                    Ok((continuation, pair)) => (continuation, pair),
                    Err((_, prepared, anchored)) => {
                        work.prepared = Some(Prepared::Security(prepared));
                        work.receipt = Some(writable_fs::hive_wal::NativeHiveJournalReceipt {
                            anchored, ..receipt
                        });
                        return Err(0xC000_003Eu32);
                    }
                },
            };
            work.installation = Some((continuation, pair));
            work.phase = Phase::Install;
        }
        Phase::Install => {
            let (continuation, pair) = work.installation.take()
                .expect("retained hive continuation and paired proof");
            match writable_fs::hive_wal::install_native_hive_publication(
                work.journal_id.expect("retained hive journal"), continuation, pair,
            ) {
                Ok(()) => {
                    handler.note_mutable_hive_journal_record(work.hive);
                    work.status = 0;
                    work.phase = Phase::ReadyReply;
                }
                Err((status, continuation, pair)) => {
                    work.installation = Some((continuation, pair));
                    return Err(status);
                }
            }
        }
        Phase::ReadyReply => {
            if work.cancelled {
                work.phase = Phase::RevokeReply;
                return Ok(false);
            }
            parked_reply::validate_saved(work.caller.reply).map_err(|status| status as u32)?;
            work.phase = Phase::ReplyEntered;
            if !crate::service_sec_image::complete_mutable_hive_mutation_reply(
                handler, work.caller.tid, work.caller.reply, work.status,
            ) { return Err(0xC000_00A3); }
            work.phase = Phase::ReplySent;
        }
        Phase::ReplyEntered => {
            if spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                work.caller.reply,
            ).map_err(|_| 0xC000_00A3u32)? {
                work.phase = Phase::ReplySent;
            } else if work.cancelled {
                work.phase = Phase::RevokeReply;
            } else { return Err(0xC000_00A3); }
        }
        Phase::ReplySent => {
            parked_reply::retire_sent(work.caller.reply).map_err(|status| status as u32)?;
            if work.cancelled {
                work.phase = Phase::ReconcileRuntime;
                return Ok(false);
            }
            if let Some(owner) = work.caller.key_owner.take() { release_key_owner(handler, owner); }
            thread_wait_state_clear_badge_ready(handler, work.caller.badge);
            work.caller.reference.release(&mut handler.pm)
                .expect("retained mutable caller reference");
            return Ok(true);
        }
        Phase::RevokeReply => {
            if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.caller.reply) {
                parked_reply::revoke(work.caller.reply).map_err(|status| status as u32)?;
            }
            work.phase = Phase::RetypeReply;
        }
        Phase::RetypeReply => {
            parked_reply::retype(work.caller.reply).map_err(|status| status as u32)?;
            work.phase = Phase::ReconcileRuntime;
        }
        Phase::ReconcileRuntime => {
            if !hosted_termination::reconcile(handler, queue, work.caller.logical) {
                return Err(0xC000_00A3);
            }
            if let Some(owner) = work.caller.key_owner.take() { release_key_owner(handler, owner); }
            work.caller.reference.release(&mut handler.pm)
                .expect("retired mutable caller reference");
            return Ok(true);
        }
    }
    Ok(false)
}

fn blocks_later_preparation(phase: &Phase) -> bool {
    matches!(phase, Phase::Prepare | Phase::Begin | Phase::Poll |
        Phase::Publish | Phase::Install)
}

/// Advance only at the outer service loop. No nested provider pump owns this Reply.
pub(crate) unsafe fn redrive(
    handler: &mut ExecNtHandler, queue: &mut nt_delay_execution::Queue,
) {
    if PENDING.load(Ordering::Acquire) == 0
        || monotonic_time_100ns() < NEXT.load(Ordering::Acquire)
        || ACTIVE.swap(true, Ordering::AcqRel) { return; }
    let mut failed = false;
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    for index in 0..rows.len() {
        let Some(mut work) = rows[index].take() else { continue; };
        EXECUTING_INDEX.store(index as u64, Ordering::Relaxed);
        let mut completed = false;
        for _ in 0..8 {
            let earlier_unpublished = rows.iter().flatten().any(|other|
                other.hive == work.hive && other.order < work.order
                    && blocks_later_preparation(&other.phase));
            EXECUTING_TID.store(if matches!(work.phase, Phase::ReconcileRuntime) {
                0
            } else {
                work.caller.tid
            }, Ordering::Release);
            match advance(handler, queue, &mut work, earlier_unpublished) {
                Ok(true) => { completed = true; break; },
                Ok(false) => {},
                Err(_) => { failed = true; break; },
            }
        }
        if completed { PENDING.fetch_sub(1, Ordering::Release); }
        else { rows[index] = Some(work); }
        EXECUTING_INDEX.store(u64::MAX, Ordering::Relaxed);
        EXECUTING_TID.store(0, Ordering::Release);
    }
    NEXT.store(monotonic_time_100ns().saturating_add(if failed { RETRY_DELAY } else { POLL_DELAY }),
        Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
}
