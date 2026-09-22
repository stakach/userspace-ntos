//! Native ownership of a hosted SYSTEM create from before BEGIN through exact terminal ACK.

use crate::*;
use alloc::string::String;
use crate::exec_handler::registry_admission::HostedRegistryPublication;
use nt_config_client::*;
use nt_process::RegistryKeyHandlePublication;
use nt_process::native_handle::NativeThreadProcessReference;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;
use nt_thread_start::amd64_context::UserApcContinuation;

struct Caller {
    publication: HostedRegistryPublication,
    parent_owner: RegistryKeyHandlePublication,
    parent: KeyRef,
    leaf: String,
    grant: u32,
    pi: usize,
    tid: u64,
    badge: u64,
    reply: u64,
    logical: ProviderLogicalCaller,
    reference: NativeThreadProcessReference,
    _continuation: UserApcContinuation,
}

enum Phase {
    Begin(CmMutationBeginAttempt<()>),
    Prepare(SystemHiveMutationPreparation<()>),
    Admit,
    Durable,
    Commit,
    Open,
    Acknowledge,
    Abort,
    AcknowledgeAbort(SystemHiveMutationAbortReceipt),
    Complete,
    ReplyEntered,
}

struct Work {
    caller: Caller,
    phase: Phase,
    prepared: Option<PreparedSystemHiveMutation>,
    journal: Option<writable_fs::registry_journal::Journal<()>>,
    receipt: Option<SystemHiveMutationCommitReceipt>,
    opening: Option<cm_key_ownership::PublicationOpen>,
    status: u32,
}

static mut ATTEMPTS: CmMutationBeginAttempts = CmMutationBeginAttempts::new();
static mut WORK: Vec<Option<Work>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicU64 = AtomicU64::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);
static CURSOR: AtomicU64 = AtomicU64::new(0);
static TRANSFERRED: AtomicBool = AtomicBool::new(false);
static mut EXECUTING: Option<ProviderLogicalCaller> = None;
const RETRY_DELAY: u64 = 10_000_000;

/// Failure returns both canonical owners unchanged; no CM mutation has been sent.
pub(crate) unsafe fn submit_hosted(
    handler: &mut ExecNtHandler,
    publication: HostedRegistryPublication,
    parent_owner: RegistryKeyHandlePublication,
    parent: KeyRef,
    leaf: String,
    grant: u32,
    expected_generation: u64,
    mutation: SystemHiveMutation<'_>,
) -> Result<(), (u32, HostedRegistryPublication, RegistryKeyHandlePublication)> {
    let _durable = allocator::enter_durable();
    let admission = (|| {
        let tcb = handler.hosted_thread_tcb(handler.current_tid).ok_or(0xC000_0008u32)?;
        let logical = handler.capture_provider_logical_caller(
            handler.pi, handler.current_tid, handler.current_badge, tcb,
        ).ok_or(0xC000_0008u32)?;
        let mount = LIVE_CONFIG_MANAGER_SYSTEM_MOUNT.ok_or(0xC000_00A3u32)?;
        let park = root_reply_park::RootReplyPark::prepare().ok_or(0xC000_009Au32)?;
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        rows.try_reserve(1).map_err(|_| 0xC000_009Au32)?;
        let mut reference = handler.pm.reference_native_requestor(publication.subject.caller())?;
        let attempt = match (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
            .reserve(mount, expected_generation, &[mutation], ())
        {
            Ok(attempt) => attempt,
            Err((status, ())) => {
                reference.release(&mut handler.pm).expect("unsubmitted registry caller");
                return Err(status as u32);
            }
        };
        Ok((park, attempt, logical, reference))
    })();
    let (park, attempt, logical, reference) = match admission {
        Ok(admission) => admission,
        Err(status) => return Err((status, publication, parent_owner)),
    };
    let caller = Caller {
        publication, parent_owner, parent, leaf, grant,
        pi: handler.pi,
        tid: handler.current_tid,
        badge: handler.current_badge,
        reply: REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        logical,
        reference,
        _continuation: if handler.current_native_call_transport {
            UserApcContinuation::NativeCall
        } else {
            UserApcContinuation::Fault {
                resume_ip: handler.current_resume_ip,
                resume_sp: handler.current_sp,
                resume_flags: handler.current_flags,
            }
        },
    };
    assert_ne!(caller.reply, 0);
    (&mut *core::ptr::addr_of_mut!(WORK)).push(Some(Work {
        caller, phase: Phase::Begin(attempt), prepared: None, journal: None,
        receipt: None, opening: None, status: 0,
    }));
    // The row owns the live Reply before ingress can select a replacement.
    park.commit();
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

pub(crate) fn take_transferred() -> bool {
    TRANSFERRED.swap(false, Ordering::AcqRel)
}

pub(crate) fn has_thread(tid: u64) -> bool {
    has_matching(|caller| u64::from(caller.thread().thread_id()) == tid)
}

pub(crate) fn has_process(pi: usize, preserve_tid: Option<u64>) -> bool {
    has_matching(|caller| caller.pi() == pi
        && preserve_tid != Some(u64::from(caller.thread().thread_id())))
}

fn has_matching(predicate: impl Fn(ProviderLogicalCaller) -> bool) -> bool {
    unsafe {
        (*core::ptr::addr_of!(EXECUTING)).is_some_and(&predicate)
            || (&*core::ptr::addr_of!(WORK)).iter().flatten()
                .any(|work| predicate(work.caller.logical))
    }
}

pub(crate) fn next_deadline() -> Option<u64> {
    (PENDING.load(Ordering::Acquire) != 0).then(|| NEXT.load(Ordering::Acquire))
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

/// Top-level only. The selected owner is moved, never borrowed, across component IPC.
pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    if PENDING.load(Ordering::Acquire) == 0
        || monotonic_time_100ns() < NEXT.load(Ordering::Acquire)
        || ACTIVE.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let _durable = allocator::enter_durable();
    let mut failed = false;
    let selected = {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let count = rows.len();
        let start = CURSOR.load(Ordering::Relaxed) as usize % count;
        (0..count).find_map(|step| {
            let index = (start + step) % count;
            rows[index].take().map(|work| (index, work))
        })
    };
    if let Some((index, mut work)) = selected {
        CURSOR.store(index as u64 + 1, Ordering::Relaxed);
        *core::ptr::addr_of_mut!(EXECUTING) = Some(work.caller.logical);
        let mut completed = false;
        // Bound each sweep; long journals resume fairly on the next maintenance tick.
        for _ in 0..16 {
            match advance(handler, &mut work) {
                Ok(true) => { completed = true; break; }
                Ok(false) => {}
                Err(_) => { failed = true; break; }
            }
        }
        if completed {
            PENDING.fetch_sub(1, Ordering::Release);
        } else {
            (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        }
        *core::ptr::addr_of_mut!(EXECUTING) = None;
    }
    NEXT.store(monotonic_time_100ns().saturating_add(if failed { RETRY_DELAY } else { 0 }), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
}

unsafe fn advance(handler: &mut ExecNtHandler, work: &mut Work) -> Result<bool, i32> {
    match &mut work.phase {
        Phase::Begin(attempt) => {
            let attempts = &mut *core::ptr::addr_of_mut!(ATTEMPTS);
            if attempt.is_acknowledged() {
                if attempt.outcome_status() == Some(0) {
                    work.phase = Phase::Prepare(attempts.take_upload(attempt)?.into_preparation());
                } else {
                    let (status, ()) = attempts.take_failure(attempt)?;
                    work.status = status as u32;
                    work.phase = Phase::Complete;
                }
                return Ok(false);
            }
            let op = if attempt.server_nonce().is_none() {
                CmMutationBeginOperation::Query
            } else if attempt.outcome_status().is_none() {
                CmMutationBeginOperation::Begin
            } else {
                CmMutationBeginOperation::Acknowledge
            };
            let mut exchange = attempts.begin_exchange(attempt, op)?;
            let response = cm_mutation_transport::begin(&exchange);
            (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
                .complete_exchange(attempt, &mut exchange, response)?;
        }
        Phase::Prepare(preparation) => {
            use CmMutationPreparationPhase as P;
            if preparation.phase() == P::Prepared {
                let (prepared, ()) = preparation.take_prepared()?;
                work.prepared = Some(prepared);
                work.phase = Phase::Admit;
                return Ok(false);
            }
            if preparation.phase() == P::Cancelled {
                preparation.take_cancelled()?;
                work.phase = Phase::Complete;
                return Ok(false);
            }
            if preparation.phase() == P::Allocating && work.status == 0 {
                if let Err(status) = preparation.allocate_journal() {
                    work.status = status as u32;
                }
                return Ok(false);
            }
            let op = match preparation.phase() {
                P::AcknowledgingCancellation => CmMutationPreparationOperation::AcknowledgeCancellation,
                _ if work.status != 0 => CmMutationPreparationOperation::Cancel,
                P::Appending => CmMutationPreparationOperation::Append,
                P::Preparing => CmMutationPreparationOperation::Prepare,
                P::Pulling => CmMutationPreparationOperation::Pull,
                _ => unreachable!("registry preparation phase"),
            };
            let mut exchange = preparation.begin_exchange(op)?;
            let response = cm_mutation_transport::prepare(&exchange);
            if let Err(status) = preparation.complete_exchange(&mut exchange, response) {
                // Before COMMIT an acknowledged cancellation is safe even after a lost PREPARE.
                if work.status == 0 { work.status = status as u32; }
                return Err(status);
            }
        }
        Phase::Admit => {
            let prepared = work.prepared.as_ref().unwrap();
            if let Err(status) = cm_mutation_transport::validate_storage(prepared) {
                work.status = status as u32;
                work.phase = Phase::Abort;
                return Ok(false);
            }
            if prepared.durable_journal().is_empty() {
                work.phase = Phase::Commit;
            } else {
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(prepared.durable_journal().len())
                    .map_err(|_| 0xC000_009Au32 as i32)?;
                bytes.extend_from_slice(prepared.durable_journal());
                match writable_fs::registry_journal::Journal::admit(bytes, ()) {
                    Ok(journal) => { work.journal = Some(journal); work.phase = Phase::Durable; }
                    Err((status, _, ())) => return Err(status as i32),
                }
            }
        }
        Phase::Durable => {
            let journal = work.journal.as_mut().unwrap();
            journal.make_durable().map_err(|status| status as i32)?;
            journal.begin_publication().map_err(|status| status as i32)?;
            work.phase = Phase::Commit;
        }
        Phase::Commit => {
            let receipt = cm_mutation_transport::commit(work.prepared.as_ref().unwrap())?;
            let outcome = receipt.outcome();
            LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.fetch_max(outcome.generation, Ordering::AcqRel);
            if outcome.has_pending_device_action {
                CONFIG_DEVICE_ACTION_PENDING.store(true, Ordering::Release);
            }
            work.receipt = Some(receipt);
            work.phase = Phase::Open;
        }
        Phase::Open => {
            if work.opening.is_none() {
                let parent = handler.cm_system_key_target(work.caller.parent)
                    .expect("retained SYSTEM parent disappeared");
                work.opening = Some(cm_key_ownership::reserve_publication_open(parent.lease, &work.caller.leaf)?);
            }
            let Some(opened) = cm_key_ownership::resume_publication_open(work.opening.as_ref().unwrap())? else {
                return Ok(false);
            };
            work.opening = None;
            let result = match opened {
                Ok(opened) => match handler.install_cm_system_key_target(CmSystemKeyTarget {
                    lease: opened.lease,
                    physical_path: nt_hive_core::canon_path(&opened.physical_path),
                }) {
                    Ok(target) => {
                        if !handler.validate_provider_logical_caller(work.caller.logical) {
                            handler.release_registry_key_target(target);
                            work.status = 0xC000_004B;
                            work.phase = Phase::Acknowledge;
                            return Ok(false);
                        }
                        let saved_pi = handler.pi;
                        handler.pi = work.caller.pi;
                        let result = handler.finish_hosted_registry_publication(
                            &mut work.caller.publication, target, work.caller.grant, true,
                        );
                        handler.pi = saved_pi;
                        result
                    }
                    Err(status) => {
                        let _ = config_manager_retire_system_hive_key(opened.lease);
                        Err(status)
                    }
                },
                Err(status) => Err(status as u32),
            };
            work.status = result.err().unwrap_or(0);
            work.phase = Phase::Acknowledge;
        }
        Phase::Acknowledge => {
            cm_mutation_transport::acknowledge(work.receipt.unwrap())?;
            if let Some(journal) = work.journal.take() {
                match journal.release_after_publication() {
                    Ok(()) => {}
                    Err(journal) => {
                        work.journal = Some(journal);
                        return Err(0xC000_000Du32 as i32);
                    }
                }
            }
            work.phase = Phase::Complete;
        }
        Phase::Abort => {
            let receipt = cm_mutation_transport::abort(work.prepared.as_ref().unwrap())?;
            work.phase = Phase::AcknowledgeAbort(receipt);
        }
        Phase::AcknowledgeAbort(receipt) => {
            cm_mutation_transport::acknowledge_abort(*receipt)?;
            work.phase = Phase::Complete;
        }
        Phase::Complete => {
            if work.status != 0 {
                handler.abort_hosted_registry_publication(&mut work.caller.publication);
            }
            if let Some(target) = work.caller.parent_owner.abort(&mut handler.pm)
                .expect("retained registry create parent") {
                handler.release_registry_key_target(target);
            }
            // An uncertain send cannot repeat cleanup or issue a second reply to this owner.
            work.phase = Phase::ReplyEntered;
            let delivered = crate::service_sec_image::complete_registry_mutation_reply(
                handler, work.caller.tid, work.caller.badge, work.caller.reply, work.status,
            );
            if !delivered { return Err(0xC000_00A3u32 as i32); }
            work.caller.reference.release(&mut handler.pm).expect("registry caller reference");
            return Ok(true);
        }
        Phase::ReplyEntered => return Err(0xC000_00A3u32 as i32),
    }
    Ok(false)
}
