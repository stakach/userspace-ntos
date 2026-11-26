//! Ordered hosted hive edits across the native WAL and paired anchor, and the hosted registry
//! requests that wait here for their data to become durable.

use crate::*;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_hive_core::{CellId, CreateChildError, DeleteKeyEditError, DeleteValueEditError,
    RegistryValueType, ResolvedHiveKey, SetKeySecurityError, SetValueError};
use crate::mutable_hive_prepared_edit::{AnchoredRecord, PreparedEdit as Prepared};
use nt_process::native_handle::NativeThreadProcessReference;
use nt_process::RegistryKeyHandlePublication;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;
use nt_thread_start::amd64_context::UserApcContinuation;
use crate::exec_handler::registry_admission::HostedRegistryPublication;
use crate::exec_handler::registry_durability::DurableRegistryRequest;
use crate::volume_checkpoint_deferral::{CallerStep, Deferral, Outcome, STATUS_DEVICE_BUSY};

const STATUS_INVALID_HANDLE: u32 = nt_fs::STATUS_INVALID_HANDLE;

enum Phase {
    Prepare, Begin, Poll, Publish, Install, PublishChild, OpenExistingChild,
    /// A durability request whose last attempt was in flight.
    Durable,
    /// A synchronous `NtNotifyChangeKey` caller whose request has not completed.
    Notify,
    ReadyReply, ReplyEntered, ReplySent,
    RevokeReply, RetypeReply, ReconcileRuntime,
}

enum Pending {
    Value { key: CellId, path: String, name: String,
        value_type: RegistryValueType, data: Vec<u8> },
    Child { parent: CellId, path: String, name: String,
        class: Option<String>, descriptor: Vec<u8>, kind: nt_hive_core::KeyKind },
    Security { key: CellId, path: String, information: u32, modification: Vec<u8> },
    DeleteValue { key: CellId, path: String, name: String },
    DeleteKey { key: CellId, path: String },
}

enum Completion {
    /// An edit of an existing key keeps the caller's handle to it until the reply.
    ExistingKey { key_owner: RegistryKeyHandlePublication },
    CreateChild {
        publication: HostedRegistryPublication,
        parent_owner: RegistryKeyHandlePublication,
        parent_key: ResolvedHiveKey,
        child: Option<CellId>,
        grant: u32,
        backup: bool,
        published: bool,
    },
    /// `NtFlushKey`, `NtSaveKey*` or `NtUnloadKey*` kept until its data is durable.
    Durable {
        request: DurableRegistryRequest,
        deferral: Deferral<writable_fs::ReserveProgress>,
    },
    /// A synchronous `NtNotifyChangeKey` kept until its posted request completes.
    ChangeNotify { post: nt_config_notify::PostId },
}

struct HostedCaller {
    pi: usize,
    tid: u64,
    badge: u64,
    reply: u64,
    logical: ProviderLogicalCaller,
    reference: NativeThreadProcessReference,
    completion: Option<Completion>,
    _continuation: UserApcContinuation,
}

#[path = "mutable_hive_provider_caller.rs"]
mod provider;
pub(crate) use provider::{provider_edit_admission, submit_provider_edit, ProviderEditAdmission,
    PROVIDER_EDIT_NOT_READY};

/// Who waits for the edit: a hosted thread with its parked Reply, or a kernel provider (a
/// driver or win32k) with its parked service lane.
enum Caller {
    Hosted(HostedCaller),
    Provider(provider::ProviderCaller),
}

impl Caller {
    /// Hosted-only phases (Reply, durability, notify, child publication) never see a provider.
    fn hosted(&mut self) -> &mut HostedCaller {
        match self {
            Self::Hosted(caller) => caller,
            Self::Provider(_) => unreachable!("provider edit in a hosted-only phase"),
        }
    }

    fn hosted_tid(&self) -> u64 {
        match self { Self::Hosted(caller) => caller.tid, Self::Provider(_) => 0 }
    }

    fn creates_child(&self) -> bool {
        matches!(self, Self::Hosted(HostedCaller {
            completion: Some(Completion::CreateChild { .. }), .. }))
    }
}

/// What a published edit of an existing key changed, for registry change notification.
enum Reported {
    Values(CellId),
    Security(CellId),
    /// The deleted key's namespace name; the name is gone once the key is.
    KeyDeleted(String),
}

struct Work {
    order: u64,
    hive: u32,
    reported: Option<Reported>,
    log_path: String,
    pending: Option<Pending>,
    prepared: Option<Prepared>,
    journal_id: Option<u64>,
    receipt: Option<writable_fs::hive_wal::NativeHiveJournalReceipt>,
    installation: Option<(nt_fs::RegistryWalContinuation, nt_fs::VerifiedPairedWalSnapshot)>,
    caller: Caller,
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
static HIVE_COMPLETION: nt_config_client::mutation_retry_schedule::MutableHiveCompletionHint =
    nt_config_client::mutation_retry_schedule::MutableHiveCompletionHint::new();
static TRANSFERRED: AtomicBool = AtomicBool::new(false);
static DURABLE_TRACED: AtomicU64 = AtomicU64::new(0);
/// Rows parked in `Phase::Notify`. They wait for a registry change, not for time, so they
/// arm no deadline until `NOTIFY_READY` says one of them has a status to collect.
static NOTIFY_WAITING: AtomicU64 = AtomicU64::new(0);
static NOTIFY_READY: AtomicBool = AtomicBool::new(false);
/// Durability requests traced when they park and when they complete.
const DURABLE_TRACE_LIMIT: u64 = 32;
/// A durability request edits no hive, so it has no place in a hive's edit order.
const NO_HIVE: u32 = u32::MAX;
const RETRY_DELAY: u64 = 10_000_000;
const POLL_DELAY: u64 = 100_000;

fn prepare_error(error: SetValueError) -> u32 {
    match error {
        SetValueError::KeyNotFound => STATUS_INVALID_HANDLE,
        SetValueError::InsufficientResources => 0xC000_009A,
        SetValueError::RetainedPublication => 0xC000_00A3,
    }
}

fn create_error(error: CreateChildError) -> u32 {
    match error {
        CreateChildError::InvalidName => 0xC000_0033,
        CreateChildError::ParentNotFound => STATUS_INVALID_HANDLE,
        CreateChildError::NameCollision => 0xC000_0035,
        CreateChildError::EmptySecurityDescriptor => 0xC000_0079,
        CreateChildError::ChildMustBeVolatile => 0xC000_0181,
        CreateChildError::ParentIsSymbolicLink => 0xC000_0022,
        CreateChildError::InsufficientResources => 0xC000_009A,
        CreateChildError::RetainedPublication => 0xC000_00A3,
    }
}

const STATUS_KEY_DELETED: u32 = 0xC000_017C;

pub(crate) fn delete_value_error(error: DeleteValueEditError) -> u32 {
    match error {
        DeleteValueEditError::KeyNotFound => STATUS_KEY_DELETED,
        DeleteValueEditError::ValueNotFound => 0xC000_0034,
        DeleteValueEditError::KeyMustBeDurable => 0xC000_0181,
        DeleteValueEditError::InsufficientResources => 0xC000_009A,
        DeleteValueEditError::RetainedPublication => 0xC000_00A3,
    }
}

pub(crate) fn delete_key_error(error: DeleteKeyEditError) -> u32 {
    match error {
        DeleteKeyEditError::NotFound => STATUS_KEY_DELETED,
        DeleteKeyEditError::CannotDelete => 0xC000_0121,
        DeleteKeyEditError::KeyMustBeDurable => 0xC000_0181,
        DeleteKeyEditError::InsufficientResources => 0xC000_009A,
        DeleteKeyEditError::RetainedPublication => 0xC000_00A3,
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
    NEXT_ORDER.try_update(Ordering::Relaxed, Ordering::Relaxed, |order|
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

/// `NtDeleteValueKey`: the value stays visible until its exact record is anchored (#422).
pub(crate) unsafe fn submit_hosted_delete_value(
    handler: &mut ExecNtHandler, key_ref: KeyRef, key: ResolvedHiveKey, name: String,
) -> Result<(), u32> {
    submit_hosted_existing_edit(handler, key_ref, key, ExistingEdit::DeleteValue { name })
}

/// `NtDeleteKey` of a leaf: the key stays visible until its exact record is anchored (#422).
pub(crate) unsafe fn submit_hosted_delete_key(
    handler: &mut ExecNtHandler, key_ref: KeyRef, key: ResolvedHiveKey,
) -> Result<(), u32> {
    submit_hosted_existing_edit(handler, key_ref, key, ExistingEdit::DeleteKey)
}

enum ExistingEdit {
    SetValue { name: String, value_type: RegistryValueType, data: Vec<u8> },
    SetSecurity { information: u32, modification: Vec<u8> },
    DeleteValue { name: String },
    DeleteKey,
}

/// The queued edit of an existing Key and the log its record is anchored for.
fn pending_existing_edit(handler: &ExecNtHandler, key: ResolvedHiveKey, edit: ExistingEdit)
    -> Result<(Pending, String), u32>
{
    let path = handler.mutable_key_relative_path(key).ok_or(STATUS_INVALID_HANDLE)?;
    let pending = match edit {
        ExistingEdit::SetValue { name, value_type, data } =>
            Pending::Value { key: key.key, path, name, value_type, data },
        ExistingEdit::SetSecurity { information, modification } =>
            Pending::Security { key: key.key, path, information, modification },
        ExistingEdit::DeleteValue { name } => Pending::DeleteValue { key: key.key, path, name },
        ExistingEdit::DeleteKey => Pending::DeleteKey { key: key.key, path },
    };
    let mut log_path = handler.mutable_hive_checkpoint_path_owned(key.hive)
        .ok_or(STATUS_INVALID_HANDLE)?;
    log_path.try_reserve(4).map_err(|_| 0xC000_009Au32)?;
    log_path.push_str(".LOG");
    Ok((pending, log_path))
}

unsafe fn submit_hosted_existing_edit(
    handler: &mut ExecNtHandler, key_ref: KeyRef, key: ResolvedHiveKey, edit: ExistingEdit,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
    let (pending, log_path) = pending_existing_edit(handler, key, edit)?;
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
        order, hive: key.hive, reported: None, log_path,
        pending: Some(pending),
        prepared: None, journal_id: None, receipt: None,
        installation: None,
        caller: Caller::Hosted(HostedCaller {
            pi: handler.pi,
            tid: handler.current_tid, badge: handler.current_badge, reply, logical,
            reference, completion: Some(Completion::ExistingKey { key_owner }),
            _continuation: if handler.current_native_call_transport {
                UserApcContinuation::NativeCall
            } else {
                UserApcContinuation::Fault {
                    resume_ip: handler.current_resume_ip,
                    resume_sp: handler.current_sp,
                    resume_flags: handler.current_flags,
                }
            },
        }),
        phase: Phase::Prepare, status: 0, cancelled: false,
    };
    match index { Some(index) => rows[index] = Some(work), None => rows.push(Some(work)) }
    park.commit();
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

/// Keep a hosted caller whose durability request is in flight. The request, the caller and its
/// Reply move together; a refusal returns the request untouched and leaves the Reply current.
pub(crate) unsafe fn submit_hosted_durability(
    handler: &mut ExecNtHandler, request: DurableRegistryRequest,
) -> Result<(), (u32, DurableRegistryRequest)> {
    let _durable = allocator::enter_durable();
    let admission = (|| {
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
        let requestor = handler.pm.capture_native_handle_caller(
            logical.thread(), nt_types::AccessMode::KernelMode)?;
        let mut reference = handler.pm.reference_native_requestor(requestor)?;
        let order = match reserve_order() {
            Ok(order) => order,
            Err(status) => {
                reference.release(&mut handler.pm).expect("unsubmitted durability caller");
                return Err(status);
            }
        };
        Ok((park, index, logical, reference, order))
    })();
    let (park, index, logical, reference, order) = match admission {
        Ok(admission) => admission,
        Err(status) => return Err((status, request)),
    };
    // The attempt that brought the request here opens its wait.
    let mut deferral = Deferral::new();
    let _ = deferral.observe(STATUS_DEVICE_BUSY, writable_fs::reserve_progress,
        monotonic_time_100ns);
    if DURABLE_TRACED.load(Ordering::Relaxed) < DURABLE_TRACE_LIMIT {
        print_str(b"[cm-durable] waiting request=");
        print_str(request.name());
        print_str(b" tid=");
        print_u64(handler.current_tid);
        print_str(b"\n");
    }
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(reply, 0);
    let work = Work {
        order, hive: NO_HIVE, reported: None, log_path: String::new(),
        pending: None, prepared: None, journal_id: None, receipt: None, installation: None,
        caller: Caller::Hosted(HostedCaller {
            pi: handler.pi,
            tid: handler.current_tid, badge: handler.current_badge, reply, logical, reference,
            completion: Some(Completion::Durable { request, deferral }),
            _continuation: if handler.current_native_call_transport {
                UserApcContinuation::NativeCall
            } else {
                UserApcContinuation::Fault {
                    resume_ip: handler.current_resume_ip,
                    resume_sp: handler.current_sp,
                    resume_flags: handler.current_flags,
                }
            },
        }),
        phase: Phase::Durable, status: 0, cancelled: false,
    };
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    match index { Some(index) => rows[index] = Some(work), None => rows.push(Some(work)) }
    park.commit();
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

/// Keep a synchronous `NtNotifyChangeKey` caller until its posted request completes. The caller
/// and its Reply move here together; a refusal leaves the Reply current and the request posted.
pub(crate) unsafe fn submit_hosted_change_notify(
    handler: &mut ExecNtHandler, post: nt_config_notify::PostId,
) -> Result<(), u32> {
    let _durable = allocator::enter_durable();
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
    let requestor = handler.pm.capture_native_handle_caller(
        logical.thread(), nt_types::AccessMode::KernelMode)?;
    let mut reference = handler.pm.reference_native_requestor(requestor)?;
    let order = match reserve_order() {
        Ok(order) => order,
        Err(status) => {
            reference.release(&mut handler.pm).expect("unsubmitted notify caller");
            return Err(status);
        }
    };
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(reply, 0);
    let work = Work {
        order, hive: NO_HIVE, reported: None, log_path: String::new(),
        pending: None, prepared: None, journal_id: None, receipt: None, installation: None,
        caller: Caller::Hosted(HostedCaller {
            pi: handler.pi,
            tid: handler.current_tid, badge: handler.current_badge, reply, logical, reference,
            completion: Some(Completion::ChangeNotify { post }),
            _continuation: if handler.current_native_call_transport {
                UserApcContinuation::NativeCall
            } else {
                UserApcContinuation::Fault {
                    resume_ip: handler.current_resume_ip,
                    resume_sp: handler.current_sp,
                    resume_flags: handler.current_flags,
                }
            },
        }),
        phase: Phase::Notify, status: 0, cancelled: false,
    };
    match index { Some(index) => rows[index] = Some(work), None => rows.push(Some(work)) }
    park.commit();
    NOTIFY_WAITING.fetch_add(1, Ordering::Release);
    PENDING.fetch_add(1, Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

/// A parked `NtNotifyChangeKey` caller has a status to collect, or is gone.
pub(crate) fn wake_change_notify() {
    NOTIFY_READY.store(true, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
}

/// Attempt a kept durability request again. `Some(status)` completes its caller.
unsafe fn advance_durable(handler: &mut ExecNtHandler, caller: &mut HostedCaller) -> Option<u32> {
    let Some(Completion::Durable { request, deferral }) = caller.completion.as_mut()
        else { unreachable!("retained durability request") };
    let status = handler.attempt_durable_registry_request(request);
    let outcome = deferral.observe(status, writable_fs::reserve_progress, monotonic_time_100ns);
    let CallerStep::Complete(status) = outcome.caller_step() else { return None; };
    if DURABLE_TRACED.fetch_add(1, Ordering::Relaxed) < DURABLE_TRACE_LIMIT {
        print_str(b"[cm-durable] ");
        let (deferrals, waited) = match outcome {
            Outcome::Settled { deferrals, waited_100ns, .. } => {
                print_str(b"durable");
                (deferrals, waited_100ns)
            }
            Outcome::Stalled { deferrals, stalled_100ns, .. } => {
                print_str(b"stalled");
                (deferrals, stalled_100ns)
            }
            _ => {
                print_str(b"refused");
                (0, 0)
            }
        };
        print_str(b" request=");
        print_str(request.name());
        print_str(b" tid=");
        print_u64(caller.tid);
        print_str(b" deferrals=");
        print_u64(deferrals);
        print_str(b" waited-100ns=");
        print_u64(waited);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
    }
    Some(status)
}

/// The caller's reserved output, exact parent reference, subject and Reply move together.
/// Failure leaves both externally owned reservations untouched for admission cleanup.
pub(crate) unsafe fn submit_hosted_create_child(
    handler: &mut ExecNtHandler,
    publication: HostedRegistryPublication,
    parent_owner: RegistryKeyHandlePublication,
    parent: KeyRef,
    parent_key: ResolvedHiveKey,
    leaf: String,
    class: Option<String>,
    descriptor: Vec<u8>,
    kind: nt_hive_core::KeyKind,
    grant: u32,
    backup: bool,
) -> Result<(), (u32, HostedRegistryPublication, RegistryKeyHandlePublication)> {
    let _durable = allocator::enter_durable();
    let admission = (|| {
        let (parent_path, path_leaf) = publication.path.rsplit_once('\\')
            .ok_or(0xC000_003Bu32)?;
        if path_leaf != leaf || handler.registry_target_path(parent).as_deref() != Some(parent_path) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let relative = handler.mutable_key_relative_path(parent_key)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let mut log_path = handler.mutable_hive_checkpoint_path_owned(parent_key.hive)
            .ok_or(STATUS_INVALID_HANDLE)?;
        log_path.try_reserve(4).map_err(|_| 0xC000_009Au32)?;
        log_path.push_str(".LOG");
        let tcb = handler.hosted_thread_tcb(handler.current_tid)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let logical = handler.capture_provider_logical_caller(
            handler.pi, handler.current_tid, handler.current_badge, tcb,
        ).ok_or(STATUS_INVALID_HANDLE)?;
        if logical.thread() != publication.subject.caller().original_thread() {
            return Err(STATUS_INVALID_HANDLE);
        }
        let park = root_reply_park::RootReplyPark::prepare().ok_or(0xC000_009Au32)?;
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let index = rows.iter().enumerate().find_map(|(index, row)|
            (row.is_none() && EXECUTING_INDEX.load(Ordering::Relaxed) != index as u64)
                .then_some(index));
        if index.is_none() { rows.try_reserve(1).map_err(|_| 0xC000_009Au32)?; }
        let requestor = handler.pm.capture_native_handle_caller(
            logical.thread(), nt_types::AccessMode::KernelMode)?;
        let mut reference = handler.pm.reference_native_requestor(requestor)?;
        let order = match reserve_order() {
            Ok(order) => order,
            Err(status) => {
                reference.release(&mut handler.pm).expect("unsubmitted mutable create caller");
                return Err(status);
            }
        };
        Ok((park, index, logical, reference, order, relative, log_path))
    })();
    let (park, index, logical, reference, order, relative, log_path) = match admission {
        Ok(admission) => admission,
        Err(status) => return Err((status, publication, parent_owner)),
    };
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(reply, 0);
    let work = Work {
        order, hive: parent_key.hive, reported: None, log_path,
        pending: Some(Pending::Child { parent: parent_key.key, path: relative,
            name: leaf, class, descriptor, kind }),
        prepared: None,
        journal_id: None, receipt: None, installation: None,
        caller: Caller::Hosted(HostedCaller {
            pi: handler.pi,
            tid: handler.current_tid, badge: handler.current_badge, reply, logical, reference,
            completion: Some(Completion::CreateChild {
                publication, parent_owner, parent_key, child: None, grant, backup,
                published: false,
            }),
            _continuation: if handler.current_native_call_transport {
                UserApcContinuation::NativeCall
            } else {
                UserApcContinuation::Fault {
                    resume_ip: handler.current_resume_ip,
                    resume_sp: handler.current_sp,
                    resume_flags: handler.current_flags,
                }
            },
        }),
        phase: Phase::Prepare, status: 0, cancelled: false,
    };
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    match index { Some(index) => rows[index] = Some(work), None => rows.push(Some(work)) }
    park.commit();
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
    Ok(())
}

pub(crate) fn take_transferred() -> bool { TRANSFERRED.swap(false, Ordering::AcqRel) }
pub(crate) fn next_deadline(now: u64) -> Option<u64> {
    nt_config_client::mutation_retry_schedule::mutable_hive_deadline(
        PENDING.load(Ordering::Acquire), NOTIFY_WAITING.load(Ordering::Acquire),
        NOTIFY_READY.load(Ordering::Acquire), NEXT.load(Ordering::Acquire),
        HIVE_COMPLETION.current(), ACTIVE.load(Ordering::Acquire), now)
}

/// A move-only witness from the exact entered HiveTicket's physical terminal schedules
/// its retained Poll row. This hint never polls the journal or publishes the caller's Reply.
pub(crate) fn wake_completed_hive_journal(ready: writable_fs::hive_wal::HiveJournalReady) {
    let _ = HIVE_COMPLETION.publish(ready.owner_id());
}
pub(crate) fn has_thread(tid: u64) -> bool {
    EXECUTING_TID.load(Ordering::Acquire) == tid || unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten()
        .any(|work| !matches!(work.phase, Phase::ReconcileRuntime)
            && work.caller.hosted_tid() == tid) }
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
        if let Err(prepared) = prepared.release_unentered(&mut handler.mutable_hives) {
            work.prepared = Some(prepared);
            return Err(status);
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

fn release_completion(handler: &mut ExecNtHandler, caller: &mut HostedCaller) {
    match caller.completion.take().expect("retained mutable completion") {
        Completion::ExistingKey { key_owner } => release_key_owner(handler, key_owner),
        Completion::CreateChild { mut publication, parent_owner, published, .. } => {
            if !published {
                handler.abort_hosted_registry_publication(&mut publication);
            }
            release_key_owner(handler, parent_owner);
        }
        Completion::Durable { request, .. } =>
            handler.release_durable_registry_request(request),
        Completion::ChangeNotify { post } => handler.abandon_registry_notify_wait(post),
    }
}

unsafe fn advance(
    handler: &mut ExecNtHandler, queue: Option<&mut nt_delay_execution::Queue>, work: &mut Work,
    earlier_unpublished: bool,
) -> Result<bool, u32> {
    work.cancelled |= match &work.caller {
        Caller::Hosted(caller) => caller_cancelled(handler, caller),
        Caller::Provider(caller) => caller.cancelled(),
    };
    match work.phase {
        Phase::Prepare => {
            if work.cancelled {
                work.status = 0xC000_0120;
                work.pending.take();
                work.phase = Phase::ReadyReply;
            } else if !earlier_unpublished
                && !handler.mutable_hives.has_retained_publication(work.hive) {
                let pending = work.pending.take().expect("unprepared mutable edit");
                work.reported = match &pending {
                    Pending::Value { key, .. } | Pending::DeleteValue { key, .. } =>
                        Some(Reported::Values(*key)),
                    Pending::Security { key, .. } => Some(Reported::Security(*key)),
                    Pending::DeleteKey { key, .. } => handler.mutable_hives
                        .key_name(ResolvedHiveKey { hive: work.hive, key: *key })
                        .map(Reported::KeyDeleted),
                    Pending::Child { .. } => None,
                };
                let prepared = match pending {
                    Pending::Value { key, path, name, value_type, data } =>
                        handler.mutable_hives.prepare_owned_set_value(
                            work.hive, key, &path, &name, value_type, data,
                        ).map(Prepared::Value).map_err(prepare_error),
                    Pending::Child { parent, path, name, class, descriptor, kind } =>
                        match handler.mutable_hives.prepare_owned_create_child_of_kind(
                            work.hive, parent, &path, &name, class.as_deref(), descriptor, kind,
                        ) {
                            Ok(prepared) => Ok(Prepared::Child(prepared)),
                            // A link is created, never opened (CmpDoOpen's collision).
                            Err(CreateChildError::NameCollision)
                                if kind == nt_hive_core::KeyKind::SymbolicLink => Err(0xC000_0035),
                            Err(CreateChildError::NameCollision) => {
                                work.phase = Phase::OpenExistingChild;
                                return Ok(false);
                            }
                            Err(error) => Err(create_error(error)),
                        },
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
                    Pending::DeleteValue { key, path, name } =>
                        handler.mutable_hives.prepare_owned_delete_value(work.hive, key, &path, &name)
                            .map(Prepared::DeleteValue).map_err(delete_value_error),
                    Pending::DeleteKey { key, path } =>
                        handler.mutable_hives.prepare_owned_delete_key(work.hive, key, &path)
                            .map(Prepared::DeleteKey).map_err(delete_key_error),
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
            let record = AnchoredRecord { anchored: receipt.anchored, file_id: receipt.file_id,
                expected_log_len: receipt.expected_log_len, log_path: &receipt.log_path };
            let (child, continuation, pair) = match prepared.publish(&mut handler.mutable_hives, record) {
                Ok(published) => published,
                Err((prepared, anchored)) => {
                    work.prepared = Some(prepared);
                    work.receipt = Some(writable_fs::hive_wal::NativeHiveJournalReceipt {
                        anchored, ..receipt
                    });
                    return Err(0xC000_003Eu32);
                }
            };
            if let Some(child) = child {
                let Some(Completion::CreateChild { child: destination, .. }) =
                    work.caller.hosted().completion.as_mut() else { unreachable!("child completion") };
                *destination = Some(child);
            }
            // The edit is now what every reader of the hive sees.
            match (child, work.reported.take()) {
                (Some(child), _) => handler.mutable_registry_subkey_created(
                    ResolvedHiveKey { hive: work.hive, key: child }),
                (None, Some(Reported::Values(key))) => handler
                    .mutable_registry_key_values_changed(ResolvedHiveKey { hive: work.hive, key }),
                (None, Some(Reported::Security(key))) => handler
                    .mutable_registry_key_security_changed(ResolvedHiveKey { hive: work.hive, key }),
                (None, Some(Reported::KeyDeleted(name))) => {
                    handler.registry_key_deleted(&name);
                    let _ = handler.overlay.detach_subtree(&name);
                }
                (None, None) => {}
            }
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
                    work.phase = if work.caller.creates_child() {
                        Phase::PublishChild
                    } else {
                        Phase::ReadyReply
                    };
                }
                Err((status, continuation, pair)) => {
                    work.installation = Some((continuation, pair));
                    return Err(status);
                }
            }
        }
        Phase::PublishChild => {
            if !work.cancelled {
                let caller = work.caller.hosted();
                let Some(Completion::CreateChild { publication, parent_key, child,
                    grant, published, .. }) = caller.completion.as_mut()
                else { unreachable!("retained child completion") };
                if !handler.validate_provider_logical_caller(caller.logical) {
                    work.cancelled = true;
                } else {
                    let saved_pi = handler.pi;
                    handler.pi = caller.pi;
                    let result = handler.finish_anchored_mutable_child(
                        publication, *parent_key, child.expect("anchored child"), *grant,
                    );
                    handler.pi = saved_pi;
                    *published = result.is_ok();
                    work.status = result.err().unwrap_or(0);
                }
            }
            work.phase = Phase::ReadyReply;
        }
        Phase::OpenExistingChild => {
            if !work.cancelled {
                let caller = work.caller.hosted();
                let Some(Completion::CreateChild { publication, parent_key, backup,
                    published, .. }) = caller.completion.as_mut()
                else { unreachable!("retained child completion") };
                if !handler.validate_provider_logical_caller(caller.logical) {
                    work.cancelled = true;
                } else {
                    let saved_pi = handler.pi;
                    handler.pi = caller.pi;
                    let result = handler.finish_existing_mutable_child(
                        publication, *parent_key, *backup,
                    );
                    handler.pi = saved_pi;
                    *published = result.is_ok();
                    work.status = result.err().unwrap_or(0);
                }
            }
            work.phase = Phase::ReadyReply;
        }
        Phase::Durable => {
            if work.cancelled {
                work.status = 0xC000_0120;
                work.phase = Phase::ReadyReply;
            } else if let Some(status) = advance_durable(handler, work.caller.hosted()) {
                work.status = status;
                work.phase = Phase::ReadyReply;
            }
        }
        Phase::Notify => {
            let Some(Completion::ChangeNotify { post }) = work.caller.hosted().completion.as_ref()
                else { unreachable!("retained change-notify request") };
            let post = *post;
            if work.cancelled {
                // The request must not complete into a caller that is gone.
                handler.abandon_registry_notify_wait(post);
                work.status = 0xC000_0120;
            } else if let Some(status) = handler.take_registry_notify_wait_status(post) {
                work.status = status;
            } else {
                return Ok(false);
            }
            NOTIFY_WAITING.fetch_sub(1, Ordering::Release);
            work.phase = Phase::ReadyReply;
        }
        Phase::ReadyReply => {
            if let Caller::Provider(caller) = &mut work.caller {
                // The provider's parked service lane completes with the real status.
                caller.finish(work.status)?;
                return Ok(true);
            }
            if work.cancelled {
                work.phase = Phase::RevokeReply;
                return Ok(false);
            }
            parked_reply::validate_saved(work.caller.hosted().reply).map_err(|status| status as u32)?;
            work.phase = Phase::ReplyEntered;
            if !crate::service_sec_image::complete_mutable_hive_mutation_reply(
                handler, work.caller.hosted().tid, work.caller.hosted().reply, work.status,
            ) { return Err(0xC000_00A3); }
            work.phase = Phase::ReplySent;
        }
        Phase::ReplyEntered => {
            if spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(
                work.caller.hosted().reply,
            ).map_err(|_| 0xC000_00A3u32)? {
                work.phase = Phase::ReplySent;
            } else if work.cancelled {
                work.phase = Phase::RevokeReply;
            } else { return Err(0xC000_00A3); }
        }
        Phase::ReplySent => {
            parked_reply::retire_sent(work.caller.hosted().reply).map_err(|status| status as u32)?;
            if work.cancelled {
                work.phase = Phase::ReconcileRuntime;
                return Ok(false);
            }
            release_completion(handler, work.caller.hosted());
            thread_wait_state_clear_badge_ready(handler, work.caller.hosted().badge);
            work.caller.hosted().reference.release(&mut handler.pm)
                .expect("retained mutable caller reference");
            return Ok(true);
        }
        Phase::RevokeReply => {
            if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(work.caller.hosted().reply) {
                parked_reply::revoke(work.caller.hosted().reply).map_err(|status| status as u32)?;
            }
            work.phase = Phase::RetypeReply;
        }
        Phase::RetypeReply => {
            parked_reply::retype(work.caller.hosted().reply).map_err(|status| status as u32)?;
            work.phase = Phase::ReconcileRuntime;
        }
        Phase::ReconcileRuntime => {
            let queue = queue.expect("hosted runtime reconciles only at the outer loop");
            if !hosted_termination::reconcile(handler, queue, work.caller.hosted().logical) {
                return Err(0xC000_00A3);
            }
            release_completion(handler, work.caller.hosted());
            work.caller.hosted().reference.release(&mut handler.pm)
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

/// The outer service loop advances every row, including each hosted Reply.
pub(crate) unsafe fn redrive(
    handler: &mut ExecNtHandler, queue: &mut nt_delay_execution::Queue,
) {
    redrive_rows(handler, Some(queue));
}

/// A nested provider pump may be waiting on a provider row: a driver or win32k whose service
/// lane is parked here. Advance every provider row, and every hosted row only through its
/// journal phases, so the single native hive journal is never held by a row this frame cannot
/// move. No nested frame owns a hosted Reply, so hosted rows stop before their reply phases.
pub(crate) unsafe fn redrive_nested() -> bool {
    if nt_config_client::mutation_retry_schedule::mutable_hive_pass(
        PENDING.load(Ordering::Acquire), monotonic_time_100ns(),
        NEXT.load(Ordering::Acquire), HIVE_COMPLETION.current()).is_none()
        || ACTIVE.load(Ordering::Acquire) { return false; }
    let Ok(handler) = crate::service_sec_image::registry_live_handler() else { return false; };
    let before = PENDING.load(Ordering::Acquire);
    redrive_rows(handler, None);
    PENDING.load(Ordering::Acquire) != before
}

/// The native hive journal a nested frame may drive: one held by a row in its WAL phase.
/// The numeric id alone authorizes nothing; the exact retained row and phase are checked here.
pub(crate) fn pending_nested_hive_wal_io() -> Option<u64> {
    if ACTIVE.load(Ordering::Acquire) { return None; }
    unsafe { (&*core::ptr::addr_of!(WORK)).iter().flatten()
        .find_map(|work| matches!(work.phase, Phase::Poll).then_some(work.journal_id).flatten()
            .filter(|&id| writable_fs::hive_wal::native_hive_journal_io_active(id))) }
}

unsafe fn redrive_rows(
    handler: &mut ExecNtHandler, mut queue: Option<&mut nt_delay_execution::Queue>,
) {
    let ready_journal = HIVE_COMPLETION.current();
    let Some(pass) = nt_config_client::mutation_retry_schedule::mutable_hive_pass(
        PENDING.load(Ordering::Acquire), monotonic_time_100ns(),
        NEXT.load(Ordering::Acquire), ready_journal) else { return; };
    if ACTIVE.swap(true, Ordering::AcqRel) { return; }
    let outer = queue.is_some();
    if outer && pass.is_timed() { NOTIFY_READY.store(false, Ordering::Release); }
    let mut failed = false;
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    for index in 0..rows.len() {
        let Some(mut work) = rows[index].take() else { continue; };
        if !pass.row_due(work.journal_id, matches!(work.phase, Phase::Poll)) {
            rows[index] = Some(work);
            continue;
        }
        EXECUTING_INDEX.store(index as u64, Ordering::Relaxed);
        let mut completed = false;
        for _ in 0..8 {
            if !outer && matches!(work.caller, Caller::Hosted(_))
                && !blocks_later_preparation(&work.phase) { break; }
            let earlier_unpublished = rows.iter().flatten().any(|other|
                other.hive == work.hive && other.order < work.order
                    && blocks_later_preparation(&other.phase));
            EXECUTING_TID.store(if matches!(work.phase, Phase::ReconcileRuntime) {
                0
            } else {
                work.caller.hosted_tid()
            }, Ordering::Release);
            match advance(handler, queue.as_deref_mut(), &mut work, earlier_unpublished) {
                Ok(true) => { completed = true; break; },
                // Still in flight: one attempt per turn.
                Ok(false) if matches!(work.phase, Phase::Durable | Phase::Notify) => break,
                Ok(false) => {},
                Err(_) => { failed = true; break; },
            }
        }
        if completed { PENDING.fetch_sub(1, Ordering::Release); }
        else { rows[index] = Some(work); }
        EXECUTING_INDEX.store(u64::MAX, Ordering::Relaxed);
        EXECUTING_TID.store(0, Ordering::Release);
    }
    if let Some(journal) = ready_journal { HIVE_COMPLETION.clear_exact(journal); }
    if pass.is_timed() {
        NEXT.store(monotonic_time_100ns().saturating_add(if failed { RETRY_DELAY } else { POLL_DELAY }),
            Ordering::Release);
    }
    ACTIVE.store(false, Ordering::Release);
}
