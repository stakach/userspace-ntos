//! Native SYSTEM create ownership from before BEGIN through exact terminal ACK.

use crate::*;
use alloc::string::String;
use crate::exec_handler::registry_admission::HostedRegistryPublication;
use nt_config_client::*;
use nt_process::RegistryKeyHandlePublication;
use nt_process::native_handle::NativeThreadProcessReference;
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;
use nt_thread_start::amd64_context::UserApcContinuation;

struct HostedCaller {
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

#[path = "registry_mutation_provider.rs"]
mod provider;
pub(crate) use provider::{submit_provider, ProviderRegistryResult};

enum Caller {
    Hosted(HostedCaller),
    Provider(provider::ProviderCaller),
}

impl Caller {
    fn logical(&self) -> Option<ProviderLogicalCaller> {
        match self {
            Self::Hosted(caller) => Some(caller.logical),
            Self::Provider(caller) => caller.logical,
        }
    }

    fn leaf(&self) -> &str {
        match self {
            Self::Hosted(caller) => &caller.leaf,
            Self::Provider(caller) => &caller.admission.leaf,
        }
    }
}

type HostedContext<'a> = Option<(&'a mut ExecNtHandler, &'a mut nt_delay_execution::Queue)>;

enum Phase {
    ProviderAdmit,
    Begin(CmMutationBeginAttempt<()>),
    Prepare(SystemHiveMutationPreparation<()>),
    Admit,
    Durable,
    Commit,
    Open,
    Acknowledge,
    Abort,
    Rollback,
    AcknowledgeAbort(SystemHiveMutationAbortReceipt),
    ReleaseRollback,
    Complete,
    ReadyReply,
    ReplyEntered,
    ReplySent,
    RevokeReply,
    RetypeReply,
    ReconcileRuntime,
    ProviderReplyEntered,
}

struct Work {
    caller: Caller,
    phase: Phase,
    prepared: Option<PreparedSystemHiveMutation>,
    journal: Option<writable_fs::registry_journal::Journal<()>>,
    receipt: Option<SystemHiveMutationCommitReceipt>,
    opening: Option<cm_key_ownership::PublicationOpen>,
    status: u32,
    cancelled: bool,
    commit_entered: bool,
    published: bool,
}

static mut ATTEMPTS: CmMutationBeginAttempts = CmMutationBeginAttempts::new();
static mut WORK: Vec<Option<Work>> = Vec::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicU64 = AtomicU64::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);
static CURSOR: AtomicU64 = AtomicU64::new(0);
static TRANSFERRED: AtomicBool = AtomicBool::new(false);
static mut EXECUTING: Option<ProviderLogicalCaller> = None;
static EXECUTING_INDEX: AtomicU64 = AtomicU64::new(u64::MAX);
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
        if logical.thread() != publication.subject.caller().original_thread() {
            return Err(0xC000_0008);
        }
        let mount = LIVE_CONFIG_MANAGER_SYSTEM_MOUNT.ok_or(0xC000_00A3u32)?;
        let park = root_reply_park::RootReplyPark::prepare().ok_or(0xC000_009Au32)?;
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let index = rows.iter().enumerate().find_map(|(index, row)|
            (row.is_none() && EXECUTING_INDEX.load(Ordering::Relaxed) != index as u64)
                .then_some(index));
        if index.is_none() { rows.try_reserve(1).map_err(|_| 0xC000_009Au32)?; }
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
        Ok((park, attempt, logical, reference, index))
    })();
    let (park, attempt, logical, reference, index) = match admission {
        Ok(admission) => admission,
        Err(status) => return Err((status, publication, parent_owner)),
    };
    let caller = HostedCaller {
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
    let work = Some(Work {
        caller: Caller::Hosted(caller), phase: Phase::Begin(attempt), prepared: None, journal: None,
        receipt: None, opening: None, status: 0,
        cancelled: false, commit_entered: false, published: false,
    });
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    match index {
        Some(index) => rows[index] = work,
        None => rows.push(work),
    }
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
                .any(|work| !matches!(work.phase, Phase::ReconcileRuntime)
                    && work.caller.logical().is_some_and(&predicate))
    }
}

pub(crate) fn next_deadline() -> Option<u64> {
    let work = (PENDING.load(Ordering::Acquire) != 0).then(|| NEXT.load(Ordering::Acquire));
    let service = unsafe {
        spawn_hosts::shared_ingress::owner::runtime::registry_service_resume_next_deadline()
    };
    match (work, service) {
        (Some(work), Some(service)) => Some(work.min(service)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

pub(crate) fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline().is_some_and(|deadline| now >= deadline))
}

/// Top-level only. The selected owner is moved, never borrowed, across component IPC.
pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler, queue: &mut nt_delay_execution::Queue) {
    redrive_inner(Some((handler, queue)));
}

/// Bootstrap and provider pumps may progress provider work without inventing a hosted handler.
pub(crate) unsafe fn redrive_provider() {
    redrive_inner(None);
}

unsafe fn redrive_inner(mut context: HostedContext<'_>) {
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
            if context.is_none() && rows[index].as_ref()
                .is_some_and(|work| matches!(work.caller, Caller::Hosted(_))) {
                return None;
            }
            rows[index].take().map(|work| (index, work))
        })
    };
    if let Some((index, mut work)) = selected {
        EXECUTING_INDEX.store(index as u64, Ordering::Relaxed);
        CURSOR.store(index as u64 + 1, Ordering::Relaxed);
        *core::ptr::addr_of_mut!(EXECUTING) = work.caller.logical();
        let mut completed = false;
        // Bound each sweep; long journals resume fairly on the next maintenance tick.
        for _ in 0..16 {
            *core::ptr::addr_of_mut!(EXECUTING) =
                if matches!(work.phase, Phase::ReconcileRuntime) { None } else { work.caller.logical() };
            match advance(&mut context, &mut work) {
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
        EXECUTING_INDEX.store(u64::MAX, Ordering::Relaxed);
    }
    NEXT.store(monotonic_time_100ns().saturating_add(if failed { RETRY_DELAY } else { 0 }), Ordering::Release);
    ACTIVE.store(false, Ordering::Release);
}

unsafe fn caller_cancelled(handler: &ExecNtHandler, caller: &HostedCaller) -> bool {
    spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(caller.reply)
        || handler.pm.thread(caller.logical.thread().thread_id())
            .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
        || handler.pm.process(caller.logical.process().pid)
            .is_some_and(|process| process.state == nt_process::ProcessState::Terminated)
}

unsafe fn advance(
    context: &mut HostedContext<'_>,
    work: &mut Work,
) -> Result<bool, i32> {
    work.cancelled |= match &work.caller {
        Caller::Hosted(caller) => caller_cancelled(&*context.as_ref().unwrap().0, caller),
        Caller::Provider(caller) => caller.cancelled(),
    };
    if work.cancelled && work.status == 0 { work.status = 0xC000_0120; }
    match &mut work.phase {
        Phase::ProviderAdmit => {
            if work.cancelled {
                work.phase = Phase::Complete;
                return Ok(false);
            }
            let Caller::Provider(caller) = &work.caller else { unreachable!() };
            match caller.begin() {
                Ok(attempt) => work.phase = Phase::Begin(attempt),
                Err(status) => { work.status = status as u32; work.phase = Phase::Complete; }
            }
        }
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
            if work.cancelled {
                work.phase = Phase::Abort;
                return Ok(false);
            }
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
            if work.cancelled {
                work.phase = Phase::Rollback;
                return Ok(false);
            }
            let journal = work.journal.as_mut().unwrap();
            journal.make_durable().map_err(|status| status as i32)?;
            work.phase = Phase::Commit;
        }
        Phase::Commit => {
            if work.cancelled && !work.commit_entered {
                work.phase = if work.journal.is_some() { Phase::Rollback } else { Phase::Abort };
                return Ok(false);
            }
            if !work.commit_entered {
                if let Some(journal) = work.journal.as_mut() {
                    journal.begin_publication().map_err(|status| status as i32)?;
                }
                // No IPC separates the storage barrier from recording COMMIT entry.
                work.commit_entered = true;
            }
            let receipt = cm_mutation_transport::commit(work.prepared.as_ref().unwrap())?;
            let outcome = receipt.outcome();
            CM_RUNTIME_SYSTEM_MUTATION_COMMITS.fetch_add(1, Ordering::Relaxed);
            CM_RUNTIME_SYSTEM_CREATE_KEYS.fetch_add(1, Ordering::Relaxed);
            LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.fetch_max(outcome.generation, Ordering::AcqRel);
            if outcome.has_pending_device_action {
                CONFIG_DEVICE_ACTION_PENDING.store(true, Ordering::Release);
            }
            work.receipt = Some(receipt);
            work.phase = Phase::Open;
        }
        Phase::Open => {
            if work.cancelled && work.opening.is_none() {
                work.phase = Phase::Acknowledge;
                return Ok(false);
            }
            if work.opening.is_none() {
                let lease = match &work.caller {
                    Caller::Hosted(caller) => registry_key_targets::system(caller.parent)
                        .expect("retained SYSTEM parent disappeared").lease,
                    Caller::Provider(caller) => caller.admission.parent_lease,
                };
                work.opening = Some(cm_key_ownership::reserve_publication_open(lease, work.caller.leaf())?);
            }
            let Some(opened) = cm_key_ownership::resume_publication_open(work.opening.as_ref().unwrap())? else {
                return Ok(false);
            };
            work.opening = None;
            let result = match opened {
                Ok(opened) if work.cancelled => {
                    let _ = config_manager_retire_system_hive_key(opened.lease);
                    Err(work.status)
                }
                Ok(opened) => match registry_key_targets::install_system(CmSystemKeyTarget {
                    lease: opened.lease,
                    physical_path: nt_hive_core::canon_path(&opened.physical_path),
                }) {
                    Ok(target) => {
                        let result = publish_target(context, &mut work.caller, target);
                        work.published = result.is_ok();
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
        Phase::Rollback => {
            work.journal.as_mut().expect("unpublished journal owner")
                .rollback().map_err(|status| status as i32)?;
            work.phase = Phase::Abort;
        }
        Phase::AcknowledgeAbort(receipt) => {
            cm_mutation_transport::acknowledge_abort(*receipt)?;
            work.phase = Phase::ReleaseRollback;
        }
        Phase::ReleaseRollback => {
            if let Some(journal) = work.journal.take() {
                match journal.release_rolled_back() {
                    Ok(()) => {}
                    Err(journal) => {
                        work.journal = Some(journal);
                        return Err(0xC000_000Du32 as i32);
                    }
                }
            }
            work.phase = Phase::Complete;
        }
        Phase::Complete => {
            match &mut work.caller {
                Caller::Hosted(caller) => {
                    let handler = &mut *context.as_mut().unwrap().0;
                    if !work.published {
                        handler.abort_hosted_registry_publication(&mut caller.publication);
                    }
                    if let Some(target) = caller.parent_owner.abort(&mut handler.pm)
                        .expect("retained registry create parent") {
                        handler.release_registry_key_target(target);
                    }
                }
                Caller::Provider(caller) => {
                    caller.cleanup(work.published && !work.cancelled)?;
                    work.phase = Phase::ProviderReplyEntered;
                    return caller.finish(work.status, work.published);
                }
            }
            work.phase = Phase::ReadyReply;
        }
        Phase::ReadyReply => {
            let Caller::Hosted(caller) = &mut work.caller else { unreachable!() };
            let handler = &mut *context.as_mut().unwrap().0;
            if work.cancelled {
                work.phase = Phase::RevokeReply;
                return Ok(false);
            }
            parked_reply::validate_saved(caller.reply).map_err(|status| status as i32)?;
            // An uncertain send cannot repeat cleanup or issue a second reply to this owner.
            work.phase = Phase::ReplyEntered;
            let delivered = crate::service_sec_image::complete_registry_mutation_reply(
                handler, caller.tid, caller.badge, caller.reply, work.status,
            );
            if !delivered { return Err(0xC000_00A3u32 as i32); }
            work.phase = Phase::ReplySent;
        }
        Phase::ReplySent => {
            let Caller::Hosted(caller) = &mut work.caller else { unreachable!() };
            let handler = &mut *context.as_mut().unwrap().0;
            parked_reply::retire_sent(caller.reply).map_err(|status| status as i32)?;
            if work.cancelled {
                work.phase = Phase::ReconcileRuntime;
                return Ok(false);
            }
            thread_wait_state_clear_badge_ready(handler, caller.badge);
            caller.reference.release(&mut handler.pm).expect("registry caller reference");
            return Ok(true);
        }
        Phase::ReplyEntered => {
            let Caller::Hosted(caller) = &work.caller else { unreachable!() };
            if spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(caller.reply)
                .map_err(|_| 0xC000_00A3u32 as i32)? {
                work.phase = Phase::ReplySent;
                return Ok(false);
            }
            if !work.cancelled { return Err(0xC000_00A3u32 as i32); }
            work.phase = Phase::RevokeReply;
        }
        Phase::RevokeReply => {
            let Caller::Hosted(caller) = &work.caller else { unreachable!() };
            if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(caller.reply) {
                parked_reply::revoke(caller.reply).map_err(|status| status as i32)?;
            }
            work.phase = Phase::RetypeReply;
        }
        Phase::RetypeReply => {
            let Caller::Hosted(caller) = &work.caller else { unreachable!() };
            parked_reply::retype(caller.reply).map_err(|status| status as i32)?;
            work.phase = Phase::ReconcileRuntime;
        }
        Phase::ReconcileRuntime => {
            let Caller::Hosted(caller) = &mut work.caller else { unreachable!() };
            let (handler, queue) = context.as_mut().unwrap();
            if !hosted_termination::reconcile(handler, queue, caller.logical) {
                return Err(0xC000_00A3u32 as i32);
            }
            caller.reference.release(&mut handler.pm).expect("retired registry caller reference");
            return Ok(true);
        }
        Phase::ProviderReplyEntered => {
            let Caller::Provider(caller) = &mut work.caller else { unreachable!() };
            return caller.finish(work.status, work.published);
        }
    }
    Ok(false)
}

unsafe fn publish_target(context: &mut HostedContext<'_>, caller: &mut Caller, target: KeyRef) -> Result<(), u32> {
    match caller {
        Caller::Hosted(caller) => {
            let handler = &mut *context.as_mut().unwrap().0;
            if caller_cancelled(handler, caller) || !handler.validate_provider_logical_caller(caller.logical) {
                handler.release_registry_key_target(target);
                return Err(0xC000_004B);
            }
            let saved_pi = handler.pi;
            handler.pi = caller.pi;
            let result = handler.finish_hosted_registry_publication(
                &mut caller.publication, target, caller.grant, true,
            );
            handler.pi = saved_pi;
            result
        }
        Caller::Provider(caller) => caller.bind_target(target).map_err(|status| status as u32),
    }
}
