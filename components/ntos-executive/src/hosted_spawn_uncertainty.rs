//! Original Reply and exact process references for an entered hosted spawn with uncertain effects.
//!
//! No second spawn or synthetic failure is permitted once VSpace construction has entered.
//! These rows are deliberately retained until an exact reconciliation path can prove the
//! child's physical state. They also fence teardown of both creator and child mechanisms.

use crate::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_process::native_handle::NativeThreadProcessReference;
use nt_user_host::entered_spawn_abort::{AbortPhase, AliasFailure, EnteredSpawnAbort};
use nt_user_host::provider_logical_caller::ProviderLogicalCaller;

const RESOURCES: u32 = nt_address_space::STATUS_INSUFFICIENT_RESOURCES;

pub(crate) struct Prepared {
    park: root_reply_park::RootReplyPark,
    reply: u64,
    creator_pi: usize,
    creator_tid: u64,
    creator_logical: ProviderLogicalCaller,
    child_pi: usize,
    child_tid: u64,
    request: nt_exe_image::SpawnRequest,
    creator: NativeThreadProcessReference,
    child_identity: nt_types::ProcessIdentity,
    child_lifetime: nt_process::ThreadLifetime,
}

/// Exact child Ps wait holds, reserved before the first native VSpace effect.
/// A routed-image snapshot has its own creator and Reply owner and borrows only these holds.
pub(crate) struct ChildRefs {
    pub(crate) identity: nt_types::ProcessIdentity,
    pub(crate) lifetime: nt_process::ThreadLifetime,
    pub(crate) tid: u64,
}

pub(crate) fn prepare_child_refs(
    handler: &mut ExecNtHandler,
    request: nt_exe_image::SpawnRequest,
) -> Result<ChildRefs, u32> {
    let target = request.target.ok_or(nt_process::STATUS_INVALID_PARAMETER)?;
    let identity = handler
        .capture_process_identity(target.pi)
        .filter(|identity| {
            identity.generation == nt_types::ProcessGeneration::Hosted(target.generation)
        })
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let tid = u64::from(
        handler
            .pm_main_tid_for_pi(target.pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?,
    );
    let lifetime = handler
        .pm
        .thread_lifetime(tid as nt_process::ThreadId)
        .filter(|lifetime| lifetime.process_id() == identity.pid)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    handler.pm.retain_process_wait_reference(identity.pid)?;
    if let Err(status) = handler
        .pm
        .retain_thread_wait_reference(lifetime.thread_id())
    {
        handler
            .pm
            .release_process_wait_reference(identity.pid)
            .expect("unentered child process wait reference");
        return Err(status);
    }
    Ok(ChildRefs {
        identity,
        lifetime,
        tid,
    })
}

pub(crate) fn release_child_refs(handler: &mut ExecNtHandler, child: ChildRefs) {
    handler
        .pm
        .release_thread_wait_reference(child.lifetime.thread_id())
        .expect("child thread wait reference");
    handler
        .pm
        .release_process_wait_reference(child.identity.pid)
        .expect("child process wait reference");
}

struct Uncertain {
    _reply: u64,
    creator_pi: usize,
    creator_tid: u64,
    creator_logical: ProviderLogicalCaller,
    child_pi: usize,
    child_tid: u64,
    _request: nt_exe_image::SpawnRequest,
    _creator: NativeThreadProcessReference,
    _child_identity: nt_types::ProcessIdentity,
    _child_lifetime: nt_process::ThreadLifetime,
    _status: u32,
    abort: Option<EnteredSpawnAbort>,
}

static mut WORK: Vec<Uncertain> = Vec::new();
static TRANSFERRED: AtomicBool = AtomicBool::new(false);
static RETRY_AT_100NS: AtomicU64 = AtomicU64::new(0);
const RETRY_DELAY_100NS: u64 = 1_000_000;

/// Reserve every owner before the first child VSpace effect. The creator has an exact native
/// requestor reference; the child has exact identity and wait references while it is pre-spawn.
pub(crate) unsafe fn prepare(
    handler: &mut ExecNtHandler,
    request: nt_exe_image::SpawnRequest,
) -> Result<Prepared, u32> {
    let _durable = allocator::enter_durable();
    let creator_tid = handler.current_tid;
    let creator_tid_id = nt_process::ThreadId::try_from(creator_tid)
        .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
    let creator_lifetime = handler
        .pm
        .thread_lifetime(creator_tid_id)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let creator_tcb = handler
        .hosted_thread_tcb(creator_tid)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let creator_logical = handler
        .capture_provider_logical_caller(
            request.creator_pi,
            creator_tid,
            handler.current_badge,
            creator_tcb,
        )
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if handler.pm_pid_for_pi(request.creator_pi) != Some(creator_lifetime.process_id()) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    rows.try_reserve(1).map_err(|_| RESOURCES)?;
    let park = root_reply_park::RootReplyPark::prepare().ok_or(RESOURCES)?;
    let creator_caller = handler
        .pm
        .capture_native_handle_caller(creator_lifetime, nt_types::AccessMode::KernelMode)?;
    let mut creator = handler.pm.reference_native_requestor(creator_caller)?;
    let child = match prepare_child_refs(handler, request) {
        Ok(child) => child,
        Err(status) => {
            creator
                .release(&mut handler.pm)
                .expect("unentered creator reference");
            return Err(status);
        }
    };
    let reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    assert_ne!(reply, 0);
    Ok(Prepared {
        park,
        reply,
        creator_pi: request.creator_pi,
        creator_tid,
        creator_logical,
        child_pi: request.target.expect("validated child target").pi,
        child_tid: child.tid,
        request,
        creator,
        child_identity: child.identity,
        child_lifetime: child.lifetime,
    })
}

pub(crate) fn release_unentered(handler: &mut ExecNtHandler, mut prepared: Prepared) {
    handler
        .pm
        .release_thread_wait_reference(prepared.child_lifetime.thread_id())
        .expect("unentered child thread wait reference");
    handler
        .pm
        .release_process_wait_reference(prepared.child_identity.pid)
        .expect("unentered child process wait reference");
    prepared
        .creator
        .release(&mut handler.pm)
        .expect("unentered creator reference");
}

/// The physical spawn was entered exactly once. Keep the original Reply and both process
/// references; a later event must reconcile this exact target before either can be retired.
pub(crate) unsafe fn retain_entered(prepared: Prepared, status: u32) {
    retain(prepared, status, None);
}

/// A returned alias failure with no entered cap effect may abort the exact child.
/// A missing or stale mechanism is retained as uncertain instead of guessing an owner.
pub(crate) unsafe fn retain_definite(handler: &ExecNtHandler, prepared: Prepared, status: u32) {
    let abort = handler
        .process_mechanisms
        .get(prepared.child_pi)
        .filter(|mechanism| {
            mechanism.pid == prepared.child_identity.pid
                && nt_types::ProcessGeneration::Hosted(mechanism.generation)
                    == prepared.child_identity.generation
                && u64::from(mechanism.main_tid) == prepared.child_tid
        })
        .and_then(|mechanism| {
            EnteredSpawnAbort::begin(mechanism, AliasFailure::Definite(status)).ok()
        });
    retain(prepared, status, abort);
}

unsafe fn retain(prepared: Prepared, status: u32, abort: Option<EnteredSpawnAbort>) {
    let Prepared {
        park,
        reply,
        creator_pi,
        creator_tid,
        creator_logical,
        child_pi,
        child_tid,
        request,
        creator,
        child_identity,
        child_lifetime,
    } = prepared;
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    assert!(
        rows.len() < rows.capacity(),
        "spawn uncertainty owner lost reserved storage"
    );
    rows.push(Uncertain {
        _reply: reply,
        creator_pi,
        creator_tid,
        creator_logical,
        child_pi,
        child_tid,
        _request: request,
        _creator: creator,
        _child_identity: child_identity,
        _child_lifetime: child_lifetime,
        _status: status,
        abort,
    });
    if rows.last().is_some_and(|work| work.abort.is_some()) {
        RETRY_AT_100NS.store(
            monotonic_time_100ns().saturating_add(RETRY_DELAY_100NS),
            Ordering::Release,
        );
    }
    park.commit();
    assert!(!TRANSFERRED.swap(true, Ordering::AcqRel));
}

pub(crate) fn take_transferred() -> bool {
    TRANSFERRED.swap(false, Ordering::AcqRel)
}

pub(crate) fn has_thread(tid: u64) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(WORK)).iter().any(|work| {
            (work.creator_tid == tid
                && work
                    .abort
                    .as_ref()
                    .is_none_or(EnteredSpawnAbort::blocks_creator_teardown))
                || (work.child_tid == tid
                    && work
                        .abort
                        .as_ref()
                        .is_none_or(EnteredSpawnAbort::blocks_child_teardown))
        })
    }
}

pub(crate) fn has_process(pi: usize, _preserve_tid: Option<u64>) -> bool {
    unsafe {
        (&*core::ptr::addr_of!(WORK)).iter().any(|work| {
            (work.creator_pi == pi
                && work
                    .abort
                    .as_ref()
                    .is_none_or(EnteredSpawnAbort::blocks_creator_teardown))
                || (work.child_pi == pi
                    && work
                        .abort
                        .as_ref()
                        .is_none_or(EnteredSpawnAbort::blocks_child_teardown))
        })
    }
}

pub(crate) fn next_deadline() -> Option<u64> {
    match RETRY_AT_100NS.load(Ordering::Acquire) {
        0 => None,
        deadline => Some(deadline),
    }
}

pub(crate) unsafe fn wake_due(
    queue: &mut nt_delay_execution::Queue,
    handler: &mut ExecNtHandler,
    now_100ns: u64,
) -> u64 {
    if next_deadline().is_some_and(|deadline| deadline <= now_100ns) {
        redrive(queue, handler)
    } else {
        0
    }
}

/// Physical observations for a caller that owns an exact entered-spawn abort.
/// Reply and reference ownership remain with that caller.
pub(crate) enum ChildAbortObservation {
    Pending,
    ChildTerminated,
    ExecutionRetired(nt_user_host::ProcessDeletionCandidate),
}

pub(crate) unsafe fn redrive_child_abort(
    child: nt_user_host::ProcessMechanism,
    phase: AbortPhase,
    status: u32,
    queue: &mut nt_delay_execution::Queue,
    handler: &mut ExecNtHandler,
) -> ChildAbortObservation {
    if child.pi >= MAX_PI || child.pi > u8::MAX as usize || status == 0 {
        return ChildAbortObservation::Pending;
    }
    match phase {
        AbortPhase::TerminateChild => {
            if handler.process_mechanisms.get(child.pi) != Some(child)
                || handler.pm.terminate_process(child.pid, status).is_err()
            {
                return ChildAbortObservation::Pending;
            }
            ChildAbortObservation::ChildTerminated
        }
        AbortPhase::RetireExecution => {
            let _ = terminate_hosted_process_mechanisms(child.pi as u8, None, queue, handler);
            let _ = handler.try_delete_hosted_process_object(child.pid);
            match handler
                .process_deletion_candidates
                .get_exact(child.pi, child.pid, child.generation)
                .filter(|candidate| {
                    candidate.phase >= nt_user_host::ProcessDeletionPhase::AwaitingReferences
                }) {
                Some(candidate) => ChildAbortObservation::ExecutionRetired(candidate),
                None => ChildAbortObservation::Pending,
            }
        }
        _ => ChildAbortObservation::Pending,
    }
}

/// Redrive only recorded definitive failures. Native teardown and Reply effects are
/// separated by exact, monotonic ownership transitions; a failed Reply is never sent twice.
pub(crate) unsafe fn redrive(
    queue: &mut nt_delay_execution::Queue,
    handler: &mut ExecNtHandler,
) -> u64 {
    RETRY_AT_100NS.store(0, Ordering::Release);
    let rows = core::ptr::addr_of_mut!(WORK);
    let mut completed = 0;
    let mut pending = false;
    let mut index = 0;
    while index < (&*rows).len() {
        // Keep only an exact row pointer across native teardown callbacks. Those
        // callbacks may inspect the work table, so no Vec borrow may span them.
        let row = (&mut *rows).as_mut_ptr().add(index);
        let mut finished = false;
        // Every successful transition is local and bounded. Drive through to the
        // first genuinely pending external effect before the root blocks in receive.
        for _ in 0..9 {
            let Some((child, phase, status, reply, creator_tid)) =
                (*row).abort.as_ref().map(|abort| {
                    (
                        abort.child(),
                        abort.phase(),
                        (*row)._status,
                        (*row)._reply,
                        (*row).creator_tid,
                    )
                })
            else {
                break;
            };
            let before = phase;
            match phase {
            AbortPhase::TerminateChild | AbortPhase::RetireExecution => {
                let observation = redrive_child_abort(child, phase, status, queue, handler);
                let abort = (*row).abort.as_mut().expect("retained abort owner");
                match observation {
                    ChildAbortObservation::Pending => {}
                    ChildAbortObservation::ChildTerminated => abort.record_child_terminated(child)
                        .expect("exact child termination advances abort owner"),
                    ChildAbortObservation::ExecutionRetired(candidate) =>
                        abort.record_execution_retired(candidate)
                            .expect("exact execution retirement advances abort owner"),
                }
            }
            AbortPhase::ReplyReady => {
                if spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(reply) {
                    (*row).abort.as_mut().expect("retained abort owner")
                        .enter_revoke(child, true)
                        .expect("proven creator cancellation enters Reply revoke");
                    continue;
                }
                if parked_reply::validate_saved(reply).is_err() { pending = true; break; }
                let status = (*row).abort.as_mut().expect("retained abort owner")
                    .enter_reply(child)
                    .expect("exact abort owner sends one original Reply");
                if reply_parked_syscall(reply, u64::from(status)) {
                    (*row).abort.as_mut().expect("retained abort owner")
                        .acknowledge_reply(child)
                        .expect("acknowledged abort Reply has exact owner");
                }
            }
            AbortPhase::ReplyEntered => {
                if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(reply)
                    && matches!(
                        spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(reply),
                        Ok(true))
                {
                    (*row).abort.as_mut().expect("retained abort owner")
                        .acknowledge_reply(child)
                        .expect("reconciled abort Reply has exact owner");
                } else if spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(reply) {
                    (*row).abort.as_mut().expect("retained abort owner")
                        .enter_revoke(child, true)
                        .expect("proven creator cancellation enters Reply revoke");
                }
            }
            AbortPhase::ReplyAcknowledged => {
                if parked_reply::retire_sent(reply).is_err() { pending = true; break; }
                thread_wait_state_clear_tid_ready(handler, creator_tid);
                let work = &mut (*row);
                handler.pm.release_thread_wait_reference(work._child_lifetime.thread_id())
                    .expect("abort child thread wait reference");
                handler.pm.release_process_wait_reference(work._child_identity.pid)
                    .expect("abort child process wait reference");
                work._creator.release(&mut handler.pm)
                    .expect("abort creator reference");
                work.abort.as_mut().expect("retained abort owner").release_references(child)
                    .expect("acknowledged Reply releases exact abort owner");
            }
            AbortPhase::RevokeEntered => {
                if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(reply)
                    || parked_reply::retype(reply).is_err()
                { pending = true; break; }
                (*row).abort.as_mut().expect("retained abort owner")
                    .acknowledge_revoke(child)
                    .expect("cancelled Reply slot retired before creator teardown");
            }
            AbortPhase::RevokeAcknowledged => {
                let creator = (*row).creator_logical;
                if !hosted_termination::reconcile(handler, queue, creator) {
                    pending = true;
                    break;
                }
                (*row).abort.as_mut().expect("retained abort owner")
                    .record_revoke_runtime_reconciled(child)
                    .expect("exact creator runtime reconciled after Reply revoke");
            }
            AbortPhase::RevokeReconciled => {
                thread_wait_state_clear_tid_ready(handler, creator_tid);
                let work = &mut (*row);
                handler.pm.release_thread_wait_reference(work._child_lifetime.thread_id())
                    .expect("abort child thread wait reference");
                handler.pm.release_process_wait_reference(work._child_identity.pid)
                    .expect("abort child process wait reference");
                work._creator.release(&mut handler.pm)
                    .expect("abort creator reference");
                work.abort.as_mut().expect("retained abort owner").release_references(child)
                    .expect("reconciled creator releases exact abort owner");
            }
            AbortPhase::Complete => {}
        }
            if (*row)
                .abort
                .as_ref()
                .is_some_and(|abort| abort.phase() == AbortPhase::Complete)
            {
                (&mut *rows).swap_remove(index);
                completed += 1;
                finished = true;
                break;
            }
            if (*row)
                .abort
                .as_ref()
                .is_some_and(|abort| abort.phase() == before)
            {
                pending = true;
                break;
            }
        }
        if !finished {
            pending |= (*row).abort.is_some();
            index += 1;
        }
    }
    RETRY_AT_100NS.store(
        if pending {
            monotonic_time_100ns().saturating_add(RETRY_DELAY_100NS)
        } else {
            0
        },
        Ordering::Release,
    );
    completed
}
