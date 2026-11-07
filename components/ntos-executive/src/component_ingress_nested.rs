//! Wait-preserving physical exclusion while another component owns root dispatch.

use super::*;
use super::physical_hold::PhysicalExecutionHold;
use nt_component_suspension::{NestedExecutionIdentity, NestedExecutionScope};
use nt_user_host::physical_execution_restore::RestoreStep;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use nt_time::CoalescedRetryWake;
use nt_component_suspension::{next_ready_pending_lane, PendingLaneReadiness};

const ABORT_RETRY_100NS: u64 = 1_600_000;
static ABORT_WAKE: CoalescedRetryWake = CoalescedRetryWake::new();
static LAST_ABORT: AtomicUsize = AtomicUsize::new(usize::MAX);

/// The slot is storage, not authority. A recycled slot cannot restore a different parent scope.
#[must_use = "retain the exact parked parent until restoration acknowledges"]
pub(crate) struct ParkedParentHandle {
    index: usize,
    generation: u64,
    identity: NestedExecutionIdentity,
}

/// A copyable lookup key for a retained restore. The row still owns every physical effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NestedRestoreTicket {
    index: usize,
    generation: u64,
    identity: NestedExecutionIdentity,
}

impl NestedRestoreTicket {
    /// A selector value for an outer continuation; only the retained row can authenticate it.
    pub(crate) const fn identity(self) -> NestedExecutionIdentity { self.identity }
}

impl ParkedParentHandle {
    pub(crate) fn identity(&self) -> NestedExecutionIdentity {
        self.identity
    }

    pub(crate) fn ticket(&self) -> NestedRestoreTicket {
        NestedRestoreTicket {
            index: self.index,
            generation: self.generation,
            identity: self.identity,
        }
    }
}

/// Capture the exact semantic result key while the physical parent row still owns the Reply.
/// This is observational; the caller must retain the result until restore acknowledges.
pub(crate) unsafe fn result_key(
    handle: &ParkedParentHandle,
) -> Option<nt_component_suspension::NestedRestoreResultKey> {
    let parent = (&*core::ptr::addr_of!(PARENTS))
        .get(handle.index)?.as_ref()?;
    if !row_matches(handle, parent) || parent.reply == 0 {
        return None;
    }
    nt_component_suspension::NestedRestoreResultKey::new(handle.identity, parent.reply)
}

/// Memory-only access: callers must not enter IPC or retain a reference from this closure.
pub(crate) unsafe fn with_receive_scope<T>(
    handle: &ParkedParentHandle,
    use_scope: impl FnOnce(&NestedExecutionScope) -> Result<T, Error>,
) -> Result<T, Error> {
    let parent = (&*core::ptr::addr_of!(PARENTS))
        .get(handle.index)
        .and_then(Option::as_ref)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !parent.physical.canonical_pending() {
        return Err(Error::Admission);
    }
    use_scope(scope)
}

struct Parent {
    generation: u64,
    route: PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    /// The physical lane Reply observed before acquisition and sealed into the nested scope.
    reply: u64,
    phase: ParentPhase,
    physical: PhysicalExecutionHold,
    scope: Option<NestedExecutionScope>,
    child: Option<ParentChild>,
    receive_restore:
        Option<nt_user_host::receive_child_barrier::ReceiveRestorePermit<crate::HostedThreadRole>>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ParentPhase {
    /// The row exists before any physical effect. No scope has been created yet.
    Acquiring,
    Parked,
    /// The local handle may disappear after a refusal; this row remains discoverable.
    RestorePending,
    /// A serialized owner is inside the staged restore. A scanner must not enter it twice.
    RestoreAttempt,
    /// Scope admission refused after the physical hold acknowledged. The canonical lane is
    /// still Running; only the retained physical projection and hold need release.
    AbortPending,
    AbortAttempt,
    /// Native entry or identity is uncertain. Retain all resources, never replay an effect.
    Quarantined,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ParentChild {
    Receive,
    RootIngress,
}

// Records are never removed before both canonical restoration and physical release acknowledge.
static mut PARENTS: Vec<Option<Parent>> = Vec::new();
static NEXT_PARENT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Observe whether an exact physical executor is still fenced by any retained parent row.
/// A failed child startup may retire its own route only after this parent hold is gone.
pub(crate) unsafe fn has_retained_parent_for_executor(executor: u64) -> bool {
    (&*core::ptr::addr_of!(PARENTS)).iter().flatten()
        .any(|parent| parent.route.identity().executor == executor)
}

fn row_matches(handle: &ParkedParentHandle, parent: &Parent) -> bool {
    ticket_matches(handle.ticket(), parent)
}

fn ticket_matches(ticket: NestedRestoreTicket, parent: &Parent) -> bool {
    parent.generation == ticket.generation
        && parent.scope.as_ref().map(NestedExecutionScope::identity) == Some(ticket.identity)
        && parent.route == ticket.identity.route()
        && parent.dispatch == ticket.identity.dispatch()
}

pub(crate) unsafe fn park_current() -> Result<Option<ParkedParentHandle>, Error> {
    let Some(lane) = lanes().running() else {
        return Ok(None);
    };
    let route = lanes()
        .peer_route(lane)
        .map_err(|_| Error::Admission)?
        .ok_or(Error::Admission)?;
    let dispatch = dispatch(route)?;
    let reply = current_reply(route)?;
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    // A retained uncertain hold fences its physical TCB even if its old route was retired.
    // A new route generation may not acquire that TCB through a second row.
    if rows.iter().flatten().any(|parent| {
        parent.route.identity().executor == route.identity().executor
    }) {
        return Err(Error::Admission);
    }
    let index = if let Some(index) = rows.iter().position(Option::is_none) {
        index
    } else {
        let _durable = crate::allocator::enter_durable();
        rows.try_reserve(1).map_err(|_| Error::Capacity)?;
        rows.push(None);
        rows.len() - 1
    };
    let generation = NEXT_PARENT_GENERATION.fetch_update(
        Ordering::AcqRel, Ordering::Acquire, |next| next.checked_add(1),
    ).map_err(|_| Error::Capacity)?;
    rows[index] = Some(Parent {
        generation,
        route,
        dispatch,
        reply,
        phase: ParentPhase::Acquiring,
        physical: PhysicalExecutionHold::new(route, dispatch),
        scope: None,
        child: None,
        receive_restore: None,
    });
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    // Suspend cancels IPC in the microkernel. Execution holds preserve the held Call, donated
    // scheduling context and queued message, including the receive continuation after Reply ACK.
    if let Err(error) = rows[index].as_mut().expect("retained parent").physical.acquire() {
        let certified_no_effect = rows[index].as_ref().expect("retained parent")
            .physical.acquire_has_no_effects();
        if certified_no_effect {
            // The kernel certified no effects. No scope exists and this row can be reused.
            rows[index] = None;
        } else {
            // A held or possibly entered acquire has no scope/handle yet. Keep it fenced and
            // visible as quarantine; never reissue acquire through another generation.
            rows[index].as_mut().expect("retained parent").phase = ParentPhase::Quarantined;
        }
        return Err(error);
    }
    let owner = owner();
    let scope = owner
        .receiver
        .as_mut()
        .expect("ready receiver")
        .suspend_for_nested_execution(
            route,
            dispatch,
            lanes(),
            owner.peers.as_ref().expect("ready peers"),
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
        );
    let scope = match scope {
        Ok(scope) => scope,
        Err(_) => {
            let parent = rows[index].as_mut().expect("retained parent");
            if parent.physical.begin_abort_after_failed_scope().is_ok() {
                parent.phase = ParentPhase::AbortPending;
                if attempt_abort(parent) {
                    rows[index] = None;
                }
            } else {
                parent.phase = ParentPhase::Quarantined;
            }
            return Err(Error::Admission);
        }
    };
    let identity = scope.identity();
    let parent = rows[index].as_mut().expect("retained parent");
    parent.scope = Some(scope);
    parent.phase = ParentPhase::Parked;
    Ok(Some(ParkedParentHandle { index, generation, identity }))
}

/// The exact parent row fences its executor until the physical release acknowledges. A failed
/// pure stage is retried from this same row; an uncertain release is never entered twice.
unsafe fn attempt_abort(parent: &mut Parent) -> bool {
    if parent.phase != ParentPhase::AbortPending { return false; }
    parent.phase = ParentPhase::AbortAttempt;
    let result = parent.physical.abort_after_failed_scope();
    if result.is_ok() {
        return true;
    }
    parent.phase = if matches!(parent.physical.restore_step(),
        Ok(RestoreStep::Projection | RestoreStep::Release | RestoreStep::Finalize)) {
        ParentPhase::AbortPending
    } else {
        ParentPhase::Quarantined
    };
    if parent.phase == ParentPhase::AbortPending {
        ABORT_WAKE.publish(
            crate::monotonic_time_100ns().saturating_add(ABORT_RETRY_100NS),
        );
    }
    false
}

unsafe fn drive_abort(index: usize, generation: u64) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    let Some(parent) = rows.get_mut(index).and_then(Option::as_mut) else { return false; };
    if parent.generation != generation { return false; }
    if attempt_abort(parent) {
        rows[index] = None;
        true
    } else {
        false
    }
}

fn has_pending_abort() -> bool {
    unsafe { (&*core::ptr::addr_of!(PARENTS)).iter()
        .any(|row| row.as_ref().is_some_and(|parent| parent.phase == ParentPhase::AbortPending)) }
}

pub(crate) fn next_abort_deadline() -> Option<u64> {
    ABORT_WAKE.next_deadline(has_pending_abort())
}

pub(crate) fn wake_abort_due(now_100ns: u64) -> u64 {
    u64::from(ABORT_WAKE.wake_due(now_100ns, has_pending_abort()))
}

/// Outer service redrive only; never call this inside a nested pump or an ACK path.
pub(crate) unsafe fn drain_abort() -> usize {
    let now = crate::monotonic_time_100ns();
    let Some(attempt) = ABORT_WAKE.begin_redrive(now, has_pending_abort()) else { return 0; };
    let _ = attempt.retry_at(now.saturating_add(ABORT_RETRY_100NS));
    let selected = {
        let rows = &*core::ptr::addr_of!(PARENTS);
        let last = LAST_ABORT.load(Ordering::Relaxed);
        let after = (last != usize::MAX).then_some(last);
        next_ready_pending_lane(rows.len(), after, |index| {
            if rows[index].as_ref().is_some_and(|row| row.phase == ParentPhase::AbortPending) {
                PendingLaneReadiness::Ready
            } else {
                PendingLaneReadiness::Absent
            }
        }).map(|index| (index, rows[index].as_ref().expect("selected abort parent").generation))
    };
    let Some((index, generation)) = selected else { return 0; };
    LAST_ABORT.store(index, Ordering::Relaxed);
    usize::from(drive_abort(index, generation))
}

pub(crate) unsafe fn bind_receive_child(
    handle: &ParkedParentHandle,
    barrier: &mut nt_user_host::receive_child_barrier::ReceiveChildBarrier<crate::HostedThreadRole>,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) -> Result<(), Error> {
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(handle.index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !parent.physical.canonical_pending() || parent.child.is_some() {
        return Err(Error::Admission);
    }
    barrier
        .bind_parent(scope, dispatch)
        .map_err(|_| Error::Admission)?;
    parent.child = Some(ParentChild::Receive);
    Ok(())
}

/// Bind a prepared ordinary root event to the exact physical parent after its hold acknowledges.
/// The pass stays in the retained child row; this parent row remains the physical authority.
pub(crate) unsafe fn bind_root_ingress_child(
    handle: &ParkedParentHandle,
    pass: &mut nt_user_host::root_ingress_pass::RootIngressPass<crate::HostedThreadRole>,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) -> Result<(), Error> {
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(handle.index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !parent.physical.canonical_pending() || parent.child.is_some()
    {
        return Err(Error::Admission);
    }
    pass.bind_parent(scope, dispatch).map_err(|_| Error::Admission)?;
    parent.child = Some(ParentChild::RootIngress);
    Ok(())
}

/// Transfer the one-shot child receipt into the existing physical parent owner before returning
/// any outer-boundary ticket. Failure never drops an entered permit or releases the parent hold.
pub(crate) unsafe fn consume_receive_settlement(
    handle: &ParkedParentHandle,
    barrier: &mut nt_user_host::receive_child_barrier::ReceiveChildBarrier<crate::HostedThreadRole>,
) -> Result<(), Error> {
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(handle.index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !parent.physical.canonical_pending()
        || parent.receive_restore.is_some()
    {
        return Err(Error::Admission);
    }
    let permit = barrier.begin_restore(scope).map_err(|_| Error::Admission)?;
    parent.receive_restore = Some(permit);
    Ok(())
}

/// Memory-only use of the sealed permit; it remains in the physical parent throughout restore.
pub(crate) unsafe fn with_receive_restore<T>(
    handle: &ParkedParentHandle,
    use_permit: impl FnOnce(
        &NestedExecutionScope,
        &nt_user_host::receive_child_barrier::ReceiveRestorePermit<crate::HostedThreadRole>,
    ) -> Result<T, Error>,
) -> Result<T, Error> {
    let parent = (&*core::ptr::addr_of!(PARENTS))
        .get(handle.index)
        .and_then(Option::as_ref)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    let permit = parent.receive_restore.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !permit.matches_scope(scope) || !parent.physical.canonical_pending()
    {
        return Err(Error::Admission);
    }
    use_permit(scope, permit)
}

unsafe fn restore_stages(handle: &mut Option<ParkedParentHandle>) -> Result<(), Error> {
    let Some(ticket) = handle.as_ref() else {
        return Ok(());
    };
    let index = ticket.index;
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    let parent = rows
        .get_mut(index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    if !row_matches(ticket, parent) || parent.phase != ParentPhase::RestoreAttempt {
        return Err(Error::Admission);
    }
    if parent.child == Some(ParentChild::RootIngress) {
        // A later checkpoint must transfer the pass's one-shot restore permit first.
        return Err(Error::Admission);
    }
    if parent.child == Some(ParentChild::Receive)
        && parent.receive_restore.as_ref().is_none_or(|permit| {
            !permit.matches_scope(parent.scope.as_ref().expect("validated scope"))
        })
    {
        return Err(Error::Admission);
    }
    if !parent.physical.held() || resolve(parent.physical.route(), false).is_none() {
        return Err(Error::Admission);
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    if parent.physical.restore_step()? == RestoreStep::Canonical {
        let scope = parent.scope.as_mut().ok_or(Error::Admission)?;
        let owner = owner();
        owner
            .receiver
            .as_mut()
            .expect("ready receiver")
            .resume_nested_execution(
                scope,
                lanes(),
                owner.peers.as_ref().expect("ready peers"),
                |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            )
            .map_err(|_| Error::Admission)?;
        parent.physical.canonical_restored()?;
    }
    if parent.physical.restore_step()? == RestoreStep::Projection {
        parent.physical.restore_projection()?;
    }
    if parent.physical.restore_step()? == RestoreStep::Release {
        parent.physical.release()?;
    }
    if parent.physical.restore_step()? == RestoreStep::Finalize {
        parent.physical.projection_restored()?;
    }
    if parent.physical.restore_step()? != RestoreStep::Done {
        return Err(Error::Admission);
    }
    rows[index] = None;
    *handle = None;
    Ok(())
}

/// Persist recovery authority before a fallible restore. A stack handle can then disappear
/// without losing the exact scope, physical hold, or child settlement permit in `PARENTS`.
pub(crate) unsafe fn mark_restore_pending(
    handle: &Option<ParkedParentHandle>,
) -> Result<(), Error> {
    let Some(ticket) = handle.as_ref() else { return Ok(()); };
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(ticket.index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    if !row_matches(ticket, parent)
        || !matches!(parent.phase, ParentPhase::Parked | ParentPhase::RestorePending)
    {
        return Err(Error::Admission);
    }
    if !parent.physical.held() {
        // An exact row without its acknowledged hold cannot be retried. Keep it fenced even if
        // the stack handle disappears after this refusal.
        parent.phase = ParentPhase::Quarantined;
        return Err(Error::Admission);
    }
    parent.phase = ParentPhase::RestoreAttempt;
    Ok(())
}

/// A pure canonical preflight refusal and a projection-owner preflight refusal have no native
/// effects, so their exact row can be retried. Release marks possible seL4 entry *before* the
/// invocation; `UncertainRelease` is quarantined and is never replayed. The finalize stage
/// follows an acknowledged release and retries only its pure owner-state acknowledgement.
fn restore_refusal_is_retryable(parent: &Parent) -> bool {
    parent.physical.held() && matches!(parent.physical.restore_step(),
        Ok(RestoreStep::Canonical | RestoreStep::Projection | RestoreStep::Finalize))
}

/// Keep a refused parent discoverable after the caller's stack frame ends. The wrapper never
/// retries inside the same pump or turns a physical uncertainty into a transport wall.
pub(crate) unsafe fn restore_or_retain(
    handle: &mut Option<ParkedParentHandle>,
) -> Result<(), Error> {
    mark_restore_pending(handle)?;
    let result = restore_stages(handle);
    if result.is_err() {
        if let Some(ticket) = handle.as_ref() {
            if let Some(parent) = (&mut *core::ptr::addr_of_mut!(PARENTS))
                .get_mut(ticket.index).and_then(Option::as_mut)
            {
                if row_matches(ticket, parent) && parent.phase == ParentPhase::RestoreAttempt {
                    parent.phase = if restore_refusal_is_retryable(parent) {
                        ParentPhase::RestorePending
                    } else {
                        ParentPhase::Quarantined
                    };
                }
            }
        }
    }
    result
}

/// Every existing nested restore caller enters through the durable owner, even when it cannot
/// itself schedule a later retry. The row outlives a dropped stack handle on refusal.
pub(crate) unsafe fn restore(handle: &mut Option<ParkedParentHandle>) -> Result<(), Error> {
    restore_or_retain(handle)
}

/// Look up an exact retained refusal without transferring ownership or changing state.
/// Recycled slots, active restores, and quarantined effects are never pending tickets.
pub(crate) unsafe fn pending_ticket(ticket: NestedRestoreTicket) -> bool {
    (&*core::ptr::addr_of!(PARENTS))
        .get(ticket.index)
        .and_then(Option::as_ref)
        .is_some_and(|parent| {
            parent.phase == ParentPhase::RestorePending
                && ticket_matches(ticket, parent)
                && restore_refusal_is_retryable(parent)
        })
}

/// Match an already authenticated pump route and its Reply against this retained parent.
/// Callers must first resolve `PumpChannel` through `channel_route`; a bare Reply number is not
/// physical authority. This check neither transfers ownership nor enters a native operation.
pub(crate) unsafe fn ticket_matches_channel(
    ticket: NestedRestoreTicket,
    route: PeerRoute,
    reply: u64,
) -> bool {
    pending_ticket(ticket) && retained_ticket_matches_channel(ticket, route, reply)
}

/// A quarantined result still owns the exact parent and caller Reply, although it grants no
/// retry. Capture that ownership at the outer boundary without treating it as native authority.
pub(crate) unsafe fn retained_ticket_matches_channel(
    ticket: NestedRestoreTicket,
    route: PeerRoute,
    reply: u64,
) -> bool {
    if reply == 0 || ticket.identity.route() != route {
        return false;
    }
    let row = (&*core::ptr::addr_of!(PARENTS))
        .get(ticket.index).and_then(Option::as_ref);
    if row.is_none_or(|parent| {
        !matches!(parent.phase, ParentPhase::RestorePending | ParentPhase::Quarantined)
            || !ticket_matches(ticket, parent) || parent.reply != reply
    }) {
        return false;
    }
    let lane = ticket.identity.dispatch().lane();
    let active = lanes();
    active.peer_route(lane).ok() == Some(Some(route))
        && active.active_dispatch_identity(lane).ok() == Some(Some(ticket.identity.dispatch()))
        && active.binding(lane).is_ok_and(|binding| {
            binding.executor_id == route.identity().executor
                && binding.receive_endpoint == route.endpoint()
                && binding.reply_object == reply
        })
}

/// Select one exact row for a bounded retry; the selector itself authorizes no native effect.
pub(crate) unsafe fn restore_pending_ticket(ticket: NestedRestoreTicket) -> Result<(), Error> {
    if !pending_ticket(ticket) { return Err(Error::Admission); }
    let mut handle = Some(ParkedParentHandle {
        index: ticket.index,
        generation: ticket.generation,
        identity: ticket.identity,
    });
    restore_or_retain(&mut handle)
}
