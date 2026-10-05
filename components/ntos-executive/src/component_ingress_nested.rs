//! Wait-preserving physical exclusion while another component owns root dispatch.

use super::*;
use nt_component_suspension::{NestedExecutionIdentity, NestedExecutionScope};

/// The slot is storage, not authority. A recycled slot cannot restore a different parent scope.
#[must_use = "retain the exact parked parent until restoration acknowledges"]
pub(crate) struct ParkedParentHandle {
    index: usize,
    identity: NestedExecutionIdentity,
}

impl ParkedParentHandle {
    pub(crate) fn identity(&self) -> NestedExecutionIdentity {
        self.identity
    }
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
    if scope.identity() != handle.identity || parent.release_entered {
        return Err(Error::Admission);
    }
    use_scope(scope)
}

struct Parent {
    route: PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    hold: Option<u64>,
    scope: Option<NestedExecutionScope>,
    release_entered: bool,
    receive_bound: bool,
    receive_restore:
        Option<nt_user_host::receive_child_barrier::ReceiveRestorePermit<crate::HostedThreadRole>>,
}

// Records are never removed before both canonical restoration and physical release acknowledge.
static mut PARENTS: Vec<Option<Parent>> = Vec::new();

pub(crate) unsafe fn park_current() -> Result<Option<ParkedParentHandle>, Error> {
    let Some(lane) = lanes().running() else {
        return Ok(None);
    };
    let route = lanes()
        .peer_route(lane)
        .map_err(|_| Error::Admission)?
        .ok_or(Error::Admission)?;
    let dispatch = dispatch(route)?;
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    let index = if let Some(index) = rows.iter().position(Option::is_none) {
        index
    } else {
        let _durable = crate::allocator::enter_durable();
        rows.try_reserve(1).map_err(|_| Error::Capacity)?;
        rows.push(None);
        rows.len() - 1
    };
    rows[index] = Some(Parent {
        route,
        dispatch,
        hold: None,
        scope: None,
        release_entered: false,
        receive_bound: false,
        receive_restore: None,
    });
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    // Suspend cancels IPC in the microkernel. Execution holds preserve the held Call, donated
    // scheduling context and queued message, including the receive continuation after Reply ACK.
    let hold = sel4_rt::execution_hold::acquire(route.identity().executor)
        .map_err(|_| Error::Admission)?;
    rows[index].as_mut().expect("retained parent").hold = Some(hold);
    crate::driver_launch::driver_thread_projection::hold(route, dispatch)
        .map_err(|_| Error::Admission)?;
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
        )
        .map_err(|_| Error::Admission)?;
    let identity = scope.identity();
    rows[index].as_mut().expect("retained parent").scope = Some(scope);
    Ok(Some(ParkedParentHandle { index, identity }))
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
    if scope.identity() != handle.identity || parent.release_entered || parent.receive_bound {
        return Err(Error::Admission);
    }
    barrier
        .bind_parent(scope, dispatch)
        .map_err(|_| Error::Admission)?;
    parent.receive_bound = true;
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
    if scope.identity() != handle.identity
        || parent.release_entered
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
    if scope.identity() != handle.identity || !permit.matches_scope(scope) || parent.release_entered
    {
        return Err(Error::Admission);
    }
    use_permit(scope, permit)
}

pub(crate) unsafe fn restore(handle: &mut Option<ParkedParentHandle>) -> Result<(), Error> {
    let Some(ticket) = handle.as_ref() else {
        return Ok(());
    };
    let index = ticket.index;
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    let parent = rows
        .get_mut(index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    if parent.scope.as_ref().map(NestedExecutionScope::identity) != Some(ticket.identity) {
        return Err(Error::Admission);
    }
    if parent.receive_bound
        && parent.receive_restore.as_ref().is_none_or(|permit| {
            !permit.matches_scope(parent.scope.as_ref().expect("validated scope"))
        })
    {
        return Err(Error::Admission);
    }
    if parent.release_entered || resolve(parent.route, false).is_none() {
        return Err(Error::Admission);
    }
    let hold = parent.hold.ok_or(Error::Admission)?;
    let scope = parent.scope.as_mut().ok_or(Error::Admission)?;
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
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
    crate::driver_launch::driver_thread_projection::restore(parent.route, parent.dispatch)
        .map_err(|_| Error::Admission)?;
    parent.release_entered = true;
    sel4_rt::execution_hold::release(parent.route.identity().executor, hold)
        .map_err(|_| Error::Admission)?;
    crate::driver_launch::driver_thread_projection::restored(parent.route, parent.dispatch)
        .map_err(|_| Error::Admission)?;
    rows[index] = None;
    *handle = None;
    Ok(())
}
