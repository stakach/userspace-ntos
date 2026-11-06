//! Wait-preserving physical exclusion while another component owns root dispatch.

use super::*;
use super::physical_hold::PhysicalExecutionHold;
use nt_component_suspension::{NestedExecutionIdentity, NestedExecutionScope};
use nt_user_host::physical_execution_restore::RestoreStep;

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
    if scope.identity() != handle.identity || !parent.physical.canonical_pending() {
        return Err(Error::Admission);
    }
    use_scope(scope)
}

struct Parent {
    physical: PhysicalExecutionHold,
    scope: Option<NestedExecutionScope>,
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
        physical: PhysicalExecutionHold::new(route, dispatch),
        scope: None,
        receive_bound: false,
        receive_restore: None,
    });
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    // Suspend cancels IPC in the microkernel. Execution holds preserve the held Call, donated
    // scheduling context and queued message, including the receive continuation after Reply ACK.
    rows[index].as_mut().expect("retained parent").physical.acquire()?;
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
    if scope.identity() != handle.identity || !parent.physical.canonical_pending() || parent.receive_bound {
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
    if scope.identity() != handle.identity || !permit.matches_scope(scope) || !parent.physical.canonical_pending()
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
