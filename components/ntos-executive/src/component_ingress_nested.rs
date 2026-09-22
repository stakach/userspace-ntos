//! Wait-preserving physical exclusion while another component owns root dispatch.

use super::*;
use nt_component_suspension::NestedExecutionScope;

struct Parent {
    route: PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    hold: Option<u64>,
    scope: Option<NestedExecutionScope>,
    release_entered: bool,
}

// Records are never removed before both canonical restoration and physical release acknowledge.
static mut PARENTS: Vec<Option<Parent>> = Vec::new();

pub(crate) unsafe fn park_current() -> Result<Option<usize>, Error> {
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
    rows[index].as_mut().expect("retained parent").scope = Some(scope);
    Ok(Some(index))
}

pub(crate) unsafe fn restore(index: Option<usize>) -> Result<(), Error> {
    let Some(index) = index else {
        return Ok(());
    };
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    let parent = rows
        .get_mut(index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
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
    Ok(())
}
