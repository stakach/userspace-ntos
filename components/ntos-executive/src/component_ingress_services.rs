//! Retained autonomous services and asynchronous driver wait Replies.

use super::*;

#[derive(Clone, Copy, PartialEq)]
enum WaitPhase {
    Entering,
    Parked,
    ReplyEntered,
    Acknowledged,
    Finished,
}
struct Wait {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
    phase: WaitPhase,
    completion: Option<ServiceCompletion>,
}

#[derive(Clone, Copy)]
enum ServiceCompletion {
    Status(i32),
    Registry { status: i32, handle: u64, disposition: u64 },
}

impl ServiceCompletion {
    fn words(self) -> (u64, [u64; 4]) {
        match self {
            Self::Status(status) => (1, [status as u32 as u64, 0, 0, 0]),
            Self::Registry { status, handle, disposition } =>
                (4, [status as u32 as u64, handle, disposition, 0]),
        }
    }
}
static mut WAITS: Vec<Wait> = Vec::new();

pub(crate) unsafe fn park_service(route: PeerRoute, token: u64) -> Result<(), Error> {
    let source = physical_source(route)?;
    if !matches!(
        source.kind,
        PhysicalSourceKind::Primary | PhysicalSourceKind::SystemThread { .. }
    ) {
        return Err(Error::Protocol);
    }
    let dispatch = dispatch(route)?;
    let reply = current_reply(route)?;
    let waits = &mut *core::ptr::addr_of_mut!(WAITS);
    if token == 0
        || waits
            .iter()
            .any(|row| row.route == route && row.phase != WaitPhase::Finished)
    {
        return Err(Error::Admission);
    }
    let index = if let Some(index) = waits
        .iter()
        .position(|row| row.phase == WaitPhase::Finished)
    {
        index
    } else {
        let _durable = crate::allocator::enter_durable();
        waits.try_reserve(1).map_err(|_| Error::Capacity)?;
        waits.push(Wait {
            route,
            dispatch,
            reply,
            token,
            phase: WaitPhase::Entering,
            completion: None,
        });
        waits.len() - 1
    };
    waits[index] = Wait {
        route,
        dispatch,
        reply,
        token,
        phase: WaitPhase::Entering,
        completion: None,
    };
    if lanes().suspend_running(route.identity().lane, reply, token).is_err() {
        // Lane admission has no native effect and preserves its prior phase on failure.
        waits[index].phase = WaitPhase::Finished;
        return Err(Error::Admission);
    }
    waits[index].phase = WaitPhase::Parked;
    Ok(())
}

pub(crate) unsafe fn wake_service(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
    status: i32,
) -> Result<(), Error> {
    wake_with_completion(route, dispatch, reply, token, ServiceCompletion::Status(status))
}

pub(crate) unsafe fn wake_registry_service(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
    status: i32,
    handle: u64,
    disposition: u64,
) -> Result<(), Error> {
    wake_with_completion(route, dispatch, reply, token,
        ServiceCompletion::Registry { status, handle, disposition })
}

unsafe fn wake_with_completion(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
    completion: ServiceCompletion,
) -> Result<(), Error> {
    let result = wake_service_inner(route, dispatch, reply, token, completion);
    if result.is_err() {
        crate::spawn_hosts::PUMP_REPLY_ERRORS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    result
}

unsafe fn wake_service_inner(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
    completion: ServiceCompletion,
) -> Result<(), Error> {
    if self::dispatch(route)? != dispatch || current_reply(route)? != reply {
        return Err(Error::Admission);
    }
    let waits = &mut *core::ptr::addr_of_mut!(WAITS);
    let wait = waits
        .iter_mut()
        .find(|row| {
            row.route == route
                && row.dispatch == dispatch
                && row.reply == reply
                && row.token == token
                && row.phase == WaitPhase::Parked
        })
        .ok_or(Error::Admission)?;
    wait.completion = Some(completion);
    wait.phase = WaitPhase::ReplyEntered;
    let (info, [m0, m1, m2, m3]) = completion.words();
    let owner = owner();
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let result = owner
        .receiver
        .as_mut()
        .expect("ready receiver")
        .reply_parked_stored(
            route,
            dispatch,
            token,
            lanes(),
            owner.peers.as_ref().expect("ready peers"),
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            |reply| {
                if crate::reply_on(reply, info, m0, m1, m2, m3) == 0 {
                    IngressReplyObservation::Acknowledged
                } else {
                    IngressReplyObservation::Indeterminate
                }
            },
        );
    if !matches!(result, Ok(IngressReplyObservation::Acknowledged)) {
        return Err(Error::Reply);
    }
    wait.phase = WaitPhase::Acknowledged;
    Ok(())
}

/// Finalize ACK bookkeeping when this continuation can reacquire root execution. A primary
/// remains in its dispatch; an autonomous service finishes only its one Call invocation.
pub(crate) unsafe fn resume_service(route: PeerRoute) -> Result<bool, Error> {
    let source = physical_source(route)?;
    let waits = &mut *core::ptr::addr_of_mut!(WAITS);
    let Some(wait) = waits
        .iter_mut()
        .find(|row| row.route == route && row.phase == WaitPhase::Acknowledged)
    else {
        return Ok(false);
    };
    if !lanes()
        .can_resume_external(route.identity().lane, wait.reply, wait.token)
        .map_err(|_| Error::Admission)?
    {
        return Ok(false);
    }
    lanes()
        .resume_external(route.identity().lane, wait.reply, wait.token)
        .map_err(|_| Error::Admission)?;
    lanes()
        .retire_external_running(route.identity().lane, wait.reply, wait.token)
        .map_err(|_| Error::Admission)?;
    if matches!(source.kind, PhysicalSourceKind::SystemThread { .. }) {
        finish_autonomous(route)?;
    }
    wait.phase = WaitPhase::Finished;
    Ok(true)
}

pub(crate) unsafe fn finish_autonomous(route: PeerRoute) -> Result<(), Error> {
    if !matches!(
        physical_source(route)?.kind,
        PhysicalSourceKind::SystemThread { .. }
    ) {
        return Err(Error::Protocol);
    }
    let dispatch = dispatch(route)?;
    let owner = owner();
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    owner
        .receiver
        .as_mut()
        .expect("ready receiver")
        .complete_stored(
            route,
            dispatch,
            lanes(),
            owner.peers.as_mut().expect("ready peers"),
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
        )
        .map_err(|_| Error::Protocol)?;
    Ok(())
}

/// The native semantic owner has requested cancellation, not successful wait completion.
/// Only the sealed installation's stop acknowledgement can authorize removing its wait token.
pub(crate) unsafe fn cancel_parked_service(route: PeerRoute) -> Result<(), Error> {
    if resolve(route, true).is_none() {
        return Err(Error::PhysicalIdentity);
    }
    let waits = &mut *core::ptr::addr_of_mut!(WAITS);
    let Some(wait) = waits
        .iter_mut()
        .find(|row| row.route == route && row.phase != WaitPhase::Finished)
    else {
        return Ok(());
    };
    let owner = owner();
    let installation = owner
        .installations
        .iter()
        .find(|row| row.route() == route)
        .ok_or(Error::UnknownPeer)?;
    lanes()
        .cancel_external_stopped(
            installation,
            owner.peers.as_ref().expect("ready peers"),
            wait.dispatch,
            wait.token,
        )
        .map_err(|_| Error::Retirement)?;
    wait.phase = WaitPhase::Finished;
    Ok(())
}
