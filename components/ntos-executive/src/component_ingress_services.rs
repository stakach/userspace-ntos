//! Retained autonomous services and asynchronous driver wait Replies.

use super::*;

#[derive(Clone, Copy, PartialEq)]
enum WaitPhase {
    Entering,
    Parked,
    ReplyEntered,
    Acknowledged,
    Resumed,
    CompletedAcknowledged,
    StoppedAcknowledged,
    Cancelled,
    Finished,
}
struct Wait {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
    phase: WaitPhase,
    completion: Option<ServiceCompletion>,
    registry: bool,
    autonomous: bool,
    resume_retry_at: u64,
    semantic_retired: bool,
}

#[derive(Clone, Copy)]
enum ServiceCompletion {
    Status(i32),
    Registry {
        status: i32,
        handle: u64,
        disposition: u64,
    },
}

impl ServiceCompletion {
    fn words(self) -> (u64, [u64; 4]) {
        match self {
            Self::Status(status) => (1, [status as u32 as u64, 0, 0, 0]),
            Self::Registry {
                status,
                handle,
                disposition,
            } => (4, [status as u32 as u64, handle, disposition, 0]),
        }
    }
}
static mut WAITS: Vec<Wait> = Vec::new();

unsafe fn wait_exact(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
) -> Option<&'static mut Wait> {
    (&mut *core::ptr::addr_of_mut!(WAITS))
        .iter_mut()
        .find(|wait| {
            wait.route == route
                && wait.dispatch == dispatch
                && wait.reply == reply
                && wait.token == token
        })
}

pub(crate) unsafe fn park_service(route: PeerRoute, token: u64) -> Result<(), Error> {
    park(route, token, false)
}

pub(crate) unsafe fn park_registry_service(route: PeerRoute, token: u64) -> Result<(), Error> {
    park(route, token, true)
}

unsafe fn park(route: PeerRoute, token: u64, registry: bool) -> Result<(), Error> {
    let source = physical_source(route)?;
    if !matches!(
        source.kind,
        PhysicalSourceKind::Primary | PhysicalSourceKind::SystemThread { .. }
    ) {
        return Err(Error::Protocol);
    }
    let dispatch = dispatch(route)?;
    let reply = current_reply(route)?;
    let autonomous = matches!(source.kind, PhysicalSourceKind::SystemThread { .. });
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
            registry,
            autonomous,
            resume_retry_at: 0,
            semantic_retired: false,
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
        registry,
        autonomous,
        resume_retry_at: 0,
        semantic_retired: false,
    };
    if lanes()
        .suspend_running(route.identity().lane, reply, token)
        .is_err()
    {
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
    wake_with_completion(
        route,
        dispatch,
        reply,
        token,
        ServiceCompletion::Status(status),
    )
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
    wake_with_completion(
        route,
        dispatch,
        reply,
        token,
        ServiceCompletion::Registry {
            status,
            handle,
            disposition,
        },
    )
}

/// A send may have consumed the physical Reply even if its wrapper returned an error.
/// Reconcile from the retained Call's acknowledgement bit; never invoke the Reply again.
pub(crate) unsafe fn reconcile_registry_service_reply(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
) -> Result<bool, Error> {
    let wait = (&*core::ptr::addr_of!(WAITS))
        .iter()
        .find(|row| {
            row.registry
                && row.route == route
                && row.dispatch == dispatch
                && row.reply == reply
                && row.token == token
        })
        .ok_or(Error::Admission)?;
    let phase = wait.phase;
    match phase {
        WaitPhase::Acknowledged
        | WaitPhase::Resumed
        | WaitPhase::CompletedAcknowledged
        | WaitPhase::StoppedAcknowledged
        | WaitPhase::Finished => {
            return Ok(true);
        }
        WaitPhase::ReplyEntered => {}
        _ => return Ok(false),
    }
    let acknowledged = owner()
        .receiver
        .as_ref()
        .expect("ready receiver")
        .stored_reply_acknowledged(route, dispatch, reply)
        .map_err(|_| Error::Retirement)?;
    if acknowledged {
        let wait = wait_exact(route, dispatch, reply, token).ok_or(Error::Retirement)?;
        if wait.phase != WaitPhase::ReplyEntered {
            return Err(Error::Retirement);
        }
        wait.phase = WaitPhase::Acknowledged;
        wait.resume_retry_at = crate::monotonic_time_100ns();
    }
    Ok(acknowledged)
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
    {
        let wait = wait_exact(route, dispatch, reply, token).ok_or(Error::Admission)?;
        if wait.phase != WaitPhase::Parked {
            return Err(Error::Admission);
        }
        wait.completion = Some(completion);
        wait.phase = WaitPhase::ReplyEntered;
    }
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
    let wait = wait_exact(route, dispatch, reply, token).ok_or(Error::Retirement)?;
    if wait.phase != WaitPhase::ReplyEntered {
        return Err(Error::Retirement);
    }
    wait.phase = WaitPhase::Acknowledged;
    wait.resume_retry_at = crate::monotonic_time_100ns();
    Ok(())
}

/// Complete one acknowledged autonomous registry service by its retained route and token.
/// A busy lane remains owned and is retried by the normal timer source.
pub(crate) unsafe fn resume_acknowledged_registry_services() -> Result<bool, Error> {
    let now = crate::monotonic_time_100ns();
    let route = (&*core::ptr::addr_of!(WAITS))
        .iter()
        .find(|wait| {
            wait.registry
                && wait.autonomous
                && matches!(wait.phase, WaitPhase::Acknowledged | WaitPhase::Resumed)
                && wait.resume_retry_at <= now
        })
        .map(|wait| wait.route);
    let Some(route) = route else {
        return Ok(false);
    };
    match resume_service(route) {
        Ok(true) => return Ok(true),
        Ok(false) => {}
        Err(error) => {
            // The external token is already retired. Retain the acknowledged Call and retry
            // only its physical completion after the query becomes available.
            if !(&*core::ptr::addr_of!(WAITS)).iter().any(|wait| {
                wait.registry
                    && wait.autonomous
                    && wait.route == route
                    && wait.phase == WaitPhase::Resumed
            }) {
                return Err(error);
            }
        }
    }
    let wait = (&mut *core::ptr::addr_of_mut!(WAITS))
        .iter_mut()
        .find(|wait| {
            wait.registry
                && wait.autonomous
                && wait.route == route
                && matches!(wait.phase, WaitPhase::Acknowledged | WaitPhase::Resumed)
        })
        .ok_or(Error::Retirement)?;
    wait.resume_retry_at = now.saturating_add(1_000_000);
    Ok(false)
}

pub(crate) unsafe fn registry_service_resume_next_deadline() -> Option<u64> {
    (&*core::ptr::addr_of!(WAITS))
        .iter()
        .filter(|wait| {
            wait.registry
                && wait.autonomous
                && matches!(wait.phase, WaitPhase::Acknowledged | WaitPhase::Resumed)
        })
        .map(|wait| wait.resume_retry_at)
        .min()
}

/// Finalize ACK bookkeeping when this continuation can reacquire root execution. A primary
/// remains in its dispatch; an autonomous service finishes only its one Call invocation.
pub(crate) unsafe fn resume_service(route: PeerRoute) -> Result<bool, Error> {
    let source = physical_source(route)?;
    let Some((dispatch, reply, token, phase)) = (&*core::ptr::addr_of!(WAITS))
        .iter()
        .find(|row| {
            row.route == route && matches!(row.phase, WaitPhase::Acknowledged | WaitPhase::Resumed)
        })
        .map(|wait| (wait.dispatch, wait.reply, wait.token, wait.phase))
    else {
        return Ok(false);
    };
    if phase == WaitPhase::Acknowledged {
        if !lanes()
            .can_resume_external(route.identity().lane, reply, token)
            .map_err(|_| Error::Admission)?
        {
            return Ok(false);
        }
        lanes()
            .resume_external(route.identity().lane, reply, token)
            .map_err(|_| Error::Admission)?;
        lanes()
            .retire_external_running(route.identity().lane, reply, token)
            .map_err(|_| Error::Admission)?;
        let wait = wait_exact(route, dispatch, reply, token).ok_or(Error::Retirement)?;
        if wait.phase != WaitPhase::Acknowledged {
            return Err(Error::Retirement);
        }
        wait.phase = WaitPhase::Resumed;
    }
    if matches!(source.kind, PhysicalSourceKind::SystemThread { .. }) {
        finish_autonomous(route)?;
    }
    let wait = wait_exact(route, dispatch, reply, token).ok_or(Error::Retirement)?;
    if wait.phase != WaitPhase::Resumed {
        return Err(Error::Retirement);
    }
    wait.phase = if wait.registry && !wait.semantic_retired {
        WaitPhase::CompletedAcknowledged
    } else {
        WaitPhase::Finished
    };
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
    let Some((dispatch, reply, token, phase, registry)) = (&*core::ptr::addr_of!(WAITS))
        .iter()
        .find(|row| row.route == route && row.phase != WaitPhase::Finished)
        .map(|wait| {
            (
                wait.dispatch,
                wait.reply,
                wait.token,
                wait.phase,
                wait.registry,
            )
        })
    else {
        return Ok(());
    };
    if matches!(phase, WaitPhase::Cancelled | WaitPhase::StoppedAcknowledged) {
        return Ok(());
    }
    if phase == WaitPhase::CompletedAcknowledged {
        // The Reply and retained Call completed already; no external token remains to cancel.
        return Ok(());
    }
    let owner = owner();
    let installation = owner
        .installations
        .iter()
        .find(|row| row.route() == route)
        .ok_or(Error::UnknownPeer)?;
    if phase == WaitPhase::Resumed {
        if !matches!(
            installation.phase(),
            PeerInstallationPhase::Retiring(
                nt_component_suspension::PeerRetirementPhase::Stopped
                    | nt_component_suspension::PeerRetirementPhase::Drained
                    | nt_component_suspension::PeerRetirementPhase::ClearingFault
                    | nt_component_suspension::PeerRetirementPhase::FaultCleared
                    | nt_component_suspension::PeerRetirementPhase::DeletingChild
                    | nt_component_suspension::PeerRetirementPhase::ChildDeleted
                    | nt_component_suspension::PeerRetirementPhase::DeletingRoot
                    | nt_component_suspension::PeerRetirementPhase::RootDeleted
            )
        ) {
            return Err(Error::Retirement);
        }
        // The external token was already retired. The stopped-route drain owns the retained
        // Call; keep the semantic tombstone until its original provider owner also retires.
        let wait = wait_exact(route, dispatch, reply, token).ok_or(Error::Retirement)?;
        wait.phase = if wait.semantic_retired {
            WaitPhase::Finished
        } else {
            WaitPhase::StoppedAcknowledged
        };
        return Ok(());
    }
    let acknowledged = if registry {
        match phase {
            WaitPhase::Acknowledged => true,
            WaitPhase::ReplyEntered => owner
                .receiver
                .as_ref()
                .expect("ready receiver")
                .stored_reply_acknowledged(route, dispatch, reply)
                .map_err(|_| Error::Retirement)?,
            _ => false,
        }
    } else {
        false
    };
    lanes()
        .cancel_external_stopped(
            installation,
            owner.peers.as_ref().expect("ready peers"),
            dispatch,
            token,
        )
        .map_err(|_| Error::Retirement)?;
    let wait = wait_exact(route, dispatch, reply, token).ok_or(Error::Retirement)?;
    if wait.phase != phase {
        return Err(Error::Retirement);
    }
    wait.phase = if registry {
        if acknowledged {
            if wait.semantic_retired {
                WaitPhase::Finished
            } else {
                WaitPhase::StoppedAcknowledged
            }
        } else {
            WaitPhase::Cancelled
        }
    } else {
        WaitPhase::Finished
    };
    Ok(())
}

/// A sealed stop/drain cancellation receipt, not inference from a missing route or Reply.
pub(crate) unsafe fn registry_service_cancelled(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
) -> bool {
    (&*core::ptr::addr_of!(WAITS)).iter().any(|wait| {
        wait.registry
            && wait.route == route
            && wait.dispatch == dispatch
            && wait.reply == reply
            && wait.token == token
            && wait.phase == WaitPhase::Cancelled
    })
}

pub(crate) unsafe fn acknowledge_registry_service_cancellation(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
) -> Result<(), Error> {
    let wait = (&mut *core::ptr::addr_of_mut!(WAITS))
        .iter_mut()
        .find(|wait| {
            wait.registry
                && wait.route == route
                && wait.dispatch == dispatch
                && wait.reply == reply
                && wait.token == token
                && wait.phase == WaitPhase::Cancelled
        })
        .ok_or(Error::Retirement)?;
    wait.phase = WaitPhase::Finished;
    Ok(())
}

/// The Reply was already acknowledged when a stopped route consumed its external token.
/// Release this tombstone only after the semantic owner finishes its own cleanup.
pub(crate) unsafe fn retire_stopped_acknowledged_registry_service(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    token: u64,
) -> Result<(), Error> {
    let wait = (&mut *core::ptr::addr_of_mut!(WAITS))
        .iter_mut()
        .find(|wait| {
            wait.registry
                && wait.route == route
                && wait.dispatch == dispatch
                && wait.reply == reply
                && wait.token == token
        })
        .ok_or(Error::Retirement)?;
    match wait.phase {
        WaitPhase::StoppedAcknowledged | WaitPhase::CompletedAcknowledged => {
            wait.phase = WaitPhase::Finished
        }
        WaitPhase::Acknowledged | WaitPhase::Resumed => wait.semantic_retired = true,
        WaitPhase::Finished => {}
        _ => return Err(Error::Retirement),
    }
    Ok(())
}
