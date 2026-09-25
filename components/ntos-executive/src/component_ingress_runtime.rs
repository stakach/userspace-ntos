//! Serialized native ownership transactions for the shared component endpoint.

use super::*;
use crate::service_sec_image::{ComponentLanes, COMPONENT_SUSPENSIONS};
use nt_component_suspension::{
    IngressReplyObservation, LaneDispatchIdentity, PeerRetirementEffect,
};

#[path = "component_ingress_sources.rs"]
mod sources;
use sources::{IngressSourceIdentity, IngressSourceRegistry};
pub(crate) use sources::{PhysicalDomain, PhysicalSource, PhysicalSourceKind};

#[path = "component_ingress_nested.rs"]
pub(crate) mod nested;

#[path = "component_ingress_services.rs"]
mod services;
pub(crate) use services::{
    acknowledge_retained_service_cancellation, cancel_parked_service, finish_autonomous,
    park_retained_service, park_service, reconcile_retained_service_reply,
    retained_service_cancelled, retained_service_resume_next_deadline,
    resume_acknowledged_retained_services, resume_service,
    retire_stopped_acknowledged_retained_service,
    wake_file_create_service, wake_query_path_rejected_service, wake_query_path_service,
    wake_registry_service, wake_service,
};

#[path = "component_ingress_retirement.rs"]
mod retirement;
pub(crate) use retirement::retire;

#[path = "component_ingress_hosted.rs"]
mod hosted;
pub(crate) use hosted::{
    can_park_hosted_reply, cancel_hosted, cancel_hosted_caller, defer_hosted_delivery,
    finish_acknowledged_hosted_reply, hosted_can_resume, hosted_cancellation_proven,
    hosted_reply_cancelled, owns_hosted_reply, release_hosted_reply, reply_hosted, restart_hosted,
    stop_and_cancel_hosted, stop_hosted_caller, take_hosted_with,
};

const RETAINED_CALL_CAPACITY: usize = 256;
const PEER_CAPACITY: usize = 256;

#[derive(Debug)]
pub(crate) enum Error {
    Initialization,
    Source,
    Capacity,
    Publication,
    UnknownPeer,
    PhysicalIdentity,
    Startup,
    Receive,
    Retain,
    Protocol,
    Fault,
    Admission,
    Reply,
    Retirement,
}

struct NativePeer {
    source: IngressSourceIdentity,
    physical: PhysicalSource,
    verify: unsafe fn(PhysicalSource) -> bool,
    route: Option<PeerRoute>,
    quarantined: bool,
    bootstrap: bool,
}

static mut SOURCES: IngressSourceRegistry = IngressSourceRegistry::new();
static mut NATIVE_PEERS: Vec<NativePeer> = Vec::new();
static mut INITIAL_REPLIES: Vec<Option<ComponentIngress<ReceivedMessage>>> = Vec::new();

unsafe fn lanes() -> &'static mut ComponentLanes {
    &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS)
}

unsafe fn owner() -> &'static mut NativeSharedIngress {
    &mut *core::ptr::addr_of_mut!(SHARED_INGRESS)
}

/// These callbacks inspect retained physical owners only, with no scheduling or IPC effects.
unsafe fn resolve(route: PeerRoute, allow_retiring: bool) -> Option<u64> {
    let record = (&*core::ptr::addr_of!(NATIVE_PEERS))
        .iter()
        .find(|peer| peer.route == Some(route))?;
    if record.source.domain() != route.identity().domain
        || record.source.generation() != route.identity().domain_generation
        || record.physical.tcb != route.identity().executor
        || (!allow_retiring && record.quarantined)
    {
        return None;
    }
    let sources = &*core::ptr::addr_of!(SOURCES);
    let physical = if record.quarantined {
        sources.resolve_retiring(record.source, |source| (record.verify)(source))
    } else {
        sources.resolve(record.source, |source| (record.verify)(source))
    }
    .ok()?;
    Some(physical.tcb)
}

pub(crate) unsafe fn prepare(probe_tcb: u64) -> Result<u64, Error> {
    let owner = owner();
    if !owner.attempted {
        let _durable = crate::allocator::enter_durable();
        owner
            .initialize(RETAINED_CALL_CAPACITY, PEER_CAPACITY, lanes(), probe_tcb)
            .map_err(|_| Error::Initialization)?;
    }
    if !owner.ready {
        return Err(Error::Initialization);
    }
    Ok(owner.receiver.as_ref().expect("ready receiver").endpoint())
}

pub(crate) unsafe fn allocate_reply(probe_tcb: u64) -> Result<u64, Error> {
    prepare(probe_tcb)?;
    let pending = &mut *core::ptr::addr_of_mut!(INITIAL_REPLIES);
    let index = if let Some(index) = pending.iter().position(Option::is_none) {
        index
    } else {
        let _durable = crate::allocator::enter_durable();
        pending.try_reserve(1).map_err(|_| Error::Capacity)?;
        pending.push(None);
        pending.len() - 1
    };
    let owner = owner();
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let reply = owner
        .replacements
        .as_mut()
        .expect("ready pool")
        .take_initial_reply(
            owner.receiver.as_ref().expect("ready receiver"),
            lanes(),
            |reply| crate::spawn_hosts::query_component_reply_binding(probe_tcb, reply),
        )
        .map_err(|_| Error::Reply)?;
    let cap = reply.reply();
    pending[index] = Some(reply);
    Ok(cap)
}

/// Return a constructor's unpublished initial Reply by moving its retained owner, not deleting
/// or reconstructing a capability. A canonical lane, held Call or another pool alias refuses.
/// The caller supplies a live retained probe TCB and clears its numeric snapshot only on success.
pub(crate) unsafe fn return_initial_reply(reply: u64, probe_tcb: u64) -> Result<(), Error> {
    if reply == 0 || probe_tcb == 0 {
        return Err(Error::PhysicalIdentity);
    }
    let pending = &mut *core::ptr::addr_of_mut!(INITIAL_REPLIES);
    let mut matching = pending
        .iter()
        .enumerate()
        .filter(|(_, owner)| owner.as_ref().is_some_and(|owner| owner.reply() == reply));
    let index = matching
        .next()
        .map(|(index, _)| index)
        .ok_or(Error::Reply)?;
    if matching.next().is_some() {
        return Err(Error::Reply);
    }
    let owner = owner();
    if !owner.ready {
        return Err(Error::Initialization);
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    owner
        .replacements
        .as_mut()
        .ok_or(Error::Initialization)?
        .insert_pending(
            &mut pending[index],
            owner.receiver.as_ref().ok_or(Error::Initialization)?,
            lanes(),
            |reply| crate::spawn_hosts::query_component_reply_binding(probe_tcb, reply),
        )
        .map_err(|_| Error::Reply)
}

/// Keep the stopped worker's complete physical receipt before calling. No worker can execute
/// until its exact badged child alias and TCB fault handler have both been acknowledged.
pub(crate) unsafe fn register(
    physical: PhysicalSource,
    reply: u64,
    cnode: u64,
    verify: unsafe fn(PhysicalSource) -> bool,
) -> Result<PeerRoute, Error> {
    if cnode == 0 || cnode == crate::CAP_INIT_THREAD_CNODE || reply == 0 {
        return Err(Error::PhysicalIdentity);
    }
    let initial_index = (&*core::ptr::addr_of!(INITIAL_REPLIES))
        .iter()
        .position(|owner| owner.as_ref().is_some_and(|owner| owner.reply() == reply))
        .ok_or(Error::Reply)?;
    let endpoint = prepare(physical.tcb)?;
    let _durable = crate::allocator::enter_durable();
    let peers = &mut *core::ptr::addr_of_mut!(NATIVE_PEERS);
    peers.try_reserve(1).map_err(|_| Error::Capacity)?;
    let source = (&mut *core::ptr::addr_of_mut!(SOURCES))
        .intern(physical, |source| verify(source))
        .map_err(|_| Error::Source)?;
    if peers.iter().any(|peer| peer.source == source) {
        return Err(Error::Publication);
    }
    let index = peers.len();
    peers.push(NativePeer {
        source,
        physical,
        verify,
        route: None,
        quarantined: false,
        bootstrap: false,
    });
    let owner = owner();
    let lanes = lanes();
    let route = owner
        .allocate_publish_peer(
            lanes,
            source.domain(),
            source.generation(),
            LaneBinding {
                executor_id: physical.tcb,
                receive_endpoint: endpoint,
                reply_object: reply,
            },
        )
        .map_err(|_| Error::Publication)?;
    peers[index].route = Some(route);
    // The staged lane is now the sole canonical owner; the constructor retains only a snapshot.
    (&mut *core::ptr::addr_of_mut!(INITIAL_REPLIES))[initial_index] = None;
    owner
        .export_peer(route, source.domain(), source.generation(), lanes, |_| {
            Some(PeerCapabilityDestination {
                cnode,
                slot: crate::CT_FAULT,
            })
        })
        .map_err(|_| Error::Publication)?;
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    owner
        .installations
        .iter_mut()
        .find(|row| row.route() == route)
        .ok_or(Error::UnknownPeer)?
        .bind_space(physical.pml4, |space| {
            let status =
                crate::tcb_set_space_r(space.executor, space.fault_slot, space.cnode, space.vspace);
            if status == 0 {
                Ok(())
            } else {
                Err(status)
            }
        })
        .map_err(|_| Error::Publication)?;
    Ok(route)
}

pub(crate) unsafe fn start_worker(
    route: PeerRoute,
    worker: &crate::spawn_hosts::SpawnedComponentWorker,
) -> Result<(), Error> {
    if resolve(route, false) != Some(worker.tcb) {
        return Err(Error::PhysicalIdentity);
    }
    super::start_worker_peer(
        route,
        route.identity().domain,
        route.identity().domain_generation,
        lanes(),
        worker,
    )
    .map_err(|_| Error::Startup)
}

pub(crate) unsafe fn start_bootstrap(
    route: PeerRoute,
    cnode: u64,
    sched_context: u64,
) -> Result<LaneDispatchIdentity, Error> {
    if resolve(route, false).is_none() || sched_context == 0 {
        return Err(Error::PhysicalIdentity);
    }
    let row = (&mut *core::ptr::addr_of_mut!(NATIVE_PEERS))
        .iter_mut()
        .find(|row| row.route == Some(route))
        .ok_or(Error::UnknownPeer)?;
    if row.bootstrap {
        return Err(Error::Startup);
    }
    let owner = owner();
    let lanes = lanes();
    let binding = lanes
        .binding(route.identity().lane)
        .map_err(|_| Error::Startup)?;
    let installation = owner
        .installations
        .iter_mut()
        .find(|row| row.route() == route)
        .ok_or(Error::UnknownPeer)?;
    row.bootstrap = true;
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    installation
        .start_bootstrap(
            owner.peers.as_ref().expect("ready peers"),
            route.identity().domain,
            route.identity().domain_generation,
            lanes,
            binding,
            nt_component_suspension::PeerSpaceBinding {
                executor: row.physical.tcb,
                cnode,
                vspace: row.physical.pml4,
                fault_slot: crate::CT_FAULT,
            },
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            |tcb| {
                let status =
                    crate::spawn_hosts::resume_spawned_component_worker(tcb, sched_context);
                if status == 0 {
                    Ok(())
                } else {
                    Err(status)
                }
            },
        )
        .map_err(|_| Error::Startup)
}

pub(crate) unsafe fn start_protocol(
    route: PeerRoute,
    cnode: u64,
    sched_context: u64,
) -> Result<(), Error> {
    if resolve(route, false).is_none() || sched_context == 0 {
        return Err(Error::PhysicalIdentity);
    }
    let source = physical_source(route)?;
    let owner = owner();
    let lanes = lanes();
    let binding = lanes
        .binding(route.identity().lane)
        .map_err(|_| Error::Startup)?;
    let installation = owner
        .installations
        .iter_mut()
        .find(|row| row.route() == route)
        .ok_or(Error::UnknownPeer)?;
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    installation
        .start(
            owner.peers.as_ref().expect("ready peers"),
            route.identity().domain,
            route.identity().domain_generation,
            lanes,
            binding,
            nt_component_suspension::PeerSpaceBinding {
                executor: source.tcb,
                cnode,
                vspace: source.pml4,
                fault_slot: crate::CT_FAULT,
            },
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            |tcb| {
                let status =
                    crate::spawn_hosts::resume_spawned_component_worker(tcb, sched_context);
                if status == 0 {
                    Ok(())
                } else {
                    Err(status)
                }
            },
        )
        .map_err(|_| Error::Startup)
}

pub(crate) unsafe fn start_autonomous(
    route: PeerRoute,
    cnode: u64,
    sched_context: u64,
) -> Result<(), Error> {
    let source = physical_source(route)?;
    if !matches!(source.kind, PhysicalSourceKind::SystemThread { .. }) || sched_context == 0 {
        return Err(Error::PhysicalIdentity);
    }
    let owner = owner();
    let lanes = lanes();
    let binding = lanes
        .binding(route.identity().lane)
        .map_err(|_| Error::Startup)?;
    let installation = owner
        .installations
        .iter_mut()
        .find(|row| row.route() == route)
        .ok_or(Error::UnknownPeer)?;
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    installation
        .start_autonomous(
            owner.peers.as_ref().expect("ready peers"),
            route.identity().domain,
            route.identity().domain_generation,
            lanes,
            binding,
            nt_component_suspension::PeerSpaceBinding {
                executor: source.tcb,
                cnode,
                vspace: source.pml4,
                fault_slot: crate::CT_FAULT,
            },
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            |tcb| {
                let status = crate::tcb_resume_r(tcb);
                if status == 0 {
                    Ok(())
                } else {
                    Err(status)
                }
            },
        )
        .map_err(|_| Error::Startup)
}

pub(crate) unsafe fn physical_source(route: PeerRoute) -> Result<PhysicalSource, Error> {
    if resolve(route, false).is_none() {
        return Err(Error::PhysicalIdentity);
    }
    (&*core::ptr::addr_of!(NATIVE_PEERS))
        .iter()
        .find(|row| row.route == Some(route))
        .map(|row| row.physical)
        .ok_or(Error::UnknownPeer)
}

pub(crate) unsafe fn retained_route(physical: PhysicalSource) -> Option<PeerRoute> {
    (&*core::ptr::addr_of!(NATIVE_PEERS))
        .iter()
        .find(|row| row.physical == physical)?
        .route
}

pub(crate) unsafe fn ready_protocol(
    route: PeerRoute,
    channel: &crate::spawn_hosts::PumpChannel,
    label: u64,
    expected: [u64; 4],
) -> Result<(), Error> {
    if channel_route(channel)? != Some(route) {
        return Err(Error::PhysicalIdentity);
    }
    let mut faults = 0;
    loop {
        match receive(IngressExecutionOwner::Startup(route), channel.tcb, true)? {
            Arrival::Hosted => {}
            Arrival::Notification(message) => {
                if !crate::spawn_hosts::pump_handle_executive_event_badge(message.badge()).0 {
                    return Err(Error::Protocol);
                }
            }
            Arrival::Call {
                route: sender,
                reply,
            } => {
                if sender != route {
                    continue;
                }
                let owner = owner();
                let info = owner
                    .receiver
                    .as_ref()
                    .expect("ready receiver")
                    .stored_message(route, reply)
                    .map_err(|_| Error::Receive)?
                    .info();
                if info == (6 << 12) | 4 {
                    let observation = owner
                        .service_startup_fault(
                            lanes(),
                            route,
                            reply,
                            channel,
                            faults,
                            faults,
                            |route| resolve(route, false),
                        )
                        .map_err(|_| Error::Fault)?;
                    if observation != IngressReplyObservation::Acknowledged {
                        return Err(Error::Fault);
                    }
                    owner
                        .finish_startup_fault(lanes(), route, reply, channel.tcb, |route| {
                            resolve(route, false)
                        })
                        .map_err(|_| Error::Fault)?;
                    faults += 1;
                    continue;
                }
                let _saved = crate::ipc_message::SavedMessageBuffer::capture();
                let mut publication = None;
                owner
                    .receiver
                    .as_mut()
                    .expect("ready receiver")
                    .ready_protocol_from_message(
                        route,
                        reply,
                        label,
                        lanes(),
                        owner.peers.as_ref().expect("ready peers"),
                        &mut publication,
                        |words: [u64; 4]| (words == expected).then_some(()),
                        |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
                    )
                    .map_err(|_| Error::Protocol)?;
                return Ok(());
            }
        }
    }
}

pub(crate) enum Arrival {
    Notification(ReceivedMessage),
    Hosted,
    Call { route: PeerRoute, reply: u64 },
}

/// Capture, classify and retain before returning to a handler. No borrowed owner crosses a
/// semantic handler, and an unrelated arrival remains owned for its own physical worker.
pub(crate) unsafe fn receive(
    execution: IngressExecutionOwner,
    probe_tcb: u64,
    blocking: bool,
) -> Result<Arrival, Error> {
    hosted::recycle_completed()?;
    let owner = owner();
    let lanes = lanes();
    owner
        .receive(lanes, execution, probe_tcb, blocking)
        .map_err(|_| Error::Receive)?;
    let peers = owner.peers.as_ref().expect("ready peers");
    let routes = peers;
    let mut resolver = |badge| {
        if nt_component_suspension::badge::valid_hosted_badge(badge) {
            crate::service_sec_image::hosted_ingress_binding(badge).map(|binding| binding.tcb)
        } else {
            let route = routes
                .resolve(badge)
                .or_else(|| routes.resolve_retiring(badge))?;
            resolve(route, true)
        }
    };
    // Classification needs a mutable receiver but not a mutable registry.
    let notification = super::super::classify(
        owner.receiver.as_mut().expect("ready receiver"),
        probe_tcb,
        &mut resolver,
    )
    .map_err(|_| Error::Receive)?;
    if let Some(message) = notification {
        return Ok(Arrival::Notification(message));
    }
    let receiver = owner.receiver.as_ref().expect("ready receiver");
    let badge = receiver.message().expect("classified Call").badge();
    let reply = receiver.reply();
    if nt_component_suspension::badge::valid_hosted_badge(badge) {
        hosted::retain(owner, lanes, badge, probe_tcb)?;
        return Ok(Arrival::Hosted);
    }
    let route = owner
        .peers
        .as_ref()
        .expect("ready peers")
        .resolve(badge)
        .or_else(|| {
            owner
                .peers
                .as_ref()
                .expect("ready peers")
                .resolve_retiring(badge)
        })
        .ok_or(Error::UnknownPeer)?;
    owner
        .retain(lanes, probe_tcb, |route| resolve(route, true))
        .map_err(|_| Error::Retain)?;
    Ok(Arrival::Call { route, reply })
}

pub(crate) unsafe fn ready_worker(
    route: PeerRoute,
    channel: &crate::spawn_hosts::PumpChannel,
    expected: WorkerReadyExpectation,
    publication: &mut Option<nt_provider_wait::ProviderStackReadyReceipt>,
) -> Result<(), Error> {
    if channel_route(channel)? != Some(route) {
        return Err(Error::PhysicalIdentity);
    }
    let mut faults = 0;
    loop {
        match receive(IngressExecutionOwner::Startup(route), channel.tcb, true)? {
            Arrival::Hosted => {}
            Arrival::Notification(message) => {
                if !crate::spawn_hosts::pump_handle_executive_event_badge(message.badge()).0 {
                    return Err(Error::Protocol);
                }
            }
            Arrival::Call {
                route: sender,
                reply,
            } => {
                if sender != route {
                    continue;
                }
                let info = owner()
                    .receiver
                    .as_ref()
                    .expect("ready receiver")
                    .stored_message(route, reply)
                    .map_err(|_| Error::Receive)?
                    .info();
                if info == (6 << 12) | 4 {
                    let observation = owner()
                        .service_startup_fault(
                            lanes(),
                            route,
                            reply,
                            channel,
                            faults,
                            faults,
                            |route| resolve(route, false),
                        )
                        .map_err(|_| Error::Fault)?;
                    if observation != IngressReplyObservation::Acknowledged {
                        return Err(Error::Fault);
                    }
                    owner()
                        .finish_startup_fault(lanes(), route, reply, channel.tcb, |route| {
                            resolve(route, false)
                        })
                        .map_err(|_| Error::Fault)?;
                    faults += 1;
                    continue;
                }
                return owner()
                    .ready(lanes(), route, reply, expected, publication, |route| {
                        resolve(route, false)
                    })
                    .map_err(|_| Error::Startup);
            }
        }
    }
}

pub(crate) unsafe fn admit(route: PeerRoute) -> Result<LaneDispatchIdentity, Error> {
    owner()
        .admit(lanes(), route, |route| resolve(route, false))
        .map_err(|_| Error::Admission)
}

/// Scheduling hint only; `admit` still owns the final physical Reply check.
pub(crate) unsafe fn ready_for_admission(route: PeerRoute) -> Result<bool, Error> {
    if resolve(route, false).is_none() {
        return Err(Error::PhysicalIdentity);
    }
    let ingress = owner();
    let receiver = ingress.receiver.as_ref().ok_or(Error::Initialization)?;
    let replacements = ingress.replacements.as_ref().ok_or(Error::Initialization)?;
    Ok(replacements.ready_for_admission(receiver, route, lanes()))
}

/// Resolve a transport snapshot through its retained physical source, not its numeric badge.
pub(crate) unsafe fn channel_route(
    channel: &crate::spawn_hosts::PumpChannel,
) -> Result<Option<PeerRoute>, Error> {
    let owner = owner();
    if !owner.ready
        || owner.receiver.as_ref().expect("ready receiver").endpoint() != channel.fault_ep
    {
        return Err(Error::PhysicalIdentity);
    }
    let route = channel.ingress_route.ok_or(Error::PhysicalIdentity)?;
    let row = (&*core::ptr::addr_of!(NATIVE_PEERS))
        .iter()
        .find(|row| row.route == Some(route))
        .ok_or(Error::PhysicalIdentity)?;
    if route.endpoint() != channel.fault_ep
        || row.physical.tcb != channel.tcb
        || row.physical.pml4 != channel.pml4
        || match row.physical.domain {
            PhysicalDomain::Hosted(domain) => channel.physical_domain != Some(domain),
            PhysicalDomain::Provider { .. } => channel.physical_domain.is_some(),
        }
        || resolve(route, false) != Some(channel.tcb)
    {
        return Err(Error::PhysicalIdentity);
    }
    Ok(Some(route))
}

pub(crate) unsafe fn endpoint() -> Option<u64> {
    let owner = owner();
    if !owner.ready {
        return None;
    }
    Some(owner.receiver.as_ref()?.endpoint())
}

pub(crate) unsafe fn owns_ingress_reply(reply: u64) -> bool {
    let owner = owner();
    owns_hosted_reply(reply)
        || (&*core::ptr::addr_of!(INITIAL_REPLIES))
            .iter()
            .filter_map(Option::as_ref)
            .any(|owner| owner.reply() == reply)
        || owner
            .receiver
            .as_ref()
            .is_some_and(|receiver| receiver.excludes_reply(reply))
        || owner
            .replacements
            .as_ref()
            .is_some_and(|pool| pool.excludes_reply(reply))
        || owner
            .pending_reply
            .as_ref()
            .is_some_and(|pending| pending.reply() == reply)
        || (&*core::ptr::addr_of!(NATIVE_PEERS))
            .iter()
            .filter_map(|peer| peer.route)
            .any(|route| {
                lanes()
                    .binding(route.identity().lane)
                    .is_ok_and(|binding| binding.reply_object == reply)
            })
}

pub(crate) unsafe fn service_autonomous() -> Result<bool, Error> {
    let Some(route) = next_autonomous()? else {
        return Ok(false);
    };
    crate::spawn_hosts::shared_pump::service_autonomous(route)?;
    Ok(true)
}

pub(crate) unsafe fn dispatch(route: PeerRoute) -> Result<LaneDispatchIdentity, Error> {
    if resolve(route, false).is_none() {
        return Err(Error::PhysicalIdentity);
    }
    lanes()
        .active_dispatch_identity(route.identity().lane)
        .map_err(|_| Error::Admission)?
        .ok_or(Error::Admission)
}

pub(crate) unsafe fn current_reply(route: PeerRoute) -> Result<u64, Error> {
    if resolve(route, false).is_none() {
        return Err(Error::PhysicalIdentity);
    }
    Ok(lanes()
        .binding(route.identity().lane)
        .map_err(|_| Error::Admission)?
        .reply_object)
}

pub(crate) unsafe fn next_message(
    route: PeerRoute,
) -> Result<Option<(u64, ReceivedMessage)>, Error> {
    if resolve(route, false).is_none() {
        return Err(Error::PhysicalIdentity);
    }
    Ok(owner()
        .receiver
        .as_ref()
        .ok_or(Error::Initialization)?
        .next_unadmitted(route)
        .map(|(reply, message)| (reply, message.clone())))
}

pub(crate) unsafe fn stored_current_message(route: PeerRoute) -> Result<ReceivedMessage, Error> {
    let reply = current_reply(route)?;
    owner()
        .receiver
        .as_ref()
        .expect("ready receiver")
        .stored_message(route, reply)
        .cloned()
        .map_err(|_| Error::Receive)
}

pub(crate) unsafe fn next_autonomous() -> Result<Option<PeerRoute>, Error> {
    for row in &*core::ptr::addr_of!(NATIVE_PEERS) {
        if row.quarantined || !matches!(row.physical.kind, PhysicalSourceKind::SystemThread { .. })
        {
            continue;
        }
        let Some(route) = row.route else {
            continue;
        };
        if next_message(route)?.is_some() {
            return Ok(Some(route));
        }
    }
    Ok(None)
}

pub(crate) unsafe fn receive_owner(route: PeerRoute) -> Result<IngressExecutionOwner, Error> {
    if resolve(route, false).is_none() {
        return Err(Error::PhysicalIdentity);
    }
    if lanes().running() == Some(route.identity().lane) {
        Ok(IngressExecutionOwner::Dispatch(dispatch(route)?))
    } else if !lanes().execution_busy() {
        Ok(IngressExecutionOwner::Idle)
    } else {
        Err(Error::Admission)
    }
}

pub(crate) unsafe fn adopt(route: PeerRoute, incoming: u64) -> Result<(), Error> {
    let dispatch = dispatch(route)?;
    let index = (&*core::ptr::addr_of!(NATIVE_PEERS))
        .iter()
        .position(|row| row.route == Some(route))
        .ok_or(Error::UnknownPeer)?;
    let bootstrap = (&*core::ptr::addr_of!(NATIVE_PEERS))[index].bootstrap;
    if bootstrap {
        let owner = owner();
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        owner
            .receiver
            .as_mut()
            .ok_or(Error::Initialization)?
            .adopt_bootstrap_call(
                route,
                dispatch,
                incoming,
                lanes(),
                owner.peers.as_ref().expect("ready peers"),
                &mut owner.pending_reply,
                |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            )
            .map_err(|_| Error::Admission)?;
        (&mut *core::ptr::addr_of_mut!(NATIVE_PEERS))[index].bootstrap = false;
        owner
            .recycle_pending_reply(lanes(), route.identity().executor)
            .map_err(|_| Error::Reply)
    } else {
        owner()
            .adopt_interim_call(lanes(), route, dispatch, incoming, |route| {
                resolve(route, false)
            })
            .map_err(|_| Error::Admission)
    }
}

pub(crate) unsafe fn reply(route: PeerRoute, reply: u64, words: &[u64]) -> Result<(), Error> {
    reply_with_info(route, reply, words.len() as u64, words)
}

pub(crate) unsafe fn reply_with_info(
    route: PeerRoute,
    reply: u64,
    info: u64,
    words: &[u64],
) -> Result<(), Error> {
    let result = (|| {
        let dispatch = dispatch(route)?;
        if current_reply(route)? != reply {
            return Err(Error::Reply);
        }
        match owner().reply(lanes(), route, dispatch, info, words, |route| {
            resolve(route, false)
        }) {
            Ok(IngressReplyObservation::Acknowledged) => Ok(()),
            _ => Err(Error::Reply),
        }
    })();
    if result.is_err() {
        crate::spawn_hosts::PUMP_REPLY_ERRORS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    result
}

unsafe fn completion_reply(route: PeerRoute, label: u64) -> Result<u64, Error> {
    let (reply, message) = next_message(route)?.ok_or(Error::Protocol)?;
    if label == 0
        || label > (u64::MAX >> 12)
        || message.info() != label << 12
        || message.badge() != route.badge()
    {
        return Err(Error::Protocol);
    }
    Ok(reply)
}

pub(crate) unsafe fn complete(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    label: u64,
) -> Result<(), Error> {
    if self::dispatch(route)? != dispatch || current_reply(route)? != reply {
        return Err(Error::Admission);
    }
    let incoming = completion_reply(route, label)?;
    let index = (&*core::ptr::addr_of!(NATIVE_PEERS))
        .iter()
        .position(|row| row.route == Some(route))
        .ok_or(Error::UnknownPeer)?;
    if (&*core::ptr::addr_of!(NATIVE_PEERS))[index].bootstrap {
        let owner = owner();
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        owner
            .receiver
            .as_mut()
            .expect("ready receiver")
            .complete_bootstrap_from_message(
                route,
                dispatch,
                incoming,
                label,
                lanes(),
                owner.peers.as_ref().expect("ready peers"),
                |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            )
            .map_err(|_| Error::Protocol)?;
        (&mut *core::ptr::addr_of_mut!(NATIVE_PEERS))[index].bootstrap = false;
        crate::service_sec_image::retire_win32k_directory_route(route, dispatch);
        crate::provider_registry_caller::retire_completed(route, dispatch);
        return Ok(());
    }
    owner()
        .complete(lanes(), route, dispatch, incoming, label, |route| {
            resolve(route, false)
        })
        .map_err(|_| Error::Protocol)?;
    crate::service_sec_image::retire_win32k_directory_route(route, dispatch);
    crate::provider_registry_caller::retire_completed(route, dispatch);
    Ok(())
}

/// A nested callback invocation returns to the outer parked continuation, not to idle.
pub(crate) unsafe fn continue_after_subcall(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    label: u64,
) -> Result<(), Error> {
    if self::dispatch(route)? != dispatch || current_reply(route)? != reply {
        return Err(Error::Admission);
    }
    let incoming = completion_reply(route, label)?;
    adopt(route, incoming)
}

pub(crate) unsafe fn complete_protocol(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    label: u64,
    words: &[u64],
) -> Result<(), Error> {
    if self::dispatch(route)? != dispatch || current_reply(route)? != reply {
        return Err(Error::Admission);
    }
    let (incoming, _) = next_message(route)?.ok_or(Error::Protocol)?;
    let owner = owner();
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    owner
        .receiver
        .as_mut()
        .expect("ready receiver")
        .complete_protocol_from_message(
            route,
            dispatch,
            incoming,
            label,
            words,
            lanes(),
            owner.peers.as_mut().expect("ready peers"),
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
        )
        .map_err(|_| Error::Protocol)?;
    crate::service_sec_image::retire_win32k_directory_route(route, dispatch);
    crate::provider_registry_caller::retire_completed(route, dispatch);
    Ok(())
}

/// Stop once and retain all remaining cancellation, Reply and alias obligations. This is not
/// deletion or a successful drain proof; uncertain stop remains entered in PeerInstallation.
pub(crate) unsafe fn quarantine(route: PeerRoute) -> Result<(), Error> {
    let index = (&*core::ptr::addr_of!(NATIVE_PEERS))
        .iter()
        .position(|row| row.route == Some(route))
        .ok_or(Error::UnknownPeer)?;
    if (&*core::ptr::addr_of!(NATIVE_PEERS))[index].quarantined {
        return Err(Error::Retirement);
    }
    let owner = owner();
    let lanes = lanes();
    let installation = owner
        .installations
        .iter_mut()
        .find(|row| row.route() == route)
        .ok_or(Error::UnknownPeer)?;
    installation
        .begin_retirement(
            owner.peers.as_mut().expect("ready peers"),
            route.identity().domain,
            route.identity().domain_generation,
            lanes,
        )
        .map_err(|error| retirement::failure("begin-peer", error))?;
    let row = &mut (&mut *core::ptr::addr_of_mut!(NATIVE_PEERS))[index];
    (&mut *core::ptr::addr_of_mut!(SOURCES))
        .begin_retirement(row.source, |physical| (row.verify)(physical))
        .map_err(|error| retirement::failure("begin-source", error))?;
    row.quarantined = true;
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    installation
        .retire_effect(
            owner.peers.as_ref().expect("ready peers"),
            lanes,
            |effect| {
                let PeerRetirementEffect::StopExecutor(tcb) = effect else {
                    return Err(u64::MAX);
                };
                let status = crate::tcb_suspend_r(tcb);
                if status == 0 {
                    Ok(())
                } else {
                    Err(status)
                }
            },
        )
        .map_err(|error| retirement::failure("stop-executor", error))
}
