//! Durable native allocation ownership for shared ingress, including failed initialization.

use alloc::vec::Vec;
use core::convert::Infallible;
use nt_component_suspension::peer_registry::{PeerRegistration, PeerRegistry, PeerRoute};
use nt_component_suspension::{
    ComponentIngress, ComponentSuspensionLanes, IngressExecutionOwner, IngressReceiver,
    IngressReplyPool, IngressResourceKind, IngressResources, LaneHandle, PeerInstallation,
    PeerInstallationError, PeerLaneError, ReceivedMessage,
};

static mut SHARED_INGRESS: NativeSharedIngress = NativeSharedIngress::new();

/// Prepare the dormant global owner once, from serialized root initialization with no reentrant
/// scheduler hooks. Failed owners stay in static storage; this does not export capabilities.
pub(crate) unsafe fn prepare<C, R, T>(
    retained_capacity: usize,
    peer_capacity: usize,
    lanes: &ComponentSuspensionLanes<C, R, T>,
    probe_tcb: u64,
) -> Result<(), InitializationError> {
    (&mut *core::ptr::addr_of_mut!(SHARED_INGRESS)).initialize(
        retained_capacity,
        peer_capacity,
        lanes,
        probe_tcb,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitializationError {
    AlreadyAttempted,
    InvalidCapacity,
    NoMemory,
    NoSlots,
    ResourceCreation,
    ReplyOwnership,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationError {
    NotReady,
    PendingAllocation,
    NoCapacity,
    NoSlots,
    Stage(PeerLaneError),
    Installation(PeerInstallationError<Infallible>),
    Mint(PeerInstallationError<u64>),
}

struct PendingPeer {
    registration: PeerRegistration,
    slot: Option<u64>,
}

/// The physical owner must keep this exact domain generation, stopped lane and endpoint alive.
/// This publishes only a root alias; child export and startup admission remain separate.
pub(crate) unsafe fn publish_peer<C, R, T>(
    lanes: &ComponentSuspensionLanes<C, R, T>,
    domain: u64,
    generation: u64,
    lane: LaneHandle,
) -> Result<PeerRoute, PublicationError> {
    (&mut *core::ptr::addr_of_mut!(SHARED_INGRESS)).publish_peer(lanes, domain, generation, lane)
}

/// Keep this owner alive even after initialization refusal. No failure deletes capabilities,
/// returns root slots, or permits another initialization attempt. Native callers must serialize
/// access and retain the physical domain owners used by the receive adapter.
#[must_use = "retain all shared ingress resources, including failed initialization"]
pub(crate) struct NativeSharedIngress {
    attempted: bool,
    ready: bool,
    slot_run: Option<(u64, u64)>,
    resources: Option<IngressResources>,
    receiver: Option<IngressReceiver<ReceivedMessage>>,
    replacements: Option<IngressReplyPool<ReceivedMessage>>,
    peers: Option<PeerRegistry>,
    installations: Vec<PeerInstallation>,
    peer_capacity: usize,
    pending_peer: Option<PendingPeer>,
    pending_reply: Option<ComponentIngress<ReceivedMessage>>,
    creation_error: Option<u64>,
}

impl NativeSharedIngress {
    pub(crate) const fn new() -> Self {
        Self {
            attempted: false,
            ready: false,
            slot_run: None,
            resources: None,
            receiver: None,
            replacements: None,
            peers: None,
            installations: Vec::new(),
            peer_capacity: 0,
            pending_peer: None,
            pending_reply: None,
            creation_error: None,
        }
    }

    /// Allocate one endpoint, one current Reply and `retained_capacity` replacement Replies.
    /// `probe_tcb` must be live and canonical. No provider is resumed or endpoint cap exported.
    pub(crate) unsafe fn initialize<C, R, T>(
        &mut self,
        retained_capacity: usize,
        peer_capacity: usize,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        probe_tcb: u64,
    ) -> Result<(), InitializationError> {
        if self.attempted {
            return Err(InitializationError::AlreadyAttempted);
        }
        self.attempted = true;
        let count = retained_capacity
            .checked_add(2)
            .and_then(|count| u64::try_from(count).ok())
            .filter(|_| retained_capacity != 0 && peer_capacity != 0 && probe_tcb != 0)
            .ok_or(InitializationError::InvalidCapacity)?;
        self.installations
            .try_reserve_exact(peer_capacity)
            .map_err(|_| InitializationError::NoMemory)?;
        self.peer_capacity = peer_capacity;
        let mut replies = Vec::new();
        replies
            .try_reserve_exact(retained_capacity + 1)
            .map_err(|_| InitializationError::NoMemory)?;
        let base = crate::try_alloc_slot_run(count).ok_or(InitializationError::NoSlots)?;
        self.slot_run = Some((base, count));
        for offset in 1..count {
            replies.push(base + offset);
        }
        self.resources =
            Some(IngressResources::new(base, replies).map_err(|_| InitializationError::NoMemory)?);
        self.peers = Some(
            PeerRegistry::try_new(base, peer_capacity)
                .map_err(|_| InitializationError::NoMemory)?,
        );
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        let result = self
            .resources
            .as_mut()
            .expect("reserved ingress resources")
            .initialize(|kind, slot| {
                let object = match kind {
                    IngressResourceKind::Endpoint => crate::OBJ_ENDPOINT,
                    IngressResourceKind::Reply => crate::OBJ_REPLY,
                };
                let error = crate::untyped_retype_r(crate::CAP_INIT_UNTYPED, object, 0, 1, slot);
                if error == 0 {
                    Ok(())
                } else {
                    Err(error)
                }
            });
        if let Err(error) = result {
            // Preserve the native status as well as the exact entered resource in the ledger.
            if let nt_component_suspension::IngressResourceError::Invoke(status) = error {
                self.creation_error = Some(status);
            }
            return Err(InitializationError::ResourceCreation);
        }
        nt_component_suspension::require_free_reply(
            crate::spawn_hosts::query_component_reply_binding(probe_tcb, base + 1),
        )
        .map_err(|_| InitializationError::ReplyOwnership)?;
        self.receiver = Some(
            IngressReceiver::new(base, base + 1, retained_capacity)
                .map_err(|_| InitializationError::NoMemory)?,
        );
        self.replacements = Some(
            IngressReplyPool::new(base, retained_capacity)
                .map_err(|_| InitializationError::NoMemory)?,
        );
        for offset in 2..count {
            self.pending_reply = Some(
                ComponentIngress::new(base, base + offset)
                    .map_err(|_| InitializationError::ReplyOwnership)?,
            );
            let reply = self.pending_reply.take().expect("owned new Reply");
            if let Err((_, reply)) = self
                .replacements
                .as_mut()
                .expect("replacement pool")
                .insert(
                    reply,
                    self.receiver.as_ref().expect("current receiver"),
                    lanes,
                    |reply| crate::spawn_hosts::query_component_reply_binding(probe_tcb, reply),
                )
            {
                self.pending_reply = Some(reply);
                return Err(InitializationError::ReplyOwnership);
            }
        }
        self.ready = true;
        Ok(())
    }

    /// Callbacks into scheduling are forbidden while references into this owner are held.
    /// Every failure after staging retains either the pending ticket/slot or an installation row.
    unsafe fn publish_peer<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        domain: u64,
        generation: u64,
        lane: LaneHandle,
    ) -> Result<PeerRoute, PublicationError> {
        if !self.ready {
            return Err(PublicationError::NotReady);
        }
        if self.pending_peer.is_some() {
            return Err(PublicationError::PendingAllocation);
        }
        if self.installations.len() >= self.peer_capacity {
            return Err(PublicationError::NoCapacity);
        }
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        let registration = self
            .peers
            .as_mut()
            .expect("initialized registry")
            .stage_lane(domain, generation, lanes, lane)
            .map_err(PublicationError::Stage)?;
        self.pending_peer = Some(PendingPeer {
            registration,
            slot: None,
        });
        let slot = crate::try_alloc_slot().ok_or(PublicationError::NoSlots)?;
        self.pending_peer.as_mut().expect("staged peer").slot = Some(slot);
        let pending = self.pending_peer.take().expect("reserved peer slot");
        let installation = match PeerInstallation::new(pending.registration, slot) {
            Ok(installation) => installation,
            Err((error, registration)) => {
                self.pending_peer = Some(PendingPeer {
                    registration,
                    slot: Some(slot),
                });
                return Err(PublicationError::Installation(error));
            }
        };
        // Capacity was reserved during initialization; publish ownership before the native effect.
        self.installations.push(installation);
        let installation = self
            .installations
            .last_mut()
            .expect("owned peer installation");
        installation
            .install(|route, destination| {
                let status = crate::cnode_mint_r(
                    crate::CAP_INIT_THREAD_CNODE,
                    destination,
                    route.endpoint(),
                    route.badge(),
                );
                if status == 0 {
                    Ok(())
                } else {
                    Err(status)
                }
            })
            .map_err(PublicationError::Mint)?;
        installation
            .publish(
                self.peers.as_mut().expect("initialized registry"),
                domain,
                generation,
                lanes,
            )
            .map_err(PublicationError::Installation)
    }

    pub(crate) unsafe fn receive<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        execution: IngressExecutionOwner,
        probe_tcb: u64,
        blocking: bool,
    ) -> Result<(), super::ReceiveError> {
        if !self.ready {
            return Err(super::ReceiveError::Ownership(
                nt_component_suspension::ReservedReceiveError::InvalidPhase,
            ));
        }
        super::receive(
            self.receiver.as_mut().expect("initialized receiver"),
            lanes,
            execution,
            probe_tcb,
            blocking,
        )
    }

    pub(crate) unsafe fn classify(
        &mut self,
        probe_tcb: u64,
        resolve_caller: impl FnOnce(u64) -> Option<u64>,
    ) -> Result<Option<ReceivedMessage>, super::ReceiveError> {
        if !self.ready {
            return Err(super::ReceiveError::Ownership(
                nt_component_suspension::ReservedReceiveError::InvalidPhase,
            ));
        }
        super::classify(
            self.receiver.as_mut().expect("initialized receiver"),
            probe_tcb,
            resolve_caller,
        )
    }

    pub(crate) unsafe fn retain<C, R, T>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        probe_tcb: u64,
        resolve_caller: impl FnOnce(nt_component_suspension::peer_registry::PeerRoute) -> Option<u64>,
    ) -> Result<(), super::ReceiveError> {
        if !self.ready {
            return Err(super::ReceiveError::Ownership(
                nt_component_suspension::ReservedReceiveError::InvalidPhase,
            ));
        }
        super::retain(
            self.receiver.as_mut().expect("initialized receiver"),
            self.replacements
                .as_mut()
                .expect("initialized replacement pool"),
            lanes,
            self.peers.as_mut().expect("initialized registry"),
            probe_tcb,
            resolve_caller,
        )
    }
}
