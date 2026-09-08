//! Constructor outcomes and the checked fault-endpoint installation boundary.

use super::*;
pub(crate) use nt_user_host::thread_endpoint::ThreadFaultEndpoint;
use nt_user_host::thread_endpoint::{EndpointInstallError, ThreadEndpointBackend};

pub(crate) type HostedThreadSpawnResult = Result<HostedThreadSpawn, HostedThreadSpawnFailure>;

/// Only pre-construction rejection permits cancellation of the runtime reservation. A partial
/// construction must enter protected ownership through the original ticket before public abort.
pub(crate) enum HostedThreadSpawnFailure {
    Unstarted,
    Retained(RetainedHostedThreadConstruction),
}

/// Successful construction only. A failed construction can own a real TCB, so no failure
/// discriminator or empty-TCB sentinel is exposed through this payload.
#[must_use = "publish the completed construction or retain it through checked failure cleanup"]
pub(crate) struct HostedThreadSpawn {
    construction: RetainedHostedThreadConstruction,
    commitment: Option<exec_handler::PreparedHostedThreadCommitment>,
}

impl HostedThreadSpawn {
    pub(crate) fn new(construction: RetainedHostedThreadConstruction) -> Self {
        construction
            .construction
            .live_slots()
            .expect("completed construction retains every live slot");
        assert!(construction.resources.is_live());
        Self {
            construction,
            commitment: None,
        }
    }

    pub(crate) fn tcb(&self) -> u64 {
        self.construction
            .construction
            .live_slots()
            .expect("unpublished completed inventory")[2]
    }
    pub(crate) fn mechanism(&self) -> HostedThreadMechanismCaps {
        let [raw, cnode, _, sc] = self
            .construction
            .construction
            .live_slots()
            .expect("unpublished completed inventory");
        HostedThreadMechanismCaps::new(raw, cnode, sc)
    }
    pub(crate) const fn teb_alias(&self) -> u64 {
        self.construction.teb_alias
    }
    pub(crate) const fn resources(&self) -> HostedThreadResources {
        self.construction.resources
    }

    pub(crate) fn registered_memory(&self) -> Result<
        nt_user_host::thread_construction::RegisteredThreadMemory,
        nt_user_host::thread_registry::ThreadRegistryError,
    > {
        self.construction.memory_progress.completed_registration(&self.construction.resources)
    }

    pub(crate) fn binding(&self) -> nt_user_host::thread_binding::ThreadBinding<HostedThreadRole> {
        self.construction.binding
    }

    /// Rejected publication transfers the original inventory, never reconstructed copied caps.
    /// The optional commitment is an uncommitted preflight, not an accounting charge to release.
    pub(crate) fn into_failed(
        self,
    ) -> (
        RetainedHostedThreadConstruction,
        Option<exec_handler::PreparedHostedThreadCommitment>,
    ) {
        (self.construction, self.commitment)
    }

    pub(crate) fn attach_commitment(
        &mut self,
        commitment: exec_handler::PreparedHostedThreadCommitment,
    ) {
        assert!(self.commitment.is_none());
        self.commitment = Some(commitment);
    }

    pub(crate) fn take_commitment(
        &mut self,
    ) -> Option<exec_handler::PreparedHostedThreadCommitment> {
        self.commitment.take()
    }
}

struct RootThreadEndpointBackend;

impl ThreadEndpointBackend for RootThreadEndpointBackend {
    type Error = u64;

    fn copy(&mut self, cnode: u64, slot: u64, source: u64) -> Result<(), u64> {
        let error = unsafe { cnode_copy_at_r(cnode, slot, source) };
        if error == 0 {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn mint(&mut self, cnode: u64, slot: u64, source: u64, badge: u64) -> Result<(), u64> {
        let error = unsafe { cnode_mint_r(cnode, slot, source, badge) };
        if error == 0 {
            Ok(())
        } else {
            Err(error)
        }
    }
}

/// The constructor owns this CNode and its empty CT_FAULT slot. All source caps are borrowed;
/// final CNode destruction owns the installed child copy, including its derivation reference.
pub(crate) unsafe fn install_hosted_thread_endpoint(
    endpoint: ThreadFaultEndpoint,
    cnode: u64,
) -> Result<(), EndpointInstallError<u64>> {
    endpoint.install(&mut RootThreadEndpointBackend, cnode, CT_FAULT)
}
