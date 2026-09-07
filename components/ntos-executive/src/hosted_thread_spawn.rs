//! Constructor outcomes and the checked fault-endpoint installation boundary.

use super::*;
pub(crate) use nt_user_host::thread_endpoint::ThreadFaultEndpoint;
use nt_user_host::thread_endpoint::{EndpointInstallError, ThreadEndpointBackend};

pub(crate) type HostedThreadSpawnResult = Result<HostedThreadSpawn, HostedThreadSpawnFailure>;

/// Only pre-construction rejection permits cancellation of the runtime reservation. A partial
/// construction must enter protected ownership through the original ticket before public abort.
pub(crate) enum HostedThreadSpawnFailure {
    Unstarted,
    Retained(FailedHostedThreadConstruction),
}

/// Successful construction only. A failed construction can own a real TCB, so no failure
/// discriminator or empty-TCB sentinel is exposed through this payload.
pub(crate) struct HostedThreadSpawn {
    tcb: u64,
    mechanism: HostedThreadMechanismCaps,
    teb_alias: u64,
    resources: HostedThreadResources,
    commitment: Option<exec_handler::PreparedHostedThreadCommitment>,
}

impl HostedThreadSpawn {
    pub(crate) fn new(
        tcb: u64,
        mechanism: HostedThreadMechanismCaps,
        teb_alias: u64,
        resources: HostedThreadResources,
    ) -> Self {
        assert!(tcb > 1 && mechanism.is_live() && resources.is_live());
        Self {
            tcb,
            mechanism,
            teb_alias,
            resources,
            commitment: None,
        }
    }

    pub(crate) const fn tcb(&self) -> u64 {
        self.tcb
    }
    pub(crate) const fn mechanism(&self) -> HostedThreadMechanismCaps {
        self.mechanism
    }
    pub(crate) const fn teb_alias(&self) -> u64 {
        self.teb_alias
    }
    pub(crate) const fn resources(&self) -> HostedThreadResources {
        self.resources
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
