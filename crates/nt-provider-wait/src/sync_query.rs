//! The root's answer to a provider's dispatcher-header refresh of an embedded KMUTANT.
//!
//! `KMUTANT.OwnerThread` names the KTHREAD that acquired the mutant (NT's
//! `KiWaitSatisfyMutant` stores `KeGetCurrentThread()`). A hosted caller is named by its
//! Process Manager thread identity. A kernel-job caller (a Ps callout or DriverEntry lane) has
//! no hosted thread record, and a retiring thread's record may already be gone, but it is the
//! thread executing the querying lane: the provider resolves that through its own lane state.

use nt_component_suspension::SuspensionCaller;

/// Thread-id word that marks "owned by the querying kernel caller". No Process Manager thread
/// id is all-ones, so this never aliases a hosted owner.
pub const SYNC_QUERY_OWNER_CALLER_TID: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSyncQueryOwner {
    Unowned,
    Hosted { tid: u64, generation: u64 },
    /// Owned by the kernel lane that issued this query.
    QueryingCaller,
}

impl ProviderSyncQueryOwner {
    /// Name `owner` for the querying caller. A kernel owner can only be named to its own lane;
    /// any other caller has no authority to learn which thread another lane executes as.
    pub fn select(
        owner: Option<SuspensionCaller>,
        querying: Option<SuspensionCaller>,
    ) -> Option<Self> {
        match owner {
            None => Some(Self::Unowned),
            Some(SuspensionCaller::Hosted(client))
                if client.client_tid != 0 && client.client_generation != 0 =>
            {
                Some(Self::Hosted { tid: client.client_tid, generation: client.client_generation })
            }
            Some(kernel @ SuspensionCaller::Kernel { lane })
                if lane.is_valid() && querying == Some(kernel) =>
            {
                Some(Self::QueryingCaller)
            }
            Some(_) => None,
        }
    }

    pub const fn words(self) -> (u64, u64) {
        match self {
            Self::Unowned => (0, 0),
            Self::Hosted { tid, generation } => (tid, generation),
            Self::QueryingCaller => (SYNC_QUERY_OWNER_CALLER_TID, 0),
        }
    }

    pub const fn from_words(tid: u64, generation: u64) -> Option<Self> {
        match (tid, generation) {
            (0, 0) => Some(Self::Unowned),
            (SYNC_QUERY_OWNER_CALLER_TID, 0) => Some(Self::QueryingCaller),
            (0, _) | (_, 0) | (SYNC_QUERY_OWNER_CALLER_TID, _) => None,
            (tid, generation) => Some(Self::Hosted { tid, generation }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LaneHandle, ProviderDomainIdentity, ProviderLocalSyncCatalog, ProviderSyncKind,
        ProviderWaitOwner, SuspensionHostedClient,
    };

    fn kernel(index: u32) -> ProviderWaitOwner {
        ProviderWaitOwner {
            provider_domain: 5,
            provider_generation: 8,
            dispatch_id: 0xec5f9,
            caller: SuspensionCaller::Kernel { lane: LaneHandle { index, generation: 1 } },
        }
    }

    /// Boot 44229358220: the win32k thread-exit callout (a kernel job on lane 43) waited
    /// for a KMUTANT another thread held. The root selector made the lane the owner, and the
    /// lane's header refresh then had no way to name it, so the lane parked holding root's token.
    #[test]
    fn a_kernel_job_that_acquires_a_mutant_is_named_to_its_own_lane() {
        let mut catalog = ProviderLocalSyncCatalog::new(ProviderDomainIdentity {
            domain: 5, generation: 8,
        }).unwrap();
        let mutant = catalog.publish(0x7100, ProviderSyncKind::Mutant).unwrap();
        let owner = kernel(43);
        let lease = catalog.acquire_wait(owner, mutant).unwrap();
        assert_eq!(catalog.consume_ready(lease), Ok(true));
        let snapshot = catalog.snapshot_bound(0x7100, mutant).unwrap();
        assert_eq!(snapshot.mutant_owner, Some(owner.caller));

        let named = ProviderSyncQueryOwner::select(snapshot.mutant_owner, Some(owner.caller));
        assert_eq!(named, Some(ProviderSyncQueryOwner::QueryingCaller));
        let (tid, generation) = named.unwrap().words();
        assert_eq!(ProviderSyncQueryOwner::from_words(tid, generation), named);
    }

    #[test]
    fn a_kernel_owner_is_not_disclosed_to_another_caller() {
        let owner = Some(kernel(43).caller);
        assert_eq!(ProviderSyncQueryOwner::select(owner, Some(kernel(44).caller)), None);
        assert_eq!(ProviderSyncQueryOwner::select(owner, None), None);
    }

    #[test]
    fn hosted_and_unowned_replies_are_unchanged() {
        let hosted = SuspensionCaller::Hosted(SuspensionHostedClient {
            client_pi: 4, client_generation: 2, client_tid: 288, client_badge: 11,
        });
        let named = ProviderSyncQueryOwner::select(Some(hosted), None).unwrap();
        assert_eq!(named.words(), (288, 2));
        assert_eq!(ProviderSyncQueryOwner::select(None, None).unwrap().words(), (0, 0));
        assert_eq!(ProviderSyncQueryOwner::from_words(288, 0), None);
        assert_eq!(ProviderSyncQueryOwner::from_words(SYNC_QUERY_OWNER_CALLER_TID, 3), None);
    }
}
