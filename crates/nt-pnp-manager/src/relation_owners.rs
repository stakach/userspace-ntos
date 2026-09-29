use alloc::vec::Vec;

use crate::{DevnodeIdentity, DeviceRelationInvalidation};

/// An exact queue generation owns one authenticated projection, even across a requeue.
pub struct RelationOwnerLedger<Owner> {
    rows: Vec<(DeviceRelationInvalidation, Owner)>,
}

impl<Owner: Copy + Eq> Default for RelationOwnerLedger<Owner> {
    fn default() -> Self {
        Self { rows: Vec::new() }
    }
}

impl<Owner: Copy + Eq> RelationOwnerLedger<Owner> {
    pub fn reserve(&mut self) -> Result<(), alloc::collections::TryReserveError> {
        self.rows.try_reserve(1)
    }

    pub fn conflicting_projection(
        &self,
        parent: DevnodeIdentity,
        relation_type: u32,
        owner: Owner,
    ) -> bool {
        self.rows.iter().any(|(invalidation, retained)| {
            invalidation.parent == parent
                && invalidation.relation_type == relation_type
                && *retained != owner
        })
    }

    pub fn owner(&self, invalidation: DeviceRelationInvalidation) -> Option<Owner> {
        self.rows
            .iter()
            .find(|(key, _)| *key == invalidation)
            .map(|(_, owner)| *owner)
    }

    /// The caller reserves capacity before publishing the corresponding queue action.
    pub fn record(&mut self, invalidation: DeviceRelationInvalidation, owner: Owner) {
        assert!(self.rows.len() < self.rows.capacity());
        assert!(self.owner(invalidation).is_none());
        self.rows.push((invalidation, owner));
    }

    pub fn remove(&mut self, invalidation: DeviceRelationInvalidation) -> Option<Owner> {
        let index = self.rows.iter().position(|(key, _)| *key == invalidation)?;
        Some(self.rows.remove(index).1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceRelationInvalidationDisposition, DeviceRelationInvalidationQueue, PnpManager};

    #[test]
    fn owner_survives_coalescing_and_requeue_until_exact_completion() {
        let mut pnp = PnpManager::new();
        pnp.create_service_bound_devnode_without_resources("ROOT\\TEST\\0000", None, 33);
        let parent = pnp.devnode_identity_for_pdo(33).unwrap();
        let mut queue = DeviceRelationInvalidationQueue::new();
        let mut owners = RelationOwnerLedger::<u64>::default();
        owners.reserve().unwrap();
        let first = queue.enqueue(parent, 0).unwrap();
        owners.record(first.invalidation, 0xabc);
        let coalesced = queue.enqueue(parent, 0).unwrap();
        assert_eq!(coalesced.disposition, DeviceRelationInvalidationDisposition::Coalesced);
        assert_eq!(owners.owner(coalesced.invalidation), Some(0xabc));
        assert!(owners.conflicting_projection(parent, 0, 0xdef));
        assert!(!owners.conflicting_projection(parent, 0, 0xabc));

        let claim = queue.claim_front().unwrap();
        owners.reserve().unwrap();
        let next = queue.enqueue(parent, 0).unwrap();
        assert_eq!(next.disposition, DeviceRelationInvalidationDisposition::Requeued);
        owners.record(next.invalidation, 0xabc);
        assert!(matches!(
            queue.complete(claim).unwrap(),
            crate::DeviceRelationInvalidationCompletion::Requeued(invalidation)
                if invalidation == next.invalidation
        ));
        assert_eq!(owners.remove(claim), Some(0xabc));
        assert_eq!(owners.owner(next.invalidation), Some(0xabc));
        let next_claim = queue.claim_front().unwrap();
        queue.complete(next_claim).unwrap();
        assert_eq!(owners.remove(next_claim), Some(0xabc));
        assert_eq!(owners.owner(next.invalidation), None);
    }
}
