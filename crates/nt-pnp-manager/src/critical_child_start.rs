use alloc::string::String;
use alloc::vec::Vec;

use crate::{BusRelationTable, DevnodeIdentity, ParentRelationIdentity, PnpManager};

/// One boot mount's canonical child, published by an accepted BusRelations generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CriticalChildStartKey {
    mount_generation: u64,
    child: DevnodeIdentity,
    parent_relation: ParentRelationIdentity,
}

impl CriticalChildStartKey {
    pub const fn mount_generation(self) -> u64 {
        self.mount_generation
    }

    pub const fn child(self) -> DevnodeIdentity {
        self.child
    }

    pub const fn parent_relation(self) -> ParentRelationIdentity {
        self.parent_relation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CriticalChildStartClaim {
    key: CriticalChildStartKey,
    token: u64,
}

impl CriticalChildStartClaim {
    pub const fn key(self) -> CriticalChildStartKey {
        self.key
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CriticalChildStartState {
    Reserved,
    Claimed,
    Terminal(u32),
    Retired(u32),
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CriticalChildStartError {
    InvalidMount,
    InvalidInstance,
    StalePublication,
    ConflictingGeneration,
    InsufficientResources,
    InvalidClaim,
    WrongPhase,
}

struct StartEntry {
    key: CriticalChildStartKey,
    instance_id: String,
    state: CriticalChildStartState,
    token: u64,
}

/// Retains retired keys as tombstones so a repeated relation cannot replay a START effect.
pub struct CriticalChildStartQueue {
    entries: Vec<StartEntry>,
    next_token: u64,
}

impl Default for CriticalChildStartQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl CriticalChildStartQueue {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_token: 1,
        }
    }

    fn current_key(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        mount_generation: u64,
        child_pdo: u64,
        instance_id: &str,
    ) -> Result<CriticalChildStartKey, CriticalChildStartError> {
        if mount_generation == 0 {
            return Err(CriticalChildStartError::InvalidMount);
        }
        if instance_id.is_empty() {
            return Err(CriticalChildStartError::InvalidInstance);
        }
        let child = pnp
            .devnode_identity_for_pdo(child_pdo)
            .ok_or(CriticalChildStartError::StalePublication)?;
        let parent_relation = pnp
            .parent_relation_for_pdo(child_pdo)
            .ok_or(CriticalChildStartError::StalePublication)?;
        if pnp.instance_id(child.devnode_id()) != Some(instance_id)
            || !pnp.relation_parent_is_started(parent_relation)
            || !relations.relation_contains(parent_relation.relation(), child_pdo)
        {
            return Err(CriticalChildStartError::StalePublication);
        }
        Ok(CriticalChildStartKey {
            mount_generation,
            child,
            parent_relation,
        })
    }

    /// Reserve ownership only after both the relation and canonical devnode are committed.
    /// Repeated publication reports its existing state and never creates a second START.
    pub fn reserve_committed(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        mount_generation: u64,
        child_pdo: u64,
        instance_id: &str,
    ) -> Result<(CriticalChildStartKey, CriticalChildStartState), CriticalChildStartError> {
        let key = Self::current_key(pnp, relations, mount_generation, child_pdo, instance_id)?;
        if let Some(entry) = self.entries.iter().find(|entry| entry.key == key) {
            return if entry.instance_id == instance_id {
                Ok((key, entry.state))
            } else {
                Err(CriticalChildStartError::ConflictingGeneration)
            };
        }
        if self.entries.iter().any(|entry| {
            entry.key.child == key.child
                && !matches!(entry.state, CriticalChildStartState::Retired(_))
        }) {
            return Err(CriticalChildStartError::ConflictingGeneration);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| CriticalChildStartError::InsufficientResources)?;
        let mut owned_instance = String::new();
        owned_instance
            .try_reserve(instance_id.len())
            .map_err(|_| CriticalChildStartError::InsufficientResources)?;
        owned_instance.push_str(instance_id);
        self.entries.push(StartEntry {
            key,
            instance_id: owned_instance,
            state: CriticalChildStartState::Reserved,
            token: 0,
        });
        Ok((key, CriticalChildStartState::Reserved))
    }

    /// Claims the oldest reserved entry. A stale publication is quarantined, not retried.
    pub fn claim_next(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        mount_generation: u64,
    ) -> Result<Option<CriticalChildStartClaim>, CriticalChildStartError> {
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.state == CriticalChildStartState::Reserved)
        else {
            return Ok(None);
        };
        let key = self.entries[index].key;
        if key.mount_generation != mount_generation {
            self.entries[index].state = CriticalChildStartState::Uncertain;
            return Err(CriticalChildStartError::StalePublication);
        }
        if Self::current_key(
            pnp,
            relations,
            key.mount_generation,
            key.child.pdo_object_id(),
            &self.entries[index].instance_id,
        ) != Ok(key)
        {
            self.entries[index].state = CriticalChildStartState::Uncertain;
            return Err(CriticalChildStartError::StalePublication);
        }
        let token = self.next_token;
        self.next_token = token
            .checked_add(1)
            .ok_or(CriticalChildStartError::InsufficientResources)?;
        self.entries[index].token = token;
        self.entries[index].state = CriticalChildStartState::Claimed;
        Ok(Some(CriticalChildStartClaim { key, token }))
    }

    fn claimed_entry(
        &mut self,
        claim: CriticalChildStartClaim,
    ) -> Result<&mut StartEntry, CriticalChildStartError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.key == claim.key && entry.token == claim.token)
            .ok_or(CriticalChildStartError::InvalidClaim)?;
        if entry.state != CriticalChildStartState::Claimed {
            return Err(CriticalChildStartError::WrongPhase);
        }
        Ok(entry)
    }

    /// Record the terminal provider result before retiring the exact claim.
    pub fn complete(
        &mut self,
        claim: CriticalChildStartClaim,
        status: u32,
    ) -> Result<(), CriticalChildStartError> {
        self.claimed_entry(claim)?.state = CriticalChildStartState::Terminal(status);
        Ok(())
    }

    /// Unknown native effect is never replayable and remains visible for diagnosis.
    pub fn quarantine(
        &mut self,
        claim: CriticalChildStartClaim,
    ) -> Result<(), CriticalChildStartError> {
        self.claimed_entry(claim)?.state = CriticalChildStartState::Uncertain;
        Ok(())
    }

    pub fn retire(
        &mut self,
        claim: CriticalChildStartClaim,
    ) -> Result<u32, CriticalChildStartError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.key == claim.key && entry.token == claim.token)
            .ok_or(CriticalChildStartError::InvalidClaim)?;
        let CriticalChildStartState::Terminal(status) = entry.state else {
            return Err(CriticalChildStartError::WrongPhase);
        };
        entry.state = CriticalChildStartState::Retired(status);
        Ok(status)
    }

    pub fn state(&self, key: CriticalChildStartKey) -> Option<CriticalChildStartState> {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BusReportedChild, DeviceState, EnumeratedPdoRecord, PdoCapabilities, PdoProperties,
        PnpBusInformation, PropertyBlobState, GUID_BUS_TYPE_PCI, INTERFACE_TYPE_PCI_BUS,
    };
    use alloc::vec;

    fn committed_child() -> (PnpManager, BusRelationTable, u64, String) {
        let mut pnp = PnpManager::new();
        let parent = pnp.create_service_bound_devnode_without_resources(
            r"ROOT\TEST_BUS\0000",
            Some("TestBus"),
            0x9000,
        );
        for state in [
            DeviceState::DriverLoaded,
            DeviceState::AddDeviceCalled,
            DeviceState::DeviceStackBuilt,
            DeviceState::ResourcesAssigned,
            DeviceState::StartIrpSent,
            DeviceState::Started,
        ] {
            pnp.transition(parent, state).unwrap();
        }
        let child = BusReportedChild::new(
            0x1234,
            r"ACPI\PNP0303",
            "0001",
            &[r"ACPI\PNP0303"],
            &[] as &[&str],
        );
        let mut relations = BusRelationTable::new();
        relations.seed_bus_relations(0x9000, &[]).unwrap();
        let prepared_relation = relations
            .prepare_bus_relations(0x9000, &[child.clone()])
            .unwrap();
        let parent_relation = pnp
            .claim_started_parent_relation(0x9000, prepared_relation.relation_identity())
            .unwrap();
        let properties = PdoProperties::enumerated(
            PnpBusInformation {
                bus_type_guid: GUID_BUS_TYPE_PCI,
                legacy_bus_type: INTERFACE_TYPE_PCI_BUS,
                bus_number: 0,
            },
            PdoCapabilities {
                removable: false,
                eject_supported: false,
                surprise_removal_ok: false,
                address: 0,
            },
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
        );
        let instance_id = child.enum_instance_path();
        let prepared_child = pnp
            .prepare_enumerated_pdo_batch(vec![EnumeratedPdoRecord::new(
                instance_id.clone(),
                child.pdo_object_id,
                properties,
            )
            .with_parent_relation(parent_relation)])
            .unwrap();
        pnp.commit_enumerated_pdo_batch(prepared_child).unwrap();
        relations.commit_bus_relations(prepared_relation).unwrap();
        (pnp, relations, child.pdo_object_id, instance_id)
    }

    #[test]
    fn exact_claim_retires_without_replay() {
        let (pnp, relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let (key, state) = queue
            .reserve_committed(&pnp, &relations, 7, pdo, &instance_id)
            .unwrap();
        assert_eq!(state, CriticalChildStartState::Reserved);
        assert_eq!(
            queue.reserve_committed(&pnp, &relations, 7, pdo, &instance_id),
            Ok((key, state))
        );
        let claim = queue.claim_next(&pnp, &relations, 7).unwrap().unwrap();
        assert_eq!(claim.key(), key);
        assert_eq!(
            queue.reserve_committed(&pnp, &relations, 7, pdo, &instance_id),
            Ok((key, CriticalChildStartState::Claimed))
        );
        assert_eq!(
            queue.retire(claim),
            Err(CriticalChildStartError::WrongPhase)
        );
        queue.complete(claim, 0).unwrap();
        assert_eq!(
            queue.complete(claim, 0),
            Err(CriticalChildStartError::WrongPhase)
        );
        assert_eq!(queue.retire(claim), Ok(0));
        assert_eq!(
            queue.reserve_committed(&pnp, &relations, 7, pdo, &instance_id),
            Ok((key, CriticalChildStartState::Retired(0)))
        );
        assert_eq!(queue.claim_next(&pnp, &relations, 7), Ok(None));
    }

    #[test]
    fn unknown_effect_quarantines_cross_generation_replay() {
        let (pnp, relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let (key, _) = queue
            .reserve_committed(&pnp, &relations, 7, pdo, &instance_id)
            .unwrap();
        let claim = queue.claim_next(&pnp, &relations, 7).unwrap().unwrap();
        queue.quarantine(claim).unwrap();
        assert_eq!(queue.state(key), Some(CriticalChildStartState::Uncertain));
        assert_eq!(
            queue.reserve_committed(&pnp, &relations, 8, pdo, &instance_id),
            Err(CriticalChildStartError::ConflictingGeneration)
        );
        assert_eq!(
            queue.complete(claim, 0),
            Err(CriticalChildStartError::WrongPhase)
        );
    }

    #[test]
    fn uncommitted_relation_cannot_reserve() {
        let (pnp, _relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let relations = BusRelationTable::new();
        assert_eq!(
            queue.reserve_committed(&pnp, &relations, 1, pdo, &instance_id),
            Err(CriticalChildStartError::StalePublication)
        );
        assert_eq!(
            queue.reserve_committed(&pnp, &relations, 0, pdo, &instance_id),
            Err(CriticalChildStartError::InvalidMount)
        );
        assert_eq!(
            queue.reserve_committed(&pnp, &_relations, 1, pdo, "wrong\\identity"),
            Err(CriticalChildStartError::StalePublication)
        );
    }

    #[test]
    fn replaced_mount_quarantines_reserved_start_before_dispatch() {
        let (pnp, relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let (key, _) = queue
            .reserve_committed(&pnp, &relations, 7, pdo, &instance_id)
            .unwrap();
        assert_eq!(
            queue.claim_next(&pnp, &relations, 8),
            Err(CriticalChildStartError::StalePublication)
        );
        assert_eq!(queue.state(key), Some(CriticalChildStartState::Uncertain));
        assert_eq!(queue.claim_next(&pnp, &relations, 8), Ok(None));
    }

    #[test]
    fn stale_relation_before_claim_is_never_dispatched() {
        let (pnp, mut relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let (key, _) = queue
            .reserve_committed(&pnp, &relations, 7, pdo, &instance_id)
            .unwrap();
        let next = relations.prepare_bus_relations(0x9000, &[]).unwrap();
        relations.commit_bus_relations(next).unwrap();
        assert_eq!(
            queue.claim_next(&pnp, &relations, 7),
            Err(CriticalChildStartError::StalePublication)
        );
        assert_eq!(queue.state(key), Some(CriticalChildStartState::Uncertain));
        assert_eq!(queue.claim_next(&pnp, &relations, 7), Ok(None));
    }
}
