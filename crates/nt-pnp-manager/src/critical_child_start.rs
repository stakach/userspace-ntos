use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    BusRelationTable, DevnodeIdentity, ParentRelationIdentity, PnpManager,
    PreparedBusRelations, PreparedEnumeratedPdoBatch, StartDeviceLifecycleReceipt,
};

/// One mounted SYSTEM hive's canonical child, published by an accepted BusRelations generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CriticalChildStartKey {
    mount_identity: u64,
    child: DevnodeIdentity,
    parent_relation: ParentRelationIdentity,
}

impl CriticalChildStartKey {
    pub const fn mount_identity(self) -> u64 {
        self.mount_identity
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

    /// Reserve queue storage before publishing a relation whose child must be started.
    pub fn reserve_capacity(&mut self, additional: usize) -> Result<(), CriticalChildStartError> {
        self.entries
            .try_reserve(additional)
            .map_err(|_| CriticalChildStartError::InsufficientResources)
    }

    /// Admit all critical starts against the prospective relation before any PnP publication.
    /// The later `reserve_committed` calls may allocate copies of instance IDs, but no stale or
    /// conflicting generation can be discovered after the PnP effect.
    pub fn validate_prospective_reservations(
        &self,
        pnp: &PnpManager,
        devnodes: &PreparedEnumeratedPdoBatch,
        relation: &PreparedBusRelations,
        mount_identity: u64,
        starts: &[(u64, String)],
    ) -> Result<(), CriticalChildStartError> {
        if mount_identity == 0 {
            return Err(CriticalChildStartError::InvalidMount);
        }
        let mut needed = 0usize;
        for (index, (pdo, instance_id)) in starts.iter().enumerate() {
            let (child, expected_instance, parent_relation) = devnodes
                .prospective_child(*pdo)
                .ok_or(CriticalChildStartError::StalePublication)?;
            if instance_id.is_empty()
                || instance_id != expected_instance
                || parent_relation.relation() != relation.relation_identity()
                || !pnp.relation_parent_is_started(parent_relation)
                || !relation.children().iter().any(|entry| entry.pdo_object_id == *pdo)
            {
                return Err(CriticalChildStartError::StalePublication);
            }
            if starts[..index].iter().any(|(prior, _)| prior == pdo) {
                return Err(CriticalChildStartError::ConflictingGeneration);
            }
            let key = CriticalChildStartKey { mount_identity, child, parent_relation };
            if let Some(entry) = self.entries.iter().find(|entry| entry.key == key) {
                if entry.instance_id != *instance_id {
                    return Err(CriticalChildStartError::ConflictingGeneration);
                }
            } else {
                if self.entries.iter().any(|entry| {
                    entry.key.child == child
                        && !matches!(entry.state, CriticalChildStartState::Retired(_))
                }) {
                    return Err(CriticalChildStartError::ConflictingGeneration);
                }
                needed = needed.checked_add(1)
                    .ok_or(CriticalChildStartError::InsufficientResources)?;
            }
        }
        if self.entries.len().checked_add(needed)
            .is_none_or(|length| length > self.entries.capacity())
        {
            return Err(CriticalChildStartError::InsufficientResources);
        }
        Ok(())
    }

    fn current_key(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        mount_identity: u64,
        child_pdo: u64,
        instance_id: &str,
    ) -> Result<CriticalChildStartKey, CriticalChildStartError> {
        if mount_identity == 0 {
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
            mount_identity,
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
        mount_identity: u64,
        child_pdo: u64,
        instance_id: &str,
    ) -> Result<(CriticalChildStartKey, CriticalChildStartState), CriticalChildStartError> {
        let mut owned_instance = String::new();
        owned_instance
            .try_reserve(instance_id.len())
            .map_err(|_| CriticalChildStartError::InsufficientResources)?;
        owned_instance.push_str(instance_id);
        self.reserve_committed_owned(pnp, relations, mount_identity, child_pdo, owned_instance)
    }

    /// Accept a pre-owned instance without allocating after the relation commit.
    pub fn reserve_committed_owned(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        mount_identity: u64,
        child_pdo: u64,
        instance_id: String,
    ) -> Result<(CriticalChildStartKey, CriticalChildStartState), CriticalChildStartError> {
        self.try_reserve_committed_owned(
            pnp, relations, mount_identity, child_pdo, instance_id,
        ).map_err(|(error, _instance_id)| error)
    }

    /// A refusal returns the exact owned instance so a retained publisher can redrive it.
    pub fn try_reserve_committed_owned(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        mount_identity: u64,
        child_pdo: u64,
        instance_id: String,
    ) -> Result<(CriticalChildStartKey, CriticalChildStartState), (CriticalChildStartError, String)> {
        let key = match Self::current_key(pnp, relations, mount_identity, child_pdo, &instance_id) {
            Ok(key) => key,
            Err(error) => return Err((error, instance_id)),
        };
        if let Some(entry) = self.entries.iter().find(|entry| entry.key == key) {
            return if entry.instance_id == instance_id {
                Ok((key, entry.state))
            } else {
                Err((CriticalChildStartError::ConflictingGeneration, instance_id))
            };
        }
        if self.entries.iter().any(|entry| {
            entry.key.child == key.child
                && !matches!(entry.state, CriticalChildStartState::Retired(_))
        }) {
            return Err((CriticalChildStartError::ConflictingGeneration, instance_id));
        }
        if self.entries.try_reserve(1).is_err() {
            return Err((CriticalChildStartError::InsufficientResources, instance_id));
        }
        self.entries.push(StartEntry {
            key,
            instance_id,
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
        mount_identity: u64,
    ) -> Result<Option<CriticalChildStartClaim>, CriticalChildStartError> {
        self.claim_next_ready(pnp, relations, mount_identity, |_, _| true)
    }

    /// Claim the oldest current child whose external START owner has retired. A skipped child
    /// stays reserved without consuming a token; stale publications are still quarantined.
    pub fn claim_next_ready(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        mount_identity: u64,
        mut ready: impl FnMut(CriticalChildStartKey, &str) -> bool,
    ) -> Result<Option<CriticalChildStartClaim>, CriticalChildStartError> {
        for index in 0..self.entries.len() {
            if self.entries[index].state != CriticalChildStartState::Reserved {
                continue;
            }
            let key = self.entries[index].key;
            if key.mount_identity != mount_identity
                || Self::current_key(
                    pnp,
                    relations,
                    key.mount_identity,
                    key.child.pdo_object_id(),
                    &self.entries[index].instance_id,
                ) != Ok(key)
            {
                self.entries[index].state = CriticalChildStartState::Uncertain;
                return Err(CriticalChildStartError::StalePublication);
            }
            if !ready(key, &self.entries[index].instance_id) {
                continue;
            }
            let token = self.next_token;
            self.next_token = token
                .checked_add(1)
                .ok_or(CriticalChildStartError::InsufficientResources)?;
            self.entries[index].token = token;
            self.entries[index].state = CriticalChildStartState::Claimed;
            return Ok(Some(CriticalChildStartClaim { key, token }));
        }
        Ok(None)
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

    /// Return an unentered demand claim behind other reserved children while another exact
    /// batch owns START. A later claim receives a fresh token after that owner has finished.
    pub fn defer(&mut self, claim: CriticalChildStartClaim) -> Result<(), CriticalChildStartError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.key == claim.key && entry.token == claim.token)
            .ok_or(CriticalChildStartError::InvalidClaim)?;
        if self.entries[index].state != CriticalChildStartState::Claimed {
            return Err(CriticalChildStartError::WrongPhase);
        }
        let mut entry = self.entries.remove(index);
        entry.token = 0;
        entry.state = CriticalChildStartState::Reserved;
        self.entries.push(entry);
        Ok(())
    }

    /// Identify a current reserved row for the receipt's exact child generation before
    /// validating the config owner's FDO. A retired row has already consumed its handoff.
    pub fn has_exact_receipt_child(
        &self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        mount_identity: u64,
        instance_id: &str,
        receipt: &StartDeviceLifecycleReceipt,
    ) -> Result<bool, CriticalChildStartError> {
        let dispatch = receipt.dispatch();
        let mut matching = self.entries.iter().filter(|entry| {
            entry.instance_id == instance_id
                && entry.key.mount_identity == mount_identity
                && entry.key.child.pdo_object_id() == receipt.pdo_device_id()
                && entry.key.child.devnode_id() == dispatch.devnode_id
                && entry.key.child.generation() == dispatch.devnode_generation
                && !matches!(entry.state, CriticalChildStartState::Retired(_))
        });
        let Some(entry) = matching.next() else {
            return Ok(false);
        };
        if matching.next().is_some() {
            return Err(CriticalChildStartError::ConflictingGeneration);
        }
        if entry.state != CriticalChildStartState::Reserved {
            return Err(CriticalChildStartError::WrongPhase);
        }
        if Self::current_key(
            pnp,
            relations,
            mount_identity,
            receipt.pdo_device_id(),
            instance_id,
        )? != entry.key
        {
            return Err(CriticalChildStartError::StalePublication);
        }
        Ok(true)
    }

    /// Retire a reserved demand only when an independent config owner already completed the
    /// same generation's canonical START and supplies its manager-minted terminal receipt.
    pub fn retire_reserved_from_start(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        mount_identity: u64,
        instance_id: &str,
        receipt: &StartDeviceLifecycleReceipt,
    ) -> Result<bool, CriticalChildStartError> {
        if !self.has_exact_receipt_child(pnp, relations, mount_identity, instance_id, receipt)? {
            return Ok(false);
        }
        let dispatch = receipt.dispatch();
        let current_parent = pnp
            .parent_relation_for_pdo(receipt.pdo_device_id())
            .ok_or(CriticalChildStartError::StalePublication)?;
        let Some(index) = self.entries.iter().position(|entry| {
            entry.instance_id == instance_id
                && entry.key.mount_identity == mount_identity
                && entry.key.parent_relation == current_parent
                && entry.key.child.pdo_object_id() == receipt.pdo_device_id()
                && entry.key.child.devnode_id() == dispatch.devnode_id
                && entry.key.child.generation() == dispatch.devnode_generation
        }) else {
            return Err(CriticalChildStartError::StalePublication);
        };
        let entry = &self.entries[index];
        if dispatch.minor != crate::PnpMinor::StartDevice
            || dispatch.canonical_irp_id == 0
            || dispatch.devnode_id != entry.key.child.devnode_id()
            || dispatch.devnode_generation != entry.key.child.generation()
            || Self::current_key(
                pnp,
                relations,
                mount_identity,
                receipt.pdo_device_id(),
                instance_id,
            ) != Ok(entry.key)
        {
            return Err(CriticalChildStartError::StalePublication);
        }
        if entry.state != CriticalChildStartState::Reserved {
            return Err(CriticalChildStartError::WrongPhase);
        }
        self.entries[index].state = CriticalChildStartState::Retired(receipt.start_status());
        Ok(true)
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

    pub fn claimed_instance_id(&self, claim: CriticalChildStartClaim) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| {
                entry.key == claim.key
                    && entry.token == claim.token
                    && entry.state == CriticalChildStartState::Claimed
            })
            .map(|entry| entry.instance_id.as_str())
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

    fn committed_children(include_second: bool) -> (PnpManager, BusRelationTable, Vec<(u64, String)>) {
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
        let first = BusReportedChild::new(
            0x1234,
            r"ACPI\PNP0303",
            "0001",
            &[r"ACPI\PNP0303"],
            &[] as &[&str],
        );
        let mut children = vec![first];
        if include_second {
            children.push(BusReportedChild::new(
                0x1235,
                r"PCI\VEN_1234&DEV_1111",
                "0002",
                &[r"PCI\VEN_1234&DEV_1111"],
                &[] as &[&str],
            ));
        }
        let mut relations = BusRelationTable::new();
        relations.seed_bus_relations(0x9000, &[]).unwrap();
        let prepared_relation = relations
            .prepare_bus_relations(0x9000, &children)
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
        let identities: Vec<_> = children
            .iter()
            .map(|child| (child.pdo_object_id, child.enum_instance_path()))
            .collect();
        let prepared_child = pnp
            .prepare_enumerated_pdo_batch(
                identities
                    .iter()
                    .map(|(pdo, instance_id)| {
                        EnumeratedPdoRecord::new(instance_id.clone(), *pdo, properties.clone())
                            .with_parent_relation(parent_relation)
                    })
                    .collect(),
            )
            .unwrap();
        pnp.commit_enumerated_pdo_batch(prepared_child).unwrap();
        relations.commit_bus_relations(prepared_relation).unwrap();
        (pnp, relations, identities)
    }

    fn committed_child() -> (PnpManager, BusRelationTable, u64, String) {
        let (pnp, relations, mut children) = committed_children(false);
        let (pdo, instance_id) = children.pop().unwrap();
        (pnp, relations, pdo, instance_id)
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
    fn pending_config_batch_defers_demand_without_replaying_its_claim() {
        let (pnp, relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let (key, _) = queue
            .reserve_committed(&pnp, &relations, 7, pdo, &instance_id)
            .unwrap();
        let first = queue.claim_next(&pnp, &relations, 7).unwrap().unwrap();
        assert_eq!(queue.defer(first), Ok(()));
        assert_eq!(queue.state(key), Some(CriticalChildStartState::Reserved));
        assert_eq!(
            queue.complete(first, 0),
            Err(CriticalChildStartError::InvalidClaim)
        );
        let second = queue.claim_next(&pnp, &relations, 7).unwrap().unwrap();
        assert_ne!(first, second);
        queue.complete(second, 0).unwrap();
        assert_eq!(queue.retire(second), Ok(0));
    }

    #[test]
    fn deferred_config_child_does_not_starve_later_bus_child() {
        let (pnp, relations, children) = committed_children(true);
        let mut queue = CriticalChildStartQueue::new();
        let (mouse_pdo, mouse_instance) = &children[0];
        let (pci_pdo, pci_instance) = &children[1];
        let (mouse_key, _) = queue
            .reserve_committed(&pnp, &relations, 7, *mouse_pdo, mouse_instance)
            .unwrap();
        let (pci_key, _) = queue
            .reserve_committed(&pnp, &relations, 7, *pci_pdo, pci_instance)
            .unwrap();

        let first = queue.claim_next(&pnp, &relations, 7).unwrap().unwrap();
        assert_eq!(first.key(), mouse_key);
        queue.defer(first).unwrap();
        assert_eq!(queue.state(mouse_key), Some(CriticalChildStartState::Reserved));
        assert_eq!(queue.complete(first, 0), Err(CriticalChildStartError::InvalidClaim));

        let second = queue.claim_next(&pnp, &relations, 7).unwrap().unwrap();
        assert_eq!(second.key(), pci_key);
        queue.complete(second, 0).unwrap();
        assert_eq!(queue.retire(second), Ok(0));

        let reclaimed = queue.claim_next(&pnp, &relations, 7).unwrap().unwrap();
        assert_eq!(reclaimed.key(), mouse_key);
        assert_ne!(reclaimed, first);
    }

    #[test]
    fn pending_owner_does_not_reclaim_or_starve_reserved_children() {
        let (pnp, relations, children) = committed_children(true);
        let mut queue = CriticalChildStartQueue::new();
        let (blocked_pdo, blocked_instance) = &children[0];
        let (ready_pdo, ready_instance) = &children[1];
        let (blocked_key, _) = queue
            .reserve_committed(&pnp, &relations, 7, *blocked_pdo, blocked_instance)
            .unwrap();
        let (ready_key, _) = queue
            .reserve_committed(&pnp, &relations, 7, *ready_pdo, ready_instance)
            .unwrap();
        let first_token = queue.next_token;

        for _ in 0..32 {
            let claim = queue
                .claim_next_ready(&pnp, &relations, 7, |key, _| key != blocked_key)
                .unwrap();
            if let Some(claim) = claim {
                assert_eq!(claim.key(), ready_key);
                queue.complete(claim, 0).unwrap();
                queue.retire(claim).unwrap();
            }
            assert_eq!(queue.state(blocked_key), Some(CriticalChildStartState::Reserved));
        }
        assert_eq!(queue.next_token, first_token + 1);

        let claim = queue
            .claim_next_ready(&pnp, &relations, 7, |_, _| true)
            .unwrap()
            .unwrap();
        assert_eq!(claim.key(), blocked_key);
        assert_eq!(queue.next_token, first_token + 2);
    }

    #[test]
    fn blocked_child_with_stale_publication_is_quarantined() {
        let (pnp, mut relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let (key, _) = queue
            .reserve_committed(&pnp, &relations, 7, pdo, &instance_id)
            .unwrap();
        let next_token = queue.next_token;
        let next = relations.prepare_bus_relations(0x9000, &[]).unwrap();
        relations.commit_bus_relations(next).unwrap();

        assert_eq!(
            queue.claim_next_ready(&pnp, &relations, 7, |_, _| false),
            Err(CriticalChildStartError::StalePublication)
        );
        assert_eq!(queue.state(key), Some(CriticalChildStartState::Uncertain));
        assert_eq!(queue.next_token, next_token);
    }

    #[test]
    fn config_terminal_retires_only_same_generation_reserved_critical_start() {
        let (pnp, relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let (key, _) = queue
            .reserve_committed(&pnp, &relations, 7, pdo, &instance_id)
            .unwrap();
        let receipt = crate::StartDeviceLifecycleReceipt {
            dispatch: crate::PnpDispatchIdentity {
                devnode_id: key.child().devnode_id(),
                devnode_generation: key.child().generation(),
                dispatch_generation: 1,
                canonical_irp_id: 0x4567,
                minor: crate::PnpMinor::StartDevice,
            },
            pdo_device_id: pdo,
            fdo_device_id: 0x7777,
            origin_driver_id: 0x8888,
            completion_driver_id: 0x8888,
            completion_device_id: 0x7777,
            driver_pending: false,
            start_status: 0xc000_0010,
        };
        assert_eq!(
            queue.retire_reserved_from_start(&pnp, &relations, 7, &instance_id, &receipt),
            Ok(true),
        );
        assert_eq!(
            queue.state(key),
            Some(CriticalChildStartState::Retired(0xc000_0010))
        );
        assert_eq!(queue.claim_next(&pnp, &relations, 7), Ok(None));
    }

    #[test]
    fn config_terminal_skips_retired_prior_generation_with_reused_pdo() {
        let (pnp, relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let (current, _) = queue
            .reserve_committed(&pnp, &relations, 7, pdo, &instance_id)
            .unwrap();
        let mut prior = current;
        prior.child = crate::DevnodeIdentity {
            devnode_id: current.child().devnode_id(),
            generation: current.child().generation().checked_add(1).unwrap(),
            pdo_object_id: pdo,
        };
        queue.entries.insert(
            0,
            StartEntry {
                key: prior,
                instance_id: instance_id.clone(),
                state: CriticalChildStartState::Retired(0),
                token: 0,
            },
        );
        let receipt = crate::StartDeviceLifecycleReceipt {
            dispatch: crate::PnpDispatchIdentity {
                devnode_id: current.child().devnode_id(),
                devnode_generation: current.child().generation(),
                dispatch_generation: 1,
                canonical_irp_id: 0x4567,
                minor: crate::PnpMinor::StartDevice,
            },
            pdo_device_id: pdo,
            fdo_device_id: 0x7777,
            origin_driver_id: 0x8888,
            completion_driver_id: 0x8888,
            completion_device_id: 0x7777,
            driver_pending: false,
            start_status: 0xc000_0010,
        };
        assert_eq!(
            queue.retire_reserved_from_start(&pnp, &relations, 7, &instance_id, &receipt),
            Ok(true),
        );
        assert_eq!(
            queue.state(current),
            Some(CriticalChildStartState::Retired(0xc000_0010))
        );
        assert_eq!(
            queue.state(prior),
            Some(CriticalChildStartState::Retired(0))
        );
    }

    #[test]
    fn root_start_without_critical_child_does_not_require_handoff() {
        let (pnp, relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let child = pnp.devnode_identity_for_pdo(pdo).unwrap();
        let receipt = crate::StartDeviceLifecycleReceipt {
            dispatch: crate::PnpDispatchIdentity {
                devnode_id: child.devnode_id(),
                devnode_generation: child.generation(),
                dispatch_generation: 1,
                canonical_irp_id: 0x4567,
                minor: crate::PnpMinor::StartDevice,
            },
            pdo_device_id: pdo,
            fdo_device_id: 0x7777,
            origin_driver_id: 0x8888,
            completion_driver_id: 0x8888,
            completion_device_id: 0x7777,
            driver_pending: false,
            start_status: 0,
        };
        assert_eq!(
            queue.has_exact_receipt_child(&pnp, &relations, 7, &instance_id, &receipt),
            Ok(false),
        );
        assert_eq!(
            queue.retire_reserved_from_start(&pnp, &relations, 7, &instance_id, &receipt),
            Ok(false),
        );
    }

    #[test]
    fn repeated_config_terminal_has_no_reserved_child_handoff() {
        let (pnp, relations, pdo, instance_id) = committed_child();
        let mut queue = CriticalChildStartQueue::new();
        let (key, _) = queue
            .reserve_committed(&pnp, &relations, 7, pdo, &instance_id)
            .unwrap();
        let receipt = crate::StartDeviceLifecycleReceipt {
            dispatch: crate::PnpDispatchIdentity {
                devnode_id: key.child().devnode_id(),
                devnode_generation: key.child().generation(),
                dispatch_generation: 1,
                canonical_irp_id: 0x4567,
                minor: crate::PnpMinor::StartDevice,
            },
            pdo_device_id: pdo,
            fdo_device_id: 0x7777,
            origin_driver_id: 0x8888,
            completion_driver_id: 0x8888,
            completion_device_id: 0x7777,
            driver_pending: false,
            start_status: 0,
        };
        assert_eq!(
            queue.has_exact_receipt_child(&pnp, &relations, 7, &instance_id, &receipt),
            Ok(true),
        );
        assert_eq!(
            queue.retire_reserved_from_start(&pnp, &relations, 7, &instance_id, &receipt),
            Ok(true),
        );
        assert_eq!(queue.state(key), Some(CriticalChildStartState::Retired(0)));
        assert_eq!(
            queue.has_exact_receipt_child(&pnp, &relations, 7, &instance_id, &receipt),
            Ok(false),
        );
        assert_eq!(
            queue.retire_reserved_from_start(&pnp, &relations, 7, &instance_id, &receipt),
            Ok(false),
        );
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
