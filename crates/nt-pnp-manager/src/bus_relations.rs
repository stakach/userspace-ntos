use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Bytes before the first pointer in the native x64 `DEVICE_RELATIONS` layout. `Count` occupies
/// the first four bytes and the pointer array is naturally aligned at offset eight.
pub const DEVICE_RELATIONS_X64_HEADER_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceRelationsCopyError {
    TruncatedHeader,
    SizeOverflow,
    TruncatedObjects,
    NullPdo,
    DuplicatePdo,
    InsufficientResources,
}

/// Validate and copy one driver-owned native x64 `DEVICE_RELATIONS` allocation.
///
/// The input may include allocator capacity after the native object, so only the count-derived
/// prefix is consumed. Copying the PDO values into PnP-owned storage lets the caller release the
/// driver's allocation before issuing any child queries.
pub fn copy_device_relations_x64(bytes: &[u8]) -> Result<Vec<u64>, DeviceRelationsCopyError> {
    if bytes.len() < DEVICE_RELATIONS_X64_HEADER_BYTES {
        return Err(DeviceRelationsCopyError::TruncatedHeader);
    }
    let count = u32::from_le_bytes(
        bytes[..4]
            .try_into()
            .expect("four-byte DEVICE_RELATIONS count slice"),
    ) as usize;
    let objects_bytes = count
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(DeviceRelationsCopyError::SizeOverflow)?;
    let required = DEVICE_RELATIONS_X64_HEADER_BYTES
        .checked_add(objects_bytes)
        .ok_or(DeviceRelationsCopyError::SizeOverflow)?;
    if required > bytes.len() {
        return Err(DeviceRelationsCopyError::TruncatedObjects);
    }

    let mut objects = Vec::new();
    objects
        .try_reserve_exact(count)
        .map_err(|_| DeviceRelationsCopyError::InsufficientResources)?;
    for encoded in bytes[DEVICE_RELATIONS_X64_HEADER_BYTES..required].chunks_exact(8) {
        let object = u64::from_le_bytes(encoded.try_into().expect("eight-byte PDO slice"));
        if object == 0 {
            return Err(DeviceRelationsCopyError::NullPdo);
        }
        if objects.contains(&object) {
            return Err(DeviceRelationsCopyError::DuplicatePdo);
        }
        objects.push(object);
    }
    Ok(objects)
}

/// Exact ownership of one queued `IoInvalidateDeviceRelations` request. The PDO is represented by
/// its canonical I/O Manager device ID rather than a hosted address, so queue ownership survives
/// component-local projections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceRelationInvalidation {
    pub pdo_device_id: u64,
    pub relation_type: u32,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceRelationInvalidationDisposition {
    Queued,
    Coalesced,
    Requeued,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnqueuedDeviceRelationInvalidation {
    pub disposition: DeviceRelationInvalidationDisposition,
    pub invalidation: DeviceRelationInvalidation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceRelationInvalidationError {
    InvalidPdo,
    SequenceExhausted,
    InsufficientResources,
    StaleClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeviceRelationInvalidationState {
    Pending {
        sequence: u64,
    },
    Claimed {
        sequence: u64,
        requeue_sequence: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DeviceRelationInvalidationRow {
    pdo_device_id: u64,
    relation_type: u32,
    state: DeviceRelationInvalidationState,
}

/// Lossless executive-facing invalidation queue.
///
/// Repeated invalidations coalesce while pending. Once a worker owns a query, the first new
/// invalidation reserves a later sequence and therefore survives completion of the in-flight
/// query. Claim, completion, and abort allocate nothing.
#[derive(Default)]
pub struct DeviceRelationInvalidationQueue {
    next_sequence: u64,
    rows: Vec<DeviceRelationInvalidationRow>,
}

impl DeviceRelationInvalidationQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn enqueue(
        &mut self,
        pdo_device_id: u64,
        relation_type: u32,
    ) -> Result<EnqueuedDeviceRelationInvalidation, DeviceRelationInvalidationError> {
        if pdo_device_id == 0 {
            return Err(DeviceRelationInvalidationError::InvalidPdo);
        }
        if let Some(index) = self.rows.iter().position(|row| {
            row.pdo_device_id == pdo_device_id && row.relation_type == relation_type
        }) {
            return match self.rows[index].state {
                DeviceRelationInvalidationState::Pending { sequence } => {
                    Ok(EnqueuedDeviceRelationInvalidation {
                        disposition: DeviceRelationInvalidationDisposition::Coalesced,
                        invalidation: DeviceRelationInvalidation {
                            pdo_device_id,
                            relation_type,
                            sequence,
                        },
                    })
                }
                DeviceRelationInvalidationState::Claimed {
                    requeue_sequence: Some(sequence),
                    ..
                } => Ok(EnqueuedDeviceRelationInvalidation {
                    disposition: DeviceRelationInvalidationDisposition::Coalesced,
                    invalidation: DeviceRelationInvalidation {
                        pdo_device_id,
                        relation_type,
                        sequence,
                    },
                }),
                DeviceRelationInvalidationState::Claimed {
                    sequence,
                    requeue_sequence: None,
                } => {
                    let requeue_sequence = self.allocate_sequence()?;
                    self.rows[index].state = DeviceRelationInvalidationState::Claimed {
                        sequence,
                        requeue_sequence: Some(requeue_sequence),
                    };
                    Ok(EnqueuedDeviceRelationInvalidation {
                        disposition: DeviceRelationInvalidationDisposition::Requeued,
                        invalidation: DeviceRelationInvalidation {
                            pdo_device_id,
                            relation_type,
                            sequence: requeue_sequence,
                        },
                    })
                }
            };
        }

        self.rows
            .try_reserve(1)
            .map_err(|_| DeviceRelationInvalidationError::InsufficientResources)?;
        let sequence = self.allocate_sequence()?;
        self.rows.push(DeviceRelationInvalidationRow {
            pdo_device_id,
            relation_type,
            state: DeviceRelationInvalidationState::Pending { sequence },
        });
        Ok(EnqueuedDeviceRelationInvalidation {
            disposition: DeviceRelationInvalidationDisposition::Queued,
            invalidation: DeviceRelationInvalidation {
                pdo_device_id,
                relation_type,
                sequence,
            },
        })
    }

    pub fn claim_front(&mut self) -> Option<DeviceRelationInvalidation> {
        let (index, sequence) = self
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, row)| match row.state {
                DeviceRelationInvalidationState::Pending { sequence } => Some((index, sequence)),
                DeviceRelationInvalidationState::Claimed { .. } => None,
            })
            .min_by_key(|(_, sequence)| *sequence)?;
        let row = &mut self.rows[index];
        row.state = DeviceRelationInvalidationState::Claimed {
            sequence,
            requeue_sequence: None,
        };
        Some(DeviceRelationInvalidation {
            pdo_device_id: row.pdo_device_id,
            relation_type: row.relation_type,
            sequence,
        })
    }

    pub fn complete(
        &mut self,
        claim: DeviceRelationInvalidation,
    ) -> Result<(), DeviceRelationInvalidationError> {
        let index = self.claimed_row_index(claim)?;
        match self.rows[index].state {
            DeviceRelationInvalidationState::Claimed {
                requeue_sequence: Some(sequence),
                ..
            } => {
                self.rows[index].state = DeviceRelationInvalidationState::Pending { sequence };
            }
            DeviceRelationInvalidationState::Claimed {
                requeue_sequence: None,
                ..
            } => {
                self.rows.remove(index);
            }
            DeviceRelationInvalidationState::Pending { .. } => unreachable!(),
        }
        Ok(())
    }

    pub fn abort(
        &mut self,
        claim: DeviceRelationInvalidation,
    ) -> Result<(), DeviceRelationInvalidationError> {
        let index = self.claimed_row_index(claim)?;
        self.rows[index].state = DeviceRelationInvalidationState::Pending {
            sequence: claim.sequence,
        };
        Ok(())
    }

    fn allocate_sequence(&mut self) -> Result<u64, DeviceRelationInvalidationError> {
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(DeviceRelationInvalidationError::SequenceExhausted)?;
        self.next_sequence = sequence;
        Ok(sequence)
    }

    fn claimed_row_index(
        &self,
        claim: DeviceRelationInvalidation,
    ) -> Result<usize, DeviceRelationInvalidationError> {
        self.rows
            .iter()
            .position(|row| {
                row.pdo_device_id == claim.pdo_device_id
                    && row.relation_type == claim.relation_type
                    && matches!(
                        row.state,
                        DeviceRelationInvalidationState::Claimed { sequence, .. }
                            if sequence == claim.sequence
                    )
            })
            .ok_or(DeviceRelationInvalidationError::StaleClaim)
    }
}

/// Identity returned by a bus for one child PDO after PnP has completed the child's QUERY_ID
/// requests. Service selection is deliberately absent: buses describe hardware, while CM/setup
/// policy binds that identity to a function driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusReportedChild {
    pub pdo_object_id: u64,
    pub device_id: String,
    pub instance_id: String,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
}

impl BusReportedChild {
    pub fn new<H, C>(
        pdo_object_id: u64,
        device_id: &str,
        instance_id: &str,
        hardware_ids: &[H],
        compatible_ids: &[C],
    ) -> Self
    where
        H: AsRef<str>,
        C: AsRef<str>,
    {
        Self {
            pdo_object_id,
            device_id: device_id.to_string(),
            instance_id: instance_id.to_string(),
            hardware_ids: hardware_ids
                .iter()
                .map(|value| value.as_ref().to_string())
                .collect(),
            compatible_ids: compatible_ids
                .iter()
                .map(|value| value.as_ref().to_string())
                .collect(),
        }
    }

    pub fn enum_instance_path(&self) -> String {
        let mut path = String::with_capacity(
            self.device_id
                .len()
                .saturating_add(1)
                .saturating_add(self.instance_id.len()),
        );
        path.push_str(&self.device_id);
        path.push('\\');
        path.push_str(&self.instance_id);
        path
    }

    fn validate(&self) -> Result<(), BusRelationError> {
        if self.pdo_object_id == 0
            || self.device_id.is_empty()
            || self.instance_id.is_empty()
            || self.hardware_ids.is_empty()
            || self.hardware_ids.iter().any(|id| id.is_empty())
            || self.compatible_ids.iter().any(|id| id.is_empty())
        {
            return Err(BusRelationError::InvalidChild);
        }
        Ok(())
    }

    fn same_devnode(&self, other: &Self) -> bool {
        self.device_id.eq_ignore_ascii_case(&other.device_id)
            && self.instance_id.eq_ignore_ascii_case(&other.instance_id)
    }

    fn same_ids(&self, other: &Self) -> bool {
        ascii_list_eq(&self.hardware_ids, &other.hardware_ids)
            && ascii_list_eq(&self.compatible_ids, &other.compatible_ids)
    }
}

fn ascii_list_eq(left: &[String], right: &[String]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusRelationChangeKind {
    Arrival,
    Change,
    Removal,
}

/// One semantic difference in a complete bus-relations query. Arrival/change carry the current
/// bus identity; removal carries the last accepted identity. A single diff never emits two changes
/// for the same Enum instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusRelationChange {
    pub kind: BusRelationChangeKind,
    pub child: BusReportedChild,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusRelationError {
    InvalidBus,
    InvalidChild,
    DuplicatePdo,
    DuplicateDevnode,
    ConflictingPdo,
    AlreadySeeded,
    StaleTransaction,
    GenerationExhausted,
    InsufficientResources,
}

#[derive(Clone, Debug)]
struct AcceptedBusRelations {
    bus_object_id: u64,
    children: Vec<BusReportedChild>,
}

/// Exact prepared ownership for one complete bus-relations publication. The next relation set is
/// private so callers cannot commit a delta other than the one PnP validated.
#[derive(Debug, PartialEq, Eq)]
pub struct PreparedBusRelations {
    base_generation: u64,
    next_generation: u64,
    bus_object_id: u64,
    next_children: Vec<BusReportedChild>,
    changes: Vec<BusRelationChange>,
}

impl PreparedBusRelations {
    pub fn changes(&self) -> &[BusRelationChange] {
        &self.changes
    }

    pub const fn base_generation(&self) -> u64 {
        self.base_generation
    }

    pub const fn next_generation(&self) -> u64 {
        self.next_generation
    }

    pub const fn bus_object_id(&self) -> u64 {
        self.bus_object_id
    }
}

/// Last accepted complete child relation set for every bus. Preparing a relation query reserves
/// all storage but changes no semantic state; callers may therefore publish the resulting CM
/// transaction durably before committing this exact prepared owner without a later allocation.
#[derive(Default)]
pub struct BusRelationTable {
    generation: u64,
    buses: Vec<AcceptedBusRelations>,
}

impl BusRelationTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn accepted_children(&self, bus_object_id: u64) -> Option<&[BusReportedChild]> {
        self.buses
            .iter()
            .find(|bus| bus.bus_object_id == bus_object_id)
            .map(|bus| bus.children.as_slice())
    }

    /// Install boot-discovered relations as the comparison baseline without manufacturing arrival
    /// actions. Each bus can be seeded exactly once.
    pub fn seed_bus_relations(
        &mut self,
        bus_object_id: u64,
        children: &[BusReportedChild],
    ) -> Result<u64, BusRelationError> {
        if bus_object_id == 0 {
            return Err(BusRelationError::InvalidBus);
        }
        if self
            .buses
            .iter()
            .any(|bus| bus.bus_object_id == bus_object_id)
        {
            return Err(BusRelationError::AlreadySeeded);
        }
        validate_complete_relations(children)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(BusRelationError::GenerationExhausted)?;
        self.buses
            .try_reserve(1)
            .map_err(|_| BusRelationError::InsufficientResources)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(children.len())
            .map_err(|_| BusRelationError::InsufficientResources)?;
        owned.extend_from_slice(children);
        self.buses.push(AcceptedBusRelations {
            bus_object_id,
            children: owned,
        });
        self.generation = next_generation;
        Ok(next_generation)
    }

    /// Validate and diff one complete QUERY_DEVICE_RELATIONS(BusRelations) result. Capacity needed
    /// by a future commit is reserved here; dropping the owner aborts without changing relations.
    pub fn prepare_bus_relations(
        &mut self,
        bus_object_id: u64,
        children: &[BusReportedChild],
    ) -> Result<PreparedBusRelations, BusRelationError> {
        if bus_object_id == 0 {
            return Err(BusRelationError::InvalidBus);
        }
        validate_complete_relations(children)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(BusRelationError::GenerationExhausted)?;
        let previous = self
            .buses
            .iter()
            .find(|bus| bus.bus_object_id == bus_object_id)
            .map(|bus| bus.children.as_slice())
            .unwrap_or(&[]);
        validate_stable_pdo_identities(previous, children)?;

        let mut next_children = Vec::new();
        next_children
            .try_reserve_exact(children.len())
            .map_err(|_| BusRelationError::InsufficientResources)?;
        next_children.extend_from_slice(children);

        let mut changes = Vec::new();
        changes
            .try_reserve_exact(children.len().saturating_add(previous.len()))
            .map_err(|_| BusRelationError::InsufficientResources)?;
        for child in children {
            match previous.iter().find(|old| old.same_devnode(child)) {
                None => changes.push(BusRelationChange {
                    kind: BusRelationChangeKind::Arrival,
                    child: child.clone(),
                }),
                Some(old) if !old.same_ids(child) => changes.push(BusRelationChange {
                    kind: BusRelationChangeKind::Change,
                    child: child.clone(),
                }),
                Some(_) => {}
            }
        }
        for old in previous {
            if !children.iter().any(|child| child.same_devnode(old)) {
                changes.push(BusRelationChange {
                    kind: BusRelationChangeKind::Removal,
                    child: old.clone(),
                });
            }
        }
        if self
            .buses
            .iter()
            .all(|bus| bus.bus_object_id != bus_object_id)
        {
            self.buses
                .try_reserve(1)
                .map_err(|_| BusRelationError::InsufficientResources)?;
        }
        Ok(PreparedBusRelations {
            base_generation: self.generation,
            next_generation,
            bus_object_id,
            next_children,
            changes,
        })
    }

    /// Commit only the exact owner prepared against the current relation generation. Once the
    /// caller has durably published corresponding CM actions, this operation allocates nothing.
    pub fn commit_bus_relations(
        &mut self,
        prepared: PreparedBusRelations,
    ) -> Result<u64, BusRelationError> {
        if prepared.base_generation != self.generation
            || prepared.next_generation != self.generation.saturating_add(1)
        {
            return Err(BusRelationError::StaleTransaction);
        }
        if let Some(bus) = self
            .buses
            .iter_mut()
            .find(|bus| bus.bus_object_id == prepared.bus_object_id)
        {
            bus.children = prepared.next_children;
        } else {
            debug_assert!(self.buses.len() < self.buses.capacity());
            self.buses.push(AcceptedBusRelations {
                bus_object_id: prepared.bus_object_id,
                children: prepared.next_children,
            });
        }
        self.generation = prepared.next_generation;
        Ok(self.generation)
    }
}

fn validate_complete_relations(children: &[BusReportedChild]) -> Result<(), BusRelationError> {
    for (index, child) in children.iter().enumerate() {
        child.validate()?;
        for other in &children[..index] {
            if child.pdo_object_id == other.pdo_object_id {
                return Err(BusRelationError::DuplicatePdo);
            }
            if child.same_devnode(other) {
                return Err(BusRelationError::DuplicateDevnode);
            }
        }
    }
    Ok(())
}

fn validate_stable_pdo_identities(
    previous: &[BusReportedChild],
    current: &[BusReportedChild],
) -> Result<(), BusRelationError> {
    for child in current {
        if let Some(old) = previous
            .iter()
            .find(|old| old.pdo_object_id == child.pdo_object_id)
        {
            if !old.same_devnode(child) {
                return Err(BusRelationError::ConflictingPdo);
            }
        }
        if let Some(old) = previous.iter().find(|old| old.same_devnode(child)) {
            if old.pdo_object_id != child.pdo_object_id {
                return Err(BusRelationError::ConflictingPdo);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn native_relations(objects: &[u64], allocation_bytes: usize) -> Vec<u8> {
        let required = DEVICE_RELATIONS_X64_HEADER_BYTES + objects.len() * 8;
        let mut bytes = vec![0xa5; allocation_bytes.max(required)];
        bytes[..4].copy_from_slice(&(objects.len() as u32).to_le_bytes());
        bytes[4..8].fill(0);
        for (index, object) in objects.iter().enumerate() {
            let offset = DEVICE_RELATIONS_X64_HEADER_BYTES + index * 8;
            bytes[offset..offset + 8].copy_from_slice(&object.to_le_bytes());
        }
        bytes
    }

    fn child(pdo: u64, instance: &str, hardware: &[&str]) -> BusReportedChild {
        BusReportedChild::new(
            pdo,
            r"ROOT\USERSPACE_NTOS_LIVE",
            instance,
            hardware,
            &[r"ROOT\USERSPACE_NTOS_TEST_DEVICE"],
        )
    }

    #[test]
    fn native_device_relations_are_copied_from_the_counted_prefix() {
        let allocation = native_relations(&[0x1000, 0x2000, 0x3000], 96);
        assert_eq!(
            copy_device_relations_x64(&allocation),
            Ok(vec![0x1000, 0x2000, 0x3000])
        );
        assert_eq!(
            copy_device_relations_x64(&native_relations(&[], 32)),
            Ok(Vec::new())
        );
    }

    #[test]
    fn native_device_relations_reject_truncated_storage() {
        assert_eq!(
            copy_device_relations_x64(&[0; 7]),
            Err(DeviceRelationsCopyError::TruncatedHeader)
        );
        let mut allocation = native_relations(&[0x1000], 16);
        allocation[..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            copy_device_relations_x64(&allocation),
            Err(DeviceRelationsCopyError::TruncatedObjects)
        );
    }

    #[test]
    fn native_device_relations_reject_null_and_duplicate_pdos() {
        assert_eq!(
            copy_device_relations_x64(&native_relations(&[0], 16)),
            Err(DeviceRelationsCopyError::NullPdo)
        );
        assert_eq!(
            copy_device_relations_x64(&native_relations(&[0x1000, 0x1000], 24)),
            Err(DeviceRelationsCopyError::DuplicatePdo)
        );
    }

    #[test]
    fn seeded_relations_are_a_baseline_not_arrivals() {
        let mut table = BusRelationTable::new();
        let original = child(10, "0001", &[r"ROOT\USERSPACE_NTOS_LIVE"]);
        assert_eq!(table.seed_bus_relations(1, &[original.clone()]), Ok(1));
        assert_eq!(table.generation(), 1);
        let prepared = table.prepare_bus_relations(1, &[original.clone()]).unwrap();
        assert!(prepared.changes().is_empty());
        assert_eq!(table.accepted_children(1), Some([original].as_slice()));
        assert_eq!(table.commit_bus_relations(prepared), Ok(2));
    }

    #[test]
    fn prepare_is_abortable_and_commit_publishes_exact_relations() {
        let mut table = BusRelationTable::new();
        table.seed_bus_relations(1, &[]).unwrap();
        let arrived = child(10, "0001", &[r"ROOT\USERSPACE_NTOS_LIVE"]);
        let prepared = table.prepare_bus_relations(1, &[arrived.clone()]).unwrap();
        assert_eq!(
            prepared.changes(),
            &[BusRelationChange {
                kind: BusRelationChangeKind::Arrival,
                child: arrived.clone(),
            }]
        );
        assert!(table.accepted_children(1).unwrap().is_empty());
        assert_eq!(table.commit_bus_relations(prepared), Ok(2));
        assert_eq!(table.accepted_children(1), Some([arrived].as_slice()));
    }

    #[test]
    fn complete_query_emits_change_then_arrival_then_removal_in_stable_order() {
        let mut table = BusRelationTable::new();
        let removed = child(10, "0001", &["OLD"]);
        let changed = child(11, "0002", &["OLD"]);
        table
            .seed_bus_relations(1, &[removed.clone(), changed.clone()])
            .unwrap();
        let changed_now = child(11, "0002", &["NEW"]);
        let arrived = child(12, "0003", &["NEW"]);
        let prepared = table
            .prepare_bus_relations(1, &[changed_now.clone(), arrived.clone()])
            .unwrap();
        assert_eq!(
            prepared.changes(),
            &[
                BusRelationChange {
                    kind: BusRelationChangeKind::Change,
                    child: changed_now,
                },
                BusRelationChange {
                    kind: BusRelationChangeKind::Arrival,
                    child: arrived,
                },
                BusRelationChange {
                    kind: BusRelationChangeKind::Removal,
                    child: removed,
                },
            ]
        );
    }

    #[test]
    fn different_buses_keep_independent_complete_relation_sets() {
        let mut table = BusRelationTable::new();
        table
            .seed_bus_relations(1, &[child(10, "0001", &["A"])])
            .unwrap();
        table
            .seed_bus_relations(2, &[child(20, "0002", &["B"])])
            .unwrap();
        let prepared = table
            .prepare_bus_relations(2, &[child(20, "0002", &["B"])])
            .unwrap();
        assert!(prepared.changes().is_empty());
        table.commit_bus_relations(prepared).unwrap();
        assert_eq!(table.accepted_children(1).unwrap()[0].pdo_object_id, 10);
        assert_eq!(table.accepted_children(2).unwrap()[0].pdo_object_id, 20);
    }

    #[test]
    fn duplicate_and_unstable_identities_are_rejected_without_mutation() {
        let mut table = BusRelationTable::new();
        let original = child(10, "0001", &["A"]);
        table.seed_bus_relations(1, &[original.clone()]).unwrap();
        assert_eq!(
            table.prepare_bus_relations(1, &[original.clone(), original.clone()]),
            Err(BusRelationError::DuplicatePdo)
        );
        assert_eq!(
            table.prepare_bus_relations(1, &[child(11, "0001", &["A"])]),
            Err(BusRelationError::ConflictingPdo)
        );
        assert_eq!(
            table.prepare_bus_relations(1, &[child(10, "0002", &["A"])]),
            Err(BusRelationError::ConflictingPdo)
        );
        assert_eq!(table.generation(), 1);
        assert_eq!(table.accepted_children(1), Some([original].as_slice()));
    }

    #[test]
    fn prepared_owner_is_generation_fenced_across_buses() {
        let mut table = BusRelationTable::new();
        table.seed_bus_relations(1, &[]).unwrap();
        table.seed_bus_relations(2, &[]).unwrap();
        let stale = table
            .prepare_bus_relations(1, &[child(10, "0001", &["A"])])
            .unwrap();
        let current = table
            .prepare_bus_relations(2, &[child(20, "0002", &["B"])])
            .unwrap();
        assert_eq!(table.commit_bus_relations(current), Ok(3));
        assert_eq!(
            table.commit_bus_relations(stale),
            Err(BusRelationError::StaleTransaction)
        );
        assert!(table.accepted_children(1).unwrap().is_empty());
    }

    #[test]
    fn invalid_children_and_duplicate_seed_are_rejected() {
        let mut table = BusRelationTable::new();
        assert_eq!(
            table.seed_bus_relations(0, &[]),
            Err(BusRelationError::InvalidBus)
        );
        assert_eq!(
            table.seed_bus_relations(1, &[child(0, "0001", &["A"])]),
            Err(BusRelationError::InvalidChild)
        );
        table.seed_bus_relations(1, &[]).unwrap();
        assert_eq!(
            table.seed_bus_relations(1, &[]),
            Err(BusRelationError::AlreadySeeded)
        );
    }

    #[test]
    fn enum_path_preserves_bus_reported_device_and_instance_identity() {
        assert_eq!(
            child(10, "0001", &["A"]).enum_instance_path(),
            r"ROOT\USERSPACE_NTOS_LIVE\0001"
        );
    }

    #[test]
    fn pending_device_relation_invalidations_coalesce() {
        let mut queue = DeviceRelationInvalidationQueue::new();
        let first = queue.enqueue(10, 0).unwrap();
        let duplicate = queue.enqueue(10, 0).unwrap();
        assert_eq!(
            first.disposition,
            DeviceRelationInvalidationDisposition::Queued
        );
        assert_eq!(
            duplicate.disposition,
            DeviceRelationInvalidationDisposition::Coalesced
        );
        assert_eq!(duplicate.invalidation, first.invalidation);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.claim_front(), Some(first.invalidation));
        assert_eq!(queue.claim_front(), None);
        assert_eq!(queue.complete(first.invalidation), Ok(()));
        assert!(queue.is_empty());
    }

    #[test]
    fn invalidation_during_claim_is_not_lost() {
        let mut queue = DeviceRelationInvalidationQueue::new();
        let first = queue.enqueue(10, 0).unwrap().invalidation;
        let claim = queue.claim_front().unwrap();
        assert_eq!(claim, first);

        let follow_up = queue.enqueue(10, 0).unwrap();
        assert_eq!(
            follow_up.disposition,
            DeviceRelationInvalidationDisposition::Requeued
        );
        assert!(follow_up.invalidation.sequence > claim.sequence);
        let duplicate = queue.enqueue(10, 0).unwrap();
        assert_eq!(
            duplicate.disposition,
            DeviceRelationInvalidationDisposition::Coalesced
        );
        assert_eq!(duplicate.invalidation, follow_up.invalidation);

        queue.complete(claim).unwrap();
        assert_eq!(queue.claim_front(), Some(follow_up.invalidation));
        queue.complete(follow_up.invalidation).unwrap();
        assert!(queue.is_empty());
    }

    #[test]
    fn abort_retries_the_exact_claim_without_allocation() {
        let mut queue = DeviceRelationInvalidationQueue::new();
        let original = queue.enqueue(10, 0).unwrap().invalidation;
        let claim = queue.claim_front().unwrap();
        queue.abort(claim).unwrap();
        assert_eq!(queue.claim_front(), Some(original));
    }

    #[test]
    fn abort_absorbs_a_later_invalidation_into_the_retry() {
        let mut queue = DeviceRelationInvalidationQueue::new();
        let original = queue.enqueue(10, 0).unwrap().invalidation;
        let claim = queue.claim_front().unwrap();
        let later = queue.enqueue(10, 0).unwrap().invalidation;
        assert!(later.sequence > original.sequence);
        queue.abort(claim).unwrap();
        assert_eq!(queue.claim_front(), Some(original));
        queue.complete(original).unwrap();
        assert!(queue.is_empty());
    }

    #[test]
    fn queue_orders_independent_pdos_and_relation_types_by_sequence() {
        let mut queue = DeviceRelationInvalidationQueue::new();
        let first = queue.enqueue(20, 1).unwrap().invalidation;
        let second = queue.enqueue(10, 0).unwrap().invalidation;
        let third = queue.enqueue(20, 0).unwrap().invalidation;
        assert_eq!(queue.claim_front(), Some(first));
        assert_eq!(queue.claim_front(), Some(second));
        queue.complete(second).unwrap();
        assert_eq!(queue.claim_front(), Some(third));
        queue.complete(first).unwrap();
        queue.complete(third).unwrap();
        assert!(queue.is_empty());
    }

    #[test]
    fn completion_and_abort_require_the_exact_live_claim() {
        let mut queue = DeviceRelationInvalidationQueue::new();
        let pending = queue.enqueue(10, 0).unwrap().invalidation;
        assert_eq!(
            queue.complete(pending),
            Err(DeviceRelationInvalidationError::StaleClaim)
        );
        let claim = queue.claim_front().unwrap();
        let wrong = DeviceRelationInvalidation {
            sequence: claim.sequence + 1,
            ..claim
        };
        assert_eq!(
            queue.complete(wrong),
            Err(DeviceRelationInvalidationError::StaleClaim)
        );
        assert_eq!(
            queue.abort(wrong),
            Err(DeviceRelationInvalidationError::StaleClaim)
        );
        queue.complete(claim).unwrap();
        assert_eq!(
            queue.complete(claim),
            Err(DeviceRelationInvalidationError::StaleClaim)
        );
    }

    #[test]
    fn invalid_pdo_and_sequence_exhaustion_fail_without_queueing() {
        let mut queue = DeviceRelationInvalidationQueue::new();
        assert_eq!(
            queue.enqueue(0, 0),
            Err(DeviceRelationInvalidationError::InvalidPdo)
        );
        queue.next_sequence = u64::MAX;
        assert_eq!(
            queue.enqueue(10, 0),
            Err(DeviceRelationInvalidationError::SequenceExhausted)
        );
        assert!(queue.is_empty());
    }
}
