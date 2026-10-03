//! Exact hosted provider projection for a PDO published by an accepted bus relation.
//!
//! Native PDO addresses are meaningful only in their provider domain. This catalog retains the
//! exact registration that produced an accepted child and joins it to the PnP manager's current
//! parent/relation generation. Callers transport the resulting authority, never the address.

use alloc::vec::Vec;

use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget, HostedDevicePointerRegistration, IoManager,
};
use nt_status::NtStatus;

use crate::{BusRelationTable, ParentRelationIdentity, PnpManager};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptedPdoProviderError {
    NotEnumerated,
    StaleRelation,
    WrongProvider,
    ConflictingProvider,
    Provider(NtStatus),
    InsufficientResources,
}

/// Broker-only proof that a live provider projection owns an accepted PDO generation.
///
/// The provider address must never be serialized to the consumer. It may only be used by the
/// broker to enter that exact provider domain or to mint a pointer-free interface lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedPdoProviderAuthority {
    pdo_object_id: u64,
    parent_relation: ParentRelationIdentity,
    provider: HostedDevicePointerRegistration,
}

impl AcceptedPdoProviderAuthority {
    pub const fn pdo_object_id(self) -> u64 {
        self.pdo_object_id
    }

    pub const fn parent_relation(self) -> ParentRelationIdentity {
        self.parent_relation
    }

    pub const fn provider(self) -> HostedDevicePointerRegistration {
        self.provider
    }
}

struct ProviderRow {
    authority: AcceptedPdoProviderAuthority,
    target: HostedForwardTarget,
}

#[derive(Debug)]
enum PreparedProviderRow {
    Existing {
        row_index: usize,
        authority: AcceptedPdoProviderAuthority,
    },
    New {
        authority: AcceptedPdoProviderAuthority,
        target: HostedForwardTarget,
    },
}

/// All allocations and exact provider references needed to publish one complete relation set.
///
/// Preparing this owner changes no routable authority. The caller must either commit it after the
/// matching PnP and BusRelations owners commit, or abort it through the same I/O manager.
#[must_use = "commit after the relation transaction, or abort to release provider references"]
#[derive(Debug)]
pub struct PreparedAcceptedPdoProviderBatch {
    base_generation: u64,
    next_generation: u64,
    parent_relation: ParentRelationIdentity,
    rows: Vec<PreparedProviderRow>,
}

/// Preparation can fail after retaining an earlier provider in the same batch. The rollback owner
/// is therefore returned even on error rather than silently dropping an exact device reference.
#[must_use = "abort the returned rollback owner before discarding the failure"]
#[derive(Debug)]
pub struct AcceptedPdoProviderPrepareFailure {
    error: AcceptedPdoProviderError,
    rollback: PreparedAcceptedPdoProviderBatch,
}

impl AcceptedPdoProviderPrepareFailure {
    pub const fn error(&self) -> AcceptedPdoProviderError {
        self.error
    }

    pub fn into_rollback(self) -> PreparedAcceptedPdoProviderBatch {
        self.rollback
    }
}

impl PreparedAcceptedPdoProviderBatch {
    pub const fn parent_relation(&self) -> ParentRelationIdentity {
        self.parent_relation
    }

    /// Release every provider reference captured before semantic publication.
    ///
    /// A refused release returns the still-owned suffix for redrive. Successfully released rows
    /// have already been removed from that owner and cannot be released twice.
    pub fn abort<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<(), (AcceptedPdoProviderError, Self)> {
        while let Some(row) = self.rows.pop() {
            if let PreparedProviderRow::New {
                authority,
                mut target,
            } = row
            {
                if let Err(status) = target.release(io) {
                    self.rows
                        .push(PreparedProviderRow::New { authority, target });
                    return Err((AcceptedPdoProviderError::Provider(status), self));
                }
            }
        }
        Ok(())
    }
}

/// Durable provider projections for accepted child PDOs.
///
/// A relation refresh updates the generation of an unchanged provider. A different provider
/// registration for the same canonical PDO is rejected until the old relation has been retired;
/// replacement cannot silently redirect an in-flight lower-edge IRP.
#[derive(Default)]
pub struct AcceptedPdoProviderCatalog {
    generation: u64,
    rows: Vec<ProviderRow>,
}

impl AcceptedPdoProviderCatalog {
    pub const fn new() -> Self {
        Self {
            generation: 0,
            rows: Vec::new(),
        }
    }

    fn prepare_failure(
        error: AcceptedPdoProviderError,
        base_generation: u64,
        next_generation: u64,
        parent_relation: ParentRelationIdentity,
        rows: Vec<PreparedProviderRow>,
    ) -> AcceptedPdoProviderPrepareFailure {
        AcceptedPdoProviderPrepareFailure {
            error,
            rollback: PreparedAcceptedPdoProviderBatch {
                base_generation,
                next_generation,
                parent_relation,
                rows,
            },
        }
    }

    fn current_authority<P>(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        io: &IoManager<P>,
        pdo_object_id: u64,
        provider: HostedDevicePointerRegistration,
    ) -> Result<AcceptedPdoProviderAuthority, AcceptedPdoProviderError> {
        let parent_relation = pnp
            .parent_relation_for_pdo(pdo_object_id)
            .ok_or(AcceptedPdoProviderError::NotEnumerated)?;
        if !pnp.relation_parent_is_started(parent_relation)
            || !relations.relation_contains(parent_relation.relation(), pdo_object_id)
        {
            return Err(AcceptedPdoProviderError::StaleRelation);
        }
        if provider.device_id().raw() != pdo_object_id
            || io.hosted_device_pointer_registration(provider.domain(), provider.address())
                != Some(provider)
        {
            return Err(AcceptedPdoProviderError::WrongProvider);
        }
        Ok(AcceptedPdoProviderAuthority {
            pdo_object_id,
            parent_relation,
            provider,
        })
    }

    /// Prepare an exact provider lease for every child in one prospective complete relation set.
    ///
    /// The supplied relation identity comes from `PreparedBusRelations` joined to the exact
    /// started parent. It intentionally need not be current yet. No route becomes resolvable until
    /// [`Self::commit_relation`] observes that exact relation and its devnodes as current.
    pub fn prepare_relation<P>(
        &mut self,
        io: &mut IoManager<P>,
        parent_relation: ParentRelationIdentity,
        providers: &[(u64, HostedDevicePointerRegistration)],
    ) -> Result<PreparedAcceptedPdoProviderBatch, AcceptedPdoProviderPrepareFailure> {
        let base_generation = self.generation;
        let Some(next_generation) = base_generation.checked_add(1) else {
            return Err(Self::prepare_failure(
                AcceptedPdoProviderError::InsufficientResources,
                base_generation,
                base_generation,
                parent_relation,
                Vec::new(),
            ));
        };
        let mut prepared_rows = Vec::new();
        if parent_relation.relation().generation() == 0
            || parent_relation.relation().bus_object_id()
                != parent_relation.parent().pdo_object_id()
        {
            return Err(Self::prepare_failure(
                AcceptedPdoProviderError::StaleRelation,
                base_generation,
                next_generation,
                parent_relation,
                prepared_rows,
            ));
        }
        if prepared_rows.try_reserve_exact(providers.len()).is_err() {
            return Err(Self::prepare_failure(
                AcceptedPdoProviderError::InsufficientResources,
                base_generation,
                next_generation,
                parent_relation,
                prepared_rows,
            ));
        }

        let mut new_count = 0usize;
        for (index, &(pdo_object_id, provider)) in providers.iter().enumerate() {
            if pdo_object_id == 0
                || provider.device_id().raw() != pdo_object_id
                || providers[..index]
                    .iter()
                    .any(|(prior_pdo, _)| *prior_pdo == pdo_object_id)
                || io.hosted_device_pointer_registration(provider.domain(), provider.address())
                    != Some(provider)
            {
                return Err(Self::prepare_failure(
                    AcceptedPdoProviderError::WrongProvider,
                    base_generation,
                    next_generation,
                    parent_relation,
                    prepared_rows,
                ));
            }
            if let Some((row_index, row)) = self
                .rows
                .iter()
                .enumerate()
                .find(|(_, row)| row.authority.pdo_object_id == pdo_object_id)
            {
                if row.authority.provider != provider {
                    return Err(Self::prepare_failure(
                        AcceptedPdoProviderError::ConflictingProvider,
                        base_generation,
                        next_generation,
                        parent_relation,
                        prepared_rows,
                    ));
                }
                if let Err(status) = row.target.validate(io) {
                    return Err(Self::prepare_failure(
                        AcceptedPdoProviderError::Provider(status),
                        base_generation,
                        next_generation,
                        parent_relation,
                        prepared_rows,
                    ));
                }
                prepared_rows.push(PreparedProviderRow::Existing {
                    row_index,
                    authority: AcceptedPdoProviderAuthority {
                        pdo_object_id,
                        parent_relation,
                        provider,
                    },
                });
            } else {
                let Some(next) = new_count.checked_add(1) else {
                    return Err(Self::prepare_failure(
                        AcceptedPdoProviderError::InsufficientResources,
                        base_generation,
                        next_generation,
                        parent_relation,
                        prepared_rows,
                    ));
                };
                new_count = next;
            }
        }
        if self.rows.try_reserve(new_count).is_err() {
            return Err(Self::prepare_failure(
                AcceptedPdoProviderError::InsufficientResources,
                base_generation,
                next_generation,
                parent_relation,
                prepared_rows,
            ));
        }

        for &(pdo_object_id, provider) in providers {
            if self
                .rows
                .iter()
                .any(|row| row.authority.pdo_object_id == pdo_object_id)
            {
                continue;
            }
            let target =
                match HostedForwardTarget::capture(io, provider.domain(), provider.address()) {
                    Ok(target)
                        if target.registration() == provider
                            && target.device_id().raw() == pdo_object_id =>
                    {
                        target
                    }
                    Ok(mut target) => {
                        if let Err(status) = target.release(io) {
                            prepared_rows.push(PreparedProviderRow::New {
                                authority: AcceptedPdoProviderAuthority {
                                    pdo_object_id,
                                    parent_relation,
                                    provider,
                                },
                                target,
                            });
                            return Err(Self::prepare_failure(
                                AcceptedPdoProviderError::Provider(status),
                                base_generation,
                                next_generation,
                                parent_relation,
                                prepared_rows,
                            ));
                        }
                        return Err(Self::prepare_failure(
                            AcceptedPdoProviderError::WrongProvider,
                            base_generation,
                            next_generation,
                            parent_relation,
                            prepared_rows,
                        ));
                    }
                    Err(status) => {
                        return Err(Self::prepare_failure(
                            AcceptedPdoProviderError::Provider(status),
                            base_generation,
                            next_generation,
                            parent_relation,
                            prepared_rows,
                        ));
                    }
                };
            prepared_rows.push(PreparedProviderRow::New {
                authority: AcceptedPdoProviderAuthority {
                    pdo_object_id,
                    parent_relation,
                    provider,
                },
                target,
            });
        }
        Ok(PreparedAcceptedPdoProviderBatch {
            base_generation,
            next_generation,
            parent_relation,
            rows: prepared_rows,
        })
    }

    /// Publish a prepared relation after the matching devnodes and BusRelations set commit.
    /// Validation completes before any catalog row changes; commit itself allocates nothing.
    pub fn commit_relation<P>(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        io: &IoManager<P>,
        prepared: PreparedAcceptedPdoProviderBatch,
    ) -> Result<(), (AcceptedPdoProviderError, PreparedAcceptedPdoProviderBatch)> {
        if self.generation != prepared.base_generation
            || prepared.next_generation != self.generation.saturating_add(1)
        {
            return Err((AcceptedPdoProviderError::StaleRelation, prepared));
        }
        let relation = prepared.parent_relation.relation();
        let complete = relations.accepted_children(relation.bus_object_id());
        if !pnp.relation_parent_is_started(prepared.parent_relation)
            || relations.current_relation_identity(relation.bus_object_id()) != Some(relation)
            || complete.is_none_or(|children| {
                children.len() != prepared.rows.len()
                    || children.iter().any(|child| {
                        !prepared.rows.iter().any(|row| {
                            let authority = match row {
                                PreparedProviderRow::Existing { authority, .. }
                                | PreparedProviderRow::New { authority, .. } => authority,
                            };
                            authority.pdo_object_id == child.pdo_object_id
                        })
                    })
            })
        {
            return Err((AcceptedPdoProviderError::StaleRelation, prepared));
        }
        let validation = prepared.rows.iter().try_for_each(|row| {
            let (authority, target) = match row {
                PreparedProviderRow::Existing {
                    row_index,
                    authority,
                } => {
                    let Some(current) = self.rows.get(*row_index) else {
                        return Err(AcceptedPdoProviderError::StaleRelation);
                    };
                    if current.authority.pdo_object_id != authority.pdo_object_id
                        || current.authority.provider != authority.provider
                    {
                        return Err(AcceptedPdoProviderError::StaleRelation);
                    }
                    (*authority, &current.target)
                }
                PreparedProviderRow::New { authority, target } => (*authority, target),
            };
            let current = Self::current_authority(
                pnp,
                relations,
                io,
                authority.pdo_object_id,
                authority.provider,
            )?;
            if current != authority {
                return Err(AcceptedPdoProviderError::StaleRelation);
            }
            target
                .validate(io)
                .map_err(AcceptedPdoProviderError::Provider)?;
            Ok(())
        });
        if let Err(error) = validation {
            return Err((error, prepared));
        }

        for row in prepared.rows {
            match row {
                PreparedProviderRow::Existing {
                    row_index,
                    authority,
                } => self.rows[row_index].authority = authority,
                PreparedProviderRow::New { authority, target } => {
                    self.rows.push(ProviderRow { authority, target });
                }
            }
        }
        self.generation = prepared.next_generation;
        Ok(())
    }

    /// Resolve only the current accepted relation and exact live provider registration.
    pub fn resolve<P>(
        &self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        io: &IoManager<P>,
        pdo_object_id: u64,
    ) -> Result<AcceptedPdoProviderAuthority, AcceptedPdoProviderError> {
        let row = self
            .rows
            .iter()
            .find(|row| row.authority.pdo_object_id == pdo_object_id)
            .ok_or(AcceptedPdoProviderError::NotEnumerated)?;
        let current =
            Self::current_authority(pnp, relations, io, pdo_object_id, row.authority.provider)?;
        if current != row.authority {
            return Err(AcceptedPdoProviderError::StaleRelation);
        }
        row.target
            .validate(io)
            .map_err(AcceptedPdoProviderError::Provider)?;
        Ok(row.authority)
    }

    /// Retire an exact row only after its accepted parent relation is no longer current.
    pub fn retire_stale<P>(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        io: &mut IoManager<P>,
        authority: AcceptedPdoProviderAuthority,
    ) -> Result<(), AcceptedPdoProviderError> {
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(AcceptedPdoProviderError::InsufficientResources)?;
        let index = self
            .rows
            .iter()
            .position(|row| row.authority == authority)
            .ok_or(AcceptedPdoProviderError::NotEnumerated)?;
        if Self::current_authority(
            pnp,
            relations,
            io,
            authority.pdo_object_id,
            authority.provider,
        )
        .is_ok()
        {
            return Err(AcceptedPdoProviderError::StaleRelation);
        }
        self.rows[index]
            .target
            .release(io)
            .map_err(AcceptedPdoProviderError::Provider)?;
        self.rows.swap_remove(index);
        self.generation = next_generation;
        Ok(())
    }

    /// Retire one catalog lease that is no longer part of its exact accepted relation.
    /// Repeating this operation to `Ok(false)` drains removals without allocating a side list.
    pub fn retire_one_stale<P>(
        &mut self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        io: &mut IoManager<P>,
    ) -> Result<bool, AcceptedPdoProviderError> {
        let Some(index) = self.rows.iter().position(|row| {
            Self::current_authority(
                pnp,
                relations,
                io,
                row.authority.pdo_object_id,
                row.authority.provider,
            ) != Ok(row.authority)
        }) else {
            return Ok(false);
        };
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(AcceptedPdoProviderError::InsufficientResources)?;
        self.rows[index]
            .target
            .release(io)
            .map_err(AcceptedPdoProviderError::Provider)?;
        self.rows.swap_remove(index);
        self.generation = next_generation;
        Ok(true)
    }

    pub fn active_count(&self) -> usize {
        self.rows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BusReportedChild, DeviceState, EnumeratedPdoRecord, PdoCapabilities, PdoProperties,
        PnpBusInformation, PropertyBlobState, GUID_BUS_TYPE_PCI, INTERFACE_TYPE_PCI_BUS,
    };
    use alloc::boxed::Box;
    use alloc::vec;
    use nt_io_manager::{
        DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend, MockObjectPort,
    };
    use nt_types::NtPath;

    fn fixture() -> (
        PnpManager,
        BusRelationTable,
        IoManager<MockObjectPort>,
        u64,
        HostedDevicePointerRegistration,
    ) {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\AcpiProvider").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let pdo = io
            .create_device(
                driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        let provider_domain = io.register_hosted_domain();
        let provider = io
            .bind_hosted_device_pointer(provider_domain, 0x1000, pdo)
            .unwrap();

        let mut pnp = PnpManager::new();
        let parent_pdo = 0x9000;
        let parent = pnp.create_service_bound_devnode_without_resources(
            r"ROOT\TEST_BUS\0000",
            Some("TestBus"),
            parent_pdo,
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
            pdo.raw(),
            r"ACPI\PNP0A08",
            "0",
            &[r"ACPI\PNP0A08"],
            &[] as &[&str],
        );
        let mut relations = BusRelationTable::new();
        relations.seed_bus_relations(parent_pdo, &[]).unwrap();
        let prepared_relation = relations
            .prepare_bus_relations(parent_pdo, core::slice::from_ref(&child))
            .unwrap();
        let parent_relation = pnp
            .claim_started_parent_relation(parent_pdo, prepared_relation.relation_identity())
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
        let prepared_child = pnp
            .prepare_enumerated_pdo_batch(vec![EnumeratedPdoRecord::new(
                child.enum_instance_path(),
                pdo.raw(),
                properties,
            )
            .with_parent_relation(parent_relation)])
            .unwrap();
        pnp.commit_enumerated_pdo_batch(prepared_child).unwrap();
        relations.commit_bus_relations(prepared_relation).unwrap();
        (pnp, relations, io, pdo.raw(), provider)
    }

    fn publish(
        catalog: &mut AcceptedPdoProviderCatalog,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        io: &mut IoManager<MockObjectPort>,
        pdo: u64,
        provider: HostedDevicePointerRegistration,
    ) -> AcceptedPdoProviderAuthority {
        let parent_relation = pnp.parent_relation_for_pdo(pdo).unwrap();
        let prepared = catalog
            .prepare_relation(io, parent_relation, &[(pdo, provider)])
            .unwrap();
        catalog
            .commit_relation(pnp, relations, io, prepared)
            .unwrap();
        catalog.resolve(pnp, relations, io, pdo).unwrap()
    }

    #[test]
    fn retains_only_the_exact_provider_for_the_current_relation() {
        let (pnp, relations, mut io, pdo, provider) = fixture();
        let mut catalog = AcceptedPdoProviderCatalog::new();
        let authority = publish(&mut catalog, &pnp, &relations, &mut io, pdo, provider);
        assert_eq!(authority.provider(), provider);
        assert_eq!(catalog.resolve(&pnp, &relations, &io, pdo), Ok(authority));
        assert_eq!(catalog.active_count(), 1);
        assert_eq!(io.hosted_device_pointer_count(provider), Ok(1));
    }

    #[test]
    fn prepared_relation_is_not_routable_and_abort_releases_its_exact_provider() {
        let (pnp, relations, mut io, pdo, provider) = fixture();
        let parent_relation = pnp.parent_relation_for_pdo(pdo).unwrap();
        let mut catalog = AcceptedPdoProviderCatalog::new();
        let prepared = catalog
            .prepare_relation(&mut io, parent_relation, &[(pdo, provider)])
            .unwrap();
        assert_eq!(
            catalog.resolve(&pnp, &relations, &io, pdo),
            Err(AcceptedPdoProviderError::NotEnumerated)
        );
        assert_eq!(io.hosted_device_pointer_count(provider), Ok(1));
        prepared.abort(&mut io).unwrap();
        assert_eq!(io.hosted_device_pointer_count(provider), Ok(0));
    }

    #[test]
    fn prepared_relation_commits_without_recapturing_the_provider() {
        let (pnp, relations, mut io, pdo, provider) = fixture();
        let parent_relation = pnp.parent_relation_for_pdo(pdo).unwrap();
        let mut catalog = AcceptedPdoProviderCatalog::new();
        let prepared = catalog
            .prepare_relation(&mut io, parent_relation, &[(pdo, provider)])
            .unwrap();
        catalog
            .commit_relation(&pnp, &relations, &io, prepared)
            .unwrap();
        let authority = catalog.resolve(&pnp, &relations, &io, pdo).unwrap();
        assert_eq!(authority.provider(), provider);
        assert_eq!(authority.parent_relation(), parent_relation);
        assert_eq!(io.hosted_device_pointer_count(provider), Ok(1));
    }

    #[test]
    fn malformed_batch_returns_an_explicit_rollback_owner() {
        let (pnp, _, mut io, pdo, provider) = fixture();
        let parent_relation = pnp.parent_relation_for_pdo(pdo).unwrap();
        let mut catalog = AcceptedPdoProviderCatalog::new();
        let failure = catalog
            .prepare_relation(
                &mut io,
                parent_relation,
                &[(pdo, provider), (pdo, provider)],
            )
            .unwrap_err();
        assert_eq!(failure.error(), AcceptedPdoProviderError::WrongProvider);
        failure.into_rollback().abort(&mut io).unwrap();
        assert_eq!(catalog.active_count(), 0);
        assert_eq!(io.hosted_device_pointer_count(provider), Ok(0));
    }

    #[test]
    fn stale_relation_is_not_routable_and_can_be_retired_exactly() {
        let (pnp, mut relations, mut io, pdo, provider) = fixture();
        let mut catalog = AcceptedPdoProviderCatalog::new();
        let authority = publish(&mut catalog, &pnp, &relations, &mut io, pdo, provider);
        let parent = authority.parent_relation().relation().bus_object_id();
        let removed = relations.prepare_bus_relations(parent, &[]).unwrap();
        relations.commit_bus_relations(removed).unwrap();
        assert_eq!(
            catalog.resolve(&pnp, &relations, &io, pdo),
            Err(AcceptedPdoProviderError::StaleRelation)
        );
        catalog
            .retire_stale(&pnp, &relations, &mut io, authority)
            .unwrap();
        assert_eq!(catalog.active_count(), 0);
        assert_eq!(io.hosted_device_pointer_count(provider), Ok(0));
    }

    #[test]
    fn relation_cleanup_retires_only_rows_no_longer_current() {
        let (pnp, mut relations, mut io, pdo, provider) = fixture();
        let mut catalog = AcceptedPdoProviderCatalog::new();
        publish(&mut catalog, &pnp, &relations, &mut io, pdo, provider);
        assert!(!catalog.retire_one_stale(&pnp, &relations, &mut io).unwrap());
        let parent = pnp
            .parent_relation_for_pdo(pdo)
            .unwrap()
            .relation()
            .bus_object_id();
        let removed = relations.prepare_bus_relations(parent, &[]).unwrap();
        relations.commit_bus_relations(removed).unwrap();
        assert!(catalog.retire_one_stale(&pnp, &relations, &mut io).unwrap());
        assert!(!catalog.retire_one_stale(&pnp, &relations, &mut io).unwrap());
        assert_eq!(io.hosted_device_pointer_count(provider), Ok(0));
    }

    #[test]
    fn provider_for_another_canonical_device_is_rejected() {
        let (pnp, relations, mut io, pdo, _) = fixture();
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\OtherProvider").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let other = io
            .create_device(
                driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        let domain = io.register_hosted_domain();
        let registration = io
            .bind_hosted_device_pointer(domain, 0x3000, other)
            .unwrap();
        let mut catalog = AcceptedPdoProviderCatalog::new();
        let parent_relation = pnp.parent_relation_for_pdo(pdo).unwrap();
        let failure = catalog
            .prepare_relation(&mut io, parent_relation, &[(pdo, registration)])
            .unwrap_err();
        assert_eq!(failure.error(), AcceptedPdoProviderError::WrongProvider);
        failure.into_rollback().abort(&mut io).unwrap();
        assert_eq!(catalog.active_count(), 0);
    }
}
