//! Ownership boundary for a file-less TargetDeviceRelation result consumed by win32k.

use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget, DeviceId, ExternalPnpTerminalReceipt,
    HostedDevicePointerRegistration, HostedDomainIdentity, IoManager, IrpId,
};
use nt_provider_wait::{
    ProviderAllocationCatalog, ProviderAllocationError, ProviderAllocationPin,
    ProviderAllocationSnapshot,
};
use nt_status::NtStatus;

use crate::{copy_device_relations_x64, write_device_relations_x64, DeviceRelationsCopyError};

pub const TARGET_DEVICE_RELATIONS_X64_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetRelationError {
    WrongTerminal,
    MissingSourceAllocation,
    WrongSourceAllocation,
    Source(DeviceRelationsCopyError),
    WrongSourcePdo,
    WrongConsumerPdo,
    Reference(NtStatus),
    Allocation(ProviderAllocationError),
    WrongAllocationBase,
    WrongPhase,
    WrongIosb,
    WrongIrp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetRelationPhase {
    Prepared,
    RelationWritten,
    IosbPublished,
    CanonicalAcknowledged,
    Transferred,
    Aborted,
}

/// A win32k allocation and one independent caller reference to its projected PDO.
///
/// The source driver's `DEVICE_RELATIONS` allocation and its original PDO reference remain
/// separate owners. The native adapter must authenticate/copy that allocation and release its
/// original reference after this new consumer reference has been captured. It must also validate
/// native pool identity and write the actual IOSB before advancing these phases.
#[must_use = "transfer the PDO reference or abort before publishing the relation"]
pub struct TargetRelationDelivery {
    irp: IrpId,
    status: NtStatus,
    projected_pdo: u64,
    pdo: Option<HostedForwardTarget>,
    relation: ProviderAllocationSnapshot,
    pin: Option<ProviderAllocationPin>,
    phase: TargetRelationPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferredTargetRelation {
    pub relation: ProviderAllocationSnapshot,
    pub projected_pdo: u64,
    pub pdo_reference: HostedDevicePointerRegistration,
}

impl TargetRelationDelivery {
    /// Capture only a genuine successful exact-device PnP terminal and a one-PDO source result.
    /// `source_bytes` must come from the authenticated driver allocation identified by
    /// `source_allocation`; the native adapter must validate its mapped pool identity too.
    pub fn capture<P>(
        io: &mut IoManager<P>,
        allocations: &mut ProviderAllocationCatalog,
        terminal: &ExternalPnpTerminalReceipt,
        exact_target: DeviceId,
        source_information: u64,
        source_allocation: ProviderAllocationSnapshot,
        source_bytes: &[u8],
        authenticated_source_pdo: u64,
        consumer_domain: HostedDomainIdentity,
        projected_pdo: u64,
        canonical_pdo: DeviceId,
        relation_address: u64,
    ) -> Result<Self, TargetRelationError> {
        if terminal.minor() != nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS
            || terminal.relation_type() != Some(nt_pnp_abi::TARGET_DEVICE_RELATION)
            || !terminal.status().is_success()
            || terminal.origin_device_id() != exact_target
        {
            return Err(TargetRelationError::WrongTerminal);
        }
        if source_information == 0 || authenticated_source_pdo == 0 {
            return Err(TargetRelationError::MissingSourceAllocation);
        }
        if terminal.information() != source_information {
            return Err(TargetRelationError::WrongSourceAllocation);
        }
        if source_information != source_allocation.base {
            return Err(TargetRelationError::WrongSourceAllocation);
        }
        let (active_source, source_pin) = allocations
            .pin_containing(source_information, TARGET_DEVICE_RELATIONS_X64_BYTES as u64)
            .map_err(TargetRelationError::Allocation)?;
        let parsed = if active_source == source_allocation {
            copy_device_relations_x64(source_bytes).map_err(TargetRelationError::Source)
        } else {
            Err(TargetRelationError::WrongSourceAllocation)
        };
        allocations.release_pin(source_pin).map_err(TargetRelationError::Allocation)?;
        let objects = parsed?;
        if objects.len() != 1 || objects[0] != authenticated_source_pdo {
            return Err(TargetRelationError::WrongSourcePdo);
        }
        let mut pdo = HostedForwardTarget::capture(io, consumer_domain, projected_pdo)
            .map_err(TargetRelationError::Reference)?;
        if pdo.device_id() != canonical_pdo {
            pdo.release(io).map_err(TargetRelationError::Reference)?;
            return Err(TargetRelationError::WrongConsumerPdo);
        }
        let (relation, pin) = match allocations
            .pin_containing(relation_address, TARGET_DEVICE_RELATIONS_X64_BYTES as u64)
        {
            Ok(captured) => captured,
            Err(error) => {
                pdo.release(io).map_err(TargetRelationError::Reference)?;
                return Err(TargetRelationError::Allocation(error));
            }
        };
        if relation.base != relation_address {
            allocations.release_pin(pin).map_err(TargetRelationError::Allocation)?;
            pdo.release(io).map_err(TargetRelationError::Reference)?;
            return Err(TargetRelationError::WrongAllocationBase);
        }
        Ok(Self {
            irp: terminal.irp_id(),
            status: terminal.status(),
            projected_pdo,
            pdo: Some(pdo),
            relation,
            pin: Some(pin),
            phase: TargetRelationPhase::Prepared,
        })
    }

    pub const fn phase(&self) -> TargetRelationPhase {
        self.phase
    }

    pub const fn allocation(&self) -> ProviderAllocationSnapshot {
        self.relation
    }

    /// `bytes` must be the native mapping of the pinned win32k allocation, not source memory.
    /// Validation precedes the first write; a failed call leaves this transaction prepared.
    pub fn write_relation<P>(
        &mut self,
        io: &IoManager<P>,
        allocations: &ProviderAllocationCatalog,
        bytes: &mut [u8],
    ) -> Result<(), TargetRelationError> {
        if self.phase != TargetRelationPhase::Prepared || self.pin.is_none() {
            return Err(TargetRelationError::WrongPhase);
        }
        self.validate(io, allocations)?;
        write_device_relations_x64(bytes, &[self.projected_pdo])
            .map_err(TargetRelationError::Source)?;
        self.phase = TargetRelationPhase::RelationWritten;
        Ok(())
    }

    /// Called only after the native adapter has written the real caller IOSB.
    pub fn iosb_published(&mut self, status: NtStatus, information: u64) -> Result<(), TargetRelationError> {
        if self.phase != TargetRelationPhase::RelationWritten {
            return Err(TargetRelationError::WrongPhase);
        }
        if status != self.status || information != self.relation.base {
            return Err(TargetRelationError::WrongIosb);
        }
        self.phase = TargetRelationPhase::IosbPublished;
        Ok(())
    }

    /// Called only after strict acknowledgement of this exact canonical PnP IRP.
    pub fn canonical_acknowledged(&mut self, irp: IrpId) -> Result<(), TargetRelationError> {
        if self.phase != TargetRelationPhase::IosbPublished {
            return Err(TargetRelationError::WrongPhase);
        }
        if irp != self.irp {
            return Err(TargetRelationError::WrongIrp);
        }
        self.phase = TargetRelationPhase::CanonicalAcknowledged;
        Ok(())
    }

    /// Release the allocation pin and transfer the counted PDO reference to win32k's caller.
    /// The caller subsequently frees `relation.base` and dereferences `pdo_reference` separately.
    pub fn transfer<P>(
        &mut self,
        io: &mut IoManager<P>,
        allocations: &mut ProviderAllocationCatalog,
    ) -> Result<TransferredTargetRelation, TargetRelationError> {
        if self.phase != TargetRelationPhase::CanonicalAcknowledged {
            return Err(TargetRelationError::WrongPhase);
        }
        self.validate(io, allocations)?;
        if let Some(pin) = self.pin {
            allocations.release_pin(pin).map_err(TargetRelationError::Allocation)?;
            self.pin = None;
        }
        let reference = self.pdo.as_mut().ok_or(TargetRelationError::WrongPhase)?
            .transfer_reference(io).map_err(TargetRelationError::Reference)?;
        self.pdo = None;
        self.phase = TargetRelationPhase::Transferred;
        Ok(TransferredTargetRelation {
            relation: self.relation,
            projected_pdo: self.projected_pdo,
            pdo_reference: reference,
        })
    }

    /// Only a not-yet-written relation can be rolled back; later uncertainty retains both owners.
    pub fn abort<P>(
        &mut self,
        io: &mut IoManager<P>,
        allocations: &mut ProviderAllocationCatalog,
    ) -> Result<(), TargetRelationError> {
        if self.phase != TargetRelationPhase::Prepared {
            return Err(TargetRelationError::WrongPhase);
        }
        if let Some(pin) = self.pin {
            allocations.release_pin(pin).map_err(TargetRelationError::Allocation)?;
            self.pin = None;
        }
        if let Some(pdo) = self.pdo.as_mut() {
            pdo.release(io).map_err(TargetRelationError::Reference)?;
            self.pdo = None;
        }
        self.phase = TargetRelationPhase::Aborted;
        Ok(())
    }

    fn validate<P>(
        &self,
        io: &IoManager<P>,
        allocations: &ProviderAllocationCatalog,
    ) -> Result<(), TargetRelationError> {
        self.pdo.as_ref().ok_or(TargetRelationError::WrongPhase)?
            .validate(io).map_err(TargetRelationError::Reference)?;
        if allocations.snapshot_active(self.relation.identity) != Ok(self.relation) {
            return Err(TargetRelationError::Allocation(ProviderAllocationError::StaleIdentity));
        }
        Ok(())
    }
}
