//! Source-owned SCSI SRB admission for one accepted foreign storage PDO.
//!
//! The producer's IRP, SRB, MDL and pool-backed transfer buffer are retained before any
//! provider entry. A raw pointer is never forwarded to another address domain. Provider
//! dispatch will consume the owned byte snapshots and must report exact terminal/ACK events.

use super::*;
use super::hosted_source_pool_memory::SourcePoolMemory;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    scsi_source_retention::ScsiSourceChildren,
    scsi_srb_transport::{merge_provider_legacy_srb, sanitized_legacy_srb, ScsiSrbRoute, WDM_X64_LEGACY_SRB_SIZE},
    source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity}, HostedDomainIdentity,
};
use nt_pnp_manager::AcceptedPdoProviderAuthority;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CaptureError {
    InvalidCaller,
    InvalidSource,
    InvalidTarget,
    InvalidSrb,
}

#[must_use = "retain through provider terminal, ACK and source-local completion"]
pub(super) struct CapturedSourceScsi {
    instance_index: usize,
    source: SourceIrpAllocation,
    ticket: SourceIrpTicket,
    target: Option<HostedForwardTarget>,
    authority: AcceptedPdoProviderAuthority,
    children: ScsiSourceChildren,
    srb: Vec<u8>,
    mdl: Option<Vec<u8>>,
    data: Vec<u8>,
    sense: Option<Vec<u8>>,
    children_retained: bool,
    source_pinned: bool,
}

impl CapturedSourceScsi {
    pub(super) fn source_identity(&self) -> SourceIrpForwardIdentity {
        SourceIrpForwardIdentity::new(self.ticket, self.source)
            .expect("retained SCSI source identity")
    }

    pub(super) fn source_irp_address(&self) -> u64 {
        self.source.component_address
    }
    pub(super) fn device_id(&self) -> nt_io_manager::DeviceId {
        self.children.route.pdo
    }
    pub(super) fn completion_finished(&self) -> bool {
        hosted_source_irp_ledger::deferred_free_requested(self.ticket)
    }
    pub(super) fn arm_callback_free(&self) -> Result<(), CaptureError> {
        self.validate_retained()?;
        hosted_source_irp_ledger::arm_deferred_free(self.ticket)
            .then_some(())
            .ok_or(CaptureError::InvalidSource)
    }
    pub(super) unsafe fn source_irp_exec(&self) -> Result<u64, CaptureError> {
        self.validate_retained()?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        hosted_instance_pool_allocation_exec_if_live(
            inst, self.source.component_address, self.source.bytes,
        )
        .ok_or(CaptureError::InvalidSource)
    }
    pub(super) fn children(&self) -> ScsiSourceChildren {
        self.children
    }
    pub(super) fn wire_srb(&self) -> Result<[u8; WDM_X64_LEGACY_SRB_SIZE], CaptureError> {
        sanitized_legacy_srb(
            &self.srb,
            self.data.len(),
            self.sense.as_ref().map_or(0, Vec::len),
        )
        .map_err(|_| CaptureError::InvalidSrb)
    }
    pub(super) fn mdl(&self) -> Option<&[u8]> {
        self.mdl.as_deref()
    }
    pub(super) fn data(&self) -> &[u8] {
        &self.data
    }
    pub(super) fn sense(&self) -> Option<&[u8]> {
        self.sense.as_deref()
    }
    /// Publish only scalar provider SRB state and bounded transfer children. All source
    /// pointer slots remain the captured source addresses, never provider addresses.
    pub(super) unsafe fn write_completion(
        &self, provider_srb: &[u8], data: &[u8], sense: &[u8],
    ) -> Result<(), CaptureError> {
        self.validate_retained()?;
        if data.len() != self.data.len()
            || sense.len() != self.sense.as_ref().map_or(0, Vec::len)
        {
            return Err(CaptureError::InvalidSrb);
        }
        let merged = merge_provider_legacy_srb(
            &self.srb, provider_srb, data.len(), sense.len(),
        )
        .map_err(|_| CaptureError::InvalidSrb)?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSource)?;
        let data_address = match self.children.data {
            Some(nt_io_manager::source_irp_auxiliary::SourceMemoryIdentity::Pool {
                component_address, ..
            }) => Some(component_address),
            None if data.is_empty() => None,
            _ => return Err(CaptureError::InvalidSource),
        };
        // Validate all destinations before the first write while holding the pool lock.
        if !memory.contains(self.children.srb.component_address, merged.len())
            || data_address.is_some_and(|address| !memory.contains(address, data.len()))
            || self.children.sense.is_some_and(|child| !memory.contains(
                child.component_address, sense.len(),
            ))
        {
            return Err(CaptureError::InvalidSource);
        }
        if let Some(address) = data_address {
            if !memory.write(address, data) { return Err(CaptureError::InvalidSource); }
        }
        if let Some(child) = self.children.sense {
            if !memory.write(child.component_address, sense) {
                return Err(CaptureError::InvalidSource);
            }
        }
        memory.write(self.children.srb.component_address, &merged)
            .then_some(())
            .ok_or(CaptureError::InvalidSource)
    }
    pub(super) fn provider_authority(&self) -> AcceptedPdoProviderAuthority {
        self.authority
    }

    /// Retire entered work against its retained physical source identities even if PnP has
    /// since replaced the parent relation. Relation retirement cannot make a completed SRB's
    /// source pool children safe to discard before the caller-local completion and ACK.
    pub(super) fn validate_retained(&self) -> Result<(), CaptureError> {
        if !self.source_pinned
            || !hosted_source_irp_ledger::scsi_children_match_current(
                self.instance_index, self.children,
            )
        {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    /// Re-observe the accepted parent relation and provider registration before entry. The
    /// physical source pins are independent and remain valid after this route is retired.
    pub(super) fn validate(&self) -> Result<(), CaptureError> {
        self.validate_retained()?;
        let target = self.target.as_ref().ok_or(CaptureError::InvalidTarget)?;
        let pdo = target
            .validate(io_manager_mut())
            .map_err(|_| CaptureError::InvalidTarget)?;
        let authority = unsafe {
            hosted_accepted_pdo_provider_catalog().resolve(
                hosted_pnp_manager_mut(),
                hosted_bus_relations(),
                io_manager_mut(),
                pdo.raw(),
            )
        }
        .map_err(|_| CaptureError::InvalidTarget)?;
        if authority != self.authority
            || self.children.route.pdo != pdo
            || self.children.route.provider != authority.provider().domain()
            || self.children.route.relation_generation
                != authority.parent_relation().relation().generation()
            || self.children.route.provider_pdo != authority.provider().address()
        {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    /// Provider IRP identity is minted by the canonical I/O Manager, not the source address.
    pub(super) fn entered(&self, provider_irp: IrpId) -> Result<(), CaptureError> {
        self.validate()?;
        hosted_source_irp_ledger::scsi_children_enter(self.children, provider_irp)
            .then_some(())
            .ok_or(CaptureError::InvalidSource)
    }

    pub(super) fn pending(&self, provider_irp: IrpId) -> Result<(), CaptureError> {
        hosted_source_irp_ledger::scsi_children_pending(self.children, provider_irp)
            .then_some(())
            .ok_or(CaptureError::InvalidSource)
    }

    pub(super) fn uncertain(&self, provider_irp: IrpId) -> Result<(), CaptureError> {
        hosted_source_irp_ledger::scsi_children_uncertain(self.children, provider_irp)
            .then_some(())
            .ok_or(CaptureError::InvalidSource)
    }

    pub(super) fn terminal(&self, provider_irp: IrpId) -> Result<(), CaptureError> {
        hosted_source_irp_ledger::scsi_children_terminal(self.children, provider_irp)
            .then_some(())
            .ok_or(CaptureError::InvalidSource)
    }

    pub(super) fn provider_acknowledged(&self, provider_irp: IrpId) -> Result<(), CaptureError> {
        hosted_source_irp_ledger::scsi_children_acknowledge(self.children, provider_irp)
            .then_some(())
            .ok_or(CaptureError::InvalidSource)
    }

    pub(super) fn source_completed(&self, provider_irp: IrpId) -> Result<(), CaptureError> {
        hosted_source_irp_ledger::scsi_children_source_completed(self.children, provider_irp)
            .then_some(())
            .ok_or(CaptureError::InvalidSource)
    }

    /// Only an unentered owner may roll back without a provider completion. This method
    /// preserves all pins if any exact release refuses, allowing the caller to redrive.
    pub(super) fn abandon_unentered(&mut self) -> Result<(), CaptureError> {
        if self.children_retained {
            self.validate_retained()?;
            if !hosted_source_irp_ledger::abandon_scsi_children(self.children) {
                return Err(CaptureError::InvalidSource);
            }
            self.children_retained = false;
        }
        self.release_references(false)
    }

    pub(super) fn release_after_completions(&mut self) -> Result<(), CaptureError> {
        if self.children_retained {
            if !hosted_source_irp_ledger::release_scsi_children(self.children) {
                return Err(CaptureError::InvalidSource);
            }
            self.children_retained = false;
        }
        self.release_references(self.completion_finished())
    }

    fn release_references(&mut self, source_completed: bool) -> Result<(), CaptureError> {
        if self.source_pinned {
            let released = if source_completed {
                hosted_source_irp_ledger::release_pending_terminal(self.ticket, self.source)
            } else {
                hosted_source_irp_ledger::unpin(self.ticket)
            };
            if !released { return Err(CaptureError::InvalidSource); }
            self.source_pinned = false;
        }
        if let Some(target) = self.target.as_mut() {
            target
                .release(io_manager_mut())
                .map_err(|_| CaptureError::InvalidTarget)?;
            self.target = None;
        }
        Ok(())
    }
}

pub(super) unsafe fn capture(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp_address: u64,
    target_device_address: u64,
) -> Result<CapturedSourceScsi, CaptureError> {
    let (instance_index, inst) =
        instance_for_pump_channel(ch, reply_cap).ok_or(CaptureError::InvalidCaller)?;
    hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge)
        .ok_or(CaptureError::InvalidCaller)?;
    let domain: HostedDomainIdentity =
        instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let (ticket, source) =
        hosted_source_irp_ledger::pin(instance_index, domain, source_irp_address)
            .ok_or(CaptureError::InvalidSource)?;
    let result = (|| {
        let mut target =
            HostedForwardTarget::capture(io_manager_mut(), domain, target_device_address)
                .map_err(|_| CaptureError::InvalidTarget)?;
        let admitted = (|| {
            let pdo = target
                .validate(io_manager_mut())
                .map_err(|_| CaptureError::InvalidTarget)?;
            let authority = hosted_accepted_pdo_provider_catalog()
                .resolve(
                    hosted_pnp_manager_mut(),
                    hosted_bus_relations(),
                    io_manager_mut(),
                    pdo.raw(),
                )
                .map_err(|_| CaptureError::InvalidTarget)?;
            if authority.provider().domain() == domain {
                return Err(CaptureError::InvalidTarget);
            }
            let route = ScsiSrbRoute {
                pdo,
                provider: authority.provider().domain(),
                relation_generation: authority.parent_relation().relation().generation(),
                provider_pdo: authority.provider().address(),
            };
            let (children, srb, mdl, data, sense) = hosted_source_irp_ledger::capture_scsi_children(
                instance_index,
                source,
                ticket,
                target_device_address,
                route,
            )
            .ok_or(CaptureError::InvalidSrb)?;
            Ok((authority, children, srb, mdl, data, sense))
        })();
        match admitted {
            Ok((authority, children, srb, mdl, data, sense)) => Ok(CapturedSourceScsi {
                instance_index,
                source,
                ticket,
                target: Some(target),
                authority,
                children,
                srb,
                mdl,
                data,
                sense,
                children_retained: true,
                source_pinned: true,
            }),
            Err(error) => {
                target
                    .release(io_manager_mut())
                    .expect("unentered SCSI target rollback");
                Err(error)
            }
        }
    })();
    if result.is_err() {
        assert!(
            hosted_source_irp_ledger::unpin(ticket),
            "unentered SCSI source rollback"
        );
    }
    result
}

/// Classify the overloaded major 0x0f from exact accepted PDO authority before reading the
/// stack union as either an SRB pointer or an internal-control code. Capture repeats this proof
/// at admission, so a revoked relation can never enter the provider after classification.
pub(super) unsafe fn accepted_foreign_pdo(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    target_device_address: u64,
) -> Result<bool, CaptureError> {
    let (_, inst) = instance_for_pump_channel(ch, reply_cap)
        .ok_or(CaptureError::InvalidCaller)?;
    hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge)
        .ok_or(CaptureError::InvalidCaller)?;
    let domain = instance_domain_identity(inst).ok_or(CaptureError::InvalidCaller)?;
    let Ok(mut target) = HostedForwardTarget::capture(
        io_manager_mut(), domain, target_device_address,
    ) else { return Ok(false); };
    let accepted = target.validate(io_manager_mut()).ok().and_then(|pdo| {
        hosted_accepted_pdo_provider_catalog().resolve(
            hosted_pnp_manager_mut(), hosted_bus_relations(), io_manager_mut(), pdo.raw(),
        ).ok()
    }).is_some_and(|authority| authority.provider().domain() != domain);
    target.release(io_manager_mut())
        .map_err(|_| CaptureError::InvalidTarget)?;
    Ok(accepted)
}
