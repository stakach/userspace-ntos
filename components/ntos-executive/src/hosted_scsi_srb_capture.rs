//! Source-owned SCSI SRB admission for one accepted foreign storage PDO.
//!
//! The producer's IRP, SRB, MDL and pool-backed transfer buffer are retained before any
//! provider entry. A raw pointer is never forwarded to another address domain. Provider
//! dispatch will consume the owned byte snapshots and must report exact terminal/ACK events.

use super::*;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    scsi_source_retention::ScsiSourceChildren,
    scsi_srb_transport::{sanitized_legacy_srb, ScsiSrbRoute, WDM_X64_LEGACY_SRB_SIZE},
    source_irp_ledger::SourceIrpAllocation, HostedDomainIdentity,
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
    pub(super) fn source_irp_address(&self) -> u64 {
        self.source.component_address
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
    pub(super) fn provider_authority(&self) -> AcceptedPdoProviderAuthority {
        self.authority
    }

    /// Re-observe the accepted parent relation, the provider's exact pointer registration,
    /// the source pin and every physical child generation before entering native dispatch.
    pub(super) fn validate(&self) -> Result<(), CaptureError> {
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
            || !hosted_source_irp_ledger::scsi_children_match_current(
                self.instance_index,
                self.children,
            )
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
            self.validate()?;
            if !hosted_source_irp_ledger::abandon_scsi_children(self.children) {
                return Err(CaptureError::InvalidSource);
            }
            self.children_retained = false;
        }
        self.release_references()
    }

    pub(super) fn release_after_completions(&mut self) -> Result<(), CaptureError> {
        if self.children_retained {
            if !hosted_source_irp_ledger::release_scsi_children(self.children) {
                return Err(CaptureError::InvalidSource);
            }
            self.children_retained = false;
        }
        self.release_references()
    }

    fn release_references(&mut self) -> Result<(), CaptureError> {
        if let Some(target) = self.target.as_mut() {
            target
                .release(io_manager_mut())
                .map_err(|_| CaptureError::InvalidTarget)?;
            self.target = None;
        }
        if self.source_pinned {
            if !hosted_source_irp_ledger::unpin(self.ticket) {
                return Err(CaptureError::InvalidSource);
            }
            self.source_pinned = false;
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
