//! Source-owned SCSI SRB admission for one accepted foreign storage PDO.
//!
//! The producer's IRP, SRB, MDL and pool-backed transfer buffer are retained before any
//! provider entry. A raw pointer is never forwarded to another address domain. Provider
//! dispatch will consume the owned byte snapshots and must report exact terminal/ACK events.

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};
use super::hosted_source_pool_memory::SourcePoolMemory;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    scsi_source_retention::ScsiSourceChildren,
    scsi_srb_transport::{failed_legacy_srb, merge_provider_legacy_srb, project_claim_source_alias, sanitized_legacy_srb, ScsiSrbRoute, WDM_X64_LEGACY_SRB_SIZE},
    source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpUseTicket}, HostedDomainIdentity,
};
use nt_pnp_manager::AcceptedPdoProviderAuthority;

static SCSI_CHILD_ADMISSION_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);

fn trace_scsi_child_admission(diagnostic: &hosted_source_irp_ledger::ScsiCaptureDiagnostic) {
    if SCSI_CHILD_ADMISSION_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 4 { return; }
    print_str(b"[scsi-child-admission] stage/srb/mdl/data/len/mdl-size/flags/count/reg-len/reg-va/locked/origin=");
    print_str(diagnostic.stage);
    print_str(b"/");
    print_hex64(diagnostic.srb);
    print_str(b"/");
    print_hex64(diagnostic.mdl);
    print_str(b"/");
    print_hex64(diagnostic.data);
    print_str(b"/");
    print_u64(u64::from(diagnostic.transfer));
    print_str(b"/");
    print_u64(diagnostic.mdl_size as u16 as u64);
    print_str(b"/");
    print_hex(diagnostic.mdl_flags as u16 as u32);
    print_str(b"/");
    print_u64(u64::from(diagnostic.mdl_count));
    print_str(b"/");
    print_u64(u64::from(diagnostic.registry_length));
    print_str(b"/");
    print_hex64(diagnostic.registry_va);
    print_str(b"/");
    print_u64(u64::from(diagnostic.registry_locked));
    print_str(b"/");
    print_u64(u64::from(diagnostic.data_origin));
    print_str(b"\n");
}

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
    source_pdo_alias: u64,
    ticket: SourceIrpTicket,
    use_ticket: SourceIrpUseTicket,
    target: Option<HostedForwardTarget>,
    authority: AcceptedPdoProviderAuthority,
    children: ScsiSourceChildren,
    stack_lease: Option<hosted_source_stack_lease::SourceStackLeaseId>,
    data_stack_lease: Option<hosted_source_stack_lease::SourceStackLeaseId>,
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

    pub(super) fn scsi_identity(&self) -> hosted_source_stack_lease::ScsiStackSource {
        hosted_source_stack_lease::ScsiStackSource::new(self.source_identity(), self.use_ticket)
            .expect("retained exact SCSI use identity")
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
        hosted_source_irp_ledger::arm_scsi_deferred_free(self.use_ticket, self.source)
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
    pub(super) fn srb_function(&self) -> Option<u8> { self.srb.get(2).copied() }
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
        claim_result: bool, status: i32,
    ) -> Result<(), CaptureError> {
        self.validate_retained()?;
        if data.len() != self.data.len()
            || sense.len() != self.sense.as_ref().map_or(0, Vec::len)
        {
            return Err(CaptureError::InvalidSrb);
        }
        if provider_srb.get(2).copied() != self.srb_function()
            || (claim_result && status != STATUS_SUCCESS)
        { return Err(CaptureError::InvalidSrb); }
        if claim_result {
            let target = self.target.as_ref().ok_or(CaptureError::InvalidTarget)?;
            if target.validate(io_manager_mut()).ok() != Some(self.children.route.pdo)
                || target.registration().address() != self.source_pdo_alias
            { return Err(CaptureError::InvalidTarget); }
        }
        let mut merged = merge_provider_legacy_srb(
            &self.srb, provider_srb, data.len(), sense.len(),
        )
        .map_err(|_| CaptureError::InvalidSrb)?;
        project_claim_source_alias(&mut merged, claim_result, self.source_pdo_alias)
            .map_err(|_| CaptureError::InvalidSrb)?;
        let inst = instance(self.instance_index).ok_or(CaptureError::InvalidSource)?;
        let memory = SourcePoolMemory::new(inst).ok_or(CaptureError::InvalidSource)?;
        let sense_address = match self.children.sense {
            Some(identity @ nt_io_manager::source_irp_auxiliary::SourceMemoryIdentity::Pool {
                component_address, ..
            }) if hosted_source_irp_ledger::scsi_sense_matches_unlocked(
                inst, identity, self.children.sense_length,
            ) => Some(component_address),
            None if sense.is_empty() => None,
            _ => return Err(CaptureError::InvalidSource),
        };
        let data_address = match self.children.data {
            Some(nt_io_manager::source_irp_auxiliary::SourceMemoryIdentity::Pool {
                component_address, ..
            }) => Some(component_address),
            Some(nt_io_manager::source_irp_auxiliary::SourceMemoryIdentity::MappedRange { .. }) => None,
            None if data.is_empty() => None,
            _ => return Err(CaptureError::InvalidSource),
        };
        let stack_data_ready = match (self.children.data, self.children.data_stack) {
            (Some(nt_io_manager::source_irp_auxiliary::SourceMemoryIdentity::MappedRange {
                component_address, bytes, exec_address,
            }), Some(range)) => {
                bytes == data.len() as u64 && self.data_stack_lease.is_some_and(|lease| {
                    hosted_source_stack_lease::scsi_data_can_write(
                        lease, self.scsi_identity(), range, component_address,
                        self.children.transfer_length, exec_address,
                    )
                })
            }
            (Some(nt_io_manager::source_irp_auxiliary::SourceMemoryIdentity::Pool { .. }), None)
            | (None, None) => true,
            _ => false,
        };
        // Validate all destinations before the first write while holding the pool lock.
        if !stack_data_ready
            || data_address.is_some_and(|address| !memory.contains(address, data.len()))
            || sense_address.is_some_and(|address| !memory.contains(address, sense.len()))
            || match self.children.srb {
                nt_io_manager::scsi_source_retention::ScsiSrbSource::Pool(pool) =>
                    !memory.contains(pool.component_address, merged.len()),
                nt_io_manager::scsi_source_retention::ScsiSrbSource::Stack { range, component_address } =>
                    !self.stack_lease.is_some_and(|lease| hosted_source_stack_lease::scsi_can_write(
                        lease, self.scsi_identity(), range, component_address,
                    )),
            }
        {
            return Err(CaptureError::InvalidSource);
        }
        if let Some(address) = data_address {
            if !memory.write(address, data) { return Err(CaptureError::InvalidSource); }
        } else if let (Some(nt_io_manager::source_irp_auxiliary::SourceMemoryIdentity::MappedRange {
            component_address, exec_address, ..
        }), Some(range), Some(lease)) = (self.children.data, self.children.data_stack, self.data_stack_lease) {
            if !hosted_source_stack_lease::write_scsi_data(
                lease, self.scsi_identity(), range, component_address, exec_address, data,
            ) { return Err(CaptureError::InvalidSource); }
        }
        if let Some(address) = sense_address {
            if !memory.write(address, sense) {
                return Err(CaptureError::InvalidSource);
            }
        }
        match self.children.srb {
            nt_io_manager::scsi_source_retention::ScsiSrbSource::Pool(pool) => {
                memory.write(pool.component_address, &merged)
                    .then_some(())
                    .ok_or(CaptureError::InvalidSource)
            }
            nt_io_manager::scsi_source_retention::ScsiSrbSource::Stack { range, component_address } => {
                let lease = self.stack_lease.ok_or(CaptureError::InvalidSource)?;
                hosted_source_stack_lease::write_scsi(
                    lease, self.scsi_identity(), range, component_address, &merged,
                ).then_some(()).ok_or(CaptureError::InvalidSource)
            }
        }
    }

    /// A malformed provider terminal is projected as an explicit failed SRB
    /// and IRP status. No provider bytes or pointers enter the source domain.
    pub(super) unsafe fn write_error_completion(&self, status: i32) -> Result<(), CaptureError> {
        let failed = failed_legacy_srb(
            &self.srb, self.data.len(), self.sense.as_ref().map_or(0, Vec::len),
        ).map_err(|_| CaptureError::InvalidSrb)?;
        self.write_completion(
            &failed, &self.data, self.sense.as_deref().unwrap_or(&[]), false, status,
        )
    }
    pub(super) fn provider_authority(&self) -> AcceptedPdoProviderAuthority {
        self.authority
    }

    /// Retire entered work against its retained physical source identities even if PnP has
    /// since replaced the parent relation. Relation retirement cannot make a completed SRB's
    /// source pool children safe to discard before the caller-local completion and ACK.
    pub(super) fn validate_retained(&self) -> Result<(), CaptureError> {
        if !self.source_pinned
            || !(hosted_source_irp_ledger::scsi_children_match_current(
                    self.instance_index, self.children, self.stack_lease, self.data_stack_lease,
                ) || hosted_source_irp_ledger::scsi_children_match_after_callback(
                    self.instance_index, self.children, self.stack_lease, self.data_stack_lease,
                ))
        {
            return Err(CaptureError::InvalidSource);
        }
        Ok(())
    }

    /// Native completion after publication does not access the caller's SRB,
    /// MDL, data or sense memory. The exact source use and physical IRP remain
    /// pinned until provider ACK and source completion both finish.
    pub(super) fn validate_published_source(&self, provider_irp: IrpId) -> Result<(), CaptureError> {
        if !self.source_pinned || !self.children_retained
            || !hosted_source_irp_ledger::scsi_published_source_matches(
                self.instance_index, self.children, provider_irp,
            )
        { return Err(CaptureError::InvalidSource); }
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
        self.release_references(false, false)
    }

    pub(super) fn release_after_completions(&mut self) -> Result<(), CaptureError> {
        if self.children_retained {
            if !hosted_source_irp_ledger::release_scsi_children(self.children) {
                return Err(CaptureError::InvalidSource);
            }
            self.children_retained = false;
        }
        self.release_references(self.completion_finished(), true)
    }

    fn release_references(
        &mut self,
        free_requested: bool,
        completed_scsi: bool,
    ) -> Result<(), CaptureError> {
        if let Some(lease) = self.data_stack_lease {
            if !unsafe { hosted_source_stack_lease::release_scsi_data(lease, self.scsi_identity()) } {
                return Err(CaptureError::InvalidSource);
            }
            self.data_stack_lease = None;
        }
        if let Some(lease) = self.stack_lease {
            if !unsafe { hosted_source_stack_lease::release_scsi(lease, self.scsi_identity()) } {
                return Err(CaptureError::InvalidSource);
            }
            self.stack_lease = None;
        }
        if self.source_pinned {
            let released = if free_requested {
                hosted_source_irp_ledger::release_pending_scsi_terminal(self.use_ticket, self.source)
            } else if completed_scsi {
                hosted_source_irp_ledger::complete_scsi_use(self.use_ticket, self.source)
            } else {
                hosted_source_irp_ledger::abandon_scsi_use(self.use_ticket, self.source)
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
    let (ticket, use_ticket, source) =
        hosted_source_irp_ledger::pin_scsi(instance_index, domain, source_irp_address)
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
            let mut diagnostic = hosted_source_irp_ledger::ScsiCaptureDiagnostic::default();
            let captured = hosted_source_irp_ledger::capture_scsi_children(
                instance_index,
                source,
                ticket,
                use_ticket,
                target_device_address,
                route,
                ch,
                reply_cap,
                &mut diagnostic,
            );
            if captured.is_none() { trace_scsi_child_admission(&diagnostic); }
            let (children, srb, mdl, data, sense, stack_lease, data_stack_lease) =
                captured.ok_or(CaptureError::InvalidSrb)?;
            Ok((authority, children, srb, mdl, data, sense, stack_lease, data_stack_lease))
        })();
        match admitted {
            Ok((authority, children, srb, mdl, data, sense, stack_lease, data_stack_lease)) => Ok(CapturedSourceScsi {
                instance_index,
                source,
                source_pdo_alias: target_device_address,
                ticket,
                use_ticket,
                target: Some(target),
                authority,
                children,
                stack_lease,
                data_stack_lease,
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
            hosted_source_irp_ledger::abandon_scsi_use(use_ticket, source),
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
