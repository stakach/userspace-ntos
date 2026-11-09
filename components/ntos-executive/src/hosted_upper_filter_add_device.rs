//! Ordered class UpperFilter attachment with retained native child-work ownership.

use super::*;
use super::hosted_add_device_continuation::{
    AddDeviceBanks, AddDevicePumpContinuation, AddDevicePumpProgress,
    dispatch_add_device_for_instance_progress, dispatch_class_lower_alias_progress,
    dispatch_pdo_projection_progress,
};
use super::hosted_upper_filter_projection::AliasKind;

static mut LEDGER: nt_pnp_manager::UpperFilterAttachmentLedger =
    nt_pnp_manager::UpperFilterAttachmentLedger::new();

fn ledger() -> &'static mut nt_pnp_manager::UpperFilterAttachmentLedger {
    unsafe { &mut *core::ptr::addr_of_mut!(LEDGER) }
}

fn ledger_status(error: nt_pnp_manager::UpperFilterAttachmentError) -> nt_status::NtStatus {
    match error {
        nt_pnp_manager::UpperFilterAttachmentError::InsufficientResources =>
            nt_status::NtStatus::INSUFFICIENT_RESOURCES,
        _ => nt_status::NtStatus::INVALID_DEVICE_REQUEST,
    }
}

enum ActivePhase {
    PdoProjectionReady,
    PdoProjectionPump(AddDevicePumpContinuation),
    PdoProjectionTerminal(Result<u64, nt_status::NtStatus>),
    LowerProjectionReady,
    LowerProjectionPump(AddDevicePumpContinuation),
    LowerProjectionTerminal(Result<u64, nt_status::NtStatus>),
    AliasReady,
    AliasPump(AddDevicePumpContinuation),
    AliasTerminal(Result<u64, nt_status::NtStatus>),
    AddDeviceReady,
    AddDevicePump(AddDevicePumpContinuation),
    AddDeviceTerminal(Result<AddDeviceDispatchResult, nt_status::NtStatus>),
    AbortPending(nt_status::NtStatus, hosted_add_device_rollback::AbortReceipt),
    AbortBlocked(nt_status::NtStatus, hosted_add_device_rollback::AbortReceipt),
    Finalized(Result<(), nt_status::NtStatus>),
    Blocked,
}

/// A claimed filter keeps its class-local aliases and shared bank until the exact native
/// AddDevice has returned and its attachment, rollback, and ledger outcomes are committed.
struct ActiveFilter {
    claim: nt_pnp_manager::UpperFilterAttachmentClaim,
    owner_id: u64,
    prepared: Option<hosted_upper_filter_projection::PreparedUpperFilterProjection>,
    class_instance: usize,
    driver_index: usize,
    driver_inst: DriverInstance,
    rollback: Option<hosted_add_device_rollback::Reservation>,
    banks: AddDeviceBanks,
    transferred: bool,
    phase: ActivePhase,
}

impl ActiveFilter {
    fn prepared(&self) -> hosted_upper_filter_projection::PreparedUpperFilterProjection {
        self.prepared.expect("upper-filter aliases are not yet published")
    }
}

/// The ledger keeps the complete ordered plan. This owner carries only its exact plan key,
/// current claim, and the path needed to validate the next class-local projection.
#[must_use = "retain the exact upper-filter Reply, aliases, bank, and ledger claim"]
pub(crate) struct UpperFilterAttachContinuation {
    key: nt_pnp_manager::UpperFilterAttachmentKey,
    instance_path: String,
    active: Option<ActiveFilter>,
    /// A claim may have entered before projection preparation refused. Keep its exact token
    /// even when no native pump was created; neither it nor a later ordered slot may replay.
    blocked_claim: Option<nt_pnp_manager::UpperFilterAttachmentClaim>,
    blocked_plan: bool,
}

#[must_use = "a yielded upper-filter attachment still owns its physical transaction"]
pub(crate) enum UpperFilterAttachProgress {
    Completed(Result<(), nt_status::NtStatus>),
    ChildWorkYield(UpperFilterAttachContinuation),
    RetainedRefusal(UpperFilterAttachContinuation),
}

impl UpperFilterAttachContinuation {
    fn projection_pump_phase(kind: AliasKind, pump: AddDevicePumpContinuation) -> ActivePhase {
        match kind {
            AliasKind::Pdo => ActivePhase::PdoProjectionPump(pump),
            AliasKind::Lower => ActivePhase::LowerProjectionPump(pump),
        }
    }

    fn projection_terminal_phase(
        kind: AliasKind, result: Result<u64, nt_status::NtStatus>,
    ) -> ActivePhase {
        match kind {
            AliasKind::Pdo => ActivePhase::PdoProjectionTerminal(result),
            AliasKind::Lower => ActivePhase::LowerProjectionTerminal(result),
        }
    }

    fn pump(&self) -> Option<&AddDevicePumpContinuation> {
        match &self.active.as_ref()?.phase {
            ActivePhase::PdoProjectionPump(pump) | ActivePhase::LowerProjectionPump(pump)
            | ActivePhase::AliasPump(pump) | ActivePhase::AddDevicePump(pump) => Some(pump),
            _ => None,
        }
    }

    fn pump_mut(&mut self) -> Option<&mut AddDevicePumpContinuation> {
        match &mut self.active.as_mut()?.phase {
            ActivePhase::PdoProjectionPump(pump) | ActivePhase::LowerProjectionPump(pump)
            | ActivePhase::AliasPump(pump) | ActivePhase::AddDevicePump(pump) => Some(pump),
            _ => None,
        }
    }

    pub(crate) fn child_work_ready(&self) -> bool {
        self.pump().is_some_and(AddDevicePumpContinuation::child_work_ready)
    }

    pub(crate) fn retry_without_new_child(&self) -> bool {
        !self.blocked_plan && (self.pump().is_some_and(
            AddDevicePumpContinuation::retry_without_new_child)
            || self.active.as_ref().is_some_and(|active| matches!(&active.phase,
                ActivePhase::PdoProjectionTerminal(_) | ActivePhase::LowerProjectionTerminal(_)
                | ActivePhase::AliasTerminal(_) | ActivePhase::AddDeviceTerminal(_)
                | ActivePhase::AbortPending(_, _)
                | ActivePhase::Finalized(_))))
    }

    pub(crate) fn physical_identity(
        &self,
    ) -> Option<component_scheduler::ChildWorkPhysicalIdentity> {
        self.pump()?.physical_identity()
    }

    pub(crate) fn record_child_step(
        &mut self,
        step: crate::service_sec_image::NestedChildStep,
    ) -> Result<(), crate::service_sec_image::NestedChildStep> {
        let Some(active) = self.active.as_ref() else { return Err(step) };
        if unsafe { nt_pnp_manager::UpperFilterAttachmentLedger::validate_current(
            hosted_pnp_manager_mut(), active.claim.key(),
        ) }.is_err() {
            return Err(step);
        }
        match self.pump_mut() {
            Some(pump) => pump.record_child_step(step),
            None => Err(step),
        }
    }

    /// A certified empty child pass keeps the same pump and claim. Only a deposited receipt or
    /// an exact retryable restoration can resume native receive without replaying ReplyRequest.
    pub(crate) unsafe fn resume(self) -> UpperFilterAttachProgress {
        self.drive()
    }

    unsafe fn mark_terminal_failure(
        active: &mut ActiveFilter,
        status: nt_status::NtStatus,
    ) {
        hosted_upper_filter_projection::block_uncertain(active.owner_id);
        if ledger().mark_uncertain(hosted_pnp_manager_mut(), active.claim).is_err() {
            active.phase = ActivePhase::Blocked;
            return;
        }
        if active.rollback.is_none() {
            // Both local aliases may exist even though AddDevice has not entered. No rollback
            // owner can retire their pointers yet, so keep the class page and lower stack held.
            active.phase = ActivePhase::Blocked;
            return;
        }
        if active.transferred {
            // The upper FDO is already attached. A ledger refusal cannot authorize teardown of
            // its lower function FDO. Keep the rollback bank and the PnP batch blocked until an
            // exact upper-stack retirement owner detaches this FDO.
            if let Some(rollback) = active.rollback.take() {
                hosted_add_device_rollback::block(rollback, status);
            }
            active.phase = ActivePhase::Blocked;
            return;
        }
        if let Some(rollback) = active.rollback.take() {
            active.phase = match hosted_add_device_rollback::abort_owned(rollback) {
                hosted_add_device_rollback::AbortProgress::Retired =>
                    ActivePhase::Finalized(Err(status)),
                hosted_add_device_rollback::AbortProgress::Retiring(receipt) =>
                    ActivePhase::AbortPending(status, receipt),
                hosted_add_device_rollback::AbortProgress::Blocked(receipt) =>
                    ActivePhase::AbortBlocked(status, receipt),
            };
            return;
        }
        active.phase = ActivePhase::Finalized(Err(status));
    }

    /// A native dispatch refusal has no authenticated terminal. Keep the class page and exact
    /// entered claim fenced; neither the next filter nor the original ReplyRequest may run.
    unsafe fn block_unsettled(
        active: &mut ActiveFilter,
        status: nt_status::NtStatus,
    ) {
        hosted_upper_filter_projection::block_uncertain(active.owner_id);
        let _ = ledger().mark_uncertain(hosted_pnp_manager_mut(), active.claim);
        if let Some(rollback) = active.rollback.take() {
            hosted_add_device_rollback::block(rollback, status);
        }
        active.phase = ActivePhase::Blocked;
    }

    unsafe fn begin_next(&mut self) -> Result<bool, nt_status::NtStatus> {
        let Some(claim) = ledger().claim_next(hosted_pnp_manager_mut(), self.key)
            .map_err(ledger_status)? else { return Ok(false) };
        self.blocked_claim = Some(claim);
        // Reserve the canonical alias owner without calling the component. The class page is
        // leased, and the ledger is entered, before the first projection ReplyRequest.
        let (owner_id, class_instance) = match
            hosted_upper_filter_projection::reserve_alias_owner(&self.instance_path, claim)
        {
            Ok(owner) => owner,
            Err(status) => {
                let _ = ledger().release_unentered(claim);
                return Err(status);
            }
        };
        let (driver_index, driver_inst) = match instance_by_driver_id(claim.driver_id()) {
            Some(instance) => instance,
            None => {
                let _ = hosted_upper_filter_projection::release_reserved_alias_owner(owner_id);
                let _ = ledger().release_unentered(claim);
                return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
            }
        };
        let class_inst = match instance(class_instance) {
            Some(instance) => instance,
            None => {
                let _ = hosted_upper_filter_projection::release_reserved_alias_owner(owner_id);
                let _ = ledger().release_unentered(claim);
                return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
            }
        };
        let banks = match AddDeviceBanks::claim(class_inst.exec_shared_va, class_instance) {
            Ok(banks) => banks,
            Err(status) => {
                let _ = hosted_upper_filter_projection::release_reserved_alias_owner(owner_id);
                let _ = ledger().release_unentered(claim);
                return Err(status);
            }
        };
        if ledger().mark_entered(hosted_pnp_manager_mut(), claim).is_err() {
            hosted_upper_filter_projection::block_uncertain(owner_id);
            self.active = Some(ActiveFilter { claim, owner_id, prepared: None,
                class_instance, driver_index, driver_inst, rollback: None, banks,
                transferred: false, phase: ActivePhase::Blocked });
        } else {
            self.active = Some(ActiveFilter { claim, owner_id, prepared: None,
                class_instance, driver_index, driver_inst, rollback: None, banks,
                transferred: false, phase: ActivePhase::PdoProjectionReady });
        }
        self.blocked_claim = None;
        Ok(true)
    }

    unsafe fn finish_dispatch(
        active: &mut ActiveFilter,
        dispatch: AddDeviceDispatchResult,
    ) -> Result<(), nt_status::NtStatus> {
        hosted_add_device_rollback::completed_dispatch(
            active.rollback.as_ref().expect("entered filter rollback"), &dispatch,
        );
        dispatch.status.to_result()?;
        if dispatch.pdo_object != active.prepared().pdo_object
            || dispatch.fdo_object != active.prepared().lower_object
        {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let pdo = nt_io_manager::DeviceId(active.claim.key().child().pdo_object_id());
        let fdo = io_manager_mut().top_of_device_stack(pdo)
            .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        if fdo.raw() == active.claim.lower_device()
            || !io_manager_mut().device(fdo).is_some_and(|device| {
                device.driver_id == DriverId(active.claim.driver_id())
                    && device.attached_to == Some(nt_io_manager::DeviceId(active.claim.lower_device()))
            })
        {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let fdo_address = io_manager_mut()
            .hosted_device_address_by_identity(active.prepared().class_domain, fdo)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let registration = hosted_device_pointer_registration(
            active.prepared().class_domain, fdo_address, fdo,
        )?;
        if !hosted_add_device_rollback::owns_created_registration(
            active.rollback.as_ref().expect("entered filter rollback"), registration,
        ) {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        let class_inst = instance(active.class_instance)
            .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
        validate_and_sync_hosted_upper_filter_device_projection(
            class_inst, active.prepared().class_domain, fdo_address, fdo,
            DriverId(active.claim.driver_id()), dispatch.driver_object,
            HostedUpperFilterTypeProof {
                source: registration,
                pdo: active.prepared().pdo_registration,
                lower: active.prepared().lower_registration,
            },
        )?;
        hosted_upper_filter_projection::complete_add_device(active.owner_id, registration)?;
        active.transferred = true;
        ledger().complete(hosted_pnp_manager_mut(), active.claim, fdo.raw(),
            active.claim.lower_device()).map_err(ledger_status)?;
        Ok(())
    }

    unsafe fn drive(mut self) -> UpperFilterAttachProgress {
        let _durable = crate::allocator::enter_durable();
        loop {
            if self.blocked_plan {
                return UpperFilterAttachProgress::RetainedRefusal(self);
            }
            if self.active.is_none() {
                match self.begin_next() {
                    Ok(false) => return UpperFilterAttachProgress::Completed(Ok(())),
                    Err(_status) => {
                        // Even a pre-claim ledger refusal may follow an earlier attached filter.
                        // The exact plan is already reserved, so lower-stack rollback is unsafe.
                        self.blocked_plan = true;
                        return UpperFilterAttachProgress::RetainedRefusal(self);
                    }
                    Ok(true) => {}
                }
            }
            let mut active = self.active.take().expect("entered filter claim");
            let phase = core::mem::replace(&mut active.phase, ActivePhase::Blocked);
            let pdo_projection_ready = matches!(&phase, ActivePhase::PdoProjectionReady);
            let pdo_projection_terminal = matches!(&phase, ActivePhase::PdoProjectionTerminal(_));
            let pdo_projection_pump = matches!(&phase, ActivePhase::PdoProjectionPump(_));
            let lower_projection_pump = matches!(&phase, ActivePhase::LowerProjectionPump(_));
            let alias_pump = matches!(&phase, ActivePhase::AliasPump(_));
            match phase {
                ActivePhase::PdoProjectionReady | ActivePhase::LowerProjectionReady => {
                    let kind = if pdo_projection_ready {
                        AliasKind::Pdo
                    } else { AliasKind::Lower };
                    if let Err(status) = hosted_upper_filter_projection::begin_alias_projection(
                        active.owner_id, kind,
                    ) {
                        Self::block_unsettled(&mut active, status);
                        self.active = Some(active);
                        return UpperFilterAttachProgress::RetainedRefusal(self);
                    }
                    let progress = dispatch_pdo_projection_progress(
                        active.class_instance, crate::initial_system_driver_caller(),
                    );
                    active.phase = match progress {
                        AddDevicePumpProgress::ProjectionCompleted(result) =>
                            Self::projection_terminal_phase(kind, result),
                        AddDevicePumpProgress::ChildWorkYield(pump)
                        | AddDevicePumpProgress::RetainedRefusal(pump) =>
                            Self::projection_pump_phase(kind, pump),
                        AddDevicePumpProgress::Completed(_) => ActivePhase::Blocked,
                    };
                    let yielded = matches!(&active.phase,
                        ActivePhase::PdoProjectionPump(pump)
                        | ActivePhase::LowerProjectionPump(pump) if pump.child_work_ready());
                    let retained = matches!(&active.phase,
                        ActivePhase::PdoProjectionPump(_) | ActivePhase::LowerProjectionPump(_)
                        | ActivePhase::Blocked);
                    self.active = Some(active);
                    if yielded { return UpperFilterAttachProgress::ChildWorkYield(self) }
                    if retained { return UpperFilterAttachProgress::RetainedRefusal(self) }
                }
                ActivePhase::PdoProjectionTerminal(result) |
                ActivePhase::LowerProjectionTerminal(result) => {
                    let kind = if pdo_projection_terminal {
                        AliasKind::Pdo
                    } else { AliasKind::Lower };
                    let accepted = result.and_then(|address|
                        hosted_upper_filter_projection::accept_alias_projection(
                            active.owner_id, kind, address));
                    if let Err(status) = accepted {
                        Self::block_unsettled(&mut active, status);
                        self.active = Some(active);
                        return UpperFilterAttachProgress::RetainedRefusal(self);
                    }
                    if kind == AliasKind::Pdo {
                        active.phase = ActivePhase::LowerProjectionReady;
                    } else {
                        let prepared = hosted_upper_filter_projection::finish_prepared(
                            active.owner_id,
                        ).and_then(|prepared| {
                            hosted_upper_filter_projection::begin_local_chain(active.owner_id)?;
                            Ok(prepared)
                        });
                        match prepared {
                            Ok(prepared) => {
                                active.prepared = Some(prepared);
                                active.phase = ActivePhase::AliasReady;
                            }
                            Err(status) => Self::block_unsettled(&mut active, status),
                        }
                    }
                    self.active = Some(active);
                }
                ActivePhase::AliasReady => {
                    let progress = dispatch_class_lower_alias_progress(
                        active.class_instance, active.prepared(), crate::initial_system_driver_caller(),
                    );
                    active.phase = match progress {
                        AddDevicePumpProgress::ProjectionCompleted(result) =>
                            ActivePhase::AliasTerminal(result),
                        AddDevicePumpProgress::ChildWorkYield(pump) => ActivePhase::AliasPump(pump),
                        AddDevicePumpProgress::RetainedRefusal(pump) => ActivePhase::AliasPump(pump),
                        AddDevicePumpProgress::Completed(_) => ActivePhase::Blocked,
                    };
                    let yielded = matches!(&active.phase, ActivePhase::AliasPump(pump)
                        if pump.child_work_ready());
                    let retained = matches!(&active.phase, ActivePhase::AliasPump(_)
                        | ActivePhase::Blocked);
                    self.active = Some(active);
                    if yielded { return UpperFilterAttachProgress::ChildWorkYield(self) }
                    if retained { return UpperFilterAttachProgress::RetainedRefusal(self) }
                }
                ActivePhase::PdoProjectionPump(pump)
                | ActivePhase::LowerProjectionPump(pump)
                | ActivePhase::AliasPump(pump)
                | ActivePhase::AddDevicePump(pump) => {
                    let alias = alias_pump;
                    let projection_kind = if pdo_projection_pump { Some(AliasKind::Pdo) }
                        else if lower_projection_pump { Some(AliasKind::Lower) }
                        else { None };
                    let waiting = |pump| match projection_kind {
                        Some(kind) => Self::projection_pump_phase(kind, pump),
                        None if alias => ActivePhase::AliasPump(pump),
                        None => ActivePhase::AddDevicePump(pump),
                    };
                    if pump.child_work_ready() && !pump.retry_without_new_child() {
                        active.phase = waiting(pump);
                        self.active = Some(active);
                        return UpperFilterAttachProgress::ChildWorkYield(self);
                    }
                    if !pump.retry_without_new_child() {
                        active.phase = waiting(pump);
                        self.active = Some(active);
                        return UpperFilterAttachProgress::RetainedRefusal(self);
                    }
                    let progress = pump.resume();
                    active.phase = match progress {
                        AddDevicePumpProgress::ProjectionCompleted(result)
                            if projection_kind.is_some() =>
                                Self::projection_terminal_phase(projection_kind.unwrap(), result),
                        AddDevicePumpProgress::ProjectionCompleted(result) if alias =>
                            ActivePhase::AliasTerminal(result),
                        AddDevicePumpProgress::Completed(result)
                            if !alias && projection_kind.is_none() =>
                            ActivePhase::AddDeviceTerminal(result),
                        AddDevicePumpProgress::ChildWorkYield(pump)
                        | AddDevicePumpProgress::RetainedRefusal(pump) =>
                            waiting(pump),
                        _ => ActivePhase::Blocked,
                    };
                    let yielded = matches!(&active.phase,
                        ActivePhase::PdoProjectionPump(pump)
                        | ActivePhase::LowerProjectionPump(pump)
                        | ActivePhase::AliasPump(pump)
                        | ActivePhase::AddDevicePump(pump) if pump.child_work_ready());
                    let retained = matches!(&active.phase,
                        ActivePhase::PdoProjectionPump(_) | ActivePhase::LowerProjectionPump(_)
                        | ActivePhase::AliasPump(_) | ActivePhase::AddDevicePump(_)
                        | ActivePhase::Blocked);
                    self.active = Some(active);
                    if yielded { return UpperFilterAttachProgress::ChildWorkYield(self) }
                    if retained { return UpperFilterAttachProgress::RetainedRefusal(self) }
                }
                ActivePhase::AliasTerminal(result) => {
                    match result.and_then(|observed_pdo| {
                        hosted_upper_filter_projection::complete_local_chain(
                            active.owner_id, observed_pdo,
                        )
                    }) {
                        Ok(()) => active.phase = ActivePhase::AddDeviceReady,
                        Err(status) => Self::mark_terminal_failure(&mut active, status),
                    }
                    self.active = Some(active);
                }
                ActivePhase::AddDeviceReady => {
                    let rollback = hosted_add_device_rollback::reserve(
                        active.class_instance, active.prepared().class_domain,
                        active.claim.key().child().pdo_object_id(), active.claim.driver_id(),
                    );
                    match rollback {
                        Err(status) => {
                            Self::mark_terminal_failure(&mut active, status);
                            self.active = Some(active);
                            continue;
                        }
                        Ok(rollback) => active.rollback = Some(rollback),
                    }
                    if let Err(status) = active.banks.transfer_to_rollback(
                        active.rollback.as_ref().expect("reserved filter rollback"),
                    ) {
                        Self::mark_terminal_failure(&mut active, status);
                        self.active = Some(active);
                        continue;
                    }
                    hosted_add_device_rollback::set_pdo(
                        active.rollback.as_ref().expect("reserved filter rollback"),
                        active.prepared().pdo_object, false,
                        Some(active.prepared().pdo_registration),
                    );
                    hosted_add_device_rollback::begin_dispatch(
                        active.rollback.as_ref().expect("reserved filter rollback"));
                    if let Err(status) = hosted_upper_filter_projection::begin_add_device(
                        active.owner_id,
                    ) {
                        Self::mark_terminal_failure(&mut active, status);
                        self.active = Some(active);
                        continue;
                    }
                    let progress = dispatch_add_device_for_instance_progress(
                        active.driver_index, active.driver_inst, active.prepared().pdo_object,
                        crate::initial_system_driver_caller(),
                    );
                    active.phase = match progress {
                        AddDevicePumpProgress::Completed(result) =>
                            ActivePhase::AddDeviceTerminal(result),
                        AddDevicePumpProgress::ChildWorkYield(pump)
                        | AddDevicePumpProgress::RetainedRefusal(pump) =>
                            ActivePhase::AddDevicePump(pump),
                        AddDevicePumpProgress::ProjectionCompleted(_) => ActivePhase::Blocked,
                    };
                    let yielded = matches!(&active.phase, ActivePhase::AddDevicePump(pump)
                        if pump.child_work_ready());
                    let retained = matches!(&active.phase, ActivePhase::AddDevicePump(_)
                        | ActivePhase::Blocked);
                    self.active = Some(active);
                    if yielded { return UpperFilterAttachProgress::ChildWorkYield(self) }
                    if retained { return UpperFilterAttachProgress::RetainedRefusal(self) }
                }
                ActivePhase::AddDeviceTerminal(result) => {
                    match result {
                        Err(status) => {
                            // `Completed(Err)` certifies that native entry was rejected or its
                            // Reply returned a malformed terminal. The rollback owner can now
                            // retire the class page; only `RetainedRefusal` is uncertain.
                            Self::mark_terminal_failure(&mut active, status);
                        }
                        Ok(dispatch) => {
                            match Self::finish_dispatch(&mut active, dispatch) {
                                Ok(()) => {
                                    // The rollback row now owns the class page ticket. Keep its
                                    // reservation until `commit_banked` can retire that ticket.
                                    active.phase = ActivePhase::Finalized(Ok(()));
                                }
                                Err(status) => Self::mark_terminal_failure(&mut active, status),
                            }
                        }
                    }
                    let blocked = matches!(&active.phase, ActivePhase::Blocked);
                    self.active = Some(active);
                    if blocked { return UpperFilterAttachProgress::RetainedRefusal(self) }
                }
                ActivePhase::AbortPending(status, receipt) => {
                    active.phase = match hosted_add_device_rollback::retry_abort_owned(receipt) {
                        hosted_add_device_rollback::AbortProgress::Retired =>
                            ActivePhase::Finalized(Err(status)),
                        hosted_add_device_rollback::AbortProgress::Retiring(receipt) =>
                            ActivePhase::AbortPending(status, receipt),
                        hosted_add_device_rollback::AbortProgress::Blocked(receipt) =>
                            ActivePhase::AbortBlocked(status, receipt),
                    };
                    let pending = matches!(&active.phase, ActivePhase::AbortPending(_, _)
                        | ActivePhase::AbortBlocked(_, _));
                    self.active = Some(active);
                    if pending { return UpperFilterAttachProgress::RetainedRefusal(self) }
                }
                ActivePhase::AbortBlocked(status, receipt) => {
                    active.phase = ActivePhase::AbortBlocked(status, receipt);
                    self.active = Some(active);
                    return UpperFilterAttachProgress::RetainedRefusal(self);
                }
                ActivePhase::Finalized(result) => {
                    if let Some(rollback) = active.rollback.take() {
                        if let Err(rollback) = hosted_add_device_rollback::commit_banked(rollback) {
                            active.rollback = Some(rollback);
                            active.phase = ActivePhase::Finalized(result);
                            self.active = Some(active);
                            return UpperFilterAttachProgress::RetainedRefusal(self);
                        }
                    }
                    if active.banks.retire().is_err() {
                        active.phase = ActivePhase::Finalized(result);
                        self.active = Some(active);
                        return UpperFilterAttachProgress::RetainedRefusal(self);
                    }
                    if let Err(status) = result {
                        return UpperFilterAttachProgress::Completed(Err(status));
                    }
                    register_instance_ready(active.driver_index, true);
                    // The previous filter is terminal and its bank is free. Only now may the
                    // ledger claim the next driver in the registry's ordered plan.
                }
                ActivePhase::Blocked => {
                    active.phase = ActivePhase::Blocked;
                    self.active = Some(active);
                    return UpperFilterAttachProgress::RetainedRefusal(self);
                }
            }
        }
    }
}

/// Reserve the ordered plan once, then transfer its exact claim and native phase to the batch
/// when the class driver yields. A later resume never repeats the prior ReplyRequest.
pub(super) unsafe fn attach_ordered_progress(
    instance_path: &str,
    pdo_id: u64,
    function_id: u64,
    mount_generation: u64,
    ordered_drivers: &[u64],
) -> UpperFilterAttachProgress {
    let _durable = crate::allocator::enter_durable();
    if ordered_drivers.is_empty() {
        return UpperFilterAttachProgress::Completed(Ok(()));
    }
    // Copy the path before reserving the plan. An allocation refusal leaves the ledger
    // untouched, so the caller may retry without confusing an entered claim with new work.
    let mut owned_path = String::new();
    if owned_path.try_reserve(instance_path.len()).is_err() {
        return UpperFilterAttachProgress::Completed(
            Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES));
    }
    owned_path.push_str(instance_path);
    let key = match ledger().reserve(
        hosted_pnp_manager_mut(), mount_generation, pdo_id, function_id, ordered_drivers,
    ) {
        Ok(key) => key,
        Err(error) => return UpperFilterAttachProgress::Completed(Err(ledger_status(error))),
    };
    UpperFilterAttachContinuation {
        key, instance_path: owned_path, active: None,
        blocked_claim: None, blocked_plan: false,
    }.drive()
}
