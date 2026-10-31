//! Exact-device POWER dispatch and completion ownership across foreign calls.
//! The canonical IRP remains live until an actual backend completion is acknowledged.

use alloc::vec::Vec;
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::completion_ack::{CompletionAckReservation, CompletionAcknowledgement};
use crate::dispatch::{DispatchContext, IrpProjection, PnpBackendDispatch};
use crate::irp::{IoParameters, IrpCompletionOrigin, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::power_irp_request::PowerParameters;
use crate::{CompletedIrp, DeviceId, DriverId, IoManager, IrpId};

const POWER: u8 = nt_io_abi::major::IRP_MJ_POWER;

#[derive(Debug)]
#[must_use = "dispatch or discard through the issuing I/O Manager"]
pub struct PreparedExternalPowerIrp {
    manager_identity: u64,
    irp_id: IrpId,
}

impl PreparedExternalPowerIrp {
    pub fn irp_id(&self) -> IrpId { self.irp_id }
}

#[derive(Debug)]
#[must_use = "recover the retained owner from this rejection"]
pub struct ExternalPowerRejection<T> {
    status: NtStatus,
    owner: T,
}

impl<T> ExternalPowerRejection<T> {
    pub fn status(&self) -> NtStatus { self.status }
    pub fn into_owner(self) -> T { self.owner }
    pub fn owner(&self) -> &T { &self.owner }
    pub fn into_prepared(self) -> T { self.owner }
}

#[derive(Debug)]
struct Snapshot {
    projection: IrpProjection,
    client: ClientId,
    origin_driver: DriverId,
    origin_device: DeviceId,
    stack: Vec<(DriverId, DeviceId)>,
}

#[derive(Debug)]
#[must_use = "invoke the exact foreign route once"]
pub struct ExternalPowerInvocation {
    prepared: PreparedExternalPowerIrp,
    snapshot: Snapshot,
}

impl ExternalPowerInvocation {
    pub fn projection(&self) -> &IrpProjection { &self.snapshot.projection }
    pub fn irp_id(&self) -> IrpId { self.prepared.irp_id }

    pub fn invoke<F>(self, invoke: F) -> ExternalPowerReturn
    where F: FnOnce(DispatchContext<'_>, &IrpProjection) -> PnpBackendDispatch {
        let mut empty = [];
        let context = DispatchContext::new(self.snapshot.projection.driver_id,
            self.snapshot.client, &mut empty);
        let outcome = invoke(context, &self.snapshot.projection);
        ExternalPowerReturn { invocation: self, outcome }
    }
}

#[derive(Debug)]
#[must_use = "reconcile through the issuing I/O Manager"]
pub struct ExternalPowerReturn {
    invocation: ExternalPowerInvocation,
    outcome: PnpBackendDispatch,
}

#[derive(Debug)]
#[must_use = "retain until terminal completion and exact ACK"]
pub struct RetainedExternalPower {
    returned: ExternalPowerReturn,
}

impl RetainedExternalPower {
    pub fn irp_id(&self) -> IrpId { self.returned.invocation.irp_id() }
    pub fn outcome(&self) -> PnpBackendDispatch { self.returned.outcome }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalPowerTerminalReceipt {
    irp_id: IrpId,
    status: NtStatus,
    information: u64,
    driver_pending: bool,
}

impl ExternalPowerTerminalReceipt {
    pub fn irp_id(&self) -> IrpId { self.irp_id }
    pub fn status(&self) -> NtStatus { self.status }
    pub fn information(&self) -> u64 { self.information }
    pub fn driver_pending(&self) -> bool { self.driver_pending }
}

#[derive(Debug)]
#[must_use = "retain a nonterminal POWER owner"]
pub enum ExternalPowerFinishResult {
    Terminal(ExternalPowerTerminalReceipt),
    Retained(RetainedExternalPower),
}

#[derive(Debug)]
#[must_use = "invoke the exact completion ACK once"]
pub struct ExternalPowerCompletionInvocation {
    owner: RetainedExternalPower,
    completion: CompletedIrp,
    reservation: CompletionAckReservation,
    backend_index: usize,
}

impl ExternalPowerCompletionInvocation {
    pub fn completion(&self) -> &CompletedIrp { &self.completion }
    pub fn backend_index(&self) -> usize { self.backend_index }
    pub fn invoke<F>(self, invoke: F) -> ExternalPowerCompletionReturn
    where F: FnOnce(&CompletedIrp) -> CompletionAcknowledgement {
        let acknowledgement = invoke(&self.completion);
        ExternalPowerCompletionReturn { invocation: self, acknowledgement }
    }
}

#[derive(Debug)]
#[must_use = "settle the foreign ACK result without replay"]
pub struct ExternalPowerCompletionReturn {
    invocation: ExternalPowerCompletionInvocation,
    acknowledgement: CompletionAcknowledgement,
}

impl ExternalPowerCompletionReturn {
    pub fn acknowledgement(&self) -> CompletionAcknowledgement { self.acknowledgement }
}

impl<P: ObjectManagerPort> IoManager<P> {
    pub fn prepare_external_power_to_exact_device(
        &mut self, client: ClientId, device: DeviceId, requestor_tid: u64,
        parameters: PowerParameters,
    ) -> Result<PreparedExternalPowerIrp, NtStatus> {
        if self.device(device).is_none_or(|d| d.delete_pending) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let mut irp = self.build_irp_record_at_device(client, device, None, POWER,
            IoParameters::Power(parameters))?;
        irp.requestor_tid = requestor_tid;
        let manager_identity = self.ensure_ownership_identity()?;
        let irp_id = self.allocate_irp(irp)?;
        let route = (|| {
            let record = self.irp(irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            let projection = IrpProjection::from_record(record)?;
            if projection.minor != parameters.minor() ||
                projection.parameters != IoParameters::Power(parameters) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let driver = self.driver(projection.driver_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            let target = driver.dispatch.get(POWER);
            let backend = target.mock_id().map(|id| id.0 as usize)
                .or_else(|| target.kernel_id().map(|id| id.0 as usize))
                .or_else(|| target.driver_peer_id().map(|id| id.0 as usize))
                .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
            if backend >= self.backends.len() { return Err(NtStatus::INVALID_PARAMETER); }
            Ok(())
        })();
        if let Err(status) = route {
            self.free_irp(irp_id);
            return Err(status);
        }
        if !self.irp_mut(irp_id).unwrap().transition(IrpState::Initialized) {
            self.free_irp(irp_id);
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(PreparedExternalPowerIrp { manager_identity, irp_id })
    }

    pub fn discard_prepared_external_power(&mut self, prepared: PreparedExternalPowerIrp)
        -> Result<(), ExternalPowerRejection<PreparedExternalPowerIrp>> {
        let result = (|| {
            self.validate_prepared(&prepared, IrpState::Initialized)?;
            if !self.irp_mut(prepared.irp_id).unwrap().transition(IrpState::Failed) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            self.free_irp(prepared.irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            Ok(())
        })();
        result.map_err(|status| ExternalPowerRejection { status, owner: prepared })
    }

    fn validate_prepared(&self, prepared: &PreparedExternalPowerIrp, state: IrpState)
        -> Result<(), NtStatus> {
        if prepared.manager_identity == 0 || prepared.manager_identity != self.ownership_identity() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let irp = self.irp(prepared.irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
        if irp.state != state || irp.origin_major != POWER || irp.file_id.is_some()
            || !irp.current_stack().is_some_and(|stack|
                stack.major == POWER && matches!(&stack.parameters,
                    IoParameters::Power(parameters) if stack.minor == parameters.minor())) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(())
    }

    pub fn begin_prepared_external_power(&mut self, prepared: PreparedExternalPowerIrp)
        -> Result<ExternalPowerInvocation, ExternalPowerRejection<PreparedExternalPowerIrp>> {
        let snapshot = (|| {
            self.validate_prepared(&prepared, IrpState::Initialized)?;
            let irp = self.irp(prepared.irp_id).unwrap();
            let projection = IrpProjection::from_record(irp)?;
            let mut stack = Vec::new();
            stack.try_reserve_exact(irp.stack.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            stack.extend(irp.stack.iter().map(|s| (s.driver_id, s.device_id)));
            Ok(Snapshot { projection, client: irp.client_id,
                origin_driver: irp.origin_driver_id, origin_device: irp.origin_device_id, stack })
        })();
        match snapshot {
            Err(status) => Err(ExternalPowerRejection { status, owner: prepared }),
            Ok(snapshot) => {
                assert!(self.irp_mut(prepared.irp_id).unwrap().transition(IrpState::Dispatched));
                Ok(ExternalPowerInvocation { prepared, snapshot })
            }
        }
    }

    fn validate_invocation(&self, invocation: &ExternalPowerInvocation)
        -> Result<(), NtStatus> {
        let p = &invocation.prepared;
        if p.manager_identity == 0 || p.manager_identity != self.ownership_identity() {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let irp = self.irp(p.irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
        let s = &invocation.snapshot;
        if irp.state == IrpState::Allocated || irp.state == IrpState::Initialized
            || irp.id != s.projection.irp_id || irp.client_id != s.client
            || irp.origin_major != POWER || irp.file_id.is_some()
            || irp.origin_driver_id != s.origin_driver || irp.origin_device_id != s.origin_device
            || irp.origin_minor != s.projection.minor
            || irp.requestor_tid != s.projection.requestor_tid
            || irp.stack.len() != s.stack.len()
            || !irp.stack.iter().zip(&s.stack).all(|(entry, pair)|
                (entry.driver_id, entry.device_id) == *pair)
            || !irp.current_stack().is_some_and(|stack|
                stack.major == POWER && stack.minor == s.projection.minor
                    && stack.parameters == s.projection.parameters) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(())
    }

    pub fn finish_external_power(&mut self, returned: ExternalPowerReturn)
        -> Result<ExternalPowerFinishResult, ExternalPowerRejection<ExternalPowerReturn>> {
        if let Err(status) = self.validate_invocation(&returned.invocation) {
            return Err(ExternalPowerRejection { status, owner: returned });
        }
        let id = returned.invocation.irp_id();
        if self.irp(id).is_none_or(|irp| irp.state != IrpState::Dispatched) {
            return Ok(ExternalPowerFinishResult::Retained(RetainedExternalPower { returned }));
        }
        match returned.outcome {
            PnpBackendDispatch::Returned { status, information } => {
                let irp = self.irp_mut(id).unwrap();
                irp.status = status;
                irp.information = information;
                assert!(irp.transition(IrpState::Completing));
                assert!(irp.transition(IrpState::Completed));
                self.free_irp(id);
                Ok(ExternalPowerFinishResult::Terminal(ExternalPowerTerminalReceipt {
                    irp_id: id, status, information, driver_pending: false,
                }))
            }
            PnpBackendDispatch::Pending => {
                let irp = self.irp_mut(id).unwrap();
                irp.status = NtStatus::PENDING;
                assert!(irp.transition(IrpState::Pending));
                Ok(ExternalPowerFinishResult::Retained(RetainedExternalPower { returned }))
            }
            PnpBackendDispatch::NotDispatched { .. }
            | PnpBackendDispatch::Indeterminate { .. } => {
                assert!(self.irp_mut(id).unwrap().transition(IrpState::Indeterminate));
                Ok(ExternalPowerFinishResult::Retained(RetainedExternalPower { returned }))
            }
        }
    }

    pub fn prepare_external_power_completion(&mut self, owner: RetainedExternalPower)
        -> Result<ExternalPowerCompletionInvocation, ExternalPowerRejection<RetainedExternalPower>> {
        let valid = (|| {
            self.validate_invocation(&owner.returned.invocation)?;
            if !matches!(owner.returned.outcome, PnpBackendDispatch::Pending) {
                return Err(NtStatus::INVALID_DEVICE_REQUEST);
            }
            let completion = self.completed_irp_snapshot(owner.irp_id()).ok_or(NtStatus::PENDING)?;
            let irp = self.irp(completion.id).ok_or(NtStatus::INVALID_PARAMETER)?;
            if completion.major != POWER || completion.minor != owner.returned.invocation.snapshot.projection.minor
                || completion.completion_origin != IrpCompletionOrigin::Driver
                || completion.status == NtStatus::PENDING || irp.completion_ack_reservation.is_some()
                || irp.detached_file_owner || !self.completed_irps.contains(&completion.id)
                || !irp.current_stack().is_some_and(|stack|
                    stack.major == POWER && stack.parameters == owner.returned.invocation.snapshot.projection.parameters) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let backend_index = self.driver(completion.completion_driver_id)
                .map(|d| d.backend.0 as usize).filter(|i| *i < self.backends.len())
                .ok_or(NtStatus::INVALID_PARAMETER)?;
            if self.backends[backend_index].is_faulted() { return Err(NtStatus::DEVICE_NOT_CONNECTED); }
            let reservation = CompletionAckReservation::new(self.ownership_identity(), completion.id)?;
            Ok((completion, reservation, backend_index))
        })();
        match valid {
            Err(status) => Err(ExternalPowerRejection { status, owner }),
            Ok((completion, reservation, backend_index)) => {
                self.irps.get_mut(completion.id).unwrap().completion_ack_reservation = Some(reservation);
                Ok(ExternalPowerCompletionInvocation { owner, completion, reservation, backend_index })
            }
        }
    }

    /// A backend that proved no handler entry transfers no POWER effect. Retire its untouched
    /// canonical packet before replying with the original rejection to the source caller.
    pub fn discard_not_dispatched_external_power(&mut self, owner: RetainedExternalPower)
        -> Result<NtStatus, ExternalPowerRejection<RetainedExternalPower>> {
        let result = (|| {
            self.validate_invocation(&owner.returned.invocation)?;
            let PnpBackendDispatch::NotDispatched { status } = owner.returned.outcome else {
                return Err(NtStatus::INVALID_DEVICE_REQUEST);
            };
            let irp = self.irp(owner.irp_id()).ok_or(NtStatus::INVALID_PARAMETER)?;
            if irp.state != IrpState::Indeterminate || irp.completion_ack_reservation.is_some() {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            self.free_irp(owner.irp_id()).ok_or(NtStatus::INVALID_PARAMETER)?;
            Ok(status)
        })();
        result.map_err(|status| ExternalPowerRejection { status, owner })
    }

    pub fn finish_external_power_completion(&mut self, returned: ExternalPowerCompletionReturn)
        -> Result<ExternalPowerTerminalReceipt, ExternalPowerRejection<ExternalPowerCompletionReturn>> {
        let invocation = &returned.invocation;
        let valid = (|| {
            self.validate_invocation(&invocation.owner.returned.invocation)?;
            let irp = self.irp(invocation.completion.id).ok_or(NtStatus::INVALID_PARAMETER)?;
            if irp.completion_ack_reservation != Some(invocation.reservation)
                || !invocation.reservation.matches(self.ownership_identity(), invocation.completion.id)
                || self.completed_irp_snapshot(invocation.completion.id) != Some(invocation.completion)
                || !self.completed_irps.contains(&invocation.completion.id)
                || self.driver(invocation.completion.completion_driver_id)
                    .map(|d| d.backend.0 as usize) != Some(invocation.backend_index) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            returned.acknowledgement.checked_status()
        })();
        if let Err(status) = valid {
            return Err(ExternalPowerRejection { status, owner: returned });
        }
        if let Err(status) = self.retire_acknowledged_completion(&invocation.completion,
            Some(invocation.reservation)) {
            return Err(ExternalPowerRejection { status, owner: returned });
        }
        let c = invocation.completion;
        Ok(ExternalPowerTerminalReceipt { irp_id: c.id, status: c.status,
            information: c.information, driver_pending: true })
    }

    /// Only a checked no-entry ACK can be attempted again. The same reserved completion and
    /// backend route remain attached to the returned invocation.
    pub fn retry_external_power_completion(&mut self, returned: ExternalPowerCompletionReturn)
        -> Result<ExternalPowerCompletionInvocation,
            ExternalPowerRejection<ExternalPowerCompletionReturn>> {
        let result = (|| {
            if !matches!(returned.acknowledgement,
                CompletionAcknowledgement::NotEntered { .. }) {
                return Err(NtStatus::INVALID_DEVICE_REQUEST);
            }
            let invocation = &returned.invocation;
            self.validate_invocation(&invocation.owner.returned.invocation)?;
            let irp = self.irp(invocation.completion.id).ok_or(NtStatus::INVALID_PARAMETER)?;
            if irp.completion_ack_reservation != Some(invocation.reservation)
                || !invocation.reservation.matches(self.ownership_identity(), invocation.completion.id)
                || self.completed_irp_snapshot(invocation.completion.id) != Some(invocation.completion)
                || !self.completed_irps.contains(&invocation.completion.id)
                || self.driver(invocation.completion.completion_driver_id)
                    .map(|d| d.backend.0 as usize) != Some(invocation.backend_index)
                || self.backends.get(invocation.backend_index).is_none_or(|b| b.is_faulted()) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(returned.invocation),
            Err(status) => Err(ExternalPowerRejection { status, owner: returned }),
        }
    }
}
