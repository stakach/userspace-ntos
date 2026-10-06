//! Owned PnP invocation across a foreign call, without a live I/O Manager borrow.

use super::*;

#[derive(Debug)]
struct Snapshot {
    projection: IrpProjection,
    client: ClientId,
    origin_driver: DriverId,
    origin_device: DeviceId,
    minor: u8,
    relation_type: Option<u32>,
    stack: Vec<(DriverId, DeviceId)>,
}

#[derive(Debug)]
#[must_use = "invoke once or retain the dispatched owner"]
pub struct ExternalPnpInvocation {
    prepared: PreparedExternalPnpIrp,
    snapshot: Snapshot,
}

#[derive(Debug)]
#[must_use = "reconcile through the issuing I/O Manager; never repeat foreign invocation"]
pub struct ExternalPnpReturn {
    invocation: ExternalPnpInvocation,
    outcome: PnpBackendDispatch,
}

#[derive(Debug)]
#[must_use = "retain nonterminal PnP ownership until checked completion reconciliation"]
pub struct RetainedExternalPnp {
    owner: ExternalPnpReturn,
    outcome: ExternalPnpDispatchResult,
}

impl RetainedExternalPnp {
    pub fn irp_id(&self) -> IrpId {
        self.owner.irp_id()
    }
    pub fn payload(&self) -> &[u8] {
        self.owner.payload()
    }
    pub fn outcome(&self) -> &ExternalPnpDispatchResult {
        &self.outcome
    }
}

/// The retained variant deliberately has no invocation or scalar-ACK consumption API. Native
/// integration requires a subsequent checked detached completion acknowledgement contract.
#[derive(Debug)]
#[must_use = "retain the nonterminal owner or consume the actual terminal result"]
pub enum ExternalPnpFinishResult {
    Terminal(ExternalPnpDispatchResult),
    Retained(RetainedExternalPnp),
}

#[derive(Debug)]
#[must_use = "retain the rejected return and its payload"]
pub struct ExternalPnpFinishRejection {
    status: NtStatus,
    owner: ExternalPnpReturn,
}

impl ExternalPnpFinishRejection {
    pub fn status(&self) -> NtStatus {
        self.status
    }
    pub fn owner(&self) -> &ExternalPnpReturn {
        &self.owner
    }
    pub fn into_owner(self) -> ExternalPnpReturn {
        self.owner
    }
}

impl ExternalPnpReturn {
    pub fn irp_id(&self) -> IrpId {
        self.invocation.prepared.irp_id
    }
    pub fn payload(&self) -> &[u8] {
        &self.invocation.prepared.payload
    }
}

impl ExternalPnpInvocation {
    pub fn irp_id(&self) -> IrpId {
        self.prepared.irp_id
    }
    pub fn projection(&self) -> &IrpProjection {
        &self.snapshot.projection
    }
    pub fn client(&self) -> ClientId {
        self.snapshot.client
    }
    pub fn payload(&self) -> &[u8] {
        &self.prepared.payload
    }

    /// Consumes the sole invocation owner. The caller authenticates the actual foreign route;
    /// this closure deliberately receives no manager reference or borrowed manager backend.
    pub fn invoke<F>(mut self, invoke: F) -> ExternalPnpReturn
    where
        F: FnOnce(DispatchContext<'_>, &IrpProjection) -> PnpBackendDispatch,
    {
        let context = DispatchContext::new(
            self.snapshot.projection.driver_id,
            self.snapshot.client,
            &mut self.prepared.payload,
        );
        let outcome = invoke(context, &self.snapshot.projection);
        ExternalPnpReturn {
            invocation: self,
            outcome,
        }
    }
}

impl<P> IoManager<P> {
    pub fn begin_prepared_external_pnp(
        &mut self,
        prepared: PreparedExternalPnpIrp,
    ) -> Result<ExternalPnpInvocation, PreparedExternalPnpRejection> {
        let result = (|| {
            if prepared.manager_identity == 0
                || prepared.manager_identity != self.ownership_identity()
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let irp = self
                .irp(prepared.irp_id)
                .ok_or(NtStatus::INVALID_PARAMETER)?;
            if irp.origin_major != nt_io_abi::major::IRP_MJ_PNP
                || irp.state != IrpState::Initialized
                || irp.file_id.is_some()
                || !irp.buffer.is_some_and(|buffer| {
                    irp.current_stack().is_some_and(|stack| {
                        stack.major == nt_io_abi::major::IRP_MJ_PNP
                            && match &stack.parameters {
                                IoParameters::Pnp(parameters) => {
                                    buffer.input_len == parameters.input_len()
                                        && buffer.output_len == parameters.output_len()
                                        && buffer.len as usize == prepared.payload.len()
                                }
                                _ => false,
                            }
                    })
                })
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let projection = IrpProjection::from_record(irp)?;
            let mut stack = Vec::new();
            stack
                .try_reserve_exact(irp.stack.len())
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            stack.extend(
                irp.stack
                    .iter()
                    .map(|entry| (entry.driver_id, entry.device_id)),
            );
            Ok(Snapshot {
                projection,
                client: irp.client_id,
                origin_driver: irp.origin_driver_id,
                origin_device: irp.origin_device_id,
                minor: irp.origin_minor,
                relation_type: irp.origin_pnp_relation_type,
                stack,
            })
        })();
        match result {
            Err(status) => Err(PreparedExternalPnpRejection { status, prepared }),
            Ok(snapshot) => {
                assert!(self
                    .irp_mut(prepared.irp_id)
                    .unwrap()
                    .transition(IrpState::Dispatched));
                Ok(ExternalPnpInvocation { prepared, snapshot })
            }
        }
    }

    pub fn finish_external_pnp(
        &mut self,
        returned: ExternalPnpReturn,
    ) -> Result<ExternalPnpFinishResult, ExternalPnpFinishRejection> {
        let valid = (|| {
            let invocation = &returned.invocation;
            let prepared = &invocation.prepared;
            let snapshot = &invocation.snapshot;
            if prepared.manager_identity == 0
                || prepared.manager_identity != self.ownership_identity()
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let irp = self
                .irp(prepared.irp_id)
                .ok_or(NtStatus::INVALID_PARAMETER)?;
            if irp.id != snapshot.projection.irp_id
                || irp.client_id != snapshot.client
                || matches!(irp.state, IrpState::Allocated | IrpState::Initialized)
                || irp.origin_driver_id != snapshot.origin_driver
                || irp.origin_device_id != snapshot.origin_device
                || irp.origin_major != nt_io_abi::major::IRP_MJ_PNP
                || irp.origin_minor != snapshot.minor
                || irp.origin_pnp_relation_type != snapshot.relation_type
                || irp.file_id.is_some()
                || irp.requestor_tid != snapshot.projection.requestor_tid
                || irp.user_data != snapshot.projection.user_data
                || irp.buffer != snapshot.projection.buffer
                || irp.stack.len() != snapshot.stack.len()
                || !irp
                    .stack
                    .iter()
                    .zip(&snapshot.stack)
                    .all(|(entry, pair)| (entry.driver_id, entry.device_id) == *pair)
                || !irp
                    .current_stack()
                    .is_some_and(|stack| stack.major == nt_io_abi::major::IRP_MJ_PNP)
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            Ok(())
        })();
        if let Err(status) = valid {
            return Err(ExternalPnpFinishRejection {
                status,
                owner: returned,
            });
        }
        let ExternalPnpReturn {
            invocation,
            outcome,
        } = returned;
        let ExternalPnpInvocation { prepared, snapshot } = invocation;
        let mut prepared = Some(prepared);
        let result = self.reconcile_external_pnp_retaining(&mut prepared, outcome);
        Ok(match prepared {
            None => ExternalPnpFinishResult::Terminal(result),
            Some(prepared) => ExternalPnpFinishResult::Retained(RetainedExternalPnp {
                owner: ExternalPnpReturn {
                    invocation: ExternalPnpInvocation { prepared, snapshot },
                    outcome,
                },
                outcome: result,
            }),
        })
    }
}
