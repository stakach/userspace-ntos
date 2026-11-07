//! Detached PnP completion ACK across foreign execution. START/lifecycle use a status-only
//! contract; FILTER requires exact provider-pointer output capture before ACK. Other pointer or
//! query results still require their own checked output/adoption contract.
use super::*;
use crate::completion_ack::{CompletionAckReservation, CompletionAcknowledgement};
use crate::source_irp_auxiliary::SourcePoolAllocationIdentity;
use crate::CompletedIrp;

/// A FILTER result copied before the provider's pending IRP is acknowledged. `Original` never
/// interprets a borrowed `IoStatus.Information` pointer as transferred ownership.
#[derive(Debug, Eq, PartialEq)]
pub enum ExternalPnpFilterOutput {
    Original,
    /// The provider returned the exact pointer to its retained input allocation.
    /// Native adapters must prove this pointer against that allocation's generation.
    BorrowedInput {
        provider_pointer: u64,
        input_allocation: SourcePoolAllocationIdentity,
    },
    Copied {
        provider_pointer: u64,
        bytes: Vec<u8>,
    },
}

impl ExternalPnpFilterOutput {
    fn matches(
        &self,
        completion: &CompletedIrp,
        retained_input: Option<SourcePoolAllocationIdentity>,
    ) -> bool {
        if completion.status == NtStatus::NOT_SUPPORTED
            || !completion.status.is_success()
            || completion.information == 0
        {
            matches!(self, Self::Original)
        } else {
            match self {
                Self::BorrowedInput {
                    provider_pointer,
                    input_allocation,
                } => retained_input == Some(*input_allocation)
                    && *provider_pointer == input_allocation.component_address
                    && *provider_pointer == completion.information,
                Self::Copied {
                    provider_pointer,
                    bytes,
                } => {
                    *provider_pointer == completion.information
                        && nt_cm_resources::validate_io_resource_requirements_list_extent(bytes)
                            == Ok(bytes.len())
                }
                Self::Original => false,
            }
        }
    }
}

#[derive(Debug)]
#[must_use = "invoke ACK only after the FILTER output is copied"]
pub struct ExternalPnpFilterCompletionInvocation {
    inner: ExternalPnpCompletionInvocation,
    output: ExternalPnpFilterOutput,
}

#[derive(Debug)]
#[must_use = "retain exact ACK result and copied output until local settlement"]
pub struct ExternalPnpFilterCompletionReturn {
    inner: ExternalPnpCompletionReturn,
    output: ExternalPnpFilterOutput,
}

impl ExternalPnpFilterCompletionInvocation {
    pub fn completion(&self) -> &CompletedIrp {
        self.inner.completion()
    }
    pub fn backend_index(&self) -> usize {
        self.inner.backend_index()
    }
    pub fn output(&self) -> &ExternalPnpFilterOutput {
        &self.output
    }
    pub fn invoke<F>(self, invoke: F) -> ExternalPnpFilterCompletionReturn
    where
        F: FnOnce(&CompletedIrp) -> CompletionAcknowledgement,
    {
        ExternalPnpFilterCompletionReturn {
            inner: self.inner.invoke(invoke),
            output: self.output,
        }
    }
}

impl ExternalPnpFilterCompletionReturn {
    pub fn output(&self) -> &ExternalPnpFilterOutput {
        &self.output
    }
    pub fn acknowledgement(&self) -> CompletionAcknowledgement {
        self.inner.acknowledgement()
    }
}

#[derive(Debug)]
#[must_use = "retain the rejected completion owner"]
pub struct ExternalPnpCompletionRejection<T> {
    status: NtStatus,
    owner: T,
}

impl<T> ExternalPnpCompletionRejection<T> {
    pub fn status(&self) -> NtStatus {
        self.status
    }
    pub fn owner(&self) -> &T {
        &self.owner
    }
    pub fn into_owner(self) -> T {
        self.owner
    }
}

#[derive(Debug)]
#[must_use = "invoke ACK once, or retain the reserved completion"]
pub struct ExternalPnpCompletionInvocation {
    owner: RetainedExternalPnp,
    completion: CompletedIrp,
    reservation: CompletionAckReservation,
    backend_index: usize,
}

impl ExternalPnpCompletionInvocation {
    pub fn completion(&self) -> &CompletedIrp {
        &self.completion
    }
    pub fn payload(&self) -> &[u8] {
        self.owner.payload()
    }
    /// Route observation only. Native adapters must authenticate the actual provider instance.
    pub fn backend_index(&self) -> usize {
        self.backend_index
    }
    pub fn invoke<F>(self, invoke: F) -> ExternalPnpCompletionReturn
    where
        F: FnOnce(&CompletedIrp) -> CompletionAcknowledgement,
    {
        let acknowledgement = invoke(&self.completion);
        ExternalPnpCompletionReturn {
            invocation: self,
            acknowledgement,
        }
    }
}

#[derive(Debug)]
#[must_use = "retain the ACK result until exact local retirement succeeds"]
pub struct ExternalPnpCompletionReturn {
    invocation: ExternalPnpCompletionInvocation,
    acknowledgement: CompletionAcknowledgement,
}

impl ExternalPnpCompletionReturn {
    pub fn payload(&self) -> &[u8] {
        self.invocation.payload()
    }
    pub fn acknowledgement(&self) -> CompletionAcknowledgement {
        self.acknowledgement
    }
    /// Only checked no-effect refusal permits another foreign ACK. Accepted and uncertain
    /// operations retain the exact response for local settlement, never another invocation.
    pub(crate) fn retry(self) -> Result<ExternalPnpCompletionInvocation, Self> {
        if matches!(
            self.acknowledgement,
            CompletionAcknowledgement::NotEntered { .. }
        ) {
            Ok(self.invocation)
        } else {
            Err(self)
        }
    }
}

impl<P: ObjectManagerPort> IoManager<P> {
    fn validate_external_pnp_completion_return(
        &self,
        returned: &ExternalPnpCompletionReturn,
    ) -> Result<(), NtStatus> {
        let invocation = &returned.invocation;
        self.validate_external_pnp_invocation(&invocation.owner.owner.invocation)?;
        let completion = &invocation.completion;
        let irp = self.irp(completion.id).ok_or(NtStatus::INVALID_PARAMETER)?;
        if irp.completion_ack_reservation != Some(invocation.reservation)
            || !irp.current_stack().is_some_and(|stack| {
                stack.major == nt_io_abi::major::IRP_MJ_PNP
                    && stack.minor == invocation.owner.owner.invocation.snapshot.minor
                    && stack.parameters
                        == invocation.owner.owner.invocation.snapshot.projection.parameters
            })
            || !invocation
                .reservation
                .matches(self.ownership_identity(), completion.id)
            || self.completed_irp_snapshot(completion.id).as_ref() != Some(completion)
            || !self.completed_irps.contains(&completion.id)
            || self
                .driver(completion.completion_driver_id)
                .map(|driver| driver.backend.0 as usize)
                != Some(invocation.backend_index)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(())
    }

    pub fn prepare_external_pnp_completion(
        &mut self,
        retained: RetainedExternalPnp,
    ) -> Result<ExternalPnpCompletionInvocation, ExternalPnpCompletionRejection<RetainedExternalPnp>>
    {
        self.prepare_external_pnp_completion_inner(retained, None)
    }

    pub fn prepare_external_pnp_filter_completion(
        &mut self,
        retained: RetainedExternalPnp,
        output: ExternalPnpFilterOutput,
    ) -> Result<
        ExternalPnpFilterCompletionInvocation,
        (
            ExternalPnpCompletionRejection<RetainedExternalPnp>,
            ExternalPnpFilterOutput,
        ),
    > {
        match self.prepare_external_pnp_completion_inner(retained, Some(&output)) {
            Ok(inner) => Ok(ExternalPnpFilterCompletionInvocation { inner, output }),
            Err(rejection) => Err((rejection, output)),
        }
    }

    fn prepare_external_pnp_completion_inner(
        &mut self,
        retained: RetainedExternalPnp,
        filter_output: Option<&ExternalPnpFilterOutput>,
    ) -> Result<ExternalPnpCompletionInvocation, ExternalPnpCompletionRejection<RetainedExternalPnp>>
    {
        let valid = (|| {
            self.validate_external_pnp_invocation(&retained.owner.invocation)?;
            if !matches!(&retained.owner.invocation.snapshot.projection.parameters,
            IoParameters::Pnp(parameters) if match filter_output {
                Some(_) => parameters.minor == nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
                None => parameters.has_status_only_result(),
            }) {
                return Err(NtStatus::NOT_SUPPORTED);
            }
            let id = retained.irp_id();
            let completion = self.completed_irp_snapshot(id).ok_or(NtStatus::PENDING)?;
            // This owner only carries a status result. A nonzero Information value could be a
            // provider-owned output pointer and must be adopted by a different contract.
            let scalar_device_state = retained.owner.invocation.snapshot.minor
                == nt_pnp_abi::IRP_MN_QUERY_PNP_DEVICE_STATE
                && completion.status.is_success()
                && completion.information & !(nt_pnp_abi::PNP_DEVICE_STATE_KNOWN_MASK as u64) == 0;
            if filter_output.is_none() && completion.information != 0 && !scalar_device_state {
                return Err(NtStatus::NOT_SUPPORTED);
            }
            if filter_output.is_some_and(|output| {
                !output.matches(&completion, retained.filter_input_allocation)
            }) {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let irp = self.irp(id).ok_or(NtStatus::INVALID_PARAMETER)?;
            if !irp.current_stack().is_some_and(|stack| {
                matches!(&stack.parameters, IoParameters::Pnp(parameters)
                    if stack.minor == parameters.minor
                        && stack.minor == retained.owner.invocation.snapshot.minor
                        && stack.parameters
                            == retained.owner.invocation.snapshot.projection.parameters
                        && match filter_output {
                            Some(_) => parameters.minor == nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
                            None => parameters.has_status_only_result(),
                        })
            }) {
                return Err(NtStatus::NOT_SUPPORTED);
            }
            if !self.completed_irps.contains(&id)
                || irp.completion_ack_reservation.is_some()
                || irp.detached_file_owner
                || irp.external_pnp_terminal_receipt_claimed
                || completion.completion_origin != IrpCompletionOrigin::Driver
                || completion.major != nt_io_abi::major::IRP_MJ_PNP
                || completion.status == NtStatus::PENDING
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let backend_index = self
                .driver(completion.completion_driver_id)
                .map(|driver| driver.backend.0 as usize)
                .filter(|index| *index < self.backends.len())
                .ok_or(NtStatus::INVALID_PARAMETER)?;
            if self.backends[backend_index].is_faulted() {
                return Err(NtStatus::DEVICE_NOT_CONNECTED);
            }
            let reservation = CompletionAckReservation::new(self.ownership_identity(), id)?;
            Ok((completion, reservation, backend_index))
        })();
        match valid {
            Err(status) => Err(ExternalPnpCompletionRejection {
                status,
                owner: retained,
            }),
            Ok((completion, reservation, backend_index)) => {
                self.irps
                    .get_mut(completion.id)
                    .unwrap()
                    .completion_ack_reservation = Some(reservation);
                Ok(ExternalPnpCompletionInvocation {
                    owner: retained,
                    completion,
                    reservation,
                    backend_index,
                })
            }
        }
    }

    pub fn finish_external_pnp_completion(
        &mut self,
        returned: ExternalPnpCompletionReturn,
    ) -> Result<
        (ExternalPnpTerminalReceipt, Vec<u8>),
        ExternalPnpCompletionRejection<ExternalPnpCompletionReturn>,
    > {
        let valid = self
            .validate_external_pnp_completion_return(&returned)
            .and_then(|_| returned.acknowledgement.checked_status());
        if let Err(status) = valid {
            return Err(ExternalPnpCompletionRejection {
                status,
                owner: returned,
            });
        }
        let invocation = &returned.invocation;
        if let Err(status) = self
            .retire_acknowledged_completion(&invocation.completion, Some(invocation.reservation))
        {
            return Err(ExternalPnpCompletionRejection {
                status,
                owner: returned,
            });
        }
        let completion = returned.invocation.completion;
        let retained = returned.invocation.owner;
        let relation_type = retained.owner.invocation.snapshot.relation_type;
        let payload = retained.owner.invocation.prepared.payload;
        Ok((
            ExternalPnpTerminalReceipt {
                irp_id: completion.id,
                origin_driver_id: completion.driver_id,
                origin_device_id: completion.device_id,
                completion_driver_id: completion.completion_driver_id,
                completion_device_id: completion.completion_device_id,
                minor: completion.minor,
                relation_type,
                status: completion.status,
                information: completion.information,
                driver_pending: true,
            },
            payload,
        ))
    }

    /// Re-enter a foreign ACK only after a proven no-entry response and exact local reservation
    /// revalidation. Accepted or uncertain replies retain their original return for settlement.
    pub fn retry_external_pnp_completion(
        &mut self,
        returned: ExternalPnpCompletionReturn,
    ) -> Result<
        ExternalPnpCompletionInvocation,
        ExternalPnpCompletionRejection<ExternalPnpCompletionReturn>,
    > {
        let valid = if matches!(
            returned.acknowledgement,
            CompletionAcknowledgement::NotEntered { .. }
        ) {
            self.validate_external_pnp_completion_return(&returned)
                .and_then(|_| {
                    self.backends
                        .get(returned.invocation.backend_index)
                        .filter(|backend| !backend.is_faulted())
                        .map(|_| ())
                        .ok_or(NtStatus::DEVICE_NOT_CONNECTED)
                })
        } else {
            Err(NtStatus::INVALID_DEVICE_REQUEST)
        };
        if let Err(status) = valid {
            return Err(ExternalPnpCompletionRejection {
                status,
                owner: returned,
            });
        }
        Ok(returned
            .retry()
            .expect("validated no-entry ACK must permit retry"))
    }

    pub fn finish_external_pnp_filter_completion(
        &mut self,
        returned: ExternalPnpFilterCompletionReturn,
    ) -> Result<
        (ExternalPnpTerminalReceipt, Vec<u8>, ExternalPnpFilterOutput),
        ExternalPnpCompletionRejection<ExternalPnpFilterCompletionReturn>,
    > {
        let ExternalPnpFilterCompletionReturn { inner, output } = returned;
        match self.finish_external_pnp_completion(inner) {
            Ok((receipt, input)) => Ok((receipt, input, output)),
            Err(rejection) => {
                let status = rejection.status();
                Err(ExternalPnpCompletionRejection {
                    status,
                    owner: ExternalPnpFilterCompletionReturn {
                        inner: rejection.into_owner(),
                        output,
                    },
                })
            }
        }
    }

    pub fn retry_external_pnp_filter_completion(
        &mut self,
        returned: ExternalPnpFilterCompletionReturn,
    ) -> Result<
        ExternalPnpFilterCompletionInvocation,
        ExternalPnpCompletionRejection<ExternalPnpFilterCompletionReturn>,
    > {
        let ExternalPnpFilterCompletionReturn { inner, output } = returned;
        match self.retry_external_pnp_completion(inner) {
            Ok(inner) => Ok(ExternalPnpFilterCompletionInvocation { inner, output }),
            Err(rejection) => Err(ExternalPnpCompletionRejection {
                status: rejection.status(),
                owner: ExternalPnpFilterCompletionReturn {
                    inner: rejection.into_owner(),
                    output,
                },
            }),
        }
    }
}
