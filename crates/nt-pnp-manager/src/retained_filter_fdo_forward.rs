//! Retained `FILTER_RESOURCE_REQUIREMENTS` forwarding from an upper filter FDO to the
//! immediately attached function FDO in another hosted domain.
//!
//! The native source IRP, its borrowed requirements pointer, and its completion routine stay in
//! the source domain. A separate canonical IRP enters the exact lower FDO. The native adapter
//! must pin the source graph and reserve the destination Reply/bank before calling `dispatch`.

use alloc::vec::Vec;

use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    CompletedIrp, CompletionAcknowledgement, DispatchContext, ExternalPnpDispatchResult,
    ExternalPnpFilterCompletionInvocation, ExternalPnpFilterCompletionReturn,
    ExternalPnpFilterOutput, ExternalPnpFinishResult, ExternalPnpInvocation, ExternalPnpReturn,
    ExternalPnpTerminalReceipt, HostedDevicePointerRegistration, IoManager, IrpId, IrpProjection,
    ObjectManagerPort, PnpBackendDispatch, PnpParameters, PreparedExternalPnpIrp,
    RetainedExternalPnp,
};
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::{filter_requirements_return_action, FilterRequirementsReturnAction, PnpManager};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterFdoForwardIdentity {
    pub source: SourceIrpTicket,
    pub source_irp: IrpId,
    pub upper: HostedDevicePointerRegistration,
    pub lower: HostedDevicePointerRegistration,
    pub devnode: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterFdoForwardError {
    WrongIdentity,
    WrongSource,
    WrongLower,
    SameDomain,
    Upper(NtStatus),
    Lower(NtStatus),
    Prepare(NtStatus),
    Dispatch(NtStatus),
    WrongTerminal,
    UnexpectedPayload,
    InvalidOutput,
    ProviderAckRequired,
    SourceCompletionRequired,
}

#[derive(Debug)]
struct Owner {
    identity: FilterFdoForwardIdentity,
    upper: HostedForwardTarget,
    lower: HostedForwardTarget,
    client: ClientId,
    requestor_tid: u64,
    /// Preserves source input bytes across a pending provider call. The native adapter must also
    /// retain the exact provider-domain allocation passed to a lower driver until its terminal.
    requirements: Vec<u8>,
    upper_released: bool,
    lower_released: bool,
}

impl Owner {
    fn validate<P>(
        &self,
        pnp: &PnpManager,
        io: &IoManager<P>,
        observed: FilterFdoForwardIdentity,
    ) -> Result<(), FilterFdoForwardError> {
        if observed != self.identity {
            return Err(FilterFdoForwardError::WrongIdentity);
        }
        self.upper
            .validate(io)
            .map_err(FilterFdoForwardError::Upper)?;
        self.lower
            .validate(io)
            .map_err(FilterFdoForwardError::Lower)?;
        validate_path(pnp, io, self.identity, self.client, self.requestor_tid)
    }

    fn release<P>(&mut self, io: &mut IoManager<P>) -> Result<(), FilterFdoForwardError> {
        if !self.upper_released {
            self.upper
                .release(io)
                .map_err(FilterFdoForwardError::Upper)?;
            self.upper_released = true;
        }
        if !self.lower_released {
            self.lower
                .release(io)
                .map_err(FilterFdoForwardError::Lower)?;
            self.lower_released = true;
        }
        Ok(())
    }
}

/// Prove that the captured source frame points at an actual immediate lower function FDO.
/// Numeric native pointers alone never establish this relationship.
fn validate_path<P>(
    pnp: &PnpManager,
    io: &IoManager<P>,
    identity: FilterFdoForwardIdentity,
    client: ClientId,
    requestor_tid: u64,
) -> Result<(), FilterFdoForwardError> {
    if identity.source.domain != identity.upper.domain()
        || identity.upper.domain() == identity.lower.domain()
        || identity.upper.device_id() == identity.lower.device_id()
    {
        return Err(FilterFdoForwardError::SameDomain);
    }
    let source = io
        .irp(identity.source_irp)
        .ok_or(FilterFdoForwardError::WrongSource)?;
    let upper = source
        .current_stack()
        .ok_or(FilterFdoForwardError::WrongSource)?;
    let lower = source
        .stack
        .get(usize::from(source.current_location) + 1)
        .ok_or(FilterFdoForwardError::WrongLower)?;
    if source.origin_major != nt_pnp_abi::IRP_MJ_PNP
        || source.origin_minor != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS
        || source.client_id != client
        || source.requestor_tid != requestor_tid
        || upper.major != nt_pnp_abi::IRP_MJ_PNP
        || upper.minor != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS
        || lower.major != nt_pnp_abi::IRP_MJ_PNP
        || lower.minor != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS
        || upper.device_id != identity.upper.device_id()
        || lower.device_id != identity.lower.device_id()
        || upper.file_id.is_some()
        || lower.file_id.is_some()
    {
        return Err(FilterFdoForwardError::WrongSource);
    }
    if io
        .device(upper.device_id)
        .and_then(|device| device.attached_to)
        != Some(lower.device_id)
        || pnp.fdo(identity.devnode) != Some(lower.device_id.raw())
    {
        return Err(FilterFdoForwardError::WrongLower);
    }
    Ok(())
}

#[derive(Debug)]
#[must_use = "dispatch or discard through the issuing I/O manager"]
pub struct PreparedFilterFdoForward {
    owner: Owner,
    provider_irp: PreparedExternalPnpIrp,
}

#[derive(Debug)]
#[must_use = "invoke exactly once outside the I/O manager borrow"]
pub struct FilterFdoInvocation {
    owner: Owner,
    invocation: ExternalPnpInvocation,
}

#[derive(Debug)]
#[must_use = "reconcile through the issuing I/O manager; never invoke again"]
pub struct FilterFdoReturn {
    owner: Owner,
    returned: ExternalPnpReturn,
    output: ExternalPnpFilterOutput,
}

#[derive(Debug)]
#[must_use = "retain a rejected return and its native-effect ownership"]
pub struct FilterFdoFinishRejection {
    error: FilterFdoForwardError,
    returned: FilterFdoReturn,
}

impl FilterFdoFinishRejection {
    pub const fn error(&self) -> FilterFdoForwardError {
        self.error
    }
    pub fn into_return(self) -> FilterFdoReturn {
        self.returned
    }
}

#[derive(Debug)]
#[must_use = "retain until exact projection references are released"]
pub struct DiscardedFilterFdoForward {
    owner: Owner,
}

#[derive(Debug)]
#[must_use = "retain entered provider effects, including uncertain outcomes"]
pub struct RetainedFilterFdoForward {
    owner: Owner,
    provider_irp: IrpId,
    indeterminate: bool,
    detached: Option<RetainedExternalPnp>,
    rejected_terminal: Option<ExternalPnpTerminalReceipt>,
}

#[derive(Debug)]
#[must_use = "complete the source and acknowledge the provider before retiring"]
pub struct TerminalFilterFdoForward {
    owner: Owner,
    receipt: ExternalPnpTerminalReceipt,
    provider_acknowledged: bool,
    source_completed: bool,
    output: ExternalPnpFilterOutput,
}

#[derive(Debug)]
#[must_use = "invoke exact provider ACK and retain its result"]
pub struct FilterFdoCompletionInvocation {
    owner: Owner,
    provider_irp: IrpId,
    invocation: ExternalPnpFilterCompletionInvocation,
}

#[derive(Debug)]
#[must_use = "settle exact provider ACK through the issuing I/O manager"]
pub struct FilterFdoCompletionReturn {
    owner: Owner,
    provider_irp: IrpId,
    returned: ExternalPnpFilterCompletionReturn,
}

#[derive(Debug)]
pub enum FilterFdoForwardResult {
    Retained(RetainedFilterFdoForward),
    Terminal(TerminalFilterFdoForward),
    Rejected {
        error: FilterFdoForwardError,
        retained: RetainedFilterFdoForward,
    },
}

#[derive(Debug)]
pub enum FilterFdoDiscardResult {
    Retired,
    NotDiscarded {
        error: FilterFdoForwardError,
        prepared: PreparedFilterFdoForward,
    },
    Retained {
        error: FilterFdoForwardError,
        discarded: DiscardedFilterFdoForward,
    },
}

impl PreparedFilterFdoForward {
    /// `requirements` is a complete source-owned copy of the native requirements list.
    /// The adapter must verify its extent and source graph before handing it over.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare<P>(
        pnp: &PnpManager,
        io: &mut IoManager<P>,
        source: SourceIrpTicket,
        source_irp: IrpId,
        upper_address: u64,
        lower: HostedDevicePointerRegistration,
        devnode: u64,
        client: ClientId,
        requestor_tid: u64,
        requirements: Vec<u8>,
    ) -> Result<Self, FilterFdoForwardError> {
        if nt_cm_resources::validate_io_resource_requirements_list_extent(&requirements)
            != Ok(requirements.len())
        {
            return Err(FilterFdoForwardError::Prepare(NtStatus::INVALID_PARAMETER));
        }
        let mut upper = HostedForwardTarget::capture(io, source.domain, upper_address)
            .map_err(FilterFdoForwardError::Upper)?;
        let mut lower_owner =
            match HostedForwardTarget::capture(io, lower.domain(), lower.address()) {
                Ok(owner) => owner,
                Err(status) => {
                    upper.release(io).map_err(FilterFdoForwardError::Upper)?;
                    return Err(FilterFdoForwardError::Lower(status));
                }
            };
        let identity = FilterFdoForwardIdentity {
            source,
            source_irp,
            upper: upper.registration(),
            lower,
            devnode,
        };
        let admission = if lower_owner.registration() != lower {
            Err(FilterFdoForwardError::WrongLower)
        } else {
            validate_path(pnp, io, identity, client, requestor_tid)
        };
        if let Err(error) = admission {
            lower_owner
                .release(io)
                .map_err(FilterFdoForwardError::Lower)?;
            upper.release(io).map_err(FilterFdoForwardError::Upper)?;
            return Err(error);
        }
        let parameters = match u32::try_from(requirements.len())
            .map_err(|_| NtStatus::INVALID_PARAMETER)
            .and_then(PnpParameters::filter_resource_requirements)
        {
            Ok(parameters) => parameters,
            Err(status) => {
                lower_owner
                    .release(io)
                    .map_err(FilterFdoForwardError::Lower)?;
                upper.release(io).map_err(FilterFdoForwardError::Upper)?;
                return Err(FilterFdoForwardError::Prepare(status));
            }
        };
        let provider_irp = match io.prepare_external_pnp_to_exact_device(
            client,
            lower.device_id(),
            requestor_tid,
            parameters,
            &requirements,
        ) {
            Ok(prepared) => prepared,
            Err(status) => {
                lower_owner
                    .release(io)
                    .map_err(FilterFdoForwardError::Lower)?;
                upper.release(io).map_err(FilterFdoForwardError::Upper)?;
                return Err(FilterFdoForwardError::Prepare(status));
            }
        };
        Ok(Self {
            owner: Owner {
                identity,
                upper,
                lower: lower_owner,
                client,
                requestor_tid,
                requirements,
                upper_released: false,
                lower_released: false,
            },
            provider_irp,
        })
    }

    pub const fn identity(&self) -> FilterFdoForwardIdentity {
        self.owner.identity
    }
    pub fn provider_irp(&self) -> IrpId {
        self.provider_irp.irp_id()
    }

    pub fn begin<P>(
        self,
        pnp: &PnpManager,
        io: &mut IoManager<P>,
        observed: FilterFdoForwardIdentity,
    ) -> Result<FilterFdoInvocation, (FilterFdoForwardError, Self)> {
        if let Err(error) = self.owner.validate(pnp, io, observed) {
            return Err((error, self));
        }
        let Self {
            owner,
            provider_irp,
        } = self;
        match io.begin_prepared_external_pnp(provider_irp) {
            Ok(invocation) => Ok(FilterFdoInvocation { owner, invocation }),
            Err(rejection) => Err((
                FilterFdoForwardError::Dispatch(rejection.status()),
                Self {
                    owner,
                    provider_irp: rejection.into_prepared(),
                },
            )),
        }
    }

    pub fn discard<P>(self, io: &mut IoManager<P>) -> FilterFdoDiscardResult {
        let Self {
            mut owner,
            provider_irp,
        } = self;
        if let Err(rejection) = io.discard_prepared_external_pnp(provider_irp) {
            return FilterFdoDiscardResult::NotDiscarded {
                error: FilterFdoForwardError::Dispatch(rejection.status()),
                prepared: Self {
                    owner,
                    provider_irp: rejection.into_prepared(),
                },
            };
        }
        match owner.release(io) {
            Ok(()) => FilterFdoDiscardResult::Retired,
            Err(error) => FilterFdoDiscardResult::Retained {
                error,
                discarded: DiscardedFilterFdoForward { owner },
            },
        }
    }
}

impl FilterFdoInvocation {
    pub const fn identity(&self) -> FilterFdoForwardIdentity {
        self.owner.identity
    }
    pub fn provider_irp(&self) -> IrpId {
        self.invocation.irp_id()
    }
    pub fn projection(&self) -> &IrpProjection {
        self.invocation.projection()
    }
    /// The native adapter captures any synchronous provider output before returning from the
    /// foreign call. Pending results use `Original` here and capture at terminal completion.
    pub fn invoke_with_output<F>(self, invoke: F) -> FilterFdoReturn
    where
        F: FnOnce(
            DispatchContext<'_>,
            &IrpProjection,
        ) -> (PnpBackendDispatch, ExternalPnpFilterOutput),
    {
        let Self { owner, invocation } = self;
        let mut output = None;
        let returned = invocation.invoke(|context, projection| {
            let (outcome, copied) = invoke(context, projection);
            output = Some(copied);
            outcome
        });
        FilterFdoReturn {
            owner,
            returned,
            output: output.expect("PnP invocation ran exactly once"),
        }
    }
}

impl FilterFdoReturn {
    pub const fn identity(&self) -> FilterFdoForwardIdentity {
        self.owner.identity
    }
    pub fn provider_irp(&self) -> IrpId {
        self.returned.irp_id()
    }
    /// Replace a rejected capture while retaining the already entered provider return.
    /// This never invokes the provider a second time.
    pub fn with_output(mut self, output: ExternalPnpFilterOutput) -> Self {
        self.output = output;
        self
    }
    pub fn finish<P>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<FilterFdoForwardResult, FilterFdoFinishRejection> {
        if let PnpBackendDispatch::Returned {
            status,
            information,
        } = self.returned.outcome()
        {
            if !valid_output(*status, *information, &self.output) {
                return Err(FilterFdoFinishRejection {
                    error: FilterFdoForwardError::InvalidOutput,
                    returned: self,
                });
            }
        }
        let Self {
            owner,
            returned,
            output,
        } = self;
        let expected = returned.irp_id();
        let finished = match io.finish_external_pnp(returned) {
            Ok(finished) => finished,
            Err(rejection) => {
                return Err(FilterFdoFinishRejection {
                    error: FilterFdoForwardError::Dispatch(rejection.status()),
                    returned: Self {
                        owner,
                        returned: rejection.into_owner(),
                        output,
                    },
                })
            }
        };
        Ok(match finished {
            ExternalPnpFinishResult::Terminal(outcome) => match outcome {
                ExternalPnpDispatchResult::Returned {
                    status,
                    information,
                    receipt,
                } => finish_terminal(owner, expected, status, information, receipt, false, output),
                ExternalPnpDispatchResult::ReturnedPayload { receipt, .. } => {
                    FilterFdoForwardResult::Rejected {
                        error: FilterFdoForwardError::UnexpectedPayload,
                        retained: RetainedFilterFdoForward {
                            owner,
                            provider_irp: expected,
                            indeterminate: true,
                            detached: None,
                            rejected_terminal: Some(receipt),
                        },
                    }
                }
                _ => unreachable!("terminal detached PnP returned nonterminal"),
            },
            ExternalPnpFinishResult::Retained(detached) => {
                let indeterminate = matches!(
                    detached.outcome(),
                    ExternalPnpDispatchResult::Indeterminate { .. }
                );
                FilterFdoForwardResult::Retained(RetainedFilterFdoForward {
                    owner,
                    provider_irp: expected,
                    indeterminate,
                    detached: Some(detached),
                    rejected_terminal: None,
                })
            }
        })
    }
}

impl DiscardedFilterFdoForward {
    pub fn retire<P>(mut self, io: &mut IoManager<P>) -> Result<(), (FilterFdoForwardError, Self)> {
        match self.owner.release(io) {
            Ok(()) => Ok(()),
            Err(error) => Err((error, self)),
        }
    }
}

fn finish_terminal(
    owner: Owner,
    expected: IrpId,
    status: NtStatus,
    information: u64,
    receipt: ExternalPnpTerminalReceipt,
    expected_pending: bool,
    output: ExternalPnpFilterOutput,
) -> FilterFdoForwardResult {
    if receipt.irp_id() != expected
        || receipt.origin_device_id() != owner.identity.lower.device_id()
        || receipt.minor() != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS
        || receipt.relation_type().is_some()
        || receipt.driver_pending() != expected_pending
        || receipt.status() != status
        || receipt.information() != information
        || receipt.status() == NtStatus::PENDING
    {
        return FilterFdoForwardResult::Rejected {
            error: FilterFdoForwardError::WrongTerminal,
            retained: RetainedFilterFdoForward {
                owner,
                provider_irp: expected,
                indeterminate: true,
                detached: None,
                rejected_terminal: Some(receipt),
            },
        };
    }
    if !valid_output(status, information, &output) {
        return FilterFdoForwardResult::Rejected {
            error: FilterFdoForwardError::InvalidOutput,
            retained: RetainedFilterFdoForward {
                owner,
                provider_irp: expected,
                indeterminate: true,
                detached: None,
                rejected_terminal: Some(receipt),
            },
        };
    }
    FilterFdoForwardResult::Terminal(TerminalFilterFdoForward {
        owner,
        receipt,
        provider_acknowledged: !expected_pending,
        source_completed: false,
        output,
    })
}

fn valid_output(status: NtStatus, information: u64, output: &ExternalPnpFilterOutput) -> bool {
    match filter_requirements_return_action(status, information) {
        FilterRequirementsReturnAction::UseOriginal
        | FilterRequirementsReturnAction::Barrier(_) => {
            matches!(output, ExternalPnpFilterOutput::Original)
        }
        FilterRequirementsReturnAction::CopyProviderOutput { information } => match output {
            ExternalPnpFilterOutput::BorrowedInput { provider_pointer } => {
                *provider_pointer != 0 && *provider_pointer == information
            }
            ExternalPnpFilterOutput::Copied {
                provider_pointer,
                bytes,
            } => {
                *provider_pointer == information
                    && nt_cm_resources::validate_io_resource_requirements_list_extent(bytes)
                        == Ok(bytes.len())
            }
            ExternalPnpFilterOutput::Original => false,
        },
    }
}

impl RetainedFilterFdoForward {
    pub const fn identity(&self) -> FilterFdoForwardIdentity {
        self.owner.identity
    }
    pub const fn provider_irp(&self) -> IrpId {
        self.provider_irp
    }
    pub const fn is_indeterminate(&self) -> bool {
        self.indeterminate
    }
    pub const fn has_rejected_terminal(&self) -> bool {
        self.rejected_terminal.is_some()
    }
    pub fn prepare_completion<P: ObjectManagerPort>(
        mut self,
        pnp: &PnpManager,
        io: &mut IoManager<P>,
        observed: FilterFdoForwardIdentity,
        output: ExternalPnpFilterOutput,
    ) -> Result<FilterFdoCompletionInvocation, (FilterFdoForwardError, Self, ExternalPnpFilterOutput)>
    {
        if let Err(error) = self.owner.validate(pnp, io, observed) {
            return Err((error, self, output));
        }
        if self.rejected_terminal.is_some() {
            return Err((FilterFdoForwardError::WrongTerminal, self, output));
        }
        let Some(detached) = self.detached.take() else {
            return Err((FilterFdoForwardError::WrongTerminal, self, output));
        };
        if let Some(completion) = io.completed_irp(self.provider_irp) {
            if !valid_output(completion.status, completion.information, &output) {
                self.detached = Some(detached);
                return Err((FilterFdoForwardError::InvalidOutput, self, output));
            }
        }
        match io.prepare_external_pnp_filter_completion(detached, output) {
            Ok(invocation) => Ok(FilterFdoCompletionInvocation {
                owner: self.owner,
                provider_irp: self.provider_irp,
                invocation,
            }),
            Err((rejection, output)) => {
                let error = FilterFdoForwardError::Lower(rejection.status());
                self.detached = Some(rejection.into_owner());
                Err((error, self, output))
            }
        }
    }
}

impl FilterFdoCompletionInvocation {
    pub fn completion(&self) -> &CompletedIrp {
        self.invocation.completion()
    }
    pub fn backend_index(&self) -> usize {
        self.invocation.backend_index()
    }
    pub fn invoke<F>(self, invoke: F) -> FilterFdoCompletionReturn
    where
        F: FnOnce(&CompletedIrp) -> CompletionAcknowledgement,
    {
        let Self {
            owner,
            provider_irp,
            invocation,
        } = self;
        FilterFdoCompletionReturn {
            owner,
            provider_irp,
            returned: invocation.invoke(invoke),
        }
    }
}

impl FilterFdoCompletionReturn {
    pub fn finish<P: ObjectManagerPort>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<FilterFdoForwardResult, (FilterFdoForwardError, Self)> {
        let Self {
            owner,
            provider_irp,
            returned,
        } = self;
        let (receipt, _input, output) = match io.finish_external_pnp_filter_completion(returned) {
            Ok(result) => result,
            Err(rejection) => {
                return Err((
                    FilterFdoForwardError::Lower(rejection.status()),
                    Self {
                        owner,
                        provider_irp,
                        returned: rejection.into_owner(),
                    },
                ))
            }
        };
        let status = receipt.status();
        let information = receipt.information();
        let mut result = finish_terminal(
            owner,
            provider_irp,
            status,
            information,
            receipt,
            true,
            output,
        );
        if let FilterFdoForwardResult::Terminal(terminal) = &mut result {
            terminal.provider_acknowledged = true;
        }
        Ok(result)
    }
    pub fn retry<P: ObjectManagerPort>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<FilterFdoCompletionInvocation, (FilterFdoForwardError, Self)> {
        let Self {
            owner,
            provider_irp,
            returned,
        } = self;
        match io.retry_external_pnp_filter_completion(returned) {
            Ok(invocation) => Ok(FilterFdoCompletionInvocation {
                owner,
                provider_irp,
                invocation,
            }),
            Err(rejection) => Err((
                FilterFdoForwardError::Lower(rejection.status()),
                Self {
                    owner,
                    provider_irp,
                    returned: rejection.into_owner(),
                },
            )),
        }
    }
}

impl TerminalFilterFdoForward {
    pub const fn identity(&self) -> FilterFdoForwardIdentity {
        self.owner.identity
    }
    pub const fn status(&self) -> NtStatus {
        self.receipt.status()
    }
    pub const fn information(&self) -> u64 {
        self.receipt.information()
    }
    pub const fn provider_irp(&self) -> IrpId {
        self.receipt.irp_id()
    }
    pub fn captured_output(&self) -> &ExternalPnpFilterOutput {
        &self.output
    }
    pub fn original_requirements(&self) -> &[u8] {
        &self.owner.requirements
    }
    pub fn return_action(&self) -> FilterRequirementsReturnAction {
        if matches!(self.output, ExternalPnpFilterOutput::BorrowedInput { .. }) {
            FilterRequirementsReturnAction::UseOriginal
        } else {
            filter_requirements_return_action(self.receipt.status(), self.receipt.information())
        }
    }

    /// The adapter calls this only after source-domain completion ran and any provider output was
    /// copied into a source-owned allocation. A Reply acknowledgement alone is insufficient.
    pub fn mark_source_completed(
        &mut self,
        observed: FilterFdoForwardIdentity,
    ) -> Result<(), FilterFdoForwardError> {
        if observed != self.owner.identity {
            return Err(FilterFdoForwardError::WrongIdentity);
        }
        self.source_completed = true;
        Ok(())
    }

    pub fn retire<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<NtStatus, (FilterFdoForwardError, Self)> {
        if !self.source_completed {
            return Err((FilterFdoForwardError::SourceCompletionRequired, self));
        }
        if !self.provider_acknowledged {
            return Err((FilterFdoForwardError::ProviderAckRequired, self));
        }
        if let Err(error) = self.owner.release(io) {
            return Err((error, self));
        }
        Ok(self.receipt.status())
    }

    /// A stopped source cannot run its local completion routine. The native teardown path must
    /// retire its exact source pin before using this terminal-only escape hatch.
    pub fn retire_after_source_stop<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<NtStatus, (FilterFdoForwardError, Self)> {
        if !self.provider_acknowledged {
            return Err((FilterFdoForwardError::ProviderAckRequired, self));
        }
        if let Err(error) = self.owner.release(io) {
            return Err((error, self));
        }
        Ok(self.receipt.status())
    }
}

#[cfg(test)]
#[path = "retained_filter_fdo_forward_tests.rs"]
mod tests;
