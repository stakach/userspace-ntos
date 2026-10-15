//! Retained START forwarding from an upper FDO to its exact lower FDO.
//!
//! The source IRP and its completion routine remain in the upper domain. The lower domain
//! receives a separate canonical IRP with owned copies of both resource lists.

use alloc::vec::Vec;
use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner},
    CompletedIrp, CompletionAcknowledgement, DispatchContext, ExternalPnpCompletionInvocation,
    ExternalPnpCompletionReturn, ExternalPnpDispatchResult, ExternalPnpFinishResult,
    ExternalPnpInvocation, ExternalPnpReturn, ExternalPnpTerminalReceipt,
    HostedDevicePointerRegistration, IoManager, IrpId, IrpProjection, ObjectManagerPort,
    PnpBackendDispatch, PnpParameters, PreparedExternalPnpIrp, RetainedExternalPnp,
};
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::{
    fdo_forward_path::{validate_fdo_forward_path, FdoForwardPathError},
    PnpManager,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartFdoForwardIdentity {
    pub source: SourceIrpTicket,
    pub source_irp: IrpId,
    pub upper: HostedDevicePointerRegistration,
    pub lower: HostedDevicePointerRegistration,
    pub devnode: u64,
}

/// One native source-completion observation from the trusted hosted adapter. This is consumed
/// once and is bound to the physical source allocation captured before lower dispatch.
#[derive(Debug)]
#[must_use = "deliver the exact native completion to its retained START owner"]
pub struct StartFdoSourceCompletionWitness {
    source: SourceIrpTicket,
    source_irp: IrpId,
    allocation: SourceIrpAllocation,
}

impl StartFdoSourceCompletionWitness {
    /// # Safety
    /// The hosted adapter must have observed the exact source's native completion walk return
    /// terminal and revalidated its generation-bearing ledger row before creating this witness.
    /// A pending-node payload or provider ACK alone is not source completion.
    pub unsafe fn after_native_terminal(
        source: SourceIrpTicket,
        source_irp: IrpId,
        allocation: SourceIrpAllocation,
    ) -> Option<Self> {
        (source.domain == allocation.domain
            && allocation.component_address != 0
            && allocation.bytes != 0
            && allocation.stack_count != 0
            && allocation.pool_generation != 0
            && matches!(allocation.owner, SourceIrpOwner::HostedCaller(_)))
        .then_some(Self {
            source,
            source_irp,
            allocation,
        })
    }
}

/// One exact source-stop observation from the trusted hosted cancellation adapter.
#[derive(Debug)]
#[must_use = "deliver the exact native source stop to its retained START owner"]
pub struct StartFdoSourceStopWitness {
    source: SourceIrpTicket,
    source_irp: IrpId,
    allocation: SourceIrpAllocation,
}

impl StartFdoSourceStopWitness {
    /// # Safety
    /// The hosted adapter must have proved that the exact route stopped or was cancelled, then
    /// successfully released the exact ticket/allocation source pin before creating this witness.
    /// A provider ACK and an attempted release do not establish source retirement.
    pub unsafe fn after_native_source_stop(
        source: SourceIrpTicket,
        source_irp: IrpId,
        allocation: SourceIrpAllocation,
    ) -> Option<Self> {
        (source.domain == allocation.domain
            && allocation.component_address != 0
            && allocation.bytes != 0
            && allocation.stack_count != 0
            && allocation.pool_generation != 0
            && matches!(allocation.owner, SourceIrpOwner::HostedCaller(_)))
        .then_some(Self {
            source,
            source_irp,
            allocation,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartFdoForwardError {
    WrongIdentity,
    WrongSource,
    WrongLower,
    SameDomain,
    Upper(NtStatus),
    Lower(NtStatus),
    Prepare(NtStatus),
    Dispatch(NtStatus),
    WrongTerminal,
    ProviderAckRequired,
    SourceCompletionRequired,
}

#[derive(Debug)]
struct Owner {
    identity: StartFdoForwardIdentity,
    native_source_allocation: Option<SourceIrpAllocation>,
    upper: HostedForwardTarget,
    lower: HostedForwardTarget,
    client: ClientId,
    requestor_tid: u64,
    upper_released: bool,
    lower_released: bool,
}

impl Owner {
    fn validate<P>(
        &self,
        pnp: &PnpManager,
        io: &IoManager<P>,
        observed: StartFdoForwardIdentity,
    ) -> Result<(), StartFdoForwardError> {
        if observed != self.identity {
            return Err(StartFdoForwardError::WrongIdentity);
        }
        self.upper
            .validate(io)
            .map_err(StartFdoForwardError::Upper)?;
        self.lower
            .validate(io)
            .map_err(StartFdoForwardError::Lower)?;
        validate_path(pnp, io, self.identity, self.client, self.requestor_tid)
    }

    fn release<P>(&mut self, io: &mut IoManager<P>) -> Result<(), StartFdoForwardError> {
        if !self.upper_released {
            self.upper
                .release(io)
                .map_err(StartFdoForwardError::Upper)?;
            self.upper_released = true;
        }
        if !self.lower_released {
            self.lower
                .release(io)
                .map_err(StartFdoForwardError::Lower)?;
            self.lower_released = true;
        }
        Ok(())
    }
}

fn validate_path<P>(
    pnp: &PnpManager,
    io: &IoManager<P>,
    identity: StartFdoForwardIdentity,
    client: ClientId,
    requestor_tid: u64,
) -> Result<(), StartFdoForwardError> {
    if identity.source.domain != identity.upper.domain() {
        return Err(StartFdoForwardError::SameDomain);
    }
    validate_fdo_forward_path(pnp, io, identity.upper, identity.lower, identity.devnode).map_err(
        |error| match error {
            FdoForwardPathError::SameDomain => StartFdoForwardError::SameDomain,
            FdoForwardPathError::WrongStack => StartFdoForwardError::WrongLower,
        },
    )?;
    let source = io
        .irp(identity.source_irp)
        .ok_or(StartFdoForwardError::WrongSource)?;
    let upper = source
        .current_stack()
        .ok_or(StartFdoForwardError::WrongSource)?;
    let lower = source
        .stack
        .get(usize::from(source.current_location) + 1)
        .ok_or(StartFdoForwardError::WrongLower)?;
    if source.origin_major != nt_pnp_abi::IRP_MJ_PNP
        || source.origin_minor != nt_pnp_abi::IRP_MN_START_DEVICE
        || source.client_id != client
        || source.requestor_tid != requestor_tid
        || upper.major != nt_pnp_abi::IRP_MJ_PNP
        || upper.minor != nt_pnp_abi::IRP_MN_START_DEVICE
        || lower.major != nt_pnp_abi::IRP_MJ_PNP
        || lower.minor != nt_pnp_abi::IRP_MN_START_DEVICE
        || upper.device_id != identity.upper.device_id()
        || lower.device_id != identity.lower.device_id()
        || upper.file_id.is_some()
        || lower.file_id.is_some()
    {
        return Err(StartFdoForwardError::WrongSource);
    }
    Ok(())
}

#[derive(Debug)]
#[must_use = "dispatch or discard through the issuing I/O manager"]
pub struct PreparedStartFdoForward {
    owner: Owner,
    provider_irp: PreparedExternalPnpIrp,
}

#[derive(Debug)]
#[must_use = "invoke exactly once outside the I/O manager borrow"]
pub struct StartFdoInvocation {
    owner: Owner,
    invocation: ExternalPnpInvocation,
}

#[derive(Debug)]
#[must_use = "reconcile through the issuing I/O manager; never invoke again"]
pub struct StartFdoReturn {
    owner: Owner,
    returned: ExternalPnpReturn,
}

#[derive(Debug)]
#[must_use = "retain a rejected return and its native-effect ownership"]
pub struct StartFdoFinishRejection {
    error: StartFdoForwardError,
    returned: StartFdoReturn,
}

#[derive(Debug)]
#[must_use = "retain until exact projection references are released"]
pub struct DiscardedStartFdoForward {
    owner: Owner,
}

#[derive(Debug)]
#[must_use = "retain entered provider effects, including uncertain outcomes"]
pub struct RetainedStartFdoForward {
    owner: Owner,
    provider_irp: IrpId,
    indeterminate: bool,
    detached: Option<RetainedExternalPnp>,
    rejected_terminal: Option<ExternalPnpTerminalReceipt>,
}

#[derive(Debug)]
#[must_use = "complete the source and acknowledge the provider before retiring"]
pub struct TerminalStartFdoForward {
    owner: Owner,
    receipt: ExternalPnpTerminalReceipt,
    provider_acknowledged: bool,
    source_completed: bool,
}

#[derive(Debug)]
#[must_use = "invoke exact provider ACK and retain its result"]
pub struct StartFdoCompletionInvocation {
    owner: Owner,
    provider_irp: IrpId,
    invocation: ExternalPnpCompletionInvocation,
}

#[derive(Debug)]
#[must_use = "settle exact provider ACK through the issuing I/O manager"]
pub struct StartFdoCompletionReturn {
    owner: Owner,
    provider_irp: IrpId,
    returned: ExternalPnpCompletionReturn,
}

#[derive(Debug)]
pub enum StartFdoForwardResult {
    Retained(RetainedStartFdoForward),
    Terminal(TerminalStartFdoForward),
    Rejected {
        error: StartFdoForwardError,
        retained: RetainedStartFdoForward,
    },
}

#[derive(Debug)]
pub enum StartFdoDiscardResult {
    Retired,
    NotDiscarded {
        error: StartFdoForwardError,
        prepared: PreparedStartFdoForward,
    },
    Retained {
        error: StartFdoForwardError,
        discarded: DiscardedStartFdoForward,
    },
}

fn valid_resource_list(bytes: &[u8]) -> bool {
    bytes.is_empty() || nt_cm_resources::validate_cm_resource_list_extent(bytes) == Ok(bytes.len())
}

impl PreparedStartFdoForward {
    /// Both input lists are source-owned copies; the native adapter must also pin the original
    /// allocations and source IRP until the source completion routine has executed.
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
        raw: Vec<u8>,
        translated: Vec<u8>,
    ) -> Result<Self, StartFdoForwardError> {
        if (raw.is_empty() != translated.is_empty())
            || !valid_resource_list(&raw)
            || !valid_resource_list(&translated)
        {
            return Err(StartFdoForwardError::Prepare(NtStatus::INVALID_PARAMETER));
        }
        let mut upper = HostedForwardTarget::capture(io, source.domain, upper_address)
            .map_err(StartFdoForwardError::Upper)?;
        let mut lower_owner =
            match HostedForwardTarget::capture(io, lower.domain(), lower.address()) {
                Ok(owner) => owner,
                Err(status) => {
                    upper.release(io).map_err(StartFdoForwardError::Upper)?;
                    return Err(StartFdoForwardError::Lower(status));
                }
            };
        let identity = StartFdoForwardIdentity {
            source,
            source_irp,
            upper: upper.registration(),
            lower,
            devnode,
        };
        let admission = if lower_owner.registration() != lower {
            Err(StartFdoForwardError::WrongLower)
        } else {
            validate_path(pnp, io, identity, client, requestor_tid)
        };
        if let Err(error) = admission {
            lower_owner
                .release(io)
                .map_err(StartFdoForwardError::Lower)?;
            upper.release(io).map_err(StartFdoForwardError::Upper)?;
            return Err(error);
        }
        let parameters = match u32::try_from(raw.len())
            .ok()
            .zip(u32::try_from(translated.len()).ok())
            .ok_or(NtStatus::INVALID_PARAMETER)
            .and_then(|(raw_len, translated_len)| PnpParameters::start(raw_len, translated_len))
        {
            Ok(parameters) => parameters,
            Err(status) => {
                lower_owner
                    .release(io)
                    .map_err(StartFdoForwardError::Lower)?;
                upper.release(io).map_err(StartFdoForwardError::Upper)?;
                return Err(StartFdoForwardError::Prepare(status));
            }
        };
        let mut payload = raw;
        if payload.try_reserve_exact(translated.len()).is_err() {
            lower_owner
                .release(io)
                .map_err(StartFdoForwardError::Lower)?;
            upper.release(io).map_err(StartFdoForwardError::Upper)?;
            return Err(StartFdoForwardError::Prepare(
                NtStatus::INSUFFICIENT_RESOURCES,
            ));
        }
        payload.extend_from_slice(&translated);
        let provider_irp = match io.prepare_external_pnp_owned_to_exact_device(
            client,
            lower.device_id(),
            requestor_tid,
            parameters,
            payload,
        ) {
            Ok(prepared) => prepared,
            Err(status) => {
                lower_owner
                    .release(io)
                    .map_err(StartFdoForwardError::Lower)?;
                upper.release(io).map_err(StartFdoForwardError::Upper)?;
                return Err(StartFdoForwardError::Prepare(status));
            }
        };
        Ok(Self {
            owner: Owner {
                identity,
                native_source_allocation: None,
                upper,
                lower: lower_owner,
                client,
                requestor_tid,
                upper_released: false,
                lower_released: false,
            },
            provider_irp,
        })
    }

    pub const fn identity(&self) -> StartFdoForwardIdentity {
        self.owner.identity
    }
    /// Bind the source allocation observed by the native adapter before provider entry.
    /// The later completion witness must name this same physical allocation and generation.
    pub fn bind_native_source_allocation(
        &mut self,
        allocation: SourceIrpAllocation,
    ) -> Result<(), StartFdoForwardError> {
        if self.owner.native_source_allocation.is_some()
            || allocation.domain != self.owner.identity.source.domain
            || allocation.component_address == 0
            || allocation.bytes == 0
            || allocation.stack_count == 0
            || allocation.pool_generation == 0
            || !matches!(allocation.owner, SourceIrpOwner::HostedCaller(_))
        {
            return Err(StartFdoForwardError::WrongSource);
        }
        self.owner.native_source_allocation = Some(allocation);
        Ok(())
    }
    pub fn provider_irp(&self) -> IrpId {
        self.provider_irp.irp_id()
    }

    pub fn begin<P>(
        self,
        pnp: &PnpManager,
        io: &mut IoManager<P>,
        observed: StartFdoForwardIdentity,
    ) -> Result<StartFdoInvocation, (StartFdoForwardError, Self)> {
        if let Err(error) = self.owner.validate(pnp, io, observed) {
            return Err((error, self));
        }
        let Self {
            owner,
            provider_irp,
        } = self;
        match io.begin_prepared_external_pnp(provider_irp) {
            Ok(invocation) => Ok(StartFdoInvocation { owner, invocation }),
            Err(rejection) => Err((
                StartFdoForwardError::Dispatch(rejection.status()),
                Self {
                    owner,
                    provider_irp: rejection.into_prepared(),
                },
            )),
        }
    }

    pub fn discard<P>(self, io: &mut IoManager<P>) -> StartFdoDiscardResult {
        let Self {
            mut owner,
            provider_irp,
        } = self;
        if let Err(rejection) = io.discard_prepared_external_pnp(provider_irp) {
            return StartFdoDiscardResult::NotDiscarded {
                error: StartFdoForwardError::Dispatch(rejection.status()),
                prepared: Self {
                    owner,
                    provider_irp: rejection.into_prepared(),
                },
            };
        }
        match owner.release(io) {
            Ok(()) => StartFdoDiscardResult::Retired,
            Err(error) => StartFdoDiscardResult::Retained {
                error,
                discarded: DiscardedStartFdoForward { owner },
            },
        }
    }
}

impl StartFdoInvocation {
    pub const fn identity(&self) -> StartFdoForwardIdentity {
        self.owner.identity
    }
    pub fn provider_irp(&self) -> IrpId {
        self.invocation.irp_id()
    }
    pub fn projection(&self) -> &IrpProjection {
        self.invocation.projection()
    }
    pub fn invoke<F>(self, invoke: F) -> StartFdoReturn
    where
        F: FnOnce(DispatchContext<'_>, &IrpProjection) -> PnpBackendDispatch,
    {
        let Self { owner, invocation } = self;
        StartFdoReturn {
            owner,
            returned: invocation.invoke(invoke),
        }
    }
}

impl StartFdoFinishRejection {
    pub const fn error(&self) -> StartFdoForwardError {
        self.error
    }
    pub fn into_return(self) -> StartFdoReturn {
        self.returned
    }
}

impl StartFdoReturn {
    pub const fn identity(&self) -> StartFdoForwardIdentity {
        self.owner.identity
    }
    pub fn provider_irp(&self) -> IrpId {
        self.returned.irp_id()
    }
    pub fn finish<P>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<StartFdoForwardResult, StartFdoFinishRejection> {
        let Self { owner, returned } = self;
        let expected = returned.irp_id();
        let finished = match io.finish_external_pnp(returned) {
            Ok(finished) => finished,
            Err(rejection) => {
                return Err(StartFdoFinishRejection {
                    error: StartFdoForwardError::Dispatch(rejection.status()),
                    returned: Self {
                        owner,
                        returned: rejection.into_owner(),
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
                } => finish_terminal(owner, expected, status, information, receipt, false),
                ExternalPnpDispatchResult::ReturnedPayload { receipt, .. } => {
                    rejected_terminal(owner, expected, receipt)
                }
                _ => unreachable!("terminal detached PnP returned nonterminal"),
            },
            ExternalPnpFinishResult::Retained(detached) => {
                let indeterminate = matches!(
                    detached.outcome(),
                    ExternalPnpDispatchResult::Indeterminate { .. }
                );
                StartFdoForwardResult::Retained(RetainedStartFdoForward {
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

impl DiscardedStartFdoForward {
    pub fn retire<P>(mut self, io: &mut IoManager<P>) -> Result<(), (StartFdoForwardError, Self)> {
        match self.owner.release(io) {
            Ok(()) => Ok(()),
            Err(error) => Err((error, self)),
        }
    }
}

fn rejected_terminal(
    owner: Owner,
    expected: IrpId,
    receipt: ExternalPnpTerminalReceipt,
) -> StartFdoForwardResult {
    StartFdoForwardResult::Rejected {
        error: StartFdoForwardError::WrongTerminal,
        retained: RetainedStartFdoForward {
            owner,
            provider_irp: expected,
            indeterminate: true,
            detached: None,
            rejected_terminal: Some(receipt),
        },
    }
}

fn finish_terminal(
    owner: Owner,
    expected: IrpId,
    status: NtStatus,
    information: u64,
    receipt: ExternalPnpTerminalReceipt,
    expected_pending: bool,
) -> StartFdoForwardResult {
    if receipt.irp_id() != expected
        || receipt.origin_device_id() != owner.identity.lower.device_id()
        || receipt.completion_device_id() != owner.identity.lower.device_id()
        || receipt.minor() != nt_pnp_abi::IRP_MN_START_DEVICE
        || receipt.relation_type().is_some()
        || receipt.driver_pending() != expected_pending
        || receipt.status() != status
        || receipt.information() != information
        || status == NtStatus::PENDING
        || information != 0
    {
        return rejected_terminal(owner, expected, receipt);
    }
    StartFdoForwardResult::Terminal(TerminalStartFdoForward {
        owner,
        receipt,
        provider_acknowledged: !expected_pending,
        source_completed: false,
    })
}

impl RetainedStartFdoForward {
    pub const fn identity(&self) -> StartFdoForwardIdentity {
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
        observed: StartFdoForwardIdentity,
    ) -> Result<StartFdoCompletionInvocation, (StartFdoForwardError, Self)> {
        if let Err(error) = self.owner.validate(pnp, io, observed) {
            return Err((error, self));
        }
        if self.rejected_terminal.is_some() {
            return Err((StartFdoForwardError::WrongTerminal, self));
        }
        let Some(detached) = self.detached.take() else {
            return Err((StartFdoForwardError::WrongTerminal, self));
        };
        match io.prepare_external_pnp_completion(detached) {
            Ok(invocation) => Ok(StartFdoCompletionInvocation {
                owner: self.owner,
                provider_irp: self.provider_irp,
                invocation,
            }),
            Err(rejection) => {
                let status = rejection.status();
                self.detached = Some(rejection.into_owner());
                Err((StartFdoForwardError::Lower(status), self))
            }
        }
    }
}

impl StartFdoCompletionInvocation {
    pub fn completion(&self) -> &CompletedIrp {
        self.invocation.completion()
    }
    pub fn backend_index(&self) -> usize {
        self.invocation.backend_index()
    }
    pub fn invoke<F>(self, invoke: F) -> StartFdoCompletionReturn
    where
        F: FnOnce(&CompletedIrp) -> CompletionAcknowledgement,
    {
        let Self {
            owner,
            provider_irp,
            invocation,
        } = self;
        StartFdoCompletionReturn {
            owner,
            provider_irp,
            returned: invocation.invoke(invoke),
        }
    }
}

impl StartFdoCompletionReturn {
    pub fn finish<P: ObjectManagerPort>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<StartFdoForwardResult, (StartFdoForwardError, Self)> {
        let Self {
            owner,
            provider_irp,
            returned,
        } = self;
        let (receipt, _input) = match io.finish_external_pnp_completion(returned) {
            Ok(result) => result,
            Err(rejection) => {
                return Err((
                    StartFdoForwardError::Lower(rejection.status()),
                    Self {
                        owner,
                        provider_irp,
                        returned: rejection.into_owner(),
                    },
                ))
            }
        };
        let mut result = finish_terminal(
            owner,
            provider_irp,
            receipt.status(),
            receipt.information(),
            receipt,
            true,
        );
        if let StartFdoForwardResult::Terminal(terminal) = &mut result {
            terminal.provider_acknowledged = true;
        }
        Ok(result)
    }
    pub fn retry<P: ObjectManagerPort>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<StartFdoCompletionInvocation, (StartFdoForwardError, Self)> {
        let Self {
            owner,
            provider_irp,
            returned,
        } = self;
        match io.retry_external_pnp_completion(returned) {
            Ok(invocation) => Ok(StartFdoCompletionInvocation {
                owner,
                provider_irp,
                invocation,
            }),
            Err(rejection) => Err((
                StartFdoForwardError::Lower(rejection.status()),
                Self {
                    owner,
                    provider_irp,
                    returned: rejection.into_owner(),
                },
            )),
        }
    }
}

impl TerminalStartFdoForward {
    pub const fn identity(&self) -> StartFdoForwardIdentity {
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
    /// Observe the exact canonical source terminal through its issuing I/O manager. The
    /// caller's copyable identity alone cannot establish that the source completion ran.
    pub fn mark_source_completed<P: ObjectManagerPort>(
        &mut self,
        io: &IoManager<P>,
        observed: StartFdoForwardIdentity,
    ) -> Result<(), StartFdoForwardError> {
        if observed != self.owner.identity {
            return Err(StartFdoForwardError::WrongIdentity);
        }
        if self.owner.native_source_allocation.is_some() {
            return Err(StartFdoForwardError::WrongSource);
        }
        let completion = io
            .completed_irp(self.owner.identity.source_irp)
            .ok_or(StartFdoForwardError::SourceCompletionRequired)?;
        if completion.id != self.owner.identity.source_irp
            || completion.client_id != self.owner.client
            || completion.requestor_tid != self.owner.requestor_tid
            || completion.device_id != self.owner.identity.upper.device_id()
            || completion.file_id.is_some()
            || completion.major != nt_pnp_abi::IRP_MJ_PNP
            || completion.minor != nt_pnp_abi::IRP_MN_START_DEVICE
        {
            return Err(StartFdoForwardError::WrongSource);
        }
        self.source_completed = true;
        Ok(())
    }
    /// Consume a native completion witness only for the exact bound source and allocation.
    pub fn mark_source_completed_from_native_witness(
        &mut self,
        witness: StartFdoSourceCompletionWitness,
    ) -> Result<(), (StartFdoForwardError, StartFdoSourceCompletionWitness)> {
        if witness.source != self.owner.identity.source
            || witness.source_irp != self.owner.identity.source_irp
            || self.owner.native_source_allocation != Some(witness.allocation)
        {
            return Err((StartFdoForwardError::WrongSource, witness));
        }
        self.source_completed = true;
        Ok(())
    }
    pub fn retire<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<NtStatus, (StartFdoForwardError, Self)> {
        if !self.source_completed {
            return Err((StartFdoForwardError::SourceCompletionRequired, self));
        }
        if !self.provider_acknowledged {
            return Err((StartFdoForwardError::ProviderAckRequired, self));
        }
        if let Err(error) = self.owner.release(io) {
            return Err((error, self));
        }
        Ok(self.receipt.status())
    }
    pub fn retire_after_source_stop<P>(
        mut self,
        io: &mut IoManager<P>,
        witness: StartFdoSourceStopWitness,
    ) -> Result<NtStatus, (StartFdoForwardError, Self, StartFdoSourceStopWitness)> {
        if witness.source != self.owner.identity.source
            || witness.source_irp != self.owner.identity.source_irp
            || self.owner.native_source_allocation != Some(witness.allocation)
        {
            return Err((StartFdoForwardError::WrongSource, self, witness));
        }
        if !self.provider_acknowledged {
            return Err((StartFdoForwardError::ProviderAckRequired, self, witness));
        }
        if let Err(error) = self.owner.release(io) {
            return Err((error, self, witness));
        }
        Ok(self.receipt.status())
    }

    /// Host-only teardown after the issuing I/O manager has retired the exact source IRP.
    pub fn retire_after_host_source_stop<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<NtStatus, (StartFdoForwardError, Self)> {
        if self.owner.native_source_allocation.is_some() {
            return Err((StartFdoForwardError::WrongSource, self));
        }
        if io.irp(self.owner.identity.source_irp).is_some() {
            return Err((StartFdoForwardError::SourceCompletionRequired, self));
        }
        if !self.provider_acknowledged {
            return Err((StartFdoForwardError::ProviderAckRequired, self));
        }
        if let Err(error) = self.owner.release(io) {
            return Err((error, self));
        }
        Ok(self.receipt.status())
    }
}
