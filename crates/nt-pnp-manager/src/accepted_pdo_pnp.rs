//! Retained, exact-provider PnP requests from a canonical function stack.
//!
//! VideoPort's hosted function stack is entered by a canonical IRP, but its lower PCI PDO
//! lives in a different provider domain. This owner gives that lower edge a separate canonical
//! IRP while retaining the exact accepted provider and the outer IRP identity. A provider
//! result is never inferred from relation metadata or the root bus.

use alloc::vec::Vec;

use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget, CompletedIrp, CompletionAcknowledgement, DeviceId,
    DispatchContext, ExternalPnpCompletionInvocation, ExternalPnpCompletionReturn,
    ExternalPnpDispatchResult, ExternalPnpFinishResult, ExternalPnpInvocation, ExternalPnpReturn,
    ExternalPnpFilterCompletionInvocation, ExternalPnpFilterCompletionReturn,
    ExternalPnpFilterOutput, ExternalPnpTerminalReceipt, IoManager, IrpId, IrpProjection,
    ObjectManagerPort, PnpBackendDispatch, PnpParameters, PreparedExternalPnpIrp, RetainedExternalPnp,
};
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::{
    AcceptedPdoProviderAuthority, AcceptedPdoProviderCatalog, AcceptedPdoProviderError,
    BusRelationTable, PnpManager,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedPdoPnpIdentity {
    /// FDO outer IRP for a lower edge; the provider IRP itself for a direct raw-PDO START.
    pub outer_irp: IrpId,
    pub pdo: DeviceId,
    pub minor: u8,
    pub provider: AcceptedPdoProviderAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptedPdoLowerFilterProofError {
    InvalidMinor,
    WrongIdentity,
    Consumed,
}

/// A one-use terminal proof for a function driver's lower accepted PDO edge.
#[derive(Debug)]
pub struct AcceptedPdoLowerFilterProof {
    identity: AcceptedPdoPnpIdentity,
    status: Option<NtStatus>,
}

impl AcceptedPdoLowerFilterProof {
    pub fn new(
        identity: AcceptedPdoPnpIdentity,
        status: NtStatus,
    ) -> Result<Self, AcceptedPdoLowerFilterProofError> {
        if identity.minor != nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS {
            return Err(AcceptedPdoLowerFilterProofError::InvalidMinor);
        }
        Ok(Self {
            identity,
            status: Some(status),
        })
    }

    pub fn take_for(
        &mut self,
        observed: AcceptedPdoPnpIdentity,
    ) -> Result<NtStatus, AcceptedPdoLowerFilterProofError> {
        if observed != self.identity {
            return Err(AcceptedPdoLowerFilterProofError::WrongIdentity);
        }
        self.status
            .take()
            .ok_or(AcceptedPdoLowerFilterProofError::Consumed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptedPdoPnpError {
    WrongIdentity,
    WrongOuter,
    WrongProvider,
    Authority(AcceptedPdoProviderError),
    Provider(NtStatus),
    Prepare(NtStatus),
    Dispatch(NtStatus),
    WrongTerminal,
    UnsupportedFilterOutput,
    ProviderAckRequired,
}

#[derive(Debug)]
struct Owner {
    identity: AcceptedPdoPnpIdentity,
    target: HostedForwardTarget,
    released: bool,
}

impl Owner {
    fn validate_outer<P>(&self, io: &IoManager<P>) -> Result<(), AcceptedPdoPnpError> {
        let outer = io
            .irp(self.identity.outer_irp)
            .ok_or(AcceptedPdoPnpError::WrongOuter)?;
        if outer.file_id.is_some()
            || outer.origin_major != nt_pnp_abi::IRP_MJ_PNP
            || outer.origin_minor != self.identity.minor
            || outer.origin_device_id != self.identity.pdo
        {
            return Err(AcceptedPdoPnpError::WrongOuter);
        }
        Ok(())
    }

    fn validate_target<P>(&self, io: &IoManager<P>) -> Result<(), AcceptedPdoPnpError> {
        let pdo = self
            .target
            .validate(io)
            .map_err(AcceptedPdoPnpError::Provider)?;
        if pdo != self.identity.pdo
            || self.target.registration() != self.identity.provider.provider()
        {
            return Err(AcceptedPdoPnpError::WrongProvider);
        }
        self.validate_outer(io)
    }

    fn validate_entry<P>(
        &self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &IoManager<P>,
        observed: AcceptedPdoPnpIdentity,
    ) -> Result<(), AcceptedPdoPnpError> {
        if observed != self.identity {
            return Err(AcceptedPdoPnpError::WrongIdentity);
        }
        self.validate_target(io)?;
        let current = providers
            .resolve(pnp, relations, io, self.identity.pdo.raw())
            .map_err(AcceptedPdoPnpError::Authority)?;
        if current != self.identity.provider {
            return Err(AcceptedPdoPnpError::WrongProvider);
        }
        Ok(())
    }

    fn release<P>(&mut self, io: &mut IoManager<P>) -> Result<(), AcceptedPdoPnpError> {
        if !self.released {
            self.target
                .release(io)
                .map_err(AcceptedPdoPnpError::Provider)?;
            self.released = true;
        }
        Ok(())
    }
}

#[derive(Debug)]
#[must_use = "dispatch or discard through the issuing I/O Manager"]
pub struct PreparedAcceptedPdoPnp {
    owner: Owner,
    provider_irp: PreparedExternalPnpIrp,
}

#[derive(Debug)]
#[must_use = "retain until the exact provider reference is released"]
pub struct DiscardedAcceptedPdoPnp {
    owner: Owner,
}

#[derive(Debug)]
#[must_use = "retain until a provider terminal and acknowledgement are observed"]
pub struct RetainedAcceptedPdoPnp {
    owner: Owner,
    provider_irp: IrpId,
    indeterminate: bool,
    detached: Option<RetainedExternalPnp>,
    rejected_receipt: Option<ExternalPnpTerminalReceipt>,
    rejected_payload: Option<Vec<u8>>,
}

/// The sole provider invocation owner, detached from the I/O Manager before native entry.
#[derive(Debug)]
#[must_use = "invoke once outside the manager borrow"]
pub struct AcceptedPdoPnpInvocation {
    owner: Owner,
    invocation: ExternalPnpInvocation,
}

#[derive(Debug)]
#[must_use = "reconcile the entered provider effect through the issuing I/O Manager"]
pub struct AcceptedPdoPnpReturn {
    owner: Owner,
    returned: ExternalPnpReturn,
}

#[derive(Debug)]
#[must_use = "invoke provider ACK outside the I/O Manager borrow"]
pub struct AcceptedPdoPnpCompletionInvocation {
    owner: Owner,
    provider_irp: IrpId,
    invocation: AcceptedPdoCompletionInvocation,
}

#[derive(Debug)]
enum AcceptedPdoCompletionInvocation {
    Start(ExternalPnpCompletionInvocation),
    Filter(ExternalPnpFilterCompletionInvocation),
}

#[derive(Debug)]
#[must_use = "settle the exact provider ACK through the issuing I/O Manager"]
pub struct AcceptedPdoPnpCompletionReturn {
    owner: Owner,
    provider_irp: IrpId,
    returned: AcceptedPdoCompletionReturn,
}

#[derive(Debug)]
enum AcceptedPdoCompletionReturn {
    Start(ExternalPnpCompletionReturn),
    Filter(ExternalPnpFilterCompletionReturn),
}

#[derive(Debug)]
#[must_use = "retain an uncertain provider ACK and its exact target"]
pub struct AcceptedPdoPnpCompletionRejection {
    error: AcceptedPdoPnpError,
    returned: AcceptedPdoPnpCompletionReturn,
}

impl AcceptedPdoPnpCompletionRejection {
    pub const fn error(&self) -> AcceptedPdoPnpError {
        self.error
    }
    pub fn into_returned(self) -> AcceptedPdoPnpCompletionReturn {
        self.returned
    }
}

#[derive(Debug)]
#[must_use = "retain the returned owner; the provider may have been entered"]
pub struct AcceptedPdoPnpFinishRejection {
    error: AcceptedPdoPnpError,
    returned: AcceptedPdoPnpReturn,
}

impl AcceptedPdoPnpFinishRejection {
    pub const fn error(&self) -> AcceptedPdoPnpError {
        self.error
    }
    pub fn into_returned(self) -> AcceptedPdoPnpReturn {
        self.returned
    }
}

#[derive(Debug)]
#[must_use = "acknowledge pending provider completion before retiring"]
pub struct TerminalAcceptedPdoPnp {
    owner: Owner,
    receipt: ExternalPnpTerminalReceipt,
    payload: Option<Vec<u8>>,
    acknowledged: bool,
}

#[derive(Debug)]
pub enum AcceptedPdoPnpResult {
    NotEntered {
        error: AcceptedPdoPnpError,
        prepared: PreparedAcceptedPdoPnp,
    },
    Retained(RetainedAcceptedPdoPnp),
    Terminal(TerminalAcceptedPdoPnp),
    Rejected {
        error: AcceptedPdoPnpError,
        retained: RetainedAcceptedPdoPnp,
    },
}

#[derive(Debug)]
pub enum AcceptedPdoPnpDiscard {
    Retired,
    NotDiscarded {
        error: AcceptedPdoPnpError,
        prepared: PreparedAcceptedPdoPnp,
    },
    Retained {
        error: AcceptedPdoPnpError,
        discarded: DiscardedAcceptedPdoPnp,
    },
}

impl PreparedAcceptedPdoPnp {
    #[allow(clippy::too_many_arguments)]
    pub fn start<P>(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &mut IoManager<P>,
        outer_irp: IrpId,
        pdo: DeviceId,
        client: ClientId,
        requestor_tid: u64,
        raw_len: u32,
        translated_len: u32,
        payload: Vec<u8>,
    ) -> Result<Self, AcceptedPdoPnpError> {
        let parameters =
            PnpParameters::start(raw_len, translated_len).map_err(AcceptedPdoPnpError::Prepare)?;
        Self::prepare(
            pnp,
            relations,
            providers,
            io,
            Some(outer_irp),
            pdo,
            client,
            requestor_tid,
            parameters,
            payload,
        )
    }

    /// Prepare one canonical PDO START without a function-stack outer IRP.
    /// The caller must begin the matching PnP dispatch with `provider_irp()` before entry.
    #[allow(clippy::too_many_arguments)]
    pub fn start_direct<P>(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &mut IoManager<P>,
        pdo: DeviceId,
        client: ClientId,
        requestor_tid: u64,
        raw_len: u32,
        translated_len: u32,
        payload: Vec<u8>,
    ) -> Result<Self, AcceptedPdoPnpError> {
        if !pnp.raw_pdo_start_admissible(relations, pdo.raw()) {
            return Err(AcceptedPdoPnpError::Prepare(NtStatus::INVALID_DEVICE_REQUEST));
        }
        let parameters =
            PnpParameters::start(raw_len, translated_len).map_err(AcceptedPdoPnpError::Prepare)?;
        Self::prepare(
            pnp, relations, providers, io, None, pdo, client, requestor_tid, parameters, payload,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn filter<P>(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &mut IoManager<P>,
        outer_irp: IrpId,
        pdo: DeviceId,
        client: ClientId,
        requestor_tid: u64,
        payload: Vec<u8>,
    ) -> Result<Self, AcceptedPdoPnpError> {
        let length = u32::try_from(payload.len())
            .map_err(|_| AcceptedPdoPnpError::Prepare(NtStatus::INVALID_PARAMETER))?;
        let parameters = PnpParameters::filter_resource_requirements(length)
            .map_err(AcceptedPdoPnpError::Prepare)?;
        Self::prepare(
            pnp,
            relations,
            providers,
            io,
            Some(outer_irp),
            pdo,
            client,
            requestor_tid,
            parameters,
            payload,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare<P>(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &mut IoManager<P>,
        outer_irp: Option<IrpId>,
        pdo: DeviceId,
        client: ClientId,
        requestor_tid: u64,
        parameters: PnpParameters,
        payload: Vec<u8>,
    ) -> Result<Self, AcceptedPdoPnpError> {
        if payload.len() != parameters.payload_len() as usize {
            return Err(AcceptedPdoPnpError::WrongOuter);
        }
        if let Some(outer_irp) = outer_irp {
            let outer = io.irp(outer_irp).ok_or(AcceptedPdoPnpError::WrongOuter)?;
            if outer.client_id != client
                || outer.file_id.is_some()
                || outer.origin_major != nt_pnp_abi::IRP_MJ_PNP
                || outer.origin_minor != parameters.minor
                || outer.origin_device_id != pdo
            {
                return Err(AcceptedPdoPnpError::WrongOuter);
            }
        }
        let authority = providers
            .resolve(pnp, relations, io, pdo.raw())
            .map_err(AcceptedPdoPnpError::Authority)?;
        let mut target = HostedForwardTarget::capture(
            io,
            authority.provider().domain(),
            authority.provider().address(),
        )
        .map_err(AcceptedPdoPnpError::Provider)?;
        if target.device_id() != pdo || target.registration() != authority.provider() {
            target
                .release(io)
                .expect("unentered provider target could not be released");
            return Err(AcceptedPdoPnpError::WrongProvider);
        }
        let provider_irp = match io.prepare_external_pnp_owned_to_exact_device(
            client,
            pdo,
            requestor_tid,
            parameters,
            payload,
        ) {
            Ok(prepared) => prepared,
            Err(status) => {
                target
                    .release(io)
                    .expect("unentered provider target could not be released");
                return Err(AcceptedPdoPnpError::Prepare(status));
            }
        };
        Ok(Self {
            owner: Owner {
                identity: AcceptedPdoPnpIdentity {
                    outer_irp: outer_irp.unwrap_or_else(|| provider_irp.irp_id()),
                    pdo,
                    minor: parameters.minor,
                    provider: authority,
                },
                target,
                released: false,
            },
            provider_irp,
        })
    }

    pub const fn identity(&self) -> AcceptedPdoPnpIdentity {
        self.owner.identity
    }
    pub fn provider_irp(&self) -> IrpId {
        self.provider_irp.irp_id()
    }

    pub fn begin<P>(
        self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &mut IoManager<P>,
        observed: AcceptedPdoPnpIdentity,
    ) -> Result<AcceptedPdoPnpInvocation, (AcceptedPdoPnpError, Self)> {
        if let Err(error) = self
            .owner
            .validate_entry(pnp, relations, providers, io, observed)
        {
            return Err((error, self));
        }
        let Self {
            owner,
            provider_irp,
        } = self;
        match io.begin_prepared_external_pnp(provider_irp) {
            Ok(invocation) => Ok(AcceptedPdoPnpInvocation { owner, invocation }),
            Err(rejection) => Err((
                AcceptedPdoPnpError::Dispatch(rejection.status()),
                Self {
                    owner,
                    provider_irp: rejection.into_prepared(),
                },
            )),
        }
    }

    pub fn discard<P>(self, io: &mut IoManager<P>) -> AcceptedPdoPnpDiscard {
        let Self {
            mut owner,
            provider_irp,
        } = self;
        if let Err(rejection) = io.discard_prepared_external_pnp(provider_irp) {
            return AcceptedPdoPnpDiscard::NotDiscarded {
                error: AcceptedPdoPnpError::Dispatch(rejection.status()),
                prepared: Self {
                    owner,
                    provider_irp: rejection.into_prepared(),
                },
            };
        }
        match owner.release(io) {
            Ok(()) => AcceptedPdoPnpDiscard::Retired,
            Err(error) => AcceptedPdoPnpDiscard::Retained {
                error,
                discarded: DiscardedAcceptedPdoPnp { owner },
            },
        }
    }
}

impl AcceptedPdoPnpInvocation {
    pub const fn identity(&self) -> AcceptedPdoPnpIdentity {
        self.owner.identity
    }
    pub fn provider_irp(&self) -> IrpId {
        self.invocation.irp_id()
    }
    pub fn projection(&self) -> &IrpProjection {
        self.invocation.projection()
    }

    pub fn invoke<F>(self, invoke: F) -> AcceptedPdoPnpReturn
    where
        F: FnOnce(DispatchContext<'_>, &IrpProjection) -> PnpBackendDispatch,
    {
        let Self { owner, invocation } = self;
        AcceptedPdoPnpReturn {
            owner,
            returned: invocation.invoke(invoke),
        }
    }
}

impl AcceptedPdoPnpReturn {
    pub const fn identity(&self) -> AcceptedPdoPnpIdentity {
        self.owner.identity
    }
    pub fn provider_irp(&self) -> IrpId {
        self.returned.irp_id()
    }

    pub fn finish<P>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<AcceptedPdoPnpResult, AcceptedPdoPnpFinishRejection> {
        let Self { owner, returned } = self;
        let expected_irp = returned.irp_id();
        let finished = match io.finish_external_pnp(returned) {
            Ok(finished) => finished,
            Err(rejection) => {
                return Err(AcceptedPdoPnpFinishRejection {
                    error: AcceptedPdoPnpError::Dispatch(rejection.status()),
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
                } => finish_terminal(
                    owner,
                    expected_irp,
                    status,
                    information,
                    receipt,
                    None,
                    false,
                ),
                ExternalPnpDispatchResult::ReturnedPayload {
                    status,
                    information,
                    payload,
                    receipt,
                } => finish_terminal(
                    owner,
                    expected_irp,
                    status,
                    information,
                    receipt,
                    Some(payload),
                    false,
                ),
                ExternalPnpDispatchResult::Pending { .. }
                | ExternalPnpDispatchResult::Indeterminate { .. } => {
                    unreachable!("terminal detached PnP returned nonterminal")
                }
            },
            ExternalPnpFinishResult::Retained(detached) => {
                let indeterminate = matches!(
                    detached.outcome(),
                    ExternalPnpDispatchResult::Indeterminate { .. }
                );
                AcceptedPdoPnpResult::Retained(RetainedAcceptedPdoPnp {
                    owner,
                    provider_irp: expected_irp,
                    indeterminate,
                    detached: Some(detached),
                    rejected_receipt: None,
                    rejected_payload: None,
                })
            }
        })
    }
}

impl DiscardedAcceptedPdoPnp {
    pub fn retire<P>(mut self, io: &mut IoManager<P>) -> Result<(), (AcceptedPdoPnpError, Self)> {
        match self.owner.release(io) {
            Ok(()) => Ok(()),
            Err(error) => Err((error, self)),
        }
    }
}

fn finish_terminal(
    owner: Owner,
    expected_irp: IrpId,
    status: NtStatus,
    information: u64,
    receipt: ExternalPnpTerminalReceipt,
    payload: Option<Vec<u8>>,
    pending: bool,
) -> AcceptedPdoPnpResult {
    let identity = owner.identity;
    let valid = receipt.irp_id() == expected_irp
        && receipt.origin_device_id() == identity.pdo
        && receipt.completion_device_id() == identity.pdo
        && receipt.minor() == identity.minor
        && receipt.relation_type().is_none()
        && receipt.driver_pending() == pending
        && status == receipt.status()
        && information == receipt.information()
        && status != NtStatus::PENDING;
    let output_valid = if identity.minor == nt_pnp_abi::IRP_MN_START_DEVICE {
        information == 0
    } else {
        // The native completion owner maps only its authenticated borrowed input pointer to
        // zero canonical Information. A successful new provider allocation remains retained
        // until a distinct copy-and-release owner can publish its bytes.
        !status.is_success() || information == 0 && payload.is_none()
    };
    if !valid || !output_valid {
        return AcceptedPdoPnpResult::Rejected {
            error: if valid && identity.minor == nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS {
                AcceptedPdoPnpError::UnsupportedFilterOutput
            } else {
                AcceptedPdoPnpError::WrongTerminal
            },
            retained: RetainedAcceptedPdoPnp {
                owner,
                provider_irp: expected_irp,
                indeterminate: true,
                detached: None,
                rejected_receipt: Some(receipt),
                rejected_payload: payload,
            },
        };
    }
    AcceptedPdoPnpResult::Terminal(TerminalAcceptedPdoPnp {
        owner,
        receipt,
        payload,
        acknowledged: !pending,
    })
}

impl RetainedAcceptedPdoPnp {
    pub const fn identity(&self) -> AcceptedPdoPnpIdentity {
        self.owner.identity
    }
    pub const fn provider_irp(&self) -> IrpId {
        self.provider_irp
    }
    pub const fn is_indeterminate(&self) -> bool {
        self.indeterminate
    }
    pub const fn has_rejected_terminal(&self) -> bool {
        self.rejected_receipt.is_some()
    }
    pub fn rejected_terminal_receipt(&self) -> Option<&ExternalPnpTerminalReceipt> {
        self.rejected_receipt.as_ref()
    }
    pub fn rejected_payload(&self) -> Option<&[u8]> {
        self.rejected_payload.as_deref()
    }

    /// Pending START and FILTER use the same exact completion ACK. FILTER can retire only if its
    /// terminal carries no new output allocation; uncertain or rejected terminals stay owned.
    pub fn prepare_completion<P: ObjectManagerPort>(
        mut self,
        io: &mut IoManager<P>,
        observed: AcceptedPdoPnpIdentity,
    ) -> Result<AcceptedPdoPnpCompletionInvocation, (AcceptedPdoPnpError, Self)> {
        if observed != self.owner.identity || self.owner.validate_target(io).is_err() {
            return Err((AcceptedPdoPnpError::WrongIdentity, self));
        }
        let Some(detached) = self.detached.take() else {
            return Err((AcceptedPdoPnpError::WrongTerminal, self));
        };
        let prepared = if self.owner.identity.minor == nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS {
            io.prepare_external_pnp_filter_completion(detached, ExternalPnpFilterOutput::Original)
                .map(AcceptedPdoCompletionInvocation::Filter)
                .map_err(|(rejection, _)| rejection)
        } else {
            io.prepare_external_pnp_completion(detached)
                .map(AcceptedPdoCompletionInvocation::Start)
        };
        match prepared {
            Ok(invocation) => Ok(AcceptedPdoPnpCompletionInvocation {
                owner: self.owner,
                provider_irp: self.provider_irp,
                invocation,
            }),
            Err(rejection) => {
                let status = rejection.status();
                self.detached = Some(rejection.into_owner());
                Err((AcceptedPdoPnpError::Provider(status), self))
            }
        }
    }
}

impl AcceptedPdoPnpCompletionInvocation {
    pub const fn identity(&self) -> AcceptedPdoPnpIdentity {
        self.owner.identity
    }
    pub fn completion(&self) -> &CompletedIrp {
        match &self.invocation {
            AcceptedPdoCompletionInvocation::Start(invocation) => invocation.completion(),
            AcceptedPdoCompletionInvocation::Filter(invocation) => invocation.completion(),
        }
    }
    pub fn backend_index(&self) -> usize {
        match &self.invocation {
            AcceptedPdoCompletionInvocation::Start(invocation) => invocation.backend_index(),
            AcceptedPdoCompletionInvocation::Filter(invocation) => invocation.backend_index(),
        }
    }

    pub fn invoke<F>(self, invoke: F) -> AcceptedPdoPnpCompletionReturn
    where
        F: FnOnce(&CompletedIrp) -> CompletionAcknowledgement,
    {
        let Self {
            owner,
            provider_irp,
            invocation,
        } = self;
        AcceptedPdoPnpCompletionReturn {
            owner,
            provider_irp,
            returned: match invocation {
                AcceptedPdoCompletionInvocation::Start(invocation) => {
                    AcceptedPdoCompletionReturn::Start(invocation.invoke(invoke))
                }
                AcceptedPdoCompletionInvocation::Filter(invocation) => {
                    AcceptedPdoCompletionReturn::Filter(invocation.invoke(invoke))
                }
            },
        }
    }
}

impl AcceptedPdoPnpCompletionReturn {
    pub const fn identity(&self) -> AcceptedPdoPnpIdentity {
        self.owner.identity
    }

    pub fn finish<P: ObjectManagerPort>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<AcceptedPdoPnpResult, AcceptedPdoPnpCompletionRejection> {
        let Self {
            owner,
            provider_irp,
            returned,
        } = self;
        let settled = match returned {
            AcceptedPdoCompletionReturn::Start(returned) => io
                .finish_external_pnp_completion(returned)
                .map(|(receipt, input)| (receipt, input))
                .map_err(|rejection| {
                    (
                        rejection.status(),
                        AcceptedPdoCompletionReturn::Start(rejection.into_owner()),
                    )
                }),
            AcceptedPdoCompletionReturn::Filter(returned) => io
                .finish_external_pnp_filter_completion(returned)
                .map(|(receipt, input, _output)| (receipt, input))
                .map_err(|rejection| {
                    (
                        rejection.status(),
                        AcceptedPdoCompletionReturn::Filter(rejection.into_owner()),
                    )
                }),
        };
        let (receipt, _owned_input) = match settled {
            Ok(terminal) => terminal,
            Err((status, returned)) => {
                return Err(AcceptedPdoPnpCompletionRejection {
                    error: AcceptedPdoPnpError::Provider(status),
                    returned: Self { owner, provider_irp, returned },
                });
            }
        };
        let result = finish_terminal(
            owner,
            provider_irp,
            receipt.status(),
            receipt.information(),
            receipt,
            None,
            true,
        );
        Ok(match result {
            AcceptedPdoPnpResult::Terminal(mut terminal) => {
                terminal.acknowledged = true;
                AcceptedPdoPnpResult::Terminal(terminal)
            }
            other => other,
        })
    }
}

impl TerminalAcceptedPdoPnp {
    pub const fn identity(&self) -> AcceptedPdoPnpIdentity {
        self.owner.identity
    }
    pub const fn status(&self) -> NtStatus {
        self.receipt.status()
    }
    pub const fn provider_irp(&self) -> IrpId {
        self.receipt.irp_id()
    }
    pub const fn provider_acknowledged(&self) -> bool {
        self.acknowledged
    }

    /// FILTER's borrowed input pointer never crosses into the outer IRP.
    pub const fn information(&self) -> u64 {
        0
    }

    /// Exact request-owned bytes returned by a synchronous FILTER provider.
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    pub fn acknowledge_provider<P: ObjectManagerPort>(
        &mut self,
        io: &mut IoManager<P>,
    ) -> Result<(), AcceptedPdoPnpError> {
        if !self.acknowledged {
            io.acknowledge_completed_irp_strict(self.receipt.irp_id())
                .map_err(AcceptedPdoPnpError::Provider)?;
            self.acknowledged = true;
        }
        Ok(())
    }

    pub fn retire<P>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<NtStatus, (AcceptedPdoPnpError, Self)> {
        self.retire_with_receipt(io).map(|receipt| receipt.status())
    }

    /// Transfer the exact terminal receipt after provider ACK and target retirement.
    /// Direct raw-PDO START uses this receipt as the sole authority for PnP lifecycle commit.
    pub fn retire_with_receipt<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<ExternalPnpTerminalReceipt, (AcceptedPdoPnpError, Self)> {
        if !self.acknowledged {
            return Err((AcceptedPdoPnpError::ProviderAckRequired, self));
        }
        if let Err(error) = self.owner.release(io) {
            return Err((error, self));
        }
        Ok(self.receipt)
    }
}
