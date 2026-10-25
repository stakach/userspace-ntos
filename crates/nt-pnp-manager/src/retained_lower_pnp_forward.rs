//! Retained cross-domain lower-edge PnP forwarding.
//!
//! A source driver IRP and its completion routine remain in the consumer domain. The canonical
//! I/O manager dispatches a separately constructed provider IRP to the accepted PDO's exact
//! provider projection. Neither a native IRP pointer nor a provider-domain DEVICE_OBJECT address
//! crosses the boundary.

use alloc::vec::Vec;

use nt_io_manager::{
    hosted_forward_target::HostedForwardTarget, retained_query_path_forward::SourceIrpTicket,
    ExternalPnpDispatchResult, ExternalPnpTerminalReceipt, HostedDevicePointerRegistration,
    HostedDomainIdentity, IoManager, IrpId, ObjectManagerPort, PnpParameters,
    PreparedExternalPnpIrp,
};
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::{
    AcceptedPdoProviderAuthority, AcceptedPdoProviderCatalog, AcceptedPdoProviderError,
    BusRelationTable, PnpManager,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowerPnpForwardIdentity {
    pub source: SourceIrpTicket,
    pub consumer: HostedDevicePointerRegistration,
    pub provider: AcceptedPdoProviderAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LowerPnpForwardError {
    WrongIdentity,
    SameDomain,
    WrongConsumer,
    Authority(AcceptedPdoProviderError),
    Consumer(NtStatus),
    Provider(NtStatus),
    InvalidStart,
    Prepare(NtStatus),
    Dispatch(NtStatus),
    WrongTerminal,
    PendingTerminal,
    NonzeroInformation,
    UnexpectedPayload,
    ProviderAckRequired,
}

#[derive(Debug)]
struct Owner {
    identity: LowerPnpForwardIdentity,
    consumer: HostedForwardTarget,
    provider: HostedForwardTarget,
    consumer_released: bool,
    provider_released: bool,
}

impl Owner {
    fn validate_targets<P>(
        &self,
        io: &IoManager<P>,
        observed: LowerPnpForwardIdentity,
    ) -> Result<(), LowerPnpForwardError> {
        if observed != self.identity {
            return Err(LowerPnpForwardError::WrongIdentity);
        }
        let consumer_device = self
            .consumer
            .validate(io)
            .map_err(LowerPnpForwardError::Consumer)?;
        let provider_device = self
            .provider
            .validate(io)
            .map_err(LowerPnpForwardError::Provider)?;
        if self.identity.source.domain != self.identity.consumer.domain()
            || self.identity.consumer.domain() == self.identity.provider.provider().domain()
            || consumer_device != provider_device
            || consumer_device.raw() != self.identity.provider.pdo_object_id()
            || self.consumer.registration() != self.identity.consumer
            || self.provider.registration() != self.identity.provider.provider()
        {
            return Err(LowerPnpForwardError::WrongConsumer);
        }
        Ok(())
    }

    fn validate_entry<P>(
        &self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &IoManager<P>,
        observed: LowerPnpForwardIdentity,
    ) -> Result<(), LowerPnpForwardError> {
        self.validate_targets(io, observed)?;
        let current = providers
            .resolve(pnp, relations, io, self.identity.provider.pdo_object_id())
            .map_err(LowerPnpForwardError::Authority)?;
        if current != self.identity.provider {
            return Err(LowerPnpForwardError::WrongIdentity);
        }
        Ok(())
    }

    fn release<P>(&mut self, io: &mut IoManager<P>) -> Result<(), LowerPnpForwardError> {
        if !self.consumer_released {
            self.consumer
                .release(io)
                .map_err(LowerPnpForwardError::Consumer)?;
            self.consumer_released = true;
        }
        if !self.provider_released {
            self.provider
                .release(io)
                .map_err(LowerPnpForwardError::Provider)?;
            self.provider_released = true;
        }
        Ok(())
    }
}

/// All allocations and exact projection references required for provider entry.
#[derive(Debug)]
#[must_use = "dispatch, or retain until it can be discarded through the issuing I/O Manager"]
pub struct PreparedLowerPnpForward {
    owner: Owner,
    provider_irp: PreparedExternalPnpIrp,
}

/// The canonical provider IRP was safely discarded before entry, but an exact projection release
/// still needs redrive. This state can never be dispatched.
#[derive(Debug)]
#[must_use = "retain until both exact projection references have been released"]
pub struct DiscardedLowerPnpForward {
    owner: Owner,
}

/// A provider effect that has no accepted terminal yet.
#[derive(Debug)]
#[must_use = "retain until an exact provider terminal is available"]
pub struct RetainedLowerPnpForward {
    owner: Owner,
    provider_irp: IrpId,
    indeterminate: bool,
    transport_status: Option<NtStatus>,
    rejected_terminal: Option<ExternalPnpTerminalReceipt>,
}

/// A genuine provider terminal retained until the source-domain completion routine has run.
#[derive(Debug)]
#[must_use = "retire only after source-local completion"]
pub struct TerminalLowerPnpForward {
    owner: Owner,
    receipt: ExternalPnpTerminalReceipt,
    provider_acknowledged: bool,
}

#[derive(Debug)]
pub enum LowerPnpForwardResult {
    NotEntered {
        error: LowerPnpForwardError,
        prepared: PreparedLowerPnpForward,
    },
    Retained(RetainedLowerPnpForward),
    Terminal(TerminalLowerPnpForward),
    Rejected {
        error: LowerPnpForwardError,
        retained: RetainedLowerPnpForward,
    },
}

#[derive(Debug)]
pub enum LowerPnpForwardDiscardResult {
    Retired,
    NotDiscarded {
        error: LowerPnpForwardError,
        prepared: PreparedLowerPnpForward,
    },
    Retained {
        error: LowerPnpForwardError,
        discarded: DiscardedLowerPnpForward,
    },
}

impl PreparedLowerPnpForward {
    /// Prepare the first supported lower-edge operation: `IRP_MN_START_DEVICE`.
    ///
    /// `payload` is `raw_len` bytes of `CM_RESOURCE_LIST` followed by `translated_len` bytes.
    /// It must already be copied out of the source component before this call.
    #[allow(clippy::too_many_arguments)]
    pub fn start<P>(
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &mut IoManager<P>,
        source: SourceIrpTicket,
        consumer_domain: HostedDomainIdentity,
        consumer_address: u64,
        client: ClientId,
        requestor_tid: u64,
        raw_len: u32,
        translated_len: u32,
        payload: Vec<u8>,
    ) -> Result<Self, LowerPnpForwardError> {
        if source.domain != consumer_domain
            || (raw_len == 0) != (translated_len == 0)
            || raw_len
                .checked_add(translated_len)
                .and_then(|len| usize::try_from(len).ok())
                != Some(payload.len())
        {
            return Err(LowerPnpForwardError::InvalidStart);
        }
        let mut consumer = HostedForwardTarget::capture(io, consumer_domain, consumer_address)
            .map_err(LowerPnpForwardError::Consumer)?;
        let authority = match providers.resolve(pnp, relations, io, consumer.device_id().raw()) {
            Ok(authority) => authority,
            Err(error) => {
                consumer
                    .release(io)
                    .map_err(LowerPnpForwardError::Consumer)?;
                return Err(LowerPnpForwardError::Authority(error));
            }
        };
        if consumer_domain == authority.provider().domain() {
            consumer
                .release(io)
                .map_err(LowerPnpForwardError::Consumer)?;
            return Err(LowerPnpForwardError::SameDomain);
        }
        let mut provider = match HostedForwardTarget::capture(
            io,
            authority.provider().domain(),
            authority.provider().address(),
        ) {
            Ok(provider) => provider,
            Err(status) => {
                consumer
                    .release(io)
                    .map_err(LowerPnpForwardError::Consumer)?;
                return Err(LowerPnpForwardError::Provider(status));
            }
        };
        if provider.registration() != authority.provider()
            || provider.device_id() != consumer.device_id()
        {
            provider
                .release(io)
                .map_err(LowerPnpForwardError::Provider)?;
            consumer
                .release(io)
                .map_err(LowerPnpForwardError::Consumer)?;
            return Err(LowerPnpForwardError::WrongConsumer);
        }

        let parameters = match PnpParameters::start(raw_len, translated_len) {
            Ok(parameters) => parameters,
            Err(status) => {
                provider
                    .release(io)
                    .map_err(LowerPnpForwardError::Provider)?;
                consumer
                    .release(io)
                    .map_err(LowerPnpForwardError::Consumer)?;
                return Err(LowerPnpForwardError::Prepare(status));
            }
        };
        let provider_irp = match io.prepare_external_pnp_owned_to_exact_device(
            client,
            authority.provider().device_id(),
            requestor_tid,
            parameters,
            payload,
        ) {
            Ok(prepared) => prepared,
            Err(status) => {
                provider
                    .release(io)
                    .map_err(LowerPnpForwardError::Provider)?;
                consumer
                    .release(io)
                    .map_err(LowerPnpForwardError::Consumer)?;
                return Err(LowerPnpForwardError::Prepare(status));
            }
        };
        let identity = LowerPnpForwardIdentity {
            source,
            consumer: consumer.registration(),
            provider: authority,
        };
        Ok(Self {
            owner: Owner {
                identity,
                consumer,
                provider,
                consumer_released: false,
                provider_released: false,
            },
            provider_irp,
        })
    }

    pub const fn identity(&self) -> LowerPnpForwardIdentity {
        self.owner.identity
    }

    pub fn provider_irp(&self) -> IrpId {
        self.provider_irp.irp_id()
    }

    pub fn dispatch<P>(
        self,
        pnp: &PnpManager,
        relations: &BusRelationTable,
        providers: &AcceptedPdoProviderCatalog,
        io: &mut IoManager<P>,
        observed: LowerPnpForwardIdentity,
    ) -> LowerPnpForwardResult {
        if let Err(error) = self
            .owner
            .validate_entry(pnp, relations, providers, io, observed)
        {
            return LowerPnpForwardResult::NotEntered {
                error,
                prepared: self,
            };
        }
        let PreparedLowerPnpForward {
            owner,
            provider_irp,
        } = self;
        let expected_irp = provider_irp.irp_id();
        let outcome = match io.dispatch_prepared_external_pnp(provider_irp) {
            Ok(outcome) => outcome,
            Err(rejection) => {
                return LowerPnpForwardResult::NotEntered {
                    error: LowerPnpForwardError::Dispatch(rejection.status()),
                    prepared: PreparedLowerPnpForward {
                        owner,
                        provider_irp: rejection.into_prepared(),
                    },
                };
            }
        };
        match outcome {
            ExternalPnpDispatchResult::Returned {
                status,
                information,
                receipt,
            } => finish_terminal(owner, expected_irp, status, information, receipt, false),
            ExternalPnpDispatchResult::ReturnedPayload { receipt, .. } => {
                LowerPnpForwardResult::Rejected {
                    error: LowerPnpForwardError::UnexpectedPayload,
                    retained: RetainedLowerPnpForward {
                        owner,
                        provider_irp: expected_irp,
                        indeterminate: true,
                        transport_status: None,
                        rejected_terminal: Some(receipt),
                    },
                }
            }
            ExternalPnpDispatchResult::Pending { irp_id } => {
                LowerPnpForwardResult::Retained(RetainedLowerPnpForward {
                    owner,
                    provider_irp: irp_id,
                    indeterminate: false,
                    transport_status: None,
                    rejected_terminal: None,
                })
            }
            ExternalPnpDispatchResult::Indeterminate {
                irp_id,
                transport_status,
            } => LowerPnpForwardResult::Retained(RetainedLowerPnpForward {
                owner,
                provider_irp: irp_id,
                indeterminate: true,
                transport_status: Some(transport_status),
                rejected_terminal: None,
            }),
        }
    }

    /// Discard a preparation only while the canonical I/O manager still proves it was not entered.
    /// A foreign/stale manager returns the complete preparation. Once the canonical IRP is gone,
    /// any refused projection release moves to a non-dispatchable retained owner.
    pub fn discard<P>(self, io: &mut IoManager<P>) -> LowerPnpForwardDiscardResult {
        let PreparedLowerPnpForward {
            mut owner,
            provider_irp,
        } = self;
        if let Err(rejection) = io.discard_prepared_external_pnp(provider_irp) {
            return LowerPnpForwardDiscardResult::NotDiscarded {
                error: LowerPnpForwardError::Dispatch(rejection.status()),
                prepared: PreparedLowerPnpForward {
                    owner,
                    provider_irp: rejection.into_prepared(),
                },
            };
        }
        match owner.release(io) {
            Ok(()) => LowerPnpForwardDiscardResult::Retired,
            Err(error) => LowerPnpForwardDiscardResult::Retained {
                error,
                discarded: DiscardedLowerPnpForward { owner },
            },
        }
    }
}

impl DiscardedLowerPnpForward {
    pub fn retire<P>(mut self, io: &mut IoManager<P>) -> Result<(), (LowerPnpForwardError, Self)> {
        match self.owner.release(io) {
            Ok(()) => Ok(()),
            Err(error) => Err((error, self)),
        }
    }
}

fn validate_terminal(
    owner: &Owner,
    expected_irp: IrpId,
    receipt: &ExternalPnpTerminalReceipt,
    expected_pending: bool,
) -> Result<(), LowerPnpForwardError> {
    if receipt.irp_id() != expected_irp
        || receipt.origin_device_id() != owner.identity.provider.provider().device_id()
        || receipt.completion_device_id() != owner.identity.provider.provider().device_id()
        || receipt.minor() != nt_pnp_abi::IRP_MN_START_DEVICE
        || receipt.relation_type().is_some()
        || receipt.driver_pending() != expected_pending
    {
        return Err(LowerPnpForwardError::WrongTerminal);
    }
    if receipt.status() == NtStatus::PENDING {
        return Err(LowerPnpForwardError::PendingTerminal);
    }
    if receipt.information() != 0 {
        return Err(LowerPnpForwardError::NonzeroInformation);
    }
    Ok(())
}

fn finish_terminal(
    owner: Owner,
    expected_irp: IrpId,
    status: NtStatus,
    information: u64,
    receipt: ExternalPnpTerminalReceipt,
    expected_pending: bool,
) -> LowerPnpForwardResult {
    let error = if status != receipt.status() || information != receipt.information() {
        Some(LowerPnpForwardError::WrongTerminal)
    } else {
        validate_terminal(&owner, expected_irp, &receipt, expected_pending).err()
    };
    if let Some(error) = error {
        return LowerPnpForwardResult::Rejected {
            error,
            retained: RetainedLowerPnpForward {
                owner,
                provider_irp: expected_irp,
                indeterminate: true,
                transport_status: None,
                rejected_terminal: Some(receipt),
            },
        };
    }
    let provider_acknowledged = !receipt.driver_pending();
    LowerPnpForwardResult::Terminal(TerminalLowerPnpForward {
        owner,
        receipt,
        provider_acknowledged,
    })
}

impl RetainedLowerPnpForward {
    pub const fn identity(&self) -> LowerPnpForwardIdentity {
        self.owner.identity
    }

    pub const fn provider_irp(&self) -> IrpId {
        self.provider_irp
    }

    pub const fn is_indeterminate(&self) -> bool {
        self.indeterminate
    }

    pub const fn transport_status(&self) -> Option<NtStatus> {
        self.transport_status
    }

    pub const fn has_rejected_terminal(&self) -> bool {
        self.rejected_terminal.is_some()
    }

    pub fn complete<P>(
        self,
        io: &IoManager<P>,
        observed: LowerPnpForwardIdentity,
        receipt: ExternalPnpTerminalReceipt,
    ) -> LowerPnpForwardResult {
        if let Err(error) = self.owner.validate_targets(io, observed) {
            return LowerPnpForwardResult::Rejected {
                error,
                retained: self,
            };
        }
        if self.rejected_terminal.is_some() {
            return LowerPnpForwardResult::Rejected {
                error: LowerPnpForwardError::WrongTerminal,
                retained: self,
            };
        }
        finish_terminal(
            self.owner,
            self.provider_irp,
            receipt.status(),
            receipt.information(),
            receipt,
            true,
        )
    }
}

impl TerminalLowerPnpForward {
    pub const fn identity(&self) -> LowerPnpForwardIdentity {
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

    pub const fn provider_acknowledged(&self) -> bool {
        self.provider_acknowledged
    }

    /// Retire a pending provider completion through the exact canonical I/O manager. Synchronous
    /// returns have already been retired by dispatch and therefore need no acknowledgement.
    pub fn acknowledge_provider<P: ObjectManagerPort>(
        &mut self,
        io: &mut IoManager<P>,
    ) -> Result<(), LowerPnpForwardError> {
        if self.provider_acknowledged {
            return Ok(());
        }
        io.acknowledge_completed_irp_strict(self.receipt.irp_id())
            .map_err(LowerPnpForwardError::Provider)?;
        self.provider_acknowledged = true;
        Ok(())
    }

    fn retire_owner<P>(
        mut self,
        io: &mut IoManager<P>,
    ) -> Result<NtStatus, (LowerPnpForwardError, Self)> {
        if !self.provider_acknowledged {
            return Err((LowerPnpForwardError::ProviderAckRequired, self));
        }
        if let Err(error) = self.owner.release(io) {
            return Err((error, self));
        }
        Ok(self.receipt.status())
    }

    /// The native adapter calls this only after the source-domain completion routine has run.
    pub fn retire<P>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<NtStatus, (LowerPnpForwardError, Self)> {
        self.retire_owner(io)
    }

    /// A stopped consumer cannot run its local completion routine. Its exact source pin must be
    /// retired by the native cancellation path before using this terminal teardown operation.
    pub fn retire_after_source_stop<P>(
        self,
        io: &mut IoManager<P>,
    ) -> Result<NtStatus, (LowerPnpForwardError, Self)> {
        self.retire_owner(io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BusReportedChild, DeviceState, EnumeratedPdoRecord, PdoCapabilities, PdoProperties,
        PnpBusInformation, PropertyBlobState, GUID_BUS_TYPE_PCI, INTERFACE_TYPE_PCI_BUS,
    };
    use alloc::boxed::Box;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::{Cell, RefCell};
    use nt_io_manager::{
        DeviceCharacteristics, DeviceFlags, DeviceType, DispatchContext, DispatchOutcome,
        DispatchTarget, DriverBackendId, DriverCompletion, DriverDispatchBackend, DriverPeerId,
        DriverRecord, IrpProjection, MajorFunctionTable, MockObjectPort, PnpBackendDispatch,
    };
    use nt_types::{NtPath, ObjectId};

    struct StartBackend;

    struct PassThroughFilterBackend;

    impl DriverDispatchBackend for PassThroughFilterBackend {
        fn dispatch_irp(
            &mut self,
            _context: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            assert_eq!(irp.minor, nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS);
            Ok(DispatchOutcome::Completed {
                status: NtStatus::NOT_SUPPORTED,
                information: irp.information,
                file_context: None,
            })
        }

        fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
            Err(NtStatus::NOT_SUPPORTED)
        }
    }

    impl DriverDispatchBackend for StartBackend {
        fn dispatch_irp(
            &mut self,
            _context: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            assert_eq!(irp.major, nt_io_abi::major::IRP_MJ_PNP);
            assert_eq!(irp.minor, nt_pnp_abi::IRP_MN_START_DEVICE);
            Ok(DispatchOutcome::Completed {
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            })
        }

        fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
            Err(NtStatus::NOT_SUPPORTED)
        }
    }

    struct PendingStartBackend {
        ready: Rc<Cell<bool>>,
        pending: Rc<RefCell<Option<IrpId>>>,
    }

    impl DriverDispatchBackend for PendingStartBackend {
        fn dispatch_irp(
            &mut self,
            _context: DispatchContext<'_>,
            irp: &IrpProjection,
        ) -> Result<DispatchOutcome, NtStatus> {
            *self.pending.borrow_mut() = Some(irp.irp_id);
            Ok(DispatchOutcome::Pending)
        }

        fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
            Err(NtStatus::NOT_SUPPORTED)
        }

        fn poll_completion(&mut self) -> Option<DriverCompletion> {
            if !self.ready.get() {
                return None;
            }
            self.pending
                .borrow_mut()
                .take()
                .map(|irp_id| DriverCompletion {
                    irp_id,
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None,
                })
        }
    }

    struct Fixture {
        pnp: PnpManager,
        relations: BusRelationTable,
        io: IoManager<MockObjectPort>,
        providers: AcceptedPdoProviderCatalog,
        client: ClientId,
        consumer_domain: HostedDomainIdentity,
        consumer_address: u64,
        provider: HostedDevicePointerRegistration,
    }

    fn fixture_with_bus(
        backend: Box<dyn DriverDispatchBackend>,
        bus_information: PnpBusInformation,
    ) -> Fixture {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let backend_id = io.register_backend(backend);
        let mut dispatch = MajorFunctionTable::new();
        dispatch.set_all(DispatchTarget::DriverPeer(DriverPeerId(backend_id as u64)));
        let driver = io.register_driver(DriverRecord::new(
            ObjectId::NULL,
            NtPath::parse_str(r"\Driver\AcpiProvider").unwrap(),
            DriverBackendId(backend_id as u64),
            dispatch,
        ));
        let pdo = io
            .create_device(
                driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        let provider_domain = io.register_hosted_domain();
        let consumer_domain = io.register_hosted_domain();
        let provider = io
            .bind_hosted_device_pointer(provider_domain, 0x1000, pdo)
            .unwrap();
        io.bind_hosted_device_pointer(consumer_domain, 0x2000, pdo)
            .unwrap();

        let mut pnp = PnpManager::new();
        let parent_pdo = 0x9000;
        let parent = pnp.create_service_bound_devnode_without_resources(
            r"ROOT\TEST_BUS\0000",
            Some("TestBus"),
            parent_pdo,
        );
        for state in [
            DeviceState::DriverLoaded,
            DeviceState::AddDeviceCalled,
            DeviceState::DeviceStackBuilt,
            DeviceState::ResourcesAssigned,
            DeviceState::StartIrpSent,
            DeviceState::Started,
        ] {
            pnp.transition(parent, state).unwrap();
        }
        let child = BusReportedChild::new(
            pdo.raw(),
            r"ACPI\PNP0A08",
            "0",
            &[r"ACPI\PNP0A08"],
            &[] as &[&str],
        );
        let mut relations = BusRelationTable::new();
        relations.seed_bus_relations(parent_pdo, &[]).unwrap();
        let prepared_relation = relations
            .prepare_bus_relations(parent_pdo, core::slice::from_ref(&child))
            .unwrap();
        let parent_relation = pnp
            .claim_started_parent_relation(parent_pdo, prepared_relation.relation_identity())
            .unwrap();
        let properties = PdoProperties::enumerated(
            bus_information,
            PdoCapabilities {
                removable: false,
                eject_supported: false,
                surprise_removal_ok: false,
                raw_device_ok: false,
                address: 0,
            },
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
        );
        let prepared_child = pnp
            .prepare_enumerated_pdo_batch(vec![EnumeratedPdoRecord::new(
                child.enum_instance_path(),
                pdo.raw(),
                properties,
            )
            .with_parent_relation(parent_relation)])
            .unwrap();
        pnp.commit_enumerated_pdo_batch(prepared_child).unwrap();
        relations.commit_bus_relations(prepared_relation).unwrap();
        let mut providers = AcceptedPdoProviderCatalog::new();
        let parent_relation = pnp.parent_relation_for_pdo(pdo.raw()).unwrap();
        let prepared_providers = providers
            .prepare_relation(&mut io, parent_relation, &[(pdo.raw(), provider)])
            .unwrap();
        providers
            .commit_relation(&pnp, &relations, &io, prepared_providers)
            .unwrap();
        Fixture {
            pnp,
            relations,
            io,
            providers,
            client,
            consumer_domain,
            consumer_address: 0x2000,
            provider,
        }
    }

    fn fixture(backend: Box<dyn DriverDispatchBackend>) -> Fixture {
        fixture_with_bus(
            backend,
            PnpBusInformation {
                bus_type_guid: GUID_BUS_TYPE_PCI,
                legacy_bus_type: INTERFACE_TYPE_PCI_BUS,
                bus_number: 0,
            },
        )
    }

    fn prepare(fixture: &mut Fixture) -> PreparedLowerPnpForward {
        let source = SourceIrpTicket::new(fixture.consumer_domain, 7, 1).unwrap();
        PreparedLowerPnpForward::start(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            source,
            fixture.consumer_domain,
            fixture.consumer_address,
            fixture.client,
            44,
            0,
            0,
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn synchronous_start_uses_exact_provider_and_retires_after_source_completion() {
        let mut fixture = fixture(Box::new(StartBackend));
        let prepared = prepare(&mut fixture);
        let identity = prepared.identity();
        assert_eq!(
            fixture.io.hosted_device_pointer_count(fixture.provider),
            Ok(2)
        );
        let terminal = match prepared.dispatch(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            identity,
        ) {
            LowerPnpForwardResult::Terminal(terminal) => terminal,
            result => panic!("unexpected START result: {result:?}"),
        };
        assert_eq!(terminal.status(), NtStatus::SUCCESS);
        assert!(terminal.provider_acknowledged());
        assert_eq!(terminal.retire(&mut fixture.io).unwrap(), NtStatus::SUCCESS);
        assert_eq!(
            fixture.io.hosted_device_pointer_count(fixture.provider),
            Ok(1)
        );
        let consumer = fixture
            .io
            .hosted_device_pointer_registration(fixture.consumer_domain, fixture.consumer_address)
            .unwrap();
        assert_eq!(fixture.io.hosted_device_pointer_count(consumer), Ok(0));
    }

    #[test]
    fn unentered_start_discards_canonical_irp_and_both_forward_references() {
        let mut fixture = fixture(Box::new(StartBackend));
        let prepared = prepare(&mut fixture);
        let irp = prepared.provider_irp();
        let consumer = fixture
            .io
            .hosted_device_pointer_registration(fixture.consumer_domain, fixture.consumer_address)
            .unwrap();
        assert_eq!(fixture.io.hosted_device_pointer_count(consumer), Ok(1));
        assert_eq!(
            fixture.io.hosted_device_pointer_count(fixture.provider),
            Ok(2)
        );
        assert!(matches!(
            prepared.discard(&mut fixture.io),
            LowerPnpForwardDiscardResult::Retired
        ));
        assert!(fixture.io.irp(irp).is_none());
        assert_eq!(fixture.io.hosted_device_pointer_count(consumer), Ok(0));
        assert_eq!(
            fixture.io.hosted_device_pointer_count(fixture.provider),
            Ok(1)
        );
    }

    #[test]
    fn pending_start_keeps_both_projections_until_exact_terminal_and_ack() {
        let ready = Rc::new(Cell::new(false));
        let pending = Rc::new(RefCell::new(None));
        let mut fixture = fixture(Box::new(PendingStartBackend {
            ready: ready.clone(),
            pending: pending.clone(),
        }));
        let prepared = prepare(&mut fixture);
        let identity = prepared.identity();
        let retained = match prepared.dispatch(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            identity,
        ) {
            LowerPnpForwardResult::Retained(retained) => retained,
            result => panic!("unexpected pending START result: {result:?}"),
        };
        let irp = retained.provider_irp();
        assert_eq!(*pending.borrow(), Some(irp));
        ready.set(true);
        assert_eq!(fixture.io.pump(), 1);
        let receipt = fixture.io.take_completed_external_pnp_receipt(irp).unwrap();
        let mut terminal = match retained.complete(&fixture.io, identity, receipt) {
            LowerPnpForwardResult::Terminal(terminal) => terminal,
            result => panic!("unexpected pending terminal: {result:?}"),
        };
        assert!(!terminal.provider_acknowledged());
        let terminal = match terminal.retire(&mut fixture.io) {
            Err((LowerPnpForwardError::ProviderAckRequired, terminal)) => terminal,
            result => panic!("pending terminal retired without ACK: {result:?}"),
        };
        let mut terminal = terminal;
        terminal.acknowledge_provider(&mut fixture.io).unwrap();
        assert_eq!(terminal.retire(&mut fixture.io).unwrap(), NtStatus::SUCCESS);
        assert!(fixture.io.irp(irp).is_none());
        assert_eq!(
            fixture.io.hosted_device_pointer_count(fixture.provider),
            Ok(1)
        );
    }

    #[test]
    fn same_domain_and_unpublished_consumer_do_not_prepare_provider_irps() {
        let mut fixture = fixture(Box::new(StartBackend));
        let before = fixture.io.irp_count();
        let source = SourceIrpTicket::new(fixture.consumer_domain, 9, 1).unwrap();
        assert!(matches!(
            PreparedLowerPnpForward::start(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &mut fixture.io,
                source,
                fixture.consumer_domain,
                0xdead,
                fixture.client,
                0,
                0,
                0,
                Vec::new(),
            ),
            Err(LowerPnpForwardError::Consumer(_))
        ));
        assert_eq!(fixture.io.irp_count(), before);

        let provider_domain = fixture.provider.domain();
        let provider_source = SourceIrpTicket::new(provider_domain, 10, 1).unwrap();
        assert!(matches!(
            PreparedLowerPnpForward::start(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &mut fixture.io,
                provider_source,
                provider_domain,
                fixture.provider.address(),
                fixture.client,
                0,
                0,
                0,
                Vec::new(),
            ),
            Err(LowerPnpForwardError::SameDomain)
        ));
        assert_eq!(fixture.io.irp_count(), before);
    }

    #[test]
    fn canonical_video_start_enters_only_the_accepted_pci_provider() {
        let mut fixture = fixture(Box::new(StartBackend));
        let pdo = fixture.provider.device_id();
        let outer = fixture
            .io
            .prepare_external_pnp_owned_to_exact_device(
                fixture.client,
                pdo,
                0,
                PnpParameters::start(0, 0).unwrap(),
                Vec::new(),
            )
            .unwrap();
        let prepared = crate::PreparedAcceptedPdoPnp::start(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            outer.irp_id(),
            pdo,
            fixture.client,
            0,
            0,
            0,
            Vec::new(),
        )
        .unwrap();
        let identity = prepared.identity();
        let invocation = prepared
            .begin(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &mut fixture.io,
                identity,
            )
            .unwrap();
        let provider_irp = invocation.provider_irp();
        let returned = invocation.invoke(|_, _| {
            // Native provider entry can take a new short borrow of the manager.
            assert!(fixture.io.irp(provider_irp).is_some());
            PnpBackendDispatch::Returned {
                status: NtStatus::SUCCESS,
                information: 0,
            }
        });
        let terminal = match returned.finish(&mut fixture.io).unwrap() {
            crate::AcceptedPdoPnpResult::Terminal(terminal) => terminal,
            result => panic!("unexpected provider result: {result:?}"),
        };
        assert_eq!(terminal.status(), NtStatus::SUCCESS);
        assert_eq!(terminal.retire(&mut fixture.io).unwrap(), NtStatus::SUCCESS);
        fixture.io.discard_prepared_external_pnp(outer).unwrap();
    }

    #[test]
    fn canonical_video_start_rejects_wrong_outer_identity_before_provider_entry() {
        let mut fixture = fixture(Box::new(StartBackend));
        let pdo = fixture.provider.device_id();
        let outer = fixture
            .io
            .prepare_external_pnp_owned_to_exact_device(
                fixture.client,
                pdo,
                0,
                PnpParameters::start(0, 0).unwrap(),
                Vec::new(),
            )
            .unwrap();
        let prepared = crate::PreparedAcceptedPdoPnp::start(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            outer.irp_id(),
            pdo,
            fixture.client,
            0,
            0,
            0,
            Vec::new(),
        )
        .unwrap();
        let wrong = crate::AcceptedPdoPnpIdentity {
            outer_irp: IrpId(outer.irp_id().raw() + 1),
            ..prepared.identity()
        };
        let prepared = match prepared.begin(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            wrong,
        ) {
            Err((crate::AcceptedPdoPnpError::WrongIdentity, prepared)) => prepared,
            result => panic!("wrong outer identity entered provider: {result:?}"),
        };
        assert!(matches!(
            prepared.discard(&mut fixture.io),
            crate::AcceptedPdoPnpDiscard::Retired
        ));
        fixture.io.discard_prepared_external_pnp(outer).unwrap();
    }

    #[test]
    fn canonical_video_filter_preserves_native_unsupported_without_exporting_input_pointer() {
        let mut fixture = fixture(Box::new(PassThroughFilterBackend));
        let pdo = fixture.provider.device_id();
        let input = vec![0u8; 64];
        let outer = fixture
            .io
            .prepare_external_pnp_owned_to_exact_device(
                fixture.client,
                pdo,
                0,
                PnpParameters::filter_resource_requirements(input.len() as u32).unwrap(),
                input.clone(),
            )
            .unwrap();
        let prepared = crate::PreparedAcceptedPdoPnp::filter(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            outer.irp_id(),
            pdo,
            fixture.client,
            0,
            input,
        )
        .unwrap();
        let identity = prepared.identity();
        let invocation = prepared
            .begin(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &mut fixture.io,
                identity,
            )
            .unwrap();
        let returned = invocation.invoke(|_, _| PnpBackendDispatch::Returned {
            status: NtStatus::NOT_SUPPORTED,
            information: 0x1234_5000,
        });
        let terminal = match returned.finish(&mut fixture.io).unwrap() {
            crate::AcceptedPdoPnpResult::Terminal(terminal) => terminal,
            result => panic!("unexpected FILTER result: {result:?}"),
        };
        assert_eq!(terminal.status(), NtStatus::NOT_SUPPORTED);
        assert_eq!(terminal.information(), 0);
        // FILTER owns only an input extent. A pass-through failure returns no output buffer.
        assert!(terminal.payload().is_none());
        assert_eq!(
            terminal.retire(&mut fixture.io).unwrap(),
            NtStatus::NOT_SUPPORTED
        );
        fixture.io.discard_prepared_external_pnp(outer).unwrap();
    }

    #[test]
    fn nested_fdo_filter_consumes_only_its_outer_accepted_pdo_proof() {
        let mut fixture = fixture(Box::new(PassThroughFilterBackend));
        let pdo = fixture.provider.device_id();
        let fdo_driver = fixture
            .io
            .create_kernel_driver_with_majors(
                &NtPath::parse_str(r"\Driver\FunctionFilter").unwrap(),
                Box::new(PassThroughFilterBackend),
                &[nt_pnp_abi::IRP_MJ_PNP],
            )
            .unwrap();
        let fdo = fixture
            .io
            .create_device(
                fdo_driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        fixture.io.attach_device_to_stack(fdo, pdo).unwrap();
        let fdo_registration = fixture
            .io
            .bind_hosted_device_pointer(fixture.consumer_domain, 0x3000, fdo)
            .unwrap();
        let pdo_projection = fixture
            .io
            .hosted_device_pointer_registration(fixture.consumer_domain, fixture.consumer_address)
            .unwrap();
        let devnode = fixture.pnp.devnode_for_pdo(pdo.raw()).unwrap();
        fixture.pnp.set_fdo(devnode, fdo.raw()).unwrap();
        let requirements = vec![0x5au8; 64];
        let parameters =
            PnpParameters::filter_resource_requirements(requirements.len() as u32).unwrap();
        let outer = fixture
            .io
            .prepare_external_pnp_owned_to_exact_device(
                fixture.client,
                pdo,
                0,
                parameters,
                requirements.clone(),
            )
            .unwrap();
        let nested = fixture
            .io
            .prepare_external_pnp_owned_to_exact_device(
                fixture.client,
                fdo,
                17,
                parameters,
                requirements,
            )
            .unwrap();
        let authority = fixture
            .providers
            .resolve(&fixture.pnp, &fixture.relations, &fixture.io, pdo.raw())
            .unwrap();
        let proof_identity = crate::AcceptedPdoPnpIdentity {
            outer_irp: outer.irp_id(),
            pdo,
            minor: nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
            provider: authority,
        };
        let mut proof =
            crate::AcceptedPdoLowerFilterProof::new(proof_identity, NtStatus::NOT_SUPPORTED)
                .unwrap();
        let class_domain = fixture.io.register_hosted_domain();
        let class_source = SourceIrpTicket::new(class_domain, 7, 1).unwrap();
        let mut edge = crate::AcceptedPdoFilterEdge::capture(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &fixture.io,
            outer.irp_id(),
            nested.irp_id(),
            fdo_registration,
            pdo_projection,
            class_source,
            fixture.client,
            17,
        )
        .unwrap();
        let nested_source = SourceIrpTicket::new(fixture.consumer_domain, 9, 1).unwrap();
        let wrong_source = SourceIrpTicket::new(fixture.consumer_domain, 9, 2).unwrap();
        assert!(edge
            .bind_nested_source(outer.irp_id(), nested_source)
            .is_err());
        assert!(edge
            .bind_nested_source(nested.irp_id(), nested_source)
            .is_ok());
        assert!(edge
            .consume_proof(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &fixture.io,
                outer.irp_id(),
                nested_source,
                &mut proof,
            )
            .is_err());
        assert!(edge
            .consume_proof(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &fixture.io,
                nested.irp_id(),
                wrong_source,
                &mut proof,
            )
            .is_err());
        fixture.io.device_mut(fdo).unwrap().attached_to = None;
        assert!(matches!(
            edge.consume_proof(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &fixture.io,
                nested.irp_id(),
                nested_source,
                &mut proof,
            ),
            Err(crate::AcceptedPdoFilterEdgeError::WrongStack)
        ));
        fixture.io.device_mut(fdo).unwrap().attached_to = Some(pdo);
        assert_eq!(
            edge.consume_proof(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &fixture.io,
                nested.irp_id(),
                nested_source,
                &mut proof,
            ),
            Ok(NtStatus::NOT_SUPPORTED)
        );
        assert!(edge
            .consume_proof(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &fixture.io,
                nested.irp_id(),
                nested_source,
                &mut proof,
            )
            .is_err());
        fixture.io.discard_prepared_external_pnp(nested).unwrap();
        fixture.io.discard_prepared_external_pnp(outer).unwrap();
    }

    #[test]
    fn direct_fdo_filter_consumes_only_its_exact_accepted_pdo_proof() {
        // The PCI FDO forwards the original PDO-origin FILTER IRP directly to
        // the ACPI PDO. There is no separately constructed nested FDO IRP.
        let mut fixture = fixture(Box::new(PassThroughFilterBackend));
        let pdo = fixture.provider.device_id();
        let fdo_driver = fixture
            .io
            .create_kernel_driver_with_majors(
                &NtPath::parse_str(r"\Driver\FunctionFilter").unwrap(),
                Box::new(PassThroughFilterBackend),
                &[nt_pnp_abi::IRP_MJ_PNP],
            )
            .unwrap();
        let fdo = fixture
            .io
            .create_device(
                fdo_driver, None, DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(), DeviceFlags::empty(), 0,
            )
            .unwrap();
        fixture.io.attach_device_to_stack(fdo, pdo).unwrap();
        let fdo_registration = fixture
            .io
            .bind_hosted_device_pointer(fixture.consumer_domain, 0x3000, fdo)
            .unwrap();
        let pdo_projection = fixture
            .io
            .hosted_device_pointer_registration(fixture.consumer_domain, fixture.consumer_address)
            .unwrap();
        let devnode = fixture.pnp.devnode_for_pdo(pdo.raw()).unwrap();
        fixture.pnp.set_fdo(devnode, fdo.raw()).unwrap();
        let parameters = PnpParameters::filter_resource_requirements(64).unwrap();
        let outer = fixture.io.prepare_external_pnp_owned_to_device(
            fixture.client, pdo, 17, parameters, vec![0x5a; 64],
        ).unwrap();
        let authority = fixture.providers.resolve(
            &fixture.pnp, &fixture.relations, &fixture.io, pdo.raw(),
        ).unwrap();
        let identity = crate::AcceptedPdoPnpIdentity {
            outer_irp: outer.irp_id(), pdo,
            minor: nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
            provider: authority,
        };
        let mut proof = crate::AcceptedPdoLowerFilterProof::new(
            identity, NtStatus::NOT_SUPPORTED,
        ).unwrap();
        let source = SourceIrpTicket::new(fixture.consumer_domain, 9, 1).unwrap();
        let stale = SourceIrpTicket::new(fixture.consumer_domain, 9, 2).unwrap();
        let foreign_domain = fixture.io.register_hosted_domain();
        let foreign_source = SourceIrpTicket::new(foreign_domain, 9, 1).unwrap();
        let mut edge = crate::AcceptedPdoDirectFilterEdge::capture(
            &fixture.pnp, &fixture.relations, &fixture.providers, &fixture.io,
            outer.irp_id(), fdo_registration, pdo_projection, fixture.client, 17,
        ).unwrap();
        assert!(edge.bind_source(outer.irp_id(), foreign_source).is_err());
        edge.bind_source(outer.irp_id(), source).unwrap();
        assert!(edge.consume_proof(
            &fixture.pnp, &fixture.relations, &fixture.providers, &fixture.io,
            outer.irp_id(), stale, &mut proof,
        ).is_err());
        fixture.io.device_mut(fdo).unwrap().attached_to = None;
        assert!(edge.consume_proof(
            &fixture.pnp, &fixture.relations, &fixture.providers, &fixture.io,
            outer.irp_id(), source, &mut proof,
        ).is_err());
        fixture.io.device_mut(fdo).unwrap().attached_to = Some(pdo);
        assert_eq!(edge.consume_proof(
            &fixture.pnp, &fixture.relations, &fixture.providers, &fixture.io,
            outer.irp_id(), source, &mut proof,
        ), Ok(NtStatus::NOT_SUPPORTED));
        assert!(edge.consume_proof(
            &fixture.pnp, &fixture.relations, &fixture.providers, &fixture.io,
            outer.irp_id(), source, &mut proof,
        ).is_err());
        fixture.io.discard_prepared_external_pnp(outer).unwrap();
    }

    #[test]
    fn accepted_acpi_child_filter_enters_its_provider_and_keeps_optional_pass_through() {
        // ReactOS ACPI's PDO leaves this optional IRP's seeded status and borrowed input pointer.
        let mut fixture = fixture_with_bus(
            Box::new(PassThroughFilterBackend),
            PnpBusInformation {
                bus_type_guid: [
                    0x8a, 0xa0, 0x91, 0xb0, 0x97, 0xba, 0xd0, 0x11, 0xbd, 0x14, 0x00, 0xaa, 0x00,
                    0xb7, 0xb3, 0x2a,
                ],
                legacy_bus_type: 13,
                bus_number: 0,
            },
        );
        let pdo = fixture.provider.device_id();
        let requirements = vec![0x5au8; 64];
        let outer = fixture
            .io
            .prepare_external_pnp_owned_to_exact_device(
                fixture.client,
                pdo,
                0,
                PnpParameters::filter_resource_requirements(requirements.len() as u32).unwrap(),
                requirements.clone(),
            )
            .unwrap();
        assert_eq!(
            fixture.io.irp(outer.irp_id()).unwrap().status,
            NtStatus::NOT_SUPPORTED
        );
        let prepared = crate::PreparedAcceptedPdoPnp::filter(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            outer.irp_id(),
            pdo,
            fixture.client,
            0,
            requirements,
        )
        .unwrap();
        let identity = prepared.identity();
        let invocation = prepared
            .begin(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &mut fixture.io,
                identity,
            )
            .unwrap();
        let mut provider_entries = 0;
        let returned = invocation.invoke(|_, irp| {
            provider_entries += 1;
            assert_eq!(irp.status, NtStatus::NOT_SUPPORTED);
            PnpBackendDispatch::Returned {
                status: irp.status,
                information: 0x1234_5000,
            }
        });
        let terminal = match returned.finish(&mut fixture.io).unwrap() {
            crate::AcceptedPdoPnpResult::Terminal(terminal) => terminal,
            result => panic!("unexpected ACPI FILTER result: {result:?}"),
        };
        assert_eq!(provider_entries, 1);
        assert_eq!(terminal.status(), NtStatus::NOT_SUPPORTED);
        assert_eq!(terminal.information(), 0);
        assert!(terminal.payload().is_none());
        let mut proof =
            crate::AcceptedPdoLowerFilterProof::new(identity, terminal.status()).unwrap();
        let wrong = crate::AcceptedPdoPnpIdentity {
            outer_irp: IrpId(identity.outer_irp.raw() + 1),
            ..identity
        };
        assert_eq!(
            proof.take_for(wrong),
            Err(crate::AcceptedPdoLowerFilterProofError::WrongIdentity),
        );
        assert_eq!(proof.take_for(identity), Ok(NtStatus::NOT_SUPPORTED));
        assert_eq!(
            proof.take_for(identity),
            Err(crate::AcceptedPdoLowerFilterProofError::Consumed),
        );
        assert_eq!(
            terminal.retire(&mut fixture.io).unwrap(),
            NtStatus::NOT_SUPPORTED
        );
        fixture.io.discard_prepared_external_pnp(outer).unwrap();
    }

    #[test]
    fn canonical_video_pending_start_keeps_provider_until_exact_ack() {
        let mut fixture = fixture(Box::new(StartBackend));
        let pdo = fixture.provider.device_id();
        let outer = fixture
            .io
            .prepare_external_pnp_owned_to_exact_device(
                fixture.client,
                pdo,
                0,
                PnpParameters::start(0, 0).unwrap(),
                Vec::new(),
            )
            .unwrap();
        let prepared = crate::PreparedAcceptedPdoPnp::start(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            outer.irp_id(),
            pdo,
            fixture.client,
            0,
            0,
            0,
            Vec::new(),
        )
        .unwrap();
        let identity = prepared.identity();
        let invocation = prepared
            .begin(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &mut fixture.io,
                identity,
            )
            .unwrap();
        let provider_irp = invocation.provider_irp();
        let returned = invocation.invoke(|_, _| PnpBackendDispatch::Pending);
        let retained = match returned.finish(&mut fixture.io).unwrap() {
            crate::AcceptedPdoPnpResult::Retained(retained) => retained,
            result => panic!("unexpected pending START result: {result:?}"),
        };
        assert_eq!(retained.provider_irp(), provider_irp);
        let driver = fixture
            .io
            .irp(provider_irp)
            .unwrap()
            .current_stack()
            .unwrap()
            .driver_id;
        assert!(fixture.io.publish_driver_completion(
            driver,
            DriverCompletion {
                irp_id: provider_irp,
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            }
        ));
        let ack = retained
            .prepare_completion(&mut fixture.io, identity)
            .unwrap();
        assert_eq!(ack.completion().id, provider_irp);
        let returned = ack.invoke(|_| nt_io_manager::CompletionAcknowledgement::Acknowledged);
        let terminal = match returned.finish(&mut fixture.io).unwrap() {
            crate::AcceptedPdoPnpResult::Terminal(terminal) => terminal,
            result => panic!("unexpected pending START terminal: {result:?}"),
        };
        assert!(terminal.provider_acknowledged());
        assert_eq!(terminal.retire(&mut fixture.io).unwrap(), NtStatus::SUCCESS);
        fixture.io.discard_prepared_external_pnp(outer).unwrap();
    }

    #[test]
    fn canonical_video_pending_filter_retires_after_exact_ack_without_output() {
        let mut fixture = fixture(Box::new(PassThroughFilterBackend));
        let pdo = fixture.provider.device_id();
        let input = vec![0x5a; 64];
        let outer = fixture
            .io
            .prepare_external_pnp_owned_to_exact_device(
                fixture.client,
                pdo,
                0,
                PnpParameters::filter_resource_requirements(input.len() as u32).unwrap(),
                input.clone(),
            )
            .unwrap();
        let prepared = crate::PreparedAcceptedPdoPnp::filter(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            outer.irp_id(),
            pdo,
            fixture.client,
            0,
            input,
        )
        .unwrap();
        let identity = prepared.identity();
        let invocation = prepared
            .begin(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &mut fixture.io,
                identity,
            )
            .unwrap();
        let provider_irp = invocation.provider_irp();
        let returned = invocation.invoke(|_, _| PnpBackendDispatch::Pending);
        let retained = match returned.finish(&mut fixture.io).unwrap() {
            crate::AcceptedPdoPnpResult::Retained(retained) => retained,
            result => panic!("unexpected pending FILTER result: {result:?}"),
        };
        assert_eq!(retained.provider_irp(), provider_irp);
        assert!(!retained.is_indeterminate());
        assert!(!retained.has_rejected_terminal());
        let driver = fixture
            .io
            .irp(provider_irp)
            .unwrap()
            .current_stack()
            .unwrap()
            .driver_id;
        assert!(fixture.io.publish_driver_completion(
            driver,
            DriverCompletion {
                irp_id: provider_irp,
                status: NtStatus::SUCCESS,
                information: 0,
                file_context: None,
            }
        ));
        let ack = retained
            .prepare_completion(&mut fixture.io, identity)
            .unwrap();
        assert_eq!(ack.completion().id, provider_irp);
        let returned = ack.invoke(|_| nt_io_manager::CompletionAcknowledgement::Acknowledged);
        let terminal = match returned.finish(&mut fixture.io).unwrap() {
            crate::AcceptedPdoPnpResult::Terminal(terminal) => terminal,
            result => panic!("unexpected pending FILTER terminal: {result:?}"),
        };
        assert!(terminal.provider_acknowledged());
        assert_eq!(terminal.status(), NtStatus::SUCCESS);
        assert_eq!(terminal.information(), 0);
        assert!(terminal.payload().is_none());
        assert_eq!(terminal.retire(&mut fixture.io).unwrap(), NtStatus::SUCCESS);
        fixture.io.discard_prepared_external_pnp(outer).unwrap();
    }

    #[test]
    fn canonical_video_filter_rejects_successful_unowned_output_pointer() {
        let mut fixture = fixture(Box::new(PassThroughFilterBackend));
        let pdo = fixture.provider.device_id();
        let input = vec![0x5a; 64];
        let outer = fixture
            .io
            .prepare_external_pnp_owned_to_exact_device(
                fixture.client,
                pdo,
                0,
                PnpParameters::filter_resource_requirements(input.len() as u32).unwrap(),
                input.clone(),
            )
            .unwrap();
        let prepared = crate::PreparedAcceptedPdoPnp::filter(
            &fixture.pnp,
            &fixture.relations,
            &fixture.providers,
            &mut fixture.io,
            outer.irp_id(),
            pdo,
            fixture.client,
            0,
            input,
        )
        .unwrap();
        let identity = prepared.identity();
        let invocation = prepared
            .begin(
                &fixture.pnp,
                &fixture.relations,
                &fixture.providers,
                &mut fixture.io,
                identity,
            )
            .unwrap();
        let returned = invocation.invoke(|_, _| PnpBackendDispatch::Returned {
            status: NtStatus::SUCCESS,
            information: 0x1234_5000,
        });
        let retained = match returned.finish(&mut fixture.io).unwrap() {
            crate::AcceptedPdoPnpResult::Rejected {
                error: crate::AcceptedPdoPnpError::UnsupportedFilterOutput,
                retained,
            } => retained,
            result => panic!("unowned FILTER output was not retained: {result:?}"),
        };
        assert!(retained.is_indeterminate());
        assert!(retained.has_rejected_terminal());
        assert_eq!(retained.identity(), identity);
    }
}
