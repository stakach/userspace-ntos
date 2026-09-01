//! # `nt-pnp-manager` — the PnP Manager core
//!
//! The devnode table + the v0.1 device-lifecycle state machine (spec: NT PnP
//! Manager, Milestone 12, §8). It validates every state transition, tracks
//! service-bound device identity, PDO/FDO/driver bindings, and raw/translated
//! resource assignment, and rejects stale devnode IDs after removal. `no_std` +
//! `alloc`. It holds no driver pointers — only IDs + resource values (§7.3).

#![no_std]

extern crate alloc;

mod bus_properties;
mod bus_relations;

pub use bus_properties::*;
pub use bus_relations::*;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub use nt_pnp_abi::DeviceState;

/// A device's assigned resources (raw == translated for the simulated backend).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceAssignment {
    pub mem_start: u64,
    pub mem_length: u32,
    pub int_vector: u32,
    pub int_level: u32,
    pub int_affinity: u64,
    pub int_latched: bool,
}

/// Resource assignment for devices that do not need hardware resources.
pub const NO_RESOURCES: ResourceAssignment = ResourceAssignment {
    mem_start: 0,
    mem_length: 0,
    int_vector: 0,
    int_level: 0,
    int_affinity: 0,
    int_latched: false,
};

/// Native GUID bytes (`GUID` fields in little-endian memory order) for the buses currently
/// enumerated by the production broker.
pub const GUID_BUS_TYPE_PCI: [u8; 16] = [
    0xb0, 0xdf, 0xeb, 0xc8, 0x10, 0xb5, 0xd0, 0x11, 0x80, 0xe5, 0x00, 0xa0, 0xc9, 0x25, 0x42, 0xe3,
];
pub const GUID_BUS_TYPE_INTERNAL: [u8; 16] = [
    0x73, 0xea, 0x30, 0x15, 0x6b, 0x08, 0xd1, 0x11, 0xa0, 0x9f, 0x00, 0xc0, 0x4f, 0xc3, 0x40, 0xb1,
];

pub const INTERFACE_TYPE_PCI_BUS: u32 = 5;
pub const INTERFACE_TYPE_PNP_BUS: u32 = 15;
pub const DEVICE_ADDRESS_UNAVAILABLE: u32 = u32::MAX;

/// Exact CM claim held until the user-mode notification response has been delivered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeviceActionClaimIdentity {
    pub mount_generation: u64,
    pub sequence: u64,
    pub claim_token: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceActionNotificationState {
    Pending,
    Responded,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceActionResponseState {
    AwaitingResponse,
    Terminal { status: u32 },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceActionReplyState {
    NotReady,
    Awaiting { status: u32 },
    Delivered { status: u32 },
    Failed { status: u32 },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceActionOwnerError {
    InvalidIdentity,
    DuplicateResponse,
    WrongPhase,
    ReplyFailed,
    NotAcknowledgeable,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExistingDeviceStartDisposition {
    AlreadyStarted,
    Busy,
    RequiresAction,
    NoSuchDevice,
}

/// Classify a synchronous StartDevice request against the canonical devnode state.
///
/// A Config Manager instance alone is not evidence that its device stack has started. Callers may
/// report success without dispatch only for a canonical `Started` devnode. Absence from the hosted
/// PnP manager means the first AddDevice/START transaction is still required; CM existence is
/// validated by the caller before this classification.
pub const fn existing_device_start_disposition(
    state: Option<DeviceState>,
) -> ExistingDeviceStartDisposition {
    match state {
        Some(DeviceState::Started) => ExistingDeviceStartDisposition::AlreadyStarted,
        Some(
            DeviceState::StartIrpSent
            | DeviceState::QueryStopPending
            | DeviceState::QueryRemovePending
            | DeviceState::RemovePending,
        ) => ExistingDeviceStartDisposition::Busy,
        Some(DeviceState::Removed) => ExistingDeviceStartDisposition::NoSuchDevice,
        Some(_) | None => ExistingDeviceStartDisposition::RequiresAction,
    }
}

/// Pure coordinator for one live CM notification.
///
/// `PlugPlayControlUserResponse` retires the notification independently of the later device-install
/// worker and its `PlugPlayControlStartDevice` transaction. This owner therefore tracks only the
/// exact notification response and its syscall reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceActionOwner {
    identity: DeviceActionClaimIdentity,
    notification: DeviceActionNotificationState,
    response: DeviceActionResponseState,
    reply: DeviceActionReplyState,
}

impl DeviceActionOwner {
    pub fn new(identity: DeviceActionClaimIdentity) -> Result<Self, DeviceActionOwnerError> {
        if identity.mount_generation == 0 || identity.sequence == 0 || identity.claim_token == 0 {
            return Err(DeviceActionOwnerError::InvalidIdentity);
        }
        Ok(Self {
            identity,
            notification: DeviceActionNotificationState::Pending,
            response: DeviceActionResponseState::AwaitingResponse,
            reply: DeviceActionReplyState::NotReady,
        })
    }

    pub const fn identity(&self) -> DeviceActionClaimIdentity {
        self.identity
    }

    pub const fn notification(&self) -> DeviceActionNotificationState {
        self.notification
    }

    pub const fn response_state(&self) -> DeviceActionResponseState {
        self.response
    }

    pub const fn reply(&self) -> DeviceActionReplyState {
        self.reply
    }

    pub fn respond(&mut self) -> Result<(), DeviceActionOwnerError> {
        if self.notification == DeviceActionNotificationState::Responded {
            return Err(DeviceActionOwnerError::DuplicateResponse);
        }
        self.notification = DeviceActionNotificationState::Responded;
        Ok(())
    }

    pub fn complete_without_dispatch(&mut self, status: u32) -> Result<(), DeviceActionOwnerError> {
        if self.response != DeviceActionResponseState::AwaitingResponse {
            return Err(DeviceActionOwnerError::WrongPhase);
        }
        self.response = DeviceActionResponseState::Terminal { status };
        self.reply = DeviceActionReplyState::Awaiting { status };
        Ok(())
    }

    pub fn record_reply(
        &mut self,
        status: u32,
        delivered: bool,
    ) -> Result<(), DeviceActionOwnerError> {
        let DeviceActionReplyState::Awaiting { status: expected } = self.reply else {
            return Err(DeviceActionOwnerError::WrongPhase);
        };
        if !delivered || status != expected {
            self.reply = DeviceActionReplyState::Failed { status };
            return Err(DeviceActionOwnerError::ReplyFailed);
        }
        self.reply = DeviceActionReplyState::Delivered { status };
        Ok(())
    }

    pub const fn ready_to_acknowledge(&self) -> bool {
        matches!(
            (self.notification, self.response, self.reply),
            (
                DeviceActionNotificationState::Responded,
                DeviceActionResponseState::Terminal { status },
                DeviceActionReplyState::Delivered {
                    status: reply_status
                }
            )
                if status == reply_status
        )
    }

    pub fn acknowledge(self) -> Result<DeviceActionClaimIdentity, DeviceActionOwnerError> {
        if !self.ready_to_acknowledge() {
            return Err(DeviceActionOwnerError::NotAcknowledgeable);
        }
        Ok(self.identity)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StartDeviceRequestIdentity {
    sequence: u64,
}

impl StartDeviceRequestIdentity {
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StartDeviceCompletionKind {
    NoStartIrp,
    LifecycleTerminal,
    OwnershipLost,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StartDeviceCallPath {
    Synchronous,
    Pending,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StartDeviceReplyOutcome {
    Delivered,
    Failed,
    Abandoned,
}

const STATUS_PENDING: u32 = 0x0000_0103;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ActiveStartDeviceReply {
    Awaiting,
    Delivered { status: u32 },
    Failed { status: u32 },
    Abandoned,
}

/// Manager-minted proof that one exact canonical START IRP retired into its terminal devnode
/// state. All fields are private so syscall/reply code can carry and inspect this receipt but
/// cannot manufacture lifecycle completion from a status value.
#[derive(Debug, PartialEq, Eq)]
pub struct StartDeviceLifecycleReceipt {
    dispatch: PnpDispatchIdentity,
    pdo_device_id: u64,
    fdo_device_id: u64,
    origin_driver_id: u64,
    completion_driver_id: u64,
    completion_device_id: u64,
    driver_pending: bool,
    start_status: u32,
}

struct StartDeviceIoTerminalIdentity {
    irp_id: u64,
    pdo_device_id: u64,
    origin_driver_id: u64,
    completion_driver_id: u64,
    completion_device_id: u64,
    minor: u8,
    driver_pending: bool,
    start_status: u32,
}

impl StartDeviceLifecycleReceipt {
    pub const fn dispatch(&self) -> PnpDispatchIdentity {
        self.dispatch
    }

    pub const fn pdo_device_id(&self) -> u64 {
        self.pdo_device_id
    }

    pub const fn fdo_device_id(&self) -> u64 {
        self.fdo_device_id
    }

    pub const fn origin_driver_id(&self) -> u64 {
        self.origin_driver_id
    }

    pub const fn completion_driver_id(&self) -> u64 {
        self.completion_driver_id
    }

    pub const fn completion_device_id(&self) -> u64 {
        self.completion_device_id
    }

    pub const fn driver_pending(&self) -> bool {
        self.driver_pending
    }

    pub const fn start_status(&self) -> u32 {
        self.start_status
    }
}

#[derive(Debug, PartialEq, Eq)]
enum StartDeviceCompletion {
    NoStartIrp {
        status: u32,
    },
    Lifecycle {
        receipt: StartDeviceLifecycleReceipt,
        status: u32,
    },
    OwnershipLost {
        irp_id: u64,
        receipt: Option<StartDeviceLifecycleReceipt>,
        status: u32,
    },
}

impl StartDeviceCompletion {
    const fn kind(&self) -> StartDeviceCompletionKind {
        match self {
            Self::NoStartIrp { .. } => StartDeviceCompletionKind::NoStartIrp,
            Self::Lifecycle { .. } => StartDeviceCompletionKind::LifecycleTerminal,
            Self::OwnershipLost { .. } => StartDeviceCompletionKind::OwnershipLost,
        }
    }

    const fn status(&self) -> u32 {
        match self {
            Self::NoStartIrp { status }
            | Self::Lifecycle { status, .. }
            | Self::OwnershipLost { status, .. } => *status,
        }
    }

    const fn irp_id(&self) -> u64 {
        match self {
            Self::Lifecycle { receipt, .. } => receipt.dispatch.canonical_irp_id,
            Self::OwnershipLost { irp_id, .. } => *irp_id,
            Self::NoStartIrp { .. } => 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct StartDeviceTerminalRecord {
    identity: StartDeviceRequestIdentity,
    instance_id: String,
    completion: StartDeviceCompletionKind,
    path: StartDeviceCallPath,
    lifecycle_receipt: Option<StartDeviceLifecycleReceipt>,
    irp_id: u64,
    status: u32,
    reply_status: Option<u32>,
    reply_outcome: StartDeviceReplyOutcome,
}

impl StartDeviceTerminalRecord {
    pub const fn identity(&self) -> StartDeviceRequestIdentity {
        self.identity
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub const fn completion(&self) -> StartDeviceCompletionKind {
        self.completion
    }

    pub const fn path(&self) -> StartDeviceCallPath {
        self.path
    }

    pub const fn lifecycle_receipt(&self) -> Option<&StartDeviceLifecycleReceipt> {
        self.lifecycle_receipt.as_ref()
    }

    pub const fn irp_id(&self) -> u64 {
        self.irp_id
    }

    pub const fn status(&self) -> u32 {
        self.status
    }

    pub const fn reply_status(&self) -> Option<u32> {
        self.reply_status
    }

    pub const fn reply_outcome(&self) -> StartDeviceReplyOutcome {
        self.reply_outcome
    }

    pub const fn reply_matches(&self) -> bool {
        matches!(self.reply_outcome, StartDeviceReplyOutcome::Delivered)
            && matches!(self.reply_status, Some(status) if status == self.status)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ActiveStartDeviceRequest {
    identity: StartDeviceRequestIdentity,
    instance_id: String,
    path: StartDeviceCallPath,
    completion: Option<StartDeviceCompletion>,
    reply: ActiveStartDeviceReply,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StartDeviceLedgerError {
    InvalidInstance,
    SequenceExhausted,
    AllocationFailed,
    UnknownRequest,
    WrongPhase,
    ReplyFailed,
}

/// Exact syscall-result ledger for instance-addressed `PlugPlayControlStartDevice` requests.
///
/// Device lifecycle ownership remains in the PnP/IRP machinery. This ledger proves the separate
/// user contract: every accepted request reaches one terminal classification and that exact status
/// is delivered through its syscall reply. Terminal capacity is reserved while the request is
/// active so a pending completion cannot disappear because proof publication allocates late.
#[derive(Default)]
pub struct StartDeviceCallLedger {
    next_sequence: u64,
    started: u64,
    active: Vec<ActiveStartDeviceRequest>,
    terminal: Vec<StartDeviceTerminalRecord>,
    protocol_errors: u64,
}

impl StartDeviceCallLedger {
    pub const fn new() -> Self {
        Self {
            next_sequence: 1,
            started: 0,
            active: Vec::new(),
            terminal: Vec::new(),
            protocol_errors: 0,
        }
    }

    pub fn begin(
        &mut self,
        instance_id: &str,
    ) -> Result<StartDeviceRequestIdentity, StartDeviceLedgerError> {
        if instance_id.is_empty() {
            return Err(StartDeviceLedgerError::InvalidInstance);
        }
        if self.next_sequence == 0 {
            return Err(StartDeviceLedgerError::SequenceExhausted);
        }
        let required_terminal_spare = self.active.len().saturating_add(1);
        let terminal_spare = self.terminal.capacity().saturating_sub(self.terminal.len());
        if terminal_spare < required_terminal_spare {
            self.terminal
                .try_reserve(required_terminal_spare)
                .map_err(|_| StartDeviceLedgerError::AllocationFailed)?;
            if self.terminal.capacity().saturating_sub(self.terminal.len())
                < required_terminal_spare
            {
                return Err(StartDeviceLedgerError::AllocationFailed);
            }
        }
        self.active
            .try_reserve(1)
            .map_err(|_| StartDeviceLedgerError::AllocationFailed)?;
        let mut owned_instance = String::new();
        owned_instance
            .try_reserve_exact(instance_id.len())
            .map_err(|_| StartDeviceLedgerError::AllocationFailed)?;
        owned_instance.push_str(instance_id);
        let identity = StartDeviceRequestIdentity {
            sequence: self.next_sequence,
        };
        self.next_sequence = self.next_sequence.checked_add(1).unwrap_or(0);
        self.started = self.started.saturating_add(1);
        self.active.push(ActiveStartDeviceRequest {
            identity,
            instance_id: owned_instance,
            path: StartDeviceCallPath::Synchronous,
            completion: None,
            reply: ActiveStartDeviceReply::Awaiting,
        });
        Ok(identity)
    }

    pub fn mark_pending(
        &mut self,
        identity: StartDeviceRequestIdentity,
    ) -> Result<(), StartDeviceLedgerError> {
        let Some(request) = self
            .active
            .iter_mut()
            .find(|request| request.identity == identity)
        else {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::UnknownRequest);
        };
        if request.path != StartDeviceCallPath::Synchronous
            || request.completion.is_some()
            || request.reply != ActiveStartDeviceReply::Awaiting
        {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::WrongPhase);
        }
        request.path = StartDeviceCallPath::Pending;
        Ok(())
    }

    fn complete(
        &mut self,
        identity: StartDeviceRequestIdentity,
        completion: StartDeviceCompletion,
    ) -> Result<(), StartDeviceLedgerError> {
        let Some(request) = self
            .active
            .iter_mut()
            .find(|request| request.identity == identity)
        else {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::UnknownRequest);
        };
        if request.completion.is_some() {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::WrongPhase);
        }
        request.completion = Some(completion);
        self.finalize_if_ready(identity)?;
        Ok(())
    }

    pub fn complete_without_start_irp(
        &mut self,
        identity: StartDeviceRequestIdentity,
        status: u32,
    ) -> Result<(), StartDeviceLedgerError> {
        self.complete(identity, StartDeviceCompletion::NoStartIrp { status })
    }

    pub fn complete_protocol_without_start_irp(
        &mut self,
        identity: StartDeviceRequestIdentity,
        status: u32,
    ) -> Result<(), StartDeviceLedgerError> {
        self.protocol_errors = self.protocol_errors.saturating_add(1);
        self.complete_without_start_irp(identity, status)
    }

    pub fn complete_lifecycle(
        &mut self,
        identity: StartDeviceRequestIdentity,
        receipt: StartDeviceLifecycleReceipt,
        status: u32,
    ) -> Result<(), StartDeviceLedgerError> {
        self.complete(
            identity,
            StartDeviceCompletion::Lifecycle { receipt, status },
        )
    }

    pub fn complete_ownership_lost(
        &mut self,
        identity: StartDeviceRequestIdentity,
        irp_id: u64,
        receipt: Option<StartDeviceLifecycleReceipt>,
        status: u32,
    ) -> Result<(), StartDeviceLedgerError> {
        if irp_id == 0
            || receipt
                .as_ref()
                .is_some_and(|receipt| receipt.dispatch().canonical_irp_id != irp_id)
        {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::WrongPhase);
        }
        self.complete(
            identity,
            StartDeviceCompletion::OwnershipLost {
                irp_id,
                receipt,
                status,
            },
        )
    }

    /// Retire an outer call whose batch claimed completion while canonical START authority was
    /// still unresolved. The row remains an ownership barrier, but the protocol counter makes the
    /// impossible transition independently visible to the exactness gate.
    pub fn complete_protocol_ownership_lost(
        &mut self,
        identity: StartDeviceRequestIdentity,
        irp_id: u64,
        receipt: Option<StartDeviceLifecycleReceipt>,
        status: u32,
    ) -> Result<(), StartDeviceLedgerError> {
        self.protocol_errors = self.protocol_errors.saturating_add(1);
        self.complete_ownership_lost(identity, irp_id, receipt, status)
    }

    pub fn record_reply(
        &mut self,
        identity: StartDeviceRequestIdentity,
        reply_status: u32,
        delivered: bool,
    ) -> Result<(), StartDeviceLedgerError> {
        let Some(request) = self
            .active
            .iter_mut()
            .find(|request| request.identity == identity)
        else {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::UnknownRequest);
        };
        let Some(completion) = request.completion.as_ref() else {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::WrongPhase);
        };
        if request.reply != ActiveStartDeviceReply::Awaiting {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::WrongPhase);
        }
        let reply_matches = delivered && completion.status() == reply_status;
        request.reply = if reply_matches {
            ActiveStartDeviceReply::Delivered {
                status: reply_status,
            }
        } else {
            ActiveStartDeviceReply::Failed {
                status: reply_status,
            }
        };
        self.finalize_if_ready(identity)?;
        if !reply_matches {
            return Err(StartDeviceLedgerError::ReplyFailed);
        }
        Ok(())
    }

    pub fn abandon(
        &mut self,
        identity: StartDeviceRequestIdentity,
    ) -> Result<(), StartDeviceLedgerError> {
        let Some(request) = self
            .active
            .iter_mut()
            .find(|request| request.identity == identity)
        else {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::UnknownRequest);
        };
        if request.path != StartDeviceCallPath::Pending
            || request.reply != ActiveStartDeviceReply::Awaiting
        {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::WrongPhase);
        }
        request.reply = ActiveStartDeviceReply::Abandoned;
        self.finalize_if_ready(identity)
    }

    fn finalize_if_ready(
        &mut self,
        identity: StartDeviceRequestIdentity,
    ) -> Result<(), StartDeviceLedgerError> {
        let Some(index) = self
            .active
            .iter()
            .position(|request| request.identity == identity)
        else {
            self.protocol_errors = self.protocol_errors.saturating_add(1);
            return Err(StartDeviceLedgerError::UnknownRequest);
        };
        if self.active[index].completion.is_none() {
            return Ok(());
        }
        let (reply_status, reply_outcome) = match self.active[index].reply {
            ActiveStartDeviceReply::Awaiting => return Ok(()),
            ActiveStartDeviceReply::Delivered { status } => {
                (Some(status), StartDeviceReplyOutcome::Delivered)
            }
            ActiveStartDeviceReply::Failed { status } => {
                (Some(status), StartDeviceReplyOutcome::Failed)
            }
            ActiveStartDeviceReply::Abandoned => (None, StartDeviceReplyOutcome::Abandoned),
        };
        let request = self.active.swap_remove(index);
        let completion = request
            .completion
            .expect("completed START request lost its result during retirement");
        let completion_kind = completion.kind();
        let irp_id = completion.irp_id();
        let status = completion.status();
        let lifecycle_receipt = match completion {
            StartDeviceCompletion::Lifecycle { receipt, .. } => Some(receipt),
            StartDeviceCompletion::OwnershipLost { receipt, .. } => receipt,
            StartDeviceCompletion::NoStartIrp { .. } => None,
        };
        debug_assert!(self.terminal.len() < self.terminal.capacity());
        self.terminal.push(StartDeviceTerminalRecord {
            identity,
            instance_id: request.instance_id,
            completion: completion_kind,
            path: request.path,
            lifecycle_receipt,
            irp_id,
            status,
            reply_status,
            reply_outcome,
        });
        Ok(())
    }

    pub const fn started(&self) -> u64 {
        self.started
    }

    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    pub fn terminal_rows(&self) -> &[StartDeviceTerminalRecord] {
        &self.terminal
    }

    pub const fn protocol_errors(&self) -> u64 {
        self.protocol_errors
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PnpBusInformation {
    pub bus_type_guid: [u8; 16],
    pub legacy_bus_type: u32,
    pub bus_number: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdoCapabilities {
    pub removable: bool,
    pub eject_supported: bool,
    pub surprise_removal_ok: bool,
    pub address: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceRemovalPolicy {
    ExpectNoRemoval = 1,
    ExpectOrderlyRemoval = 2,
    ExpectSurpriseRemoval = 3,
}

impl DeviceRemovalPolicy {
    pub fn from_capabilities(capabilities: &PdoCapabilities) -> Self {
        if !capabilities.removable {
            Self::ExpectNoRemoval
        } else if capabilities.eject_supported && !capabilities.surprise_removal_ok {
            Self::ExpectOrderlyRemoval
        } else {
            Self::ExpectSurpriseRemoval
        }
    }
}

/// PnP must distinguish a bus query that has not run from a successful query that returned no
/// descriptors. Both differ from a present native variable-length structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropertyBlobState {
    Unqueried,
    KnownNone,
    Present(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdoProperties {
    pub bus_information: Option<PnpBusInformation>,
    pub capabilities: Option<PdoCapabilities>,
    pub removal_policy: Option<DeviceRemovalPolicy>,
    pub boot_resources_raw: PropertyBlobState,
    pub boot_resources_translated: PropertyBlobState,
    /// Initial requirements returned by the bus before the function stack is built.
    pub resource_requirements: PropertyBlobState,
    /// Requirements after `IRP_MN_FILTER_RESOURCE_REQUIREMENTS` has traversed the function stack.
    pub filtered_resource_requirements: PropertyBlobState,
    pub allocated_resources_raw: PropertyBlobState,
    pub allocated_resources_translated: PropertyBlobState,
}

impl PdoProperties {
    pub fn from_bus_queries(
        bus_information: Option<PnpBusInformation>,
        capabilities: Option<PdoCapabilities>,
        boot_resources_raw: PropertyBlobState,
        boot_resources_translated: PropertyBlobState,
        resource_requirements: PropertyBlobState,
    ) -> Self {
        let removal_policy = capabilities
            .as_ref()
            .map(DeviceRemovalPolicy::from_capabilities);
        Self {
            bus_information,
            capabilities,
            removal_policy,
            boot_resources_raw,
            boot_resources_translated,
            resource_requirements,
            filtered_resource_requirements: PropertyBlobState::Unqueried,
            allocated_resources_raw: PropertyBlobState::Unqueried,
            allocated_resources_translated: PropertyBlobState::Unqueried,
        }
    }

    pub fn enumerated(
        bus_information: PnpBusInformation,
        capabilities: PdoCapabilities,
        boot_resources_raw: PropertyBlobState,
        boot_resources_translated: PropertyBlobState,
        resource_requirements: PropertyBlobState,
    ) -> Self {
        Self::from_bus_queries(
            Some(bus_information),
            Some(capabilities),
            boot_resources_raw,
            boot_resources_translated,
            resource_requirements,
        )
    }

    fn immutable_identity_eq(&self, other: &Self) -> bool {
        self.bus_information == other.bus_information
            && self.capabilities == other.capabilities
            && self.removal_policy == other.removal_policy
            && self.boot_resources_raw == other.boot_resources_raw
            && self.boot_resources_translated == other.boot_resources_translated
            && self.resource_requirements == other.resource_requirements
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PnpDevicePropertyValue<'a> {
    Bytes(&'a [u8]),
    U32(u32),
    Guid([u8; 16]),
}

impl PnpDevicePropertyValue<'_> {
    pub fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::U32(_) => 4,
            Self::Guid(_) => 16,
        }
    }

    pub fn copy_to(&self, out: &mut [u8]) -> bool {
        if out.len() != self.len() {
            return false;
        }
        match self {
            Self::Bytes(bytes) => out.copy_from_slice(bytes),
            Self::U32(value) => out.copy_from_slice(&value.to_le_bytes()),
            Self::Guid(guid) => out.copy_from_slice(guid),
        }
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PnpPropertyError {
    StalePdo,
    InvalidProperty,
    ObjectNameNotFound,
    DeviceNotReady,
}

/// The MMIO interrupt resource shape used by unit tests.
#[cfg(test)]
const MMIO_INTERRUPT_TEST_RESOURCES: ResourceAssignment = ResourceAssignment {
    mem_start: 0x1000_0000,
    mem_length: 0x1000,
    int_vector: 5,
    int_level: 5,
    int_affinity: 1,
    int_latched: false,
};

/// Why a PnP operation was rejected (spec §8.3, §25).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PnpError {
    /// The requested state transition is not allowed from the current state.
    InvalidTransition,
    /// The devnode ID is unknown or refers to a removed (stale) devnode.
    StaleId,
    InvalidIdentity,
    ConflictingPdo,
    ConflictingStack,
    DispatchInFlight,
    StaleDispatch,
    StalePublication,
    InsufficientResources,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PnpMinor {
    StartDevice,
    QueryRemoveDevice,
    RemoveDevice,
    CancelRemoveDevice,
    StopDevice,
    QueryStopDevice,
    CancelStopDevice,
    SurpriseRemoval,
}

impl PnpMinor {
    pub const fn raw(self) -> u8 {
        match self {
            Self::StartDevice => nt_pnp_abi::IRP_MN_START_DEVICE,
            Self::QueryRemoveDevice => nt_pnp_abi::IRP_MN_QUERY_REMOVE_DEVICE,
            Self::RemoveDevice => nt_pnp_abi::IRP_MN_REMOVE_DEVICE,
            Self::CancelRemoveDevice => nt_pnp_abi::IRP_MN_CANCEL_REMOVE_DEVICE,
            Self::StopDevice => nt_pnp_abi::IRP_MN_STOP_DEVICE,
            Self::QueryStopDevice => nt_pnp_abi::IRP_MN_QUERY_STOP_DEVICE,
            Self::CancelStopDevice => nt_pnp_abi::IRP_MN_CANCEL_STOP_DEVICE,
            Self::SurpriseRemoval => nt_pnp_abi::IRP_MN_SURPRISE_REMOVAL,
        }
    }
}

/// Exact ownership of one PnP IRP while it is outside the manager.
///
/// The fields are private so only the manager that began the dispatch can validate and complete it.
#[derive(Debug, PartialEq, Eq)]
pub struct PnpDispatchToken {
    devnode_id: u64,
    devnode_generation: u64,
    dispatch_generation: u64,
    canonical_irp_id: u64,
    minor: PnpMinor,
}

/// Read-only identity of a dispatch authority. This does not permit callers to forge or complete a
/// dispatch; the opaque token remains required for lifecycle mutation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PnpDispatchIdentity {
    pub devnode_id: u64,
    pub devnode_generation: u64,
    pub dispatch_generation: u64,
    pub canonical_irp_id: u64,
    pub minor: PnpMinor,
}

impl PnpDispatchToken {
    pub const fn identity(&self) -> PnpDispatchIdentity {
        PnpDispatchIdentity {
            devnode_id: self.devnode_id,
            devnode_generation: self.devnode_generation,
            dispatch_generation: self.dispatch_generation,
            canonical_irp_id: self.canonical_irp_id,
            minor: self.minor,
        }
    }
}

/// Exact authority to publish `Removed` after the returned REMOVE IRP's external teardown commits.
#[derive(Debug, PartialEq, Eq)]
pub struct PnpRemovalToken {
    devnode_id: u64,
    devnode_generation: u64,
    remove_dispatch_generation: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct PendingPnpDispatch {
    generation: u64,
    canonical_irp_id: u64,
    minor: PnpMinor,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct PnpNegotiation {
    minor: PnpMinor,
    accepted: bool,
}

struct Devnode {
    id: u64,
    generation: u64,
    instance_id: Option<String>,
    service: Option<String>,
    state: DeviceState,
    pdo_object_id: u64,
    fdo_object_id: u64,
    driver_id: u64,
    resources: ResourceAssignment,
    pdo_properties: Option<PdoProperties>,
    pending_dispatch: Option<PendingPnpDispatch>,
    negotiation: Option<PnpNegotiation>,
    remove_ready: Option<u64>,
}

/// Complete PnP-owned identity and immutable bus properties for one enumerated canonical PDO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumeratedPdoRecord {
    pub instance_id: String,
    pub pdo_object_id: u64,
    pub properties: PdoProperties,
}

impl EnumeratedPdoRecord {
    pub fn new(instance_id: String, pdo_object_id: u64, properties: PdoProperties) -> Self {
        Self {
            instance_id,
            pdo_object_id,
            properties,
        }
    }
}

enum PreparedEnumeratedPdo {
    Existing {
        record: EnumeratedPdoRecord,
        id: u64,
        generation: u64,
    },
    New {
        record: EnumeratedPdoRecord,
        id: u64,
        generation: u64,
    },
}

impl PreparedEnumeratedPdo {
    const fn id(&self) -> u64 {
        match self {
            Self::Existing { id, .. } | Self::New { id, .. } => *id,
        }
    }
}

/// Fully owned and capacity-reserved PDO publication transaction.
///
/// Preparation performs every fallible allocation. Commit only revalidates the manager insertion
/// generation and immutable identities before moving prebuilt records into reserved table slots.
pub struct PreparedEnumeratedPdoBatch {
    base_devnode_count: usize,
    base_next_id: u64,
    base_next_gen: u64,
    committed_next_id: u64,
    committed_next_gen: u64,
    new_count: usize,
    records: Vec<PreparedEnumeratedPdo>,
}

impl PreparedEnumeratedPdoBatch {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn devnode_id(&self, index: usize) -> Option<u64> {
        self.records.get(index).map(PreparedEnumeratedPdo::id)
    }
}

/// Whether the v0.1 state machine permits `from -> to` (spec §8.2/§8.3). `Failed` is
/// reachable from any active state.
pub fn can_transition(from: DeviceState, to: DeviceState) -> bool {
    use DeviceState::*;
    if to == Failed {
        return from != Removed;
    }
    matches!(
        (from, to),
        (Uninitialized, Enumerated)
            | (Enumerated, DriverLoaded)
            | (DriverLoaded, AddDeviceCalled)
            | (AddDeviceCalled, DeviceStackBuilt)
            | (DeviceStackBuilt, ResourcesAssigned)
            | (ResourcesAssigned, StartIrpSent)
            | (StartIrpSent, Started)
            | (ResourcesAssigned, DeviceStackBuilt) // assignment rollback
            // Started -> stop / remove paths.
            | (Started, QueryStopPending)
            | (Started, QueryRemovePending)
            | (QueryStopPending, Stopped)
            | (QueryStopPending, Started) // cancel-stop
            | (Stopped, ResourcesAssigned) // rebalance before restart
            | (Stopped, StartIrpSent) // restart
            | (Stopped, RemovePending)
            | (Failed, RemovePending)
            | (QueryRemovePending, RemovePending)
            | (QueryRemovePending, Started) // cancel-remove
    )
}

/// The PnP Manager: a service-bound devnode table and lifecycle state machine.
#[derive(Default)]
pub struct PnpManager {
    devnodes: Vec<Devnode>,
    next_id: u64,
    next_gen: u64,
    next_dispatch_gen: u64,
}

impl PnpManager {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            next_gen: 1,
            next_dispatch_gen: 1,
            ..Default::default()
        }
    }

    fn find(&self, id: u64) -> Option<&Devnode> {
        self.devnodes.iter().find(|d| d.id == id)
    }
    fn find_mut(&mut self, id: u64) -> Option<&mut Devnode> {
        self.devnodes.iter_mut().find(|d| d.id == id)
    }

    fn push_devnode(
        &mut self,
        instance_id: Option<&str>,
        service: Option<&str>,
        pdo_object_id: u64,
        resources: ResourceAssignment,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let generation = self.next_gen;
        self.next_gen += 1;
        self.devnodes.push(Devnode {
            id,
            generation,
            instance_id: instance_id.map(ToString::to_string),
            service: service.map(ToString::to_string),
            state: DeviceState::Enumerated,
            pdo_object_id,
            fdo_object_id: 0,
            driver_id: 0,
            resources,
            pdo_properties: None,
            pending_dispatch: None,
            negotiation: None,
            remove_ready: None,
        });
        id
    }

    /// Enumerate a registry/service-bound devnode in state `Enumerated`.
    ///
    /// The Configuration Manager owns `Enum\<InstanceId>` parsing and service binding. The PnP
    /// Manager records the already-resolved identity plus resource assignment and owns only the
    /// lifecycle state.
    pub fn create_service_bound_devnode(
        &mut self,
        instance_id: &str,
        service: Option<&str>,
        pdo_object_id: u64,
        resources: ResourceAssignment,
    ) -> u64 {
        self.push_devnode(Some(instance_id), service, pdo_object_id, resources)
    }

    /// Enumerate a service-bound devnode with no assigned hardware resources.
    pub fn create_service_bound_devnode_without_resources(
        &mut self,
        instance_id: &str,
        service: Option<&str>,
        pdo_object_id: u64,
    ) -> u64 {
        self.create_service_bound_devnode(instance_id, service, pdo_object_id, NO_RESOURCES)
    }

    fn matching_enumerated_pdo<'a>(
        &'a self,
        record: &EnumeratedPdoRecord,
    ) -> Result<Option<&'a Devnode>, PnpError> {
        let mut matching = None;
        for devnode in &self.devnodes {
            let pdo_matches = devnode.pdo_object_id == record.pdo_object_id;
            let instance_matches = devnode
                .instance_id
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(&record.instance_id));
            if !pdo_matches && !instance_matches {
                continue;
            }
            if devnode.state == DeviceState::Removed {
                if pdo_matches {
                    return Err(PnpError::ConflictingPdo);
                }
                continue;
            }
            if matching.is_some_and(|prior: &Devnode| prior.id != devnode.id) {
                return Err(PnpError::ConflictingPdo);
            }
            matching = Some(devnode);
        }
        let Some(devnode) = matching else {
            return Ok(None);
        };
        if devnode.pdo_object_id != record.pdo_object_id
            || !devnode
                .instance_id
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(&record.instance_id))
            || !devnode
                .pdo_properties
                .as_ref()
                .is_some_and(|properties| properties.immutable_identity_eq(&record.properties))
        {
            return Err(PnpError::ConflictingPdo);
        }
        Ok(Some(devnode))
    }

    /// Validate and reserve one atomic batch of canonical PDO publications.
    ///
    /// Records may name an exact existing live devnode, which is retained idempotently. Every new
    /// devnode ID, generation, owned string/property record, and destination table slot is prepared
    /// here so [`Self::commit_enumerated_pdo_batch`] does not allocate.
    pub fn prepare_enumerated_pdo_batch(
        &mut self,
        records: Vec<EnumeratedPdoRecord>,
    ) -> Result<PreparedEnumeratedPdoBatch, PnpError> {
        for (index, record) in records.iter().enumerate() {
            if record.instance_id.is_empty() || record.pdo_object_id == 0 {
                return Err(PnpError::InvalidIdentity);
            }
            if records[..index].iter().any(|prior| {
                prior.pdo_object_id == record.pdo_object_id
                    || prior.instance_id.eq_ignore_ascii_case(&record.instance_id)
            }) {
                return Err(PnpError::ConflictingPdo);
            }
        }

        let base_next_id = self.next_id;
        let base_next_gen = self.next_gen;
        let mut committed_next_id = base_next_id;
        let mut committed_next_gen = base_next_gen;
        let mut new_count = 0usize;
        let mut prepared = Vec::new();
        prepared
            .try_reserve(records.len())
            .map_err(|_| PnpError::InsufficientResources)?;
        for record in records {
            if let Some(existing) = self.matching_enumerated_pdo(&record)? {
                prepared.push(PreparedEnumeratedPdo::Existing {
                    record,
                    id: existing.id,
                    generation: existing.generation,
                });
                continue;
            }
            let id = committed_next_id;
            let generation = committed_next_gen;
            committed_next_id = committed_next_id
                .checked_add(1)
                .ok_or(PnpError::InsufficientResources)?;
            committed_next_gen = committed_next_gen
                .checked_add(1)
                .ok_or(PnpError::InsufficientResources)?;
            new_count = new_count
                .checked_add(1)
                .ok_or(PnpError::InsufficientResources)?;
            prepared.push(PreparedEnumeratedPdo::New {
                record,
                id,
                generation,
            });
        }
        self.devnodes
            .try_reserve(new_count)
            .map_err(|_| PnpError::InsufficientResources)?;
        Ok(PreparedEnumeratedPdoBatch {
            base_devnode_count: self.devnodes.len(),
            base_next_id,
            base_next_gen,
            committed_next_id,
            committed_next_gen,
            new_count,
            records: prepared,
        })
    }

    /// Commit a prepared PDO batch without allocation or partial publication.
    pub fn commit_enumerated_pdo_batch(
        &mut self,
        prepared: PreparedEnumeratedPdoBatch,
    ) -> Result<(), PnpError> {
        let committed_len = self
            .devnodes
            .len()
            .checked_add(prepared.new_count)
            .ok_or(PnpError::StalePublication)?;
        if self.devnodes.len() != prepared.base_devnode_count
            || self.next_id != prepared.base_next_id
            || self.next_gen != prepared.base_next_gen
            || committed_len > self.devnodes.capacity()
        {
            return Err(PnpError::StalePublication);
        }
        for entry in &prepared.records {
            match entry {
                PreparedEnumeratedPdo::Existing {
                    record,
                    id,
                    generation,
                } => {
                    let existing = self
                        .matching_enumerated_pdo(record)
                        .map_err(|_| PnpError::StalePublication)?
                        .filter(|devnode| {
                            devnode.id == *id
                                && devnode.generation == *generation
                                && devnode.state != DeviceState::Removed
                        });
                    if existing.is_none() {
                        return Err(PnpError::StalePublication);
                    }
                }
                PreparedEnumeratedPdo::New { record, .. } => {
                    if self
                        .matching_enumerated_pdo(record)
                        .map_err(|_| PnpError::StalePublication)?
                        .is_some()
                    {
                        return Err(PnpError::StalePublication);
                    }
                }
            }
        }

        for entry in prepared.records {
            let PreparedEnumeratedPdo::New {
                record,
                id,
                generation,
            } = entry
            else {
                continue;
            };
            debug_assert!(self.devnodes.len() < self.devnodes.capacity());
            self.devnodes.push(Devnode {
                id,
                generation,
                instance_id: Some(record.instance_id),
                service: None,
                state: DeviceState::Enumerated,
                pdo_object_id: record.pdo_object_id,
                fdo_object_id: 0,
                driver_id: 0,
                resources: NO_RESOURCES,
                pdo_properties: Some(record.properties),
                pending_dispatch: None,
                negotiation: None,
                remove_ready: None,
            });
        }
        self.next_id = prepared.committed_next_id;
        self.next_gen = prepared.committed_next_gen;
        Ok(())
    }

    /// Publish the immutable bus/capability state owned by one enumerated canonical PDO before a
    /// function driver's `AddDevice` is allowed to run. Re-publication is idempotent only for the
    /// exact same devnode identity and property record.
    pub fn register_enumerated_pdo(
        &mut self,
        instance_id: &str,
        pdo_object_id: u64,
        properties: PdoProperties,
    ) -> Result<u64, PnpError> {
        let mut owned_instance = String::new();
        owned_instance
            .try_reserve(instance_id.len())
            .map_err(|_| PnpError::InsufficientResources)?;
        owned_instance.push_str(instance_id);
        let mut records = Vec::new();
        records
            .try_reserve(1)
            .map_err(|_| PnpError::InsufficientResources)?;
        records.push(EnumeratedPdoRecord::new(
            owned_instance,
            pdo_object_id,
            properties,
        ));
        let prepared = self.prepare_enumerated_pdo_batch(records)?;
        let id = prepared.devnode_id(0).ok_or(PnpError::InvalidIdentity)?;
        self.commit_enumerated_pdo_batch(prepared)?;
        Ok(id)
    }

    pub fn devnode_for_pdo(&self, pdo_object_id: u64) -> Option<u64> {
        self.devnodes
            .iter()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .map(|devnode| devnode.id)
    }

    pub fn devnode_for_instance(&self, instance_id: &str) -> Option<u64> {
        self.devnodes
            .iter()
            .find(|devnode| {
                devnode.state != DeviceState::Removed
                    && devnode
                        .instance_id
                        .as_deref()
                        .is_some_and(|current| current.eq_ignore_ascii_case(instance_id))
            })
            .map(|devnode| devnode.id)
    }

    pub fn enumerated_pdo_properties(&self, pdo_object_id: u64) -> Option<&PdoProperties> {
        self.devnodes
            .iter()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.state != DeviceState::Removed
                    && devnode.pdo_properties.is_some()
            })
            .and_then(|devnode| devnode.pdo_properties.as_ref())
    }

    /// Publish a successfully built function stack as one atomic lifecycle step.
    ///
    /// AddDevice execution and canonical I/O-manager attachment happen outside this crate. Their
    /// identities become authoritative here only after both have completed.
    pub fn commit_device_stack(
        &mut self,
        pdo_object_id: u64,
        fdo_object_id: u64,
        driver_id: u64,
    ) -> Result<u64, PnpError> {
        if pdo_object_id == 0 || fdo_object_id == 0 || driver_id == 0 {
            return Err(PnpError::InvalidIdentity);
        }
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id && devnode.pdo_properties.is_some()
            })
            .ok_or(PnpError::StaleId)?;
        if devnode.state == DeviceState::Removed {
            return Err(PnpError::StaleId);
        }
        if devnode.fdo_object_id != 0 || devnode.driver_id != 0 {
            return if devnode.fdo_object_id == fdo_object_id
                && devnode.driver_id == driver_id
                && matches!(
                    devnode.state,
                    DeviceState::DeviceStackBuilt
                        | DeviceState::ResourcesAssigned
                        | DeviceState::StartIrpSent
                        | DeviceState::Started
                        | DeviceState::QueryStopPending
                        | DeviceState::Stopped
                        | DeviceState::QueryRemovePending
                        | DeviceState::RemovePending
                ) {
                Ok(devnode.id)
            } else {
                Err(PnpError::ConflictingStack)
            };
        }
        if devnode.state != DeviceState::Enumerated
            || devnode.pending_dispatch.is_some()
            || devnode.negotiation.is_some()
            || devnode.remove_ready.is_some()
        {
            return Err(PnpError::InvalidTransition);
        }
        devnode.fdo_object_id = fdo_object_id;
        devnode.driver_id = driver_id;
        devnode.state = DeviceState::DeviceStackBuilt;
        Ok(devnode.id)
    }

    /// Roll back a stack that never became externally visible to PnP clients.
    pub fn rollback_device_stack(
        &mut self,
        pdo_object_id: u64,
        fdo_object_id: u64,
        driver_id: u64,
    ) -> Result<(), PnpError> {
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id && devnode.pdo_properties.is_some()
            })
            .ok_or(PnpError::StaleId)?;
        if devnode.state != DeviceState::DeviceStackBuilt
            || devnode.pending_dispatch.is_some()
            || devnode.negotiation.is_some()
            || devnode.remove_ready.is_some()
        {
            return Err(PnpError::InvalidTransition);
        }
        if devnode.fdo_object_id != fdo_object_id || devnode.driver_id != driver_id {
            return Err(PnpError::ConflictingStack);
        }
        devnode.fdo_object_id = 0;
        devnode.driver_id = 0;
        devnode.state = DeviceState::Enumerated;
        Ok(())
    }

    pub fn commit_resource_assignment(
        &mut self,
        pdo_object_id: u64,
        raw: Vec<u8>,
        translated: Vec<u8>,
    ) -> Result<(), PnpError> {
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .ok_or(PnpError::StaleId)?;
        let properties = devnode.pdo_properties.as_mut().unwrap();
        let raw = if raw.is_empty() {
            PropertyBlobState::KnownNone
        } else {
            PropertyBlobState::Present(raw)
        };
        let translated = if translated.is_empty() {
            PropertyBlobState::KnownNone
        } else {
            PropertyBlobState::Present(translated)
        };
        if devnode.state == DeviceState::ResourcesAssigned {
            return if properties.allocated_resources_raw == raw
                && properties.allocated_resources_translated == translated
            {
                Ok(())
            } else {
                Err(PnpError::InvalidTransition)
            };
        }
        if !matches!(
            devnode.state,
            DeviceState::DeviceStackBuilt | DeviceState::Stopped
        ) || devnode.pending_dispatch.is_some()
            || devnode.negotiation.is_some()
            || devnode.remove_ready.is_some()
        {
            return Err(PnpError::InvalidTransition);
        }
        properties.allocated_resources_raw = raw;
        properties.allocated_resources_translated = translated;
        devnode.state = DeviceState::ResourcesAssigned;
        Ok(())
    }

    /// Release the exact hardware assignment after a returned STOP while retaining the built
    /// function stack for a later rebalance and START.
    pub fn release_stopped_resource_assignment(
        &mut self,
        pdo_object_id: u64,
    ) -> Result<(), PnpError> {
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .ok_or(PnpError::StaleId)?;
        if devnode.state != DeviceState::Stopped
            || devnode.pending_dispatch.is_some()
            || devnode.negotiation.is_some()
            || devnode.remove_ready.is_some()
        {
            return Err(PnpError::InvalidTransition);
        }
        let properties = devnode.pdo_properties.as_mut().unwrap();
        properties.allocated_resources_raw = PropertyBlobState::Unqueried;
        properties.allocated_resources_translated = PropertyBlobState::Unqueried;
        properties.filtered_resource_requirements = PropertyBlobState::Unqueried;
        Ok(())
    }

    pub fn commit_filtered_resource_requirements(
        &mut self,
        pdo_object_id: u64,
        filtered: Vec<u8>,
    ) -> Result<(), PnpError> {
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .ok_or(PnpError::StaleId)?;
        if !matches!(
            devnode.state,
            DeviceState::DeviceStackBuilt | DeviceState::Stopped
        ) || devnode.pending_dispatch.is_some()
            || devnode.negotiation.is_some()
            || devnode.remove_ready.is_some()
        {
            return Err(PnpError::InvalidTransition);
        }
        devnode
            .pdo_properties
            .as_mut()
            .unwrap()
            .filtered_resource_requirements = if filtered.is_empty() {
            PropertyBlobState::KnownNone
        } else {
            PropertyBlobState::Present(filtered)
        };
        Ok(())
    }

    pub fn clear_resource_assignment(&mut self, pdo_object_id: u64) -> Result<(), PnpError> {
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .ok_or(PnpError::StaleId)?;
        if devnode.pending_dispatch.is_some()
            || devnode.negotiation.is_some()
            || devnode.remove_ready.is_some()
        {
            return Err(PnpError::DispatchInFlight);
        }
        if devnode.state == DeviceState::DeviceStackBuilt {
            return Ok(());
        }
        if devnode.state != DeviceState::ResourcesAssigned {
            return Err(PnpError::InvalidTransition);
        }
        let properties = devnode.pdo_properties.as_mut().unwrap();
        properties.allocated_resources_raw = PropertyBlobState::Unqueried;
        properties.allocated_resources_translated = PropertyBlobState::Unqueried;
        properties.filtered_resource_requirements = PropertyBlobState::Unqueried;
        devnode.state = DeviceState::DeviceStackBuilt;
        Ok(())
    }

    /// Begin one canonical PnP dispatch and return its exact completion authority.
    pub fn begin_pnp_dispatch(
        &mut self,
        pdo_object_id: u64,
        minor: PnpMinor,
        canonical_irp_id: u64,
    ) -> Result<PnpDispatchToken, PnpError> {
        if canonical_irp_id == 0 {
            return Err(PnpError::InvalidIdentity);
        }
        let dispatch_generation = self.next_dispatch_gen;
        let next_dispatch_generation = dispatch_generation
            .checked_add(1)
            .ok_or(PnpError::InsufficientResources)?;
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id && devnode.pdo_properties.is_some()
            })
            .ok_or(PnpError::StaleId)?;
        if devnode.state == DeviceState::Removed {
            return Err(PnpError::StaleId);
        }
        if devnode.pending_dispatch.is_some() || devnode.remove_ready.is_some() {
            return Err(PnpError::DispatchInFlight);
        }
        let prior_state = devnode.state;
        let allowed = match minor {
            PnpMinor::StartDevice => matches!(
                prior_state,
                DeviceState::ResourcesAssigned | DeviceState::Stopped
            ),
            PnpMinor::QueryStopDevice | PnpMinor::QueryRemoveDevice => {
                prior_state == DeviceState::Started
            }
            PnpMinor::StopDevice => {
                prior_state == DeviceState::QueryStopPending
                    && devnode.negotiation
                        == Some(PnpNegotiation {
                            minor: PnpMinor::QueryStopDevice,
                            accepted: true,
                        })
            }
            PnpMinor::CancelStopDevice => {
                prior_state == DeviceState::QueryStopPending
                    && devnode
                        .negotiation
                        .is_some_and(|negotiation| negotiation.minor == PnpMinor::QueryStopDevice)
            }
            PnpMinor::CancelRemoveDevice => {
                prior_state == DeviceState::QueryRemovePending
                    && devnode
                        .negotiation
                        .is_some_and(|negotiation| negotiation.minor == PnpMinor::QueryRemoveDevice)
            }
            PnpMinor::RemoveDevice => {
                matches!(
                    prior_state,
                    DeviceState::Stopped | DeviceState::RemovePending | DeviceState::Failed
                ) || (prior_state == DeviceState::QueryRemovePending
                    && devnode.negotiation
                        == Some(PnpNegotiation {
                            minor: PnpMinor::QueryRemoveDevice,
                            accepted: true,
                        }))
            }
            PnpMinor::SurpriseRemoval => {
                matches!(
                    prior_state,
                    DeviceState::Started
                        | DeviceState::Stopped
                        | DeviceState::QueryStopPending
                        | DeviceState::QueryRemovePending
                        | DeviceState::Failed
                )
            }
        };
        if !allowed {
            return Err(PnpError::InvalidTransition);
        }
        match minor {
            PnpMinor::StartDevice => devnode.state = DeviceState::StartIrpSent,
            PnpMinor::QueryStopDevice => devnode.state = DeviceState::QueryStopPending,
            PnpMinor::QueryRemoveDevice => devnode.state = DeviceState::QueryRemovePending,
            PnpMinor::RemoveDevice | PnpMinor::SurpriseRemoval => {
                devnode.state = DeviceState::RemovePending
            }
            _ => {}
        }
        if minor == PnpMinor::SurpriseRemoval {
            devnode.negotiation = None;
        }
        devnode.pending_dispatch = Some(PendingPnpDispatch {
            generation: dispatch_generation,
            canonical_irp_id,
            minor,
        });
        self.next_dispatch_gen = next_dispatch_generation;
        Ok(PnpDispatchToken {
            devnode_id: devnode.id,
            devnode_generation: devnode.generation,
            dispatch_generation,
            canonical_irp_id,
            minor,
        })
    }

    /// Complete a PnP IRP that returned or completed through the whole device stack.
    ///
    /// STOP, REMOVE, CANCEL, and SURPRISE requests cannot be failed by a conforming driver, so any
    /// returned completion advances their lifecycle even if the driver supplied a failure status.
    /// An absent return must not call this method; the pending record then remains as a retirement
    /// barrier.
    pub fn complete_pnp_dispatch(
        &mut self,
        token: &PnpDispatchToken,
        completed_canonical_irp_id: u64,
        status_success: bool,
    ) -> Result<DeviceState, PnpError> {
        let devnode = self
            .find_mut(token.devnode_id)
            .ok_or(PnpError::StaleDispatch)?;
        let pending = devnode.pending_dispatch.ok_or(PnpError::StaleDispatch)?;
        if devnode.generation != token.devnode_generation
            || pending.generation != token.dispatch_generation
            || completed_canonical_irp_id == 0
            || pending.canonical_irp_id != completed_canonical_irp_id
            || pending.canonical_irp_id != token.canonical_irp_id
            || pending.minor != token.minor
        {
            return Err(PnpError::StaleDispatch);
        }
        devnode.state = match pending.minor {
            PnpMinor::StartDevice => {
                if status_success {
                    DeviceState::Started
                } else {
                    DeviceState::Failed
                }
            }
            PnpMinor::QueryStopDevice => {
                devnode.negotiation = Some(PnpNegotiation {
                    minor: pending.minor,
                    accepted: status_success,
                });
                DeviceState::QueryStopPending
            }
            PnpMinor::StopDevice => DeviceState::Stopped,
            PnpMinor::CancelStopDevice => DeviceState::Started,
            PnpMinor::QueryRemoveDevice => {
                devnode.negotiation = Some(PnpNegotiation {
                    minor: pending.minor,
                    accepted: status_success,
                });
                DeviceState::QueryRemovePending
            }
            PnpMinor::CancelRemoveDevice => DeviceState::Started,
            PnpMinor::RemoveDevice => {
                devnode.remove_ready = Some(pending.generation);
                DeviceState::RemovePending
            }
            PnpMinor::SurpriseRemoval => DeviceState::RemovePending,
        };
        if !matches!(
            pending.minor,
            PnpMinor::QueryStopDevice | PnpMinor::QueryRemoveDevice
        ) {
            devnode.negotiation = None;
        }
        devnode.pending_dispatch = None;
        Ok(devnode.state)
    }

    /// Complete one canonical START dispatch and mint its immutable lifecycle receipt.
    ///
    /// The caller must retain the original dispatch token until this point. The manager checks the
    /// token against the current devnode generation, canonical stack binding, absence of an
    /// in-flight dispatch, and the terminal state implied by the exact driver status.
    pub fn complete_start_device_dispatch(
        &mut self,
        token: &PnpDispatchToken,
        fdo_device_id: u64,
        io_receipt: nt_io_manager::ExternalPnpTerminalReceipt,
    ) -> Result<StartDeviceLifecycleReceipt, PnpError> {
        let io_identity = StartDeviceIoTerminalIdentity {
            irp_id: io_receipt.irp_id().raw(),
            pdo_device_id: io_receipt.origin_device_id().raw(),
            origin_driver_id: io_receipt.origin_driver_id().raw(),
            completion_driver_id: io_receipt.completion_driver_id().raw(),
            completion_device_id: io_receipt.completion_device_id().raw(),
            minor: io_receipt.minor(),
            driver_pending: io_receipt.driver_pending(),
            start_status: io_receipt.status().raw() as u32,
        };
        self.complete_start_device_dispatch_identity(token, fdo_device_id, io_identity)
    }

    fn complete_start_device_dispatch_identity(
        &mut self,
        token: &PnpDispatchToken,
        fdo_device_id: u64,
        io_identity: StartDeviceIoTerminalIdentity,
    ) -> Result<StartDeviceLifecycleReceipt, PnpError> {
        let identity = token.identity();
        let pdo_device_id = io_identity.pdo_device_id;
        let origin_driver_id = io_identity.origin_driver_id;
        let completion_driver_id = io_identity.completion_driver_id;
        let completion_device_id = io_identity.completion_device_id;
        let start_status = io_identity.start_status;
        if identity.minor != PnpMinor::StartDevice
            || identity.canonical_irp_id == 0
            || io_identity.irp_id != identity.canonical_irp_id
            || io_identity.minor != PnpMinor::StartDevice.raw()
            || start_status == STATUS_PENDING
            || pdo_device_id == 0
            || fdo_device_id == 0
            || origin_driver_id == 0
            || completion_driver_id == 0
            || completion_device_id == 0
        {
            return Err(PnpError::InvalidIdentity);
        }
        let pending_devnode = self
            .find(identity.devnode_id)
            .ok_or(PnpError::StaleDispatch)?;
        let pending = pending_devnode
            .pending_dispatch
            .ok_or(PnpError::StaleDispatch)?;
        if pending_devnode.generation != identity.devnode_generation
            || pending.generation != identity.dispatch_generation
            || pending.canonical_irp_id != identity.canonical_irp_id
            || pending.minor != PnpMinor::StartDevice
            || pending_devnode.pdo_object_id != pdo_device_id
            || pending_devnode.fdo_object_id != fdo_device_id
        {
            return Err(PnpError::StaleDispatch);
        }
        self.complete_pnp_dispatch(token, identity.canonical_irp_id, start_status as i32 >= 0)?;
        let devnode = self
            .find(identity.devnode_id)
            .ok_or(PnpError::StaleDispatch)?;
        let expected_state = if start_status as i32 >= 0 {
            DeviceState::Started
        } else {
            DeviceState::Failed
        };
        if devnode.generation != identity.devnode_generation
            || devnode.pending_dispatch.is_some()
            || devnode.state != expected_state
            || devnode.pdo_object_id != pdo_device_id
            || devnode.fdo_object_id != fdo_device_id
        {
            return Err(PnpError::StaleDispatch);
        }
        Ok(StartDeviceLifecycleReceipt {
            dispatch: identity,
            pdo_device_id,
            fdo_device_id,
            origin_driver_id,
            completion_driver_id,
            completion_device_id,
            driver_pending: io_identity.driver_pending,
            start_status,
        })
    }

    /// Confirm that a manager-minted START receipt belongs to the exact requested instance.
    pub fn start_device_receipt_matches_instance(
        &self,
        receipt: &StartDeviceLifecycleReceipt,
        instance_id: &str,
    ) -> bool {
        self.find(receipt.dispatch.devnode_id)
            .is_some_and(|devnode| {
                devnode.generation == receipt.dispatch.devnode_generation
                    && devnode.pdo_object_id == receipt.pdo_device_id
                    && devnode.fdo_object_id == receipt.fdo_device_id
                    && devnode
                        .instance_id
                        .as_deref()
                        .is_some_and(|current| current.eq_ignore_ascii_case(instance_id))
            })
    }

    /// Obtain the authority created by a returned REMOVE IRP. This is retryable while external
    /// teardown remains incomplete and does not itself mutate the devnode.
    pub fn removal_token(&self, pdo_object_id: u64) -> Result<PnpRemovalToken, PnpError> {
        let devnode = self
            .devnodes
            .iter()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id && devnode.pdo_properties.is_some()
            })
            .ok_or(PnpError::StaleId)?;
        if devnode.state != DeviceState::RemovePending || devnode.pending_dispatch.is_some() {
            return Err(PnpError::InvalidTransition);
        }
        Ok(PnpRemovalToken {
            devnode_id: devnode.id,
            devnode_generation: devnode.generation,
            remove_dispatch_generation: devnode.remove_ready.ok_or(PnpError::InvalidTransition)?,
        })
    }

    /// Publish `Removed` only after all external interface, resource, stack, and object teardown
    /// governed by the exact returned REMOVE dispatch has committed.
    pub fn finish_remove(&mut self, token: PnpRemovalToken) -> Result<(), PnpError> {
        let devnode = self
            .find_mut(token.devnode_id)
            .ok_or(PnpError::StaleDispatch)?;
        if devnode.generation != token.devnode_generation
            || devnode.state != DeviceState::RemovePending
            || devnode.pending_dispatch.is_some()
            || devnode.remove_ready != Some(token.remove_dispatch_generation)
        {
            return Err(PnpError::StaleDispatch);
        }
        let properties = devnode
            .pdo_properties
            .as_mut()
            .ok_or(PnpError::StaleDispatch)?;
        properties.allocated_resources_raw = PropertyBlobState::Unqueried;
        properties.allocated_resources_translated = PropertyBlobState::Unqueried;
        properties.filtered_resource_requirements = PropertyBlobState::Unqueried;
        devnode.fdo_object_id = 0;
        devnode.driver_id = 0;
        devnode.negotiation = None;
        devnode.remove_ready = None;
        devnode.state = DeviceState::Removed;
        Ok(())
    }

    pub fn pnp_dispatch_in_flight(&self, id: u64) -> bool {
        self.find(id)
            .is_some_and(|devnode| devnode.pending_dispatch.is_some())
    }

    /// Query one PnP/resource-owned `DEVICE_REGISTRY_PROPERTY` by canonical PDO identity.
    pub fn query_device_property(
        &self,
        pdo_object_id: u64,
        property: u32,
    ) -> Result<PnpDevicePropertyValue<'_>, PnpPropertyError> {
        let devnode = self
            .devnodes
            .iter()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .ok_or(PnpPropertyError::StalePdo)?;
        let properties = devnode.pdo_properties.as_ref().unwrap();
        match property {
            4 => property_blob_value(&properties.boot_resources_translated),
            12 => properties
                .bus_information
                .as_ref()
                .map(|bus| PnpDevicePropertyValue::Guid(bus.bus_type_guid))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            13 => properties
                .bus_information
                .as_ref()
                .filter(|bus| bus.legacy_bus_type != u32::MAX)
                .map(|bus| PnpDevicePropertyValue::U32(bus.legacy_bus_type))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            14 => properties
                .bus_information
                .as_ref()
                .filter(|bus| bus.bus_number & 0x8000_0000 == 0)
                .map(|bus| PnpDevicePropertyValue::U32(bus.bus_number))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            16 => properties
                .capabilities
                .as_ref()
                .filter(|capabilities| capabilities.address != DEVICE_ADDRESS_UNAVAILABLE)
                .map(|capabilities| PnpDevicePropertyValue::U32(capabilities.address))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            19 => properties
                .removal_policy
                .map(|policy| PnpDevicePropertyValue::U32(policy as u32))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            20 => match &properties.filtered_resource_requirements {
                PropertyBlobState::Unqueried => {
                    property_blob_value(&properties.resource_requirements)
                }
                filtered => property_blob_value(filtered),
            },
            21 => property_blob_value(&properties.allocated_resources_raw),
            _ => Err(PnpPropertyError::InvalidProperty),
        }
    }

    pub fn state(&self, id: u64) -> Option<DeviceState> {
        self.find(id).map(|d| d.state)
    }

    pub fn generation(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.generation)
    }

    pub fn instance_id(&self, id: u64) -> Option<&str> {
        self.find(id).and_then(|d| d.instance_id.as_deref())
    }

    pub fn service(&self, id: u64) -> Option<&str> {
        self.find(id).and_then(|d| d.service.as_deref())
    }

    pub fn devnodes_for_service(&self, service: &str) -> Vec<u64> {
        self.devnodes
            .iter()
            .filter(|d| {
                d.service
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(service))
            })
            .map(|d| d.id)
            .collect()
    }

    pub fn resources(&self, id: u64) -> Option<ResourceAssignment> {
        self.find(id).map(|d| d.resources)
    }

    pub fn pdo(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.pdo_object_id)
    }
    pub fn fdo(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.fdo_object_id)
    }

    pub fn set_fdo(&mut self, id: u64, fdo_object_id: u64) -> Result<(), PnpError> {
        self.find_mut(id).ok_or(PnpError::StaleId)?.fdo_object_id = fdo_object_id;
        Ok(())
    }
    pub fn set_driver(&mut self, id: u64, driver_id: u64) -> Result<(), PnpError> {
        self.find_mut(id).ok_or(PnpError::StaleId)?.driver_id = driver_id;
        Ok(())
    }

    /// Attempt a state transition, validating it against the state machine (spec
    /// §8.3). A devnode already `Removed` is stale.
    pub fn transition(&mut self, id: u64, to: DeviceState) -> Result<(), PnpError> {
        let d = self.find_mut(id).ok_or(PnpError::StaleId)?;
        if d.state == DeviceState::Removed {
            return Err(PnpError::StaleId);
        }
        if d.pending_dispatch.is_some() || d.negotiation.is_some() || d.remove_ready.is_some() {
            return Err(PnpError::DispatchInFlight);
        }
        if !can_transition(d.state, to) {
            return Err(PnpError::InvalidTransition);
        }
        d.state = to;
        Ok(())
    }

    /// True once the device is `Started` — resource mapping / interrupt connect is
    /// allowed only then (spec §15.2).
    pub fn mapping_allowed(&self, id: u64) -> bool {
        self.state(id) == Some(DeviceState::Started)
    }

    /// True if the devnode ID resolves to a device that is not removed.
    pub fn is_live(&self, id: u64) -> bool {
        matches!(self.state(id), Some(s) if s != DeviceState::Removed)
    }
}

fn property_blob_value(
    state: &PropertyBlobState,
) -> Result<PnpDevicePropertyValue<'_>, PnpPropertyError> {
    match state {
        PropertyBlobState::Unqueried => Err(PnpPropertyError::DeviceNotReady),
        PropertyBlobState::KnownNone => Ok(PnpDevicePropertyValue::Bytes(&[])),
        PropertyBlobState::Present(bytes) => Ok(PnpDevicePropertyValue::Bytes(bytes)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicU64, Ordering};
    use DeviceState::*;

    static NEXT_TEST_CANONICAL_IRP_ID: AtomicU64 = AtomicU64::new(1);

    fn create_mmio_test_devnode(p: &mut PnpManager, pdo_object_id: u64) -> u64 {
        p.create_service_bound_devnode(
            r"ROOT\MMIO_INTERRUPT_TEST\0000",
            Some("MmioInterruptTest"),
            pdo_object_id,
            MMIO_INTERRUPT_TEST_RESOURCES,
        )
    }

    fn pci_properties() -> PdoProperties {
        PdoProperties::enumerated(
            PnpBusInformation {
                bus_type_guid: GUID_BUS_TYPE_PCI,
                legacy_bus_type: INTERFACE_TYPE_PCI_BUS,
                bus_number: 2,
            },
            PdoCapabilities {
                removable: false,
                eject_supported: false,
                surprise_removal_ok: false,
                address: (3 << 16) | 1,
            },
            PropertyBlobState::Present(vec![9, 8]),
            PropertyBlobState::Present(vec![1, 2, 3]),
            PropertyBlobState::KnownNone,
        )
    }

    #[test]
    fn canonical_pdo_properties_exist_before_add_device_and_assignment() {
        let mut p = PnpManager::new();
        let pdo = 0x1234;
        let id = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, pci_properties())
            .unwrap();
        assert_eq!(p.devnode_for_pdo(pdo), Some(id));
        assert_eq!(
            p.query_device_property(pdo, 12),
            Ok(PnpDevicePropertyValue::Guid(GUID_BUS_TYPE_PCI))
        );
        assert_eq!(
            p.query_device_property(pdo, 13),
            Ok(PnpDevicePropertyValue::U32(INTERFACE_TYPE_PCI_BUS))
        );
        assert_eq!(
            p.query_device_property(pdo, 14),
            Ok(PnpDevicePropertyValue::U32(2))
        );
        assert_eq!(
            p.query_device_property(pdo, 16),
            Ok(PnpDevicePropertyValue::U32((3 << 16) | 1))
        );
        assert_eq!(
            p.query_device_property(pdo, 19),
            Ok(PnpDevicePropertyValue::U32(
                DeviceRemovalPolicy::ExpectNoRemoval as u32
            ))
        );
        assert_eq!(
            p.query_device_property(pdo, 4),
            Ok(PnpDevicePropertyValue::Bytes(&[1, 2, 3]))
        );
        assert_eq!(
            p.query_device_property(pdo, 20),
            Ok(PnpDevicePropertyValue::Bytes(&[]))
        );
        assert_eq!(
            p.commit_filtered_resource_requirements(pdo, vec![0x44, 0x55]),
            Err(PnpError::InvalidTransition)
        );
        p.commit_device_stack(pdo, 0x5678, 0x9abc).unwrap();
        p.commit_filtered_resource_requirements(pdo, vec![0x44, 0x55])
            .unwrap();
        assert_eq!(
            p.query_device_property(pdo, 20),
            Ok(PnpDevicePropertyValue::Bytes(&[0x44, 0x55]))
        );
        assert_eq!(
            p.query_device_property(pdo, 21),
            Err(PnpPropertyError::DeviceNotReady)
        );
        p.commit_resource_assignment(pdo, vec![4, 5], vec![6, 7])
            .unwrap();
        assert_eq!(
            p.query_device_property(pdo, 21),
            Ok(PnpDevicePropertyValue::Bytes(&[4, 5]))
        );
        assert_eq!(
            p.register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, pci_properties(),),
            Ok(id)
        );
        assert_eq!(
            p.query_device_property(pdo, 21),
            Ok(PnpDevicePropertyValue::Bytes(&[4, 5]))
        );
        p.clear_resource_assignment(pdo).unwrap();
        assert_eq!(
            p.query_device_property(pdo, 21),
            Err(PnpPropertyError::DeviceNotReady)
        );
        assert_eq!(p.state(id), Some(DeviceStackBuilt));
    }

    #[test]
    fn canonical_pdo_republication_is_exact_and_removal_policy_is_derived() {
        let mut p = PnpManager::new();
        let pdo = 0x1234;
        let properties = pci_properties();
        let id = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, properties.clone())
            .unwrap();
        assert_eq!(
            p.register_enumerated_pdo(r"pci\ven_1234&dev_5678\0001", pdo, properties.clone()),
            Ok(id)
        );
        let mut conflicting = properties;
        conflicting.capabilities.as_mut().unwrap().address = 7;
        assert_eq!(
            p.register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, conflicting),
            Err(PnpError::ConflictingPdo)
        );

        let mut conflicting_raw = pci_properties();
        conflicting_raw.boot_resources_raw = PropertyBlobState::Present(vec![7]);
        assert_eq!(
            p.register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, conflicting_raw,),
            Err(PnpError::ConflictingPdo)
        );
        assert_eq!(
            p.register_enumerated_pdo("", 1, pci_properties()),
            Err(PnpError::InvalidIdentity)
        );
        assert_eq!(
            DeviceRemovalPolicy::from_capabilities(&PdoCapabilities {
                removable: true,
                eject_supported: true,
                surprise_removal_ok: false,
                address: 0,
            }),
            DeviceRemovalPolicy::ExpectOrderlyRemoval
        );
        assert_eq!(
            DeviceRemovalPolicy::from_capabilities(&PdoCapabilities {
                removable: true,
                eject_supported: false,
                surprise_removal_ok: true,
                address: 0,
            }),
            DeviceRemovalPolicy::ExpectSurpriseRemoval
        );
    }

    #[test]
    fn prepared_pdo_batch_reserves_and_commits_exact_records_without_growth() {
        let mut p = PnpManager::new();
        let existing_properties = pci_properties();
        let existing_id = p
            .register_enumerated_pdo(
                r"PCI\VEN_1234&DEV_5678\0001",
                0x1234,
                existing_properties.clone(),
            )
            .unwrap();
        let records = vec![
            EnumeratedPdoRecord::new(
                String::from(r"pci\ven_1234&dev_5678\0001"),
                0x1234,
                existing_properties,
            ),
            EnumeratedPdoRecord::new(
                String::from(r"PCI\VEN_1234&DEV_5679\0001"),
                0x1235,
                pci_properties(),
            ),
            EnumeratedPdoRecord::new(
                String::from(r"PCI\VEN_1234&DEV_5680\0001"),
                0x1236,
                pci_properties(),
            ),
        ];
        let prepared = p.prepare_enumerated_pdo_batch(records).unwrap();
        assert_eq!(prepared.len(), 3);
        assert_eq!(prepared.devnode_id(0), Some(existing_id));
        assert_eq!(prepared.devnode_id(1), Some(existing_id + 1));
        assert_eq!(prepared.devnode_id(2), Some(existing_id + 2));
        let reserved_capacity = p.devnodes.capacity();
        p.commit_enumerated_pdo_batch(prepared).unwrap();
        assert_eq!(p.devnodes.capacity(), reserved_capacity);
        assert_eq!(p.devnodes.len(), 3);
        assert_eq!(p.devnode_for_pdo(0x1235), Some(existing_id + 1));
        assert_eq!(p.devnode_for_pdo(0x1236), Some(existing_id + 2));
        assert_eq!(p.next_id, existing_id + 3);
        assert_eq!(p.next_gen, existing_id + 3);
    }

    #[test]
    fn prepared_pdo_batch_rejects_duplicates_conflicts_and_stale_commit() {
        let mut p = PnpManager::new();
        let records = vec![
            EnumeratedPdoRecord::new(
                String::from(r"PCI\VEN_1234&DEV_5678\0001"),
                0x1234,
                pci_properties(),
            ),
            EnumeratedPdoRecord::new(
                String::from(r"pci\ven_1234&dev_5678\0001"),
                0x1235,
                pci_properties(),
            ),
        ];
        assert_eq!(
            p.prepare_enumerated_pdo_batch(records).err(),
            Some(PnpError::ConflictingPdo)
        );
        assert!(p.devnodes.is_empty());

        let prepared = p
            .prepare_enumerated_pdo_batch(vec![EnumeratedPdoRecord::new(
                String::from(r"PCI\VEN_1234&DEV_5678\0001"),
                0x1234,
                pci_properties(),
            )])
            .unwrap();
        p.create_service_bound_devnode_without_resources(r"ROOT\INTERVENING\0000", None, 0x9000);
        assert_eq!(
            p.commit_enumerated_pdo_batch(prepared),
            Err(PnpError::StalePublication)
        );
        assert_eq!(p.devnode_for_pdo(0x1234), None);
    }

    #[test]
    fn absent_native_bus_properties_remain_absent_on_the_canonical_pdo() {
        let mut p = PnpManager::new();
        let properties = PdoProperties::from_bus_queries(
            None,
            None,
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
        );
        p.register_enumerated_pdo(r"ROOT\PROPERTYLESS\0000", 0x7777, properties)
            .unwrap();
        assert_eq!(
            p.query_device_property(0x7777, 12),
            Err(PnpPropertyError::ObjectNameNotFound)
        );
        assert_eq!(
            p.query_device_property(0x7777, 16),
            Err(PnpPropertyError::ObjectNameNotFound)
        );
        assert_eq!(
            p.query_device_property(0x7777, 19),
            Err(PnpPropertyError::ObjectNameNotFound)
        );
    }

    #[test]
    fn service_bound_mmio_devnode_is_enumerated_with_resources() {
        let mut p = PnpManager::new();
        let id = create_mmio_test_devnode(&mut p, 0xBD0);
        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(p.pdo(id), Some(0xBD0));
        assert_eq!(p.instance_id(id), Some(r"ROOT\MMIO_INTERRUPT_TEST\0000"));
        assert_eq!(p.service(id), Some("MmioInterruptTest"));
        let r = p.resources(id).unwrap();
        assert_eq!(r.mem_start, 0x1000_0000);
        assert_eq!(r.int_vector, 5);
    }

    #[test]
    fn service_bound_devnode_tracks_registry_identity() {
        let mut p = PnpManager::new();
        let resources = ResourceAssignment {
            mem_start: 0x2000_0000,
            mem_length: 0x2000,
            int_vector: 9,
            int_level: 9,
            int_affinity: 3,
            int_latched: true,
        };

        let id = p.create_service_bound_devnode(
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            Some("E1000"),
            0x1000,
            resources,
        );

        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(
            p.instance_id(id),
            Some(r"PCI\VEN_8086&DEV_100E\3&11583659&0&18")
        );
        assert_eq!(p.service(id), Some("E1000"));
        assert_eq!(p.pdo(id), Some(0x1000));
        assert_eq!(p.resources(id), Some(resources));
        assert_eq!(p.devnodes_for_service("e1000"), vec![id]);
    }

    #[test]
    fn service_bound_devnode_without_resources_is_enumerated() {
        let mut p = PnpManager::new();
        let id = p.create_service_bound_devnode_without_resources(
            r"ROOT\KMDF_INTERFACE_REGISTRY_TEST\0001",
            Some("KmdfInterfaceRegistryTest"),
            0x3000,
        );

        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(p.resources(id), Some(NO_RESOURCES));
        assert_eq!(
            p.devnodes_for_service("KmdfInterfaceRegistryTest"),
            vec![id]
        );
    }

    #[test]
    fn full_start_lifecycle() {
        let mut p = PnpManager::new();
        let id = create_mmio_test_devnode(&mut p, 0);
        for s in [
            DriverLoaded,
            AddDeviceCalled,
            DeviceStackBuilt,
            ResourcesAssigned,
            StartIrpSent,
            Started,
        ] {
            assert_eq!(p.transition(id, s), Ok(()), "to {s:?}");
        }
        assert!(p.mapping_allowed(id));
        assert!(p.is_live(id));
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut p = PnpManager::new();
        let id = create_mmio_test_devnode(&mut p, 0);
        // No START before AddDevice.
        assert_eq!(
            p.transition(id, StartIrpSent),
            Err(PnpError::InvalidTransition)
        );
        assert!(!p.mapping_allowed(id)); // not Started
    }

    #[test]
    fn no_duplicate_start() {
        let mut p = PnpManager::new();
        let id = create_mmio_test_devnode(&mut p, 0);
        for s in [
            DriverLoaded,
            AddDeviceCalled,
            DeviceStackBuilt,
            ResourcesAssigned,
            StartIrpSent,
            Started,
        ] {
            p.transition(id, s).unwrap();
        }
        // Started -> StartIrpSent is not allowed (no restart without Stop).
        assert_eq!(
            p.transition(id, StartIrpSent),
            Err(PnpError::InvalidTransition)
        );
    }

    fn begin_pnp(
        p: &mut PnpManager,
        pdo: u64,
        minor: PnpMinor,
    ) -> Result<PnpDispatchToken, PnpError> {
        let canonical_irp_id = NEXT_TEST_CANONICAL_IRP_ID.fetch_add(1, Ordering::Relaxed);
        p.begin_pnp_dispatch(pdo, minor, canonical_irp_id)
    }

    fn complete_pnp(
        p: &mut PnpManager,
        token: &PnpDispatchToken,
        status_success: bool,
    ) -> Result<DeviceState, PnpError> {
        let completed_canonical_irp_id = token.canonical_irp_id;
        p.complete_pnp_dispatch(token, completed_canonical_irp_id, status_success)
    }

    #[test]
    fn remove_then_stale() {
        let mut p = PnpManager::new();
        let pdo = 0x9000;
        let id = assigned_pci_devnode(&mut p, pdo);
        let start = begin_pnp(&mut p, pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut p, &start, true).unwrap();
        let query = begin_pnp(&mut p, pdo, PnpMinor::QueryRemoveDevice).unwrap();
        complete_pnp(&mut p, &query, true).unwrap();
        let remove = begin_pnp(&mut p, pdo, PnpMinor::RemoveDevice).unwrap();
        assert_eq!(complete_pnp(&mut p, &remove, false), Ok(RemovePending));
        let token = p.removal_token(pdo).unwrap();
        p.finish_remove(token).unwrap();
        assert_eq!(p.state(id), Some(Removed));
        assert!(!p.is_live(id));
        assert!(!p.mapping_allowed(id));
        // Any further transition on a removed devnode is stale.
        assert_eq!(p.transition(id, Started), Err(PnpError::StaleId));
    }

    #[test]
    fn removed_instance_can_reenumerate_with_a_new_canonical_pdo() {
        let mut p = PnpManager::new();
        let first_pdo = 0x9100;
        let sibling_pdo = 0x9200;
        let first = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", first_pdo, pci_properties())
            .unwrap();
        let sibling = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0002", sibling_pdo, pci_properties())
            .unwrap();
        p.commit_device_stack(first_pdo, first_pdo + 1, 0x55)
            .unwrap();
        p.commit_device_stack(sibling_pdo, sibling_pdo + 1, 0x55)
            .unwrap();
        p.commit_resource_assignment(first_pdo, vec![1], vec![2])
            .unwrap();
        p.commit_resource_assignment(sibling_pdo, vec![3], vec![4])
            .unwrap();
        let first_start = begin_pnp(&mut p, first_pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut p, &first_start, true).unwrap();
        let sibling_start = begin_pnp(&mut p, sibling_pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut p, &sibling_start, true).unwrap();

        let surprise = begin_pnp(&mut p, first_pdo, PnpMinor::SurpriseRemoval).unwrap();
        complete_pnp(&mut p, &surprise, true).unwrap();
        let remove = begin_pnp(&mut p, first_pdo, PnpMinor::RemoveDevice).unwrap();
        complete_pnp(&mut p, &remove, true).unwrap();
        let replacement = EnumeratedPdoRecord::new(
            String::from(r"PCI\VEN_1234&DEV_5678\0001"),
            0x9300,
            pci_properties(),
        );
        assert_eq!(
            p.prepare_enumerated_pdo_batch(vec![replacement.clone()])
                .err(),
            Some(PnpError::ConflictingPdo)
        );

        let removal = p.removal_token(first_pdo).unwrap();
        p.finish_remove(removal).unwrap();
        assert_eq!(p.state(first), Some(Removed));
        assert_eq!(p.state(sibling), Some(Started));

        let prepared = p.prepare_enumerated_pdo_batch(vec![replacement]).unwrap();
        let replacement_id = prepared.devnode_id(0).unwrap();
        assert_ne!(replacement_id, first);
        assert!(p.generation(replacement_id).is_none());
        p.commit_enumerated_pdo_batch(prepared).unwrap();
        assert_eq!(p.state(replacement_id), Some(Enumerated));
        assert_eq!(
            p.devnode_for_instance(r"PCI\VEN_1234&DEV_5678\0001"),
            Some(replacement_id)
        );
        assert_eq!(p.devnode_for_pdo(0x9300), Some(replacement_id));
        assert_eq!(p.state(sibling), Some(Started));
        assert!(p.mapping_allowed(sibling));

        assert_eq!(
            p.register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", first_pdo, pci_properties(),),
            Err(PnpError::ConflictingPdo)
        );
    }

    fn assigned_pci_devnode(p: &mut PnpManager, pdo: u64) -> u64 {
        let id = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, pci_properties())
            .unwrap();
        assert_eq!(p.commit_device_stack(pdo, pdo + 1, 0x55), Ok(id));
        p.commit_resource_assignment(pdo, vec![1], vec![2]).unwrap();
        id
    }

    #[test]
    fn canonical_stack_and_resource_publication_is_exact_and_reversible() {
        let mut p = PnpManager::new();
        let pdo = 0x4000;
        let id = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, pci_properties())
            .unwrap();
        assert_eq!(p.commit_device_stack(pdo, 0x4001, 0x55), Ok(id));
        assert_eq!(p.state(id), Some(DeviceStackBuilt));
        assert_eq!(p.fdo(id), Some(0x4001));
        assert_eq!(p.commit_device_stack(pdo, 0x4001, 0x55), Ok(id));
        assert_eq!(
            p.commit_device_stack(pdo, 0x4002, 0x55),
            Err(PnpError::ConflictingStack)
        );

        p.commit_resource_assignment(pdo, vec![1], vec![2]).unwrap();
        assert_eq!(p.state(id), Some(ResourcesAssigned));
        assert_eq!(p.commit_resource_assignment(pdo, vec![1], vec![2]), Ok(()));
        assert_eq!(
            p.commit_resource_assignment(pdo, vec![3], vec![2]),
            Err(PnpError::InvalidTransition)
        );
        p.clear_resource_assignment(pdo).unwrap();
        assert_eq!(p.state(id), Some(DeviceStackBuilt));
        p.rollback_device_stack(pdo, 0x4001, 0x55).unwrap();
        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(p.fdo(id), Some(0));
    }

    #[test]
    fn start_dispatch_requires_an_exact_return() {
        let mut p = PnpManager::new();
        let pdo = 0x5000;
        let id = assigned_pci_devnode(&mut p, pdo);
        assert_eq!(
            p.begin_pnp_dispatch(pdo, PnpMinor::StartDevice, 0),
            Err(PnpError::InvalidIdentity)
        );
        assert_eq!(p.state(id), Some(ResourcesAssigned));
        assert!(!p.pnp_dispatch_in_flight(id));
        assert_eq!(p.next_dispatch_gen, 1);
        let token = begin_pnp(&mut p, pdo, PnpMinor::StartDevice).unwrap();
        assert_eq!(
            token.identity(),
            PnpDispatchIdentity {
                devnode_id: id,
                devnode_generation: p.generation(id).unwrap(),
                dispatch_generation: 1,
                canonical_irp_id: token.canonical_irp_id,
                minor: PnpMinor::StartDevice,
            }
        );
        let duplicate = PnpDispatchToken {
            devnode_id: token.devnode_id,
            devnode_generation: token.devnode_generation,
            dispatch_generation: token.dispatch_generation,
            canonical_irp_id: token.canonical_irp_id,
            minor: token.minor,
        };
        let observed_mismatch = PnpDispatchToken {
            devnode_id: token.devnode_id,
            devnode_generation: token.devnode_generation,
            dispatch_generation: token.dispatch_generation,
            canonical_irp_id: token.canonical_irp_id,
            minor: token.minor,
        };
        let wrong_irp = PnpDispatchToken {
            devnode_id: token.devnode_id,
            devnode_generation: token.devnode_generation,
            dispatch_generation: token.dispatch_generation,
            canonical_irp_id: token.canonical_irp_id + 1,
            minor: token.minor,
        };
        assert_eq!(p.state(id), Some(StartIrpSent));
        assert!(p.pnp_dispatch_in_flight(id));
        assert_eq!(p.transition(id, Failed), Err(PnpError::DispatchInFlight));
        assert_eq!(
            begin_pnp(&mut p, pdo, PnpMinor::StartDevice),
            Err(PnpError::DispatchInFlight)
        );
        assert_eq!(
            p.complete_pnp_dispatch(&observed_mismatch, token.canonical_irp_id + 1, true),
            Err(PnpError::StaleDispatch)
        );
        assert_eq!(
            complete_pnp(&mut p, &wrong_irp, true),
            Err(PnpError::StaleDispatch)
        );
        assert_eq!(complete_pnp(&mut p, &token, true), Ok(Started));
        assert_eq!(
            complete_pnp(&mut p, &duplicate, true),
            Err(PnpError::StaleDispatch)
        );
        assert!(!p.pnp_dispatch_in_flight(id));

        let mut failed = PnpManager::new();
        let failed_id = assigned_pci_devnode(&mut failed, pdo);
        let token = begin_pnp(&mut failed, pdo, PnpMinor::StartDevice).unwrap();
        assert_eq!(complete_pnp(&mut failed, &token, false), Ok(Failed));
        assert!(!failed.mapping_allowed(failed_id));
        let remove = begin_pnp(&mut failed, pdo, PnpMinor::RemoveDevice).unwrap();
        assert_eq!(complete_pnp(&mut failed, &remove, false), Ok(RemovePending));
        let removal = failed.removal_token(pdo).unwrap();
        failed.finish_remove(removal).unwrap();

        let mut indeterminate = PnpManager::new();
        let indeterminate_id = assigned_pci_devnode(&mut indeterminate, pdo);
        let _lost = begin_pnp(&mut indeterminate, pdo, PnpMinor::StartDevice).unwrap();
        assert_eq!(indeterminate.state(indeterminate_id), Some(StartIrpSent));
        assert!(indeterminate.pnp_dispatch_in_flight(indeterminate_id));
        assert_eq!(
            begin_pnp(&mut indeterminate, pdo, PnpMinor::RemoveDevice),
            Err(PnpError::DispatchInFlight)
        );
    }

    #[test]
    fn stop_and_remove_negotiation_requires_cancel_or_commit() {
        let mut p = PnpManager::new();
        let pdo = 0x6000;
        let id = assigned_pci_devnode(&mut p, pdo);
        let start = begin_pnp(&mut p, pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut p, &start, true).unwrap();
        assert_eq!(
            begin_pnp(&mut p, pdo, PnpMinor::RemoveDevice),
            Err(PnpError::InvalidTransition)
        );

        let query_stop = begin_pnp(&mut p, pdo, PnpMinor::QueryStopDevice).unwrap();
        assert_eq!(p.state(id), Some(QueryStopPending));
        complete_pnp(&mut p, &query_stop, false).unwrap();
        assert_eq!(
            begin_pnp(&mut p, pdo, PnpMinor::StopDevice),
            Err(PnpError::InvalidTransition)
        );
        let cancel_stop = begin_pnp(&mut p, pdo, PnpMinor::CancelStopDevice).unwrap();
        assert_eq!(complete_pnp(&mut p, &cancel_stop, false), Ok(Started));

        let query_stop = begin_pnp(&mut p, pdo, PnpMinor::QueryStopDevice).unwrap();
        complete_pnp(&mut p, &query_stop, true).unwrap();
        let stop = begin_pnp(&mut p, pdo, PnpMinor::StopDevice).unwrap();
        assert_eq!(complete_pnp(&mut p, &stop, false), Ok(Stopped));
        assert!(!p.mapping_allowed(id));
        p.release_stopped_resource_assignment(pdo).unwrap();
        let properties = p.enumerated_pdo_properties(pdo).unwrap();
        assert_eq!(
            properties.allocated_resources_raw,
            PropertyBlobState::Unqueried
        );
        assert_eq!(
            properties.allocated_resources_translated,
            PropertyBlobState::Unqueried
        );
        assert_eq!(
            properties.filtered_resource_requirements,
            PropertyBlobState::Unqueried
        );
        p.commit_filtered_resource_requirements(pdo, vec![7, 8])
            .unwrap();
        p.commit_resource_assignment(pdo, vec![3], vec![4]).unwrap();
        assert_eq!(p.state(id), Some(ResourcesAssigned));

        let restart = begin_pnp(&mut p, pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut p, &restart, true).unwrap();
        let query_remove = begin_pnp(&mut p, pdo, PnpMinor::QueryRemoveDevice).unwrap();
        complete_pnp(&mut p, &query_remove, false).unwrap();
        assert_eq!(
            begin_pnp(&mut p, pdo, PnpMinor::RemoveDevice),
            Err(PnpError::InvalidTransition)
        );
        let cancel_remove = begin_pnp(&mut p, pdo, PnpMinor::CancelRemoveDevice).unwrap();
        assert_eq!(complete_pnp(&mut p, &cancel_remove, false), Ok(Started));

        let query_remove = begin_pnp(&mut p, pdo, PnpMinor::QueryRemoveDevice).unwrap();
        complete_pnp(&mut p, &query_remove, true).unwrap();
        let remove = begin_pnp(&mut p, pdo, PnpMinor::RemoveDevice).unwrap();
        assert_eq!(complete_pnp(&mut p, &remove, false), Ok(RemovePending));
        let removal = p.removal_token(pdo).unwrap();
        p.finish_remove(removal).unwrap();
        assert!(!p.is_live(id));
    }

    #[test]
    fn surprise_removal_is_a_returned_barrier_before_final_remove() {
        let mut p = PnpManager::new();
        let pdo = 0x7000;
        let id = assigned_pci_devnode(&mut p, pdo);
        let start = begin_pnp(&mut p, pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut p, &start, true).unwrap();
        let surprise = begin_pnp(&mut p, pdo, PnpMinor::SurpriseRemoval).unwrap();
        assert_eq!(p.state(id), Some(RemovePending));
        assert_eq!(complete_pnp(&mut p, &surprise, false), Ok(RemovePending));
        let remove = begin_pnp(&mut p, pdo, PnpMinor::RemoveDevice).unwrap();
        assert_eq!(complete_pnp(&mut p, &remove, false), Ok(RemovePending));
        assert_eq!(
            begin_pnp(&mut p, pdo, PnpMinor::RemoveDevice),
            Err(PnpError::DispatchInFlight)
        );
        let removal = p.removal_token(pdo).unwrap();
        p.finish_remove(removal).unwrap();
    }

    #[test]
    fn stop_rebalance_is_exact_with_started_sibling() {
        let mut p = PnpManager::new();
        let first_pdo = 0x7100;
        let second_pdo = 0x7200;
        let first = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", first_pdo, pci_properties())
            .unwrap();
        let second = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0002", second_pdo, pci_properties())
            .unwrap();
        p.commit_device_stack(first_pdo, first_pdo + 1, 0x55)
            .unwrap();
        p.commit_device_stack(second_pdo, second_pdo + 1, 0x55)
            .unwrap();
        p.commit_resource_assignment(first_pdo, vec![1], vec![2])
            .unwrap();
        p.commit_resource_assignment(second_pdo, vec![5], vec![6])
            .unwrap();
        let first_start = begin_pnp(&mut p, first_pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut p, &first_start, true).unwrap();
        let second_start = begin_pnp(&mut p, second_pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut p, &second_start, true).unwrap();

        let query = begin_pnp(&mut p, first_pdo, PnpMinor::QueryStopDevice).unwrap();
        complete_pnp(&mut p, &query, true).unwrap();
        let stop = begin_pnp(&mut p, first_pdo, PnpMinor::StopDevice).unwrap();
        complete_pnp(&mut p, &stop, true).unwrap();
        p.release_stopped_resource_assignment(first_pdo).unwrap();

        assert_eq!(p.state(first), Some(Stopped));
        assert_eq!(p.state(second), Some(Started));
        assert!(p.mapping_allowed(second));
        assert_eq!(
            p.enumerated_pdo_properties(second_pdo)
                .unwrap()
                .allocated_resources_raw,
            PropertyBlobState::Present(vec![5])
        );
    }

    #[test]
    fn indeterminate_stop_and_remove_dispatches_remain_barriers() {
        let mut stopping = PnpManager::new();
        let pdo = 0x8000;
        let id = assigned_pci_devnode(&mut stopping, pdo);
        let start = begin_pnp(&mut stopping, pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut stopping, &start, true).unwrap();
        let query = begin_pnp(&mut stopping, pdo, PnpMinor::QueryStopDevice).unwrap();
        complete_pnp(&mut stopping, &query, true).unwrap();
        let _lost_stop = begin_pnp(&mut stopping, pdo, PnpMinor::StopDevice).unwrap();
        assert_eq!(stopping.state(id), Some(QueryStopPending));
        assert!(stopping.pnp_dispatch_in_flight(id));

        let mut removing = PnpManager::new();
        let id = assigned_pci_devnode(&mut removing, pdo);
        let start = begin_pnp(&mut removing, pdo, PnpMinor::StartDevice).unwrap();
        complete_pnp(&mut removing, &start, true).unwrap();
        let surprise = begin_pnp(&mut removing, pdo, PnpMinor::SurpriseRemoval).unwrap();
        complete_pnp(&mut removing, &surprise, true).unwrap();
        let _lost_remove = begin_pnp(&mut removing, pdo, PnpMinor::RemoveDevice).unwrap();
        assert_eq!(removing.state(id), Some(RemovePending));
        assert!(removing.pnp_dispatch_in_flight(id));
    }

    fn action_identity() -> DeviceActionClaimIdentity {
        DeviceActionClaimIdentity {
            mount_generation: 17,
            sequence: 4,
            claim_token: 0x55aa,
        }
    }

    #[test]
    fn existing_start_success_requires_canonical_started_state() {
        assert_eq!(
            existing_device_start_disposition(Some(DeviceState::Started)),
            ExistingDeviceStartDisposition::AlreadyStarted
        );
        for state in [
            DeviceState::StartIrpSent,
            DeviceState::QueryStopPending,
            DeviceState::QueryRemovePending,
            DeviceState::RemovePending,
        ] {
            assert_eq!(
                existing_device_start_disposition(Some(state)),
                ExistingDeviceStartDisposition::Busy
            );
        }
        for state in [
            DeviceState::Enumerated,
            DeviceState::DeviceStackBuilt,
            DeviceState::ResourcesAssigned,
            DeviceState::Stopped,
            DeviceState::Failed,
        ] {
            assert_eq!(
                existing_device_start_disposition(Some(state)),
                ExistingDeviceStartDisposition::RequiresAction
            );
        }
        assert_eq!(
            existing_device_start_disposition(Some(DeviceState::Removed)),
            ExistingDeviceStartDisposition::NoSuchDevice
        );
        assert_eq!(
            existing_device_start_disposition(None),
            ExistingDeviceStartDisposition::RequiresAction
        );
    }

    #[test]
    fn device_action_ack_requires_response_and_delivered_syscall_reply() {
        let mut response_first = DeviceActionOwner::new(action_identity()).unwrap();
        response_first.respond().unwrap();
        assert!(!response_first.ready_to_acknowledge());
        response_first.complete_without_dispatch(0).unwrap();
        assert!(!response_first.ready_to_acknowledge());
        assert_eq!(
            response_first.reply(),
            DeviceActionReplyState::Awaiting { status: 0 }
        );
        response_first.record_reply(0, true).unwrap();
        assert!(response_first.ready_to_acknowledge());
        assert_eq!(response_first.acknowledge(), Ok(action_identity()));

        let mut terminal_first = DeviceActionOwner::new(action_identity()).unwrap();
        terminal_first.complete_without_dispatch(0).unwrap();
        assert_eq!(
            terminal_first.clone().acknowledge(),
            Err(DeviceActionOwnerError::NotAcknowledgeable)
        );
        terminal_first.record_reply(0, true).unwrap();
        assert!(!terminal_first.ready_to_acknowledge());
        terminal_first.respond().unwrap();
        assert!(terminal_first.ready_to_acknowledge());

        let mut terminal_error = DeviceActionOwner::new(action_identity()).unwrap();
        terminal_error
            .complete_without_dispatch(0xc000_0034)
            .unwrap();
        terminal_error.record_reply(0xc000_0034, true).unwrap();
        terminal_error.respond().unwrap();
        assert!(terminal_error.ready_to_acknowledge());
        assert_eq!(terminal_error.acknowledge(), Ok(action_identity()));
    }

    #[test]
    fn device_action_response_cannot_be_completed_twice() {
        let mut pending = DeviceActionOwner::new(action_identity()).unwrap();
        pending.respond().unwrap();
        pending.complete_without_dispatch(0).unwrap();
        assert_eq!(
            pending.complete_without_dispatch(0xc000_0001),
            Err(DeviceActionOwnerError::WrongPhase)
        );
        assert_eq!(pending.identity(), action_identity());
        assert_eq!(
            pending.response_state(),
            DeviceActionResponseState::Terminal { status: 0 }
        );
        assert!(!pending.ready_to_acknowledge());
    }

    #[test]
    fn device_action_reply_must_match_the_terminal_result() {
        let mut mismatch = DeviceActionOwner::new(action_identity()).unwrap();
        mismatch.complete_without_dispatch(0).unwrap();
        assert_eq!(
            mismatch.record_reply(0xc000_0001, true),
            Err(DeviceActionOwnerError::ReplyFailed)
        );
        assert_eq!(
            mismatch.reply(),
            DeviceActionReplyState::Failed {
                status: 0xc000_0001
            }
        );
        assert!(!mismatch.ready_to_acknowledge());

        let mut undelivered = DeviceActionOwner::new(action_identity()).unwrap();
        undelivered.complete_without_dispatch(0).unwrap();
        assert_eq!(
            undelivered.record_reply(0, false),
            Err(DeviceActionOwnerError::ReplyFailed)
        );
        assert!(!undelivered.ready_to_acknowledge());
    }

    #[test]
    fn device_action_identity_and_response_are_fail_closed() {
        assert_eq!(
            DeviceActionOwner::new(DeviceActionClaimIdentity {
                mount_generation: 0,
                sequence: 1,
                claim_token: 1,
            }),
            Err(DeviceActionOwnerError::InvalidIdentity)
        );
        let mut owner = DeviceActionOwner::new(action_identity()).unwrap();
        owner.respond().unwrap();
        assert_eq!(
            owner.respond(),
            Err(DeviceActionOwnerError::DuplicateResponse)
        );
    }

    fn completed_start_receipt(
        canonical_irp_id: u64,
        driver_pending: bool,
        status: u32,
    ) -> StartDeviceLifecycleReceipt {
        let mut manager = PnpManager::new();
        let pdo = 0x7000 + canonical_irp_id;
        let id = assigned_pci_devnode(&mut manager, pdo);
        let token = manager
            .begin_pnp_dispatch(pdo, PnpMinor::StartDevice, canonical_irp_id)
            .unwrap();
        let receipt = manager
            .complete_start_device_dispatch_identity(
                &token,
                pdo + 1,
                StartDeviceIoTerminalIdentity {
                    irp_id: canonical_irp_id,
                    pdo_device_id: pdo,
                    origin_driver_id: 0x55,
                    completion_driver_id: 0x55,
                    completion_device_id: pdo + 1,
                    minor: PnpMinor::StartDevice.raw(),
                    driver_pending,
                    start_status: status,
                },
            )
            .unwrap();
        assert_eq!(receipt.dispatch(), token.identity());
        assert_eq!(receipt.driver_pending(), driver_pending);
        assert_eq!(manager.state(id), Some(DeviceState::Started));
        receipt
    }

    #[test]
    fn start_receipt_rejects_wrong_stack_before_lifecycle_mutation() {
        let mut manager = PnpManager::new();
        let pdo = 0x7800;
        let id = assigned_pci_devnode(&mut manager, pdo);
        let token = manager
            .begin_pnp_dispatch(pdo, PnpMinor::StartDevice, 0x99)
            .unwrap();
        assert_eq!(
            manager.complete_start_device_dispatch_identity(
                &token,
                pdo + 1,
                StartDeviceIoTerminalIdentity {
                    irp_id: 0x99,
                    pdo_device_id: pdo,
                    origin_driver_id: 0x55,
                    completion_driver_id: 0x55,
                    completion_device_id: pdo + 1,
                    minor: PnpMinor::StartDevice.raw(),
                    driver_pending: true,
                    start_status: STATUS_PENDING,
                },
            ),
            Err(PnpError::InvalidIdentity)
        );
        assert_eq!(manager.state(id), Some(DeviceState::StartIrpSent));
        assert!(manager.pnp_dispatch_in_flight(id));
        assert_eq!(
            manager.complete_start_device_dispatch_identity(
                &token,
                pdo + 2,
                StartDeviceIoTerminalIdentity {
                    irp_id: 0x99,
                    pdo_device_id: pdo,
                    origin_driver_id: 0x55,
                    completion_driver_id: 0x55,
                    completion_device_id: pdo + 1,
                    minor: PnpMinor::StartDevice.raw(),
                    driver_pending: false,
                    start_status: 0,
                },
            ),
            Err(PnpError::StaleDispatch)
        );
        assert_eq!(manager.state(id), Some(DeviceState::StartIrpSent));
        assert!(manager.pnp_dispatch_in_flight(id));
        let receipt = manager
            .complete_start_device_dispatch_identity(
                &token,
                pdo + 1,
                StartDeviceIoTerminalIdentity {
                    irp_id: 0x99,
                    pdo_device_id: pdo,
                    origin_driver_id: 0x55,
                    completion_driver_id: 0x55,
                    completion_device_id: pdo + 1,
                    minor: PnpMinor::StartDevice.raw(),
                    driver_pending: false,
                    start_status: 0,
                },
            )
            .unwrap();
        assert_eq!(manager.state(id), Some(DeviceState::Started));
        assert!(
            manager.start_device_receipt_matches_instance(&receipt, r"PCI\VEN_1234&DEV_5678\0001")
        );
        assert!(
            !manager.start_device_receipt_matches_instance(&receipt, r"PCI\VEN_1234&DEV_5678\0002")
        );
    }

    #[test]
    fn start_device_ledger_tracks_no_irp_and_exact_pending_lifecycle() {
        let mut ledger = StartDeviceCallLedger::new();
        let sync = ledger.begin(r"ROOT\SYNC\0000").unwrap();
        ledger.complete_without_start_irp(sync, 0).unwrap();
        ledger.record_reply(sync, 0, true).unwrap();

        let pending = ledger.begin(r"PCI\VEN_1234&DEV_5678\0001").unwrap();
        ledger.mark_pending(pending).unwrap();
        assert_eq!(ledger.active_len(), 1);
        let receipt = completed_start_receipt(0x91, true, 0);
        let expected_dispatch = receipt.dispatch();
        ledger.complete_lifecycle(pending, receipt, 0).unwrap();
        ledger.record_reply(pending, 0, true).unwrap();

        assert_eq!(ledger.started(), 2);
        assert_eq!(ledger.active_len(), 0);
        assert_eq!(ledger.protocol_errors(), 0);
        assert_eq!(ledger.terminal_rows().len(), 2);
        assert_eq!(ledger.terminal_rows()[0].identity(), sync);
        assert_eq!(
            ledger.terminal_rows()[0].completion(),
            StartDeviceCompletionKind::NoStartIrp
        );
        assert_eq!(
            ledger.terminal_rows()[0].path(),
            StartDeviceCallPath::Synchronous
        );
        assert_eq!(ledger.terminal_rows()[1].identity(), pending);
        assert_eq!(
            ledger.terminal_rows()[1].completion(),
            StartDeviceCompletionKind::LifecycleTerminal
        );
        assert_eq!(
            ledger.terminal_rows()[1].path(),
            StartDeviceCallPath::Pending
        );
        assert_eq!(
            ledger.terminal_rows()[1]
                .lifecycle_receipt()
                .map(StartDeviceLifecycleReceipt::dispatch),
            Some(expected_dispatch)
        );
        assert!(ledger
            .terminal_rows()
            .iter()
            .all(StartDeviceTerminalRecord::reply_matches));
    }

    #[test]
    fn start_device_ledger_reserves_every_active_terminal_before_side_effects() {
        let mut ledger = StartDeviceCallLedger::new();
        for index in 0..5 {
            let instance = alloc::format!(r"ROOT\TERMINAL\{index:04}");
            let request = ledger.begin(&instance).unwrap();
            ledger.complete_without_start_irp(request, 0).unwrap();
            ledger.record_reply(request, 0, true).unwrap();
        }
        ledger.terminal.shrink_to_fit();
        for index in 0..4 {
            let instance = alloc::format!(r"ROOT\ACTIVE\{index:04}");
            ledger.begin(&instance).unwrap();
            assert!(
                ledger.terminal.capacity() - ledger.terminal.len() >= ledger.active.len(),
                "terminal storage was not reserved for every active request"
            );
        }
    }

    #[test]
    fn start_device_ledger_retains_reply_failure_and_ownership_loss() {
        let mut ledger = StartDeviceCallLedger::new();
        let request = ledger.begin(r"PCI\LOST\0000").unwrap();
        ledger.mark_pending(request).unwrap();
        ledger
            .complete_ownership_lost(request, 0x88, None, 0xc000_0001)
            .unwrap();
        assert_eq!(
            ledger.record_reply(request, 0xc000_0001, false),
            Err(StartDeviceLedgerError::ReplyFailed)
        );
        assert_eq!(ledger.active_len(), 0);
        assert_eq!(ledger.terminal_rows().len(), 1);
        assert!(!ledger.terminal_rows()[0].reply_matches());
        assert_eq!(
            ledger.terminal_rows()[0].completion(),
            StartDeviceCompletionKind::OwnershipLost
        );
        assert_eq!(ledger.terminal_rows()[0].irp_id(), 0x88);
        assert_eq!(
            ledger.terminal_rows()[0].reply_outcome(),
            StartDeviceReplyOutcome::Failed
        );
    }

    #[test]
    fn start_device_ledger_preserves_committed_receipt_across_ownership_loss() {
        let mut ledger = StartDeviceCallLedger::new();
        let request = ledger.begin(r"PCI\LOST_AFTER_COMMIT\0000").unwrap();
        ledger.mark_pending(request).unwrap();
        let receipt = completed_start_receipt(0x93, true, 0);
        let dispatch = receipt.dispatch();
        ledger
            .complete_ownership_lost(request, 0x93, Some(receipt), 0xc000_0001)
            .unwrap();
        ledger.record_reply(request, 0xc000_0001, true).unwrap();

        let row = &ledger.terminal_rows()[0];
        assert_eq!(row.completion(), StartDeviceCompletionKind::OwnershipLost);
        assert_eq!(
            row.lifecycle_receipt()
                .map(StartDeviceLifecycleReceipt::dispatch),
            Some(dispatch)
        );
    }

    #[test]
    fn start_device_ledger_keeps_start_and_outer_statuses_distinct() {
        let mut ledger = StartDeviceCallLedger::new();
        let request = ledger.begin(r"PCI\OUTER_FAILURE\0000").unwrap();
        let receipt = completed_start_receipt(0x94, false, 0);
        ledger
            .complete_lifecycle(request, receipt, 0xc000_0001)
            .unwrap();
        ledger.record_reply(request, 0xc000_0001, true).unwrap();
        let row = &ledger.terminal_rows()[0];
        assert_eq!(row.status(), 0xc000_0001);
        assert_eq!(row.lifecycle_receipt().unwrap().start_status(), 0);
    }

    #[test]
    fn start_device_ledger_retains_abandonment_until_lifecycle_terminal() {
        let mut ledger = StartDeviceCallLedger::new();
        let request = ledger.begin(r"ROOT\ABANDON\0000").unwrap();
        ledger.mark_pending(request).unwrap();
        ledger.abandon(request).unwrap();
        assert_eq!(ledger.active_len(), 1);
        let receipt = completed_start_receipt(0x92, true, 0);
        ledger.complete_lifecycle(request, receipt, 0).unwrap();
        assert_eq!(ledger.active_len(), 0);
        assert_eq!(ledger.terminal_rows()[0].reply_status(), None);
        assert_eq!(
            ledger.terminal_rows()[0].reply_outcome(),
            StartDeviceReplyOutcome::Abandoned
        );
    }

    #[test]
    fn start_device_ledger_rejects_wrong_phase_and_identity() {
        let mut ledger = StartDeviceCallLedger::new();
        assert_eq!(
            ledger.begin(""),
            Err(StartDeviceLedgerError::InvalidInstance)
        );
        let request = ledger.begin(r"ROOT\EXACT\0000").unwrap();
        assert_eq!(
            ledger.record_reply(request, 0, true),
            Err(StartDeviceLedgerError::WrongPhase)
        );
        assert_eq!(ledger.protocol_errors(), 1);
        ledger.complete_without_start_irp(request, 0).unwrap();
        assert_eq!(
            ledger.complete_without_start_irp(request, 0),
            Err(StartDeviceLedgerError::WrongPhase)
        );
        assert_eq!(ledger.protocol_errors(), 2);
        ledger.record_reply(request, 0, true).unwrap();
        assert_eq!(
            ledger.complete_without_start_irp(request, 0),
            Err(StartDeviceLedgerError::UnknownRequest)
        );
        assert_eq!(ledger.protocol_errors(), 3);
    }
}
