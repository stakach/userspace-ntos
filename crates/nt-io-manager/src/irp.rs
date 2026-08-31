//! IRP records, the IRP state machine, and I/O stack locations (spec §13).

use alloc::vec::Vec;

use nt_io_abi::{DeviceId, DriverId, FileId, IrpId};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId};

use crate::directory_control::DirectoryNotifyParameters;
use crate::ea::{QueryEaParameters, SetEaParameters};
use crate::file::{CreateOptions, ShareAccess};
use crate::lock_control::LockControlParameters;
use crate::quota::{QueryQuotaParameters, SetQuotaParameters};
use crate::volume_information::{QueryVolumeInformationParameters, SetVolumeInformationParameters};

/// How a driver peer may touch a registered buffer.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum BufferAccess {
    #[default]
    Read,
    Write,
    ReadWrite,
}

/// A reference to a SURT registered buffer (spec §14.1). Never a raw pointer —
/// validated (id/generation/bounds/rights) before dispatch.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct IoBufferRef {
    pub buffer_id: u64,
    pub offset: u64,
    pub len: u32,
    pub input_len: u32,
    pub output_len: u32,
    pub access: BufferAccess,
}

/// Cancellation state of an IRP (spec §13.1, §18).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum CancelState {
    #[default]
    NotCancelled,
    CancelRequested,
    Cancelled,
}

/// `IRP_MJ_CREATE` parameters.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct CreateParameters {
    pub desired_access: AccessMask,
    pub share_access: ShareAccess,
    pub create_options: CreateOptions,
    pub create_disposition: u32,
    pub file_attributes: u32,
    /// Bytes of `FILE_FULL_EA_INFORMATION` at the tail of the CREATE input buffer. Any preceding
    /// input bytes are the canonical FILE_OBJECT name used by an isolated WDM provider.
    pub ea_length: u32,
    /// Canonical directory File retained by this File for a handle-relative CREATE.
    pub related_file: Option<FileId>,
}

/// `IRP_MJ_READ` / `IRP_MJ_WRITE` parameters.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct ReadWriteParameters {
    pub length: u32,
    pub key: u32,
    pub offset: u64,
}

/// `IRP_MJ_DEVICE_CONTROL` / `IRP_MJ_INTERNAL_DEVICE_CONTROL` parameters.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct DeviceControlParameters {
    pub ioctl_code: u32,
    pub input_len: u32,
    pub output_len: u32,
}

/// `IRP_MJ_QUERY_INFORMATION` parameters.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct InformationParameters {
    pub info_class: u32,
    pub length: u32,
}

/// `IRP_MJ_SET_INFORMATION` parameters.
///
/// Rename, link, and move-cluster requests may retain a second canonical File
/// representing the target directory. This is the I/O Manager identity behind
/// the WDM `Parameters.SetFile.FileObject`; it is never a caller handle or
/// pointer.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum SetInformationControl {
    #[default]
    None,
    ReplaceIfExists(bool),
    ClusterCount(u32),
}

impl SetInformationControl {
    pub const fn valid_for_class(self, info_class: u32) -> bool {
        match (info_class, self) {
            (10 | 11, Self::ReplaceIfExists(_)) | (31, Self::ClusterCount(_)) => true,
            (10 | 11 | 31, _) => false,
            (_, Self::None) => true,
            _ => false,
        }
    }

    pub const fn wire_value(self) -> u32 {
        match self {
            Self::None => 0,
            Self::ReplaceIfExists(value) => value as u32,
            Self::ClusterCount(value) => value,
        }
    }

    pub const fn replace_if_exists(self) -> bool {
        matches!(self, Self::ReplaceIfExists(true))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct SetInformationParameters {
    pub info_class: u32,
    pub length: u32,
    pub target_file: Option<FileId>,
    pub control: SetInformationControl,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PnpStartParameters {
    pub raw_resource_list_len: u32,
    pub translated_resource_list_len: u32,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PnpParameters {
    pub minor: u8,
    kind: PnpParameterKind,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum PnpParameterKind {
    Lifecycle,
    Start(PnpStartParameters),
    QueryDeviceRelations { relation_type: u32 },
    QueryId { id_type: u32 },
    QueryInformation,
    QueryCapabilities,
    FilterResourceRequirements { input_len: u32 },
}

impl PnpParameters {
    pub fn lifecycle(minor: u8) -> Result<Self, NtStatus> {
        if minor == nt_pnp_abi::IRP_MN_START_DEVICE || !Self::is_lifecycle_minor(minor) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(Self {
            minor,
            kind: PnpParameterKind::Lifecycle,
        })
    }

    pub fn start(
        raw_resource_list_len: u32,
        translated_resource_list_len: u32,
    ) -> Result<Self, NtStatus> {
        if (raw_resource_list_len == 0) != (translated_resource_list_len == 0)
            || raw_resource_list_len
                .checked_add(translated_resource_list_len)
                .is_none()
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(Self {
            minor: nt_pnp_abi::IRP_MN_START_DEVICE,
            kind: PnpParameterKind::Start(PnpStartParameters {
                raw_resource_list_len,
                translated_resource_list_len,
            }),
        })
    }

    pub const fn query_device_relations(relation_type: u32) -> Self {
        Self {
            minor: nt_pnp_abi::IRP_MN_QUERY_DEVICE_RELATIONS,
            kind: PnpParameterKind::QueryDeviceRelations { relation_type },
        }
    }

    pub const fn query_id(id_type: u32) -> Self {
        Self {
            minor: nt_pnp_abi::IRP_MN_QUERY_ID,
            kind: PnpParameterKind::QueryId { id_type },
        }
    }

    /// Construct a PnP query whose result is returned through `IoStatus.Information` and whose
    /// stack-location parameter union is empty.
    pub fn query_information(minor: u8) -> Result<Self, NtStatus> {
        if !matches!(
            minor,
            nt_pnp_abi::IRP_MN_QUERY_RESOURCES
                | nt_pnp_abi::IRP_MN_QUERY_RESOURCE_REQUIREMENTS
                | nt_pnp_abi::IRP_MN_QUERY_BUS_INFORMATION
        ) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(Self {
            minor,
            kind: PnpParameterKind::QueryInformation,
        })
    }

    /// Construct `IRP_MN_QUERY_CAPABILITIES`, whose stack parameter points to an initialized
    /// request-owned `DEVICE_CAPABILITIES` buffer that the driver mutates in place.
    pub const fn query_capabilities() -> Self {
        Self {
            minor: nt_pnp_abi::IRP_MN_QUERY_CAPABILITIES,
            kind: PnpParameterKind::QueryCapabilities,
        }
    }

    /// Construct `IRP_MN_FILTER_RESOURCE_REQUIREMENTS`. The input extent is the complete native
    /// requirements list referenced by both the stack location and the initial IoStatus pointer.
    pub fn filter_resource_requirements(input_len: u32) -> Result<Self, NtStatus> {
        if input_len == 0 {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(Self {
            minor: nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
            kind: PnpParameterKind::FilterResourceRequirements { input_len },
        })
    }

    pub const fn start_parameters(self) -> Option<PnpStartParameters> {
        match self.kind {
            PnpParameterKind::Start(start) => Some(start),
            _ => None,
        }
    }

    pub const fn relation_type(self) -> Option<u32> {
        match self.kind {
            PnpParameterKind::QueryDeviceRelations { relation_type } => Some(relation_type),
            _ => None,
        }
    }

    pub const fn id_type(self) -> Option<u32> {
        match self.kind {
            PnpParameterKind::QueryId { id_type } => Some(id_type),
            _ => None,
        }
    }

    pub const fn filter_resource_requirements_len(self) -> Option<u32> {
        match self.kind {
            PnpParameterKind::FilterResourceRequirements { input_len } => Some(input_len),
            _ => None,
        }
    }

    pub const fn wire_argument(self) -> Option<u32> {
        match self.kind {
            PnpParameterKind::QueryDeviceRelations { relation_type } => Some(relation_type),
            PnpParameterKind::QueryId { id_type } => Some(id_type),
            _ => None,
        }
    }

    pub fn input_len(self) -> u32 {
        match self.kind {
            PnpParameterKind::Start(start) => start
                .raw_resource_list_len
                .checked_add(start.translated_resource_list_len)
                .expect("validated PnP START extents overflowed"),
            PnpParameterKind::QueryCapabilities => nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE as u32,
            PnpParameterKind::FilterResourceRequirements { input_len } => input_len,
            _ => 0,
        }
    }

    pub fn output_len(self) -> u32 {
        match self.kind {
            PnpParameterKind::QueryCapabilities => nt_pnp_abi::DEVICE_CAPABILITIES_X64_SIZE as u32,
            _ => 0,
        }
    }

    pub fn payload_len(self) -> u32 {
        self.input_len().max(self.output_len())
    }

    fn is_lifecycle_minor(minor: u8) -> bool {
        matches!(
            minor,
            nt_pnp_abi::IRP_MN_QUERY_REMOVE_DEVICE
                | nt_pnp_abi::IRP_MN_REMOVE_DEVICE
                | nt_pnp_abi::IRP_MN_CANCEL_REMOVE_DEVICE
                | nt_pnp_abi::IRP_MN_STOP_DEVICE
                | nt_pnp_abi::IRP_MN_QUERY_STOP_DEVICE
                | nt_pnp_abi::IRP_MN_CANCEL_STOP_DEVICE
                | nt_pnp_abi::IRP_MN_SURPRISE_REMOVAL
        )
    }
}

/// The per-major parameter payload of an I/O stack location (spec §13.3). Only
/// the v0.1 variants are functional; the rest route to `STATUS_NOT_SUPPORTED`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum IoParameters {
    Create(CreateParameters),
    Cleanup,
    Close,
    Read(ReadWriteParameters),
    Write(ReadWriteParameters),
    DeviceControl(DeviceControlParameters),
    InternalDeviceControl(DeviceControlParameters),
    FlushBuffers,
    QueryInformation(InformationParameters),
    SetInformation(SetInformationParameters),
    QueryEa(QueryEaParameters),
    SetEa(SetEaParameters),
    QueryQuota(QueryQuotaParameters),
    SetQuota(SetQuotaParameters),
    QueryVolumeInformation(QueryVolumeInformationParameters),
    SetVolumeInformation(SetVolumeInformationParameters),
    NotifyDirectory(DirectoryNotifyParameters),
    LockControl(LockControlParameters),
    Pnp(PnpParameters),
    Power,
    #[default]
    Unsupported,
}

impl IoParameters {
    /// The input/output extents represented inside a buffered SystemBuffer for
    /// normal I/O Manager request builders.
    pub fn buffered_lengths(&self, system_buffer_len: usize) -> (u32, u32) {
        let cap = system_buffer_len.min(u32::MAX as usize) as u32;
        match self {
            IoParameters::Read(p) => (0, p.length.min(cap)),
            IoParameters::Write(p) => (p.length.min(cap), 0),
            IoParameters::DeviceControl(p) | IoParameters::InternalDeviceControl(p) => {
                (p.input_len.min(cap), p.output_len.min(cap))
            }
            IoParameters::QueryInformation(p) => (0, p.length.min(cap)),
            IoParameters::SetInformation(p) => (p.length.min(cap), 0),
            IoParameters::QueryEa(p) => (p.ea_list_length.min(cap), p.length.min(cap)),
            IoParameters::SetEa(p) => (p.length.min(cap), 0),
            IoParameters::QueryQuota(p) => (
                p.input_length().unwrap_or(u32::MAX).min(cap),
                p.length.min(cap),
            ),
            IoParameters::SetQuota(p) => (p.length.min(cap), 0),
            IoParameters::QueryVolumeInformation(p) => (0, p.length.min(cap)),
            IoParameters::SetVolumeInformation(p) => (p.length.min(cap), 0),
            IoParameters::NotifyDirectory(p) => (0, p.length.min(cap)),
            IoParameters::LockControl(_) => (0, 0),
            IoParameters::Pnp(p) => (p.input_len().min(cap), p.output_len().min(cap)),
            _ => (0, 0),
        }
    }
}

bitflags::bitflags! {
    /// `SL_*` stack-location flags.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct StackFlags: u8 {
        const FORCE_ACCESS_CHECK = 0x01;
        const OPEN_PAGING_FILE = 0x02;
        const OPEN_TARGET_DIRECTORY = 0x04;
        const STOP_ON_SYMLINK = 0x08;
        const CASE_SENSITIVE = 0x80;
        // Query-directory/query-EA/query-quota interpretations of the same
        // per-major IO_STACK_LOCATION flag byte.
        const RESTART_SCAN = 0x01;
        const RETURN_SINGLE_ENTRY = 0x02;
        const INDEX_SPECIFIED = 0x04;
        const WATCH_TREE = 0x01;
    }
}

bitflags::bitflags! {
    /// `SL_*` stack-location control (completion routing).
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct StackControl: u8 {
        const INVOKE_ON_SUCCESS = 0x40;
        const INVOKE_ON_ERROR = 0x80;
        const INVOKE_ON_CANCEL = 0x20;
        const PENDING_RETURNED = 0x01;
        const ERROR_RETURNED = 0x02;
    }
}

/// One I/O stack location (spec §13.3) — the per-driver view of an IRP.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IoStackLocation {
    pub driver_id: DriverId,
    pub major: u8,
    pub minor: u8,
    pub flags: StackFlags,
    pub control: StackControl,
    pub device_id: DeviceId,
    pub file_id: Option<FileId>,
    pub parameters: IoParameters,
}

impl IoStackLocation {
    /// A stack location for `major` targeting `device_id`.
    pub fn new(
        driver_id: DriverId,
        major: u8,
        device_id: DeviceId,
        file_id: Option<FileId>,
    ) -> Self {
        Self {
            driver_id,
            major,
            minor: 0,
            flags: StackFlags::empty(),
            control: StackControl::empty(),
            device_id,
            file_id,
            parameters: IoParameters::Unsupported,
        }
    }
}

/// IRP lifecycle state (spec §13.2). Allowed transitions are explicit + tested.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum IrpState {
    #[default]
    Allocated,
    Initialized,
    Queued,
    Dispatched,
    Pending,
    /// Backend entry occurred, but the I/O manager could not observe a trustworthy outer return.
    /// The canonical identity remains live as a teardown barrier and accepts no later completion.
    Indeterminate,
    CancelRequested,
    Completing,
    Completed,
    Cancelled,
    Failed,
    Freed,
}

impl IrpState {
    /// Whether `self -> next` is an allowed transition (spec §13.2).
    pub fn can_transition_to(self, next: IrpState) -> bool {
        use IrpState::*;
        matches!(
            (self, next),
            (Allocated, Initialized)
                | (Initialized, Queued | Dispatched | Cancelled | Failed)
                | (Queued, Dispatched | Cancelled | Failed)
                | (
                    Dispatched,
                    Pending | Indeterminate | Completing | Cancelled | Failed
                )
                | (
                    Pending,
                    CancelRequested | Completing | Completed | Cancelled | Failed
                )
                | (CancelRequested, Completing | Cancelled | Completed | Failed)
                | (Completing, Completed | Failed)
                | (Completed | Cancelled | Failed, Freed)
        )
    }

    /// A terminal state (no further transitions except to `Freed`).
    pub fn is_final(self) -> bool {
        matches!(
            self,
            IrpState::Completed | IrpState::Cancelled | IrpState::Failed | IrpState::Freed
        )
    }
}

/// Provenance of an asynchronous terminal result retained by the I/O manager.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IrpCompletionOrigin {
    /// The owning driver backend published a genuine terminal completion.
    Driver,
    /// The I/O manager synthesized failure after losing the driver transport.
    TransportFault,
}

/// Immutable identity of the request bytes copied into an IRP's system buffer before dispatch.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RequestInputFingerprint {
    pub len: u32,
    pub digest: u64,
}

pub fn request_input_fingerprint(input: &[u8]) -> RequestInputFingerprint {
    RequestInputFingerprint {
        len: input.len().min(u32::MAX as usize) as u32,
        digest: input.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        }),
    }
}

/// Canonical I/O Manager IRP record (spec §13.1). Lives only in the I/O Manager;
/// driver peers receive a projection, never this.
pub struct IrpRecord {
    pub id: IrpId,
    pub client_id: ClientId,
    /// Immutable driver identity at the request origin. For device requests this is the driver
    /// that owns `origin_device_id`; driver-directed requests use their explicit target.
    pub origin_driver_id: DriverId,
    pub file_id: Option<FileId>,
    /// Immutable device identity at the request origin. The current target lives in the active
    /// stack location and may differ when an attached filter is above this device.
    pub origin_device_id: DeviceId,
    pub origin_major: u8,
    pub origin_minor: u8,
    pub state: IrpState,
    pub status: NtStatus,
    pub information: u64,
    /// Driver-owned context captured by the terminal CREATE result.
    pub completion_file_context: Option<u64>,
    pub completion_origin: Option<IrpCompletionOrigin>,
    pub stack: Vec<IoStackLocation>,
    pub current_location: u8,
    pub buffer: Option<IoBufferRef>,
    request_input_fingerprint: Option<RequestInputFingerprint>,
    pub cancel: CancelState,
    pub user_data: u64,
    /// Requesting thread identity used by NT's thread-scoped cancellation contract.
    pub requestor_tid: u64,
}

impl IrpRecord {
    /// A freshly-allocated IRP for `major` on `device_id` (id filled in by the
    /// store's caller). Starts `Allocated`, status `STATUS_PENDING`.
    pub fn new(
        client_id: ClientId,
        device_id: DeviceId,
        file_id: Option<FileId>,
        major: u8,
    ) -> Self {
        Self {
            id: IrpId::NULL,
            client_id,
            origin_driver_id: DriverId::NULL,
            file_id,
            origin_device_id: device_id,
            origin_major: major,
            origin_minor: 0,
            state: IrpState::Allocated,
            status: NtStatus::PENDING,
            information: 0,
            completion_file_context: None,
            completion_origin: None,
            stack: Vec::new(),
            current_location: 0,
            buffer: None,
            request_input_fingerprint: None,
            cancel: CancelState::NotCancelled,
            user_data: 0,
            requestor_tid: 0,
        }
    }

    /// Return the identity captured before the request was visible to a driver.
    pub fn request_input_fingerprint(&self) -> Option<RequestInputFingerprint> {
        self.request_input_fingerprint
    }

    pub(crate) fn set_request_input_fingerprint(&mut self, input: &[u8]) {
        self.request_input_fingerprint = Some(request_input_fingerprint(input));
    }

    /// Advance the IRP state if the transition is allowed. Returns whether it
    /// was applied.
    pub fn transition(&mut self, next: IrpState) -> bool {
        if self.state.can_transition_to(next) {
            self.state = next;
            true
        } else {
            false
        }
    }

    /// The current (top-of-stack) I/O stack location, if any.
    pub fn current_stack(&self) -> Option<&IoStackLocation> {
        self.stack.get(self.current_location as usize)
    }

    /// Publish the next lower stack location and advance ownership. The caller must own the current
    /// frame, while the supplied frame must preserve the precomputed lower driver/device/File
    /// identity. Stale, skipped, or cross-stack forwarding is rejected without changing the cursor.
    pub fn handoff_to_next_stack(
        &mut self,
        caller: DriverId,
        next_stack: IoStackLocation,
    ) -> Result<&IoStackLocation, NtStatus> {
        let current = self.current_stack().ok_or(NtStatus::INVALID_PARAMETER)?;
        if current.driver_id != caller {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let next = self
            .current_location
            .checked_add(1)
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        let expected = self
            .stack
            .get(next as usize)
            .ok_or(NtStatus::INVALID_DEVICE_REQUEST)?;
        if next_stack.driver_id != expected.driver_id
            || next_stack.device_id != expected.device_id
            || next_stack.file_id != expected.file_id
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        self.stack[next as usize] = next_stack;
        self.current_location = next;
        self.current_stack().ok_or(NtStatus::INVALID_PARAMETER)
    }
}
