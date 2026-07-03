//! IRP records, the IRP state machine, and I/O stack locations (spec §13).

use alloc::vec::Vec;

use nt_io_abi::{DeviceId, FileId, IrpId};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId};

use crate::file::{CreateOptions, ShareAccess};

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

/// `IRP_MJ_QUERY_INFORMATION` / `IRP_MJ_SET_INFORMATION` parameters.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct InformationParameters {
    pub info_class: u32,
    pub length: u32,
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
    SetInformation(InformationParameters),
    Pnp,
    Power,
    #[default]
    Unsupported,
}

bitflags::bitflags! {
    /// `SL_*` stack-location flags.
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct StackFlags: u8 {
        const CASE_SENSITIVE = 0x01;
        const OPEN_TARGET_DIRECTORY = 0x02;
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
    }
}

/// One I/O stack location (spec §13.3) — the per-driver view of an IRP.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IoStackLocation {
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
    pub fn new(major: u8, device_id: DeviceId, file_id: Option<FileId>) -> Self {
        Self {
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
                | (Dispatched, Pending | Completing | Cancelled | Failed)
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

/// Canonical I/O Manager IRP record (spec §13.1). Lives only in the I/O Manager;
/// driver peers receive a projection, never this.
pub struct IrpRecord {
    pub id: IrpId,
    pub client_id: ClientId,
    pub file_id: Option<FileId>,
    pub device_id: DeviceId,
    pub major: u8,
    pub minor: u8,
    pub state: IrpState,
    pub status: NtStatus,
    pub information: u64,
    pub stack: Vec<IoStackLocation>,
    pub current_location: u8,
    pub buffer: Option<IoBufferRef>,
    pub cancel: CancelState,
    pub user_data: u64,
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
            file_id,
            device_id,
            major,
            minor: 0,
            state: IrpState::Allocated,
            status: NtStatus::PENDING,
            information: 0,
            stack: Vec::new(),
            current_location: 0,
            buffer: None,
            cancel: CancelState::NotCancelled,
            user_data: 0,
        }
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
}
