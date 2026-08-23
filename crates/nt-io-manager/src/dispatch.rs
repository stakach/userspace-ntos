//! The pluggable driver dispatch backend (spec §15).
//!
//! The I/O Manager builds an [`IrpProjection`] (never the canonical `IrpRecord`)
//! and hands it to a [`DriverDispatchBackend`] together with a [`DispatchContext`]
//! (the buffered-I/O staging buffer + surrounding ids). A backend completes
//! synchronously, accepts the request as pending, or fails. The mock backend
//! ([`crate::MockDriverBackend`]) implements this in-process; a SURT driver-peer
//! backend (later) marshals the projection + buffer ids to an isolated peer.

use nt_status::NtStatus;

use crate::irp::{IoBufferRef, IoParameters, IrpRecord};
use crate::{DeviceId, DriverId, FileId, IrpId};
use nt_types::ClientId;

/// The surrounding context for one dispatch. `system_buffer` is the buffered-I/O
/// staging area (`SystemBuffer`): for a read it receives the driver's output; for
/// a write / IOCTL it initially holds the client input. A backend that marshals
/// to a peer over SURT ignores it and uses the projection's buffer id instead.
pub struct DispatchContext<'a> {
    pub driver_id: DriverId,
    pub client_id: ClientId,
    pub system_buffer: &'a mut [u8],
    pub direct_buffer: Option<&'a mut [u8]>,
    pub type3_input_buffer: Option<&'a mut [u8]>,
    pub user_buffer: Option<&'a mut [u8]>,
}

impl<'a> DispatchContext<'a> {
    pub fn new(driver_id: DriverId, client_id: ClientId, system_buffer: &'a mut [u8]) -> Self {
        Self {
            driver_id,
            client_id,
            system_buffer,
            direct_buffer: None,
            type3_input_buffer: None,
            user_buffer: None,
        }
    }

    pub fn with_transfer_buffers(
        driver_id: DriverId,
        client_id: ClientId,
        system_buffer: &'a mut [u8],
        direct_buffer: Option<&'a mut [u8]>,
        type3_input_buffer: Option<&'a mut [u8]>,
        user_buffer: Option<&'a mut [u8]>,
    ) -> Self {
        Self {
            driver_id,
            client_id,
            system_buffer,
            direct_buffer,
            type3_input_buffer,
            user_buffer,
        }
    }

    pub fn ioctl_input_buffer(&self, method: u32) -> &[u8] {
        match method {
            nt_io_abi::ioctl::METHOD_NEITHER => self.type3_input_buffer.as_deref().unwrap_or(&[]),
            _ => self.system_buffer,
        }
    }

    pub fn ioctl_output_buffer_mut(&mut self, method: u32) -> &mut [u8] {
        match method {
            nt_io_abi::ioctl::METHOD_IN_DIRECT | nt_io_abi::ioctl::METHOD_OUT_DIRECT => {
                self.direct_buffer.as_deref_mut().unwrap_or(&mut [])
            }
            nt_io_abi::ioctl::METHOD_NEITHER => self.user_buffer.as_deref_mut().unwrap_or(&mut []),
            _ => self.system_buffer,
        }
    }

    pub fn has_nonbuffered_transfer(&self) -> bool {
        self.direct_buffer.is_some()
            || self.type3_input_buffer.is_some()
            || self.user_buffer.is_some()
    }
}

/// The per-driver view of an IRP handed to a backend (spec §4.2, §16.4). Carries
/// ids + the current stack location's parameters — never a canonical pointer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IrpProjection {
    pub irp_id: IrpId,
    pub device_id: DeviceId,
    pub file_id: Option<FileId>,
    pub major: u8,
    pub minor: u8,
    pub parameters: IoParameters,
    pub buffer: Option<IoBufferRef>,
    pub user_data: u64,
    pub requestor_tid: u64,
}

impl IrpProjection {
    /// Project the canonical IRP (using its current stack location's parameters).
    pub fn from_record(record: &IrpRecord) -> Self {
        let (minor, parameters) = record
            .current_stack()
            .map(|s| (s.minor, s.parameters.clone()))
            .unwrap_or((record.minor, IoParameters::Unsupported));
        Self {
            irp_id: record.id,
            device_id: record.device_id,
            file_id: record.file_id,
            major: record.major,
            minor,
            parameters,
            buffer: record.buffer,
            user_data: record.user_data,
            requestor_tid: record.requestor_tid,
        }
    }
}

/// The result of dispatching an IRP to a backend (spec §15.1).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DispatchOutcome {
    /// Finished synchronously with a final status + `IoStatus.Information`.
    Completed { status: NtStatus, information: u64 },
    /// Accepted as pending; a final completion arrives later.
    Pending,
    /// Rejected up front with a failure status.
    Failed { status: NtStatus },
}

impl DispatchOutcome {
    /// Map an `NtStatus` to a synchronous outcome: success → `Completed`, error →
    /// `Failed`.
    pub fn from_status(status: NtStatus, information: u64) -> Self {
        if status.is_success() {
            DispatchOutcome::Completed {
                status,
                information,
            }
        } else {
            DispatchOutcome::Failed { status }
        }
    }
}

/// A final completion of a previously-pending IRP, delivered by a driver back to
/// the I/O Manager (spec §16.5, the reverse-ring `IODRV_OP_COMPLETE_IRP`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct DriverCompletion {
    pub irp_id: IrpId,
    pub status: NtStatus,
    pub information: u64,
}

/// A driver dispatch backend (spec §15.1). Pluggable: the mock backend for
/// tests/bring-up, or a SURT driver-peer backend for an isolated Driver Host.
pub trait DriverDispatchBackend {
    /// Dispatch one IRP projection. Returns how it was handled.
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus>;

    /// Request cancellation of a (typically pending) IRP owned by this backend.
    fn cancel_irp(&mut self, irp_id: IrpId) -> Result<(), NtStatus>;

    /// Poll for a ready final completion of a previously-pending IRP. The I/O
    /// Manager's `pump` drains these. Backends that only complete synchronously
    /// use the default (never any pending completions).
    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        None
    }

    /// Copy retained output for a terminal asynchronous completion. The I/O
    /// Manager calls this only after `irp_id` has been published as completed
    /// and bounds the destination to `IoStatus.Information`. Backends that can
    /// complete pending requests with nonzero output must retain that output
    /// until [`acknowledge_completion`](Self::acknowledge_completion).
    fn copy_completion_output(
        &mut self,
        _irp_id: IrpId,
        _offset: u64,
        output: &mut [u8],
    ) -> Result<usize, NtStatus> {
        if output.is_empty() {
            Ok(0)
        } else {
            Err(NtStatus::NOT_SUPPORTED)
        }
    }

    /// Release backend-owned state for an acknowledged terminal completion.
    /// Failure leaves the canonical completion live so the consumer can retry.
    /// Backends without retained asynchronous state have nothing to release.
    fn acknowledge_completion(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        Ok(())
    }

    /// Whether the backend's driver has faulted/disconnected (spec §16.6). The
    /// I/O Manager's `pump` faults such a driver — failing its in-flight IRPs and
    /// marking its devices delete-pending. In-process backends never fault.
    fn is_faulted(&self) -> bool {
        false
    }
}
