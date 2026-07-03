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
}

impl<'a> DispatchContext<'a> {
    pub fn new(driver_id: DriverId, client_id: ClientId, system_buffer: &'a mut [u8]) -> Self {
        Self {
            driver_id,
            client_id,
            system_buffer,
        }
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
}
