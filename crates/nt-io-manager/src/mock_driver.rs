//! An in-process mock driver backend (spec §15.2).
//!
//! Deterministic + configurable, for unit/integration tests and bring-up before a
//! real Driver Host exists: create succeeds/fails, reads return fixed data, writes
//! record bytes, IOCTLs echo their input or return a configured status, requests
//! can be forced pending then completed later, and any operation can be failed by
//! error injection.

use alloc::vec::Vec;

use nt_io_abi::major;
use nt_status::NtStatus;

use crate::dispatch::{DispatchContext, DispatchOutcome, DriverDispatchBackend, IrpProjection};
use crate::irp::IoParameters;
use crate::IrpId;

/// How the mock handles `IRP_MJ_DEVICE_CONTROL` / `IRP_MJ_INTERNAL_DEVICE_CONTROL`.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum IoctlBehavior {
    /// Copy the input back as the output (buffered echo).
    #[default]
    Echo,
    /// Complete with a fixed status (no transfer).
    Status(NtStatus),
}

/// A configurable in-process driver backend.
#[derive(Default)]
pub struct MockDriverBackend {
    create_status: NtStatus,
    read_data: Vec<u8>,
    ioctl: IoctlBehavior,
    force_pending: bool,
    inject_error: Option<NtStatus>,
    written: Vec<u8>,
    pending: Vec<IrpId>,
    cancelled: Vec<IrpId>,
}

impl MockDriverBackend {
    /// A backend that completes creates successfully and echoes IOCTLs.
    pub fn new() -> Self {
        Self {
            create_status: NtStatus::SUCCESS,
            ..Self::default()
        }
    }

    /// Set the data returned by reads (builder-style).
    pub fn with_read_data(mut self, data: &[u8]) -> Self {
        self.read_data = data.to_vec();
        self
    }

    /// Set the status `IRP_MJ_CREATE` completes with.
    pub fn set_create_status(&mut self, status: NtStatus) {
        self.create_status = status;
    }

    /// Set IOCTL behaviour.
    pub fn set_ioctl(&mut self, behavior: IoctlBehavior) {
        self.ioctl = behavior;
    }

    /// If true, every dispatch is accepted as pending (completed later via
    /// [`complete_pending`](Self::complete_pending)).
    pub fn set_force_pending(&mut self, pending: bool) {
        self.force_pending = pending;
    }

    /// Fail every dispatch with `status` (error injection); `None` disables it.
    pub fn inject_error(&mut self, status: Option<NtStatus>) {
        self.inject_error = status;
    }

    /// The bytes recorded by the most recent write.
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Whether `irp` is currently accepted-pending in this backend.
    pub fn is_pending(&self, irp: IrpId) -> bool {
        self.pending.contains(&irp)
    }

    /// Whether `irp` was cancelled while pending.
    pub fn was_cancelled(&self, irp: IrpId) -> bool {
        self.cancelled.contains(&irp)
    }

    /// Deliver the final completion of a previously-pending IRP (what the driver
    /// peer would send over the reverse ring). Returns the outcome for the I/O
    /// Manager to apply. Errors if `irp` is not pending here.
    pub fn complete_pending(
        &mut self,
        irp: IrpId,
        status: NtStatus,
        information: u64,
    ) -> Result<DispatchOutcome, NtStatus> {
        match self.pending.iter().position(|&i| i == irp) {
            Some(pos) => {
                self.pending.remove(pos);
                Ok(DispatchOutcome::from_status(status, information))
            }
            None => Err(NtStatus::INVALID_PARAMETER),
        }
    }
}

/// Copy up to `min(want, src.len(), dst.len())` bytes of `src` into `dst`,
/// returning the count.
fn fill(dst: &mut [u8], src: &[u8], want: usize) -> u64 {
    let n = want.min(src.len()).min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n as u64
}

impl DriverDispatchBackend for MockDriverBackend {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        if let Some(status) = self.inject_error {
            return Ok(DispatchOutcome::Failed { status });
        }
        if self.force_pending {
            self.pending.push(irp.irp_id);
            return Ok(DispatchOutcome::Pending);
        }

        let outcome = match irp.major {
            major::IRP_MJ_CREATE => DispatchOutcome::from_status(self.create_status, 0),

            major::IRP_MJ_READ => {
                let want = match &irp.parameters {
                    IoParameters::Read(p) => p.length as usize,
                    _ => ctx.system_buffer.len(),
                };
                let n = fill(ctx.system_buffer, &self.read_data, want);
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n,
                }
            }

            major::IRP_MJ_WRITE => {
                let want = match &irp.parameters {
                    IoParameters::Write(p) => p.length as usize,
                    _ => ctx.system_buffer.len(),
                };
                let n = want.min(ctx.system_buffer.len());
                self.written = ctx.system_buffer[..n].to_vec();
                // Loopback: a later read returns what was written (so a
                // write/read round-trip is observable through the I/O result).
                self.read_data = self.written.clone();
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n as u64,
                }
            }

            major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL => {
                match self.ioctl {
                    IoctlBehavior::Echo => {
                        // Buffered echo: input already occupies the system buffer, so
                        // the output is those same bytes (bounded by output length).
                        let (input_len, output_len) = match &irp.parameters {
                            IoParameters::DeviceControl(p)
                            | IoParameters::InternalDeviceControl(p) => {
                                (p.input_len as usize, p.output_len as usize)
                            }
                            _ => (0, 0),
                        };
                        let n = input_len.min(output_len).min(ctx.system_buffer.len());
                        DispatchOutcome::Completed {
                            status: NtStatus::SUCCESS,
                            information: n as u64,
                        }
                    }
                    IoctlBehavior::Status(status) => DispatchOutcome::from_status(status, 0),
                }
            }

            major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE | major::IRP_MJ_FLUSH_BUFFERS => {
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                }
            }

            _ => DispatchOutcome::Failed {
                status: NtStatus::INVALID_DEVICE_REQUEST,
            },
        };
        Ok(outcome)
    }

    fn cancel_irp(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
        match self.pending.iter().position(|&i| i == irp_id) {
            Some(pos) => {
                self.pending.remove(pos);
                self.cancelled.push(irp_id);
                Ok(())
            }
            None => Err(NtStatus::INVALID_PARAMETER),
        }
    }
}
