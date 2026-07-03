//! IRP dispatch into the loaded driver (spec §10.1). Builds a local `IRP` +
//! `IO_STACK_LOCATION` projection from a `DH_OP_DISPATCH_IRP` request, calls the
//! driver's `MajorFunction[major]`, and returns the completion — enforcing
//! exactly-once completion (spec §10.2).

use nt_driver_runtime::ObjectKind;
use nt_kernel_abi::{major, DeviceIoControlParams, GuestAddr, Irp};

use crate::{DispatchInvoke, DriverDispatchGate, DriverServices, DriverState, IoManagerBridge};

const STATUS_PENDING: i32 = 0x0000_0103;
const STATUS_CANCELLED: i32 = 0xC000_0120u32 as i32;
const STATUS_DEVICE_REMOVED: i32 = 0xC000_02BFu32 as i32;
const STATUS_NO_SUCH_DEVICE: i32 = 0xC000_000Eu32 as i32;
const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;
const STATUS_INVALID_DEVICE_STATE: i32 = 0xC000_0184u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;

/// A final completion the Driver Host delivers to the I/O Manager (a
/// `DH_OP_COMPLETE_IRP`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DhCompletion {
    pub irp_id: u64,
    pub status: i32,
    pub information: u64,
}

/// A pending (`STATUS_PENDING`) IRP awaiting a later completion/cancel/fault.
pub(crate) struct PendingIrp {
    pub irp_id: u64,
    pub irp_addr: GuestAddr,
}

/// A request to dispatch one IRP to the loaded driver (a `DH_OP_DISPATCH_IRP`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DispatchRequest {
    pub irp_id: u64,
    /// Canonical `DeviceId` of the target device.
    pub device_id: u64,
    pub major: u8,
    pub minor: u8,
    pub ioctl_code: u32,
    pub input_len: u32,
    pub output_len: u32,
}

/// The outcome of a dispatch (spec §10.1 steps 8–9).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatchResult {
    Completed { status: i32, information: u64 },
    Pending,
    Failed { status: i32 },
}

impl crate::DriverHost {
    /// Dispatch one IRP into the driver: build the local `IRP` +
    /// `IO_STACK_LOCATION`, call `MajorFunction[major]` through `gate`, and return
    /// the completion. `io_buffer` is the `SystemBuffer` staging area (input on
    /// entry; the driver's output on a completed return).
    pub fn dispatch_irp(
        &mut self,
        gate: &dyn DriverDispatchGate,
        bridge: &mut dyn IoManagerBridge,
        req: DispatchRequest,
        io_buffer: &mut [u8],
    ) -> DispatchResult {
        if self.state != DriverState::Started {
            return DispatchResult::Failed {
                status: STATUS_INVALID_DEVICE_STATE,
            };
        }
        // Resolve the local device projection from the canonical id (spec §10.1
        // step 5).
        let device = match self
            .runtime
            .objects()
            .find_by_id(ObjectKind::DeviceObject, req.device_id)
        {
            Some(e) => e.addr,
            None => {
                return DispatchResult::Failed {
                    status: STATUS_NO_SUCH_DEVICE,
                }
            }
        };
        let routine = self.dispatch[req.major as usize];
        if routine.is_null() {
            return DispatchResult::Failed {
                status: STATUS_INVALID_DEVICE_REQUEST,
            };
        }

        // Stage the SystemBuffer + build the local IRP + stack location (step 6).
        let bufsize = io_buffer.len().max(1);
        let sysbuf = match self.runtime.arena_mut().alloc(bufsize, 8) {
            Some(a) => a,
            None => {
                return DispatchResult::Failed {
                    status: STATUS_INSUFFICIENT_RESOURCES,
                }
            }
        };
        self.runtime.arena_mut().write_bytes(sysbuf, io_buffer);

        let irp = match self.runtime.create_irp(req.irp_id, 1, sysbuf) {
            Some(i) => i,
            None => {
                return DispatchResult::Failed {
                    status: STATUS_INSUFFICIENT_RESOURCES,
                }
            }
        };
        if let Some(mut sl) = self.runtime.irp_current_stack(irp) {
            sl.major_function = req.major;
            sl.minor_function = req.minor;
            sl.device_object = device;
            if req.major == major::IRP_MJ_DEVICE_CONTROL
                || req.major == major::IRP_MJ_INTERNAL_DEVICE_CONTROL
            {
                sl.set_device_io_control(DeviceIoControlParams {
                    output_buffer_length: req.output_len,
                    input_buffer_length: req.input_len,
                    io_control_code: req.ioctl_code,
                    ..Default::default()
                });
            }
            self.runtime.set_irp_current_stack(irp, sl);
        }
        self.runtime.track_irp(irp);

        // Call the driver's dispatch routine (step 7).
        let ret = {
            let mut services = DriverServices::new(&mut self.runtime, bridge);
            gate.call_dispatch(
                DispatchInvoke {
                    routine: routine.0,
                    device_object: device,
                    irp,
                },
                &mut services,
            )
        };

        // Determine the outcome (steps 8–9).
        let result = if let Some((status, information)) = self.runtime.irp_completion(irp) {
            // Mirror the driver's SystemBuffer output back (spec §12).
            let n = io_buffer.len();
            if let Some(bytes) = self.runtime.arena().slice(sysbuf, n) {
                io_buffer.copy_from_slice(bytes);
            }
            DispatchResult::Completed {
                status,
                information,
            }
        } else if ret == STATUS_PENDING {
            // The driver accepted the IRP as pending; track it for later
            // completion / cancel / fault (spec §10.1 step 9).
            self.pending.push(PendingIrp {
                irp_id: req.irp_id,
                irp_addr: irp,
            });
            DispatchResult::Pending
        } else {
            DispatchResult::Failed { status: ret }
        };

        if !matches!(result, DispatchResult::Pending) {
            self.runtime.untrack_irp(irp);
        }
        result
    }

    /// Number of IRPs the driver is holding as pending.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Complete a previously-pending IRP (the driver's deferred DPC/worker calling
    /// `IoCompleteRequest`, spec §10.1 step 9). Queues a completion for
    /// [`poll_completion`](Self::poll_completion). Returns `true` if this call
    /// produced the completion (it may lose a race to a cancel — spec §10.2).
    pub fn complete_pending(&mut self, irp_id: u64, status: i32, information: u64) -> bool {
        let Some(idx) = self.pending.iter().position(|p| p.irp_id == irp_id) else {
            return false;
        };
        let irp = self.pending[idx].irp_addr;
        self.write_io_status(irp, status, information);
        match self.runtime.complete_irp(irp) {
            Ok((s, info)) => {
                self.pending.remove(idx);
                self.runtime.untrack_irp(irp);
                self.completions.push(DhCompletion {
                    irp_id,
                    status: s,
                    information: info,
                });
                true
            }
            Err(_) => {
                // Already completed (a cancel won the race) — no-op.
                self.pending.remove(idx);
                false
            }
        }
    }

    /// `DH_OP_CANCEL_IRP` — cancel a pending IRP (spec §10.3). If it is still
    /// pending, complete it with `STATUS_CANCELLED`; if completion already won the
    /// race, this is a no-op. Exactly one final state reaches the I/O Manager.
    pub fn cancel_irp(&mut self, irp_id: u64) -> bool {
        let Some(idx) = self.pending.iter().position(|p| p.irp_id == irp_id) else {
            return false;
        };
        let irp = self.pending[idx].irp_addr;
        if self.runtime.is_irp_completed(irp) {
            self.pending.remove(idx);
            return false;
        }
        self.write_io_status(irp, STATUS_CANCELLED, 0);
        if let Some(mut record) = self.runtime.arena().read::<Irp>(irp) {
            record.cancel = 1;
            self.runtime.arena_mut().write(irp, record);
        }
        match self.runtime.complete_irp(irp) {
            Ok((s, info)) => {
                self.pending.remove(idx);
                self.runtime.untrack_irp(irp);
                self.completions.push(DhCompletion {
                    irp_id,
                    status: s,
                    information: info,
                });
                true
            }
            Err(_) => {
                self.pending.remove(idx);
                false
            }
        }
    }

    /// Drain one ready completion (the I/O Manager's `pump`, spec §16.5).
    pub fn poll_completion(&mut self) -> Option<DhCompletion> {
        if self.completions.is_empty() {
            None
        } else {
            Some(self.completions.remove(0))
        }
    }

    /// Fault the driver: fail all pending IRPs (`STATUS_DEVICE_REMOVED`) so the
    /// I/O Manager can finalize them, and mark the driver faulted (spec §17).
    pub fn fault(&mut self) {
        for p in core::mem::take(&mut self.pending) {
            self.runtime.untrack_irp(p.irp_addr);
            self.completions.push(DhCompletion {
                irp_id: p.irp_id,
                status: STATUS_DEVICE_REMOVED,
                information: 0,
            });
        }
        self.state = DriverState::Faulted;
    }

    fn write_io_status(&mut self, irp: GuestAddr, status: i32, information: u64) {
        if let Some(mut record) = self.runtime.arena().read::<Irp>(irp) {
            record.io_status.status = status;
            record.io_status.information = information;
            self.runtime.arena_mut().write(irp, record);
        }
    }
}
