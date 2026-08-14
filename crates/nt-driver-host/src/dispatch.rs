//! IRP dispatch into the loaded driver (spec §10.1). Builds a local `IRP` +
//! `IO_STACK_LOCATION` projection from a `DH_OP_DISPATCH_IRP` request, calls the
//! driver's `MajorFunction[major]`, and returns the completion — enforcing
//! exactly-once completion (spec §10.2).

use nt_driver_runtime::ObjectKind;
use nt_io_abi::ioctl;
use nt_kernel_abi::{major, DeviceIoControlParams, GuestAddr, Irp};

use crate::{DispatchInvoke, DriverDispatchGate, DriverServices, DriverState, IoManagerBridge};

const STATUS_PENDING: i32 = 0x0000_0103;
const STATUS_CANCELLED: i32 = 0xC000_0120u32 as i32;
const STATUS_DEVICE_REMOVED: i32 = 0xC000_02BFu32 as i32;
const STATUS_NO_SUCH_DEVICE: i32 = 0xC000_000Eu32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
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

/// Buffers projected into a dispatched IRP.
pub struct DispatchBuffers<'a> {
    pub system: &'a mut [u8],
    pub direct: Option<&'a mut [u8]>,
    pub type3_input: Option<&'a mut [u8]>,
    pub user: Option<&'a mut [u8]>,
}

impl<'a> DispatchBuffers<'a> {
    pub fn new(system: &'a mut [u8]) -> Self {
        Self {
            system,
            direct: None,
            type3_input: None,
            user: None,
        }
    }

    pub fn with_transfer_buffers(
        system: &'a mut [u8],
        direct: Option<&'a mut [u8]>,
        type3_input: Option<&'a mut [u8]>,
        user: Option<&'a mut [u8]>,
    ) -> Self {
        Self {
            system,
            direct,
            type3_input,
            user,
        }
    }
}

/// The outcome of a dispatch (spec §10.1 steps 8–9).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DispatchResult {
    Completed { status: i32, information: u64 },
    Pending,
    Failed { status: i32 },
}

impl crate::DriverHost {
    fn alloc_driver_buffer(&mut self, data: &[u8], allocate_empty: bool) -> Option<GuestAddr> {
        if data.is_empty() && !allocate_empty {
            return Some(GuestAddr::NULL);
        }
        let addr = self.runtime.arena_mut().alloc(data.len().max(1), 8)?;
        if !data.is_empty() {
            self.runtime.arena_mut().write_bytes(addr, data);
        }
        Some(addr)
    }

    fn alloc_nonpaged_mdl(&mut self, virtual_address: GuestAddr, len: usize) -> Option<GuestAddr> {
        if virtual_address.is_null() || len == 0 || len > u32::MAX as usize {
            return Some(GuestAddr::NULL);
        }
        let mdl = self.runtime.arena_mut().alloc(nt_mdl::MDL_SIZE, 8)?;
        let mut bytes = [0u8; nt_mdl::MDL_SIZE];
        put_i16(
            &mut bytes,
            nt_mdl::MDL_OFF_SIZE as usize,
            nt_mdl::MDL_SIZE as i16,
        );
        put_i16(
            &mut bytes,
            nt_mdl::MDL_OFF_FLAGS as usize,
            nt_mdl::MDL_MAPPED_TO_SYSTEM_VA
                | nt_mdl::MDL_PAGES_LOCKED
                | nt_mdl::MDL_SOURCE_IS_NONPAGED_POOL,
        );
        put_u64(
            &mut bytes,
            nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA as usize,
            virtual_address.0,
        );
        put_u64(
            &mut bytes,
            nt_mdl::MDL_OFF_START_VA as usize,
            virtual_address.0 & !0xFFF,
        );
        put_u32(&mut bytes, nt_mdl::MDL_OFF_BYTE_COUNT as usize, len as u32);
        put_u32(
            &mut bytes,
            nt_mdl::MDL_OFF_BYTE_OFFSET as usize,
            (virtual_address.0 & 0xFFF) as u32,
        );
        self.runtime
            .arena_mut()
            .write_bytes(mdl, &bytes)
            .then_some(mdl)
    }

    fn copy_driver_buffer(&self, addr: GuestAddr, out: &mut [u8]) {
        if addr.is_null() || out.is_empty() {
            return;
        }
        if let Some(bytes) = self.runtime.arena().slice(addr, out.len()) {
            out.copy_from_slice(bytes);
        }
    }

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
        self.dispatch_irp_with_buffers(gate, bridge, req, DispatchBuffers::new(io_buffer))
    }

    /// Dispatch one IRP with explicit transfer-method buffers.
    pub fn dispatch_irp_with_buffers(
        &mut self,
        gate: &dyn DriverDispatchGate,
        bridge: &mut dyn IoManagerBridge,
        req: DispatchRequest,
        mut buffers: DispatchBuffers<'_>,
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
        let Some(&routine) = self.dispatch.get(req.major as usize) else {
            return DispatchResult::Failed {
                status: STATUS_INVALID_DEVICE_REQUEST,
            };
        };
        if routine.is_null() {
            return DispatchResult::Failed {
                status: STATUS_INVALID_DEVICE_REQUEST,
            };
        }

        // Stage transfer buffers + build the local IRP + stack location (step 6).
        let control_method = if req.major == major::IRP_MJ_DEVICE_CONTROL
            || req.major == major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        {
            Some(ioctl::method(req.ioctl_code))
        } else {
            None
        };
        if !dispatch_buffers_match(control_method, req, &buffers) {
            return DispatchResult::Failed {
                status: STATUS_INVALID_PARAMETER,
            };
        }
        let sysbuf = match control_method {
            Some(ioctl::METHOD_NEITHER) => GuestAddr::NULL,
            _ => match self.alloc_driver_buffer(&*buffers.system, true) {
                Some(a) => a,
                None => {
                    return DispatchResult::Failed {
                        status: STATUS_INSUFFICIENT_RESOURCES,
                    }
                }
            },
        };
        let direct_buffer = match control_method {
            Some(ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT) => {
                let data = buffers.direct.as_deref().unwrap_or(&[]);
                match self.alloc_driver_buffer(data, false) {
                    Some(a) => a,
                    None => {
                        return DispatchResult::Failed {
                            status: STATUS_INSUFFICIENT_RESOURCES,
                        }
                    }
                }
            }
            _ => GuestAddr::NULL,
        };
        let type3_input_buffer = match control_method {
            Some(ioctl::METHOD_NEITHER) => {
                let data = buffers.type3_input.as_deref().unwrap_or(&[]);
                match self.alloc_driver_buffer(data, false) {
                    Some(a) => a,
                    None => {
                        return DispatchResult::Failed {
                            status: STATUS_INSUFFICIENT_RESOURCES,
                        }
                    }
                }
            }
            _ => GuestAddr::NULL,
        };
        let user_buffer = match control_method {
            Some(ioctl::METHOD_NEITHER) => {
                let data = buffers.user.as_deref().unwrap_or(&[]);
                match self.alloc_driver_buffer(data, false) {
                    Some(a) => a,
                    None => {
                        return DispatchResult::Failed {
                            status: STATUS_INSUFFICIENT_RESOURCES,
                        }
                    }
                }
            }
            _ => GuestAddr::NULL,
        };
        let mdl_address = match self.alloc_nonpaged_mdl(
            direct_buffer,
            buffers.direct.as_ref().map(|b| b.len()).unwrap_or(0),
        ) {
            Some(a) => a,
            None => {
                return DispatchResult::Failed {
                    status: STATUS_INSUFFICIENT_RESOURCES,
                }
            }
        };

        let irp = match self.runtime.create_irp(req.irp_id, 1, sysbuf) {
            Some(i) => i,
            None => {
                return DispatchResult::Failed {
                    status: STATUS_INSUFFICIENT_RESOURCES,
                }
            }
        };
        if let Some(mut record) = self.runtime.arena().read::<Irp>(irp) {
            record.mdl_address = mdl_address;
            record.user_buffer = user_buffer;
            self.runtime.arena_mut().write(irp, record);
        }
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
                    type3_input_buffer,
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
            // Mirror the driver's method-specific output back (spec §12).
            match control_method {
                Some(ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT) => {
                    if let Some(out) = buffers.direct.as_deref_mut() {
                        self.copy_driver_buffer(direct_buffer, out);
                    }
                }
                Some(ioctl::METHOD_NEITHER) => {
                    if let Some(out) = buffers.user.as_deref_mut() {
                        self.copy_driver_buffer(user_buffer, out);
                    }
                }
                _ => self.copy_driver_buffer(sysbuf, &mut *buffers.system),
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

fn put_i16(bytes: &mut [u8], offset: usize, value: i16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn dispatch_buffers_match(
    control_method: Option<u32>,
    req: DispatchRequest,
    buffers: &DispatchBuffers<'_>,
) -> bool {
    let input_len = req.input_len as usize;
    let output_len = req.output_len as usize;
    match control_method {
        Some(ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT) => {
            buffers.system.len() >= input_len
                && buffers.direct.as_ref().map(|b| b.len()).unwrap_or(0) >= output_len
                && buffers.type3_input.is_none()
                && buffers.user.is_none()
        }
        Some(ioctl::METHOD_NEITHER) => {
            buffers.system.is_empty()
                && buffers.type3_input.as_ref().map(|b| b.len()).unwrap_or(0) >= input_len
                && buffers.user.as_ref().map(|b| b.len()).unwrap_or(0) >= output_len
                && buffers.direct.is_none()
        }
        Some(ioctl::METHOD_BUFFERED) => {
            buffers.system.len() >= input_len.max(output_len)
                && buffers.direct.is_none()
                && buffers.type3_input.is_none()
                && buffers.user.is_none()
        }
        Some(_) => false,
        None => {
            buffers.system.len() >= input_len.max(output_len)
                && buffers.direct.is_none()
                && buffers.type3_input.is_none()
                && buffers.user.is_none()
        }
    }
}
