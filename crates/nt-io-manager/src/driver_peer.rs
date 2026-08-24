//! Driver-peer dispatch backend (spec §15.3, §16).
//!
//! A [`DriverPeerBackend`] is a [`DriverDispatchBackend`] that marshals IRP
//! projections to an isolated, **untrusted** driver peer (a future Driver Host)
//! over a [`DriverPeerTransport`] — a SURT ring pair on the kernel, or a
//! [`MockDriverPeer`] in tests. The peer completes synchronously (a dispatch
//! response), accepts a request as pending (a later reverse-ring completion), or
//! faults. A faulted peer's requests fail with `STATUS_DEVICE_NOT_CONNECTED`; the
//! I/O Manager's `pump` then fails its in-flight IRPs (see `fault.rs`).

use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use nt_io_abi::{ioctl, major, IrpDispatchRequest};
use nt_status::NtStatus;

use crate::dispatch::{
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend, IrpProjection,
};
use crate::IrpId;

/// The transport to a driver peer: dispatch/cancel, poll reverse-ring
/// completions, report faults (spec §16.1–16.2).
pub trait DriverPeerTransport {
    /// Send `IODRV_OP_DISPATCH_IRP` with `request` + transfer buffers, returning
    /// the peer's immediate dispatch response.
    fn dispatch(
        &mut self,
        request: &IrpDispatchRequest,
        buffers: PeerTransferBuffers<'_>,
    ) -> DispatchOutcome;
    /// Send `IODRV_OP_CANCEL_IRP` for `irp_id`.
    fn cancel(&mut self, irp_id: IrpId);
    /// Poll the reverse ring for a peer's final `IODRV_OP_COMPLETE_IRP`.
    fn poll_completion(&mut self) -> Option<DriverCompletion>;
    /// Whether the peer has faulted / disconnected.
    fn is_faulted(&self) -> bool;
}

/// Transfer buffers passed to a driver peer. `system` is the
/// `AssociatedIrp.SystemBuffer` staging area; the optional buffers model direct
/// I/O and neither I/O without collapsing them into `system`.
pub struct PeerTransferBuffers<'a> {
    pub system: &'a mut [u8],
    pub direct: Option<&'a mut [u8]>,
    pub type3_input: Option<&'a mut [u8]>,
    pub user: Option<&'a mut [u8]>,
}

impl<'a> PeerTransferBuffers<'a> {
    pub fn new(system: &'a mut [u8]) -> Self {
        Self {
            system,
            direct: None,
            type3_input: None,
            user: None,
        }
    }
}

fn segment(cursor: &mut u32, len: usize) -> Result<(u32, u32), NtStatus> {
    let len = u32::try_from(len).map_err(|_| NtStatus::INVALID_PARAMETER)?;
    if len == 0 {
        return Ok((0, 0));
    }
    let offset = *cursor;
    *cursor = cursor.checked_add(len).ok_or(NtStatus::INVALID_PARAMETER)?;
    Ok((offset, len))
}

/// Build the wire dispatch request for a projection (spec §16.4).
fn build_dispatch_request(
    irp: &IrpProjection,
    ctx: &DispatchContext<'_>,
) -> Result<IrpDispatchRequest, NtStatus> {
    let mut cursor = u32::try_from(core::mem::size_of::<IrpDispatchRequest>())
        .map_err(|_| NtStatus::INVALID_PARAMETER)?;
    let (buffer_offset, buffer_len) = segment(&mut cursor, ctx.system_buffer.len())?;
    let (direct_buffer_offset, direct_buffer_len) = segment(
        &mut cursor,
        ctx.direct_buffer.as_ref().map(|b| b.len()).unwrap_or(0),
    )?;
    let (type3_input_offset, type3_input_len) = segment(
        &mut cursor,
        ctx.type3_input_buffer
            .as_ref()
            .map(|b| b.len())
            .unwrap_or(0),
    )?;
    let (user_buffer_offset, user_buffer_len) = segment(
        &mut cursor,
        ctx.user_buffer.as_ref().map(|b| b.len()).unwrap_or(0),
    )?;
    let (ioctl_code, input_len, output_len) = match &irp.parameters {
        crate::irp::IoParameters::DeviceControl(p)
        | crate::irp::IoParameters::InternalDeviceControl(p) => {
            (p.ioctl_code, p.input_len, p.output_len)
        }
        _ => (0, 0, 0),
    };
    Ok(IrpDispatchRequest {
        abi_size: core::mem::size_of::<IrpDispatchRequest>() as u16,
        major: irp.major,
        minor: irp.minor,
        flags: irp.flags.bits() as u32 | ((irp.control.bits() as u32) << 8),
        irp_id: irp.irp_id.0,
        driver_id: irp.driver_id.0,
        device_id: irp.device_id.0,
        file_id: irp.file_id.map(|f| f.0).unwrap_or(0),
        buffer_id: irp.buffer.map(|b| b.buffer_id).unwrap_or(0),
        buffer_offset: buffer_offset as u64,
        buffer_len,
        direct_buffer_offset,
        direct_buffer_len,
        type3_input_offset,
        type3_input_len,
        user_buffer_offset,
        user_buffer_len,
        input_len,
        output_len,
        ioctl_code,
        parameter_offset: 0,
        parameter_len: 0,
        stack_location: irp.stack_location as u32,
        stack_count: irp.stack_count as u32,
    })
}

/// A `DriverDispatchBackend` that dispatches to an isolated driver peer over `T`.
pub struct DriverPeerBackend<T> {
    transport: T,
}

impl<T: DriverPeerTransport> DriverPeerBackend<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: DriverPeerTransport> DriverDispatchBackend for DriverPeerBackend<T> {
    fn dispatch_irp(
        &mut self,
        ctx: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        if self.transport.is_faulted() {
            return Ok(DispatchOutcome::Failed {
                status: NtStatus::DEVICE_NOT_CONNECTED,
            });
        }
        let request = build_dispatch_request(irp, &ctx)?;
        Ok(self.transport.dispatch(
            &request,
            PeerTransferBuffers {
                system: ctx.system_buffer,
                direct: ctx.direct_buffer,
                type3_input: ctx.type3_input_buffer,
                user: ctx.user_buffer,
            },
        ))
    }

    fn cancel_irp(&mut self, irp_id: IrpId) -> Result<(), NtStatus> {
        self.transport.cancel(irp_id);
        Ok(())
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.transport.poll_completion()
    }

    fn is_faulted(&self) -> bool {
        self.transport.is_faulted()
    }
}

// ---------------------------------------------------------------------------
// Mock driver peer — an in-memory simulated peer for tests. The state is shared
// (Rc<RefCell>) so a test can control a peer that has already been boxed into the
// I/O Manager's backend registry.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PeerState {
    create_status: NtStatus,
    read_data: Vec<u8>,
    force_pending: bool,
    pending_completion: Option<(NtStatus, u64)>,
    faulted: bool,
    written: Vec<u8>,
    ready: Vec<DriverCompletion>,
}

/// A shared handle to a mock peer's configuration + observed state.
#[derive(Clone, Default)]
pub struct MockPeerControl {
    state: Rc<RefCell<PeerState>>,
}

impl MockPeerControl {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(PeerState {
                create_status: NtStatus::SUCCESS,
                ..Default::default()
            })),
        }
    }

    /// The transport handle to hand to a [`DriverPeerBackend`].
    pub fn transport(&self) -> MockDriverPeer {
        MockDriverPeer {
            state: self.state.clone(),
        }
    }

    pub fn set_read_data(&self, data: &[u8]) {
        self.state.borrow_mut().read_data = data.to_vec();
    }
    pub fn set_create_status(&self, status: NtStatus) {
        self.state.borrow_mut().create_status = status;
    }
    pub fn set_force_pending(&self, pending: bool) {
        self.state.borrow_mut().force_pending = pending;
    }
    pub fn set_pending_completion(&self, status: NtStatus, information: u64) {
        self.state.borrow_mut().pending_completion = Some((status, information));
    }
    /// Simulate the peer faulting / disconnecting.
    pub fn set_faulted(&self, faulted: bool) {
        self.state.borrow_mut().faulted = faulted;
    }
    pub fn written(&self) -> Vec<u8> {
        self.state.borrow().written.clone()
    }
}

/// A mock driver-peer transport, obtained from [`MockPeerControl::transport`].
pub struct MockDriverPeer {
    state: Rc<RefCell<PeerState>>,
}

impl DriverPeerTransport for MockDriverPeer {
    fn dispatch(
        &mut self,
        request: &IrpDispatchRequest,
        mut buffers: PeerTransferBuffers<'_>,
    ) -> DispatchOutcome {
        let mut s = self.state.borrow_mut();
        if s.faulted {
            return DispatchOutcome::Failed {
                status: NtStatus::DEVICE_NOT_CONNECTED,
            };
        }
        let is_data = matches!(
            request.major,
            major::IRP_MJ_READ
                | major::IRP_MJ_WRITE
                | major::IRP_MJ_DEVICE_CONTROL
                | major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        );
        if s.force_pending && is_data {
            if let Some((status, information)) = s.pending_completion {
                s.ready.push(DriverCompletion {
                    irp_id: IrpId(request.irp_id),
                    status,
                    information,
                    file_context: None,
                });
            }
            return DispatchOutcome::Pending;
        }
        match request.major {
            major::IRP_MJ_CREATE => DispatchOutcome::from_status(s.create_status, 0),
            major::IRP_MJ_READ => {
                let buffer = &mut buffers.system;
                let n = s.read_data.len().min(buffer.len());
                buffer[..n].copy_from_slice(&s.read_data[..n]);
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n as u64,
                    file_context: None,
                }
            }
            major::IRP_MJ_WRITE => {
                let n = (request.buffer_len as usize).min(buffers.system.len());
                s.written = buffers.system[..n].to_vec();
                s.read_data = s.written.clone(); // loopback
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n as u64,
                    file_context: None,
                }
            }
            major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL => {
                let method = ioctl::method(request.ioctl_code);
                let mut input_copy = Vec::new();
                match method {
                    ioctl::METHOD_NEITHER => {
                        let input = buffers.type3_input.as_deref().unwrap_or(&[]);
                        let input_len = (request.input_len as usize).min(input.len());
                        input_copy.extend_from_slice(&input[..input_len]);
                    }
                    _ => {
                        let input_len = (request.input_len as usize).min(buffers.system.len());
                        input_copy.extend_from_slice(&buffers.system[..input_len]);
                    }
                };
                let output = match method {
                    ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
                        buffers.direct.as_deref_mut().unwrap_or(&mut [])
                    }
                    ioctl::METHOD_NEITHER => buffers.user.as_deref_mut().unwrap_or(&mut []),
                    _ => buffers.system,
                };
                let n = input_copy
                    .len()
                    .min(request.output_len as usize)
                    .min(output.len());
                output[..n].copy_from_slice(&input_copy[..n]);
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n as u64,
                    file_context: None,
                }
            }
            major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE | major::IRP_MJ_FLUSH_BUFFERS => {
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: 0,
                    file_context: None,
                }
            }
            _ => DispatchOutcome::Failed {
                status: NtStatus::INVALID_DEVICE_REQUEST,
            },
        }
    }

    fn cancel(&mut self, irp_id: IrpId) {
        let mut state = self.state.borrow_mut();
        if !state
            .ready
            .iter()
            .any(|completion| completion.irp_id == irp_id)
        {
            state.ready.push(DriverCompletion {
                irp_id,
                status: NtStatus::CANCELLED,
                information: 0,
                file_context: None,
            });
        }
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.state.borrow_mut().ready.pop()
    }

    fn is_faulted(&self) -> bool {
        self.state.borrow().faulted
    }
}
