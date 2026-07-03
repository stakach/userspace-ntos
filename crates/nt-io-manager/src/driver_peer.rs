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

use nt_io_abi::{major, IrpDispatchRequest};
use nt_status::NtStatus;

use crate::dispatch::{
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend, IrpProjection,
};
use crate::IrpId;

/// The transport to a driver peer: dispatch/cancel, poll reverse-ring
/// completions, report faults (spec §16.1–16.2).
pub trait DriverPeerTransport {
    /// Send `IODRV_OP_DISPATCH_IRP` with `request` + the shared `buffer` (write
    /// input / read output), returning the peer's immediate dispatch response.
    fn dispatch(&mut self, request: &IrpDispatchRequest, buffer: &mut [u8]) -> DispatchOutcome;
    /// Send `IODRV_OP_CANCEL_IRP` for `irp_id`.
    fn cancel(&mut self, irp_id: IrpId);
    /// Poll the reverse ring for a peer's final `IODRV_OP_COMPLETE_IRP`.
    fn poll_completion(&mut self) -> Option<DriverCompletion>;
    /// Whether the peer has faulted / disconnected.
    fn is_faulted(&self) -> bool;
}

/// Build the wire dispatch request for a projection (spec §16.4).
fn build_dispatch_request(irp: &IrpProjection, buffer_len: u32) -> IrpDispatchRequest {
    IrpDispatchRequest {
        abi_size: core::mem::size_of::<IrpDispatchRequest>() as u16,
        major: irp.major,
        minor: irp.minor,
        flags: 0,
        irp_id: irp.irp_id.0,
        device_id: irp.device_id.0,
        file_id: irp.file_id.map(|f| f.0).unwrap_or(0),
        buffer_id: irp.buffer.map(|b| b.buffer_id).unwrap_or(0),
        buffer_offset: 0,
        buffer_len,
        parameter_offset: 0,
        parameter_len: 0,
        _reserved: 0,
    }
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
        let request = build_dispatch_request(irp, ctx.system_buffer.len() as u32);
        Ok(self.transport.dispatch(&request, ctx.system_buffer))
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
    fn dispatch(&mut self, request: &IrpDispatchRequest, buffer: &mut [u8]) -> DispatchOutcome {
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
                });
            }
            return DispatchOutcome::Pending;
        }
        match request.major {
            major::IRP_MJ_CREATE => DispatchOutcome::from_status(s.create_status, 0),
            major::IRP_MJ_READ => {
                let n = s.read_data.len().min(buffer.len());
                buffer[..n].copy_from_slice(&s.read_data[..n]);
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n as u64,
                }
            }
            major::IRP_MJ_WRITE => {
                let n = (request.buffer_len as usize).min(buffer.len());
                s.written = buffer[..n].to_vec();
                s.read_data = s.written.clone(); // loopback
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: n as u64,
                }
            }
            major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL => {
                // Buffered echo: the input already occupies the system buffer.
                DispatchOutcome::Completed {
                    status: NtStatus::SUCCESS,
                    information: buffer.len() as u64,
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
        }
    }

    fn cancel(&mut self, irp_id: IrpId) {
        self.state.borrow_mut().ready.retain(|c| c.irp_id != irp_id);
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        self.state.borrow_mut().ready.pop()
    }

    fn is_faulted(&self) -> bool {
        self.state.borrow().faulted
    }
}
