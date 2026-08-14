//! The io-side component: runs the I/O Manager (over an in-process Object
//! Manager) and dispatches driver work to the **isolated driver peer** over SURT.
//!
//! `SurtPeerTransport` implements `DriverPeerTransport`: it stages the
//! `IrpDispatchRequest` plus transfer-method-specific buffer segments into the
//! shared data frame, pushes an `IODRV_OP_DISPATCH_IRP` `SurtSqe`, wakes the
//! peer, blocks for the peer's dispatch `SurtCqe`, then copies the peer's output
//! segments back and maps it to a `DispatchOutcome`. Every open/read/write/IOCTL
//! the io-side runs on its own `IoManager` therefore crosses an address-space
//! boundary into the driver peer.

use crate::*;

use alloc::boxed::Box;
use core::mem::size_of;

use nt_io_abi::opcodes::driver::IODRV_OP_DISPATCH_IRP;
use nt_io_abi::{ioctl, IrpDispatchRequest};
use nt_io_manager::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, DispatchOutcome,
    DriverCompletion, DriverPeerBackend, DriverPeerTransport, IoManager, IrpId,
    ObjectManagerLibraryPort, ShareAccess,
    PeerTransferBuffers,
};
use nt_object_manager::ComponentId;
use nt_status::NtStatus;
use nt_types::{AccessMask, HandleValue, NtPath};
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

/// The driver-peer transport over the SURT ring pair.
struct SurtPeerTransport<'a> {
    sq: Producer<SurtSqe>,
    cq: Consumer<SurtCqe>,
    signal_peer: Sel4Notify<'a, KernelEnv>,
    wait_completion: Sel4Notify<'a, KernelEnv>,
    next_id: u64,
}

impl DriverPeerTransport for SurtPeerTransport<'_> {
    fn dispatch(
        &mut self,
        request: &IrpDispatchRequest,
        mut buffers: PeerTransferBuffers<'_>,
    ) -> DispatchOutcome {
        let total_len = match staged_len(request) {
            Some(len) if len <= REQ_DATA_LEN => len,
            _ => {
                return DispatchOutcome::Failed {
                    status: NtStatus::INVALID_PARAMETER,
                }
            }
        };
        if !segment_matches(request.buffer_offset, request.buffer_len, buffers.system.len())
            || !optional_segment_matches(
                request.direct_buffer_offset,
                request.direct_buffer_len,
                buffers.direct.as_ref().map(|b| b.len()).unwrap_or(0),
            )
            || !optional_segment_matches(
                request.type3_input_offset,
                request.type3_input_len,
                buffers.type3_input.as_ref().map(|b| b.len()).unwrap_or(0),
            )
            || !optional_segment_matches(
                request.user_buffer_offset,
                request.user_buffer_len,
                buffers.user.as_ref().map(|b| b.len()).unwrap_or(0),
            )
        {
            return DispatchOutcome::Failed {
                status: NtStatus::INVALID_PARAMETER,
            };
        }

        // Stage [IrpDispatchRequest][system][direct][type3][user] into the shared data frame.
        unsafe {
            let base = REQ_DATA_VADDR as *mut u8;
            for (i, b) in bytemuck::bytes_of(request).iter().enumerate() {
                core::ptr::write_volatile(base.add(i), *b);
            }
            write_segment(request.buffer_offset, &*buffers.system);
            if let Some(direct) = buffers.direct.as_deref() {
                write_segment(request.direct_buffer_offset as u64, direct);
            }
            if let Some(type3) = buffers.type3_input.as_deref() {
                write_segment(request.type3_input_offset as u64, type3);
            }
            if let Some(user) = buffers.user.as_deref() {
                write_segment(request.user_buffer_offset as u64, user);
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        let sqe = SurtSqe {
            opcode: IODRV_OP_DISPATCH_IRP,
            len: total_len as u32,
            request_id: id,
            offset: 0,
            ..Default::default()
        };
        while self.sq.try_push(sqe).is_err() {
            yield_now();
        }
        let _ = self.sq.notify_consumer(&self.signal_peer);

        // Block for the peer's dispatch completion.
        let mut status = 0i32;
        let mut information = 0u64;
        let _ = drain_blocking(&mut self.cq, &self.wait_completion, |cqe: &SurtCqe| {
            if cqe.request_id == id {
                status = cqe.status;
                information = cqe.information;
                false
            } else {
                true
            }
        });

        // Copy the peer's output segments back into the caller's buffers.
        unsafe {
            read_segment(request.buffer_offset, &mut *buffers.system);
            if let Some(direct) = buffers.direct.as_deref_mut() {
                read_segment(request.direct_buffer_offset as u64, direct);
            }
            if let Some(user) = buffers.user.as_deref_mut() {
                read_segment(request.user_buffer_offset as u64, user);
            }
        }
        DispatchOutcome::from_status(NtStatus(status), information)
    }

    fn cancel(&mut self, _irp_id: IrpId) {}

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        None
    }

    fn is_faulted(&self) -> bool {
        false
    }
}

fn segment_end(offset: u64, len: u32) -> Option<usize> {
    if len == 0 {
        return Some(0);
    }
    let offset = usize::try_from(offset).ok()?;
    let len = len as usize;
    offset.checked_add(len)
}

fn staged_len(request: &IrpDispatchRequest) -> Option<usize> {
    [
        segment_end(0, size_of::<IrpDispatchRequest>() as u32)?,
        segment_end(request.buffer_offset, request.buffer_len)?,
        segment_end(
            request.direct_buffer_offset as u64,
            request.direct_buffer_len,
        )?,
        segment_end(request.type3_input_offset as u64, request.type3_input_len)?,
        segment_end(request.user_buffer_offset as u64, request.user_buffer_len)?,
    ]
    .into_iter()
    .max()
}

fn segment_matches(offset: u64, len: u32, actual_len: usize) -> bool {
    len as usize == actual_len
        && ((len == 0 && offset == 0) || (len != 0 && offset >= size_of::<IrpDispatchRequest>() as u64))
}

fn optional_segment_matches(offset: u32, len: u32, actual_len: usize) -> bool {
    len as usize == actual_len
        && ((len == 0 && offset == 0)
            || (len != 0 && offset as usize >= size_of::<IrpDispatchRequest>()))
}

unsafe fn write_segment(offset: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let base = (REQ_DATA_VADDR + offset) as *mut u8;
    for (i, b) in data.iter().enumerate() {
        core::ptr::write_volatile(base.add(i), *b);
    }
}

unsafe fn read_segment(offset: u64, data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    let base = (REQ_DATA_VADDR + offset) as *const u8;
    for (i, slot) in data.iter_mut().enumerate() {
        *slot = core::ptr::read_volatile(base.add(i));
    }
}

fn npath(s: &str) -> NtPath {
    NtPath::parse_str(s).unwrap_or_default()
}

fn check(name: &[u8], ok: bool, passed: &mut u64) {
    if ok {
        print_str(b"  PASS ");
        *passed += 1;
    } else {
        print_str(b"  FAIL ");
    }
    print_str(name);
    print_str(b"\n");
}

#[no_mangle]
#[link_section = ".text.io_side_entry"]
pub unsafe extern "C" fn io_side_entry() -> ! {
    let sq = match Producer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let cq = match Consumer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let transport = SurtPeerTransport {
        sq,
        cq,
        signal_peer: Sel4Notify::new(&ENV, CT_N_SUB),
        wait_completion: Sel4Notify::new(&ENV, CT_N_COMP),
        next_id: 1,
    };

    // Build the I/O Manager over an in-process Object Manager, with a driver whose
    // backend is the isolated peer.
    let port = match ObjectManagerLibraryPort::new(ComponentId(1)) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let mut io = IoManager::new(port);
    let driver = match io.create_driver_peer(
        &npath("\\Driver\\Peer"),
        Box::new(DriverPeerBackend::new(transport)),
    ) {
        Ok(d) => d,
        Err(_) => park(),
    };
    if io
        .create_device(
            driver,
            Some(&npath("\\Device\\Test0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .is_err()
    {
        park();
    }
    if io
        .create_symbolic_link(&npath("\\??\\Test0"), &npath("\\Device\\Test0"))
        .is_err()
    {
        park();
    }
    let client = io.register_client();

    let mut passed = 0u64;

    let handle = io.open(
        client,
        &npath("\\??\\Test0"),
        AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
        ShareAccess::empty(),
        CreateOptions::empty(),
        0,
    );
    check(b"open", handle.is_ok(), &mut passed);
    let h = handle.unwrap_or(HandleValue::NULL);

    check(b"write", io.write(client, h, 0, b"hi") == Ok(2), &mut passed);

    let mut out = [0u8; 8];
    let read = io.read(client, h, 0, &mut out);
    check(
        b"read",
        matches!(read, Ok(8)) && &out == b"peerread",
        &mut passed,
    );

    let code = ioctl::ctl_code(0x22, 0x800, ioctl::METHOD_BUFFERED, ioctl::FILE_ANY_ACCESS);
    let mut io_out = [0u8; 4];
    check(
        b"device_control",
        matches!(io.device_control(client, h, code, b"ping", &mut io_out), Ok(n) if &io_out[..n as usize] == b"ping"),
        &mut passed,
    );

    check(b"cleanup", io.cleanup(client, h).is_ok(), &mut passed);
    check(b"close", io.close(client, h).is_ok(), &mut passed);

    let _ = ep_send_one(CT_RESULT, passed);
    park()
}

fn park() -> ! {
    loop {
        yield_now();
    }
}
