//! The driver-peer component: an isolated, untrusted "driver" over SURT.
//!
//! It consumes `IODRV_OP_DISPATCH_IRP` requests off the submission ring, decodes
//! the `IrpDispatchRequest` from the shared data frame, simulates a driver by
//! major function (create OK, read returns fixed data, write/IOCTL succeed), and
//! pushes a final `SurtCqe` (`IODRV_CQE_FINAL`). It needs no heap — it reads the
//! wire ABI directly and writes into the shared frame.

use crate::*;

use core::mem::size_of;

use nt_io_abi::projection::cqe_flags;
use nt_io_abi::{ioctl, major, IrpDispatchRequest};
use nt_status::NtStatus;
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

#[no_mangle]
#[link_section = ".text.peer_entry"]
pub unsafe extern "C" fn peer_entry() -> ! {
    let mut submissions = match Consumer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let mut completions = match Producer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let wait_requests = Sel4Notify::new(&ENV, CT_N_SUB);
    let signal_completion = Sel4Notify::new(&ENV, CT_N_COMP);

    let _ = drain_blocking(&mut submissions, &wait_requests, |sqe: &SurtSqe| {
        let (status, information) = handle(sqe.len as usize);
        let cqe = SurtCqe {
            request_id: sqe.request_id,
            status: status.raw(),
            flags: cqe_flags::IODRV_CQE_FINAL,
            information,
            ..Default::default()
        };
        while completions.try_push(cqe).is_err() {
            yield_now();
        }
        let _ = completions.notify_consumer(&signal_completion);
        true
    });
    park()
}

/// Decode the `IrpDispatchRequest` from the shared data frame + simulate a driver.
unsafe fn handle(total_len: usize) -> (NtStatus, u64) {
    let hdr = size_of::<IrpDispatchRequest>();
    if total_len < hdr {
        return (NtStatus::INVALID_PARAMETER, 0);
    }
    // SAFETY: the ring pop acquired the io-side's release; the header + buffer are
    // in the shared data frame at REQ_DATA_VADDR.
    let header = unsafe { core::slice::from_raw_parts(REQ_DATA_VADDR as *const u8, hdr) };
    let req: IrpDispatchRequest = bytemuck::pod_read_unaligned(header);
    if req.abi_size as usize != hdr {
        return (NtStatus::INVALID_PARAMETER, 0);
    }

    match req.major {
        major::IRP_MJ_CREATE => (NtStatus::SUCCESS, 0),
        major::IRP_MJ_READ => {
            let Some(buffer) = (unsafe {
                frame_slice_mut(total_len, req.buffer_offset, req.buffer_len)
            }) else {
                return (NtStatus::INVALID_PARAMETER, 0);
            };
            let data = b"peerread";
            let n = data.len().min(buffer.len());
            buffer[..n].copy_from_slice(&data[..n]);
            (NtStatus::SUCCESS, n as u64)
        }
        major::IRP_MJ_WRITE => (NtStatus::SUCCESS, req.buffer_len as u64),
        major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL => {
            let method = ioctl::method(req.ioctl_code);
            let (input_offset, input_len, output_offset, output_len) = match method {
                ioctl::METHOD_NEITHER => (
                    req.type3_input_offset as u64,
                    req.type3_input_len,
                    req.user_buffer_offset as u64,
                    req.user_buffer_len,
                ),
                ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => (
                    req.buffer_offset,
                    req.buffer_len,
                    req.direct_buffer_offset as u64,
                    req.direct_buffer_len,
                ),
                _ => (
                    req.buffer_offset,
                    req.buffer_len,
                    req.buffer_offset,
                    req.buffer_len,
                ),
            };
            let n = (req.input_len as usize)
                .min(req.output_len as usize)
                .min(input_len as usize)
                .min(output_len as usize);
            if n != 0
                && !unsafe { copy_frame_bytes(total_len, input_offset, output_offset, n) }
            {
                return (NtStatus::INVALID_PARAMETER, 0);
            }
            (NtStatus::SUCCESS, n as u64)
        }
        major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE | major::IRP_MJ_FLUSH_BUFFERS => {
            (NtStatus::SUCCESS, 0)
        }
        _ => (NtStatus::INVALID_DEVICE_REQUEST, 0),
    }
}

unsafe fn frame_slice_mut(total_len: usize, offset: u64, len: u32) -> Option<&'static mut [u8]> {
    if len == 0 {
        return Some(core::slice::from_raw_parts_mut(REQ_DATA_VADDR as *mut u8, 0));
    }
    let offset = usize::try_from(offset).ok()?;
    let len = len as usize;
    let end = offset.checked_add(len)?;
    if end > total_len || end > REQ_DATA_LEN {
        return None;
    }
    Some(core::slice::from_raw_parts_mut(
        (REQ_DATA_VADDR + offset as u64) as *mut u8,
        len,
    ))
}

unsafe fn copy_frame_bytes(
    total_len: usize,
    input_offset: u64,
    output_offset: u64,
    len: usize,
) -> bool {
    let Some(input) = frame_slice_mut(total_len, input_offset, len as u32) else {
        return false;
    };
    let Some(output) = frame_slice_mut(total_len, output_offset, len as u32) else {
        return false;
    };
    if input.as_ptr() == output.as_ptr() {
        return true;
    }
    for index in 0..len {
        let byte = core::ptr::read_volatile(input.as_ptr().add(index));
        core::ptr::write_volatile(output.as_mut_ptr().add(index), byte);
    }
    true
}

fn park() -> ! {
    loop {
        yield_now();
    }
}
