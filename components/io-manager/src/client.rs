//! The client component: an isolated `nt_io_client::IoClient` whose transport
//! backend marshals requests over the SURT rings to the server.
//!
//! `SurtBackend::call` copies the encoded request into the shared request frame,
//! pushes a `SurtSqe`, wakes the server, then blocks for the matching completion
//! and maps the `SurtCqe` back into an `IoReply`, copying any read/IOCTL output
//! payload back from the shared reply frame. Every call crosses an address-space
//! boundary.

use crate::*;

use nt_io_abi::{ioctl, IoReply};
use nt_io_client::{Backend, IoClient};
use nt_types::{AccessMask, HandleValue};
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

struct SurtBackend<'a> {
    sq: Producer<SurtSqe>,
    cq: Consumer<SurtCqe>,
    signal_request: Sel4Notify<'a, KernelEnv>,
    wait_completion: Sel4Notify<'a, KernelEnv>,
    next_id: u64,
}

impl Backend for SurtBackend<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> IoReply {
        // Stage the encoded request into the shared request frame.
        unsafe {
            let dst = REQ_DATA_VADDR as *mut u8;
            for (i, b) in in_buf.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), *b);
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        let sqe = SurtSqe {
            opcode,
            len: in_buf.len() as u32,
            request_id: id,
            offset: 0,
            ..Default::default()
        };
        while self.sq.try_push(sqe).is_err() {
            yield_now();
        }
        let _ = self.sq.notify_consumer(&self.signal_request);

        // Block for our completion (single request in flight).
        let mut reply = IoReply::default();
        let _ = drain_blocking(&mut self.cq, &self.wait_completion, |cqe: &SurtCqe| {
            if cqe.request_id == id {
                reply = IoReply {
                    status: cqe.status,
                    flags: cqe.flags,
                    information: cqe.information,
                    detail0: cqe.detail0,
                    detail1: cqe.detail1,
                };
                false // stop draining
            } else {
                true
            }
        });

        // Copy back any read / IOCTL output payload.
        let n = (reply.information as usize).min(out_buf.len());
        unsafe {
            let src = REP_DATA_VADDR as *const u8;
            for (i, slot) in out_buf.iter_mut().enumerate().take(n) {
                *slot = core::ptr::read_volatile(src.add(i));
            }
        }
        reply
    }
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
#[link_section = ".text.client_entry"]
pub unsafe extern "C" fn client_entry() -> ! {
    let sq = match Producer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let cq = match Consumer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let mut c = IoClient::new(SurtBackend {
        sq,
        cq,
        signal_request: Sel4Notify::new(&ENV, CT_N_SUB),
        wait_completion: Sel4Notify::new(&ENV, CT_N_COMP),
        next_id: 1,
    });

    let mut passed = 0u64;

    check(b"ping", c.ping().is_success(), &mut passed);

    // Open the device by its DOS-devices symlink, read/write access.
    let handle = c.open(
        "\\??\\Test0",
        AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
        0,
        0,
        0,
    );
    check(b"open", handle.is_ok(), &mut passed);
    let h = handle.unwrap_or(HandleValue::NULL);

    check(b"write", c.write(h, 0, b"hello") == Ok(5), &mut passed);

    let mut out = [0u8; 8];
    let read = c.read(h, 0, &mut out);
    check(
        b"read",
        matches!(read, Ok(5)) && &out[..5] == b"hello",
        &mut passed,
    );

    let code = ioctl::ctl_code(0x22, 0x800, ioctl::METHOD_BUFFERED, ioctl::FILE_ANY_ACCESS);
    let mut io_out = [0u8; 8];
    check(
        b"device_control",
        matches!(c.device_control(h, code, b"ping", &mut io_out), Ok(n) if &io_out[..n as usize] == b"ping"),
        &mut passed,
    );

    check(b"cleanup", c.cleanup(h).is_ok(), &mut passed);
    check(b"close", c.close(h).is_ok(), &mut passed);

    let _ = ep_send_one(CT_RESULT, passed);
    park()
}

fn park() -> ! {
    loop {
        yield_now();
    }
}
