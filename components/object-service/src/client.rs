//! The client component: an isolated `nt_object_client::ObjectClient` whose
//! transport backend marshals requests over the SURT rings to the server.
//!
//! `SurtBackend::call` copies the encoded request into the shared request frame,
//! pushes a `SurtSqe`, wakes the server, then blocks for the matching completion
//! and maps the `SurtCqe` back into an `ObReply`. It drives the same script the
//! in-process M7b demo did — but now every call crosses an address-space boundary.

use crate::*;

use alloc::vec::Vec;

use nt_object_abi::ObReply;
use nt_object_client::{Backend, ObjectClient};
use nt_types::{AccessMask, ObjectId};
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
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> ObReply {
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
        let mut reply = ObReply::default();
        let _ = drain_blocking(&mut self.cq, &self.wait_completion, |cqe: &SurtCqe| {
            if cqe.request_id == id {
                reply = ObReply {
                    status: cqe.status,
                    information: cqe.information as u32,
                    detail0: cqe.detail0,
                    detail1: cqe.detail1,
                };
                false // stop draining
            } else {
                true
            }
        });

        // Copy back any variable-length result payload.
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
    let mut c = ObjectClient::new(SurtBackend {
        sq,
        cq,
        signal_request: Sel4Notify::new(&ENV, CT_N_SUB),
        wait_completion: Sel4Notify::new(&ENV, CT_N_COMP),
        next_id: 1,
    });

    let mut passed = 0u64;

    check(b"ping", c.ping().is_success(), &mut passed);

    let created = c.create_directory("\\Device\\Test0", true);
    check(b"create_directory", created.is_ok(), &mut passed);
    let id = created.unwrap_or(ObjectId::NULL);

    check(b"lookup", c.lookup("\\Device\\Test0", true) == Ok(id), &mut passed);

    let handle = c.open("\\Device\\Test0", AccessMask::GENERIC_READ, None, true);
    check(b"open", handle.is_ok(), &mut passed);

    check(
        b"create_symbolic_link",
        c.create_symbolic_link("\\??\\Link", "\\Device\\Test0", true)
            .is_ok(),
        &mut passed,
    );
    check(b"lookup_via_symlink", c.lookup("\\??\\Link", true) == Ok(id), &mut passed);

    let expected: Vec<u16> = "\\Device\\Test0".encode_utf16().collect();
    let target = c.query_symbolic_link("\\??\\Link", true);
    check(
        b"query_symbolic_link",
        matches!(&target, Ok(t) if t.as_slice() == expected.as_slice()),
        &mut passed,
    );

    match handle {
        Ok(h) => check(b"close_handle", c.close_handle(h).is_ok(), &mut passed),
        Err(_) => check(b"close_handle", false, &mut passed),
    }

    let _ = ep_send_one(CT_RESULT, passed);
    park()
}

fn park() -> ! {
    loop {
        yield_now();
    }
}
