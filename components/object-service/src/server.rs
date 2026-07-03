//! The server component: an isolated `nt_object_server::Server` driven by SURT.
//!
//! It consumes OB requests off the submission ring (`SurtSqe` = opcode + a slice
//! of the shared request frame), dispatches each through the unchanged
//! `Server::dispatch`, and produces replies onto the completion ring
//! (`SurtCqe` = `ObReply` field-for-field), writing any variable result into the
//! shared reply frame.

use crate::*;

use nt_object_manager::ClientKind;
use nt_object_server::Server;
use nt_types::AccessMode;
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

#[no_mangle]
#[link_section = ".text.server_entry"]
pub unsafe extern "C" fn server_entry() -> ! {
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

    let mut server = match Server::new() {
        Ok(s) => s,
        Err(_) => park(),
    };
    let client = server.connect(ClientKind::NativeUser, AccessMode::UserMode);

    let _ = drain_blocking(&mut submissions, &wait_requests, |sqe: &SurtSqe| {
        // SAFETY: single request in flight; the ring push/pop pairs order the
        // client's write to the request frame before this read.
        let in_buf = unsafe {
            core::slice::from_raw_parts((REQ_DATA_VADDR + sqe.offset) as *const u8, sqe.len as usize)
        };
        let out_buf =
            unsafe { core::slice::from_raw_parts_mut(REP_DATA_VADDR as *mut u8, REP_DATA_LEN) };
        let reply = server.dispatch(client, sqe.opcode, in_buf, out_buf);

        let cqe = SurtCqe {
            request_id: sqe.request_id,
            status: reply.status,
            information: reply.information as u64,
            detail0: reply.detail0,
            detail1: reply.detail1,
            ..Default::default()
        };
        while completions.try_push(cqe).is_err() {
            yield_now();
        }
        let _ = completions.notify_consumer(&signal_completion);
        true // serve forever
    });
    park()
}

fn park() -> ! {
    loop {
        yield_now();
    }
}
