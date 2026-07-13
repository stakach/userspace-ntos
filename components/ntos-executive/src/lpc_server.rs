//! The LPC connection-broker component: an isolated `nt_lpc_server::Server`
//! driven by SURT.
//!
//! It consumes LPC control-plane requests off the submission ring (`SurtSqe` =
//! opcode + a slice of the shared request frame), dispatches each through the
//! unchanged `Server::dispatch`, and produces replies onto the completion ring
//! (`SurtCqe` = `LpcReply` field-for-field). This is the CONTROL plane only —
//! create/connect/accept/complete rendezvous; the message data plane never
//! reaches this component (the executive serves it directly).
//!
//! Runs in its own VSpace/CSpace/TCB (spawned by `stand_up_service`), mapping the
//! executive image read-only + the shared ring/data frames at the shared
//! `SUB_RING_VADDR` family (each child maps at those vaddrs in its own VSpace;
//! the executive maps this service's frames at the distinct `LPC_*` vaddrs).

use crate::*;

use nt_lpc_server::{AcceptPolicy, Server};
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

#[no_mangle]
#[link_section = ".text.lpc_server_entry"]
pub unsafe extern "C" fn lpc_server_entry() -> ! {
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

    // Path B (authentic): Manual accept — a connect leaves the connection Pending for a REAL
    // receiver (smss's SmpApiLoop thread, driven by the executive's `sm_rendezvous`) to drain via
    // receive → accept → complete. Replaces the interim AutoAccept where the server modelled the
    // acceptor. The full receive/accept/complete machinery is unchanged (host-tested under both).
    let mut server = Server::new();
    server.set_accept_policy(AcceptPolicy::Manual);

    let _ = drain_blocking(&mut submissions, &wait_requests, |sqe: &SurtSqe| {
        // SAFETY: single request in flight; the ring push/pop pairs order the
        // client's write to the request frame before this read.
        let in_buf = unsafe {
            core::slice::from_raw_parts((REQ_DATA_VADDR + sqe.offset) as *const u8, sqe.len as usize)
        };
        let out_buf =
            unsafe { core::slice::from_raw_parts_mut(REP_DATA_VADDR as *mut u8, REP_DATA_LEN) };
        let reply = server.dispatch(sqe.opcode, in_buf, out_buf);

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
