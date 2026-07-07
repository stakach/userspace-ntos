//! The Configuration Manager (registry) as an isolated service, driven by SURT.
//!
//! Mirrors `server.rs` (the Object Manager service) but runs `nt_config_server::
//! CmServer` — it consumes CM requests off its submission ring, dispatches each
//! through the registry authority, and produces `CmReply`s onto its completion
//! ring. Its own VSpace maps its ring frames at the same shared vaddrs the Ob
//! service uses (each service is a separate VSpace, so the vaddrs don't collide).

use crate::*;

use nt_config_server::CmServer;
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

#[no_mangle]
#[link_section = ".text.cm_server_entry"]
pub unsafe extern "C" fn cm_server_entry() -> ! {
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

    let mut server = CmServer::new();

    let _ = drain_blocking(&mut submissions, &wait_requests, |sqe: &SurtSqe| {
        // SAFETY: single request in flight; the ring push/pop orders the client's
        // write to the request frame before this read.
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
