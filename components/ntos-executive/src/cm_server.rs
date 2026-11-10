//! The Configuration Manager (registry) as an isolated service, driven by SURT.
//!
//! Mirrors `server.rs` (the Object Manager service) but runs `nt_config_server::
//! CmServer` — it consumes CM requests off its submission ring, dispatches each
//! through the registry authority, and produces `CmReply`s onto its completion
//! ring. Its own VSpace maps its ring frames at the same shared vaddrs the Ob
//! service uses (each service is a separate VSpace, so the vaddrs don't collide).

use crate::*;

use alloc::rc::Rc;
use core::num::NonZeroU32;
use nt_config_abi::{mutation_begin, opcode};
use nt_config_server::{CmIdentitySource, CmServer};
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

#[no_mangle]
#[link_section = ".text.cm_server_entry"]
pub unsafe extern "C" fn cm_server_entry(launch_context: u64) -> ! {
    let Some(launch_context) = ServiceLaunchContext::decode(launch_context) else {
        park();
    };
    if !unsafe { allocator::initialize_mapped_heap(launch_context.heap_frames()) } {
        park();
    }
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

    let Some(incarnation) = NonZeroU32::new(launch_context.incarnation()) else {
        park();
    };
    let identities = Rc::new(CmIdentitySource::new(incarnation));
    let mut server = CmServer::new_with_identity_source(identities);
    // This service has a private stack even though the shared image's statics are read-only.
    let mut busy_begin_count = 0u64;

    let _ = drain_blocking(&mut submissions, &wait_requests, |sqe: &SurtSqe| {
        // SAFETY: single request in flight; the ring push/pop orders the client's
        // write to the request frame before this read.
        let in_buf = unsafe {
            core::slice::from_raw_parts(
                (REQ_DATA_VADDR + sqe.offset) as *const u8,
                sqe.len as usize,
            )
        };
        let out_buf =
            unsafe { core::slice::from_raw_parts_mut(REP_DATA_VADDR as *mut u8, REP_DATA_LEN) };
        let reply = server.dispatch(sqe.opcode, in_buf, out_buf);
        if sqe.opcode == opcode::CM_OP_SYSTEM_HIVE_MUTATION_BEGIN && reply.status == 0 {
            if let (Some(request), Some(outcome)) = (
                mutation_begin::Request::from_bytes(in_buf),
                mutation_begin::Reply::from_bytes(
                    &out_buf[..core::mem::size_of::<mutation_begin::Reply>()],
                ),
            ) {
                if request.operation == mutation_begin::operation::BEGIN
                    && outcome.disposition == mutation_begin::disposition::OUTCOME
                    && outcome.outcome_status == nt_status::NtStatus::DEVICE_BUSY.raw()
                {
                    busy_begin_count = busy_begin_count.saturating_add(1);
                    if busy_begin_count <= 16 || busy_begin_count % 32 == 0 {
                        let owner = server.system_mutation_busy_diagnostic();
                        print_str(b"[cm-busy-begin] n/requester/slot/seq/expected-gen/prepared/checkpoint/checkpoint-offset/checkpoint-len/outcome-gen/lease/lease-uploaded/lease-total=");
                        for value in [
                            busy_begin_count,
                            request.requester_nonce,
                            request.request_slot,
                            request.request_generation,
                            request.expected_generation,
                            owner.prepared_token,
                            owner.checkpoint_token,
                            owner.checkpoint_offset as u64,
                            owner.checkpoint_len as u64,
                            owner.outcome_receipt_generation,
                            owner.lease_token,
                            owner.lease_uploaded as u64,
                            owner.lease_total as u64,
                        ] {
                            print_u64(value);
                            print_str(b"/");
                        }
                        print_str(b"\n");
                    }
                }
            }
        }
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
