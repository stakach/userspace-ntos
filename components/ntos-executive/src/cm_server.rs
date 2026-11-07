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
use core::sync::atomic::{AtomicU64, Ordering};
use nt_config_abi::{hive_mutation_commit_disposition, hive_mutation_commit_operation,
    mutation_begin, opcode, CmHiveMutationCommitReply, CmHiveMutationCommitRequest};
use nt_config_server::{CmServer, CmIdentitySource};
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

static SYSTEM_WRITER_OWNER_TRACES: AtomicU64 = AtomicU64::new(0);

/// BEGIN names its request generation; ACK names its validated outcome receipt generation.
fn trace_system_writer_owner(server: &CmServer, phase: &[u8], identity: u64) {
    if SYSTEM_WRITER_OWNER_TRACES.fetch_add(1, Ordering::Relaxed) >= 512 {
        return;
    }
    let owner = server.system_mutation_busy_diagnostic();
    print_str(b"[cm-writer-owner] phase/generation/prepared/checkpoint/offset/length/outcome/lease/uploaded/total=");
    print_str(phase);
    for value in [identity, owner.prepared_token, owner.checkpoint_token,
        owner.checkpoint_offset as u64, owner.checkpoint_len as u64,
        owner.outcome_receipt_generation, owner.lease_token,
        owner.lease_uploaded as u64, owner.lease_total as u64] {
        print_str(b"/");
        print_u64(value);
    }
    print_str(b"\n");
}

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
        let begin = (sqe.opcode == opcode::CM_OP_SYSTEM_HIVE_MUTATION_BEGIN)
            .then(|| mutation_begin::Request::from_bytes(in_buf)).flatten();
        let commit = (sqe.opcode == opcode::CM_OP_SYSTEM_HIVE_MUTATION_COMMIT)
            .then(|| CmHiveMutationCommitRequest::from_bytes(in_buf)).flatten();
        let reply = server.dispatch(sqe.opcode, in_buf, out_buf);
        if reply.status == 0 {
            if let Some(request) = begin.filter(|request| request.operation == mutation_begin::operation::BEGIN) {
                let size = core::mem::size_of::<mutation_begin::Reply>();
                if reply.information as usize >= size {
                    if let Some(result) = mutation_begin::Reply::from_bytes(&out_buf[..size]) {
                        if result.outcome_status == nt_status::NtStatus::DEVICE_BUSY.raw() as i32 {
                            trace_system_writer_owner(&server, b"begin-busy", request.request_generation);
                        }
                    }
                }
            }
            if let Some(request) = commit.filter(|request| request.operation == hive_mutation_commit_operation::ACKNOWLEDGE) {
                let size = core::mem::size_of::<CmHiveMutationCommitReply>();
                if reply.information as usize >= size {
                    if let Some(result) = CmHiveMutationCommitReply::from_bytes(&out_buf[..size]) {
                        if result.disposition == hive_mutation_commit_disposition::ACKNOWLEDGED {
                            trace_system_writer_owner(&server, b"outcome-ack", request.receipt_generation);
                        }
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
