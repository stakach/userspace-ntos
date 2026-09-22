//! Root-loop delivery from the same owned endpoint used by nested provider pumps.

use crate::spawn_hosts::shared_ingress::owner::runtime;
use crate::*;
use nt_component_suspension::{IngressExecutionOwner, ReceivedMessage, ReplyBindingObservation};

// seL4 boot-cap slot for the executive's own TCB; used only as a live Reply-query probe.
const ROOT_THREAD_CAP: u64 = 1;

pub(crate) unsafe fn handles(endpoint: u64) -> bool {
    runtime::endpoint() == Some(endpoint)
}

unsafe fn materialize(message: ReceivedMessage) -> (u64, u64, u64, u64, u64, u64) {
    crate::ipc_message::restore_received(&message);
    let [r0, r1, r2, r3] = message.registers();
    (message.badge(), message.info(), r0, r1, r2, r3)
}

/// This runs only at a root event boundary. Nested pumps enqueue hosted Calls without touching
/// REPLY_MAIN_SLOT, which may still be the Reply of their outer blocked syscall.
pub(crate) unsafe fn receive(reply_cptr: u64) -> (u64, u64, u64, u64, u64, u64) {
    assert_eq!(
        reply_cptr,
        REPLY_MAIN_SLOT.load(Ordering::Relaxed),
        "shared root receive must own the current hosted Reply"
    );
    if reply_cptr != 0 {
        if runtime::owns_hosted_reply(reply_cptr) {
            runtime::release_hosted_reply(reply_cptr).expect(
                "root receive retains a hosted Call until acknowledged semantic completion",
            );
        } else {
            assert_eq!(
                crate::spawn_hosts::query_component_reply_binding(ROOT_THREAD_CAP, reply_cptr),
                Ok(ReplyBindingObservation::Free),
                "root receive cannot replace a held hosted Reply"
            );
        }
    }
    loop {
        let delivered = runtime::take_hosted_with(|reply, _message| {
            // The pre-delivery sweep may have recycled the previous acknowledged root Reply.
            let reply_cptr = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            if wait_reply_pool_find_cap(reply).is_some() {
                return false;
            }
            let old_index = if reply_cptr == 0 {
                None
            } else {
                let Some(index) = wait_reply_pool_find_cap(reply_cptr) else {
                    return false;
                };
                Some(index)
            };
            // Allocation and admission precede the ownership transfer. Failure leaves the full
            // incoming Call in the ingress queue and the old root Reply unchanged.
            let _durable = crate::allocator::enter_durable();
            if wait_reply_pool_insert_cap(reply, true).is_none() {
                return false;
            }
            REPLY_MAIN_SLOT.store(reply, Ordering::Relaxed);
            if let Some(old_index) = old_index {
                wait_reply_pool_mark_free(old_index);
            }
            true
        })
        .expect("hosted ingress handoff retained after refusal");
        if let Some((_reply, message)) = delivered {
            return materialize(message);
        }
        // The snapshot journal owns the mounted volume through COMMIT and its terminal ACK.
        // Autonomous Calls stay retained and unadmitted while that ownership is live.
        if !crate::writable_fs::registry_journal::owns_volume() {
            if runtime::service_autonomous()
                .expect("autonomous ingress remains retained on failure")
            {
                continue;
            }
        }
        match runtime::receive(IngressExecutionOwner::Idle, ROOT_THREAD_CAP, true)
            .expect("unified executive ingress retained after receive failure")
        {
            runtime::Arrival::Notification(message) => return materialize(message),
            runtime::Arrival::Hosted | runtime::Arrival::Call { .. } => {}
        }
    }
}

pub(crate) unsafe fn reply_receive(
    reply_cptr: u64,
    info: u64,
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
) -> (u64, u64, u64, u64, u64, u64) {
    // One-way acknowledged reply separates outgoing ownership from receive admission. The
    // unified receiver retains arrivals between these operations, including hosted reentry.
    assert!(
        client_reply_on(reply_cptr, info, r0, r1, r2, r3),
        "uncertain hosted reply cannot be replayed or replaced"
    );
    receive(REPLY_MAIN_SLOT.load(Ordering::Relaxed))
}
