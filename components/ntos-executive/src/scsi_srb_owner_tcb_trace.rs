//! Read-only seL4 worker/Reply snapshot for an exact active SCSI pump owner.
//!
//! The periodic census can run while a nested provider pump holds the Executive's dispatch
//! stack. Read the physical worker and Reply named by that atomic owner snapshot; this trace
//! never authorizes completion, retries a request, or changes a scheduler state.

use super::scsi_srb_pump_owner::ScsiSrbPumpOwnerIdentity;
use super::{print_hex64, print_str, print_tcb_debug_opt, print_u64};
use crate::win32k_glue;

pub(super) fn print(owner: &ScsiSrbPumpOwnerIdentity) {
    print_str(b"[scsi-srb-tcb] seq/inst/irp=");
    print_u64(owner.sequence);
    print_str(b"/");
    print_u64(owner.instance);
    print_str(b"/");
    print_hex64(owner.irp_id);
    if owner.tcb == 0 || owner.reply_cap == 0 {
        print_str(b" missing-worker-or-reply\n");
        return;
    }
    let mut state = [0u64; win32k_glue::TCB_DEBUG_STATE_WORDS];
    unsafe { win32k_glue::tcb_read_debug_state(owner.tcb, owner.reply_cap, &mut state) };
    for (label, index) in [
        (b" state=".as_slice(), win32k_glue::TCB_DBG_STATE),
        (b" sched=".as_slice(), win32k_glue::TCB_DBG_SCHEDULABLE),
        (b" enq=".as_slice(), win32k_glue::TCB_DBG_ENQUEUED),
        (b" prio=".as_slice(), win32k_glue::TCB_DBG_PRIORITY),
    ] {
        print_str(label);
        print_u64(state[index]);
    }
    for (label, index) in [
        (b" sc=".as_slice(), win32k_glue::TCB_DBG_SC),
        (b" active-sc=".as_slice(), win32k_glue::TCB_DBG_ACTIVE_SC),
        (b" pending-reply=".as_slice(), win32k_glue::TCB_DBG_PENDING_REPLY),
        (b" reply-to=".as_slice(), win32k_glue::TCB_DBG_REPLY_TO),
        (b" reply-bound=".as_slice(), win32k_glue::TCB_DBG_REPLY_BOUND_TCB),
        (b" current=".as_slice(), win32k_glue::TCB_DBG_CURRENT_TCB),
        (b" target=".as_slice(), win32k_glue::TCB_DBG_TARGET_TCB),
        (b" direct=".as_slice(), win32k_glue::TCB_DBG_DIRECT_HANDOFF),
        (b" qtop=".as_slice(), win32k_glue::TCB_DBG_QUEUE_TOP_PRIORITY),
    ] {
        print_str(label);
        print_tcb_debug_opt(state[index]);
    }
    print_str(b" call=");
    print_u64(state[win32k_glue::TCB_DBG_BLOCKED_IS_CALL]);
    print_str(b" ntfn=");
    print_tcb_debug_opt(state[win32k_glue::TCB_DBG_BOUND_NOTIFICATION]);
    print_str(b"\n");
}
