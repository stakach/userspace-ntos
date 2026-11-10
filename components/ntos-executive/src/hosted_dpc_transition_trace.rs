//! Bounded observation of the exact hosted DPC queue-to-drain handoff.
//!
//! This never owns a DPC or requests a wake. The root DPC table and its generation remain
//! authoritative; missing observations lose diagnostics only.

use super::*;

// Stages: 0 queue result, 1 before QueueDpc service Reply, 2 after Reply/checkpoint,
// 3 scheduler yield, 4 physical receive, 5 drain owner, 6 drain result.
static STAGE_COUNTS: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];

pub(crate) fn record(
    stage: usize,
    owner: Option<HostedDpcOwner>,
    dpc: u64,
    generation: u64,
    value: u64,
    status: i32,
    tcb: u64,
    reply: u64,
) {
    let Some(counter) = STAGE_COUNTS.get(stage) else { return; };
    let ordinal = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if ordinal > 32 && !ordinal.is_power_of_two() { return; }
    let pending = hosted_driver_dpc_activation_pending();
    let (bootstrap, timer, receive) = unsafe {
        (crate::dispatcher_bootstrap::is_owned(),
            crate::dispatcher_bootstrap::timer_work_pending(),
            crate::dispatcher_bootstrap::receive_work_pending())
    };
    print_str(b"[hosted-dpc-transition] stage/ordinal/domain/cookie/lane/dpc/gen/value/status/tcb/reply/pending/bootstrap/timer/receive=");
    print_u64(stage as u64); print_str(b"/"); print_u64(ordinal);
    for number in [
        owner.map_or(0, |owner| owner.domain_id),
        owner.map_or(0, |owner| owner.domain_cookie),
        owner.map_or(0, |owner| owner.lane_generation),
        dpc, generation, value, status as u32 as u64, tcb, reply,
        u64::from(pending), u64::from(bootstrap), u64::from(timer), u64::from(receive),
    ] {
        print_str(b"/"); print_u64(number);
    }
    print_str(b"\n");
}
