//! Copied ingress evidence, never scheduling or admission authority.

pub(crate) fn print_hold_snapshot(now: u64) {
    use core::fmt::Write;
    let snapshot = unsafe {
        crate::spawn_hosts::shared_ingress::owner::runtime::hold_snapshot()
    };
    let logical = snapshot.running.and_then(|running| unsafe {
        crate::win32k_glue::dispatch_observation_snapshot(running.lane)
    });
    let mut record = nt_printf::record::RecordBuffer::<4096>::new();
    let _ = writeln!(record, "[ingress-hold] t_ms={} running={:?} oldest={:?} logical={:?}",
        now / 10_000, snapshot.running, snapshot.oldest, logical);
    sel4_rt::print_record(if record.overflowed() {
        b"[ingress-hold] record-truncated\n"
    } else {
        record.bytes()
    });
}
