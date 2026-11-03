//! Bounded observation of an exact retained File READ/WRITE component pump.
//!
//! A message cycle includes its handler and any reply/receive continuation. Gross receive and
//! normal Reply are measured separately so their overlap can be read without treating a raw
//! physical Receive as the whole component pump. None of these counters affect ownership.

use super::*;

const LABEL_BASE: u64 = 0x770;
const LABEL_SLOTS: usize = 0x120;
const OTHER_LABEL: usize = LABEL_SLOTS;
const BUCKETS: usize = LABEL_SLOTS + 1;
const TOP_LABELS: usize = 6;

static LABEL_COUNTS: [AtomicU64; BUCKETS] = [const { AtomicU64::new(0) }; BUCKETS];
static LABEL_TICKS: [AtomicU64; BUCKETS] = [const { AtomicU64::new(0) }; BUCKETS];
static REPLY_CALLS: AtomicU64 = AtomicU64::new(0);
static REPLY_TICKS: AtomicU64 = AtomicU64::new(0);
static RECEIVE_CALLS: AtomicU64 = AtomicU64::new(0);
static RECEIVE_TICKS: AtomicU64 = AtomicU64::new(0);

fn bucket(label: u64) -> usize {
    label.checked_sub(LABEL_BASE)
        .filter(|offset| *offset < LABEL_SLOTS as u64)
        .map_or(OTHER_LABEL, |offset| offset as usize)
}

pub(super) struct MessageCycle {
    bucket: usize,
    started: u64,
}

impl MessageCycle {
    pub(super) unsafe fn enter(ch: &PumpChannel, label: u64) -> Option<Self> {
        crate::driver_launch::file_rpc_pump_for_diagnostic(ch).then(|| Self {
            bucket: bucket(label),
            started: crate::disk_census_ticks(),
        })
    }
}

impl Drop for MessageCycle {
    fn drop(&mut self) {
        LABEL_COUNTS[self.bucket].fetch_add(1, Ordering::Relaxed);
        LABEL_TICKS[self.bucket].fetch_add(
            crate::disk_census_ticks().wrapping_sub(self.started), Ordering::Relaxed);
    }
}

pub(super) unsafe fn start(ch: &PumpChannel) -> Option<u64> {
    crate::driver_launch::file_rpc_pump_for_diagnostic(ch)
        .then(crate::disk_census_ticks)
}

pub(super) fn record_reply(started: Option<u64>) {
    if let Some(started) = started {
        REPLY_CALLS.fetch_add(1, Ordering::Relaxed);
        REPLY_TICKS.fetch_add(crate::disk_census_ticks().wrapping_sub(started), Ordering::Relaxed);
    }
}

pub(super) fn record_receive(started: Option<u64>) {
    if let Some(started) = started {
        RECEIVE_CALLS.fetch_add(1, Ordering::Relaxed);
        RECEIVE_TICKS.fetch_add(crate::disk_census_ticks().wrapping_sub(started), Ordering::Relaxed);
    }
}

pub(super) fn print_census() {
    let receive_calls = RECEIVE_CALLS.load(Ordering::Relaxed);
    if receive_calls == 0 { return; }
    crate::print_str(b"[census] file-pump reply-count/ticks-M receive-count/ticks-M=");
    crate::print_u64(REPLY_CALLS.load(Ordering::Relaxed));
    crate::print_str(b"/");
    crate::print_u64(REPLY_TICKS.load(Ordering::Relaxed) / 1_000_000);
    crate::print_str(b" ");
    crate::print_u64(receive_calls);
    crate::print_str(b"/");
    crate::print_u64(RECEIVE_TICKS.load(Ordering::Relaxed) / 1_000_000);
    crate::print_str(b" top-cycle-label/count/ticks-M:");
    let mut chosen = [usize::MAX; TOP_LABELS];
    for rank in 0..TOP_LABELS {
        let mut best = usize::MAX;
        let mut best_ticks = 0;
        for bucket in 0..BUCKETS {
            if chosen[..rank].contains(&bucket) { continue; }
            let ticks = LABEL_TICKS[bucket].load(Ordering::Relaxed);
            if ticks > best_ticks {
                best = bucket;
                best_ticks = ticks;
            }
        }
        if best == usize::MAX { break; }
        chosen[rank] = best;
        crate::print_str(b" ");
        if best == OTHER_LABEL {
            crate::print_str(b"other");
        } else {
            crate::print_str(b"0x");
            crate::print_hex((LABEL_BASE + best as u64) as u32);
        }
        crate::print_str(b"/");
        crate::print_u64(LABEL_COUNTS[best].load(Ordering::Relaxed));
        crate::print_str(b"/");
        crate::print_u64(best_ticks / 1_000_000);
    }
    crate::print_str(b"\n");
}
