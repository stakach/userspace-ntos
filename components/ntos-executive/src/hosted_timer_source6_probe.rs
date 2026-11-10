//! Bounded observation of the exact hosted timer chosen by source 6.
//!
//! Timer delivery owns the mutable queues. A nested periodic census can read only the copied
//! atomic record, and a refused DPC queue attempt is never reported as an executed DPC.

use core::sync::atomic::{AtomicU64, Ordering};

const FIELDS: usize = 16;
const INSTANCE: usize = 3;
const DOMAIN: usize = 4;
const COOKIE: usize = 5;
const TIMER: usize = 6;
const GENERATION: usize = 7;
const EFFECT: usize = 13;
const WOKEN: usize = 14;
const DPC_QUEUE: usize = 15;

// A single timer-delivery owner writes this record. A nested reader returns None on an in-flight
// publication instead of spinning in a reentrant callback that cannot finish the writer.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static SOURCE6_SCANS: AtomicU64 = AtomicU64::new(0);
static RECORD: [AtomicU64; FIELDS] = [const { AtomicU64::new(0) }; FIELDS];

pub(crate) struct Scan {
    fields: [u64; FIELDS],
}

pub(crate) fn select(now: nt_time::TimeSnapshot, selected: Option<(u64, u64)>) -> Option<Scan> {
    let (deadline, source) = selected?;
    if source != crate::DELAY_TIMER_SOURCE_HOSTED_KERNEL_TIMER {
        return None;
    }
    let scan = SOURCE6_SCANS.fetch_add(1, Ordering::Relaxed) + 1;
    if scan > 8 && !scan.is_power_of_two() {
        return None;
    }
    let mut fields = [0u64; FIELDS];
    fields[0] = scan;
    fields[1] = now.monotonic_100ns;
    fields[2] = deadline;
    fields[INSTANCE] = u64::MAX;
    if let Some((instance, timer)) =
        crate::driver_launch::hosted_driver_earliest_timer_snapshot(now)
    {
        fields[INSTANCE] = instance as u64;
        if let Some((domain, cookie)) =
            crate::driver_launch::hosted_driver_timer_domain_identity(instance)
        {
            fields[DOMAIN] = domain;
            fields[COOKIE] = cookie;
        }
        fields[TIMER] = timer.timer_ptr;
        fields[GENERATION] = timer.generation;
        let (kind, raw_deadline) = match timer.deadline {
            nt_time::Deadline::Infinite => (0, 0),
            nt_time::Deadline::Relative { monotonic_100ns } => (1, monotonic_100ns),
            nt_time::Deadline::Absolute { system_time_100ns } => (2, system_time_100ns),
        };
        fields[8] = kind;
        fields[9] = raw_deadline;
        fields[10] = timer.projected_monotonic_100ns;
        fields[11] = timer.period_100ns;
        fields[12] = timer.dpc_ptr.unwrap_or(0);
    }
    Some(Scan { fields })
}

impl Scan {
    fn matches_expiry(&self, instance: usize, expiry: nt_kernel_exec::TimerExpiry) -> bool {
        self.fields[INSTANCE] == instance as u64
            && self.fields[TIMER] == expiry.timer_ptr
            && self.fields[GENERATION] == expiry.generation
    }

    pub(crate) fn missing_instance(
        &mut self,
        instance: usize,
        expiry: nt_kernel_exec::TimerExpiry,
    ) {
        if self.matches_expiry(instance, expiry) {
            self.fields[EFFECT] = 3;
        }
    }

    /// `effect`: 1 = timer body map refused, 2 = signal published.
    /// `dpc_queue`: 0 = no DPC, 1 = queue accepted, 2 = queue refused. This is not execution.
    pub(crate) fn observe_expiry(
        &mut self,
        instance: usize,
        domain: u64,
        cookie: u64,
        expiry: nt_kernel_exec::TimerExpiry,
        effect: u64,
        woken: u64,
        dpc_queue: u64,
    ) {
        if self.matches_expiry(instance, expiry)
            && self.fields[DOMAIN] == domain
            && self.fields[COOKIE] == cookie
        {
            self.fields[EFFECT] = effect;
            self.fields[WOKEN] = woken;
            self.fields[DPC_QUEUE] = dpc_queue;
        }
    }

    pub(crate) fn publish(self) {
        SEQUENCE.fetch_add(1, Ordering::AcqRel);
        for (slot, value) in RECORD.iter().zip(self.fields) {
            slot.store(value, Ordering::Relaxed);
        }
        SEQUENCE.fetch_add(1, Ordering::Release);
        // Only the initial and exponential source-6 scans enter this path.
        crate::print_str(b"[hosted-timer-source6] scan/now/selected/instance/domain/cookie/ptr/gen/deadline-kind/deadline/projected/period/dpc/effect/woken/dpc-queue=");
        print_fields(self.fields);
    }
}

pub(crate) fn snapshot() -> Option<[u64; FIELDS]> {
    let before = SEQUENCE.load(Ordering::Acquire);
    if before == 0 || before & 1 != 0 {
        return None;
    }
    let mut fields = [0u64; FIELDS];
    for (value, slot) in fields.iter_mut().zip(RECORD.iter()) {
        *value = slot.load(Ordering::Relaxed);
    }
    (SEQUENCE.load(Ordering::Acquire) == before).then_some(fields)
}

pub(crate) fn print_fields(fields: [u64; FIELDS]) {
    for (index, value) in fields.into_iter().enumerate() {
        if index != 0 {
            crate::print_str(b"/");
        }
        crate::print_u64(value);
    }
    crate::print_str(b"\n");
}
