//! Same-gap root work receipts for the bounded installer Close probe (#476).
//! Root SC time and these inclusive TSC counters have different units and can overlap;
//! neither a numeric Reply nor a counter delta is authority to change execution.

use crate::*;
use core::sync::atomic::Ordering;
use nt_hosted_runtime::{CounterDelta, RootGapBaselineBudget, RootGapObservation,
    RootServiceGapLedger, RootRuntimeDelta, RuntimeSample, SpanOwner, top_counter_deltas};

const ROWS: usize = super::installer_child_span_census::ROWS;
const STEPS: usize = crate::reply_tail_step_census::STEPS;
const HOT: usize = crate::hot_service_cost_census::HOT_SERVICES;
const TOTALS: usize = 9;
const BASELINE_LIMIT: u64 = 2048;

struct Baseline {
    at_100ns: u64,
    at_tsc: u64,
    totals: [u64; TOTALS],
    step_ticks: [u64; STEPS],
    step_calls: [u64; STEPS],
    hot_ticks: [u64; HOT],
    hot_calls: [u64; HOT],
}

impl Baseline {
    const fn new() -> Self {
        Self { at_100ns: 0, at_tsc: 0, totals: [0; TOTALS],
            step_ticks: [0; STEPS], step_calls: [0; STEPS],
            hot_ticks: [0; HOT], hot_calls: [0; HOT] }
    }

    fn capture(&mut self) -> bool {
        if !crate::serial_records::is_root_executor() { return false; }
        let Some((hot_ticks, hot_calls)) = crate::hot_service_cost_census::snapshot() else {
            return false;
        };
        let Some((step_ticks, step_calls)) = crate::reply_tail_step_census::snapshot() else {
            return false;
        };
        self.at_100ns = monotonic_time_100ns();
        self.at_tsc = crate::disk_census_ticks();
        for index in 0..TOTALS { self.totals[index] = total_counter(index); }
        self.step_ticks = step_ticks;
        self.step_calls = step_calls;
        self.hot_ticks = hot_ticks;
        self.hot_calls = hot_calls;
        true
    }

    fn delta(&self) -> Option<CounterSummary> {
        if !crate::serial_records::is_root_executor() { return None; }
        let Some((hot_ticks, hot_calls)) = crate::hot_service_cost_census::snapshot() else {
            return None;
        };
        let Some((step_ticks, step_calls)) = crate::reply_tail_step_census::snapshot() else {
            return None;
        };
        let mut totals = [0; TOTALS];
        for (index, total) in totals.iter_mut().enumerate() {
            *total = total_counter(index).checked_sub(self.totals[index])?;
        }
        let observed_at_100ns = monotonic_time_100ns();
        if observed_at_100ns < self.at_100ns { return None; }
        let elapsed_tsc = crate::disk_census_ticks().checked_sub(self.at_tsc)?;
        let steps = top_counter_deltas::<3>(&self.step_ticks, |index| step_ticks[index])?;
        let hot = top_counter_deltas::<2>(&self.hot_ticks, |index| hot_ticks[index])?;
        // A regression in a non-top call count is still a counter-lifetime mismatch.
        for index in 0..STEPS {
            if step_calls[index] < self.step_calls[index] { return None; }
        }
        for index in 0..HOT {
            if hot_calls[index] < self.hot_calls[index] { return None; }
        }
        let steps = ranked(steps, &self.step_calls, |index| step_calls[index])?;
        let hot = ranked(hot, &self.hot_calls, |index| hot_calls[index])?;
        Some(CounterSummary { started_at_100ns: self.at_100ns, observed_at_100ns,
            elapsed_tsc, totals, steps, hot })
    }
}

fn total_counter(index: usize) -> u64 {
    let cell = match index {
        0 => &crate::EXEC_DISPATCH_TICKS,
        1 => &crate::RECV_BLOCKED_TICKS,
        2 => &crate::LOOP_KUSER_TICKS,
        3 => &crate::LOOP_DRAIN_TICKS,
        4 => &crate::LOOP_QUIESCE_TICKS,
        5 => &crate::DRAIN_SCAN_TICKS,
        6 => &crate::DRAIN_WORK_TICKS,
        7 => &crate::DRAIN_REARM_TICKS,
        8 => &crate::DELAY_WAKE_REPLY_TICKS,
        _ => return 0,
    };
    cell.load(Ordering::Relaxed)
}

#[derive(Clone, Copy)]
struct Ranked { index: usize, ticks: u64, calls: u64 }

fn ranked<const N: usize>(top: [Option<CounterDelta>; N], before_calls: &[u64],
    mut current_calls: impl FnMut(usize) -> u64) -> Option<[Option<Ranked>; N]> {
    let mut result = [None; N];
    for (slot, entry) in top.into_iter().enumerate() {
        let Some(entry) = entry else { continue; };
        result[slot] = Some(Ranked { index: entry.index, ticks: entry.ticks,
            calls: current_calls(entry.index).checked_sub(*before_calls.get(entry.index)?)? });
    }
    Some(result)
}

pub(crate) struct CounterSummary {
    started_at_100ns: u64,
    observed_at_100ns: u64,
    elapsed_tsc: u64,
    totals: [u64; TOTALS],
    steps: [Option<Ranked>; 3],
    hot: [Option<Ranked>; 2],
}

static mut LEDGER: RootServiceGapLedger<ROWS> = RootServiceGapLedger::new();
static mut BASELINES: [Baseline; ROWS] = [const { Baseline::new() }; ROWS];
static mut BASELINE_BUDGET: RootGapBaselineBudget = RootGapBaselineBudget::new(BASELINE_LIMIT);

/// Capture only after the exact nonpending Close return. No native debug IPC runs here.
pub(crate) fn arm(owner: SpanOwner, return_at_100ns: u64) -> bool {
    if !crate::serial_records::is_root_executor() { return false; }
    let ledger = unsafe { &mut *core::ptr::addr_of_mut!(LEDGER) };
    let Some(slot) = ledger.arm(owner, return_at_100ns, None) else { return false; };
    let budget = unsafe { &mut *core::ptr::addr_of_mut!(BASELINE_BUDGET) };
    if !budget.admit() {
        ledger.retire(owner);
        if budget.refused() == 1 {
            print_str(b"[installer-child-root-gap] baseline-limit-reached used/limit=");
            print_u64(budget.used()); print_str(b"/");
            print_u64(BASELINE_LIMIT); print_str(b"\n");
        }
        return false;
    }
    if unsafe { (&mut *core::ptr::addr_of_mut!(BASELINES))[slot].capture() } { true }
    else { ledger.retire(owner); false }
}

pub(crate) fn attach_root_runtime(owner: SpanOwner, return_at_100ns: u64,
    root: Option<RuntimeSample>) {
    if !crate::serial_records::is_root_executor() { return; }
    let _ = unsafe { (&mut *core::ptr::addr_of_mut!(LEDGER)) }
        .attach_root_runtime(owner, return_at_100ns, root);
}

/// Copy a small delta before diagnostic SC/TCB reads. A stale owner or return timestamp
/// cannot access another row's baseline, even if its physical slot has been reused.
pub(crate) fn capture_delta(owner: SpanOwner, return_at_100ns: u64)
    -> Option<CounterSummary> {
    if !crate::serial_records::is_root_executor() { return None; }
    let slot = unsafe { (&*core::ptr::addr_of!(LEDGER)) }.slot(owner, return_at_100ns)?;
    unsafe { (&*core::ptr::addr_of!(BASELINES))[slot].delta() }
}

pub(crate) fn sample(owner: SpanOwner, return_at_100ns: u64, now: u64,
    root: Option<RuntimeSample>, counters: Option<CounterSummary>) {
    if !crate::serial_records::is_root_executor() { return; }
    let Some(observation) = unsafe { (&mut *core::ptr::addr_of_mut!(LEDGER)) }
        .sample(owner, return_at_100ns, now, root) else { return; };
    print_observation(b"sample", observation, counters);
}

pub(crate) fn finish(owner: SpanOwner, return_at_100ns: u64, now: u64, is_unmap: bool,
    root: Option<RuntimeSample>, counters: Option<CounterSummary>) {
    if !crate::serial_records::is_root_executor() { return; }
    let Some(observation) = unsafe { (&mut *core::ptr::addr_of_mut!(LEDGER)) }
        .finish(owner, return_at_100ns, now, is_unmap, root) else { return; };
    print_observation(b"unmap-entry", observation, counters);
}

pub(crate) fn retire(owner: SpanOwner) {
    if !crate::serial_records::is_root_executor() { return; }
    unsafe { (&mut *core::ptr::addr_of_mut!(LEDGER)) }.retire(owner);
}

pub(crate) fn print_budget() {
    if !crate::serial_records::is_root_executor() { return; }
    let budget = unsafe { &*core::ptr::addr_of!(BASELINE_BUDGET) };
    if budget.refused() != 0 {
        print_str(b"[installer-child-root-gap] baseline-used/refused/limit=");
        print_u64(budget.used()); print_str(b"/");
        print_u64(budget.refused()); print_str(b"/");
        print_u64(BASELINE_LIMIT); print_str(b"\n");
    }
}

fn print_observation(phase: &[u8], observation: RootGapObservation,
    counters: Option<CounterSummary>) {
    print_str(b"[installer-child-root-gap] phase="); print_str(phase);
    print_str(b" pi/pgen/tid/tgen/return-at/observed-at/age-ms/root-sc-separate-window-kind/bound-us/donated-us=");
    let (kind, bound, donated) = match observation.root {
        RootRuntimeDelta::Classified { bound_us, donated_us } => (1, bound_us, donated_us),
        RootRuntimeDelta::Unavailable => (2, 0, 0),
        RootRuntimeDelta::ChangedContext => (3, 0, 0),
        RootRuntimeDelta::CounterRegression => (4, 0, 0),
    };
    for (index, value) in [observation.owner.process_index as u64,
        observation.owner.process_generation, observation.owner.thread_id,
        observation.owner.thread_generation, observation.return_at_100ns,
        observation.observed_at_100ns,
        observation.observed_at_100ns.saturating_sub(observation.return_at_100ns) / 10_000,
        kind, bound, donated].into_iter().enumerate() {
        if index != 0 { print_str(b"/"); }
        print_u64(value);
    }
    let Some(counters) = counters else {
        print_str(b" tsc-counter-regression-or-unavailable=1\n"); return;
    };
    print_str(b" root-wide-counter-window-100ns/from/to=");
    print_u64(counters.started_at_100ns); print_str(b"/");
    print_u64(counters.observed_at_100ns);
    print_str(b" root-wide-inclusive-tsc/elapsed/dispatch/recv-blocked/loop-kuser/loop-drain/loop-quiesce/drain-scan/drain-work/drain-rearm/delay-wake-reply=");
    print_u64(counters.elapsed_tsc);
    for value in counters.totals { print_str(b"/"); print_u64(value); }
    print_str(b" root-wide-inclusive-reply-step=ticks/calls:");
    for row in counters.steps.into_iter().flatten() {
        print_str(b" ");
        if let Some(label) = crate::reply_tail_step_census::label(row.index) {
            print_str(label.as_bytes());
        } else { print_u64(row.index as u64); }
        print_str(b"="); print_u64(row.ticks); print_str(b"/"); print_u64(row.calls);
    }
    print_str(b" root-wide-inclusive-hot-service=ticks/calls:");
    for row in counters.hot.into_iter().flatten() {
        print_str(b" ");
        if let Some(label) = crate::hot_service_cost_census::label(row.index) {
            print_str(label.as_bytes());
        } else { print_u64(row.index as u64); }
        print_str(b"="); print_u64(row.ticks); print_str(b"/"); print_u64(row.calls);
    }
    print_str(b"\n");
}
