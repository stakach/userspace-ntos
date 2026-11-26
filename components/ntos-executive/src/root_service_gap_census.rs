//! Same-gap root work receipts for the bounded installer Close probe (#476).
//! Root SC time and these inclusive TSC counters have different units and can overlap;
//! neither a numeric Reply nor a counter delta is authority to change execution.

use crate::*;
use core::sync::atomic::{AtomicBool, Ordering};
use nt_hosted_runtime::{CounterDelta, HotProcessCost, HotProcessRank,
    GapIoKind, GapIoObservation, GapRouteSnapshot, RootGapRouteLedger,
    RootGapBaselineBudget, RootGapObservation, RootServiceGapLedger, RootRuntimeDelta,
    RuntimeSample, SpanOwner, rank_hot_process_deltas, top_counter_deltas};

const ROWS: usize = super::installer_child_span_census::ROWS;
const STEPS: usize = crate::reply_tail_step_census::STEPS;
const HOT: usize = crate::hot_service_cost_census::HOT_SERVICES;
const TOTALS: usize = 9;
const BASELINE_LIMIT: u64 = 2048;
const FILE_ROUTES: usize = 12;

struct Baseline {
    at_100ns: u64,
    at_tsc: u64,
    totals: [u64; TOTALS],
    step_ticks: [u64; STEPS],
    step_calls: [u64; STEPS],
    hot_ticks: [u64; HOT],
    hot_calls: [u64; HOT],
    outer_file_calls: [u64; 2],
    owners: [HotProcessCost; MAX_PI],
}

impl Baseline {
    const fn new() -> Self {
        Self { at_100ns: 0, at_tsc: 0, totals: [0; TOTALS],
            step_ticks: [0; STEPS], step_calls: [0; STEPS],
            hot_ticks: [0; HOT], hot_calls: [0; HOT],
            outer_file_calls: [0; 2],
            owners: [HotProcessCost::EMPTY; MAX_PI] }
    }

    fn capture(&mut self) -> bool {
        if !crate::serial_records::is_root_executor() { return false; }
        let started_at_100ns = monotonic_time_100ns();
        let started_at_tsc = crate::disk_census_ticks();
        let Some((hot_ticks, hot_calls)) = crate::hot_service_cost_census::snapshot() else {
            return false;
        };
        let Some((step_ticks, step_calls)) = crate::reply_tail_step_census::snapshot() else {
            return false;
        };
        self.at_100ns = started_at_100ns;
        self.at_tsc = started_at_tsc;
        for index in 0..TOTALS { self.totals[index] = total_counter(index); }
        self.step_ticks = step_ticks;
        self.step_calls = step_calls;
        self.hot_ticks = hot_ticks;
        self.hot_calls = hot_calls;
        self.outer_file_calls = crate::exec_handler::native_io_attribution::snapshot_file_calls();
        self.owners = crate::native_process_time_census::snapshot_hot_file();
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
        let current_owners = crate::native_process_time_census::snapshot_hot_file();
        let current_file_calls = crate::exec_handler::native_io_attribution::snapshot_file_calls();
        let outer_file_calls = [
            current_file_calls[0].checked_sub(self.outer_file_calls[0])?,
            current_file_calls[1].checked_sub(self.outer_file_calls[1])?,
        ];
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
        let owners = rank_hot_process_deltas::<MAX_PI, 3>(&self.owners, &current_owners);
        Some(CounterSummary { started_at_100ns: self.at_100ns, observed_at_100ns,
            elapsed_tsc, totals, steps, hot, owners,
            outer_file_calls, routes: None })
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
    owners: Option<HotProcessRank<3>>,
    outer_file_calls: [u64; 2],
    routes: Option<GapRouteSnapshot<FILE_ROUTES>>,
}

static mut LEDGER: RootServiceGapLedger<ROWS> = RootServiceGapLedger::new();
static mut FILE_ROUTE_LEDGER: RootGapRouteLedger<ROWS, FILE_ROUTES> = RootGapRouteLedger::new();
static FILE_ROUTE_ACTIVE: AtomicBool = AtomicBool::new(false);
static mut BASELINES: [Baseline; ROWS] = [const { Baseline::new() }; ROWS];
static mut BASELINE_BUDGET: RootGapBaselineBudget = RootGapBaselineBudget::new(BASELINE_LIMIT);

/// Capture only after the exact nonpending Close return. No native debug IPC runs here.
pub(crate) fn arm(owner: SpanOwner, return_at_100ns: u64) -> bool {
    if !crate::serial_records::is_root_executor() { return false; }
    let ledger = unsafe { &mut *core::ptr::addr_of_mut!(LEDGER) };
    let Some(slot) = ledger.arm(owner, return_at_100ns, None) else { return false; };
    let routes = unsafe { &mut *core::ptr::addr_of_mut!(FILE_ROUTE_LEDGER) };
    if !routes.arm(slot, owner, return_at_100ns) {
        ledger.retire(owner);
        return false;
    }
    let budget = unsafe { &mut *core::ptr::addr_of_mut!(BASELINE_BUDGET) };
    if !budget.admit() {
        ledger.retire(owner);
        let _ = routes.retire(slot, owner, return_at_100ns);
        refresh_file_route_activity(routes);
        if budget.refused() == 1 {
            print_str(b"[installer-child-root-gap] baseline-limit-reached used/limit=");
            print_u64(budget.used()); print_str(b"/");
            print_u64(BASELINE_LIMIT); print_str(b"\n");
        }
        return false;
    }
    if !unsafe { (&mut *core::ptr::addr_of_mut!(BASELINES))[slot].capture() } {
        ledger.retire(owner);
        let _ = routes.retire(slot, owner, return_at_100ns);
        refresh_file_route_activity(routes);
        return false;
    }
    FILE_ROUTE_ACTIVE.store(true, Ordering::Release);
    true
}

pub(crate) fn has_active_file_route_gap() -> bool {
    FILE_ROUTE_ACTIVE.load(Ordering::Acquire)
}

/// Record every Read/Write return while an exact root gap is armed, before sparse printing.
pub(crate) fn record_file_route(observation: GapIoObservation) {
    if !has_active_file_route_gap() || !crate::serial_records::is_root_executor() { return; }
    unsafe { (&mut *core::ptr::addr_of_mut!(FILE_ROUTE_LEDGER)).record(observation); }
}

fn refresh_file_route_activity(routes: &RootGapRouteLedger<ROWS, FILE_ROUTES>) {
    FILE_ROUTE_ACTIVE.store(routes.active(), Ordering::Release);
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
    let mut summary = unsafe { (&*core::ptr::addr_of!(BASELINES))[slot].delta()? };
    summary.routes = unsafe { (&*core::ptr::addr_of!(FILE_ROUTE_LEDGER)) }
        .sample(slot, owner, return_at_100ns);
    Some(summary)
}

pub(crate) fn sample(owner: SpanOwner, return_at_100ns: u64, now: u64,
    root: Option<RuntimeSample>, counters: Option<CounterSummary>) {
    if !crate::serial_records::is_root_executor() { return; }
    let Some(observation) = unsafe { (&mut *core::ptr::addr_of_mut!(LEDGER)) }
        .sample(owner, return_at_100ns, now, root) else { return; };
    if let Some(counters) = counters.as_ref() {
        print_file_route_observation(b"sample", observation,
            counters.routes, counters.outer_file_calls);
    }
    print_observation(b"sample", observation, counters);
}

pub(crate) fn finish(owner: SpanOwner, return_at_100ns: u64, now: u64, is_unmap: bool,
    root: Option<RuntimeSample>, counters: Option<CounterSummary>) {
    if !crate::serial_records::is_root_executor() { return; }
    let ledger = unsafe { &mut *core::ptr::addr_of_mut!(LEDGER) };
    let slot = ledger.slot(owner, return_at_100ns);
    let observation = ledger.finish(owner, return_at_100ns, now, is_unmap, root);
    let routes = unsafe { &mut *core::ptr::addr_of_mut!(FILE_ROUTE_LEDGER) };
    let _ = slot.and_then(|slot| routes.retire(slot, owner, return_at_100ns));
    refresh_file_route_activity(routes);
    let Some(observation) = observation else { return; };
    if let Some(counters) = counters.as_ref() {
        print_file_route_observation(b"unmap-entry", observation,
            counters.routes, counters.outer_file_calls);
    }
    print_observation(b"unmap-entry", observation, counters);
}

pub(crate) fn retire(owner: SpanOwner) {
    if !crate::serial_records::is_root_executor() { return; }
    unsafe { (&mut *core::ptr::addr_of_mut!(LEDGER)) }.retire(owner);
    let routes = unsafe { &mut *core::ptr::addr_of_mut!(FILE_ROUTE_LEDGER) };
    routes.retire_owner(owner);
    refresh_file_route_activity(routes);
}

fn print_file_route_observation(phase: &[u8], observation: RootGapObservation,
    snapshot: Option<GapRouteSnapshot<FILE_ROUTES>>, outer_file_calls: [u64; 2]) {
    let Some(snapshot) = snapshot else { return; };
    print_str(b"[installer-child-root-file-route] phase="); print_str(phase);
    print_str(b" owner-pi/gen/tid/tgen/return-at/observed-at=");
    for (index, value) in [observation.owner.process_index as u64,
        observation.owner.process_generation, observation.owner.thread_id,
        observation.owner.thread_generation, observation.return_at_100ns,
        observation.observed_at_100ns]
        .into_iter().enumerate() {
        if index != 0 { print_str(b"/"); }
        print_u64(value);
    }
    print_str(b" read-outer/route-total/unknown-owner/changed-generation/unknown-route/overflow/reconciles=");
    print_route_counts(&snapshot, GapIoKind::Read, outer_file_calls[0]);
    print_str(b" write-outer/route-total/unknown-owner/changed-generation/unknown-route/overflow/reconciles=");
    print_route_counts(&snapshot, GapIoKind::Write, outer_file_calls[1]);
    print_str(b"\n");
    for entry in snapshot.entries.into_iter().flatten() {
        let key = entry.key;
        // The canonical device record, queried at report time, is the only basis for naming
        // this a pipe route. The device may have retired after the captured File dispatch.
        let device_type = unsafe { crate::driver_launch::io_manager_mut()
            .device(nt_io_manager::DeviceId(key.device_id)).map(|device| device.device_type.0) };
        print_str(b"[installer-child-root-file-route-entry] kind=");
        let kind: &[u8] = match key.kind { GapIoKind::Read => b"read", GapIoKind::Write => b"write" };
        print_str(kind);
        print_str(b" pi/gen/handle/file/device/type/status/park/calls/outer-dispatch-ticks/requested/known-request/completed/known-completion=");
        let (status, park) = match key.disposition {
            nt_hosted_runtime::GapIoDisposition::Completed => (0, 0),
            nt_hosted_runtime::GapIoDisposition::PendingAsync => (0x103, 1),
            nt_hosted_runtime::GapIoDisposition::PendingPark => (0x103, 2),
            nt_hosted_runtime::GapIoDisposition::Failed(status) => (status, 0),
        };
        for (index, value) in [key.process_index as u64, key.process_generation,
            key.handle, key.file_id, key.device_id, device_type.unwrap_or(0) as u64,
            status as u64, park, entry.stats.calls, entry.stats.dispatch_ticks,
            entry.stats.requested_bytes, entry.stats.known_requests,
            entry.stats.completed_bytes, entry.stats.known_completions]
            .into_iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(value);
        }
        print_str(b" device-type-known="); print_u64(u64::from(device_type.is_some()));
        print_str(b"\n");
    }
}

fn print_route_counts(snapshot: &GapRouteSnapshot<FILE_ROUTES>, kind: GapIoKind, outer_calls: u64) {
    let index = match kind { GapIoKind::Read => 0, GapIoKind::Write => 1 };
    for (part, value) in [outer_calls, snapshot.total[index].calls,
        snapshot.unknown_owner[index].calls, snapshot.changed_generation[index].calls,
        snapshot.unknown_route[index].calls, snapshot.capacity_overflow[index].calls,
        u64::from(snapshot.reconciles(kind) && snapshot.total[index].calls == outer_calls)]
        .into_iter().enumerate() {
        if part != 0 { print_str(b"/"); }
        print_u64(value);
    }
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
    print_str(b" exact-generation-hot-file-top=pi/gen/read-calls/read-ticks/read-serial-bytes/read-requested-bytes/read-known-requests/write-calls/write-ticks/write-serial-bytes/write-requested-bytes/write-known-requests:");
    if let Some(owners) = counters.owners {
        for row in owners.top.into_iter().flatten() {
            print_str(b" ");
            for (index, value) in [row.process_index as u64, row.generation,
                row.read.calls, row.read.ticks, row.read.serial_bytes,
                row.read.requested_bytes, row.read.known_request_calls,
                row.write.calls, row.write.ticks, row.write.serial_bytes,
                row.write.requested_bytes, row.write.known_request_calls]
                .into_iter().enumerate() {
                if index != 0 { print_str(b"/"); }
                print_u64(value);
            }
        }
        print_str(b" omitted/changed=");
        print_u64(owners.omitted_owners); print_str(b"/");
        print_u64(owners.changed_owners);
    } else {
        print_str(b" counter-regression-or-unavailable");
    }
    print_str(b"\n");
}
