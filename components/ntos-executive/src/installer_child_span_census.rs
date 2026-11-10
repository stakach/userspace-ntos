//! Bounded, root-owned native table-dispatch observation after a child reaches
//! its first assigned PnP Enum open. Pending returns remain explicitly unresolved.

use crate::*;
use core::sync::atomic::{AtomicBool, Ordering};
use nt_hosted_runtime::{CensusEpochGate, InstallerSyscallSpans, SpanOwner};

const ROWS: usize = 8;
const TOP: usize = 4;
const CENSUS_LIMIT: u64 = 16;

static ACTIVE: AtomicBool = AtomicBool::new(false);
static mut CENSUS_GATE: CensusEpochGate = CensusEpochGate::new(CENSUS_LIMIT);
static mut SPANS: InstallerSyscallSpans<ROWS, TOP> = InstallerSyscallSpans::new();

fn exact_owner(handler: &ExecNtHandler, pi: usize, tid: u64, badge: u64) -> Option<SpanOwner> {
    if handler.hosted_thread_pi_for_badge(badge) != Some(pi)
        || handler.hosted_thread_tid_for_badge(badge) != Some(tid) {
        return None;
    }
    let process = handler.capture_thread_process_identity(pi, tid)?;
    let generation = handler.hosted_process_generation(pi)?;
    let nt_user_host::process_identity::ProcessGeneration::Hosted(actual_generation) =
        process.generation else { return None; };
    if generation != actual_generation { return None; }
    let lifetime = handler.pm.thread_lifetime(u32::try_from(tid).ok()?)?;
    if lifetime.process_id() != process.pid { return None; }
    Some(SpanOwner { process_index: pi, process_generation: generation,
        thread_id: tid, thread_generation: lifetime.generation() })
}

fn retire_stale(handler: &ExecNtHandler) {
    let mut stale = [None; ROWS];
    {
        let ledger = unsafe { &*core::ptr::addr_of!(SPANS) };
        for (index, owner) in ledger.owners().enumerate() {
            let badge = handler.hosted_thread_badge_for_tid(owner.thread_id);
            if badge.and_then(|badge| exact_owner(handler, owner.process_index,
                owner.thread_id, badge)) != Some(owner) {
                stale[index] = Some(owner);
            }
        }
    }
    let ledger = unsafe { &mut *core::ptr::addr_of_mut!(SPANS) };
    for owner in stale.into_iter().flatten() { let _ = ledger.retire(owner); }
}

pub(crate) fn activate_after_enum_open(handler: &ExecNtHandler, pi: usize) {
    retire_stale(handler);
    let Some(owner) = exact_owner(handler, pi, handler.current_tid, handler.current_badge) else {
        return;
    };
    if unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)).activate(owner) } {
        if !ACTIVE.load(Ordering::Acquire) {
            let epoch = CENSUS_PERIODIC_DUMPS.load(Ordering::Relaxed);
            unsafe { (&mut *core::ptr::addr_of_mut!(CENSUS_GATE)).prime(epoch); }
        }
        ACTIVE.store(true, Ordering::Release);
    }
}

pub(crate) fn begin(handler: &ExecNtHandler, pi: usize, tid: u64,
    badge: u64, ssn: u32) -> Option<SpanOwner> {
    if !ACTIVE.load(Ordering::Acquire) { return None; }
    let owner = exact_owner(handler, pi, tid, badge)?;
    unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)).begin(
        owner, ssn, monotonic_time_100ns()).then_some(owner) }
}

pub(crate) fn returned(handler: &ExecNtHandler, owner: Option<SpanOwner>,
    badge: u64, ssn: u32, status: u32) {
    let Some(owner) = owner else { return; };
    if exact_owner(handler, owner.process_index, owner.thread_id, badge) != Some(owner) {
        return;
    }
    let _ = unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)).return_from_dispatch(
        owner, ssn, status, monotonic_time_100ns()) };
}

/// Sparse 30-second sample, capped at sixteen census passes after activation.
/// Only table dispatch is covered; retained pending owners have no terminal timestamp here.
pub(crate) fn print_census(handler: &ExecNtHandler) {
    if !ACTIVE.load(Ordering::Acquire) { return; }
    let epoch = CENSUS_PERIODIC_DUMPS.load(Ordering::Relaxed);
    if !unsafe { (&mut *core::ptr::addr_of_mut!(CENSUS_GATE)).admit(epoch) } { return; }
    retire_stale(handler);
    let now = monotonic_time_100ns();
    let ledger = unsafe { &*core::ptr::addr_of!(SPANS) };
    for owner in ledger.owners() {
        let Some(badge) = handler.hosted_thread_badge_for_tid(owner.thread_id) else { continue; };
        if exact_owner(handler, owner.process_index, owner.thread_id, badge) != Some(owner) {
            continue;
        }
        let Some(snapshot) = ledger.snapshot(owner, now) else { continue; };
        let state = u32::try_from(owner.thread_id).ok()
            .and_then(|tid| handler.pm.thread(tid)).map(|thread| thread.state);
        print_str(b"[installer-child-span] scope=generic-table pi/pgen/tid/tgen/state/parked/completed/pending-dispatches/unresolved/gap-total-ms/gap-max-ms/last-return-present/last-return-age-ms/active-present/active-ssn/active-entry-age-ms/pending-present/pending-ssn/pending-entry-age-ms/top-overflow/unindexed-ssn-range=");
        let state_code = match state {
            Some(nt_process::ThreadState::Initialized) => 1,
            Some(nt_process::ThreadState::Ready) => 2,
            Some(nt_process::ThreadState::Running) => 3,
            Some(nt_process::ThreadState::Waiting) => 4,
            Some(nt_process::ThreadState::Suspended) => 5,
            Some(nt_process::ThreadState::Terminated) => 6,
            None => 0,
        };
        for (index, value) in [owner.process_index as u64, owner.process_generation,
            owner.thread_id, owner.thread_generation, state_code,
            u64::from(thread_wait_state_badge_parked(badge)), snapshot.completed,
            snapshot.retained_pending, snapshot.unresolved_replaced,
            snapshot.total_gap_100ns / 10_000, snapshot.max_gap_100ns / 10_000,
            u64::from(snapshot.last_return_age_100ns.is_some()),
            snapshot.last_return_age_100ns.unwrap_or(0) / 10_000,
            u64::from(snapshot.active.is_some()),
            snapshot.active.map_or(0, |span| span.ssn as u64),
            snapshot.active.map_or(0, |span| span.age_100ns / 10_000),
            u64::from(snapshot.pending.is_some()),
            snapshot.pending.map_or(0, |span| span.ssn as u64),
            snapshot.pending.map_or(0, |span| span.age_100ns / 10_000),
            snapshot.overflow_ssns, snapshot.unindexed_calls].into_iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(value);
        }
        print_str(b" census-epoch="); print_u64(epoch);
        print_str(b" top-ssn/calls/wall-total-ms/max-ms=");
        for top in snapshot.top.into_iter().flatten() {
            print_u64(top.ssn as u64); print_str(b"/");
            print_u64(top.calls); print_str(b"/");
            print_u64(top.total_100ns / 10_000); print_str(b"/");
            print_u64(top.max_100ns / 10_000); print_str(b" ");
        }
        print_str(b"\n");
    }
    if ledger.activation_overflow() != 0 {
        print_str(b"[installer-child-span] activation-overflow=");
        print_u64(ledger.activation_overflow()); print_str(b"\n");
    }
}
