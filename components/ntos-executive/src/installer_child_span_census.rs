//! Bounded, root-owned native table-dispatch observation after a child reaches
//! its first assigned PnP Enum open. Pending returns remain explicitly unresolved.

use crate::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_hosted_runtime::{CensusEpochGate, InstallerFaultReceipt, InstallerFaultReceipts,
    InstallerSyscallSpans, SpanOwner};
use core::fmt::Write;

const ROWS: usize = 8;
const TOP: usize = 4;
const CENSUS_LIMIT: u64 = 16;
const GAP_THRESHOLD_100NS: u64 = 5 * 10_000_000;
const GAP_SCAN_INTERVAL_100NS: u64 = 10_000_000;
const GAP_REPEAT_INTERVAL_100NS: u64 = 5 * 10_000_000;
const GAP_SAMPLES_PER_RETURN: u8 = 3;
const GAP_SAMPLES_TOTAL: u64 = 64;

#[derive(Clone, Copy)]
struct GapSampleRecord {
    owner: SpanOwner,
    return_at: u64,
    sampled_at: u64,
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_GAP_SCAN_100NS: AtomicU64 = AtomicU64::new(0);
static mut CENSUS_GATE: CensusEpochGate = CensusEpochGate::new(CENSUS_LIMIT);
static mut SPANS: InstallerSyscallSpans<ROWS, TOP> = InstallerSyscallSpans::new();
static mut FAULTS: InstallerFaultReceipts<ROWS> = InstallerFaultReceipts::new();

#[derive(Clone, Copy, Debug)]
pub(crate) enum PageInSource {
    Data(nt_memory_manager::SectionIdentity),
    Image(nt_memory_manager::image_section::ImageAreaId),
}

#[derive(Clone, Copy)]
pub(crate) struct PageInProbe {
    pub source: PageInSource,
    pub phase: u8,
    pub phase_entered_at_100ns: u64,
    pub irp_id: Option<u64>,
    pub irp_entered_at_100ns: Option<u64>,
    pub read_subphase: u8,
    pub page: u64,
    pub reply: u64,
    pub executing: bool,
}
// Only the root loop appends to this finite diagnostic history. An old generation never
// authorizes another sample; the total cap also bounds all native debug IPCs for the boot.
static mut GAP_SAMPLES: [Option<GapSampleRecord>; GAP_SAMPLES_TOTAL as usize] =
    [None; GAP_SAMPLES_TOTAL as usize];
static mut GAP_SAMPLES_USED: usize = 0;

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
    for owner in stale.into_iter().flatten() {
        let _ = ledger.retire(owner);
        unsafe { (&mut *core::ptr::addr_of_mut!(FAULTS)).retire(owner); }
    }
}

/// Capture ingress before a routed worker moves the exact fault Reply. Sampling is gated by
/// the already activated installer ledger, so ordinary boot faults do not fill this table.
pub(crate) fn note_fault(handler: &ExecNtHandler, pi: usize, tid: u64, badge: u64,
    reply: u64, ip: u64, addr: u64, error_code: u64) {
    if !ACTIVE.load(Ordering::Acquire) { return; }
    let tracked = unsafe { (&*core::ptr::addr_of!(SPANS)).owners() }
        .any(|owner| owner.process_index == pi && owner.thread_id == tid);
    if !tracked { return; }
    let Some(owner) = exact_owner(handler, pi, tid, badge) else { return; };
    let now = monotonic_time_100ns();
    if unsafe { (&*core::ptr::addr_of!(SPANS)).snapshot(owner, now) }
        .is_none() { return; }
    let _ = unsafe { (&mut *core::ptr::addr_of_mut!(FAULTS)).record(
        InstallerFaultReceipt { owner, badge, reply, fault_ip: ip, fault_addr: addr,
            fault_error_code: error_code, entered_at_100ns: now }) };
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

/// Claim before the native debug reads; nested observations cannot repeat an uncertain read.
/// The return timestamp distinguishes consecutive gaps of the same exact thread.
fn claim_gap_sample(owner: SpanOwner, return_at: u64, now: u64) -> bool {
    let used = unsafe { *core::ptr::addr_of!(GAP_SAMPLES_USED) };
    if used as u64 >= GAP_SAMPLES_TOTAL { return false; }
    let history = unsafe { &*core::ptr::addr_of!(GAP_SAMPLES) };
    let mut count = 0u8;
    let mut last = 0u64;
    for record in history[..used].iter().flatten() {
        if record.owner == owner && record.return_at == return_at {
            count += 1;
            last = last.max(record.sampled_at);
        }
    }
    if count >= GAP_SAMPLES_PER_RETURN
        || (count != 0 && now.saturating_sub(last) < GAP_REPEAT_INTERVAL_100NS)
    { return false; }
    unsafe {
        (&mut *core::ptr::addr_of_mut!(GAP_SAMPLES))[used] =
            Some(GapSampleRecord { owner, return_at, sampled_at: now });
        *core::ptr::addr_of_mut!(GAP_SAMPLES_USED) = used + 1;
    }
    true
}

/// Observe a live return-to-entry interval from the root loop's existing census opportunity.
/// This does not add a wakeup: a gap with no root events cannot be physically sampled.
pub(crate) fn maybe_sample_gap(handler: &ExecNtHandler, now: u64) {
    if !ACTIVE.load(Ordering::Acquire) { return; }
    let due = NEXT_GAP_SCAN_100NS.load(Ordering::Acquire);
    if now < due || NEXT_GAP_SCAN_100NS.compare_exchange(due,
        now.saturating_add(GAP_SCAN_INTERVAL_100NS), Ordering::AcqRel,
        Ordering::Acquire).is_err() { return; }

    // Copy value-only candidates before any debug IPC mutates the executive IPC buffer.
    let mut candidates = [None; ROWS];
    {
        let ledger = unsafe { &*core::ptr::addr_of!(SPANS) };
        for (slot, owner) in ledger.owners().enumerate() {
            let Some(snapshot) = ledger.snapshot(owner, now) else { continue; };
            if snapshot.active.is_some() || snapshot.pending.is_some() { continue; }
            let Some(age) = snapshot.last_return_age_100ns else { continue; };
            if age < GAP_THRESHOLD_100NS { continue; }
            candidates[slot] = Some((owner, now.saturating_sub(age)));
        }
    }

    for (owner, return_at) in candidates.into_iter().flatten() {
        let Some(badge) = handler.hosted_thread_badge_for_tid(owner.thread_id) else { continue; };
        if exact_owner(handler, owner.process_index, owner.thread_id, badge) != Some(owner) {
            continue;
        }
        let Some(tcb) = handler.hosted_thread_tcb_for_badge(badge).filter(|tcb| *tcb > 1)
            else { continue; };
        if !claim_gap_sample(owner, return_at, now) { continue; }

        // Copy value-only root/worker records before debug IPC can nest into a provider pump.
        let fault = unsafe { (&*core::ptr::addr_of!(FAULTS)).latest(owner, badge) };
        let (section_probe, image_probe) = if let Some(fault) = fault {
            let page = fault.fault_addr & !0xfffu64;
            (crate::section_pagein_work::diagnostic_snapshot(
                owner, badge, page, fault.reply),
             crate::native_image_pagein_work::diagnostic_snapshot(
                owner, badge, page, fault.reply))
        } else { (None, None) };

        let _message = unsafe { crate::ipc_message::SavedMessageBuffer::capture() };
        let mut regs = [0u64; 20];
        let regs_valid = unsafe { win32k_glue::tcb_read_regs20_checked(tcb, &mut regs) };
        let mut state = [0u64; win32k_glue::TCB_DEBUG_STATE_WORDS];
        unsafe { win32k_glue::tcb_read_debug_state(tcb, 0, &mut state) };

        // A numeric TCB cap or badge is not identity. Do not attribute a sample to an
        // owner that retired, changed generation, or entered another table call.
        let still_same_gap = unsafe { (&*core::ptr::addr_of!(SPANS)).snapshot(owner, now) }
            .is_some_and(|snapshot| snapshot.active.is_none()
                && snapshot.pending.is_none()
                && snapshot.last_return_age_100ns == Some(now.saturating_sub(return_at)));
        if exact_owner(handler, owner.process_index, owner.thread_id, badge) == Some(owner)
            && handler.hosted_thread_tcb_for_badge(badge) == Some(tcb)
            && still_same_gap
        {
            print_str(b"[installer-child-gap-tcb] pi/pgen/tid/tgen/badge/tcb/return-at-100ns/sample-at-100ns/age-ms/regs-valid/state/sched/enqueued/active-sc/pending-reply/reply-to/fault-type/blocked-is-call/call-reply-kind/call-reply-index/receiver-tcb/receiver-cspace/receiver-state=");
            for (index, value) in [owner.process_index as u64, owner.process_generation,
                owner.thread_id, owner.thread_generation, badge, tcb,
                return_at, now, now.saturating_sub(return_at) / 10_000,
                u64::from(regs_valid),
                state[win32k_glue::TCB_DBG_STATE], state[win32k_glue::TCB_DBG_SCHEDULABLE],
                state[win32k_glue::TCB_DBG_ENQUEUED], state[win32k_glue::TCB_DBG_ACTIVE_SC],
                state[win32k_glue::TCB_DBG_PENDING_REPLY], state[win32k_glue::TCB_DBG_REPLY_TO],
                state[win32k_glue::TCB_DBG_PENDING_FAULT],
                state[win32k_glue::TCB_DBG_BLOCKED_IS_CALL],
                state[win32k_glue::TCB_DBG_CALL_REPLY_KIND],
                state[win32k_glue::TCB_DBG_CALL_REPLY_INDEX],
                state[win32k_glue::TCB_DBG_CALL_RECEIVER_TCB],
                state[win32k_glue::TCB_DBG_CALL_RECEIVER_CSPACE],
                state[win32k_glue::TCB_DBG_CALL_RECEIVER_STATE],
            ].into_iter().enumerate() {
                if index != 0 { print_str(b"/"); }
                print_u64(value);
            }
            if regs_valid {
                print_str(b" rip="); print_hex_u64(regs[0]);
                print_str(b" rsp="); print_hex_u64(regs[1]);
                print_str(b" rdx="); print_hex_u64(regs[nt_user_callback::USER_CONTEXT_RDX]);
                print_str(b" rsi="); print_hex_u64(regs[nt_user_callback::USER_CONTEXT_RSI]);
            }
            print_str(b"\n");
            if state[win32k_glue::TCB_DBG_PENDING_FAULT] == 6 {
                let mut record = nt_printf::record::RecordBuffer::<512>::new();
                match fault {
                    Some(fault) => {
                        let _ = write!(record,
                            "[installer-child-gap-fault] pi/pgen/tid/tgen/badge/reply/ip/addr/x86-error/age-ms={}/{}/{}/{}/{}/{}/0x{:x}/0x{:x}/0x{:x}/{}",
                            owner.process_index, owner.process_generation, owner.thread_id,
                            owner.thread_generation, badge, fault.reply, fault.fault_ip,
                            fault.fault_addr, fault.fault_error_code,
                            now.saturating_sub(fault.entered_at_100ns) / 10_000);
                        match (section_probe, image_probe) {
                            (Some(probe), None) | (None, Some(probe)) => {
                                let _ = write!(record,
                                    " worker={:?} phase={} age-ms={} read-subphase={} irp={:?} irp-age-ms={:?} executing={}",
                                    probe.source, probe.phase,
                                    now.saturating_sub(probe.phase_entered_at_100ns) / 10_000,
                                    probe.read_subphase, probe.irp_id,
                                    probe.irp_entered_at_100ns.map(|at|
                                        now.saturating_sub(at) / 10_000), probe.executing);
                            }
                            (None, None) => { let _ = write!(record, " worker=none"); }
                            (Some(_), Some(_)) => {
                                let _ = write!(record, " worker=ambiguous");
                            }
                        }
                    }
                    None => { let _ = write!(record,
                        "[installer-child-gap-fault] pi/pgen/tid/tgen={}/{}/{}/{} receipt=none",
                        owner.process_index, owner.process_generation, owner.thread_id,
                        owner.thread_generation); }
                }
                let _ = write!(record, "\n");
                sel4_rt::print_record(if record.overflowed() {
                    b"[installer-child-gap-fault] trace truncated\n"
                } else { record.bytes() });
            }
        }
    }
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
        print_str(b" same-ssn-gap/ssn/count/total-ms/max-ms=");
        for gap in snapshot.same_ssn_gaps.into_iter().flatten() {
            print_u64(gap.ssn as u64); print_str(b"/");
            print_u64(gap.calls); print_str(b"/");
            print_u64(gap.total_100ns / 10_000); print_str(b"/");
            print_u64(gap.max_100ns / 10_000); print_str(b" ");
        }
        print_str(b" transition-pairs/from-ssn/to-ssn/count/total-ms/max-ms=");
        for pair in snapshot.top_transition_pairs.into_iter().flatten() {
            print_u64(pair.from_ssn as u64); print_str(b"/");
            print_u64(pair.to_ssn as u64); print_str(b"/");
            print_u64(pair.calls); print_str(b"/");
            print_u64(pair.total_100ns / 10_000); print_str(b"/");
            print_u64(pair.max_100ns / 10_000); print_str(b" ");
        }
        print_str(b" pair-overflow/distinct-omitted/gaps-untracked/ms-untracked=");
        print_u64(snapshot.overflow_transition_pairs); print_str(b"/");
        print_u64(snapshot.untracked_transition_gaps); print_str(b"/");
        print_u64(snapshot.untracked_transition_gap_100ns / 10_000);
        // This exact return-to-next-entry interval belongs to the pi/generation/tid above.
        // It excludes pending dispatch returns, whose terminal time is not observed here.
        print_str(b" longest-gap/present/from-ssn/from-status/to-ssn/from-at-100ns/to-at-100ns=");
        let longest = snapshot.longest_gap;
        for (index, value) in [
            u64::from(longest.is_some()),
            longest.map_or(0, |gap| u64::from(gap.from_ssn)),
            longest.map_or(0, |gap| u64::from(gap.from_status)),
            longest.map_or(0, |gap| u64::from(gap.to_ssn)),
            longest.map_or(0, |gap| gap.from_at_100ns),
            longest.map_or(0, |gap| gap.to_at_100ns),
        ].into_iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(value);
        }
        print_str(b"\n");
    }
    if ledger.activation_overflow() != 0 {
        print_str(b"[installer-child-span] activation-overflow=");
        print_u64(ledger.activation_overflow()); print_str(b"\n");
    }
}
