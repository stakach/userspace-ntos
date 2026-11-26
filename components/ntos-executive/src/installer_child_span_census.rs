//! Bounded, root-owned native table-dispatch observation after a child reaches
//! its first assigned PnP Enum open. Pending returns remain explicitly unresolved.

use crate::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_hosted_runtime::{CensusEpochGate, InstallerFaultReceipt, InstallerFaultReceipts,
    InstallerFaultTicket, InstallerSyscallSpans, OpenCloseGapSampleBudget,
    PairedRuntimeSample, RuntimeSample, SpanOwner, OPEN_CLOSE_GAP_THRESHOLD_100NS};
use core::fmt::Write;

pub(crate) const ROWS: usize = 8;
const TOP: usize = 4;
const CENSUS_LIMIT: u64 = 16;
const GAP_SCAN_INTERVAL_100NS: u64 = 2_500_000; // 250 ms.
const GAP_SAMPLES_TOTAL: usize = 12;
const RUNTIME_READ_LIMIT: u64 = 8192;
const RUNTIME_FINAL_LIMIT: u64 = 64;
const SSN_NT_CLOSE: u32 = 27;
const SSN_NT_UNMAP_VIEW_OF_SECTION: u32 = 277;
// rust-micro publishes the boot rootserver's bound SC at the canonical init cap slot.
const ROOT_SCHED_CONTEXT_CAP: u64 = 14;
// The rootserver TCB is the canonical initial cap, also used by the deadman diagnostic.
const ROOT_TCB_CAP: u64 = 1;

static ACTIVE: AtomicBool = AtomicBool::new(false);
static NEXT_GAP_SCAN_100NS: AtomicU64 = AtomicU64::new(0);
static RUNTIME_READS_USED: AtomicU64 = AtomicU64::new(0);
static RUNTIME_READS_REFUSED: AtomicU64 = AtomicU64::new(0);
static RUNTIME_FINALS_USED: AtomicU64 = AtomicU64::new(0);
static RUNTIME_FINALS_REFUSED: AtomicU64 = AtomicU64::new(0);
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
// The root loop alone claims this finite budget before uncertain native debug reads.
static mut GAP_SAMPLES: OpenCloseGapSampleBudget<GAP_SAMPLES_TOTAL> =
    OpenCloseGapSampleBudget::new();

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

/// Read a cumulative SC counter without changing the hosted thread or its scheduling context.
/// A failed or changed identity leaves the containing wall interval unclassified.
fn read_sched_runtime(sched_context: u64) -> Option<RuntimeSample> {
    if RUNTIME_READS_USED.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |used| (used < RUNTIME_READ_LIMIT).then_some(used + 1)).is_err() {
        RUNTIME_READS_REFUSED.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let read = sel4_rt::sched_context_read_runtime(sched_context).ok()?;
    Some(RuntimeSample { sched_context, bound_us: read.bound_time_us,
        donated_us: read.donated_time_us })
}

fn runtime_sample(handler: &ExecNtHandler, owner: SpanOwner, badge: u64) -> PairedRuntimeSample {
    if exact_owner(handler, owner.process_index, owner.thread_id, badge) != Some(owner) {
        return PairedRuntimeSample::default();
    }
    let Some(binding) = handler.thread_runtime.executable_by_tid(owner.thread_id)
        .map(|runtime| runtime.binding()) else { return PairedRuntimeSample::default() };
    if binding.pi != owner.process_index || binding.badge != badge {
        return PairedRuntimeSample::default();
    }
    let observed_sched_context = handler.observed_sched_context_for_binding(binding);
    let sched_context = observed_sched_context.filter(|sc| *sc != 0);
    let sample = {
        let _message = unsafe { crate::ipc_message::SavedMessageBuffer::capture() };
        PairedRuntimeSample {
            child: sched_context.and_then(read_sched_runtime),
            root: read_sched_runtime(ROOT_SCHED_CONTEXT_CAP),
        }
    };
    if exact_owner(handler, owner.process_index, owner.thread_id, badge) != Some(owner)
        || handler.observed_sched_context_for_binding(binding) != observed_sched_context {
        return PairedRuntimeSample::default();
    }
    sample
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
        // Children can finish between periodic passes. Emit their final value-only
        // totals before exact-generation retirement discards the row.
        if RUNTIME_FINALS_USED.fetch_update(Ordering::AcqRel, Ordering::Acquire,
            |used| (used < RUNTIME_FINAL_LIMIT).then_some(used + 1)).is_ok() {
            if let Some(snapshot) = ledger.snapshot(owner, monotonic_time_100ns()) {
                let runtime = snapshot.close_unmap;
                print_str(b"[installer-child-close-unmap-final] pi/pgen/tid/tgen/pairs/classified/wall-ms/fault-ms/bound-us/donated-us/unclassified-ms/read-fail/context-change/counter-regress=");
                for (index, value) in [owner.process_index as u64, owner.process_generation,
                    owner.thread_id, owner.thread_generation, runtime.pairs,
                    runtime.classified, runtime.wall_100ns / 10_000,
                    runtime.fault_100ns / 10_000, runtime.bound_us, runtime.donated_us,
                    runtime.unclassified_100ns / 10_000, runtime.failed_read,
                    runtime.changed_context, runtime.counter_regression]
                    .into_iter().enumerate() {
                    if index != 0 { print_str(b"/"); }
                    print_u64(value);
                }
                print_str(b" root-sc-lower-bound/classified/bound-us/donated-us/unclassified-ms/read-fail/context-change/counter-regress=");
                for (index, value) in [runtime.root_classified, runtime.root_bound_us,
                    runtime.root_donated_us, runtime.root_unclassified_100ns / 10_000,
                    runtime.root_failed_read, runtime.root_changed_context,
                    runtime.root_counter_regression].into_iter().enumerate() {
                    if index != 0 { print_str(b"/"); }
                    print_u64(value);
                }
                print_str(b"\n");
            }
        } else if RUNTIME_FINALS_REFUSED.fetch_add(1, Ordering::Relaxed) == 0 {
            print_str(b"[installer-child-close-unmap-final] summary-limit-reached=");
            print_u64(RUNTIME_FINAL_LIMIT);
            print_str(b"\n");
        }
        let _ = ledger.retire(owner);
        super::root_service_gap_census::retire(owner);
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

/// Claim the exact ingress observation only after a routed fault Work and its Reply have
/// been durably installed. The retained logical caller, not a numeric Reply, proves which
/// thread incarnation owns the worker. Other VM faults remain outside this accounting.
pub(crate) fn claim_routed_fault(handler: &ExecNtHandler,
    logical: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
    pi: usize, tid: u64, badge: u64, reply: u64, page: u64,
) -> Option<InstallerFaultTicket> {
    if logical.pi() != pi || u64::from(logical.thread().thread_id()) != tid
        || logical.badge() != badge || handler.capture_process_identity(pi) != Some(logical.process())
    { return None; }
    let owner = exact_owner(handler, pi, tid, badge)?;
    if logical.thread().generation() != owner.thread_generation { return None; }
    let receipt = unsafe { (&mut *core::ptr::addr_of_mut!(FAULTS)) }
        .claim_exact(owner, badge, reply, page)?;
    unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)) }
        .fault_enter(owner, reply, receipt.entered_at_100ns)
}

/// A routed worker may settle its diagnostic only after its exact Reply was acknowledged
/// and the parked slot retired. A cancelled or uncertain worker leaves the ticket unresolved.
pub(crate) fn complete_routed_fault(handler: &ExecNtHandler,
    logical: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
    badge: u64, reply: u64, ticket: InstallerFaultTicket,
) {
    let owner = ticket.owner();
    if ticket.reply() != reply || logical.pi() != owner.process_index
        || u64::from(logical.thread().thread_id()) != owner.thread_id
        || logical.thread().generation() != owner.thread_generation
        || logical.badge() != badge
        || handler.capture_process_identity(owner.process_index) != Some(logical.process())
        || exact_owner(handler, owner.process_index, owner.thread_id, badge) != Some(owner)
    { return; }
    let _ = unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)) }
        .fault_reply_accepted(ticket, monotonic_time_100ns());
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
    // Timestamp the table entry before diagnostic IPC so read cost is not
    // charged to the guest's return-to-entry wall interval.
    let now = monotonic_time_100ns();
    let ledger = unsafe { &*core::ptr::addr_of!(SPANS) };
    let open = ledger.open_close_gap(owner, now);
    let counters = open.and_then(|gap| super::root_service_gap_census::capture_delta(
        owner, gap.return_at_100ns));
    let needs_runtime = ledger.needs_runtime_sample(owner, ssn);
    let runtime = if needs_runtime { runtime_sample(handler, owner, badge) }
        else { PairedRuntimeSample::default() };
    let begun = unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)).begin_with_pair_runtime(
        owner, ssn, now, runtime) };
    if let Some(gap) = open {
        if begun {
            super::root_service_gap_census::finish(owner, gap.return_at_100ns, now,
                ssn == SSN_NT_UNMAP_VIEW_OF_SECTION, runtime.root, counters);
        } else { super::root_service_gap_census::retire(owner); }
    }
    begun.then_some(owner)
}

pub(crate) fn returned(handler: &ExecNtHandler, owner: Option<SpanOwner>,
    badge: u64, ssn: u32, status: u32) -> bool {
    let Some(owner) = owner else { return false; };
    if exact_owner(handler, owner.process_index, owner.thread_id, badge) != Some(owner) {
        return false;
    }
    let now = monotonic_time_100ns();
    let returned = unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)).return_from_dispatch(
        owner, ssn, status, now) };
    if returned && ssn == SSN_NT_CLOSE && status != nt_user_callback::STATUS_PENDING as u32 {
        let may_sample = unsafe { (&*core::ptr::addr_of!(GAP_SAMPLES)).can_sample(owner) };
        if may_sample { let _ = super::root_service_gap_census::arm(owner, now); }
        let runtime = runtime_sample(handler, owner, badge);
        let _ = unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)) }
            .record_close_pair_runtime(owner, now, runtime);
        super::root_service_gap_census::attach_root_runtime(owner, now, runtime.root);
        // The owning route rearms its shared one-shot after this ledger mutation.
        let armed = unsafe { (&*core::ptr::addr_of!(GAP_SAMPLES)).can_sample(owner) }
            && unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)) }
                .arm_open_close_gap_deadline(owner);
        if !armed { super::root_service_gap_census::retire(owner); }
        return armed;
    }
    false
}

/// Claim before the native debug reads; nested observations cannot repeat an uncertain read.
/// The return timestamp distinguishes consecutive gaps of the same exact thread.
fn claim_gap_sample(owner: SpanOwner, return_at: u64) -> bool {
    if !unsafe { (&mut *core::ptr::addr_of_mut!(GAP_SAMPLES)).claim(owner, return_at) } {
        return false;
    }
    // An ingress-triggered sample may precede the timer delivery. No second wake is owed.
    let _ = unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)) }
        .cancel_open_close_gap_deadline(owner, return_at);
    true
}

pub(crate) fn next_gap_deadline() -> Option<u64> {
    if !ACTIVE.load(Ordering::Acquire) { return None; }
    unsafe { (&*core::ptr::addr_of!(SPANS)).next_open_close_gap_deadline() }
}

pub(crate) fn has_pending_gap_observation() -> bool {
    ACTIVE.load(Ordering::Acquire)
        && unsafe { (&*core::ptr::addr_of!(SPANS)).has_pending_gap_observation() }
}

pub(crate) fn consume_due_gap_deadlines(now: u64) -> u64 {
    if !ACTIVE.load(Ordering::Acquire) { return 0; }
    unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)) }
        .consume_due_open_close_gap_deadlines(now)
}

/// Observe a live return-to-entry interval from the root's owned maintenance boundary.
/// A one-shot Close deadline creates that boundary even if no other ingress arrives.
pub(crate) fn maybe_sample_gap(handler: &ExecNtHandler, now: u64) {
    if !ACTIVE.load(Ordering::Acquire) { return; }
    let next_scan = NEXT_GAP_SCAN_100NS.load(Ordering::Acquire);
    let periodic = now >= next_scan && NEXT_GAP_SCAN_100NS.compare_exchange(next_scan,
        now.saturating_add(GAP_SCAN_INTERVAL_100NS), Ordering::AcqRel,
        Ordering::Acquire).is_ok();
    if !periodic && !unsafe { (&*core::ptr::addr_of!(SPANS)).has_due_open_close_gap() } {
        return;
    }

    // Copy value-only candidates before any debug IPC mutates the executive IPC buffer.
    let mut candidates = [None; ROWS];
    {
        let ledger = unsafe { &*core::ptr::addr_of!(SPANS) };
        for (slot, owner) in ledger.owners().enumerate() {
            if !periodic && !ledger.is_due_open_close_gap(owner) { continue; }
            let Some(gap) = ledger.open_close_gap(owner, now) else { continue; };
            if gap.age_100ns < OPEN_CLOSE_GAP_THRESHOLD_100NS { continue; }
            candidates[slot] = Some(gap);
        }
    }

    for gap in candidates.into_iter().flatten() {
        let owner = gap.owner;
        let return_at = gap.return_at_100ns;
        // A delivered one-shot owns only this maintenance opportunity. Consume its
        // value-only receipt before native identity lookups: a retired badge or missing
        // TCB may lose this diagnostic, but cannot keep quiesce blocked indefinitely.
        let _ = unsafe { (&mut *core::ptr::addr_of_mut!(SPANS)) }
            .take_due_open_close_gap(owner, now);
        let Some(badge) = handler.hosted_thread_badge_for_tid(owner.thread_id) else { continue; };
        if exact_owner(handler, owner.process_index, owner.thread_id, badge) != Some(owner) {
            continue;
        }
        let Some(tcb) = handler.hosted_thread_tcb_for_badge(badge).filter(|tcb| *tcb > 1)
            else { continue; };
        if !claim_gap_sample(owner, return_at) { continue; }
        // Earlier candidates can perform debug IPC and serial output. Timestamp this
        // exact candidate at its own counter boundary, not at the start of the pass.
        let sample_at = monotonic_time_100ns();
        let root_counters = super::root_service_gap_census::capture_delta(owner, return_at);
        let runtime = runtime_sample(handler, owner, badge);

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
        let mut root_state = [0u64; win32k_glue::TCB_DEBUG_STATE_WORDS];
        unsafe { win32k_glue::tcb_read_debug_state(ROOT_TCB_CAP, 0, &mut root_state) };

        // A numeric TCB cap or badge is not identity. Do not attribute a sample to an
        // owner that retired, changed generation, or entered another table call.
        let still_same_gap = unsafe { (&*core::ptr::addr_of!(SPANS)).open_close_gap(owner, sample_at) }
            .is_some_and(|current| current.return_at_100ns == return_at
                && current.from_status == gap.from_status);
        if exact_owner(handler, owner.process_index, owner.thread_id, badge) == Some(owner)
            && handler.hosted_thread_tcb_for_badge(badge) == Some(tcb)
            && still_same_gap
        {
            super::root_service_gap_census::sample(owner, return_at, sample_at,
                runtime.root, root_counters);
            print_str(b"[installer-child-open-close-gap-tcb] pi/pgen/tid/tgen/badge/tcb/return-at-100ns/sample-at-100ns/age-ms/close-status/regs-valid/state/sched/enqueued/active-sc/pending-reply/reply-to/fault-type/blocked-is-call/call-reply-kind/call-reply-index/receiver-tcb/receiver-cspace/receiver-state=");
            for (index, value) in [owner.process_index as u64, owner.process_generation,
                owner.thread_id, owner.thread_generation, badge, tcb,
                return_at, sample_at, sample_at.saturating_sub(return_at) / 10_000,
                u64::from(gap.from_status),
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
            print_str(b" priority/affinity/domain/current-domain/queue-top/direct-handoff=");
            for (index, value) in [state[win32k_glue::TCB_DBG_PRIORITY],
                state[win32k_glue::TCB_DBG_AFFINITY],
                state[win32k_glue::TCB_DBG_DOMAIN],
                state[win32k_glue::TCB_DBG_CURRENT_DOMAIN],
                state[win32k_glue::TCB_DBG_QUEUE_TOP_PRIORITY],
                state[win32k_glue::TCB_DBG_DIRECT_HANDOFF]].into_iter().enumerate() {
                if index != 0 { print_str(b"/"); }
                print_u64(value);
            }
            print_str(b" root-tcb/state/sched/enqueued/priority/sc/active-sc/pending-reply/fault/affinity/domain/current-domain/queue-top/direct-handoff=");
            for (index, value) in [ROOT_TCB_CAP,
                root_state[win32k_glue::TCB_DBG_STATE],
                root_state[win32k_glue::TCB_DBG_SCHEDULABLE],
                root_state[win32k_glue::TCB_DBG_ENQUEUED],
                root_state[win32k_glue::TCB_DBG_PRIORITY],
                root_state[win32k_glue::TCB_DBG_SC],
                root_state[win32k_glue::TCB_DBG_ACTIVE_SC],
                root_state[win32k_glue::TCB_DBG_PENDING_REPLY],
                root_state[win32k_glue::TCB_DBG_PENDING_FAULT],
                root_state[win32k_glue::TCB_DBG_AFFINITY],
                root_state[win32k_glue::TCB_DBG_DOMAIN],
                root_state[win32k_glue::TCB_DBG_CURRENT_DOMAIN],
                root_state[win32k_glue::TCB_DBG_QUEUE_TOP_PRIORITY],
                root_state[win32k_glue::TCB_DBG_DIRECT_HANDOFF]].into_iter().enumerate() {
                if index != 0 { print_str(b"/"); }
                print_u64(value);
            }
            print_str(b" sc-read/child-valid/cap/bound-us/donated-us/root-valid/cap/bound-us/donated-us=");
            for (index, value) in [u64::from(runtime.child.is_some()),
                runtime.child.map_or(0, |sample| sample.sched_context),
                runtime.child.map_or(0, |sample| sample.bound_us),
                runtime.child.map_or(0, |sample| sample.donated_us),
                u64::from(runtime.root.is_some()),
                runtime.root.map_or(0, |sample| sample.sched_context),
                runtime.root.map_or(0, |sample| sample.bound_us),
                runtime.root.map_or(0, |sample| sample.donated_us)].into_iter().enumerate() {
                if index != 0 { print_str(b"/"); }
                print_u64(value);
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
                            sample_at.saturating_sub(fault.entered_at_100ns) / 10_000);
                        match (section_probe, image_probe) {
                            (Some(probe), None) | (None, Some(probe)) => {
                                let _ = write!(record,
                                    " worker={:?} phase={} age-ms={} read-subphase={} irp={:?} irp-age-ms={:?} executing={}",
                                    probe.source, probe.phase,
                                    sample_at.saturating_sub(probe.phase_entered_at_100ns) / 10_000,
                                    probe.read_subphase, probe.irp_id,
                                    probe.irp_entered_at_100ns.map(|at|
                                        sample_at.saturating_sub(at) / 10_000), probe.executing);
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
    retire_stale(handler);
    let epoch = CENSUS_PERIODIC_DUMPS.load(Ordering::Relaxed);
    if !unsafe { (&mut *core::ptr::addr_of_mut!(CENSUS_GATE)).admit(epoch) } { return; }
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
        print_str(b" routed-fault-gap-ms/residual-gap-ms/unresolved-faults/fault-admission-overflow=");
        print_u64(snapshot.completed_fault_gap_100ns / 10_000); print_str(b"/");
        print_u64(snapshot.residual_gap_100ns / 10_000); print_str(b"/");
        print_u64(snapshot.unresolved_faults); print_str(b"/");
        print_u64(snapshot.fault_admission_overflow);
        print_str(b" close-unmap/pairs/classified/wall-ms/fault-ms/bound-us/donated-us/unclassified-ms/read-fail/context-change/counter-regress=");
        let runtime = snapshot.close_unmap;
        for (index, value) in [runtime.pairs, runtime.classified,
            runtime.wall_100ns / 10_000, runtime.fault_100ns / 10_000,
            runtime.bound_us, runtime.donated_us,
            runtime.unclassified_100ns / 10_000, runtime.failed_read,
            runtime.changed_context, runtime.counter_regression].into_iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(value);
        }
        print_str(b" root-sc-lower-bound/classified/bound-us/donated-us/unclassified-ms/read-fail/context-change/counter-regress=");
        for (index, value) in [runtime.root_classified, runtime.root_bound_us,
            runtime.root_donated_us, runtime.root_unclassified_100ns / 10_000,
            runtime.root_failed_read, runtime.root_changed_context,
            runtime.root_counter_regression].into_iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(value);
        }
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
    let refused = RUNTIME_READS_REFUSED.load(Ordering::Relaxed);
    if refused != 0 {
        print_str(b"[installer-child-span] runtime-reads-used/refused=");
        print_u64(RUNTIME_READS_USED.load(Ordering::Relaxed)); print_str(b"/");
        print_u64(refused); print_str(b"\n");
    }
    super::root_service_gap_census::print_budget();
}
