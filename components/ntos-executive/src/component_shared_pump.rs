//! Shared receiver routing for a currently entered component invocation.

use super::shared_ingress::owner::runtime;
use super::file_pump_diagnostic::{Stage, StageScope};
use super::*;
use nt_component_suspension::{
    InlineIrqCheckpoint, InlineIrqCheckpointError, InlineIrqCheckpointMismatch,
    InlineIrqCheckpointObservation, IngressExecutionOwner,
};
use nt_component_suspension::peer_registry::PeerRoute;

// Counts only entered receive scopes and observed IRQ notifications. Periodic census reads these
// atomics without walking the hosted ingress table or changing receive ownership.
static ACTIVE_IRP_RECEIVES: AtomicU64 = AtomicU64::new(0);
static ACTIVE_SYSCALL_RECEIVES: AtomicU64 = AtomicU64::new(0);
static ACTIVE_RETAINED_SEH_RECEIVES: AtomicU64 = AtomicU64::new(0);
const ACTIVE_IRP_SNAPSHOT_SLOTS: usize = 8;
const SNAPSHOT_CLAIMED: u64 = u64::MAX;
static NEXT_IRP_SNAPSHOT: AtomicU64 = AtomicU64::new(1);
static ACTIVE_IRP_SNAPSHOT_OVERFLOW: AtomicU64 = AtomicU64::new(0);

// The receive scope owns the shared mapping. Publish only copied numeric values so a periodic
// census never dereferences a component mapping after its scope or instance has retired.
struct ActiveIrpSnapshot {
    sequence: AtomicU64,
    domain: AtomicU64,
    cookie: AtomicU64,
    route: AtomicU64,
    tcb: AtomicU64,
    shared_va: AtomicU64,
    reply: AtomicU64,
    source_irp: AtomicU64,
    control_id: AtomicU64,
    major: AtomicU64,
    minor: AtomicU64,
}

impl ActiveIrpSnapshot {
    const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            domain: AtomicU64::new(0),
            cookie: AtomicU64::new(0),
            route: AtomicU64::new(0),
            tcb: AtomicU64::new(0),
            shared_va: AtomicU64::new(0),
            reply: AtomicU64::new(0),
            source_irp: AtomicU64::new(0),
            control_id: AtomicU64::new(0),
            major: AtomicU64::new(0),
            minor: AtomicU64::new(0),
        }
    }
}

static ACTIVE_IRP_SNAPSHOTS: [ActiveIrpSnapshot; ACTIVE_IRP_SNAPSHOT_SLOTS] =
    [const { ActiveIrpSnapshot::new() }; ACTIVE_IRP_SNAPSHOT_SLOTS];

// The nested Syscall receiver can hold the root service loop while timer notifications keep
// arriving. Copy the exact entered owner and count only non-timer arrivals. The periodic reader
// never follows a route, touches the shared mapping, or changes receive ownership.
const ACTIVE_SYSCALL_SNAPSHOT_SLOTS: usize = 8;
// Phase values in the serial census: 1 pump work, 2 physical wait, 3 hosted arrival,
// 4 Call arrival, 5 notification. Only phases 3 and 4 advance provider progress.
const SYSCALL_PHASE_PUMP_WORK: u64 = 1;
const SYSCALL_PHASE_PHYSICAL_WAIT: u64 = 2;
const SYSCALL_PHASE_HOSTED: u64 = 3;
const SYSCALL_PHASE_CALL: u64 = 4;
const SYSCALL_PHASE_NOTIFICATION: u64 = 5;
static NEXT_SYSCALL_SNAPSHOT: AtomicU64 = AtomicU64::new(1);
static ACTIVE_SYSCALL_SNAPSHOT_OVERFLOW: AtomicU64 = AtomicU64::new(0);

struct ActiveSyscallSnapshot {
    sequence: AtomicU64,
    observation_epoch: AtomicU64,
    started_100ns: AtomicU64,
    domain: AtomicU64,
    cookie: AtomicU64,
    route: AtomicU64,
    route_domain: AtomicU64,
    route_generation: AtomicU64,
    lane_index: AtomicU64,
    lane_generation: AtomicU64,
    tcb: AtomicU64,
    reply: AtomicU64,
    ssn: AtomicU64,
    client_pi: AtomicU64,
    client_generation: AtomicU64,
    provider_arrivals: AtomicU64,
    last_provider_at_100ns: AtomicU64,
    phase: AtomicU64,
    last_transition_at_100ns: AtomicU64,
    reply_binding: AtomicU64,
    last_binding_at_100ns: AtomicU64,
}

impl ActiveSyscallSnapshot {
    const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            observation_epoch: AtomicU64::new(0),
            started_100ns: AtomicU64::new(0),
            domain: AtomicU64::new(0),
            cookie: AtomicU64::new(0),
            route: AtomicU64::new(0),
            route_domain: AtomicU64::new(0),
            route_generation: AtomicU64::new(0),
            lane_index: AtomicU64::new(0),
            lane_generation: AtomicU64::new(0),
            tcb: AtomicU64::new(0),
            reply: AtomicU64::new(0),
            ssn: AtomicU64::new(0),
            client_pi: AtomicU64::new(0),
            client_generation: AtomicU64::new(0),
            provider_arrivals: AtomicU64::new(0),
            last_provider_at_100ns: AtomicU64::new(0),
            phase: AtomicU64::new(0),
            last_transition_at_100ns: AtomicU64::new(0),
            reply_binding: AtomicU64::new(0),
            last_binding_at_100ns: AtomicU64::new(0),
        }
    }

    // Only the entered receive scope writes this slot. An odd epoch means a pair of diagnostic
    // fields is being replaced; readers skip it rather than reporting a mixed observation.
    fn begin_update(&self) { self.observation_epoch.fetch_add(1, Ordering::AcqRel); }
    fn end_update(&self) { self.observation_epoch.fetch_add(1, Ordering::Release); }
}

static ACTIVE_SYSCALL_SNAPSHOTS: [ActiveSyscallSnapshot; ACTIVE_SYSCALL_SNAPSHOT_SLOTS] =
    [const { ActiveSyscallSnapshot::new() }; ACTIVE_SYSCALL_SNAPSHOT_SLOTS];

fn capture_active_syscall_snapshot(ch: &PumpChannel, route: PeerRoute) -> Option<(usize, u64)> {
    let sequence = NEXT_SYSCALL_SNAPSHOT.fetch_add(1, Ordering::Relaxed);
    if sequence == 0 || sequence == SNAPSHOT_CLAIMED {
        ACTIVE_SYSCALL_SNAPSHOT_OVERFLOW.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let Some((index, slot)) = ACTIVE_SYSCALL_SNAPSHOTS.iter().enumerate().find(|(_, slot)| {
        slot.sequence.compare_exchange(0, SNAPSHOT_CLAIMED,
            Ordering::AcqRel, Ordering::Relaxed).is_ok()
    }) else {
        ACTIVE_SYSCALL_SNAPSHOT_OVERFLOW.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let domain = ch.physical_domain;
    slot.started_100ns.store(crate::monotonic_time_100ns(), Ordering::Relaxed);
    slot.domain.store(domain.map_or(0, |id| id.domain_id.raw()), Ordering::Relaxed);
    slot.cookie.store(domain.map_or(0, |id| id.cookie), Ordering::Relaxed);
    slot.route.store(route.badge(), Ordering::Relaxed);
    let route_identity = route.identity();
    slot.route_domain.store(route_identity.domain, Ordering::Relaxed);
    slot.route_generation.store(route_identity.domain_generation, Ordering::Relaxed);
    slot.lane_index.store(route_identity.lane.index as u64, Ordering::Relaxed);
    slot.lane_generation.store(route_identity.lane.generation, Ordering::Relaxed);
    slot.tcb.store(ch.tcb, Ordering::Relaxed);
    slot.reply.store(unsafe { runtime::current_reply(route).unwrap_or(0) }, Ordering::Relaxed);
    slot.ssn.store(if ch.shared_va == 0 { 0 } else {
        unsafe { core::ptr::read_volatile((ch.shared_va + crate::win32k_subsystem::SH_REQ_SSN) as *const u64) }
    }, Ordering::Relaxed);
    slot.client_pi.store(ch.client_pi, Ordering::Relaxed);
    slot.client_generation.store(ch.client_generation, Ordering::Relaxed);
    slot.provider_arrivals.store(0, Ordering::Relaxed);
    slot.last_provider_at_100ns.store(0, Ordering::Relaxed);
    slot.observation_epoch.store(0, Ordering::Relaxed);
    slot.phase.store(SYSCALL_PHASE_PUMP_WORK, Ordering::Relaxed);
    slot.last_transition_at_100ns.store(slot.started_100ns.load(Ordering::Relaxed), Ordering::Relaxed);
    slot.reply_binding.store(0, Ordering::Relaxed);
    slot.last_binding_at_100ns.store(0, Ordering::Relaxed);
    slot.sequence.store(sequence, Ordering::Release);
    Some((index, sequence))
}

pub(super) fn print_active_syscall_receive_census() {
    for (index, slot) in ACTIVE_SYSCALL_SNAPSHOTS.iter().enumerate() {
        let sequence = slot.sequence.load(Ordering::Acquire);
        if sequence == 0 || sequence == SNAPSHOT_CLAIMED { continue; }
        let epoch = slot.observation_epoch.load(Ordering::Acquire);
        if epoch & 1 != 0 { continue; }
        let values = [
            slot.started_100ns.load(Ordering::Relaxed),
            slot.domain.load(Ordering::Relaxed), slot.cookie.load(Ordering::Relaxed),
            slot.route.load(Ordering::Relaxed),
            slot.route_domain.load(Ordering::Relaxed),
            slot.route_generation.load(Ordering::Relaxed),
            slot.lane_index.load(Ordering::Relaxed),
            slot.lane_generation.load(Ordering::Relaxed),
            slot.tcb.load(Ordering::Relaxed),
            slot.reply.load(Ordering::Relaxed), slot.ssn.load(Ordering::Relaxed),
            slot.client_pi.load(Ordering::Relaxed),
            slot.client_generation.load(Ordering::Relaxed),
            slot.provider_arrivals.load(Ordering::Relaxed),
            slot.last_provider_at_100ns.load(Ordering::Relaxed),
            slot.phase.load(Ordering::Relaxed),
            slot.last_transition_at_100ns.load(Ordering::Relaxed),
            slot.reply_binding.load(Ordering::Relaxed),
            slot.last_binding_at_100ns.load(Ordering::Relaxed),
        ];
        core::sync::atomic::fence(Ordering::Acquire);
        if slot.observation_epoch.load(Ordering::Acquire) != epoch { continue; }
        if slot.sequence.load(Ordering::Acquire) != sequence { continue; }
        crate::print_str(b"[pump-active-syscall] slot/sequence/start-100ns/domain/cookie/route/route-domain/route-gen/lane/lane-gen/tcb/reply/ssn/client-pi/client-gen/provider-arrivals/last-provider-100ns/phase/last-transition-100ns/pre-recv-reply-binding/pre-recv-binding-sampled-100ns=");
        crate::print_u64(index as u64);
        crate::print_str(b"/"); crate::print_u64(sequence);
        for value in values {
            crate::print_str(b"/"); crate::print_u64(value);
        }
        crate::print_str(b"\n");
    }
    let overflow = ACTIVE_SYSCALL_SNAPSHOT_OVERFLOW.load(Ordering::Relaxed);
    if overflow != 0 {
        crate::print_str(b"[pump-active-syscall] snapshot-overflow=");
        crate::print_u64(overflow);
        crate::print_str(b"\n");
    }
}

fn capture_active_irp_snapshot(ch: &PumpChannel, route: PeerRoute) -> Option<(usize, u64)> {
    let sequence = NEXT_IRP_SNAPSHOT.fetch_add(1, Ordering::Relaxed);
    if sequence == 0 || sequence == SNAPSHOT_CLAIMED {
        ACTIVE_IRP_SNAPSHOT_OVERFLOW.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let Some((index, slot)) = ACTIVE_IRP_SNAPSHOTS.iter().enumerate().find(|(_, slot)| {
        slot.sequence.compare_exchange(0, SNAPSHOT_CLAIMED,
            Ordering::AcqRel, Ordering::Relaxed).is_ok()
    }) else {
        ACTIVE_IRP_SNAPSHOT_OVERFLOW.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let domain = ch.physical_domain;
    slot.domain.store(domain.map_or(0, |id| id.domain_id.raw()), Ordering::Relaxed);
    slot.cookie.store(domain.map_or(0, |id| id.cookie), Ordering::Relaxed);
    slot.route.store(route.badge(), Ordering::Relaxed);
    slot.tcb.store(ch.tcb, Ordering::Relaxed);
    slot.shared_va.store(ch.shared_va, Ordering::Relaxed);
    slot.reply.store(unsafe { runtime::current_reply(route).unwrap_or(0) }, Ordering::Relaxed);
    if ch.shared_va != 0 {
        let read = |offset| unsafe { core::ptr::read_volatile((ch.shared_va + offset) as *const u64) };
        slot.source_irp.store(read(crate::driver_launch::SH_ACTIVE_IRP), Ordering::Relaxed);
        slot.control_id.store(read(crate::driver_launch::SH_REQ_CONTROL_ID), Ordering::Relaxed);
        slot.major.store(read(crate::driver_launch::SH_REQ_MAJOR), Ordering::Relaxed);
        slot.minor.store(read(crate::driver_launch::SH_REQ_MINOR), Ordering::Relaxed);
    }
    slot.sequence.store(sequence, Ordering::Release);
    Some((index, sequence))
}

pub(super) fn print_active_irp_receive_census() {
    for (index, slot) in ACTIVE_IRP_SNAPSHOTS.iter().enumerate() {
        let sequence = slot.sequence.load(Ordering::Acquire);
        if sequence == 0 || sequence == SNAPSHOT_CLAIMED { continue; }
        let values = [
            slot.domain.load(Ordering::Relaxed), slot.cookie.load(Ordering::Relaxed),
            slot.route.load(Ordering::Relaxed), slot.tcb.load(Ordering::Relaxed),
            slot.shared_va.load(Ordering::Relaxed), slot.reply.load(Ordering::Relaxed),
            slot.source_irp.load(Ordering::Relaxed), slot.control_id.load(Ordering::Relaxed),
            slot.major.load(Ordering::Relaxed), slot.minor.load(Ordering::Relaxed),
        ];
        if slot.sequence.load(Ordering::Acquire) != sequence { continue; }
        crate::print_str(b"[pump-active-irp] slot/sequence/domain/cookie/route/tcb/shared/reply/source-irp/control-id/major/minor=");
        crate::print_u64(index as u64);
        crate::print_str(b"/"); crate::print_u64(sequence);
        for value in values {
            crate::print_str(b"/"); crate::print_u64(value);
        }
        crate::print_str(b"\n");
    }
    let overflow = ACTIVE_IRP_SNAPSHOT_OVERFLOW.load(Ordering::Relaxed);
    if overflow != 0 {
        crate::print_str(b"[pump-active-irp] snapshot-overflow=");
        crate::print_u64(overflow);
        crate::print_str(b"\n");
    }
}
static IRQ_IRP_RECEIVES: AtomicU64 = AtomicU64::new(0);
static IRQ_SYSCALL_RECEIVES: AtomicU64 = AtomicU64::new(0);
static IRQ_RETAINED_SEH_RECEIVES: AtomicU64 = AtomicU64::new(0);
// Route-scoped File READ/WRITE receive observations. The physical transport and retained File IRP
// are checked at the point of measurement; these counters are never used to make a routing choice.
static FILE_RECEIVE_CALLS: AtomicU64 = AtomicU64::new(0);
static FILE_RECEIVE_TICKS: AtomicU64 = AtomicU64::new(0);
static FILE_RECEIVE_HOSTED: AtomicU64 = AtomicU64::new(0);
static FILE_RECEIVE_CALL: AtomicU64 = AtomicU64::new(0);
static FILE_RECEIVE_TIMER: AtomicU64 = AtomicU64::new(0);
static FILE_RECEIVE_OTHER_NOTIFICATION: AtomicU64 = AtomicU64::new(0);
static FILE_RECEIVE_ERROR: AtomicU64 = AtomicU64::new(0);
static FILE_RECEIVE_SCHEDULER_YIELD: AtomicU64 = AtomicU64::new(0);
static FILE_RECEIVE_AUTONOMOUS: AtomicU64 = AtomicU64::new(0);
static PS_CREATE_RECEIVE_TRACE: AtomicU64 = AtomicU64::new(0);
static PS_CREATE_RECEIVE_EVENTS: AtomicU64 = AtomicU64::new(0);
static PS_CREATE_AUTONOMOUS_EVENTS: AtomicU64 = AtomicU64::new(0);
static PS_CREATE_AFTER_AUTONOMOUS_TRACE: AtomicU64 = AtomicU64::new(0);
static PS_CREATE_AFTER_AUTONOMOUS_SELECT: AtomicU64 = AtomicU64::new(0);
static PS_CREATE_FOLD_EVENTS: AtomicU64 = AtomicU64::new(0);
static PS_CREATE_PARENT_MESSAGES: AtomicU64 = AtomicU64::new(0);
static PS_CREATE_LAST_PARENT_INFO: AtomicU64 = AtomicU64::new(0);
static PS_CREATE_LAST_PARENT_OP: AtomicU64 = AtomicU64::new(0);

pub(super) fn begin_ps_create_receive_trace() {
    PS_CREATE_RECEIVE_TRACE.store(1, Ordering::Relaxed);
    PS_CREATE_RECEIVE_EVENTS.store(0, Ordering::Relaxed);
    PS_CREATE_AUTONOMOUS_EVENTS.store(0, Ordering::Relaxed);
    PS_CREATE_AFTER_AUTONOMOUS_TRACE.store(0, Ordering::Relaxed);
    PS_CREATE_AFTER_AUTONOMOUS_SELECT.store(0, Ordering::Relaxed);
    PS_CREATE_FOLD_EVENTS.store(0, Ordering::Relaxed);
    PS_CREATE_PARENT_MESSAGES.store(0, Ordering::Relaxed);
    PS_CREATE_LAST_PARENT_INFO.store(0, Ordering::Relaxed);
    PS_CREATE_LAST_PARENT_OP.store(0, Ordering::Relaxed);
}

pub(super) fn ps_create_parent_progress() -> (u64, u64, u64) {
    (
        PS_CREATE_PARENT_MESSAGES.load(Ordering::Relaxed),
        PS_CREATE_LAST_PARENT_INFO.load(Ordering::Relaxed),
        PS_CREATE_LAST_PARENT_OP.load(Ordering::Relaxed),
    )
}

fn trace_ps_create_event(stage: &[u8], route: PeerRoute, reply: u64, info: u64) {
    if PS_CREATE_RECEIVE_TRACE.load(Ordering::Relaxed) == 0 {
        return;
    }
    let counter = if stage.starts_with(b"autonomous-") {
        &PS_CREATE_AUTONOMOUS_EVENTS
    } else if stage.starts_with(b"fold-") {
        &PS_CREATE_FOLD_EVENTS
    } else {
        &PS_CREATE_RECEIVE_EVENTS
    };
    let sequence = counter.fetch_add(1, Ordering::Relaxed) + 1;
    let initial = if stage.starts_with(b"autonomous-") || stage.starts_with(b"fold-") {
        32
    } else {
        8
    };
    if sequence > initial && !sequence.is_power_of_two() {
        return;
    }
    crate::print_str(b"[ps-create-event] #");
    crate::print_u64(sequence);
    crate::print_str(b" stage=");
    crate::print_str(stage);
    crate::print_str(b" route=");
    crate::print_u64(route.badge());
    crate::print_str(b" reply=");
    crate::print_u64(reply);
    crate::print_str(b" label=");
    crate::print_u64(info >> 12);
    crate::print_str(b"\n");
}

fn trace_ps_create_receive(ch: &PumpChannel, stage: &[u8], route: Option<PeerRoute>) {
    let sequence = PS_CREATE_RECEIVE_TRACE.load(Ordering::Relaxed);
    if sequence == 0 {
        return;
    }
    let (prefix, ordinal) = if sequence <= 64 {
        PS_CREATE_RECEIVE_TRACE.store(sequence + 1, Ordering::Relaxed);
        (&b"[ps-create-receive] #"[..], sequence)
    } else {
        let after = PS_CREATE_AFTER_AUTONOMOUS_TRACE.load(Ordering::Relaxed);
        if after == 0 {
            return;
        }
        PS_CREATE_AFTER_AUTONOMOUS_TRACE.store(after + 1, Ordering::Relaxed);
        if after > 48 && !after.is_power_of_two() {
            return;
        }
        (&b"[ps-create-after-autonomous] #"[..], after)
    };
    crate::print_str(prefix);
    crate::print_u64(ordinal);
    crate::print_str(b" stage=");
    crate::print_str(stage);
    crate::print_str(b" tcb=");
    crate::print_u64(ch.tcb);
    crate::print_str(b" route=");
    crate::print_u64(route.map_or(0, |route| route.badge()));
    crate::print_str(b"\n");
}

struct ReceiveCensusScope {
    kind: ReqKind,
    retained_seh: bool,
    irp_snapshot: Option<(usize, u64)>,
    syscall_snapshot: Option<(usize, u64)>,
}

impl ReceiveCensusScope {
    fn enter(ch: &PumpChannel, route: PeerRoute, retained_seh: bool) -> Self {
        let kind = ch.caps.kind;
        let irp_snapshot = if kind == ReqKind::Irp {
            capture_active_irp_snapshot(ch, route)
        } else { None };
        let syscall_snapshot = if kind == ReqKind::Syscall {
            capture_active_syscall_snapshot(ch, route)
        } else { None };
        match kind {
            ReqKind::Irp => { ACTIVE_IRP_RECEIVES.fetch_add(1, Ordering::Relaxed); }
            ReqKind::Syscall => { ACTIVE_SYSCALL_RECEIVES.fetch_add(1, Ordering::Relaxed); }
        }
        if retained_seh {
            ACTIVE_RETAINED_SEH_RECEIVES.fetch_add(1, Ordering::Relaxed);
        }
        Self { kind, retained_seh, irp_snapshot, syscall_snapshot }
    }
}

fn record_active_syscall_provider_arrival(scope: &ReceiveCensusScope) {
    let Some((index, sequence)) = scope.syscall_snapshot else { return; };
    let slot = &ACTIVE_SYSCALL_SNAPSHOTS[index];
    if slot.sequence.load(Ordering::Acquire) != sequence { return; }
    slot.begin_update();
    slot.provider_arrivals.fetch_add(1, Ordering::Relaxed);
    slot.last_provider_at_100ns.store(crate::monotonic_time_100ns(), Ordering::Relaxed);
    slot.end_update();
}

fn record_active_syscall_transition(scope: &ReceiveCensusScope, phase: u64) {
    let Some((index, sequence)) = scope.syscall_snapshot else { return; };
    let slot = &ACTIVE_SYSCALL_SNAPSHOTS[index];
    if slot.sequence.load(Ordering::Acquire) != sequence { return; }
    if slot.phase.load(Ordering::Relaxed) == phase { return; }
    slot.begin_update();
    slot.last_transition_at_100ns.store(crate::monotonic_time_100ns(), Ordering::Relaxed);
    slot.phase.store(phase, Ordering::Release);
    slot.end_update();
}

fn record_active_syscall_physical_owner(scope: &ReceiveCensusScope, route: PeerRoute, tcb: u64) {
    let Some((index, sequence)) = scope.syscall_snapshot else { return; };
    let slot = &ACTIVE_SYSCALL_SNAPSHOTS[index];
    if slot.sequence.load(Ordering::Acquire) != sequence { return; }
    let now = crate::monotonic_time_100ns();
    let last = slot.last_binding_at_100ns.load(Ordering::Relaxed);
    // This samples the binding before Recv; Recv can change it while blocked. The kernel query
    // can be expensive, so refresh at most once per five seconds and print the sample's age.
    if last != 0 && now.wrapping_sub(last) < 50_000_000 { return; }
    let route_identity = route.identity();
    let route_domain = slot.route_domain.load(Ordering::Relaxed);
    let route_generation = slot.route_generation.load(Ordering::Relaxed);
    let lane_index = slot.lane_index.load(Ordering::Relaxed);
    let lane_generation = slot.lane_generation.load(Ordering::Relaxed);
    let reply = slot.reply.load(Ordering::Relaxed);
    let observation = if slot.route.load(Ordering::Relaxed) != route.badge()
        || route_identity.domain != route_domain
        || route_identity.domain_generation != route_generation
        || route_identity.lane.index as u64 != lane_index
        || route_identity.lane.generation != lane_generation
        || route_identity.executor != tcb
        || slot.tcb.load(Ordering::Relaxed) != tcb
    {
        runtime::ActiveReplyObservation::RouteMismatch
    } else {
        unsafe { runtime::observe_active_reply(
            route, route_domain, route_generation, lane_index, lane_generation, tcb, reply,
        ) }
    };
    slot.begin_update();
    slot.reply_binding.store(observation as u64, Ordering::Relaxed);
    slot.last_binding_at_100ns.store(crate::monotonic_time_100ns(), Ordering::Release);
    slot.end_update();
}

impl Drop for ReceiveCensusScope {
    fn drop(&mut self) {
        if let Some((index, sequence)) = self.irp_snapshot {
            let _ = ACTIVE_IRP_SNAPSHOTS[index].sequence.compare_exchange(
                sequence, 0, Ordering::AcqRel, Ordering::Relaxed,
            );
        }
        if let Some((index, sequence)) = self.syscall_snapshot {
            let _ = ACTIVE_SYSCALL_SNAPSHOTS[index].sequence.compare_exchange(
                sequence, 0, Ordering::AcqRel, Ordering::Relaxed,
            );
        }
        match self.kind {
            ReqKind::Irp => { ACTIVE_IRP_RECEIVES.fetch_sub(1, Ordering::Relaxed); }
            ReqKind::Syscall => { ACTIVE_SYSCALL_RECEIVES.fetch_sub(1, Ordering::Relaxed); }
        }
        if self.retained_seh {
            ACTIVE_RETAINED_SEH_RECEIVES.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

pub(super) fn receive_census() -> (u64, u64, u64, u64, u64, u64) {
    (
        ACTIVE_IRP_RECEIVES.load(Ordering::Relaxed),
        ACTIVE_SYSCALL_RECEIVES.load(Ordering::Relaxed),
        ACTIVE_RETAINED_SEH_RECEIVES.load(Ordering::Relaxed),
        IRQ_IRP_RECEIVES.load(Ordering::Relaxed),
        IRQ_SYSCALL_RECEIVES.load(Ordering::Relaxed),
        IRQ_RETAINED_SEH_RECEIVES.load(Ordering::Relaxed),
    )
}

pub(super) fn file_receive_census() -> [u64; 9] {
    [
        FILE_RECEIVE_CALLS.load(Ordering::Relaxed),
        FILE_RECEIVE_TICKS.load(Ordering::Relaxed),
        FILE_RECEIVE_HOSTED.load(Ordering::Relaxed),
        FILE_RECEIVE_CALL.load(Ordering::Relaxed),
        FILE_RECEIVE_TIMER.load(Ordering::Relaxed),
        FILE_RECEIVE_OTHER_NOTIFICATION.load(Ordering::Relaxed),
        FILE_RECEIVE_ERROR.load(Ordering::Relaxed),
        FILE_RECEIVE_SCHEDULER_YIELD.load(Ordering::Relaxed),
        FILE_RECEIVE_AUTONOMOUS.load(Ordering::Relaxed),
    ]
}

/// Run the established bounded IRQ/DPC scheduler for an exact dispatch or an idle receiver.
/// A dispatch is parked and restored by the scheduler; an idle receiver has no parent to park.
/// Neither case sends or replays the retained Reply.
unsafe fn inline_irq_observation(
    ch: &PumpChannel, route: PeerRoute,
) -> InlineIrqCheckpointObservation {
    InlineIrqCheckpointObservation {
        route: runtime::channel_route(ch).ok().flatten(),
        dispatch: runtime::dispatch(route).ok(),
        reply: runtime::current_reply(route).ok(),
        execution: runtime::receive_owner(route).ok(),
    }
}

unsafe fn trace_inline_irq_checkpoint_failure(
    ch: &PumpChannel,
    error: InlineIrqCheckpointError,
    expected_route: PeerRoute,
    expected_dispatch: Option<nt_component_suspension::LaneDispatchIdentity>,
    expected_reply: Option<u64>,
    observed: InlineIrqCheckpointObservation,
) {
    let (phase, mismatch) = match error {
        InlineIrqCheckpointError::Preflight(mismatch) => (b"preflight".as_slice(), mismatch),
        InlineIrqCheckpointError::PostRestore(mismatch) => (b"post-restore".as_slice(), mismatch),
        InlineIrqCheckpointError::Consumed => (b"consumed".as_slice(), InlineIrqCheckpointMismatch::ExecutionOwner),
    };
    let mismatch = match mismatch {
        InlineIrqCheckpointMismatch::Route => b"route".as_slice(),
        InlineIrqCheckpointMismatch::Dispatch => b"dispatch".as_slice(),
        InlineIrqCheckpointMismatch::Reply => b"reply".as_slice(),
        InlineIrqCheckpointMismatch::ExecutionOwner => b"execution-owner".as_slice(),
    };
    let (owner_kind, owner_epoch) = match observed.execution {
        Some(IngressExecutionOwner::Dispatch(dispatch)) => (1, dispatch.epoch()),
        Some(IngressExecutionOwner::Idle) => (2, 0),
        Some(IngressExecutionOwner::Startup(_)) => (3, 0),
        None => (0, 0),
    };
    crate::print_str(b"[inline-irq-checkpoint] phase=");
    crate::print_str(phase);
    crate::print_str(b" mismatch=");
    crate::print_str(mismatch);
    crate::print_str(b" route-status=");
    let route_status: &[u8] = match runtime::channel_route(ch) {
        Ok(Some(_)) => b"resolved",
        Ok(None) => b"absent",
        Err(runtime::Error::PhysicalIdentity) => b"physical-identity",
        Err(runtime::Error::UnknownPeer) => b"unknown-peer",
        Err(runtime::Error::Admission) => b"admission",
        Err(runtime::Error::Initialization) => b"initialization",
        Err(_) => b"other",
    };
    crate::print_str(route_status);
    crate::print_str(b" raw-channel/badge/domain/gen/executor/tcb/pml4/physical-domain/cookie/fault-ep=");
    crate::print_u64(ch.ingress_route.map_or(0, |route| route.badge()));
    crate::print_str(b"/"); crate::print_u64(ch.ingress_route.map_or(0, |route| route.identity().domain));
    crate::print_str(b"/"); crate::print_u64(ch.ingress_route.map_or(0, |route| route.identity().domain_generation));
    crate::print_str(b"/"); crate::print_u64(ch.ingress_route.map_or(0, |route| route.identity().executor));
    crate::print_str(b"/"); crate::print_u64(ch.tcb);
    crate::print_str(b"/"); crate::print_u64(ch.pml4);
    crate::print_str(b"/"); crate::print_u64(ch.physical_domain.map_or(0, |domain| domain.domain_id.raw()));
    crate::print_str(b"/"); crate::print_u64(ch.physical_domain.map_or(0, |domain| domain.cookie));
    crate::print_str(b"/"); crate::print_u64(ch.fault_ep);
    crate::print_str(b" expected-badge/domain/gen/tcb/dispatch/reply=");
    crate::print_u64(expected_route.badge());
    crate::print_str(b"/"); crate::print_u64(expected_route.identity().domain);
    crate::print_str(b"/"); crate::print_u64(expected_route.identity().domain_generation);
    crate::print_str(b"/"); crate::print_u64(expected_route.identity().executor);
    crate::print_str(b"/"); crate::print_u64(expected_dispatch.map_or(0, |dispatch| dispatch.epoch()));
    crate::print_str(b"/"); crate::print_u64(expected_reply.unwrap_or(0));
    crate::print_str(b" actual-route/badge/domain/gen/tcb/dispatch/reply/owner-kind/owner-epoch=");
    crate::print_u64(observed.route.map_or(0, |route| route.badge()));
    crate::print_str(b"/"); crate::print_u64(observed.route.map_or(0, |route| route.identity().domain));
    crate::print_str(b"/"); crate::print_u64(observed.route.map_or(0, |route| route.identity().domain_generation));
    crate::print_str(b"/"); crate::print_u64(observed.route.map_or(0, |route| route.identity().executor));
    crate::print_str(b"/"); crate::print_u64(observed.dispatch.map_or(0, |dispatch| dispatch.epoch()));
    crate::print_str(b"/"); crate::print_u64(observed.reply.unwrap_or(0));
    crate::print_str(b"/"); crate::print_u64(owner_kind);
    crate::print_str(b"/"); crate::print_u64(owner_epoch);
    let running = runtime::hold_snapshot().running;
    crate::print_str(b" running-lane/index/gen/badge/dispatch/reply/tcb/quarantined=");
    crate::print_u64(running.map_or(0, |row| u64::from(row.lane.index)));
    crate::print_str(b"/"); crate::print_u64(running.map_or(0, |row| row.lane.generation));
    crate::print_str(b"/"); crate::print_u64(running.and_then(|row| row.route).map_or(0, |route| route.badge()));
    crate::print_str(b"/"); crate::print_u64(running.and_then(|row| row.dispatch).map_or(0, |dispatch| dispatch.epoch()));
    crate::print_str(b"/"); crate::print_u64(running.and_then(|row| row.binding).map_or(0, |binding| binding.reply_object));
    crate::print_str(b"/"); crate::print_u64(running.and_then(|row| row.physical).map_or(0, |source| source.tcb));
    crate::print_str(b"/"); crate::print_u64(running.and_then(|row| row.quarantined).map_or(2, u64::from));
    crate::print_str(b"\n");
}

unsafe fn service_inline_irq_checkpoint(
    ch: &PumpChannel,
    route: PeerRoute,
) -> Result<(), runtime::Error> {
    let before = inline_irq_observation(ch, route);
    let Some(dispatch) = before.dispatch else {
        trace_inline_irq_checkpoint_failure(ch, InlineIrqCheckpointError::Preflight(
            InlineIrqCheckpointMismatch::Dispatch), route, None, before.reply, before);
        return Err(runtime::Error::PhysicalIdentity);
    };
    let Some(reply) = before.reply else {
        trace_inline_irq_checkpoint_failure(ch, InlineIrqCheckpointError::Preflight(
            InlineIrqCheckpointMismatch::Reply), route, Some(dispatch), None, before);
        return Err(runtime::Error::PhysicalIdentity);
    };
    let mut checkpoint = match InlineIrqCheckpoint::begin(route, dispatch, reply, before) {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            trace_inline_irq_checkpoint_failure(ch, error, route, Some(dispatch), Some(reply), before);
            return Err(runtime::Error::PhysicalIdentity);
        }
    };
    // The ticket preserves whether this entry had a parent. In the idle case
    // service_irq_yield parks nothing and must return the same idle receiver.
    let scope = crate::driver_launch::ComponentSchedulerScope::enter();
    scope.service_irq_yield(ch.shared_va);
    let after = inline_irq_observation(ch, route);
    if let Err(error) = checkpoint.verify_after(after) {
        trace_inline_irq_checkpoint_failure(ch, error, route, Some(dispatch), Some(reply), after);
        return Err(runtime::Error::PhysicalIdentity);
    }
    Ok(())
}

/// A physical IRQ bit is independent of the ordinary request kind and kernel-yield capability.
unsafe fn inline_irq_work_pending() -> bool {
    crate::driver_launch::hosted_irq_work_pending()
        || crate::driver_launch::hosted_driver_dpc_activation_pending()
        || crate::dispatcher_bootstrap::timer_work_pending()
}

unsafe fn nested_restore_refusal(
    ticket: Option<runtime::nested::NestedRestoreTicket>,
) -> PumpMessage {
    let Some(ticket) = ticket else { return PumpMessage::transport_wall(); };
    if runtime::nested::pending_ticket(ticket) {
        PumpMessage::nested_restore_yield(ticket)
    } else {
        // The owner keeps an uncertain physical release fenced. It must never be retried or
        // converted into an ordinary wall that panics the root pump.
        PumpMessage::nested_restore_quarantined(ticket)
    }
}

pub(super) unsafe fn receive(
    ch: &PumpChannel, route: PeerRoute, retained_seh: bool, serviced_scheduler_yield: bool,
) -> PumpMessage {
    let census_scope = ReceiveCensusScope::enter(ch, route, retained_seh);
    // A retained exception walk and an ordinary syscall channel without kernel IRQ yield cannot
    // return a scheduler continuation. Give already-latched work one isolated pass here instead.
    let inline_irq_checkpoint =
        retained_seh || (ch.caps.kind == ReqKind::Syscall && !ch.caps.kernel_irq_yield);
    let mut irq_checkpoint = inline_irq_checkpoint && inline_irq_work_pending();
    let mut timer_probe_consumed = false;
    loop {
        record_active_syscall_transition(&census_scope, SYSCALL_PHASE_PUMP_WORK);
        trace_ps_create_receive(ch, b"loop", Some(route));
        if !retained_seh {
            let _stage = StageScope::enter(ch, Stage::YieldPreflight);
            match crate::win32k_glue::prepare_receive_yield(ch) {
                Ok(Some(yielded)) => {
                    trace_ps_create_receive(ch, b"receive-yield", Some(route));
                    return PumpMessage::hosted_receive_yield(yielded);
                }
                Ok(None) => {}
                Err(error) => {
                    crate::print_str(b"[receive-yield-failure] propagated-error=");
                    crate::print_str(match error {
                        runtime::Error::PhysicalIdentity => b"physical",
                        runtime::Error::Admission => b"admission",
                        runtime::Error::Capacity => b"capacity",
                        runtime::Error::Receive => b"receive",
                        _ => b"other",
                    });
                    crate::print_str(b"\n");
                    panic!("receive-yield preparation retains exact ingress ownership");
                }
            }
            match crate::win32k_glue::prepare_service_wait_yield(ch) {
                Ok(Some(yielded)) => {
                    trace_ps_create_receive(ch, b"service-wait-yield", Some(route));
                    return PumpMessage::hosted_service_wait_yield(yielded);
                }
                Ok(None) => {}
                Err(_) => panic!("service-wait yield lost its exact physical ownership"),
            }
            match crate::win32k_glue::prepare_root_maintenance_yield(ch) {
                Ok(Some(yielded)) => {
                    trace_ps_create_receive(ch, b"root-maintenance-yield", Some(route));
                    return PumpMessage::hosted_root_maintenance_yield(yielded);
                }
                Ok(None) => {}
                // Maintenance is optional independent work. No native effects have entered at
                // this preflight, so a refused checkpoint leaves the current Receive intact.
                Err(_) => trace_ps_create_receive(ch, b"root-maintenance-refused", Some(route)),
            }
        }
        // A native SYSTEM fold may finish its second physical slot while this IRP Receive
        // retains the parent Call. Release its exact CM checkpoint and reserve before a
        // dependent registry writer retries; the generic outer finalizer cannot run here.
        let wal_ack_pending = {
            let _stage = StageScope::enter(ch, Stage::WalAckReady);
            crate::writable_fs::system_wal_fold_ack_pending()
        };
        if wal_ack_pending {
            let _stage = StageScope::enter(ch, Stage::NestedWork);
            let mut parent = match runtime::nested::park_current() {
                Ok(parent) => parent,
                Err(_) => return PumpMessage::transport_wall(),
            };
            let progressed = crate::writable_fs::redrive_retained_system_wal_fold_after_native_completion();
            let ticket = parent.as_ref().map(|parent| parent.ticket());
            if runtime::nested::restore_or_retain(&mut parent).is_err() {
                return nested_restore_refusal(ticket);
            }
            if progressed { continue; }
        }
        // Timer delivery only records a due fold while the outer service loop is retained.
        // Enter CM and native snapshot I/O here with the exact Receive parent parked; the
        // cadence gate prevents a recursive CM call from admitting the same fold again.
        let wal_fold_pending = {
            let _stage = StageScope::enter(ch, Stage::WalFoldReady);
            crate::service_sec_image::system_wal_fold_work_pending()
        };
        if wal_fold_pending {
            let _stage = StageScope::enter(ch, Stage::NestedWork);
            trace_ps_create_event(b"fold-enter", route, 0, 0);
            let mut parent = match runtime::nested::park_current() {
                Ok(parent) => parent,
                Err(_) => return PumpMessage::transport_wall(),
            };
            let result = crate::service_sec_image::service_due_system_wal_fold();
            trace_ps_create_event(b"fold-service-return", route, 0, 0);
            let ticket = parent.as_ref().map(|parent| parent.ticket());
            if runtime::nested::restore_or_retain(&mut parent).is_err() {
                return nested_restore_refusal(ticket);
            }
            trace_ps_create_event(b"fold-restore-return", route, 0, 0);
            match result {
                Ok(true) => continue,
                Ok(false) => {},
                Err(_) => return PumpMessage::transport_wall(),
            }
        }
        let registry_stage = StageScope::enter(ch, Stage::Registry);
        let progressed = crate::registry_mutation_work::redrive_provider();
        drop(registry_stage);
        // A retained CM mutation can use all sixteen steps and still have a local terminal
        // phase to run. Take another fair, bounded pass before entering a blocking Receive.
        // A stalled or ineligible owner returns false, so it cannot spin this pump.
        if progressed && crate::registry_mutation_work::wake_due(crate::monotonic_time_100ns()) != 0 {
            continue;
        }
        let header_recheck = {
            let _stage = StageScope::enter(ch, Stage::RegistryHeaderReady);
            crate::registry_mutation_work::pending_provider_header_recheck()
        };
        if let Some(id) = header_recheck {
            let _stage = StageScope::enter(ch, Stage::NestedWork);
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            let mut parent = match runtime::nested::park_current() {
                Ok(parent) => parent,
                Err(_) => return PumpMessage::transport_wall(),
            };
            let serviced = crate::driver_launch::service_mounted_native_registry_recheck(id);
            let ticket = parent.as_ref().map(|parent| parent.ticket());
            if runtime::nested::restore_or_retain(&mut parent).is_err() {
                return nested_restore_refusal(ticket);
            }
            if serviced != 0 { continue; }
        }
        let registry_wal = {
            let _stage = StageScope::enter(ch, Stage::RegistryWalReady);
            crate::registry_mutation_work::pending_provider_native_wal_io()
        };
        if let Some(id) = registry_wal {
            let _stage = StageScope::enter(ch, Stage::NestedWork);
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            let mut parent = match runtime::nested::park_current() {
                Ok(parent) => parent,
                Err(_) => return PumpMessage::transport_wall(),
            };
            let serviced = crate::driver_launch::service_mounted_native_registry_wal(id);
            let ticket = parent.as_ref().map(|parent| parent.ticket());
            if runtime::nested::restore_or_retain(&mut parent).is_err() {
                return nested_restore_refusal(ticket);
            }
            if serviced != 0 { continue; }
        }
        let nested_file_ready = {
            let _stage = StageScope::enter(ch, Stage::NestedFileReady);
            crate::service_sec_image::nested_hosted_file_work_ready()
        };
        if nested_file_ready {
            let _stage = StageScope::enter(ch, Stage::NestedWork);
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            let mut parent = match runtime::nested::park_current() {
                Ok(parent) => parent,
                Err(_) => return PumpMessage::transport_wall(),
            };
            let progressed = crate::service_sec_image::redrive_nested_hosted_file_work();
            let ticket = parent.as_ref().map(|parent| parent.ticket());
            if runtime::nested::restore_or_retain(&mut parent).is_err() {
                return nested_restore_refusal(ticket);
            }
            if progressed { continue; }
        }
        trace_ps_create_receive(ch, b"retained-services", Some(route));
        let retained = {
            let _stage = StageScope::enter(ch, Stage::RetainedService);
            runtime::resume_acknowledged_retained_services()
        };
        match retained {
            Ok(true) => continue,
            Ok(false) => {}
            Err(_) => {
                crate::print_str(b"[pump-ingress] retained-service resume failed\n");
                return PumpMessage::transport_wall();
            }
        }
        trace_ps_create_receive(ch, b"resume-service", Some(route));
        let resumed = {
            let _stage = StageScope::enter(ch, Stage::RouteResume);
            runtime::resume_service(route)
        };
        if resumed.is_err() {
            crate::print_str(b"[pump-ingress] route resume failed\n");
            return PumpMessage::transport_wall();
        }
        trace_ps_create_receive(ch, b"route-next", Some(route));
        let next_result = {
            let _stage = StageScope::enter(ch, Stage::NextMessage);
            runtime::next_message(route)
        };
        let next = match next_result {
            Ok(next) => next,
            Err(_) => {
                crate::print_str(b"[pump-ingress] next-message failed\n");
                return PumpMessage::transport_wall();
            }
        };
        if let Some((reply, message)) = next {
            if PS_CREATE_RECEIVE_TRACE.load(Ordering::Relaxed) != 0 {
                PS_CREATE_LAST_PARENT_INFO.store(message.info(), Ordering::Relaxed);
                PS_CREATE_LAST_PARENT_OP.store(message.word(0).unwrap_or(0), Ordering::Relaxed);
                PS_CREATE_PARENT_MESSAGES.fetch_add(1, Ordering::Relaxed);
            }
            trace_ps_create_event(b"parent-message", route, reply, message.info());
            let completion = message.info() >> 12 == ch.dispatch_label;
            {
                let _stage = StageScope::enter(ch, Stage::CallAdoption);
                if !completion && runtime::adopt(route, reply).is_err() {
                    crate::print_str(b"[pump-ingress] Call adoption failed\n");
                    return PumpMessage::transport_wall();
                }
            }
            let mut message = PumpMessage::from_received(message);
            if !completion {
                message.shared_reply = Some(reply);
            }
            return message;
        }
        // The registry journal has moved the mounted volume into its own transaction.
        // Leave autonomous Calls in the retained receiver until that owner releases it.
        if !crate::writable_fs::registry_journal::owns_volume() {
            trace_ps_create_receive(ch, b"autonomous-select", Some(route));
            if PS_CREATE_AFTER_AUTONOMOUS_TRACE.load(Ordering::Relaxed) != 0 {
                let selected = PS_CREATE_AFTER_AUTONOMOUS_SELECT.fetch_add(1, Ordering::Relaxed) + 1;
                if selected <= 8 || selected.is_power_of_two() {
                    runtime::trace_autonomous_candidates();
                }
            }
            let autonomous = {
                let _stage = StageScope::enter(ch, Stage::AutonomousSelect);
                runtime::next_autonomous()
            };
            match autonomous {
                Ok(Some(sender)) => {
                    if crate::driver_launch::file_rpc_pump_for_diagnostic(ch) {
                        FILE_RECEIVE_AUTONOMOUS.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Ok(Some((reply, info))) = runtime::pending_route_snapshot(sender) {
                        trace_ps_create_event(b"autonomous-message", sender, reply, info);
                    }
                    trace_ps_create_receive(ch, b"autonomous-found", Some(sender));
                    {
                        let _stage = StageScope::enter(ch, Stage::AutonomousService);
                        service_autonomous(sender)
                            .expect("autonomous failure retains its own source and parent scope");
                    }
                    trace_ps_create_event(b"autonomous-return", sender, 0, 0);
                    trace_ps_create_receive(ch, b"autonomous-return", Some(sender));
                    PS_CREATE_AFTER_AUTONOMOUS_TRACE.store(1, Ordering::Relaxed);
                    PS_CREATE_AFTER_AUTONOMOUS_SELECT.store(0, Ordering::Relaxed);
                    continue;
                }
                Ok(None) => {}
                Err(_) => {
                    crate::print_str(b"[pump-ingress] autonomous selection failed\n");
                    return PumpMessage::transport_wall();
                }
            }
        }
        let timer_irq_stage = StageScope::enter(ch, Stage::TimerIrqPreflight);
        let timer_checkpoint = !retained_seh
            && (ch.caps.kind == ReqKind::Irp || ch.caps.kernel_irq_yield)
            && crate::dispatcher_bootstrap::timer_work_pending();
        if timer_checkpoint && timer_probe_consumed {
            if crate::driver_launch::file_rpc_pump_for_diagnostic(ch) {
                FILE_RECEIVE_SCHEDULER_YIELD.fetch_add(1, Ordering::Relaxed);
            }
            trace_ps_create_receive(ch, b"timer-yield", Some(route));
            return PumpMessage::scheduler_yield();
        }
        // A pending timer still gets its scheduler pass, but first give a newly arrived Call
        // one nonblocking physical receive through the exact retained ingress owner. Otherwise
        // continuously republished timer demand can starve a worker's READY Call forever.
        timer_probe_consumed = timer_checkpoint;
        if inline_irq_checkpoint && irq_checkpoint {
            if service_inline_irq_checkpoint(ch, route).is_err() {
                crate::print_str(b"[pump-ingress] inline IRQ checkpoint lost its route\n");
                return PumpMessage::transport_wall();
            }
            // Deferred IRQ bits may remain set. This pass belongs to the observed arrival only;
            // inspect new Calls before waiting, then await another notification to retry.
            irq_checkpoint = false;
            continue;
        }
        drop(timer_irq_stage);
        let owner_result = {
            let _stage = StageScope::enter(ch, Stage::ReceiveOwner);
            runtime::receive_owner(route)
        };
        let execution = match owner_result {
            Ok(execution) => execution,
            Err(_) => {
                crate::print_str(b"[pump-ingress] receive owner failed\n");
                return PumpMessage::transport_wall();
            }
        };
        trace_ps_create_receive(ch, b"physical-receive", Some(route));
        let file_receive = crate::driver_launch::file_rpc_pump_for_diagnostic(ch);
        let receive_started = if file_receive { crate::disk_census_ticks() } else { 0 };
        record_active_syscall_physical_owner(&census_scope, route, ch.tcb);
        record_active_syscall_transition(&census_scope, SYSCALL_PHASE_PHYSICAL_WAIT);
        let arrival = runtime::receive(execution, ch.tcb,
            serviced_scheduler_yield || !timer_checkpoint);
        if file_receive {
            FILE_RECEIVE_CALLS.fetch_add(1, Ordering::Relaxed);
            FILE_RECEIVE_TICKS.fetch_add(
                crate::disk_census_ticks().wrapping_sub(receive_started), Ordering::Relaxed);
            let counter = match &arrival {
                Ok(runtime::Arrival::Hosted) => &FILE_RECEIVE_HOSTED,
                Ok(runtime::Arrival::Call { .. }) => &FILE_RECEIVE_CALL,
                Ok(runtime::Arrival::Notification(message))
                    if crate::badge_has_delay_timer(message.badge()) => &FILE_RECEIVE_TIMER,
                Ok(runtime::Arrival::Notification(_)) => &FILE_RECEIVE_OTHER_NOTIFICATION,
                Err(_) => &FILE_RECEIVE_ERROR,
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
        match arrival {
            Ok(runtime::Arrival::Hosted) => {
                record_active_syscall_transition(&census_scope, SYSCALL_PHASE_HOSTED);
                record_active_syscall_provider_arrival(&census_scope);
                trace_ps_create_receive(ch, b"hosted-arrival", Some(route));
                trace_ps_create_event(b"hosted-arrival", route, 0, 0);
            }
            Ok(runtime::Arrival::Call { route: sender, reply }) => {
                record_active_syscall_transition(&census_scope, SYSCALL_PHASE_CALL);
                record_active_syscall_provider_arrival(&census_scope);
                trace_ps_create_receive(ch, b"call-arrival", Some(sender));
                trace_ps_create_event(b"call-arrival", sender, reply, 0);
                // The coordinator retains unrelated Calls for their exact source. Inspect only
                // this invocation's stored arrival on the next pass.
            }
            Ok(runtime::Arrival::Notification(message)) => {
                record_active_syscall_transition(&census_scope, SYSCALL_PHASE_NOTIFICATION);
                trace_ps_create_receive(ch, b"notification", Some(route));
                // The shared ingress has already proven NoCall with a free Reply. An empty
                // nonblocking probe has no sender and must not count as watchdog progress.
                if timer_checkpoint && message.badge() == 0 && message.info() == 0 {
                    if file_receive {
                        FILE_RECEIVE_SCHEDULER_YIELD.fetch_add(1, Ordering::Relaxed);
                    }
                    return PumpMessage::scheduler_yield();
                }
                {
                    let _stage = StageScope::enter(ch, Stage::CensusTick);
                    crate::census_tick_static(crate::monotonic_time_100ns());
                }
                let (event, _, irq) = {
                    let _stage = StageScope::enter(ch, Stage::EventBadge);
                    pump_handle_executive_event_badge(message.badge())
                };
                if irq {
                    match ch.caps.kind {
                        ReqKind::Irp => { IRQ_IRP_RECEIVES.fetch_add(1, Ordering::Relaxed); }
                        ReqKind::Syscall => { IRQ_SYSCALL_RECEIVES.fetch_add(1, Ordering::Relaxed); }
                    }
                    if retained_seh {
                        IRQ_RETAINED_SEH_RECEIVES.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if !event {
                    continue;
                }
                if pump_deadman_tripped() {
                    return PumpMessage::deadman_wall();
                }
                if inline_irq_checkpoint && (irq || inline_irq_work_pending()) {
                    irq_checkpoint = true;
                }
                if !inline_irq_checkpoint && pump_scheduler_work_pending(ch, irq) {
                    if file_receive {
                        FILE_RECEIVE_SCHEDULER_YIELD.fetch_add(1, Ordering::Relaxed);
                    }
                    trace_ps_create_receive(ch, b"scheduler-yield", Some(route));
                    return PumpMessage::scheduler_yield();
                }
            }
            Err(_) => {
                crate::print_str(b"[pump-ingress] physical receive failed\n");
                return PumpMessage::transport_wall();
            }
        }
    }
}

pub(super) unsafe fn autonomous(ch: &PumpChannel) -> bool {
    matches!(runtime::channel_route(ch).and_then(|route| route.ok_or(runtime::Error::UnknownPeer))
        .and_then(|route| runtime::physical_source(route)),
        Ok(source) if matches!(source.kind, runtime::PhysicalSourceKind::SystemThread { .. }))
}

/// Persistent dispatch workers retain their invocation across a service wait; unlike autonomous
/// threads, the service ACK cannot finish their enclosing dispatch.
pub(super) unsafe fn service_wait_yields(ch: &PumpChannel) -> bool {
    if autonomous(ch) { return true; }
    if ch.caps.kind != ReqKind::Irp { return false; }
    // The class HOOK worker runs inside an earlier AddDevice/CONNECT pump. Keep receiving on
    // this exact worker while its lower source is redriven; returning a provider-wait slice to
    // ordinary IRP dispatch would misclassify the live continuation as a transport wall.
    if crate::driver_launch::hosted_class_irp_lane::is_channel(ch) { return false; }
    // The exact class source has already parked its CONNECT Call. Its retained owner must
    // redrive the port provider before this receiver can deliver the first service Reply.
    if crate::driver_launch::parked_hosted_connect_source_channel(ch) { return false; }
    matches!(runtime::channel_route(ch).and_then(|route| route.ok_or(runtime::Error::UnknownPeer))
        .and_then(|route| runtime::physical_source(route)),
        Ok(source) if matches!(source.domain, runtime::PhysicalDomain::Hosted(_))
            && matches!(source.kind, runtime::PhysicalSourceKind::DispatchWorker { .. }))
}

pub(super) unsafe fn service_autonomous(route: PeerRoute) -> Result<(), runtime::Error> {
    let mut parent = runtime::nested::park_current()?;
    let serviced = (|| {
        runtime::resume_service(route)?;
        runtime::admit(route)?;
        let channel = crate::driver_launch::autonomous_pump_channel(route)
            .ok_or(runtime::Error::PhysicalIdentity)?;
        let message = runtime::stored_current_message(route)?;
        let mut reply = channel.reply_cap;
        let mut seh = hosted_seh_pump::SehLease::claim(&channel, reply, true)
            .ok_or(runtime::Error::PhysicalIdentity)?;
        let outcome = component_pump_loop(
            &channel,
            PumpMessage::from_received(message),
            &mut reply,
            nt_user_host::component_pump::ComponentPumpAccounting::new(false),
            &mut seh.pump,
        );
        let suspended = outcome.callback_suspended
            || outcome.provider_wait_suspended
            || outcome.lpc_wait_suspended;
        trace_ps_create_event(b"autonomous-pump-exit", route, reply, u64::from(suspended) << 12);
        let seh_finished = seh.finish(&channel, reply, suspended);
        trace_ps_create_event(b"autonomous-seh-finish", route, reply, u64::from(seh_finished) << 12);
        if !seh_finished {
            return Err(runtime::Error::PhysicalIdentity);
        }
        // An autonomous thread does not speak the dispatch-worker completion protocol. Only
        // the acknowledged service Reply can complete its invocation and return this lane idle.
        if outcome.completed
            && crate::service_sec_image::component_execution_lane_is_idle(route.identity().lane)
            || outcome.provider_wait_suspended
        {
            Ok(())
        } else {
            pump_wall_state_diag(&channel, outcome);
            Err(runtime::Error::Protocol)
        }
    })();
    trace_ps_create_event(b"autonomous-serviced", route, 0, u64::from(serviced.is_ok()) << 12);
    if serviced.is_err() {
        autonomous_failure_diag(route, b"terminate/drain");
        if !crate::driver_launch::terminate_failed_autonomous_service(route) {
            autonomous_failure_diag(route, b"uncertain; parent retained");
            return Err(runtime::Error::Retirement);
        }
    }
    trace_ps_create_event(b"autonomous-restore-enter", route, 0, 0);
    if let Err(error) = runtime::nested::restore(&mut parent) {
        autonomous_failure_diag(route, b"parent restoration retained");
        return Err(error);
    }
    trace_ps_create_event(b"autonomous-restore-return", route, 0, 0);
    Ok(())
}

unsafe fn autonomous_failure_diag(route: PeerRoute, stage: &[u8]) {
    crate::print_str(b"[autonomous-ingress] ");
    crate::print_str(stage);
    crate::print_str(b" badge=");
    crate::print_u64(route.badge());
    crate::print_str(b" tcb=");
    crate::print_u64(route.identity().executor);
    crate::print_str(b"\n");
}

pub(super) unsafe fn reply(ch: &PumpChannel, reply: u64, info: u64, words: [u64; 4]) -> bool {
    reply_with_info(ch, reply, info, words, false)
}

pub(super) unsafe fn reply_seh(ch: &PumpChannel, reply: u64, info: u64, words: [u64; 4]) -> bool {
    if nt_unwind::seh_transport::SehCommand::parse(info, words).is_none() {
        crate::print_str(b"[fsd-seh] malformed command reply\n");
        PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    reply_with_info(ch, reply, info, words, true)
}

unsafe fn reply_with_info(ch: &PumpChannel, reply: u64, info: u64, words: [u64; 4], labeled: bool) -> bool {
    // Capture the entire IPC bank before any
    // binding probe can overwrite MR4+, then pass an owned payload to the retained reply owner.
    if info & 0xf80 != 0 || (info >> 12 != 0 && !labeled) || (info & 0x7f) > 120 {
        if labeled { crate::print_str(b"[fsd-seh] reply info refused\n"); }
        PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let captured = crate::ipc_message::capture_received(0, info, words);
    let len = (info & 0x7f) as usize;
    let mut payload = [0u64; 120];
    for (index, word) in payload[..len].iter_mut().enumerate() {
        *word = captured.word(index).expect("validated Reply length");
    }
    match runtime::channel_route(ch) {
        Ok(Some(route)) => {
            let result = runtime::reply_with_info(route, reply, info, &payload[..len]);
            if labeled && result.is_err() { crate::print_str(b"[fsd-seh] retained reply refused\n"); }
            result.is_ok()
        }
        Ok(None) | Err(_) => {
            if labeled { crate::print_str(b"[fsd-seh] reply route refused\n"); }
            PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

pub(super) unsafe fn authenticated_badge(ch: &PumpChannel, badge: u64) -> bool {
    matches!(runtime::channel_route(ch), Ok(Some(route)) if route.badge() == badge)
}
