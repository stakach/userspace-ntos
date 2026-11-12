//! Wait-preserving physical exclusion while another component owns root dispatch.

use super::*;
#[path = "component_ingress_nested_source_ioctl.rs"]
mod source_ioctl;
pub(crate) use source_ioctl::{
    drain_source_ioctl_parent, park_resuming_source_ioctl,
    redrive_selected_source_ioctl_terminal, requeue_no_effect_source_ioctl,
    restore_settled_source_ioctl_parent, source_ioctl_child_blocks_fresh_dispatch,
    source_ioctl_parent_retained, source_ioctl_parent_blocks_provider_resume,
    source_ioctl_parent_ready,
    register_selected_source_ioctl_dispatch, finish_selected_source_ioctl_dispatch,
    quarantine_refused_source_ioctl, trace_source_ioctl_parent_for_work,
};
use crate::{win32k_glue, win32k_subsystem};
use super::physical_hold::PhysicalExecutionHold;
use nt_component_suspension::{ExternalAdmissionKey, NestedExecutionIdentity, NestedExecutionScope};
use nt_user_host::physical_execution_restore::RestoreStep;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use nt_time::CoalescedRetryWake;
use nt_component_suspension::{next_ready_pending_lane, PendingLaneReadiness};
use nt_component_suspension::NestedPreEntryCheckpoint;
use nt_component_suspension::NestedPreEntryParentParkReceipt;
use nt_component_suspension::NestedPreEntryParentRestoreReceipt;
use nt_component_suspension::NestedPreEntryPhase;

const ABORT_RETRY_100NS: u64 = 1_600_000;
static ABORT_WAKE: CoalescedRetryWake = CoalescedRetryWake::new();
static LAST_ABORT: AtomicUsize = AtomicUsize::new(usize::MAX);

// Temporary read-only evidence for a source Work that arrives while its exact Win32k
// provider frame is Resuming. One slot per physical lane prevents unrelated provider
// activity from evicting this resume before the source terminal is sampled.
#[derive(Clone, Copy)]
struct SourceResumeTrace {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    key: u64,
    owner: u64,
    stages: [u64; 5], // begin, pump enter, pump return, no child, first source Work
}

const SOURCE_RESUME_TRACE_CAP: usize = 256;
static SOURCE_RESUME_TRACE_NEXT: AtomicU64 = AtomicU64::new(0);
static mut SOURCE_RESUME_TRACES: [Option<SourceResumeTrace>; SOURCE_RESUME_TRACE_CAP] =
    [None; SOURCE_RESUME_TRACE_CAP];

pub(crate) unsafe fn record_source_resume_transition(
    stage: u64, lane: nt_component_suspension::LaneHandle,
    dispatch: LaneDispatchIdentity, reply: u64,
    key: nt_component_suspension::SuspensionKey, owner: nt_component_suspension::SuspensionOwner,
) {
    if !(1..=4).contains(&stage) { return }
    if dispatch.lane() != lane { return }
    let Some(route) = lanes().peer_route(lane).ok().flatten() else { return };
    let index = lane.index as usize;
    if index >= SOURCE_RESUME_TRACE_CAP { return }
    let slot = core::ptr::addr_of_mut!(SOURCE_RESUME_TRACES)
        .cast::<Option<SourceResumeTrace>>().add(index);
    let previous = slot.read();
    let same = previous.is_some_and(|entry| entry.route == route
        && entry.dispatch == dispatch && entry.reply == reply
        && entry.key == key.id && entry.owner == owner.dispatch_id);
    let mut record = match previous {
        Some(entry) if stage != 1 && same => entry,
        _ => SourceResumeTrace {
            route, dispatch, reply, key: key.id, owner: owner.dispatch_id, stages: [0; 5],
        },
    };
    record.stages[(stage - 1) as usize] = SOURCE_RESUME_TRACE_NEXT
        .fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    slot.write(Some(record));
}

unsafe fn trace_first_exact_resuming_source_work(
    work_route: PeerRoute, work_dispatch: LaneDispatchIdentity, work_reply: u64,
) {
    let exact = lanes().frames().find_map(|(lane, frame)| {
        let matching = lanes().peer_route(lane).ok().flatten() == Some(work_route)
            && lanes().active_dispatch_identity(lane).ok().flatten() == Some(work_dispatch)
            && lanes().binding(lane).ok().map(|binding| binding.reply_object) == Some(work_reply)
            && matches!(frame.phase, nt_component_suspension::SuspensionPhase::Resuming { .. });
        matching.then_some((lane, frame.key, frame.owner))
    });
    let Some((lane, key, owner)) = exact else { return };
    let index = lane.index as usize;
    let slot = (index < SOURCE_RESUME_TRACE_CAP).then(|| core::ptr::addr_of_mut!(SOURCE_RESUME_TRACES)
        .cast::<Option<SourceResumeTrace>>().add(index));
    let previous = slot.and_then(|slot| slot.read());
    let same = previous.is_some_and(|entry| entry.route == work_route
        && entry.dispatch == work_dispatch && entry.reply == work_reply
        && entry.key == key.id && entry.owner == owner.dispatch_id);
    let mut record = match previous {
        Some(entry) if same => entry,
        _ => SourceResumeTrace {
            route: work_route, dispatch: work_dispatch, reply: work_reply,
            key: key.id, owner: owner.dispatch_id, stages: [0; 5],
        },
    };
    if record.stages[4] != 0 { return }
    record.stages[4] = SOURCE_RESUME_TRACE_NEXT.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if let Some(slot) = slot { slot.write(Some(record)); }
    crate::print_str(b"[source-resume-history] lane/gen/epoch/reply/key/owner/begin/pump-enter/pump-return/no-child/first-work/begin-missing=");
    for value in [u64::from(lane.index), lane.generation, work_dispatch.epoch(),
        work_reply, key.id, owner.dispatch_id, record.stages[0], record.stages[1],
        record.stages[2], record.stages[3], record.stages[4],
        u64::from(record.stages[0] == 0)] {
        crate::print_str(b"/"); crate::print_hex_u64(value);
    }
    crate::print_str(b"\n");
}

/// The slot is storage, not authority. A recycled slot cannot restore a different parent scope.
#[must_use = "retain the exact parked parent until restoration acknowledges"]
pub(crate) struct ParkedParentHandle {
    index: usize,
    generation: u64,
    identity: NestedExecutionIdentity,
}

/// Issued only after the exact retained parent has completed every physical restore stage.
/// Consuming this receipt admits one receive continuation; a selector alone cannot do so.
#[must_use = "consume when resuming the exact nested child-work receive"]
pub(crate) struct ChildWorkParentRestored {
    ticket: NestedRestoreTicket,
}

impl ChildWorkParentRestored {
    pub(crate) fn ticket(&self) -> NestedRestoreTicket { self.ticket }
}

/// Issued only when this park attempt made no physical change, or its abort fully acknowledged.
/// It names the exact prepared child and cannot be constructed outside this owner module.
#[must_use = "consume only while cancelling the matching unbound root ingress pass"]
pub(crate) struct NoEffectParkProof {
    admission: ExternalAdmissionKey,
}

/// A real parent park was physically restored before its selected child was delivered.
/// This move-only receipt authorizes only cancellation of the exact untouched child Call.
#[must_use = "retain until the matching undelivered child pass is cancelled"]
pub(crate) struct RestoredBeforeChildProof {
    parent: NestedExecutionIdentity,
    token: nt_user_host::root_ingress_pass::UndeliveredRootIngress<crate::HostedThreadRole>,
}

impl RestoredBeforeChildProof {
    pub(crate) fn parent(&self) -> NestedExecutionIdentity { self.parent }
    pub(crate) fn admission_key(&self) -> ExternalAdmissionKey { self.token.admission_key() }
    pub(crate) fn child(&self) -> nt_user_host::thread_binding::ThreadBinding<crate::HostedThreadRole> {
        self.token.child()
    }
    pub(crate) fn token(&self) -> &nt_user_host::root_ingress_pass::UndeliveredRootIngress<crate::HostedThreadRole> {
        &self.token
    }
}

impl NoEffectParkProof {
    pub(crate) fn admission_key(&self) -> ExternalAdmissionKey { self.admission }
}

pub(crate) enum RootParkOutcome {
    NoRunningLane(NoEffectParkProof),
    Parked(ParkedParentHandle),
    RefusedNoEffect(Error, NoEffectParkProof),
    Retained(Error),
}

enum ParkAttemptOutcome {
    NoRunningLane(Option<SourceIoctlParent>),
    Parked(ParkedParentHandle),
    RefusedNoEffect(Error, Option<SourceIoctlParent>),
    Retained(Error),
}

pub(crate) enum SourceIoctlPark {
    NoChild,
    Parked(ParkedParentHandle),
    /// Certified no physical effect; the exact selection and page remain owned here.
    RefusedNoEffect(SourceIoctlParent),
    RequeuedNoEffect,
    Retained,
}

/// A copyable lookup key for a retained restore. The row still owns every physical effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NestedRestoreTicket {
    index: usize,
    generation: u64,
    identity: NestedExecutionIdentity,
}

impl NestedRestoreTicket {
    /// A selector value for an outer continuation; only the retained row can authenticate it.
    pub(crate) const fn identity(self) -> NestedExecutionIdentity { self.identity }
}

impl ParkedParentHandle {
    pub(crate) fn identity(&self) -> NestedExecutionIdentity {
        self.identity
    }

    pub(crate) fn ticket(&self) -> NestedRestoreTicket {
        NestedRestoreTicket {
            index: self.index,
            generation: self.generation,
            identity: self.identity,
        }
    }
}

/// Capture the exact semantic result key while the physical parent row still owns the Reply.
/// This is observational; the caller must retain the result until restore acknowledges.
pub(crate) unsafe fn result_key(
    handle: &ParkedParentHandle,
) -> Option<nt_component_suspension::NestedRestoreResultKey> {
    let parent = (&*core::ptr::addr_of!(PARENTS))
        .get(handle.index)?.as_ref()?;
    if !row_matches(handle, parent) || parent.reply == 0 {
        return None;
    }
    nt_component_suspension::NestedRestoreResultKey::new(handle.identity, parent.reply)
}

/// Memory-only access: callers must not enter IPC or retain a reference from this closure.
pub(crate) unsafe fn with_receive_scope<T>(
    handle: &ParkedParentHandle,
    use_scope: impl FnOnce(&NestedExecutionScope) -> Result<T, Error>,
) -> Result<T, Error> {
    let parent = (&*core::ptr::addr_of!(PARENTS))
        .get(handle.index)
        .and_then(Option::as_ref)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !parent.physical.canonical_pending() {
        return Err(Error::Admission);
    }
    use_scope(scope)
}

struct Parent {
    generation: u64,
    root_admission: Option<ExternalAdmissionKey>,
    route: PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    /// The physical lane Reply observed before acquisition and sealed into the nested scope.
    reply: u64,
    phase: ParentPhase,
    physical: PhysicalExecutionHold,
    scope: Option<NestedExecutionScope>,
    child: Option<ParentChild>,
    receive_restore:
        Option<nt_user_host::receive_child_barrier::ReceiveRestorePermit<crate::HostedThreadRole>>,
    root_ingress_restore:
        Option<nt_user_host::root_ingress_pass::RootIngressRestorePermit<crate::HostedThreadRole>>,
    root_lane_begun: bool,
    undelivered_root:
        Option<nt_user_host::root_ingress_pass::UndeliveredRootIngress<crate::HostedThreadRole>>,
    source_ioctl: Option<SourceIoctlParent>,
}

/// Retained with the physical Reply before a source terminal may borrow the singleton page.
/// The selection is move-only; a packet address or recycled Work index cannot stand for it.
pub(crate) struct SourceIoctlParent {
    key: crate::driver_launch::NestedIoctlKey,
    checkpoint: NestedPreEntryCheckpoint<crate::driver_launch::NestedIoctlKey>,
    selection: Option<crate::driver_launch::NestedIoctlSelection>,
    shared_resume: win32k_glue::SharedResumeSnapshot,
    dispatch: nt_user_callback::DispatchContext,
    client: win32k_glue::Win32kClientContext,
    shared_leases: nt_user_callback::SharedPageLeaseStack<2>,
    child_dispatch: Option<u64>,
}

struct ParkedSourceIoctlPage(NestedExecutionIdentity);

// SAFETY: issued only after the retained Parent row owns the complete page snapshot, the
// exact Reply, a validated canonical nested scope, and an acknowledged physical hold.
unsafe impl NestedPreEntryParentParkReceipt for ParkedSourceIoctlPage {
    fn scope_identity(&self) -> NestedExecutionIdentity { self.0 }
}

struct RestoredSourceIoctlPage(NestedExecutionIdentity);

// SAFETY: issued only after the exact full page has been physically restored and its
// displaced lease acknowledged. A transport ACK alone never creates this receipt.
unsafe impl NestedPreEntryParentRestoreReceipt for RestoredSourceIoctlPage {
    fn scope_identity(&self) -> NestedExecutionIdentity { self.0 }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ParentPhase {
    /// The row exists before any physical effect. No scope has been created yet.
    Acquiring,
    Parked,
    /// The local handle may disappear after a refusal; this row remains discoverable.
    RestorePending,
    /// A serialized owner is inside the staged restore. A scanner must not enter it twice.
    RestoreAttempt,
    /// Scope admission refused after the physical hold acknowledged. The canonical lane is
    /// still Running; only the retained physical projection and hold need release.
    AbortPending,
    AbortAttempt,
    /// Native entry or identity is uncertain. Retain all resources, never replay an effect.
    Quarantined,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ParentChild {
    Receive,
    RootIngress,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RestoreOwner {
    Ordinary,
    RootIngress,
    UndeliveredRoot,
}

enum RestoreReceipt {
    Ordinary,
    RootIngress(nt_user_host::root_ingress_pass::RootIngressRestorePermit<crate::HostedThreadRole>),
    UndeliveredRoot(nt_user_host::root_ingress_pass::UndeliveredRootIngress<crate::HostedThreadRole>),
}

// Records are never removed before both canonical restoration and physical release acknowledge.
static mut PARENTS: Vec<Option<Parent>> = Vec::new();
static NEXT_PARENT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Observe whether an exact physical executor is still fenced by any retained parent row.
/// A failed child startup may retire its own route only after this parent hold is gone.
pub(crate) unsafe fn has_retained_parent_for_executor(executor: u64) -> bool {
    (&*core::ptr::addr_of!(PARENTS)).iter().flatten()
        .any(|parent| parent.route.identity().executor == executor)
}

/// Memory-only check for the physical parent of one retained ordinary root child. A failed
/// check leaves the caller responsible for treating the child as a provider-selection barrier.
pub(crate) unsafe fn root_ingress_parent_is_held(
    handle: &ParkedParentHandle,
    admission: ExternalAdmissionKey,
) -> bool {
    (&*core::ptr::addr_of!(PARENTS))
        .get(handle.index)
        .and_then(Option::as_ref)
        .is_some_and(|parent| {
            row_matches(handle, parent)
                && parent.root_admission == Some(admission)
                && parent.child == Some(ParentChild::RootIngress)
                && matches!(parent.phase,
                    ParentPhase::Parked | ParentPhase::RestorePending
                        | ParentPhase::RestoreAttempt | ParentPhase::Quarantined)
                && parent.physical.held()
        })
}

/// Recover only the exact parked, still-unbound parent selector after the pump returned to the
/// serialized root owner. No child admission or physical effect is performed by this lookup.
pub(crate) unsafe fn parked_unbound_root_parent(
    ticket: NestedRestoreTicket,
    admission: ExternalAdmissionKey,
) -> Option<ParkedParentHandle> {
    let parent = (&*core::ptr::addr_of!(PARENTS)).get(ticket.index)?.as_ref()?;
    if !ticket_matches(ticket, parent)
        || parent.root_admission != Some(admission)
        || parent.child.is_some()
        || parent.phase != ParentPhase::Parked
        || !parent.physical.held()
    {
        return None;
    }
    Some(ParkedParentHandle {
        index: ticket.index,
        generation: ticket.generation,
        identity: ticket.identity,
    })
}

fn row_matches(handle: &ParkedParentHandle, parent: &Parent) -> bool {
    ticket_matches(handle.ticket(), parent)
}

fn ticket_matches(ticket: NestedRestoreTicket, parent: &Parent) -> bool {
    parent.generation == ticket.generation
        && parent.scope.as_ref().map(NestedExecutionScope::identity) == Some(ticket.identity)
        && parent.route == ticket.identity.route()
        && parent.dispatch == ticket.identity.dispatch()
}

pub(crate) unsafe fn park_current() -> Result<Option<ParkedParentHandle>, Error> {
    match park_current_attempt(None, None) {
        ParkAttemptOutcome::NoRunningLane(_) => Ok(None),
        ParkAttemptOutcome::Parked(handle) => Ok(Some(handle)),
        ParkAttemptOutcome::RefusedNoEffect(error, _) | ParkAttemptOutcome::Retained(error) => {
            Err(error)
        }
    }
}

/// Bounded, read-only diagnosis for a source terminal that meets the shared-page fence.
pub(crate) unsafe fn trace_source_terminal_lane(
    work_route: PeerRoute, work_dispatch: LaneDispatchIdentity, work_reply: u64,
    packet: u64, terminal_ready: bool, nested_ready: bool,
) {
    static TRACES: AtomicU64 = AtomicU64::new(0);
    // Sample a sustained refusal as well as the first few. A short-lived earlier packet
    // must not exhaust the diagnosis before a later terminal reaches the actual wall.
    let sample = TRACES.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if !sample.is_power_of_two() { return; }
    trace_first_exact_resuming_source_work(work_route, work_dispatch, work_reply);
    let (running, route, phase, top_kind, top_id, top_phase, top_owner) = {
        let catalog = lanes();
        let running = catalog.running();
        let route = running.and_then(|lane| catalog.peer_route(lane).ok().flatten());
        let phase = running.and_then(|lane| catalog.phase(lane).ok());
        let top = running.and_then(|lane| catalog.top(lane).ok().flatten());
        let top_phase = top.map(|frame| match &frame.phase {
            nt_component_suspension::SuspensionPhase::Waiting => 1,
            nt_component_suspension::SuspensionPhase::Resuming { .. } => 2,
            nt_component_suspension::SuspensionPhase::ResumingChildParked { .. } => 3,
            nt_component_suspension::SuspensionPhase::ResumingChildQuarantined { .. } => 4,
            _ => 5,
        }).unwrap_or(0);
        (running, route, phase, top.map_or(0, |frame| frame.key.kind as u64),
            top.map_or(0, |frame| frame.key.id), top_phase,
            top.map_or(0, |frame| frame.owner.dispatch_id))
    };
    let current_dispatch = route.and_then(|route| dispatch(route).ok());
    let current_reply = route.and_then(|route| current_reply(route).ok());
    let work_id = work_route.identity();
    let current_id = route.map(PeerRoute::identity);
    crate::print_str(b"[source-terminal-lane] packet/terminal-ready/nested-ready/run-lane/run-gen/run-phase/top-kind/top-id/top-phase/top-owner/work-domain/work-gen/work-exec/work-lane/work-lgen/work-epoch/work-reply/current-domain/current-gen/current-exec/current-lane/current-lgen/current-epoch/current-reply/match=");
    for value in [
        packet,
        u64::from(terminal_ready), u64::from(nested_ready),
        running.map_or(0, |lane| lane.index as u64),
        running.map_or(0, |lane| lane.generation),
        match phase {
            Some(nt_component_suspension::LanePhase::Running) => 1,
            Some(nt_component_suspension::LanePhase::NestedExecution(_)) => 2,
            Some(nt_component_suspension::LanePhase::Suspended) => 3,
            Some(_) => 4,
            None => 0,
        },
        top_kind, top_id, top_phase, top_owner,
        work_id.domain, work_id.domain_generation, work_id.executor,
        work_dispatch.lane().index as u64, work_dispatch.lane().generation,
        work_dispatch.epoch(), work_reply,
        current_id.map_or(0, |id| id.domain),
        current_id.map_or(0, |id| id.domain_generation),
        current_id.map_or(0, |id| id.executor),
        current_dispatch.map_or(0, |id| id.lane().index as u64),
        current_dispatch.map_or(0, |id| id.lane().generation),
        current_dispatch.map_or(0, |id| id.epoch()),
        current_reply.unwrap_or(0),
        u64::from(route == Some(work_route)
            && current_dispatch == Some(work_dispatch)
            && current_reply == Some(work_reply)),
    ] {
        crate::print_str(b"/"); crate::print_hex_u64(value);
    }
    crate::print_str(b"\n");
    for (frame_lane, frame) in lanes().frames() {
        let frame_route = lanes().peer_route(frame_lane).ok().flatten();
        let frame_dispatch = lanes().active_dispatch_identity(frame_lane).ok().flatten();
        let frame_reply = lanes().binding(frame_lane).ok().map(|binding| binding.reply_object);
        let phase = match &frame.phase {
            nt_component_suspension::SuspensionPhase::Waiting => 1,
            nt_component_suspension::SuspensionPhase::Resuming { .. } => 2,
            nt_component_suspension::SuspensionPhase::ResumingChildParked { .. } => 3,
            nt_component_suspension::SuspensionPhase::ResumingChildQuarantined { .. } => 4,
            nt_component_suspension::SuspensionPhase::MaintenanceResuming { .. } => 5,
            _ => 6,
        };
        let exact_work = frame_route == Some(work_route)
            && frame_dispatch == Some(work_dispatch)
            && frame_reply == Some(work_reply);
        crate::print_str(b"[source-terminal-frame] sample/lane/gen/phase/kind/key/owner/route-domain/route-gen/route-exec/epoch/reply/exact-work/parent-blocks-resume=");
        for value in [sample, u64::from(frame_lane.index), frame_lane.generation,
            phase, frame.key.kind as u64, frame.key.id, frame.owner.dispatch_id,
            frame_route.map_or(0, |route| route.identity().domain),
            frame_route.map_or(0, |route| route.identity().domain_generation),
            frame_route.map_or(0, |route| route.identity().executor),
            frame_dispatch.map_or(0, |dispatch| dispatch.epoch()),
            frame_reply.unwrap_or(0),
            u64::from(exact_work),
            u64::from(source_ioctl_parent_blocks_provider_resume(frame.owner.dispatch_id))] {
            crate::print_str(b"/"); crate::print_hex_u64(value);
        }
        crate::print_str(b"\n");
        if exact_work
            && lanes().phase(frame_lane) == Ok(nt_component_suspension::LanePhase::Suspended)
            && matches!(frame.phase, nt_component_suspension::SuspensionPhase::Selected { .. })
        {
            crate::component_resume::trace_source_selected_resume_snapshot(
                frame_lane, frame.key, frame.owner,
            );
        }
    }
    for (index, parent) in (&*core::ptr::addr_of!(PARENTS)).iter().enumerate() {
        let Some(parent) = parent.as_ref() else { continue };
        crate::print_str(b"[source-terminal-any-parent] sample/row/gen/phase/held/canonical/scope/child/source/route-exec/lane/lane-gen/epoch/reply/exact-work=");
        for value in [sample, index as u64, parent.generation, parent.phase as u64,
            u64::from(parent.physical.held()),
            u64::from(parent.physical.canonical_pending()),
            u64::from(parent.scope.is_some()), u64::from(parent.child.is_some()),
            u64::from(parent.source_ioctl.is_some()), parent.route.identity().executor,
            u64::from(parent.dispatch.lane().index), parent.dispatch.lane().generation,
            parent.dispatch.epoch(), parent.reply,
            u64::from(parent.route == work_route && parent.dispatch == work_dispatch
                && parent.reply == work_reply)] {
            crate::print_str(b"/"); crate::print_hex_u64(value);
        }
        crate::print_str(b"\n");
    }
    trace_source_ioctl_parent_for_work(sample, work_route, work_dispatch, work_reply, packet);
}

fn trace_source_park(stage: &[u8]) {
    crate::print_str(b"[source-parent-park] stage=");
    crate::print_str(stage);
    crate::print_str(b"\n");
}

/// Observe the exact owner at a native deferred-resume return without changing admission.
pub(crate) unsafe fn trace_deferred_resume_owner(
    lane: nt_component_suspension::LaneHandle,
    key: nt_component_suspension::SuspensionKey,
    owner: nt_component_suspension::SuspensionOwner,
) {
    let lanes = lanes();
    let phase = lanes.frame(lane, key).ok().flatten()
        .filter(|frame| frame.owner == owner)
        .map(|frame| match &frame.phase {
            nt_component_suspension::SuspensionPhase::Waiting => 1,
            nt_component_suspension::SuspensionPhase::Selected { .. } => 2,
            nt_component_suspension::SuspensionPhase::Resuming { .. } => 3,
            nt_component_suspension::SuspensionPhase::ResumingChildParked { .. } => 4,
            nt_component_suspension::SuspensionPhase::ResumingChildQuarantined { .. } => 5,
            nt_component_suspension::SuspensionPhase::Cancelled { .. } => 6,
            _ => 7,
        }).unwrap_or(0);
    let parents = &*core::ptr::addr_of!(PARENTS);
    let total_parents = parents.iter().flatten().count();
    let matching_parents = parents.iter().flatten().filter(|parent| {
        parent.source_ioctl.as_ref().is_some_and(|source|
            source.checkpoint.parent_key() == key
                && source.checkpoint.parent_owner() == owner
                && source.checkpoint.parent_dispatch().lane() == lane)
    }).count();
    let lane_phase = lanes.phase(lane).map_or(0, |phase| match phase {
        nt_component_suspension::LanePhase::Running => 1,
        nt_component_suspension::LanePhase::Suspended => 2,
        nt_component_suspension::LanePhase::NestedExecution(_) => 3,
        nt_component_suspension::LanePhase::Terminal => 4,
        _ => 5,
    });
    crate::print_str(b"[deferred-resume-owner] lane/key/owner/run-lane/lane-phase/frame-phase/parent-count/exact-source-parents/source-retained=");
    for value in [lane.index as u64, key.id, owner.dispatch_id,
        lanes.running().map_or(u64::MAX, |running| running.index as u64),
        lane_phase, phase,
        total_parents as u64, matching_parents as u64,
        u64::from(source_ioctl_parent_retained())] {
        crate::print_str(b"/");
        crate::print_hex_u64(value);
    }
    crate::print_str(b"\n");
}

/// Root ingress receives a move-only proof only when the exact park attempt has no effects.
/// A retained or uncertain attempt never grants cancellation of its prepared child owner.
pub(crate) unsafe fn park_current_for_root(admission: ExternalAdmissionKey) -> RootParkOutcome {
    match park_current_attempt(Some(admission), None) {
        ParkAttemptOutcome::NoRunningLane(_) => {
            RootParkOutcome::NoRunningLane(NoEffectParkProof { admission })
        }
        ParkAttemptOutcome::Parked(handle) => RootParkOutcome::Parked(handle),
        ParkAttemptOutcome::RefusedNoEffect(error, _) => {
            RootParkOutcome::RefusedNoEffect(error, NoEffectParkProof { admission })
        }
        ParkAttemptOutcome::Retained(error) => RootParkOutcome::Retained(error),
    }
}

unsafe fn park_current_attempt(
    root_admission: Option<ExternalAdmissionKey>, source_ioctl: Option<SourceIoctlParent>,
) -> ParkAttemptOutcome {
    let source_selected = source_ioctl.is_some();
    // A previous uncertain park remains keyed to this exact child even if the route changed.
    // Never issue a new no-effect proof after a retained attempt for the same admission.
    if root_admission.is_some() && (&*core::ptr::addr_of!(PARENTS)).iter().flatten()
        .any(|parent| parent.root_admission == root_admission)
    {
        return ParkAttemptOutcome::Retained(Error::Admission);
    }
    let Some(lane) = lanes().running() else {
        if source_selected { trace_source_park(b"no-running-lane"); }
        return ParkAttemptOutcome::NoRunningLane(source_ioctl);
    };
    let preflight = (|| -> Result<_, Error> {
        let route = lanes()
            .peer_route(lane)
            .map_err(|_| Error::Admission)?
            .ok_or(Error::Admission)?;
        Ok((route, dispatch(route)?, current_reply(route)?))
    })();
    let (route, dispatch, reply) = match preflight {
        Ok(values) => values,
        Err(error) => {
            if source_selected { trace_source_park(b"route-preflight"); }
            return ParkAttemptOutcome::RefusedNoEffect(error, source_ioctl);
        }
    };
    if source_ioctl.as_ref().is_some_and(|source|
        source.checkpoint.parent_route() != route
            || source.checkpoint.parent_dispatch() != dispatch
            || source.checkpoint.parent_reply_object() != reply
            || source.selection.as_ref().is_none_or(|selection|
                selection.key().route != route
                    || selection.key().dispatch != dispatch
                    || selection.key().reply != reply))
    {
        if source_selected { trace_source_park(b"source-identity"); }
        return ParkAttemptOutcome::RefusedNoEffect(Error::Admission, source_ioctl);
    }
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    // A retained uncertain hold fences its physical TCB even if its old route was retired.
    // A new route generation may not acquire that TCB through a second row.
    if rows.iter().flatten().any(|parent| {
        parent.route.identity().executor == route.identity().executor
    }) {
        if source_selected { trace_source_park(b"existing-physical-parent"); }
        return ParkAttemptOutcome::Retained(Error::Admission);
    }
    let index = match rows.iter().position(Option::is_none) {
        Some(index) => index,
        None => {
            let _durable = crate::allocator::enter_durable();
            if rows.try_reserve(1).is_err() {
                if source_selected { trace_source_park(b"parent-capacity"); }
                return ParkAttemptOutcome::RefusedNoEffect(Error::Capacity, source_ioctl);
            }
            rows.push(None);
            rows.len() - 1
        }
    };
    let generation = match NEXT_PARENT_GENERATION.fetch_update(
        Ordering::AcqRel, Ordering::Acquire, |next| next.checked_add(1),
    ) {
        Ok(generation) => generation,
        Err(_) => {
            if source_selected { trace_source_park(b"parent-generation"); }
            return ParkAttemptOutcome::RefusedNoEffect(Error::Capacity, source_ioctl);
        }
    };
    rows[index] = Some(Parent {
        generation,
        root_admission,
        route,
        dispatch,
        reply,
        phase: ParentPhase::Acquiring,
        physical: PhysicalExecutionHold::new(route, dispatch),
        scope: None,
        child: None,
        receive_restore: None,
        root_ingress_restore: None,
        root_lane_begun: false,
        undelivered_root: None,
        source_ioctl,
    });
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    // Suspend cancels IPC in the microkernel. Execution holds preserve the held Call, donated
    // scheduling context and queued message, including the receive continuation after Reply ACK.
    if let Err(error) = rows[index].as_mut().expect("retained parent").physical.acquire() {
        if source_selected { trace_source_park(b"physical-acquire"); }
        let certified_no_effect = rows[index].as_ref().expect("retained parent")
            .physical.acquire_has_no_effects();
        if certified_no_effect {
            // The kernel certified no effects. No scope exists and this row can be reused.
            let source = rows[index].as_mut().expect("retained parent").source_ioctl.take();
            rows[index] = None;
            return ParkAttemptOutcome::RefusedNoEffect(error, source);
        } else {
            // A held or possibly entered acquire has no scope/handle yet. Keep it fenced and
            // visible as quarantine; never reissue acquire through another generation.
            rows[index].as_mut().expect("retained parent").phase = ParentPhase::Quarantined;
        }
        return ParkAttemptOutcome::Retained(error);
    }
    let owner = owner();
    let scope = owner
        .receiver
        .as_mut()
        .expect("ready receiver")
        .suspend_for_nested_execution(
            route,
            dispatch,
            lanes(),
            owner.peers.as_ref().expect("ready peers"),
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
        );
    let scope = match scope {
        Ok(scope) => scope,
        Err(_) => {
            if source_selected { trace_source_park(b"scope-suspend"); }
            let parent = rows[index].as_mut().expect("retained parent");
            if parent.physical.begin_abort_after_failed_scope().is_ok() {
                parent.phase = ParentPhase::AbortPending;
                if attempt_abort(parent) {
                    let source = rows[index].as_mut().expect("retained parent").source_ioctl.take();
                    rows[index] = None;
                    return ParkAttemptOutcome::RefusedNoEffect(Error::Admission, source);
                }
            } else {
                parent.phase = ParentPhase::Quarantined;
            }
            return ParkAttemptOutcome::Retained(Error::Admission);
        }
    };
    let identity = scope.identity();
    let parent = rows[index].as_mut().expect("retained parent");
    parent.scope = Some(scope);
    if let Some(source) = parent.source_ioctl.as_mut() {
        let scope = parent.scope.as_ref().expect("retained source scope");
        if let Err((error, _park_receipt)) = source.checkpoint.park(
            lanes(), scope, ParkedSourceIoctlPage(scope.identity()),
        ) {
            trace_source_park(b"checkpoint-park");
            crate::print_str(b"[source-parent-park] checkpoint-error=");
            crate::print_hex_u64(error as u64);
            crate::print_str(b"\n");
            parent.phase = ParentPhase::Quarantined;
            return ParkAttemptOutcome::Retained(Error::Admission);
        }
        trace_source_park(b"parked");
    }
    parent.phase = ParentPhase::Parked;
    ParkAttemptOutcome::Parked(ParkedParentHandle { index, generation, identity })
}

/// The exact parent row fences its executor until the physical release acknowledges. A failed
/// pure stage is retried from this same row; an uncertain release is never entered twice.
unsafe fn attempt_abort(parent: &mut Parent) -> bool {
    if parent.phase != ParentPhase::AbortPending { return false; }
    parent.phase = ParentPhase::AbortAttempt;
    let result = parent.physical.abort_after_failed_scope();
    if result.is_ok() {
        return true;
    }
    parent.phase = if matches!(parent.physical.restore_step(),
        Ok(RestoreStep::Projection | RestoreStep::Release | RestoreStep::Finalize)) {
        ParentPhase::AbortPending
    } else {
        ParentPhase::Quarantined
    };
    if parent.phase == ParentPhase::AbortPending {
        ABORT_WAKE.publish(
            crate::monotonic_time_100ns().saturating_add(ABORT_RETRY_100NS),
        );
    }
    false
}

unsafe fn drive_abort(index: usize, generation: u64) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    let Some(parent) = rows.get_mut(index).and_then(Option::as_mut) else { return false; };
    if parent.generation != generation { return false; }
    if attempt_abort(parent) {
        rows[index] = None;
        true
    } else {
        false
    }
}

fn has_pending_abort() -> bool {
    unsafe { (&*core::ptr::addr_of!(PARENTS)).iter()
        .any(|row| row.as_ref().is_some_and(|parent| parent.phase == ParentPhase::AbortPending)) }
}

pub(crate) fn next_abort_deadline() -> Option<u64> {
    ABORT_WAKE.next_deadline(has_pending_abort())
}

pub(crate) fn wake_abort_due(now_100ns: u64) -> u64 {
    u64::from(ABORT_WAKE.wake_due(now_100ns, has_pending_abort()))
}

/// Outer service redrive only; never call this inside a nested pump or an ACK path.
pub(crate) unsafe fn drain_abort() -> usize {
    let has_work = has_pending_abort();
    if !has_work { return 0; }
    let now = crate::monotonic_time_100ns();
    let Some(attempt) = ABORT_WAKE.begin_redrive(now, has_work) else { return 0; };
    let _ = attempt.retry_at(now.saturating_add(ABORT_RETRY_100NS));
    let selected = {
        let rows = &*core::ptr::addr_of!(PARENTS);
        let last = LAST_ABORT.load(Ordering::Relaxed);
        let after = (last != usize::MAX).then_some(last);
        next_ready_pending_lane(rows.len(), after, |index| {
            if rows[index].as_ref().is_some_and(|row| row.phase == ParentPhase::AbortPending) {
                PendingLaneReadiness::Ready
            } else {
                PendingLaneReadiness::Absent
            }
        }).map(|index| (index, rows[index].as_ref().expect("selected abort parent").generation))
    };
    let Some((index, generation)) = selected else { return 0; };
    LAST_ABORT.store(index, Ordering::Relaxed);
    usize::from(drive_abort(index, generation))
}

pub(crate) unsafe fn bind_receive_child(
    handle: &ParkedParentHandle,
    barrier: &mut nt_user_host::receive_child_barrier::ReceiveChildBarrier<crate::HostedThreadRole>,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) -> Result<(), Error> {
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(handle.index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !parent.physical.canonical_pending() || parent.child.is_some() {
        return Err(Error::Admission);
    }
    barrier
        .bind_parent(scope, dispatch)
        .map_err(|_| Error::Admission)?;
    parent.child = Some(ParentChild::Receive);
    Ok(())
}

/// Bind a prepared ordinary root event to the exact physical parent after its hold acknowledges.
/// The pass stays in the retained child row; this parent row remains the physical authority.
pub(crate) unsafe fn bind_root_ingress_child(
    handle: &ParkedParentHandle,
    pass: &mut nt_user_host::root_ingress_pass::RootIngressPass<crate::HostedThreadRole>,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) -> Result<(), Error> {
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(handle.index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !parent.physical.canonical_pending() || parent.child.is_some()
    {
        return Err(Error::Admission);
    }
    pass.bind_parent(scope, dispatch).map_err(|_| Error::Admission)?;
    parent.child = Some(ParentChild::RootIngress);
    Ok(())
}

/// Store the sealed, untouched child in its exact parent before any restoration effect. The
/// parent remains discoverable if a later canonical query or physical release refuses.
pub(crate) unsafe fn begin_undelivered_root_unwind(
    handle: &ParkedParentHandle,
    token: &mut Option<nt_user_host::root_ingress_pass::UndeliveredRootIngress<crate::HostedThreadRole>>,
) -> Result<(), Error> {
    let witness = token.as_ref().ok_or(Error::Admission)?;
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(handle.index).and_then(Option::as_mut).ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !parent.physical.canonical_pending() || !parent.physical.held()
        || parent.root_admission != Some(witness.admission_key())
        || witness.child().tcb != witness.admission_key().executor()
        || parent.child.is_some() || parent.receive_restore.is_some()
        || parent.root_ingress_restore.is_some() || parent.undelivered_root.is_some()
    {
        return Err(Error::Admission);
    }
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    let key = nt_component_suspension::SuspensionKey::root_ingress(
        witness.admission_key().admission_sequence(),
    );
    if lanes().frame(scope.dispatch().lane(), key)
        .map_err(|_| Error::Admission)?.is_some()
    {
        return Err(Error::Admission);
    }
    parent.undelivered_root = token.take();
    Ok(())
}

/// Read-only preflight for the parent identity before the child pass seals its Prepared phase.
pub(crate) unsafe fn undelivered_root_parent_candidate(
    handle: &ParkedParentHandle, admission: ExternalAdmissionKey,
) -> bool {
    (&*core::ptr::addr_of!(PARENTS)).get(handle.index).and_then(Option::as_ref)
        .is_some_and(|parent| {
            row_matches(handle, parent) && parent.phase == ParentPhase::Parked
                && parent.root_admission == Some(admission)
                && parent.child.is_none() && parent.undelivered_root.is_none()
                && parent.physical.canonical_pending() && parent.physical.held()
        })
}

/// Transfer the one-shot child receipt into the existing physical parent owner before returning
/// any outer-boundary ticket. Failure never drops an entered permit or releases the parent hold.
pub(crate) unsafe fn consume_receive_settlement(
    handle: &ParkedParentHandle,
    barrier: &mut nt_user_host::receive_child_barrier::ReceiveChildBarrier<crate::HostedThreadRole>,
) -> Result<(), Error> {
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(handle.index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !parent.physical.canonical_pending()
        || parent.receive_restore.is_some()
    {
        return Err(Error::Admission);
    }
    let permit = barrier.begin_restore(scope).map_err(|_| Error::Admission)?;
    parent.receive_restore = Some(permit);
    Ok(())
}

/// Memory-only use of the sealed permit; it remains in the physical parent throughout restore.
pub(crate) unsafe fn with_receive_restore<T>(
    handle: &ParkedParentHandle,
    use_permit: impl FnOnce(
        &NestedExecutionScope,
        &nt_user_host::receive_child_barrier::ReceiveRestorePermit<crate::HostedThreadRole>,
    ) -> Result<T, Error>,
) -> Result<T, Error> {
    let parent = (&*core::ptr::addr_of!(PARENTS))
        .get(handle.index)
        .and_then(Option::as_ref)
        .ok_or(Error::Admission)?;
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    let permit = parent.receive_restore.as_ref().ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || !permit.matches_scope(scope) || !parent.physical.canonical_pending()
    {
        return Err(Error::Admission);
    }
    use_permit(scope, permit)
}

/// Seal the child's one-shot checkpoint in the physical parent before changing the lane or
/// entering restoration. A refused lane transition leaves both owners in their retained rows.
pub(crate) unsafe fn begin_root_ingress_restore(
    handle: &ParkedParentHandle,
    pass: &mut nt_user_host::root_ingress_pass::RootIngressPass<crate::HostedThreadRole>,
) -> Result<(), Error> {
    use nt_component_suspension::SuspensionKey;
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(handle.index).and_then(Option::as_mut).ok_or(Error::Admission)?;
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
        || parent.child != Some(ParentChild::RootIngress)
        || !parent.physical.canonical_pending()
        || parent.root_admission != Some(pass.admission_key())
        || pass.child().tcb != pass.admission_key().executor()
    {
        return Err(Error::Admission);
    }
    let scope = parent.scope.as_ref().ok_or(Error::Admission)?;
    if parent.root_ingress_restore.is_none() {
        let permit = pass.begin_restore(scope).map_err(|_| Error::Admission)?;
        if permit.parent() != handle.identity || permit.child() != pass.child()
            || permit.admission_key() != pass.admission_key()
            || permit.checkpoint().parent() != handle.identity
            || permit.checkpoint().child() != permit.admission_key()
        {
            // A successful begin_restore is one-shot. A mismatch is retained, never retried.
            parent.root_ingress_restore = Some(permit);
            parent.phase = ParentPhase::Quarantined;
            return Err(Error::Admission);
        }
        parent.root_ingress_restore = Some(permit);
    }
    let permit = parent.root_ingress_restore.as_ref().ok_or(Error::Admission)?;
    if permit.parent() != handle.identity || permit.child() != pass.child()
        || permit.admission_key() != pass.admission_key()
        || permit.checkpoint().parent() != handle.identity
        || permit.checkpoint().child() != permit.admission_key()
    {
        return Err(Error::Admission);
    }
    if !parent.root_lane_begun {
        let key = SuspensionKey::root_ingress(permit.admission_key().admission_sequence());
        // The sealed lane frame is the owner authority: admission bound its owner to this
        // exact scope and child key. The resume API rechecks that entire binding.
        let frame = lanes().frame(scope.dispatch().lane(), key)
            .map_err(|_| Error::Admission)?.ok_or(Error::Admission)?;
        let frame_owner = frame.owner;
        lanes().begin_root_ingress_restore(
            scope, key, frame_owner, permit.checkpoint(),
            crate::ComponentSuspensionCompletion::receive_ready(),
        ).map_err(|_| Error::Admission)?;
        parent.root_lane_begun = true;
    }
    Ok(())
}

unsafe fn restore_stages(
    handle: &mut Option<ParkedParentHandle>, restore_owner: RestoreOwner,
) -> Result<RestoreReceipt, Error> {
    let Some(ticket) = handle.as_ref() else {
        return if restore_owner == RestoreOwner::Ordinary {
            Ok(RestoreReceipt::Ordinary)
        } else { Err(Error::Admission) };
    };
    let index = ticket.index;
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    let parent = rows
        .get_mut(index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    if !row_matches(ticket, parent) || parent.phase != ParentPhase::RestoreAttempt {
        return Err(Error::Admission);
    }
    if restore_owner == RestoreOwner::Ordinary
        && (parent.root_admission.is_some() || parent.child == Some(ParentChild::RootIngress))
    {
        return Err(Error::Admission);
    }
    if restore_owner == RestoreOwner::RootIngress
        && (parent.child != Some(ParentChild::RootIngress)
        || !parent.root_lane_begun || parent.root_ingress_restore.as_ref().is_none_or(|permit| {
        permit.parent() != ticket.identity
            || Some(permit.admission_key()) != parent.root_admission
            || permit.checkpoint().parent() != ticket.identity
            || permit.checkpoint().child() != permit.admission_key()
    })) {
        return Err(Error::Admission);
    }
    if restore_owner == RestoreOwner::UndeliveredRoot
        && (parent.child.is_some() || parent.root_ingress_restore.is_some()
            || parent.undelivered_root.as_ref().is_none_or(|token| {
                Some(token.admission_key()) != parent.root_admission
                    || token.child().tcb != token.admission_key().executor()
            }))
    {
        return Err(Error::Admission);
    }
    if parent.child == Some(ParentChild::Receive)
        && parent.receive_restore.as_ref().is_none_or(|permit| {
            !permit.matches_scope(parent.scope.as_ref().expect("validated scope"))
        })
    {
        return Err(Error::Admission);
    }
    if !parent.physical.held() || resolve(parent.physical.route(), false).is_none() {
        return Err(Error::Admission);
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    if parent.physical.restore_step()? == RestoreStep::Canonical {
        let scope = parent.scope.as_mut().ok_or(Error::Admission)?;
        let owner = owner();
        owner
            .receiver
            .as_mut()
            .expect("ready receiver")
            .resume_nested_execution(
                scope,
                lanes(),
                owner.peers.as_ref().expect("ready peers"),
                |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            )
            .map_err(|_| Error::Admission)?;
        parent.physical.canonical_restored()?;
    }
    if parent.physical.restore_step()? == RestoreStep::Projection {
        parent.physical.restore_projection()?;
    }
    if parent.physical.restore_step()? == RestoreStep::Release {
        parent.physical.release()?;
    }
    if parent.physical.restore_step()? == RestoreStep::Finalize {
        parent.physical.projection_restored()?;
    }
    if parent.physical.restore_step()? != RestoreStep::Done {
        return Err(Error::Admission);
    }
    let restored = match restore_owner {
        RestoreOwner::Ordinary => RestoreReceipt::Ordinary,
        RestoreOwner::RootIngress => RestoreReceipt::RootIngress(
            parent.root_ingress_restore.take().ok_or(Error::Admission)?),
        RestoreOwner::UndeliveredRoot => RestoreReceipt::UndeliveredRoot(
            parent.undelivered_root.take().ok_or(Error::Admission)?),
    };
    rows[index] = None;
    *handle = None;
    Ok(restored)
}

/// Persist recovery authority before a fallible restore. A stack handle can then disappear
/// without losing the exact scope, physical hold, or child settlement permit in `PARENTS`.
pub(crate) unsafe fn mark_restore_pending(
    handle: &Option<ParkedParentHandle>,
) -> Result<(), Error> {
    let Some(ticket) = handle.as_ref() else { return Ok(()); };
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(ticket.index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    if !row_matches(ticket, parent) || parent.root_admission.is_some()
        || !matches!(parent.phase, ParentPhase::Parked | ParentPhase::RestorePending)
    {
        return Err(Error::Admission);
    }
    if !parent.physical.held() {
        // An exact row without its acknowledged hold cannot be retried. Keep it fenced even if
        // the stack handle disappears after this refusal.
        parent.phase = ParentPhase::Quarantined;
        return Err(Error::Admission);
    }
    parent.phase = ParentPhase::RestoreAttempt;
    Ok(())
}

unsafe fn mark_undelivered_root_restore_pending(
    handle: &Option<ParkedParentHandle>,
) -> Result<(), Error> {
    let ticket = handle.as_ref().ok_or(Error::Admission)?;
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(ticket.index).and_then(Option::as_mut).ok_or(Error::Admission)?;
    if !row_matches(ticket, parent) || parent.child.is_some()
        || !matches!(parent.phase, ParentPhase::Parked | ParentPhase::RestorePending)
        || parent.undelivered_root.as_ref().is_none_or(|token| {
            Some(token.admission_key()) != parent.root_admission
                || token.child().tcb != token.admission_key().executor()
        })
    {
        return Err(Error::Admission);
    }
    if !parent.physical.held() {
        parent.phase = ParentPhase::Quarantined;
        return Err(Error::Admission);
    }
    parent.phase = ParentPhase::RestoreAttempt;
    Ok(())
}

unsafe fn mark_root_restore_pending(handle: &Option<ParkedParentHandle>) -> Result<(), Error> {
    let ticket = handle.as_ref().ok_or(Error::Admission)?;
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(ticket.index).and_then(Option::as_mut).ok_or(Error::Admission)?;
    if !row_matches(ticket, parent) || parent.child != Some(ParentChild::RootIngress)
        || !matches!(parent.phase, ParentPhase::Parked | ParentPhase::RestorePending)
        || !parent.root_lane_begun || parent.root_ingress_restore.is_none()
    {
        return Err(Error::Admission);
    }
    if !parent.physical.held() {
        parent.phase = ParentPhase::Quarantined;
        return Err(Error::Admission);
    }
    parent.phase = ParentPhase::RestoreAttempt;
    Ok(())
}

/// A pure canonical preflight refusal and a projection-owner preflight refusal have no native
/// effects, so their exact row can be retried. Release marks possible seL4 entry *before* the
/// invocation; `UncertainRelease` is quarantined and is never replayed. The finalize stage
/// follows an acknowledged release and retries only its pure owner-state acknowledgement.
fn restore_refusal_is_retryable(parent: &Parent) -> bool {
    parent.physical.held() && matches!(parent.physical.restore_step(),
        Ok(RestoreStep::Canonical | RestoreStep::Projection | RestoreStep::Finalize))
}

/// Keep a refused parent discoverable after the caller's stack frame ends. The wrapper never
/// retries inside the same pump or turns a physical uncertainty into a transport wall.
pub(crate) unsafe fn restore_or_retain(
    handle: &mut Option<ParkedParentHandle>,
) -> Result<(), Error> {
    mark_restore_pending(handle)?;
    let result = restore_stages(handle, RestoreOwner::Ordinary).map(|_| ());
    if result.is_err() {
        retain_restore_refusal(handle);
    }
    result
}

/// Persist an intentionally parked parent before the pump stack unwinds. This transition has
/// no physical effect; the exact row keeps the Reply, scope and hold until an outer owner runs
/// one child and requests its restore. On refusal the move-only handle stays with the caller.
pub(crate) unsafe fn retain_child_work_parent(
    handle: &mut Option<ParkedParentHandle>,
) -> Result<Option<NestedRestoreTicket>, Error> {
    let Some(ticket) = handle.as_ref() else { return Ok(None) };
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(ticket.index)
        .and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    if !row_matches(ticket, parent) || parent.root_admission.is_some()
        || parent.phase != ParentPhase::Parked || !parent.physical.held()
    {
        return Err(Error::Admission);
    }
    parent.phase = ParentPhase::RestorePending;
    let selector = ticket.ticket();
    *handle = None;
    Ok(Some(selector))
}

/// A successful physical restore creates a one-use receive receipt. A no-effect refusal stays
/// retryable in the retained row; uncertain release stays quarantined there.
pub(crate) unsafe fn restore_child_work_parent(
    ticket: NestedRestoreTicket,
) -> Result<ChildWorkParentRestored, Error> {
    restore_pending_ticket(ticket)?;
    Ok(ChildWorkParentRestored { ticket })
}

/// A selected child may have made an uncertain effect. Revoke the exact parked parent's
/// restore eligibility before dropping the child-step certificate; the physical hold and Reply
/// remain in this row for diagnosis and later explicit reconciliation.
pub(crate) unsafe fn quarantine_child_work_parent(
    ticket: NestedRestoreTicket,
) -> Result<(), Error> {
    let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(ticket.index).and_then(Option::as_mut).ok_or(Error::Admission)?;
    if !ticket_matches(ticket, parent) || parent.phase != ParentPhase::RestorePending
        || !parent.physical.held()
    {
        return Err(Error::Admission);
    }
    parent.phase = ParentPhase::Quarantined;
    Ok(())
}

/// A root child has a typed positive receipt. It is produced only after every physical parent
/// stage acknowledges; on any refusal the exact permit remains in `PARENTS`.
pub(crate) unsafe fn restore_root_ingress(
    handle: &mut Option<ParkedParentHandle>,
) -> Result<nt_user_host::root_ingress_pass::RootIngressRestored<crate::HostedThreadRole>, Error> {
    mark_root_restore_pending(handle)?;
    let result = restore_stages(handle, RestoreOwner::RootIngress);
    if result.is_err() {
        retain_restore_refusal(handle);
    }
    let RestoreReceipt::RootIngress(permit) = result? else { return Err(Error::Admission) };
    Ok(permit.acknowledge_restore())
}

/// Complete the actual parent restoration before granting cancellation of an untouched child.
pub(crate) unsafe fn restore_undelivered_root(
    handle: &mut Option<ParkedParentHandle>,
) -> Result<RestoredBeforeChildProof, Error> {
    let parent_identity = handle.as_ref().ok_or(Error::Admission)?.identity();
    mark_undelivered_root_restore_pending(handle)?;
    let result = restore_stages(handle, RestoreOwner::UndeliveredRoot);
    if result.is_err() { retain_restore_refusal(handle); }
    let RestoreReceipt::UndeliveredRoot(token) = result? else { return Err(Error::Admission) };
    Ok(RestoredBeforeChildProof { parent: parent_identity, token })
}

unsafe fn retain_restore_refusal(handle: &Option<ParkedParentHandle>) {
    if let Some(ticket) = handle.as_ref() {
        if let Some(parent) = (&mut *core::ptr::addr_of_mut!(PARENTS))
            .get_mut(ticket.index).and_then(Option::as_mut)
        {
            if row_matches(ticket, parent) && parent.phase == ParentPhase::RestoreAttempt {
                parent.phase = if restore_refusal_is_retryable(parent) {
                    ParentPhase::RestorePending
                } else {
                    ParentPhase::Quarantined
                };
            }
        }
    }
}

/// Every existing nested restore caller enters through the durable owner, even when it cannot
/// itself schedule a later retry. The row outlives a dropped stack handle on refusal.
pub(crate) unsafe fn restore(handle: &mut Option<ParkedParentHandle>) -> Result<(), Error> {
    restore_or_retain(handle)
}

/// Look up an exact retained refusal without transferring ownership or changing state.
/// Recycled slots, active restores, and quarantined effects are never pending tickets.
pub(crate) unsafe fn pending_ticket(ticket: NestedRestoreTicket) -> bool {
    (&*core::ptr::addr_of!(PARENTS))
        .get(ticket.index)
        .and_then(Option::as_ref)
        .is_some_and(|parent| {
            parent.phase == ParentPhase::RestorePending
                && parent.root_admission.is_none()
                && ticket_matches(ticket, parent)
                && restore_refusal_is_retryable(parent)
        })
}

pub(crate) unsafe fn pending_undelivered_root_ticket(ticket: NestedRestoreTicket) -> bool {
    (&*core::ptr::addr_of!(PARENTS))
        .get(ticket.index).and_then(Option::as_ref)
        .is_some_and(|parent| {
            parent.phase == ParentPhase::RestorePending
                && ticket_matches(ticket, parent)
                && parent.child.is_none()
                && parent.undelivered_root.as_ref().is_some_and(|token| {
                    Some(token.admission_key()) == parent.root_admission
                        && token.child().tcb == token.admission_key().executor()
                })
                && restore_refusal_is_retryable(parent)
        })
}

/// A pre-effect restore refusal may leave the sealed parent in Parked. Only the same held,
/// canonical physical owner may retry; Quarantined and entered attempts are excluded.
pub(crate) unsafe fn parked_undelivered_root_ticket(ticket: NestedRestoreTicket) -> bool {
    (&*core::ptr::addr_of!(PARENTS))
        .get(ticket.index).and_then(Option::as_ref)
        .is_some_and(|parent| {
            parent.phase == ParentPhase::Parked
                && ticket_matches(ticket, parent)
                && parent.child.is_none()
                && parent.undelivered_root.as_ref().is_some_and(|token| {
                    Some(token.admission_key()) == parent.root_admission
                        && token.child().tcb == token.admission_key().executor()
                })
                && parent.physical.canonical_pending() && parent.physical.held()
        })
}

pub(crate) unsafe fn restore_pending_undelivered_root_ticket(
    ticket: NestedRestoreTicket,
) -> Result<RestoredBeforeChildProof, Error> {
    if !pending_undelivered_root_ticket(ticket) { return Err(Error::Admission); }
    let mut handle = Some(ParkedParentHandle {
        index: ticket.index, generation: ticket.generation, identity: ticket.identity,
    });
    restore_undelivered_root(&mut handle)
}

/// A retained root refusal has a distinct typed redrive because success must return its
/// one-shot child receipt. The ordinary ticket path cannot dispose of that receipt.
pub(crate) unsafe fn pending_root_ticket(ticket: NestedRestoreTicket) -> bool {
    (&*core::ptr::addr_of!(PARENTS))
        .get(ticket.index)
        .and_then(Option::as_ref)
        .is_some_and(|parent| {
            parent.phase == ParentPhase::RestorePending
                && parent.child == Some(ParentChild::RootIngress)
                && ticket_matches(ticket, parent)
                && parent.root_lane_begun
                && parent.root_ingress_restore.as_ref().is_some_and(|permit| {
                    permit.parent() == ticket.identity
                        && Some(permit.admission_key()) == parent.root_admission
                        && permit.checkpoint().parent() == ticket.identity
                        && permit.checkpoint().child() == permit.admission_key()
                })
                && restore_refusal_is_retryable(parent)
        })
}

/// Redrive only the exact retained root parent. A successful physical restoration transfers
/// the positive child receipt to the caller; an uncertain effect stays quarantined in PARENTS.
pub(crate) unsafe fn restore_pending_root_ticket(
    ticket: NestedRestoreTicket,
) -> Result<nt_user_host::root_ingress_pass::RootIngressRestored<crate::HostedThreadRole>, Error> {
    if !pending_root_ticket(ticket) { return Err(Error::Admission); }
    let mut handle = Some(ParkedParentHandle {
        index: ticket.index,
        generation: ticket.generation,
        identity: ticket.identity,
    });
    restore_root_ingress(&mut handle)
}

/// Match an already authenticated pump route and its Reply against this retained parent.
/// Callers must first resolve `PumpChannel` through `channel_route`; a bare Reply number is not
/// physical authority. This check neither transfers ownership nor enters a native operation.
pub(crate) unsafe fn ticket_matches_channel(
    ticket: NestedRestoreTicket,
    route: PeerRoute,
    reply: u64,
) -> bool {
    pending_ticket(ticket) && retained_ticket_matches_channel(ticket, route, reply)
}

/// A quarantined result still owns the exact parent and caller Reply, although it grants no
/// retry. Capture that ownership at the outer boundary without treating it as native authority.
pub(crate) unsafe fn retained_ticket_matches_channel(
    ticket: NestedRestoreTicket,
    route: PeerRoute,
    reply: u64,
) -> bool {
    if reply == 0 || ticket.identity.route() != route {
        return false;
    }
    let row = (&*core::ptr::addr_of!(PARENTS))
        .get(ticket.index).and_then(Option::as_ref);
    if row.is_none_or(|parent| {
        !matches!(parent.phase, ParentPhase::RestorePending | ParentPhase::Quarantined)
            || !ticket_matches(ticket, parent) || parent.reply != reply
    }) {
        return false;
    }
    let lane = ticket.identity.dispatch().lane();
    let active = lanes();
    active.peer_route(lane).ok() == Some(Some(route))
        && active.active_dispatch_identity(lane).ok() == Some(Some(ticket.identity.dispatch()))
        && active.binding(lane).is_ok_and(|binding| {
            binding.executor_id == route.identity().executor
                && binding.receive_endpoint == route.endpoint()
                && binding.reply_object == reply
        })
}

/// Select one exact row for a bounded retry; the selector itself authorizes no native effect.
pub(crate) unsafe fn restore_pending_ticket(ticket: NestedRestoreTicket) -> Result<(), Error> {
    if !pending_ticket(ticket) { return Err(Error::Admission); }
    let mut handle = Some(ParkedParentHandle {
        index: ticket.index,
        generation: ticket.generation,
        identity: ticket.identity,
    });
    restore_or_retain(&mut handle)
}
