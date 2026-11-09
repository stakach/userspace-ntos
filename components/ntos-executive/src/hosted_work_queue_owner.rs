//! Retained ownership of a provider work queue entry after its shared ring slot advances.
//!
//! This identity names the queue entry only. A suspended callback must separately retain
//! and authenticate its physical route, dispatch, TCB, Reply, and epoch before root resumes it.

use super::*;
use nt_component_suspension::HostedWorkQueueClaim;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct QueueEntryKey {
    domain_id: u64,
    domain_cookie: u64,
    head: u64,
    work_item: u64,
}

impl QueueEntryKey {
    pub(super) fn new(inst: DriverInstance, head: u64, work_item: u64) -> Self {
        Self {
            domain_id: inst.hosted_domain_id,
            domain_cookie: inst.hosted_domain_cookie,
            head,
            work_item,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct QueueEntry {
    pub(super) kind: u64,
    pub(super) work_item: u64,
    pub(super) routine: u64,
    pub(super) arg0: u64,
    pub(super) arg1: u64,
}

struct Row {
    sequence: u64,
    file_floor: u64,
    claim: HostedWorkQueueClaim<QueueEntryKey, QueueEntry>,
    ndis: Option<HostedProviderNdisWorkItemDispatch>,
    pump: Option<component_scheduler::HostedPumpRestore>,
    child_step: Option<crate::service_sec_image::NestedChildStep>,
    resuming: bool,
    terminal_ack: Option<TerminalAck>,
}

/// The provider has returned and all NDIS disposition effects have already been applied.
/// Only the pure queue-claim ACK may be retried from this phase.
#[derive(Clone, Copy)]
struct TerminalAck {
    physical: component_scheduler::ChildWorkPhysicalIdentity,
    status: i32,
}

static mut CLAIMS: Vec<Option<Row>> = Vec::new();
static mut ORPHANED_PUMPS: Vec<component_scheduler::HostedPumpRestore> = Vec::new();
static mut ORPHANED_STEPS: Vec<crate::service_sec_image::NestedChildStep> = Vec::new();
static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// An exact selector for a parked callback. Queue entry identity and physical invocation
/// identity are separate; neither the shared ring head nor a numeric Reply alone is authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct QueuedCallbackSelector {
    index: usize,
    key: QueueEntryKey,
    sequence: u64,
    physical: component_scheduler::ChildWorkPhysicalIdentity,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum QueuedCallbackRootAction {
    NeedsChild(QueuedCallbackSelector),
    ResumeRecordedStep(QueuedCallbackSelector),
    RetryRestore(QueuedCallbackSelector),
    RetryTerminalAck(QueuedCallbackSelector),
}

pub(crate) enum QueuedCallbackProgress {
    Completed,
    TerminalFailure(i32),
    NeedsChild,
    PendingRestore,
    PendingTerminalAck,
    AwaitingLocalChild,
    RecordedStep,
    InnerFilePending,
    Blocked,
}

/// Reserve the claim before clearing the shared slot or entering any native callback.
pub(super) unsafe fn claim(
    index: usize, key: QueueEntryKey, entry: QueueEntry, file_floor: u64,
) -> bool {
    let orphaned = &mut *core::ptr::addr_of_mut!(ORPHANED_PUMPS);
    if !orphaned.is_empty() || orphaned.try_reserve(1).is_err() { return false; }
    let orphaned_steps = &mut *core::ptr::addr_of_mut!(ORPHANED_STEPS);
    if !orphaned_steps.is_empty() || orphaned_steps.try_reserve(1).is_err() { return false; }
    let rows = &mut *core::ptr::addr_of_mut!(CLAIMS);
    if rows.len() <= index {
        let additional = index + 1 - rows.len();
        if rows.try_reserve(additional).is_err() { return false; }
        rows.resize_with(index + 1, || None);
    }
    if rows[index].is_some() { return false; }
    let sequence = NEXT_SEQUENCE.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |current| current.checked_add(1)).ok();
    let Some(sequence) = sequence else { return false; };
    rows[index] = Some(Row {
        sequence, file_floor, claim: HostedWorkQueueClaim::dequeue(key, entry),
        ndis: None, pump: None, child_step: None, resuming: false, terminal_ack: None,
    });
    true
}

pub(super) unsafe fn pending(index: usize) -> bool {
    (&*core::ptr::addr_of!(CLAIMS)).get(index).is_some_and(Option::is_some)
}

/// Store the move-only callback result before returning to the root. The orphan reserve was
/// made before dispatch; an impossible lost queue row still retains the physical pump.
pub(super) unsafe fn retain_pump(
    index: usize, key: QueueEntryKey, pump: component_scheduler::HostedPumpRestore,
) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(CLAIMS);
    if let Some(row) = rows.get_mut(index).and_then(Option::as_mut) {
        if row.claim.invocation() == key && row.pump.is_none() {
            row.pump = Some(pump);
            return true;
        }
    }
    (&mut *core::ptr::addr_of_mut!(ORPHANED_PUMPS)).push(pump);
    false
}

/// Return only copied callback arguments; the row keeps the physical queue claim.
pub(super) unsafe fn enter(index: usize, key: QueueEntryKey) -> Option<QueueEntry> {
    (&mut *core::ptr::addr_of_mut!(CLAIMS)).get_mut(index)?
        .as_mut()?.claim.enter(key).ok()
}

pub(super) unsafe fn record_ndis(
    index: usize, key: QueueEntryKey, dispatch: Option<HostedProviderNdisWorkItemDispatch>,
) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(CLAIMS)).get_mut(index)
        .and_then(Option::as_mut) else { return false; };
    if row.claim.retained_entry(key).is_err() || row.ndis.is_some() { return false; }
    row.ndis = dispatch;
    true
}

pub(super) unsafe fn acknowledge_return(index: usize, key: QueueEntryKey) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(CLAIMS);
    let Some(row) = rows.get_mut(index).and_then(Option::as_mut) else { return false; };
    if row.pump.is_some() || row.child_step.is_some() || row.resuming { return false; }
    if row.claim.acknowledge_return(key).is_err() { return false; }
    rows[index] = None;
    true
}

/// The typed scheduler has already authenticated the exact dispatch terminal before
/// retiring it. Remove this resuming row atomically with its one-use queue ACK.
unsafe fn acknowledge_resumed_return(selector: QueuedCallbackSelector) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(CLAIMS);
    let Some(row) = rows.get_mut(selector.index).and_then(Option::as_mut) else {
        return false;
    };
    if row.sequence != selector.sequence || row.claim.invocation() != selector.key
        || row.terminal_ack.is_none_or(|terminal| terminal.physical != selector.physical)
        || row.child_step.is_some()
        || !(row.resuming && row.pump.is_none()
            || !row.resuming && matches!(row.pump.as_ref(),
                Some(component_scheduler::HostedPumpRestore::Restored(pr)) if pr.completed))
        || row.claim.acknowledge_return(selector.key).is_err()
    { return false; }
    rows[selector.index] = None;
    true
}

unsafe fn mark_terminal_ack(selector: QueuedCallbackSelector, status: i32) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(CLAIMS))
        .get_mut(selector.index).and_then(Option::as_mut) else { return false; };
    if row.sequence != selector.sequence || row.claim.invocation() != selector.key
        || !row.resuming || row.pump.is_some() || row.child_step.is_some()
        || row.terminal_ack.is_some()
    { return false; }
    row.terminal_ack = Some(TerminalAck { physical: selector.physical, status });
    true
}

/// The shared slot was consumed, but the callback did not enter. A missing or mismatched
/// row stays retained; neither path may acknowledge a provider return that never occurred.
pub(super) unsafe fn abort_before_enter(index: usize, key: QueueEntryKey) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(CLAIMS);
    let Some(row) = rows.get_mut(index).and_then(Option::as_mut) else { return false; };
    if row.ndis.is_some() || row.claim.abort_before_enter(key).is_err() { return false; }
    rows[index] = None;
    true
}

unsafe fn exact_physical_identity(
    index: usize, row: &Row,
) -> Option<component_scheduler::ChildWorkPhysicalIdentity> {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let identity = row.pump.as_ref()?.child_work_identity()?;
    let inst = instance(index)?;
    let key = row.claim.invocation();
    let domain = instance_domain_identity(inst)?;
    let source = runtime::physical_source(identity.route).ok()?;
    if key.domain_id != inst.hosted_domain_id
        || key.domain_cookie != inst.hosted_domain_cookie
        || identity.route != hosted_ingress_sources::primary_route(index)?
        || identity.tcb != inst.tcb || identity.pml4 != inst.pml4
        || identity.shared_va != inst.exec_shared_va
        || source.domain != runtime::PhysicalDomain::Hosted(domain)
        || source.kind != runtime::PhysicalSourceKind::Primary
        || source.tcb != identity.tcb || source.pml4 != identity.pml4
        || runtime::dispatch(identity.route).ok() != Some(identity.dispatch)
        || runtime::current_reply(identity.route).ok() != Some(identity.reply_cap)
    { return None; }
    Some(identity)
}

fn selector_for(index: usize, row: &Row) -> Option<QueuedCallbackSelector> {
    let physical = unsafe { exact_physical_identity(index, row) }?;
    Some(QueuedCallbackSelector {
        index, key: row.claim.invocation(), sequence: row.sequence, physical,
    })
}

/// Newer claimed callbacks are physically nested beneath older work, including older File
/// pumps. Select in reverse claim order; a recorded step never authorizes a second child.
pub(crate) unsafe fn queued_callback_root_action() -> Option<QueuedCallbackRootAction> {
    if !(&*core::ptr::addr_of!(ORPHANED_PUMPS)).is_empty()
        || !(&*core::ptr::addr_of!(ORPHANED_STEPS)).is_empty()
    { return None; }
    let rows = &*core::ptr::addr_of!(CLAIMS);
    // Pick the newest retained row first. A blocked or currently resuming inner callback
    // fences every older row; filtering by action before ordering would violate LIFO.
    let (index, row) = rows.iter().enumerate()
        .filter_map(|(index, slot)| slot.as_ref()
            .filter(|row| row.pump.is_some() || row.resuming)
            .map(|row| (index, row)))
        .max_by_key(|(_, row)| row.sequence)?;
    if row.resuming { return None; }
    if let Some(terminal) = row.terminal_ack {
        return Some(QueuedCallbackRootAction::RetryTerminalAck(QueuedCallbackSelector {
            index, key: row.claim.invocation(), sequence: row.sequence,
            physical: terminal.physical,
        }));
    }
    let selector = selector_for(index, row)?;
    match row.pump.as_ref()? {
        component_scheduler::HostedPumpRestore::ChildWorkReady { .. }
            if row.child_step.is_some() =>
                Some(QueuedCallbackRootAction::ResumeRecordedStep(selector)),
        component_scheduler::HostedPumpRestore::ChildWorkReady { .. } =>
            Some(QueuedCallbackRootAction::NeedsChild(selector)),
        component_scheduler::HostedPumpRestore::ChildWorkPending(pending)
            if pending.retryable() =>
                Some(QueuedCallbackRootAction::RetryRestore(selector)),
        _ => None,
    }
}

pub(crate) unsafe fn queued_callback_file_floor(
    selector: QueuedCallbackSelector,
) -> Option<u64> {
    let row = (&*core::ptr::addr_of!(CLAIMS)).get(selector.index)?.as_ref()?;
    (row.sequence == selector.sequence && row.claim.invocation() == selector.key
        && (row.terminal_ack.is_some_and(|terminal| terminal.physical == selector.physical)
            || row.pump.as_ref().and_then(|pump| pump.child_work_identity())
                == Some(selector.physical)))
        .then_some(row.file_floor)
}

/// Consume one root-issued child observation. NoReady entered no effect and leaves the
/// exact parent parked until a real local child can run on a later root turn.
pub(crate) unsafe fn record_queued_callback_child_step(
    selector: QueuedCallbackSelector,
    step: crate::service_sec_image::NestedChildStep,
) -> QueuedCallbackProgress {
    let rows = &mut *core::ptr::addr_of_mut!(CLAIMS);
    if let Some(row) = rows.get_mut(selector.index).and_then(Option::as_mut) {
        if row.sequence == selector.sequence && row.claim.invocation() == selector.key
            && !row.resuming && row.child_step.is_none()
            && row.pump.as_ref().and_then(|pump| pump.child_work_identity())
                == Some(selector.physical)
            && matches!(row.pump.as_ref(),
                Some(component_scheduler::HostedPumpRestore::ChildWorkReady { .. }))
        {
            if !step.ran_child() {
                return QueuedCallbackProgress::AwaitingLocalChild;
            }
            row.child_step = Some(step);
            return QueuedCallbackProgress::RecordedStep;
        }
    }
    if step.ran_child() {
        (&mut *core::ptr::addr_of_mut!(ORPHANED_STEPS)).push(step);
    }
    QueuedCallbackProgress::Blocked
}

pub(crate) unsafe fn unsettled_queued_callback() -> bool {
    !(&*core::ptr::addr_of!(ORPHANED_PUMPS)).is_empty()
        || !(&*core::ptr::addr_of!(ORPHANED_STEPS)).is_empty()
        || (&*core::ptr::addr_of!(CLAIMS)).iter().flatten()
            .any(|row| row.pump.is_some() || row.resuming)
}

fn same_selector(row: &Row, selector: QueuedCallbackSelector) -> bool {
    row.sequence == selector.sequence && row.claim.invocation() == selector.key
        && row.pump.as_ref().and_then(|pump| pump.child_work_identity())
            == Some(selector.physical)
}

unsafe fn retain_result(
    selector: QueuedCallbackSelector, pump: component_scheduler::HostedPumpRestore,
) -> QueuedCallbackProgress {
    if let Some(row) = (&mut *core::ptr::addr_of_mut!(CLAIMS))
        .get_mut(selector.index).and_then(Option::as_mut)
    {
        if row.sequence == selector.sequence && row.claim.invocation() == selector.key
            && row.resuming && row.pump.is_none()
        {
            let progress = match &pump {
                component_scheduler::HostedPumpRestore::ChildWorkReady { .. } =>
                    QueuedCallbackProgress::NeedsChild,
                component_scheduler::HostedPumpRestore::ChildWorkPending(pending)
                    if pending.retryable() => QueuedCallbackProgress::PendingRestore,
                _ => QueuedCallbackProgress::Blocked,
            };
            row.pump = Some(pump);
            row.resuming = false;
            return progress;
        }
    }
    (&mut *core::ptr::addr_of_mut!(ORPHANED_PUMPS)).push(pump);
    QueuedCallbackProgress::Blocked
}

unsafe fn terminal_physical_bound(
    selector: QueuedCallbackSelector, inst: DriverInstance,
) -> bool {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let Some(domain) = instance_domain_identity(inst) else { return false; };
    let Ok(source) = runtime::physical_source(selector.physical.route) else { return false; };
    inst.hosted_domain_id == selector.key.domain_id
        && inst.hosted_domain_cookie == selector.key.domain_cookie
        && inst.tcb == selector.physical.tcb && inst.pml4 == selector.physical.pml4
        && inst.exec_shared_va == selector.physical.shared_va
        && hosted_ingress_sources::primary_route(selector.index) == Some(selector.physical.route)
        && source.domain == runtime::PhysicalDomain::Hosted(domain)
        && source.kind == runtime::PhysicalSourceKind::Primary
        && source.tcb == selector.physical.tcb && source.pml4 == selector.physical.pml4
}

unsafe fn finish_returned_callback(
    selector: QueuedCallbackSelector, pr: crate::spawn_hosts::PumpResult,
) -> QueuedCallbackProgress {
    let Some(inst) = instance(selector.index) else {
        return retain_result(selector,
            component_scheduler::HostedPumpRestore::Restored(pr));
    };
    if !terminal_physical_bound(selector, inst) || pr.reply_cap == 0 || !pr.completed
    {
        register_instance_ready(selector.index, false);
        return retain_result(selector,
            component_scheduler::HostedPumpRestore::Restored(pr));
    }
    let shared = inst.exec_shared_va;
    let status = read_volatile((shared + SH_REQ_STATUS) as *const i32);
    let ndis = (&*core::ptr::addr_of!(CLAIMS)).get(selector.index)
        .and_then(Option::as_ref).and_then(|row| row.ndis);
    if status != STATUS_SUCCESS {
        if let Some(dispatch) = ndis {
            mark_hosted_provider_ndis_work_item_dispatch_indeterminate(dispatch);
        }
        if !mark_terminal_ack(selector, status) {
            register_instance_ready(selector.index, false);
            return retain_result(selector,
                component_scheduler::HostedPumpRestore::Restored(pr));
        }
        if !acknowledge_resumed_return(selector) {
            register_instance_ready(selector.index, false);
            return retain_result(selector,
                component_scheduler::HostedPumpRestore::Restored(pr));
        }
        register_instance_ready(selector.index, false);
        return QueuedCallbackProgress::TerminalFailure(status);
    }
    if let Some(dispatch) = ndis {
        if !complete_hosted_provider_ndis_work_item_dispatch(dispatch) {
            register_instance_ready(selector.index, false);
            return retain_result(selector,
                component_scheduler::HostedPumpRestore::Restored(pr));
        }
        if let Some(row) = (&mut *core::ptr::addr_of_mut!(CLAIMS))
            .get_mut(selector.index).and_then(Option::as_mut)
        {
            row.ndis = None;
        }
    }
    if !mark_terminal_ack(selector, STATUS_SUCCESS) {
        register_instance_ready(selector.index, false);
        return retain_result(selector,
            component_scheduler::HostedPumpRestore::Restored(pr));
    }
    if !acknowledge_resumed_return(selector) {
        register_instance_ready(selector.index, false);
        return retain_result(selector,
            component_scheduler::HostedPumpRestore::Restored(pr));
    }
    let total = read_volatile((shared + SH_WORK_QUEUE_DRAINED) as *const u64);
    write_volatile((shared + SH_WORK_QUEUE_DRAINED) as *mut u64,
        total.saturating_add(1));
    QueuedCallbackProgress::Completed
}

/// Run only the already-sealed child receipt, or retry one certified no-effects restore.
/// The root must have settled every generic File owner newer than this queue claim first.
pub(crate) unsafe fn resume_queued_callback_after_file_settlement(
    selector: QueuedCallbackSelector,
) -> QueuedCallbackProgress {
    // A completed callback cannot run another receive. Only the queue claim's no-effects
    // ACK is retryable after its terminal phase was recorded before the first ACK attempt.
    let terminal = {
        let rows = &*core::ptr::addr_of!(CLAIMS);
        let Some(row) = rows.get(selector.index).and_then(Option::as_ref) else {
            return QueuedCallbackProgress::Blocked;
        };
        if row.sequence != selector.sequence || row.claim.invocation() != selector.key
            || rows.iter().flatten().any(|other| other.sequence > row.sequence
                && (other.pump.is_some() || other.resuming))
        { return QueuedCallbackProgress::Blocked; }
        row.terminal_ack.map(|terminal| (terminal, row.file_floor))
    };
    if let Some((terminal, floor)) = terminal {
        if terminal.physical != selector.physical {
            return QueuedCallbackProgress::Blocked;
        }
        if crate::driver_launch::generic_file_pump_unsettled_after(floor) {
            return QueuedCallbackProgress::InnerFilePending;
        }
        let Some(inst) = instance(selector.index) else { return QueuedCallbackProgress::Blocked; };
        if !terminal_physical_bound(selector, inst) {
            return QueuedCallbackProgress::Blocked;
        }
        if !acknowledge_resumed_return(selector) {
            return QueuedCallbackProgress::PendingTerminalAck;
        }
        if terminal.status != STATUS_SUCCESS {
            register_instance_ready(selector.index, false);
            return QueuedCallbackProgress::TerminalFailure(terminal.status);
        }
        let shared = inst.exec_shared_va;
        let total = read_volatile((shared + SH_WORK_QUEUE_DRAINED) as *const u64);
        write_volatile((shared + SH_WORK_QUEUE_DRAINED) as *mut u64,
            total.saturating_add(1));
        return QueuedCallbackProgress::Completed;
    }
    let (floor, has_step, retry) = {
        let rows = &*core::ptr::addr_of!(CLAIMS);
        let Some(row) = rows.get(selector.index).and_then(Option::as_ref) else {
            return QueuedCallbackProgress::Blocked;
        };
        if !same_selector(row, selector)
            || exact_physical_identity(selector.index, row) != Some(selector.physical)
            || rows.iter().flatten().any(|other| other.sequence > row.sequence
                && (other.pump.is_some() || other.resuming))
        { return QueuedCallbackProgress::Blocked; }
        let retry = matches!(row.pump.as_ref(),
            Some(component_scheduler::HostedPumpRestore::ChildWorkPending(pending))
                if pending.retryable());
        (row.file_floor, row.child_step.is_some(), retry)
    };
    if crate::driver_launch::generic_file_pump_unsettled_after(floor) {
        return QueuedCallbackProgress::InnerFilePending;
    }
    if retry && has_step { return QueuedCallbackProgress::Blocked; }
    if !has_step && !retry { return QueuedCallbackProgress::AwaitingLocalChild; }
    let (pump, step) = {
        let Some(row) = (&mut *core::ptr::addr_of_mut!(CLAIMS))
            .get_mut(selector.index).and_then(Option::as_mut) else {
            return QueuedCallbackProgress::Blocked;
        };
        let Some(pump) = row.pump.take() else { return QueuedCallbackProgress::Blocked; };
        row.resuming = true;
        (pump, row.child_step.take())
    };
    let next = if retry {
        component_scheduler::retry_child_work(pump)
    } else {
        let Some(step) = step else { return retain_result(selector, pump); };
        match component_scheduler::resume_child_work(pump, step) {
            Ok(next) => next,
            Err((pump, step)) => {
                if let Some(row) = (&mut *core::ptr::addr_of_mut!(CLAIMS))
                    .get_mut(selector.index).and_then(Option::as_mut)
                {
                    if row.sequence == selector.sequence && row.claim.invocation() == selector.key
                        && row.pump.is_none() && row.child_step.is_none()
                    {
                        row.pump = Some(pump);
                        row.child_step = Some(step);
                        row.resuming = false;
                        return QueuedCallbackProgress::Blocked;
                    }
                }
                (&mut *core::ptr::addr_of_mut!(ORPHANED_PUMPS)).push(pump);
                (&mut *core::ptr::addr_of_mut!(ORPHANED_STEPS)).push(step);
                return QueuedCallbackProgress::Blocked;
            }
        }
    };
    match next {
        component_scheduler::HostedPumpRestore::Restored(pr) =>
            finish_returned_callback(selector, pr),
        retained => retain_result(selector, retained),
    }
}
