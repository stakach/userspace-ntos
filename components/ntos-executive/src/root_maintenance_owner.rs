//! Durable physical owner for one root-maintenance win32k syscall yield.
//!
//! A slot is storage, not authority. Every access checks route generation, dispatch epoch,
//! original Reply, and provider/caller owner. Dropping a ticket does not release a native hold.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_component_suspension::peer_registry::PeerRoute;
use nt_component_suspension::{LaneDispatchIdentity, SuspensionKey, SuspensionOwner,
    SuspensionKind, SuspensionPhase, TerminalIdentity};

use crate::spawn_hosts::shared_ingress::owner::runtime::physical_hold::PhysicalExecutionHold;
use super::{component_callback_transfer::CallbackTransfer, ComponentNativeContinuation};
use crate::win32k_glue::{PendingRootMaintenanceDispatch, ProviderWaitPumpCompletion,
    RootMaintenancePumpCompletion, RootMaintenancePumpReturn};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootMaintenanceTicket {
    pub(crate) index: usize,
    pub(crate) generation: u64,
    pub(crate) route: PeerRoute,
    pub(crate) dispatch: LaneDispatchIdentity,
    /// The current authenticated provider Reply after any interim Call adoption.
    pub(crate) reply: u64,
    /// Immutable Reply captured with the original receive-half continuation.
    pub(crate) origin_reply: u64,
    /// The original hosted syscall Reply held by the root's return target.
    pub(crate) root_reply: u64,
    pub(crate) owner: SuspensionOwner,
}

#[derive(Clone, Copy)]
pub(crate) struct RootMaintenanceReservation(usize);

#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Retained,
    Admitted,
    Resuming,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootMaintenanceTransferKind {
    Terminal,
    CallbackTerminal,
    Provider,
    Lpc,
    Receive,
    ServiceWait,
    RootMaintenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootMaintenanceAcceptedTransfer {
    Terminal(TerminalIdentity),
    Frame(SuspensionKey),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootMaintenanceTransferPhase {
    Returned,
    Entering { kind: RootMaintenanceTransferKind, key: SuspensionKey },
    Transferred { kind: RootMaintenanceTransferKind, accepted: RootMaintenanceAcceptedTransfer },
    Indeterminate,
}

#[derive(Clone, Copy)]
struct PostPump {
    result: RootMaintenancePumpCompletion,
    phase: RootMaintenanceTransferPhase,
}

struct Row {
    generation: u64,
    pending: PendingRootMaintenanceDispatch,
    active_reply: u64,
    root_reply: u64,
    physical: PhysicalExecutionHold,
    continuation: Option<ComponentNativeContinuation>,
    callback: Option<CallbackTransfer>,
    post_pump: Option<PostPump>,
    callback_token: Option<u64>,
    next_repark: Option<RootMaintenanceTicket>,
    key: Option<SuspensionKey>,
    state: State,
}

enum Slot {
    Reserved,
    Active(Row),
}

static mut ROWS: Vec<Option<Slot>> = Vec::new();
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_READY_CURSOR: AtomicU64 = AtomicU64::new(0);

/// Reserve storage before consuming the sole pending snapshot. A failed allocation leaves that
/// snapshot and its original Reply in the win32k pending cell.
pub(crate) unsafe fn reserve_capacity() -> Option<RootMaintenanceReservation> {
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    if let Some(index) = rows.iter().position(Option::is_none) {
        rows[index] = Some(Slot::Reserved);
        return Some(RootMaintenanceReservation(index));
    }
    let _durable = crate::allocator::enter_durable();
    rows.try_reserve(1).ok()?;
    let index = rows.len();
    rows.push(Some(Slot::Reserved));
    Some(RootMaintenanceReservation(index))
}

pub(crate) unsafe fn cancel_reservation(reservation: RootMaintenanceReservation) {
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    if let Some(slot @ Some(Slot::Reserved)) = rows.get_mut(reservation.0) {
        *slot = None;
    }
}

/// Transfer the captured snapshot into a durable row. No physical operation has entered yet.
pub(crate) unsafe fn retain(
    reservation: RootMaintenanceReservation,
    pending: PendingRootMaintenanceDispatch,
    root_reply: u64,
) -> Result<RootMaintenanceTicket, PendingRootMaintenanceDispatch> {
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    let Some(slot @ Some(Slot::Reserved)) = rows.get_mut(reservation.0) else {
        return Err(pending);
    };
    let generation = NEXT_GENERATION.fetch_update(
        Ordering::AcqRel, Ordering::Acquire, |next| next.checked_add(1),
    ).map_err(|_| pending)?;
    let yielded = pending.yielded;
    let ticket = RootMaintenanceTicket {
        index: reservation.0,
        generation,
        route: yielded.route,
        dispatch: yielded.dispatch,
        reply: yielded.reply,
        origin_reply: yielded.reply,
        root_reply,
        owner: yielded.owner,
    };
    *slot = Some(Slot::Active(Row {
        generation,
        pending,
        active_reply: yielded.reply,
        root_reply,
        physical: PhysicalExecutionHold::new(yielded.route, yielded.dispatch),
        continuation: None,
        callback: None,
        post_pump: None,
        callback_token: None,
        next_repark: None,
        key: None,
        state: State::Retained,
    }));
    Ok(ticket)
}

fn row_matches(ticket: RootMaintenanceTicket, row: &Row) -> bool {
    let yielded = row.pending.yielded;
    row.generation == ticket.generation
        && yielded.route == ticket.route
        && yielded.dispatch == ticket.dispatch
        && yielded.reply == ticket.origin_reply
        && row.pending.snapshot.pump.reply_cap == ticket.origin_reply
        && row.active_reply == ticket.reply
        && row.root_reply == ticket.root_reply
        && yielded.owner == ticket.owner
}

unsafe fn row(ticket: RootMaintenanceTicket) -> Option<&'static Row> {
    let Some(Some(Slot::Active(row))) = (&*core::ptr::addr_of!(ROWS)).get(ticket.index) else {
        return None;
    };
    row_matches(ticket, row).then_some(row)
}

unsafe fn row_mut(ticket: RootMaintenanceTicket) -> Option<&'static mut Row> {
    let Some(Some(Slot::Active(row))) = (&mut *core::ptr::addr_of_mut!(ROWS)).get_mut(ticket.index) else {
        return None;
    };
    row_matches(ticket, row).then_some(row)
}

pub(crate) unsafe fn pending(ticket: RootMaintenanceTicket) -> Option<PendingRootMaintenanceDispatch> {
    row(ticket).map(|row| row.pending)
}

pub(crate) unsafe fn key(ticket: RootMaintenanceTicket) -> Option<SuspensionKey> {
    row(ticket)?.key
}

/// The closure must not retain this mutable reference across a callback. The row itself
/// remains stored before and after every native effect, including uncertain results.
pub(crate) unsafe fn with_physical<T>(
    ticket: RootMaintenanceTicket,
    use_hold: impl FnOnce(&mut PhysicalExecutionHold) -> T,
) -> Option<T> {
    let row = row_mut(ticket)?;
    Some(use_hold(&mut row.physical))
}

pub(crate) unsafe fn store_continuation(
    ticket: RootMaintenanceTicket,
    continuation: ComponentNativeContinuation,
) -> bool {
    let Some(row) = row_mut(ticket) else { return false; };
    if row.state != State::Retained || row.continuation.is_some() { return false; }
    row.continuation = Some(continuation);
    true
}

pub(crate) unsafe fn take_continuation(
    ticket: RootMaintenanceTicket,
) -> Option<ComponentNativeContinuation> {
    let row = row_mut(ticket)?;
    if row.state != State::Retained { return None; }
    row.continuation.take()
}

pub(crate) unsafe fn restore_continuation(
    ticket: RootMaintenanceTicket,
    continuation: ComponentNativeContinuation,
) -> bool {
    store_continuation(ticket, continuation)
}

pub(crate) unsafe fn mark_admitted(
    ticket: RootMaintenanceTicket,
    key: SuspensionKey,
) -> bool {
    let Some(row) = row_mut(ticket) else { return false; };
    if row.state != State::Retained || row.key.is_some() || row.continuation.is_some()
        || key.kind != nt_component_suspension::SuspensionKind::RootMaintenance {
        return false;
    }
    row.key = Some(key);
    row.state = State::Admitted;
    true
}

pub(crate) unsafe fn is_admitted(ticket: RootMaintenanceTicket) -> bool {
    row(ticket).is_some_and(|row| matches!(row.state, State::Admitted | State::Resuming))
}

/// Select an admitted checkpoint for a later outer turn after a Busy refusal. Selection does
/// not begin resume or touch the native hold; exact route and lane identities are checked again
/// by the caller before any effect. Resuming rows are never selected for possible replay.
pub(crate) unsafe fn next_ready_ticket() -> Option<RootMaintenanceTicket> {
    let rows = &*core::ptr::addr_of!(ROWS);
    if rows.is_empty() { return None; }
    let start = (NEXT_READY_CURSOR.fetch_add(1, Ordering::Relaxed) as usize) % rows.len();
    let lanes = &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS);
    for offset in 0..rows.len() {
        let index = (start + offset) % rows.len();
        let Some(Slot::Active(row)) = rows[index].as_ref() else { continue; };
        if row.state != State::Admitted || !row.physical.held() {
            continue;
        }
        let Some(key) = row.key else { continue; };
        let yielded = row.pending.yielded;
        let lane = yielded.dispatch.lane();
        if lanes.phase(lane) != Ok(nt_component_suspension::LanePhase::Suspended)
            || lanes.active_dispatch_identity(lane) != Ok(Some(yielded.dispatch))
            || !lanes.peer_route(lane).is_ok_and(|route| route == Some(yielded.route))
            || !lanes.binding(lane).is_ok_and(|binding| binding.reply_object == yielded.reply)
        {
            continue;
        }
        let Some(frame) = lanes.frame(lane, key).ok().flatten() else { continue; };
        if frame.key != key || frame.owner != yielded.owner
            || !matches!(&frame.phase,
                nt_component_suspension::SuspensionPhase::MaintenanceReady { observed_pass }
                    if *observed_pass > yielded.captured_pass)
        {
            continue;
        }
        return Some(RootMaintenanceTicket {
            index,
            generation: row.generation,
            route: yielded.route,
            dispatch: yielded.dispatch,
            reply: row.active_reply,
            origin_reply: yielded.reply,
            root_reply: row.root_reply,
            owner: yielded.owner,
        });
    }
    None
}

/// Return a stored native result for reconciliation. Entering and Indeterminate rows are not
/// candidates: a pure effect may already have occurred and selecting them could replay it.
pub(crate) unsafe fn next_returned_ticket() -> Option<RootMaintenanceTicket> {
    let rows = &*core::ptr::addr_of!(ROWS);
    if rows.is_empty() { return None; }
    let start = (NEXT_READY_CURSOR.fetch_add(1, Ordering::Relaxed) as usize) % rows.len();
    let lanes = &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS);
    for offset in 0..rows.len() {
        let index = (start + offset) % rows.len();
        let Some(Slot::Active(row)) = rows[index].as_ref() else { continue; };
        if row.state != State::Resuming { continue; }
        let Some(owned) = row.post_pump else { continue; };
        if result_kind(owned.result).is_none() { continue; }
        let Some(old_key) = row.key else { continue; };
        let yielded = row.pending.yielded;
        let lane = yielded.dispatch.lane();
        let ticket = RootMaintenanceTicket {
            index, generation: row.generation, route: yielded.route,
            dispatch: yielded.dispatch, reply: row.active_reply,
            origin_reply: yielded.reply,
            root_reply: row.root_reply, owner: yielded.owner,
        };
        if lanes.active_dispatch_identity(lane) != Ok(Some(yielded.dispatch))
            || !lanes.peer_route(lane).is_ok_and(|route| route == Some(yielded.route))
            || !lanes.binding(lane).is_ok_and(|binding| binding.reply_object == row.active_reply)
        { continue; }
        let actionable = match owned.phase {
            RootMaintenanceTransferPhase::Returned => match result_kind(owned.result) {
                Some(RootMaintenanceTransferKind::ServiceWait) =>
                    returned_service_wait_external_is_exact(ticket, owned.result),
                Some(RootMaintenanceTransferKind::Receive) =>
                    returned_receive_parent_is_exact(ticket, owned.result),
                Some(_) => lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Running)
                    && lanes.frame(lane, old_key).ok().flatten().is_some_and(|frame| {
                        frame.key == old_key && frame.owner == yielded.owner
                            && matches!(&frame.phase, SuspensionPhase::MaintenanceResuming { .. })
                    }),
                None => false,
            },
            RootMaintenanceTransferPhase::Transferred { kind, accepted } => match accepted {
                RootMaintenanceAcceptedTransfer::Terminal(identity) =>
                    result_kind(owned.result) == Some(kind)
                        && matches!(kind, RootMaintenanceTransferKind::Terminal
                            | RootMaintenanceTransferKind::CallbackTerminal)
                        && identity.lane() == lane && identity.key() == old_key
                        && identity.owner() == yielded.owner
                        && lanes.terminal(identity, row.active_reply).is_ok_and(|terminal| {
                            matches!(terminal.phase,
                                nt_component_suspension::TerminalPhase::Ready { .. }
                                | nt_component_suspension::TerminalPhase::Acknowledged { .. })
                        }),
                RootMaintenanceAcceptedTransfer::Frame(next_key) =>
                    result_kind(owned.result) == Some(kind)
                        && next_key.kind == expected_key_kind(kind)
                        && !matches!(kind, RootMaintenanceTransferKind::Terminal
                            | RootMaintenanceTransferKind::CallbackTerminal)
                        && (if kind == RootMaintenanceTransferKind::Receive {
                            transferred_receive_parent_is_exact(ticket, owned.result, next_key)
                        } else {
                            lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Suspended)
                        })
                        && lanes.frame(lane, next_key).ok().flatten().is_some_and(|frame| {
                            frame.key == next_key && frame.owner == yielded.owner
                        }),
            },
            RootMaintenanceTransferPhase::Entering { .. }
            | RootMaintenanceTransferPhase::Indeterminate => false,
        };
        if !actionable { continue; }
        return Some(ticket);
    }
    None
}

pub(crate) unsafe fn mark_resuming(ticket: RootMaintenanceTicket) -> bool {
    let Some(row) = row_mut(ticket) else { return false; };
    if row.state != State::Admitted { return false; }
    row.state = State::Resuming;
    true
}

pub(crate) unsafe fn is_resuming(ticket: RootMaintenanceTicket) -> bool {
    row(ticket).is_some_and(|row| row.state == State::Resuming)
}

/// A returned native receive half has already performed its physical effects. Keep the exact
/// result in its durable owner so terminal and repark refusals cannot cause a second receive.
pub(crate) unsafe fn result(ticket: RootMaintenanceTicket) -> Option<RootMaintenancePumpCompletion> {
    let row = row(ticket)?;
    if row.state != State::Resuming { return None; }
    row.post_pump.map(|owned| owned.result)
}

pub(crate) unsafe fn store_result(
    ticket: RootMaintenanceTicket,
    returned: RootMaintenancePumpReturn,
) -> Result<RootMaintenanceTicket, RootMaintenancePumpReturn> {
    let Some(row) = row(ticket) else { return Err(returned); };
    if row.state != State::Resuming || row.post_pump.is_some() || returned.reply_cap == 0 {
        return Err(returned);
    }
    let Some(key) = row.key else { return Err(returned); };
    let lanes = &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS);
    let lane = ticket.dispatch.lane();
    if lanes.active_dispatch_identity(lane) != Ok(Some(ticket.dispatch))
        || !lanes.peer_route(lane).is_ok_and(|route| route == Some(ticket.route))
        || !lanes.binding(lane).is_ok_and(|binding| binding.reply_object == returned.reply_cap)
    { return Err(returned); }
    let exact = match returned.completion {
        RootMaintenancePumpCompletion::Restored(_)
        | RootMaintenancePumpCompletion::MaintenanceReparked(_)
        | RootMaintenancePumpCompletion::RetainedFailure(_) =>
            lanes.validate_root_maintenance_return_reply(
                ticket.route, ticket.dispatch, key, ticket.owner, returned.reply_cap,
            ).is_ok(),
        RootMaintenancePumpCompletion::ServiceReparked(next) =>
            next.yielded.route == ticket.route
                && next.yielded.dispatch == ticket.dispatch
                && next.yielded.token != 0
                && next.yielded.reply == returned.reply_cap
                && next.snapshot.pump.reply_cap == returned.reply_cap,
        RootMaintenancePumpCompletion::ReceiveReparked(next) =>
            next.yielded.parent.route() == ticket.route
                && next.yielded.parent.dispatch() == ticket.dispatch
                && next.yielded.owner == ticket.owner
                && next.snapshot.pump.reply_cap == returned.reply_cap,
    };
    if !exact { return Err(returned); }
    // The captured continuation and its original Reply remain immutable provenance. Publish
    // the authenticated current Reply and returned result in one no-effect owner transition.
    let Some(row) = row_mut(ticket) else { return Err(returned); };
    row.active_reply = returned.reply_cap;
    row.post_pump = Some(PostPump { result: returned.completion,
        phase: RootMaintenanceTransferPhase::Returned });
    Ok(RootMaintenanceTicket { reply: returned.reply_cap, ..ticket })
}

fn result_kind(result: RootMaintenancePumpCompletion) -> Option<RootMaintenanceTransferKind> {
    use RootMaintenancePumpCompletion as Pump;
    use ProviderWaitPumpCompletion as Provider;
    Some(match result {
        Pump::Restored(Provider::Completed(_)) => RootMaintenanceTransferKind::Terminal,
        Pump::Restored(Provider::UserCallbackSuspended) =>
            RootMaintenanceTransferKind::CallbackTerminal,
        Pump::Restored(Provider::Reparked(_)) => RootMaintenanceTransferKind::Provider,
        Pump::Restored(Provider::LpcReparked(_)) => RootMaintenanceTransferKind::Lpc,
        Pump::ReceiveReparked(_) => RootMaintenanceTransferKind::Receive,
        Pump::ServiceReparked(_) => RootMaintenanceTransferKind::ServiceWait,
        Pump::MaintenanceReparked(_) => RootMaintenanceTransferKind::RootMaintenance,
        Pump::Restored(Provider::Failed(_) | Provider::ReceiveReparked(_)
            | Provider::ServiceReparked(_)) | Pump::RetainedFailure(_) => return None,
    })
}

fn expected_key_kind(kind: RootMaintenanceTransferKind) -> SuspensionKind {
    match kind {
        RootMaintenanceTransferKind::Terminal | RootMaintenanceTransferKind::CallbackTerminal
        | RootMaintenanceTransferKind::RootMaintenance => SuspensionKind::RootMaintenance,
        RootMaintenanceTransferKind::Provider => SuspensionKind::ProviderWait,
        RootMaintenanceTransferKind::Lpc => SuspensionKind::LpcRequest,
        RootMaintenanceTransferKind::Receive => SuspensionKind::Receive,
        RootMaintenanceTransferKind::ServiceWait => SuspensionKind::ServiceWait,
    }
}

fn returned_service_wait_external_is_exact(
    ticket: RootMaintenanceTicket,
    result: RootMaintenancePumpCompletion,
) -> bool {
    let RootMaintenancePumpCompletion::ServiceReparked(next) = result else { return false; };
    let yielded = next.yielded;
    let Some(old_key) = (unsafe { row(ticket) }).and_then(|row| row.key) else { return false; };
    let lanes = unsafe { &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS) };
    let lane = ticket.dispatch.lane();
    yielded.token != 0
        && yielded.route == ticket.route
        && yielded.dispatch == ticket.dispatch
        && yielded.reply == ticket.reply
        && lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Suspended)
        && lanes.external_top(lane) == Ok(Some(yielded.token))
        && lanes.frame(lane, old_key).ok().flatten().is_some_and(|frame| {
            frame.key == old_key && frame.owner == ticket.owner
                && matches!(&frame.phase, SuspensionPhase::MaintenanceResuming { .. })
        })
}

fn returned_receive_parent_is_exact(
    ticket: RootMaintenanceTicket,
    result: RootMaintenancePumpCompletion,
) -> bool {
    let RootMaintenancePumpCompletion::ReceiveReparked(next) = result else { return false; };
    let parent = next.yielded.parent;
    let Some(old_key) = (unsafe { row(ticket) }).and_then(|row| row.key) else { return false; };
    let lanes = unsafe { &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS) };
    let lane = ticket.dispatch.lane();
    parent.route() == ticket.route && parent.dispatch() == ticket.dispatch
        && next.yielded.owner == ticket.owner
        && next.yielded.replaces == Some(old_key)
        && next.snapshot.pump.reply_cap == ticket.reply
        && lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::NestedExecution(parent.sequence()))
        && unsafe { crate::spawn_hosts::shared_ingress::owner::runtime::with_bound_receive_scope(
            parent, |scope| Ok(scope.identity() == parent && !scope.is_consumed()
                && scope.route() == ticket.route && scope.dispatch() == ticket.dispatch),
        ) }.ok() == Some(true)
        && lanes.frame(lane, old_key).ok().flatten().is_some_and(|frame| {
            frame.key == old_key && frame.owner == ticket.owner
                && matches!(&frame.phase, SuspensionPhase::MaintenanceResuming { .. })
        })
}

fn transferred_receive_parent_is_exact(
    ticket: RootMaintenanceTicket,
    result: RootMaintenancePumpCompletion,
    next_key: SuspensionKey,
) -> bool {
    let RootMaintenancePumpCompletion::ReceiveReparked(next) = result else { return false; };
    let parent = next.yielded.parent;
    let lanes = unsafe { &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS) };
    let lane = ticket.dispatch.lane();
    parent.route() == ticket.route && parent.dispatch() == ticket.dispatch
        && next.yielded.owner == ticket.owner
        && next.snapshot.pump.reply_cap == ticket.reply
        && lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::NestedExecution(parent.sequence()))
        && unsafe { crate::spawn_hosts::shared_ingress::owner::runtime::with_bound_receive_scope(
            parent, |scope| Ok(scope.identity() == parent && !scope.is_consumed()),
        ) }.ok() == Some(true)
        && lanes.frame(lane, next_key).ok().flatten().is_some_and(|frame| {
            frame.key == next_key && frame.owner == ticket.owner
                && matches!(&frame.phase, SuspensionPhase::Waiting)
        })
}

pub(crate) unsafe fn transfer_phase(
    ticket: RootMaintenanceTicket,
) -> Option<RootMaintenanceTransferPhase> {
    let row = row(ticket)?;
    if row.state != State::Resuming { return None; }
    Some(row.post_pump?.phase)
}

/// Record exact intended kind and key before entering any pure terminal or repark operation.
pub(crate) unsafe fn begin_result_transfer(
    ticket: RootMaintenanceTicket,
    kind: RootMaintenanceTransferKind,
    next_key: SuspensionKey,
) -> bool {
    if !next_key.is_valid() { return false; }
    let Some(row) = row(ticket) else { return false; };
    let Some(owned) = row.post_pump else { return false; };
    if row.state != State::Resuming || owned.phase != RootMaintenanceTransferPhase::Returned
        || result_kind(owned.result) != Some(kind)
    { return false; }
    let expected = expected_key_kind(kind);
    if next_key.kind != expected
        || matches!(kind, RootMaintenanceTransferKind::Terminal
            | RootMaintenanceTransferKind::CallbackTerminal
            | RootMaintenanceTransferKind::RootMaintenance)
            && row.key != Some(next_key)
    { return false; }
    let Some(old_key) = row.key else { return false; };
    let lanes = &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS);
    let lane = ticket.dispatch.lane();
    let old_phase_exact = match kind {
        RootMaintenanceTransferKind::ServiceWait =>
            returned_service_wait_external_is_exact(ticket, owned.result),
        RootMaintenanceTransferKind::Receive =>
            returned_receive_parent_is_exact(ticket, owned.result),
        _ => lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Running),
    };
    if !old_phase_exact
        || lanes.active_dispatch_identity(lane) != Ok(Some(ticket.dispatch))
        || !lanes.peer_route(lane).is_ok_and(|route| route == Some(ticket.route))
        || !lanes.binding(lane).is_ok_and(|binding| binding.reply_object == ticket.reply)
        || !lanes.frame(lane, old_key).ok().flatten().is_some_and(|frame| {
            frame.key == old_key && frame.owner == ticket.owner
                && matches!(&frame.phase, SuspensionPhase::MaintenanceResuming { .. })
        })
    { return false; }
    let Some(row) = row_mut(ticket) else { return false; };
    let Some(owned) = row.post_pump.as_mut() else { return false; };
    if owned.phase != RootMaintenanceTransferPhase::Returned { return false; }
    owned.phase = RootMaintenanceTransferPhase::Entering { kind, key: next_key };
    true
}

/// Only a proven pure no-effect refusal can return to the stored result for another attempt.
pub(crate) unsafe fn refuse_result_transfer_no_effects(ticket: RootMaintenanceTicket) -> bool {
    let Some(row) = row(ticket) else { return false; };
    let Some(owned) = row.post_pump else { return false; };
    if row.state != State::Resuming
        || !matches!(owned.phase, RootMaintenanceTransferPhase::Entering { .. })
    { return false; }
    let Some(key) = row.key else { return false; };
    let lanes = &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS);
    let lane = ticket.dispatch.lane();
    let old_phase_exact = match result_kind(owned.result) {
        Some(RootMaintenanceTransferKind::ServiceWait) =>
            returned_service_wait_external_is_exact(ticket, owned.result),
        Some(RootMaintenanceTransferKind::Receive) =>
            returned_receive_parent_is_exact(ticket, owned.result),
        Some(_) => lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Running),
        None => false,
    };
    if !old_phase_exact
        || lanes.active_dispatch_identity(lane) != Ok(Some(ticket.dispatch))
        || !lanes.peer_route(lane).is_ok_and(|route| route == Some(ticket.route))
        || !lanes.binding(lane).is_ok_and(|binding| binding.reply_object == ticket.reply)
        || lanes.terminal_identities().any(|identity| identity.lane() == lane)
        || !lanes.frame(lane, key).ok().flatten().is_some_and(|frame| {
            frame.key == key && frame.owner == ticket.owner
                && matches!(&frame.phase, SuspensionPhase::MaintenanceResuming { .. })
        })
    { return false; }
    let Some(row) = row_mut(ticket) else { return false; };
    let Some(owned) = row.post_pump.as_mut() else { return false; };
    if !matches!(owned.phase, RootMaintenanceTransferPhase::Entering { .. }) { return false; }
    owned.phase = RootMaintenanceTransferPhase::Returned;
    true
}

/// The accepted identity is retained before subsequent owner retirement or backend admission.
pub(crate) unsafe fn accept_result_transfer(
    ticket: RootMaintenanceTicket,
    accepted: RootMaintenanceAcceptedTransfer,
) -> bool {
    let Some(row) = row_mut(ticket) else { return false; };
    let Some(owned) = row.post_pump.as_mut() else { return false; };
    let RootMaintenanceTransferPhase::Entering { kind, key } = owned.phase else { return false; };
    if row.state != State::Resuming { return false; }
    let lanes = &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS);
    let lane = ticket.dispatch.lane();
    if lanes.active_dispatch_identity(lane) != Ok(Some(ticket.dispatch))
        || !lanes.peer_route(lane).is_ok_and(|route| route == Some(ticket.route))
        || !lanes.binding(lane).is_ok_and(|binding| binding.reply_object == ticket.reply)
    { return false; }
    let accepted_exact = match accepted {
        RootMaintenanceAcceptedTransfer::Terminal(identity) => {
            matches!(kind, RootMaintenanceTransferKind::Terminal
                | RootMaintenanceTransferKind::CallbackTerminal)
                && identity.lane() == lane && identity.key() == key
                && identity.owner() == ticket.owner
                && lanes.terminal(identity, ticket.reply).is_ok()
        }
        RootMaintenanceAcceptedTransfer::Frame(next_key) => {
            !matches!(kind, RootMaintenanceTransferKind::Terminal
                | RootMaintenanceTransferKind::CallbackTerminal)
                && next_key == key
                && (if kind == RootMaintenanceTransferKind::Receive {
                    transferred_receive_parent_is_exact(ticket, owned.result, next_key)
                } else {
                    lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Suspended)
                })
                && lanes.frame(lane, key).ok().flatten().is_some_and(|frame| {
                    frame.key == key && frame.owner == ticket.owner
                        && (kind != RootMaintenanceTransferKind::RootMaintenance
                            || matches!(&frame.phase, SuspensionPhase::MaintenanceWaiting { .. }))
                })
        }
    };
    if !accepted_exact { return false; }
    owned.phase = RootMaintenanceTransferPhase::Transferred { kind, accepted };
    true
}

pub(crate) unsafe fn mark_result_transfer_indeterminate(ticket: RootMaintenanceTicket) -> bool {
    let Some(row) = row_mut(ticket) else { return false; };
    let Some(owned) = row.post_pump.as_mut() else { return false; };
    if row.state != State::Resuming
        || !matches!(owned.phase, RootMaintenanceTransferPhase::Entering { .. })
    { return false; }
    owned.phase = RootMaintenanceTransferPhase::Indeterminate;
    true
}

/// Capturing a callback may consume native state. Retain its token across a typed terminal
/// refusal so retry publishes the same callback rather than capturing it again.
pub(crate) unsafe fn callback_token(ticket: RootMaintenanceTicket) -> Option<u64> {
    let row = row(ticket)?;
    if row.state != State::Resuming { return None; }
    row.callback_token
}

pub(crate) unsafe fn store_callback_token(ticket: RootMaintenanceTicket, token: u64) -> bool {
    let Some(row) = row_mut(ticket) else { return false; };
    if row.state != State::Resuming || row.callback_token.is_some() || token == 0 {
        return false;
    }
    row.callback_token = Some(token);
    true
}

fn same_repark_pending(a: PendingRootMaintenanceDispatch, b: PendingRootMaintenanceDispatch) -> bool {
    a.yielded.route == b.yielded.route
        && a.yielded.dispatch == b.yielded.dispatch
        && a.yielded.reply == b.yielded.reply
        && a.yielded.owner == b.yielded.owner
        && a.yielded.captured_pass == b.yielded.captured_pass
        && a.snapshot.dispatch.lane == b.snapshot.dispatch.lane
        && a.snapshot.dispatch.dispatch_id == b.snapshot.dispatch.dispatch_id
        && a.snapshot.client.pi == b.snapshot.client.pi
        && a.snapshot.client.generation == b.snapshot.client.generation
        && a.snapshot.client.tid == b.snapshot.client.tid
        && a.snapshot.client.badge == b.snapshot.client.badge
        && a.snapshot.client.tcb == b.snapshot.client.tcb
        && a.snapshot.channel.tcb == b.snapshot.channel.tcb
        && a.snapshot.channel.fault_ep == b.snapshot.channel.fault_ep
        && a.snapshot.pump.reply_cap == b.snapshot.pump.reply_cap
}

pub(crate) unsafe fn next_repark_ticket(old: RootMaintenanceTicket) -> Option<RootMaintenanceTicket> {
    let old_row = row(old)?;
    let next = old_row.next_repark?;
    let new_row = row(next)?;
    (old_row.state == State::Resuming
        && matches!(new_row.state, State::Retained | State::Admitted)
        && new_row.root_reply == old.root_reply
        && next.route == old.route && next.dispatch == old.dispatch
        && next.reply == old.reply && next.owner == old.owner).then_some(next)
}

/// Reserve and retain the next physical generation before its hold is acquired. A retry returns
/// the same generation-bound ticket, including after a certified no-effects acquire refusal.
pub(crate) unsafe fn prepare_next_repark(
    old: RootMaintenanceTicket,
    next: PendingRootMaintenanceDispatch,
) -> Option<RootMaintenanceTicket> {
    let old_row = row(old)?;
    let Some(owned) = old_row.post_pump else { return None; };
    let RootMaintenancePumpCompletion::MaintenanceReparked(expected) = owned.result else {
        return None;
    };
    if old_row.state != State::Resuming
        || owned.phase != RootMaintenanceTransferPhase::Returned
        || !same_repark_pending(expected, next)
        || next.yielded.route != old.route || next.yielded.dispatch != old.dispatch
        || next.yielded.reply != old.reply || next.yielded.owner != old.owner
    { return None; }
    if let Some(ticket) = old_row.next_repark {
        return (next_repark_ticket(old) == Some(ticket)
            && row(ticket).is_some_and(|new_row| same_repark_pending(new_row.pending, next)))
            .then_some(ticket);
    }
    let reservation = reserve_capacity()?;
    let ticket = match retain(reservation, next, old.root_reply) {
        Ok(ticket) => ticket,
        Err(_) => {
            cancel_reservation(reservation);
            return None;
        }
    };
    // The owner is serialized. Even if the old row unexpectedly disappears, retain the new
    // row and refuse native acquisition; dropping the ticket cannot release a physical effect.
    let Some(old_row) = row_mut(old) else { return None; };
    if old_row.next_repark.is_some() { return None; }
    old_row.next_repark = Some(ticket);
    Some(ticket)
}

/// Store a callback before reading or mutating the shared callback bank. Refusal returns the
/// exact owned transfer; no callback input, parent context, or Reply is discarded.
pub(crate) unsafe fn store_callback(
    ticket: RootMaintenanceTicket,
    callback: CallbackTransfer,
) -> Result<(), CallbackTransfer> {
    let Some(row) = row_mut(ticket) else { return Err(callback); };
    if !matches!(row.state, State::Admitted | State::Resuming) || row.callback.is_some() {
        return Err(callback);
    }
    row.callback = Some(callback);
    Ok(())
}

/// Memory-only access to the row's callback. Native capture/preparation may enter inside the
/// closure; on any failure this row continues to own the transfer and its original Reply.
pub(crate) unsafe fn with_callback<T>(
    ticket: RootMaintenanceTicket,
    use_callback: impl FnOnce(&mut CallbackTransfer) -> T,
) -> Option<T> {
    let row = row_mut(ticket)?;
    if !matches!(row.state, State::Admitted | State::Resuming) { return None; }
    Some(use_callback(row.callback.as_mut()?))
}

/// Transfer only after the typed terminal path has accepted the callback payload. A refusal
/// leaves this row intact so capture or publication is never silently repeated.
pub(crate) unsafe fn take_callback(ticket: RootMaintenanceTicket) -> Option<CallbackTransfer> {
    let row = row_mut(ticket)?;
    if row.state != State::Resuming { return None; }
    row.callback.take()
}

pub(crate) unsafe fn physical_restore_done(ticket: RootMaintenanceTicket) -> bool {
    row(ticket).is_some_and(|row| {
        row.physical.restore_step().ok()
            == Some(nt_user_host::physical_execution_restore::RestoreStep::Done)
    })
}

pub(crate) unsafe fn can_retire(ticket: RootMaintenanceTicket) -> bool {
    row(ticket).is_some_and(|row| row.state == State::Resuming
        && row.callback.is_none()
        && row.post_pump.is_some_and(|owned| {
            matches!(owned.phase, RootMaintenanceTransferPhase::Transferred { .. })
        }))
        && physical_restore_done(ticket)
}

/// Find the still-retained physical row for a returned maintenance continuation. The terminal
/// path may have moved its hosted return target into retirement, so authenticate against the
/// original yielded route, dispatch, component Reply, owner, and captured client/dispatch.
/// Ambiguous matches are refused rather than selecting a slot by numeric index alone.
pub(crate) unsafe fn ticket_for(
    pending: PendingRootMaintenanceDispatch,
) -> Option<RootMaintenanceTicket> {
    let rows = &*core::ptr::addr_of!(ROWS);
    let mut matched = None;
    for (index, slot) in rows.iter().enumerate() {
        let Some(Slot::Active(row)) = slot else { continue; };
        let held = row.pending;
        if row.state != State::Resuming
            || held.yielded.route != pending.yielded.route
            || held.yielded.dispatch != pending.yielded.dispatch
            || held.yielded.reply != pending.yielded.reply
            || held.yielded.owner != pending.yielded.owner
            || held.snapshot.dispatch.lane != pending.snapshot.dispatch.lane
            || held.snapshot.dispatch.dispatch_id != pending.snapshot.dispatch.dispatch_id
            || held.snapshot.client.pi != pending.snapshot.client.pi
            || held.snapshot.client.generation != pending.snapshot.client.generation
            || held.snapshot.client.tid != pending.snapshot.client.tid
            || held.snapshot.client.badge != pending.snapshot.client.badge
            || held.snapshot.client.tcb != pending.snapshot.client.tcb
            || held.snapshot.channel.tcb != pending.snapshot.channel.tcb
            || held.snapshot.channel.fault_ep != pending.snapshot.channel.fault_ep
        {
            continue;
        }
        let ticket = RootMaintenanceTicket {
            index,
            generation: row.generation,
            route: held.yielded.route,
            dispatch: held.yielded.dispatch,
            reply: row.active_reply,
            origin_reply: held.yielded.reply,
            root_reply: row.root_reply,
            owner: held.yielded.owner,
        };
        if matched.is_some() { return None; }
        matched = Some(ticket);
    }
    matched
}

/// Only the terminal ACK path may call this after the exact physical hold is restored. A
/// stale ticket or uncertain release leaves the row retained and cannot recycle its slot.
pub(crate) unsafe fn retire(ticket: RootMaintenanceTicket) -> Option<PendingRootMaintenanceDispatch> {
    if !can_retire(ticket) { return None; }
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    let pending = match rows[ticket.index].take()? {
        Slot::Active(row) => row.pending,
        Slot::Reserved => return None,
    };
    Some(pending)
}

/// A normally resumed pump may enter a real provider/Receive/ServiceWait wait instead of
/// returning to its caller. Retire this checkpoint only after the typed lane has transferred
/// the same dispatch, owner, component Reply, and continuation to that exact new suspension.
pub(crate) unsafe fn retire_after_repark(
    ticket: RootMaintenanceTicket,
    next_key: SuspensionKey,
) -> Option<PendingRootMaintenanceDispatch> {
    if next_key.kind == nt_component_suspension::SuspensionKind::RootMaintenance
        || !next_key.is_valid() || !can_retire(ticket)
    {
        return None;
    }
    let old = row(ticket)?;
    let owned = old.post_pump?;
    if !matches!(owned.phase,
        RootMaintenanceTransferPhase::Transferred {
            accepted: RootMaintenanceAcceptedTransfer::Frame(key), ..
        } if key == next_key)
    { return None; }
    let lane = ticket.dispatch.lane();
    let lanes = &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS);
    let phase_exact = if next_key.kind == SuspensionKind::Receive {
        transferred_receive_parent_is_exact(ticket, owned.result, next_key)
    } else {
        lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Suspended)
    };
    if !phase_exact || lanes.active_dispatch_identity(lane) != Ok(Some(ticket.dispatch))
        || !lanes.peer_route(lane).is_ok_and(|route| route == Some(ticket.route))
        || !lanes.binding(lane).is_ok_and(|binding| binding.reply_object == ticket.reply)
    {
        return None;
    }
    let frame = lanes.frame(lane, next_key).ok()??;
    if frame.key != next_key || frame.owner != ticket.owner { return None; }
    retire(ticket)
}

/// A continued receive half may find another overdue independent task. The new checkpoint must
/// have its own entered physical hold and durable row; a completed hold generation is never
/// re-acquired. Transfer the same pure frame first, then retire only the old restored row.
pub(crate) unsafe fn retire_after_maintenance_repark(
    old: RootMaintenanceTicket,
    new: RootMaintenanceTicket,
) -> Option<PendingRootMaintenanceDispatch> {
    if old.index == new.index
        || old.generation == new.generation
        || old.route != new.route
        || old.dispatch != new.dispatch
        || old.reply != new.reply
        || old.root_reply != new.root_reply
        || old.owner != new.owner
        || !can_retire(old)
    {
        return None;
    }
    let old_row = row(old)?;
    let new_row = row(new)?;
    if old_row.next_repark != Some(new)
        || !matches!(old_row.post_pump?.phase,
            RootMaintenanceTransferPhase::Transferred {
                kind: RootMaintenanceTransferKind::RootMaintenance,
                accepted: RootMaintenanceAcceptedTransfer::Frame(key),
            } if Some(key) == new_row.key)
        || new_row.state != State::Admitted
        || new_row.key.is_none()
        || new_row.key != old_row.key
        || new_row.continuation.is_some()
        || !new_row.physical.held()
        || new_row.physical.restore_step().ok()?
            != nt_user_host::physical_execution_restore::RestoreStep::Canonical
        || old_row.pending.snapshot.dispatch.dispatch_id
            != new_row.pending.snapshot.dispatch.dispatch_id
        || old_row.pending.snapshot.client.pi != new_row.pending.snapshot.client.pi
        || old_row.pending.snapshot.client.generation != new_row.pending.snapshot.client.generation
        || old_row.pending.snapshot.client.tid != new_row.pending.snapshot.client.tid
        || old_row.pending.snapshot.client.badge != new_row.pending.snapshot.client.badge
        || old_row.pending.snapshot.client.tcb != new_row.pending.snapshot.client.tcb
    {
        return None;
    }
    let key = new_row.key?;
    let lane = new.dispatch.lane();
    let lanes = &*core::ptr::addr_of!(super::COMPONENT_SUSPENSIONS);
    if lanes.phase(lane) != Ok(nt_component_suspension::LanePhase::Suspended)
        || lanes.active_dispatch_identity(lane) != Ok(Some(new.dispatch))
        || !lanes.binding(lane).is_ok_and(|binding| binding.reply_object == new.reply)
    {
        return None;
    }
    let frame = lanes.frame(lane, key).ok()??;
    if frame.key != key || frame.owner != new.owner
        || !matches!(&frame.phase,
            nt_component_suspension::SuspensionPhase::MaintenanceWaiting { captured_pass }
                if *captured_pass == new_row.pending.yielded.captured_pass)
    {
        return None;
    }
    retire(old)
}
