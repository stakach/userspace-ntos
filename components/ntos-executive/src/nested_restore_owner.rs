//! Original root Reply and pump continuation retained across a nested parent restore refusal.
//!
//! The ingress owner keeps the physical parent and its Reply. This owner keeps the independent
//! root Reply and the already-entered receive-half snapshot; neither may be inferred from a
//! copied ticket after an outer service turn.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_component_suspension::{NestedRestoreFrame, NestedRestoreKey, NestedRestorePhase,
    NestedRestoreTransferRefusal};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NestedRestoreOwnerTicket {
    index: usize,
    generation: u64,
    key: NestedRestoreKey,
}

impl NestedRestoreOwnerTicket {
    pub(crate) fn key(self) -> NestedRestoreKey { self.key }
}

struct Row {
    generation: u64,
    frame: NestedRestoreFrame<win32k_glue::PendingNestedRestoreDispatch>,
    return_target: HostedReturnTarget<win32k_glue::StagedUserCallbackContext>,
    destination: HostedContinuationDestination,
    root_parked: bool,
    result_entered: bool,
    result: Option<win32k_glue::NestedRestorePumpCompletion>,
    callback_reservation: Option<component_callback_transfer::CallbackTransfer>,
    callback_token: Option<u64>,
    callback_terminal_payload: Option<component_terminal::NativeTerminal>,
    callback_failure: Option<u32>,
    terminal: Option<nt_component_suspension::TerminalIdentity>,
    due_at: u64,
    shared_leases: nt_user_callback::SharedPageLeaseStack<2>,
    displaced_shared_resume: Option<win32k_glue::SharedResumeSnapshot>,
    quarantined_parent_pump: Option<crate::spawn_hosts::PumpResult>,
    quarantined_child_pump: Option<QuarantinedChildPump>,
    quarantined_child_job_result: Option<QuarantinedChildJobResult>,
}

#[allow(dead_code)] // Retained for owner diagnostics and explicit recovery, never replayed.
struct QuarantinedChildPump {
    pump: crate::spawn_hosts::PumpResult,
    channel: crate::spawn_hosts::PumpChannel,
    dispatch: nt_user_callback::DispatchContext,
    client: win32k_glue::Win32kClientContext,
}

#[allow(dead_code)] // A restore refusal retains this completed effect; it is never replayed.
struct QuarantinedChildJobResult {
    result: Result<(u64, bool), u32>,
    dispatch: nt_user_callback::DispatchContext,
    client: win32k_glue::Win32kClientContext,
}

static mut ROWS: Vec<Option<Row>> = Vec::new();
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn exact(row: &Row, ticket: NestedRestoreOwnerTicket) -> bool {
    row.generation == ticket.generation && row.frame.key() == ticket.key
}

fn retain_callback_failure(
    row: &mut Row,
    ticket: NestedRestoreOwnerTicket,
    stage: &[u8],
    status: u32,
) {
    if row.callback_failure.is_some() { return; }
    row.callback_failure = Some(status);
    print_str(b"[nested-restore] callback-retained stage=");
    print_str(stage);
    print_str(b" row/generation=");
    print_u64(ticket.index as u64);
    print_str(b"/");
    print_u64(ticket.generation);
    print_str(b" parent-reply=");
    print_hex_u64(ticket.key.parent_reply());
    print_str(b" root-reply=");
    print_hex_u64(ticket.key.root_reply());
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}

unsafe fn retain_exact_callback_failure(
    ticket: NestedRestoreOwnerTicket,
    stage: &[u8],
    status: u32,
) {
    if let Some(row) = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut)
    {
        if exact(row, ticket) {
            retain_callback_failure(row, ticket, stage, status);
        }
    }
}

/// Reserve storage before the root Reply can be parked. The returned index is only a free slot;
/// no physical or Reply authority has transferred yet.
pub(crate) unsafe fn reserve_capacity() -> Option<usize> {
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    if let Some(index) = rows.iter().position(Option::is_none) {
        return Some(index);
    }
    let _durable = allocator::enter_durable();
    rows.try_reserve(1).ok()?;
    rows.push(None);
    Some(rows.len() - 1)
}

fn expected_owner(
    pending: win32k_glue::PendingNestedRestoreDispatch,
) -> Option<nt_component_suspension::SuspensionOwner> {
    let owner = pending.origin.owner?;
    let client = pending.snapshot.client;
    (owner.is_valid()
        && owner.dispatch_id == pending.snapshot.dispatch.dispatch_id
        && owner.caller == nt_component_suspension::SuspensionCaller::Hosted(
            nt_component_suspension::SuspensionHostedClient {
                client_pi: client.pi,
                client_generation: client.generation,
                client_tid: client.tid,
                client_badge: client.badge,
            },
        ))
        .then_some(owner)
}

/// Move the source snapshot into a durable frame before attempting `RootReplyPark`. A refused
/// preflight returns the unchanged snapshot to the caller. Quarantine is still retained here;
/// its physical ticket can never be selected for a retry.
pub(crate) unsafe fn retain(
    index: usize,
    pending: win32k_glue::PendingNestedRestoreDispatch,
    root_reply: u64,
    destination: HostedContinuationDestination,
    root_already_parked: bool,
) -> Result<NestedRestoreOwnerTicket, win32k_glue::PendingNestedRestoreDispatch> {
    let rows = &*core::ptr::addr_of!(ROWS);
    if !rows.get(index).is_some_and(Option::is_none) { return Err(pending); }
    let (row, key) = prepare_row(pending, root_reply, destination, root_already_parked)?;
    let generation = row.generation;
    (&mut *core::ptr::addr_of_mut!(ROWS))[index] = Some(row);
    Ok(NestedRestoreOwnerTicket { index, generation, key })
}

unsafe fn prepare_row(
    pending: win32k_glue::PendingNestedRestoreDispatch,
    root_reply: u64,
    destination: HostedContinuationDestination,
    root_already_parked: bool,
) -> Result<(Row, NestedRestoreKey), win32k_glue::PendingNestedRestoreDispatch> {
    let Some(parent) = pending.snapshot.pump.nested_restore_yield
        .or(pending.snapshot.pump.nested_restore_quarantined)
    else { return Err(pending); };
    let Some(owner) = expected_owner(pending) else { return Err(pending); };
    let channel = &pending.snapshot.channel;
    let Some(route) = runtime::channel_route(channel).ok().flatten() else {
        return Err(pending);
    };
    let provider = runtime::physical_source(route).ok();
    if !runtime::nested::retained_ticket_matches_channel(
        parent, route, pending.snapshot.pump.reply_cap,
    ) || pending.snapshot.dispatch.lane != route.identity().lane
        || !provider.is_some_and(|physical| matches!(physical.domain,
            runtime::PhysicalDomain::Provider { domain, .. }
                if domain.domain == owner.provider_domain
                    && domain.generation == owner.provider_generation))
        || !win32k_glue::win32k_client_context_is_admitted(pending.snapshot.client)
    {
        return Err(pending);
    }
    let Some(key) = NestedRestoreKey::new(
        parent.identity(), pending.snapshot.pump.reply_cap, root_reply, owner,
    ) else { return Err(pending); };
    let Ok(return_target) = HostedReturnTarget::new(root_reply, None) else {
        return Err(pending);
    };
    let generation = match NEXT_GENERATION.fetch_update(
        Ordering::AcqRel, Ordering::Acquire, |next| next.checked_add(1),
    ) {
        Ok(generation) => generation,
        Err(_) => return Err(pending),
    };
    let mut frame = NestedRestoreFrame::prepare(key, pending);
    frame.retain(key).expect("new frame has its exact key and prepared phase");
    if pending.snapshot.pump.nested_restore_quarantined.is_some() {
        frame.quarantine(key).expect("retained quarantine has its exact key");
    }
    let row = Row {
        generation, frame, return_target, destination,
        root_parked: root_already_parked,
        result_entered: false, result: None,
        callback_reservation: None, callback_token: None,
        callback_terminal_payload: None, callback_failure: None,
        terminal: None,
        due_at: if root_already_parked { monotonic_time_100ns() } else { 0 },
        shared_leases: nt_user_callback::SharedPageLeaseStack::new(),
        displaced_shared_resume: None,
        quarantined_parent_pump: None,
        quarantined_child_pump: None,
        quarantined_child_job_result: None,
    };
    Ok((row, key))
}

/// The prepared park has only pre-effect validation and infallible pool/slot stores. Keep the
/// frame borrowed through that memory-only transition so no successful park can leave its row
/// undiscoverable by the outer scheduler.
pub(crate) unsafe fn park_root(
    ticket: NestedRestoreOwnerTicket,
    reply_park: crate::root_reply_park::RootReplyPark,
) -> Result<(), crate::root_reply_park::RootReplyPark> {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut) else { return Err(reply_park); };
    if !exact(row, ticket) || row.root_parked { return Err(reply_park); }
    reply_park.try_commit()?;
    row.root_parked = true;
    row.due_at = monotonic_time_100ns();
    Ok(())
}

/// A refused pre-effect park leaves the original Reply active and the snapshot owned here.
/// Expose that exact row so service-loop diagnostics or a later safe park retry can find it.
pub(crate) unsafe fn next_unparked() -> Option<NestedRestoreOwnerTicket> {
    (&*core::ptr::addr_of!(ROWS)).iter().enumerate().find_map(|(index, row)| {
        let row = row.as_ref()?;
        (!row.root_parked).then_some(NestedRestoreOwnerTicket {
            index, generation: row.generation, key: row.frame.key(),
        })
    })
}

/// A refused park has not changed the original Reply. Retry only the exact row and same root
/// cap; a changed main slot must be investigated without rotating another caller's Reply.
pub(crate) unsafe fn retry_unparked_root(
    ticket: NestedRestoreOwnerTicket,
) -> bool {
    let Some(row) = (&*core::ptr::addr_of!(ROWS))
        .get(ticket.index).and_then(Option::as_ref) else { return false; };
    if !exact(row, ticket) || row.root_parked
        || REPLY_MAIN_SLOT.load(Ordering::Relaxed) != ticket.key.root_reply()
    { return false; }
    let Some(park) = crate::root_reply_park::RootReplyPark::prepare() else { return false; };
    park_root(ticket, park).is_ok()
}

/// Read-only selection. A quarantined parent retains both Replies but is never retried.
pub(crate) unsafe fn next_retry() -> Option<NestedRestoreOwnerTicket> {
    let now = monotonic_time_100ns();
    (&*core::ptr::addr_of!(ROWS)).iter().enumerate().find_map(|(index, row)| {
        let row = row.as_ref()?;
        (row.root_parked && row.due_at <= now && row.callback_failure.is_none()
            && (!row.result_entered || row.result.is_some())
            && matches!(row.frame.phase(),
            NestedRestorePhase::Retained | NestedRestorePhase::Restored
                | NestedRestorePhase::ResultRetained))
            .then_some(NestedRestoreOwnerTicket {
                index, generation: row.generation, key: row.frame.key(),
            })
    })
}

pub(crate) unsafe fn next_deadline() -> Option<u64> {
    (&*core::ptr::addr_of!(ROWS)).iter().flatten()
        .filter(|row| row.root_parked && row.callback_failure.is_none()
            && (!row.result_entered || row.result.is_some())
            && matches!(row.frame.phase(),
            NestedRestorePhase::Retained | NestedRestorePhase::Restored
                | NestedRestorePhase::ResultRetained))
        .map(|row| row.due_at)
        .min()
}

pub(crate) unsafe fn defer_retry(ticket: NestedRestoreOwnerTicket) {
    if let Some(row) = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut)
    {
        if exact(row, ticket) && row.root_parked {
            row.due_at = monotonic_time_100ns().saturating_add(1_600_000);
        }
    }
}

pub(crate) unsafe fn pending(
    ticket: NestedRestoreOwnerTicket,
) -> Option<win32k_glue::PendingNestedRestoreDispatch> {
    let row = (&*core::ptr::addr_of!(ROWS)).get(ticket.index)?.as_ref()?;
    if !exact(row, ticket) || !row.root_parked { return None; }
    // The pending snapshot is Copy. The frame remains the sole authority to transfer it.
    row.frame.continuation_ref(ticket.key).ok().copied()
}

/// The receiving row is the durable owner of the parent pump and both Replies. A child may
/// overwrite its singleton shared page only after this exact row retains a stable full copy.
/// `None` means no receiving parent; `Some(Err(()))` fences a matched parent on uncertainty.
pub(crate) unsafe fn capture_displaced_shared_resume(
    active: nt_user_callback::DispatchContext,
) -> Option<Result<NestedRestoreOwnerTicket, ()>> {
    if active.dispatch_id == 0 { return None; }
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    for (index, row) in rows.iter_mut().enumerate() {
        let Some(row) = row.as_mut() else { continue };
        if row.frame.phase() != NestedRestorePhase::Receiving { continue }
        let key = row.frame.key();
        let Some(pending) = row.frame.continuation_ref(key).ok().copied() else { continue };
        // A grandchild would overwrite the live child page. Refuse it before any write until
        // that child has its own durable nested owner; the parent row remains retryable.
        if row.shared_leases.len() > 1 { return Some(Err(())); }
        if pending.snapshot.dispatch.dispatch_id != active.dispatch_id { continue }
        if pending.snapshot.dispatch != active {
            let _ = row.frame.quarantine_receive(key);
            return Some(Err(()));
        }
        let ticket = NestedRestoreOwnerTicket { index, generation: row.generation, key };
        let identity = nt_user_callback::SharedPageLeaseIdentity {
            dispatch: active,
            client: win32k_glue::shared_page_client_identity(pending.snapshot.client),
        };
        let Some(snapshot) = win32k_glue::try_capture_exact_shared_resume_snapshot(
            active, pending.snapshot.client,
        ) else {
            let _ = row.frame.quarantine_receive(key);
            return Some(Err(()));
        };
        if row.shared_leases.begin(identity).is_err()
            || row.shared_leases.displace(identity,
                snapshot.lease_snapshot(pending.snapshot.client)).is_err()
        {
            let _ = row.frame.quarantine_receive(key);
            return Some(Err(()));
        }
        row.displaced_shared_resume = Some(snapshot);
        return Some(Ok(ticket));
    }
    None
}

pub(crate) unsafe fn begin_displacing_child(
    ticket: NestedRestoreOwnerTicket,
    dispatch: nt_user_callback::DispatchContext,
    client: win32k_glue::Win32kClientContext,
) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut) else { return false };
    if !exact(row, ticket) || row.frame.phase() != NestedRestorePhase::Receiving
        || row.displaced_shared_resume.is_none()
    { return false }
    let identity = nt_user_callback::SharedPageLeaseIdentity {
        dispatch, client: win32k_glue::shared_page_client_identity(client),
    };
    row.shared_leases.begin(identity).is_ok()
}

/// The new dispatch refused before its first shared write. The old publication remains owned
/// by this row even if client-window re-selection or the exact restoration refuses.
pub(crate) unsafe fn abort_displaced_shared_resume(
    ticket: NestedRestoreOwnerTicket,
) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut) else { return false };
    if !exact(row, ticket) || row.frame.phase() != NestedRestorePhase::Receiving {
        return false;
    }
    let Some(parent) = row.frame.continuation_ref(ticket.key).ok().copied() else {
        let _ = row.frame.quarantine_receive(ticket.key);
        return false;
    };
    let Some(snapshot) = row.displaced_shared_resume else {
        let _ = row.frame.quarantine_receive(ticket.key);
        return false;
    };
    let identity = nt_user_callback::SharedPageLeaseIdentity {
        dispatch: parent.snapshot.dispatch,
        client: win32k_glue::shared_page_client_identity(parent.snapshot.client),
    };
    let page = snapshot.lease_snapshot(parent.snapshot.client);
    if !win32k_glue::select_and_restore_shared_resume_snapshot(
        snapshot, parent.snapshot.dispatch, parent.snapshot.client,
    ).1
    {
        let _ = row.shared_leases.acknowledge_restore(
            identity, nt_user_callback::SharedPageRestoreEffect::Uncertain,
        );
        let _ = row.frame.quarantine_receive(ticket.key);
        return false;
    }
    if row.shared_leases.acknowledge_restore(
        identity, nt_user_callback::SharedPageRestoreEffect::Applied(page),
    ).is_err() || row.shared_leases.finish(identity, Some(page)).is_err() {
        let _ = row.frame.quarantine_receive(ticket.key);
        return false;
    }
    row.displaced_shared_resume = None;
    true
}

/// A completed child releases only its live lease. A yielded child must supply its full exact
/// page after the pending pump/Reply owner is retained. Restore then acknowledges the old page.
pub(crate) unsafe fn finish_displacing_child(
    ticket: NestedRestoreOwnerTicket,
    dispatch: nt_user_callback::DispatchContext,
    client: win32k_glue::Win32kClientContext,
    terminal: bool,
    yielded: Option<win32k_glue::SharedResumeSnapshot>,
) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut) else { return false };
    if !exact(row, ticket) || row.frame.phase() != NestedRestorePhase::Receiving {
        return false;
    }
    let child = nt_user_callback::SharedPageLeaseIdentity {
        dispatch, client: win32k_glue::shared_page_client_identity(client),
    };
    let finished = if terminal && yielded.is_none() {
        row.shared_leases.finish_terminal(child).is_ok()
    } else if !terminal {
        yielded.is_some_and(|snapshot| row.shared_leases.finish(
            child, Some(snapshot.lease_snapshot(client)),
        ).is_ok())
    } else { false };
    if !finished {
        let _ = row.frame.quarantine_receive(ticket.key);
        return false;
    }
    let Some(parent_snapshot) = row.displaced_shared_resume else {
        let _ = row.frame.quarantine_receive(ticket.key);
        return false;
    };
    let Some(parent) = row.frame.continuation_ref(ticket.key).ok().copied() else {
        let _ = row.frame.quarantine_receive(ticket.key);
        return false;
    };
    let identity = nt_user_callback::SharedPageLeaseIdentity {
        dispatch: parent.snapshot.dispatch,
        client: win32k_glue::shared_page_client_identity(parent.snapshot.client),
    };
    let page = parent_snapshot.lease_snapshot(parent.snapshot.client);
    if !win32k_glue::select_and_restore_shared_resume_snapshot(
        parent_snapshot, parent.snapshot.dispatch, parent.snapshot.client,
    ).1
    {
        let _ = row.shared_leases.acknowledge_restore(
            identity, nt_user_callback::SharedPageRestoreEffect::Uncertain,
        );
        let _ = row.frame.quarantine_receive(ticket.key);
        return false;
    }
    if row.shared_leases.acknowledge_restore(
        identity, nt_user_callback::SharedPageRestoreEffect::Applied(page),
    ).is_err() || row.shared_leases.finish(identity, Some(page)).is_err() {
        let _ = row.frame.quarantine_receive(ticket.key);
        return false;
    }
    true
}

/// Keep a nonterminal child pump whose outcome has no other durable pending owner. Neither its
/// Reply nor its channel may be reused while the parent's displaced page remains uncertain.
pub(crate) unsafe fn retain_quarantined_child_pump(
    ticket: NestedRestoreOwnerTicket,
    pump: crate::spawn_hosts::PumpResult,
    channel: crate::spawn_hosts::PumpChannel,
    dispatch: nt_user_callback::DispatchContext,
    client: win32k_glue::Win32kClientContext,
) {
    if let Some(row) = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut)
    {
        if exact(row, ticket) && row.quarantined_child_pump.is_none() {
            row.quarantined_child_pump = Some(QuarantinedChildPump {
                pump, channel, dispatch, client,
            });
        }
    }
}

/// The early kernel-job path has no PumpResult or pending child slot. Preserve its exact
/// completed/failed effect when the parent page cannot be restored after the job returned.
pub(crate) unsafe fn retain_quarantined_child_job_result(
    ticket: NestedRestoreOwnerTicket,
    result: Result<(u64, bool), u32>,
    dispatch: nt_user_callback::DispatchContext,
    client: win32k_glue::Win32kClientContext,
) {
    if let Some(row) = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut)
    {
        if exact(row, ticket) && row.quarantined_child_job_result.is_none() {
            row.quarantined_child_job_result = Some(QuarantinedChildJobResult {
                result, dispatch, client,
            });
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NestedRestorePassOutcome {
    Refused,
    Quarantined,
    ResultRetained,
}

/// One outer turn advances at most one physical restore or receive-half entry. The frame phase
/// is committed before each fallible effect; a later turn cannot replay an acknowledged restore
/// or an already-entered receive. Terminal/wait transfer consumes only `ResultRetained`.
pub(crate) unsafe fn run_one(
    ticket: NestedRestoreOwnerTicket,
) -> NestedRestorePassOutcome {
    let Some(pending) = pending(ticket) else { return NestedRestorePassOutcome::Refused; };
    let row = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut);
    let Some(row) = row else { return NestedRestorePassOutcome::Refused; };
    if !exact(row, ticket) || !row.root_parked || !row.return_target.can_resume() {
        return NestedRestorePassOutcome::Refused;
    }
    if row.frame.phase() == NestedRestorePhase::ResultRetained {
        return NestedRestorePassOutcome::ResultRetained;
    }
    if row.frame.phase() == NestedRestorePhase::Retained {
        if row.frame.begin_retry(ticket.key).is_err() {
            return NestedRestorePassOutcome::Refused;
        }
        // End the row borrow before the nested pump may allocate, invoke IPC or access the owner.
        let restore = crate::spawn_hosts::component_pump_restore_nested_parent(
            &pending.snapshot.channel, &pending.snapshot.pump,
        );
        let row = (&mut *core::ptr::addr_of_mut!(ROWS))
            .get_mut(ticket.index).and_then(Option::as_mut);
        let Some(row) = row else { return NestedRestorePassOutcome::Quarantined; };
        if !exact(row, ticket) { return NestedRestorePassOutcome::Quarantined; }
        match restore {
            Ok(crate::spawn_hosts::NestedParentRestoreOutcome::Restored) => {
                if row.frame.acknowledge_restored(ticket.key).is_err() {
                    return NestedRestorePassOutcome::Quarantined;
                }
            }
            Ok(crate::spawn_hosts::NestedParentRestoreOutcome::Retryable) => {
                let _ = row.frame.refuse_retry_no_effects(ticket.key);
                return NestedRestorePassOutcome::Refused;
            }
            Ok(crate::spawn_hosts::NestedParentRestoreOutcome::Quarantined) | Err(_) => {
                let _ = row.frame.quarantine(ticket.key);
                return NestedRestorePassOutcome::Quarantined;
            }
        }
    }
    let row = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut);
    let Some(row) = row else { return NestedRestorePassOutcome::Quarantined; };
    if !exact(row, ticket) { return NestedRestorePassOutcome::Quarantined; }
    if row.callback_reservation.is_none() {
        let Ok(reservation) = component_callback_transfer::CallbackTransfer::reserve() else {
            return NestedRestorePassOutcome::Refused;
        };
        row.callback_reservation = Some(reservation);
    }
    if row.frame.begin_receive(ticket.key).is_err() {
        return NestedRestorePassOutcome::Refused;
    }
    let result = win32k_glue::resume_suspended_nested_restore_receive(pending);
    let row = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut);
    let Some(row) = row else { return NestedRestorePassOutcome::Quarantined; };
    if !exact(row, ticket) { return NestedRestorePassOutcome::Quarantined; }
    if row.frame.phase() != NestedRestorePhase::Receiving {
        row.quarantined_parent_pump = result.ok();
        return NestedRestorePassOutcome::Quarantined;
    }
    let pump = match result {
        Ok(pump) => pump,
        Err(_) => {
            // Client-window selection can have native mapping effects before it refuses.
            // Without a separate certified no-effect receipt the receive entry cannot replay.
            let _ = row.frame.quarantine_receive(ticket.key);
            return NestedRestorePassOutcome::Quarantined;
        }
    };
    let mut next = pending;
    next.snapshot.pump = pump;
    let Some(shared_resume) = win32k_glue::try_capture_exact_shared_resume_snapshot(
        pending.snapshot.dispatch, pending.snapshot.client,
    ) else {
        row.quarantined_parent_pump = Some(pump);
        let _ = row.frame.quarantine_receive(ticket.key);
        return NestedRestorePassOutcome::Quarantined;
    };
    next.snapshot.shared_resume = shared_resume;
    row.displaced_shared_resume = None;
    if let Err((_, retained)) = row.frame.record_receive_result(ticket.key, next) {
        row.quarantined_parent_pump = Some(retained.snapshot.pump);
        return NestedRestorePassOutcome::Quarantined;
    }
    NestedRestorePassOutcome::ResultRetained
}

/// Output and callback settlement is an entered effect, even if a later pure transfer refuses.
/// Cache its typed outcome once; a later outer turn may retry only the destination admission.
pub(crate) unsafe fn settle_result(
    ticket: NestedRestoreOwnerTicket,
) -> Option<win32k_glue::NestedRestorePumpCompletion> {
    let pending = pending(ticket)?;
    {
        let row = (&mut *core::ptr::addr_of_mut!(ROWS))
            .get_mut(ticket.index)?.as_mut()?;
        if !exact(row, ticket) || row.frame.phase() != NestedRestorePhase::ResultRetained {
            return None;
        }
        if let Some(result) = row.result { return Some(result); }
        if row.result_entered { return None; }
        row.result_entered = true;
    }
    let result = win32k_glue::settle_nested_restore_result(pending);
    let row = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index)?.as_mut()?;
    if !exact(row, ticket) || !row.result_entered || row.result.is_some() {
        return None;
    }
    row.result = Some(result);
    if matches!(result, win32k_glue::NestedRestorePumpCompletion::Restored(
        win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended,
    )) {
        let Some(callback) = row.callback_reservation.as_mut() else {
            retain_callback_failure(row, ticket, b"missing-reservation",
                nt_process::STATUS_INSUFFICIENT_RESOURCES);
            return Some(result);
        };
        match callback.capture(
            pending.snapshot.client,
            pending.snapshot.dispatch.lane,
            pending.snapshot.dispatch.dispatch_id,
        ) {
            Ok(token) => {
                if let Some(callback) = row.callback_reservation.take() {
                    row.callback_token = Some(token);
                    row.callback_terminal_payload = Some(
                        component_terminal::NativeTerminal::nested_callback(callback),
                    );
                } else {
                    retain_callback_failure(row, ticket, b"capture-owner",
                        nt_process::STATUS_UNSUCCESSFUL);
                }
            }
            Err(status) => {
                // Capture may have observed a reused shared bank. Keep the exact result, failed
                // transfer, physical owner and both Replies; never recapture another callback.
                retain_callback_failure(row, ticket, b"capture", status);
            }
        }
    } else {
        row.callback_reservation = None;
    }
    Some(result)
}

/// A real callback reached by the resumed receive half retains its newly captured input and
/// token through the ordinary four-stage callback terminal. A pure admission refusal returns
/// the non-Copy native payload to this row; it never recaptures the shared callback bank.
pub(crate) unsafe fn transfer_callback_terminal(
    ticket: NestedRestoreOwnerTicket,
) -> Option<nt_component_suspension::TerminalIdentity> {
    let (result, return_target, destination, new_token) = {
        let row = (&*core::ptr::addr_of!(ROWS)).get(ticket.index)?.as_ref()?;
        if !exact(row, ticket) || !row.root_parked
            || row.frame.phase() != NestedRestorePhase::ResultRetained
            || row.callback_failure.is_some()
        { return None; }
        (row.result?, row.return_target, row.destination, row.callback_token?)
    };
    if !matches!(result, win32k_glue::NestedRestorePumpCompletion::Restored(
        win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended,
    )) { return None; }
    let pending = pending(ticket)?;
    let outer_token = match wait_transfer_origin(&pending) {
        Some(NestedWaitTransfer::None) if new_token != 0 => None,
        Some(NestedWaitTransfer::InCallback { token, .. })
            if new_token != 0 && token != new_token => Some(token),
        _ => {
            retain_exact_callback_failure(ticket, b"origin",
                nt_process::STATUS_INVALID_PARAMETER);
            return None;
        }
    };
    if pending.origin.registered_client
        && !win32k_glue::win32k_client_context_is_admitted(pending.snapshot.client)
    {
        retain_exact_callback_failure(ticket, b"client",
            nt_process::STATUS_INVALID_PARAMETER);
        return None;
    }
    let sequence = next_dispatcher_wait_sequence();
    let row = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index)?.as_mut()?;
    if !exact(row, ticket) || row.terminal.is_some() { return None; }
    let Some(offered) = row.callback_terminal_payload.take() else {
        retain_callback_failure(row, ticket, b"missing-payload",
            nt_process::STATUS_UNSUCCESSFUL);
        return None;
    };
    let mut payload = Some(offered);
    let retained = row.frame.transfer_result_no_effects(ticket.key, |pending| {
        let continuation = ComponentNativeContinuation::Hosted(HostedNativeContinuation {
            pending: PendingComponentDispatch::NestedRestore(PendingNestedTerminalDispatch {
                ticket, client: pending.snapshot.client,
            }),
            return_target,
            destination,
        });
        let Some(offered) = payload.take() else { return Err(pending); };
        match (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .retain_nested_restored_callback_terminal_owned(
                ticket.key, outer_token, new_token, sequence, continuation, offered,
            )
        {
            Ok(identity) => Ok(identity),
            Err((_error, _continuation, offered)) => {
                payload = Some(offered);
                Err(pending)
            }
        }
    });
    if let Some(offered) = payload {
        row.callback_terminal_payload = Some(offered);
    } else if retained.is_err() {
        retain_callback_failure(row, ticket, b"terminal-payload",
            nt_process::STATUS_UNSUCCESSFUL);
    }
    let Ok(identity) = retained else { return None; };
    row.terminal = Some(identity);
    Some(identity)
}

/// Admit a genuinely completed receive half to the existing terminal pipeline. The pure lane
/// transition either atomically takes both continuation and payload or returns them untouched;
/// the independent frame still retains the original root Reply on every refusal.
pub(crate) unsafe fn transfer_completed_terminal(
    ticket: NestedRestoreOwnerTicket,
) -> Option<nt_component_suspension::TerminalIdentity> {
    let (result, return_target, destination) = {
        let row = (&*core::ptr::addr_of!(ROWS)).get(ticket.index)?.as_ref()?;
        if !exact(row, ticket) || !row.root_parked
            || row.frame.phase() != NestedRestorePhase::ResultRetained
        { return None; }
        (row.result?, row.return_target, row.destination)
    };
    let win32k_glue::NestedRestorePumpCompletion::Restored(
        win32k_glue::ProviderWaitPumpCompletion::Completed(dispatch),
    ) = result else { return None; };
    let sequence = next_dispatcher_wait_sequence();
    let row = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index)?.as_mut()?;
    if !exact(row, ticket) || row.terminal.is_some() { return None; }
    let retained = row.frame.transfer_result_no_effects(ticket.key, |pending| {
        // An in-callback nested syscall returns through its existing external token. It is not
        // NtCallbackReturn, so no staged parent-TCB context may be manufactured for this path.
        let external_token = match (pending.origin.nested_user_callback,
            pending.origin.outer_callback)
        {
            (false, None) if pending.snapshot.callback_token.is_none() => None,
            (true, Some((lane, token)))
                if lane == pending.snapshot.dispatch.lane
                    && pending.snapshot.callback_token == Some(token)
                    && token != 0 => Some(token),
            _ => return Err(pending),
        };
        if pending.origin.registered_client
            && !win32k_glue::win32k_client_context_is_admitted(pending.snapshot.client)
        {
            return Err(pending);
        }
        let continuation = ComponentNativeContinuation::Hosted(HostedNativeContinuation {
            pending: PendingComponentDispatch::NestedRestore(PendingNestedTerminalDispatch {
                ticket, client: pending.snapshot.client,
            }),
            return_target,
            destination,
        });
        let payload = component_terminal::NativeTerminal::completed(dispatch);
        match (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .retain_nested_restored_terminal_owned(
                ticket.key, external_token, sequence, continuation, payload,
            )
        {
            Ok(identity) => Ok(identity),
            Err((_error, _continuation, _payload)) => Err(pending),
        }
    });
    let Ok(identity) = retained else { return None; };
    row.terminal = Some(identity);
    Some(identity)
}

/// A nested syscall entered while a user callback is running has an external token, but has not
/// completed NtCallbackReturn. Keep that distinction when handing a genuine wait to its owner.
fn wait_transfer_origin(
    pending: &win32k_glue::PendingNestedRestoreDispatch,
) -> Option<NestedWaitTransfer> {
    match (pending.origin.nested_user_callback, pending.origin.outer_callback,
        pending.snapshot.callback_token)
    {
        (false, None, None) => Some(NestedWaitTransfer::None),
        (true, Some((lane, token)), Some(snapshot_token))
            if lane == pending.snapshot.dispatch.lane && token != 0
                && token == snapshot_token =>
        {
            Some(NestedWaitTransfer::InCallback { lane, token })
        }
        _ => None,
    }
}

fn quarantine_wait_transfer(ticket: NestedRestoreOwnerTicket) {
    // The pure frame has already retained and quarantined the result. This diagnostic points to
    // the durable row; a failed LPC cancellation is never authority to retry its admission.
    print_str(b"[nested-restore] wait-transfer-indeterminate row/generation=");
    print_u64(ticket.index as u64);
    print_str(b"/");
    print_u64(ticket.generation);
    print_str(b"\n");
}

/// Hand a real later wait to its existing admission owner with the already parked root Reply.
/// A no-effect refusal leaves the real result and root Reply retained for a later outer turn;
/// an indeterminate admission fences them permanently instead of replaying the operation.
pub(crate) unsafe fn transfer_genuine_wait(
    ticket: NestedRestoreOwnerTicket,
    handler: *mut ExecNtHandler,
) -> bool {
    if handler.is_null() { return false; }
    let (result, destination) = {
        let Some(row) = (&*core::ptr::addr_of!(ROWS))
            .get(ticket.index).and_then(Option::as_ref) else { return false; };
        if !exact(row, ticket) || !row.root_parked
            || row.frame.phase() != NestedRestorePhase::ResultRetained
        { return false; }
        let Some(result) = row.result else { return false; };
        (result, row.destination)
    };
    let root_reply = ticket.key.root_reply();
    let row = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut);
    let Some(row) = row else { return false; };
    if !exact(row, ticket) { return false; }
    let transfer = row.frame.transfer_result_with(ticket.key, |old| {
        let Some(origin) = wait_transfer_origin(old) else {
            return Err(NestedRestoreTransferRefusal::NoEffects);
        };
        let admitted = match result {
            win32k_glue::NestedRestorePumpCompletion::Restored(
                win32k_glue::ProviderWaitPumpCompletion::Reparked(next),
            ) if provider_wait_expected_owner(next) == Some(ticket.key.owner()) => {
                provider_wait_admit_with_transfer(
                    &mut *handler, next, root_reply, origin, destination,
                )
            }
            win32k_glue::NestedRestorePumpCompletion::Restored(
                win32k_glue::ProviderWaitPumpCompletion::LpcReparked(next),
            ) if lpc_wait_expected_owner(next) == Some(ticket.key.owner()) => {
                lpc_wait_admit_with_transfer(
                    &mut *handler, next, root_reply, origin, destination,
                )
            }
            win32k_glue::NestedRestorePumpCompletion::ReceiveReparked(next)
                if next.yielded.owner == ticket.key.owner() => {
                    receive_admit_with_transfer(next, root_reply, origin, destination)
                }
            win32k_glue::NestedRestorePumpCompletion::ServiceReparked(next)
                if service_wait_expected_owner(next) == Some(ticket.key.owner()) => {
                    service_wait_admit_with_transfer(next, root_reply, origin, destination)
                }
            _ => RetainedWaitAdmission::RefusedNoEffect,
        };
        match admitted {
            RetainedWaitAdmission::Accepted => Ok(()),
            RetainedWaitAdmission::RefusedNoEffect =>
                Err(NestedRestoreTransferRefusal::NoEffects),
            RetainedWaitAdmission::Indeterminate =>
                Err(NestedRestoreTransferRefusal::Indeterminate),
        }
    });
    match transfer {
        Ok(()) => {}
        Err(nt_component_suspension::NestedRestoreFrameError::Indeterminate) => {
            quarantine_wait_transfer(ticket);
            return false;
        }
        Err(_) => return false,
    }
    (&mut *core::ptr::addr_of_mut!(ROWS))[ticket.index] = None;
    true
}

/// A receive half can refuse another nested parent restore. The new exact physical row already
/// owns that refusal; transfer the same parked root Reply without preparing or committing a
/// second park. The old frame is consumed only after the new row has been retained.
pub(crate) unsafe fn transfer_nested_repark(
    ticket: NestedRestoreOwnerTicket,
) -> bool {
    let (next, destination) = {
        let Some(row) = (&*core::ptr::addr_of!(ROWS))
            .get(ticket.index).and_then(Option::as_ref) else { return false; };
        if !exact(row, ticket) || !row.root_parked
            || row.frame.phase() != NestedRestorePhase::ResultRetained
        { return false; }
        let Some(win32k_glue::NestedRestorePumpCompletion::NestedReparked(next)) = row.result
        else { return false; };
        (next, row.destination)
    };
    let Some(reservation) = reserve_capacity() else { return false; };
    if !(&*core::ptr::addr_of!(ROWS))
        .get(reservation).is_some_and(Option::is_none)
    { return false; }
    let Ok((new_row, new_key)) = prepare_row(
        next, ticket.key.root_reply(), destination, true,
    ) else { return false; };
    let new_ticket = NestedRestoreOwnerTicket {
        index: reservation, generation: new_row.generation, key: new_key,
    };
    let row = (&mut *core::ptr::addr_of_mut!(ROWS))
        .get_mut(ticket.index).and_then(Option::as_mut);
    let Some(row) = row else { return false; };
    if !exact(row, ticket) { return false; }
    let transferred = row.frame.transfer_result_no_effects(ticket.key, |_old| Ok(new_ticket));
    if transferred.is_err() { return false; }
    let rows = &mut *core::ptr::addr_of_mut!(ROWS);
    rows[reservation] = Some(new_row);
    rows[ticket.index] = None;
    true
}

pub(crate) unsafe fn can_retire_terminal(
    ticket: NestedRestoreOwnerTicket,
    identity: nt_component_suspension::TerminalIdentity,
) -> bool {
    (&*core::ptr::addr_of!(ROWS)).get(ticket.index)
        .and_then(Option::as_ref)
        .is_some_and(|row| exact(row, ticket) && row.root_parked
            && row.frame.phase() == NestedRestorePhase::Consumed
            && row.terminal == Some(identity))
}

pub(crate) unsafe fn retire_terminal(
    ticket: NestedRestoreOwnerTicket,
) -> bool {
    let Some(identity) = (&*core::ptr::addr_of!(ROWS))
        .get(ticket.index).and_then(Option::as_ref)
        .and_then(|row| exact(row, ticket).then_some(row.terminal).flatten())
    else { return false; };
    if !can_retire_terminal(ticket, identity) { return false; }
    (&mut *core::ptr::addr_of_mut!(ROWS))[ticket.index] = None;
    true
}
