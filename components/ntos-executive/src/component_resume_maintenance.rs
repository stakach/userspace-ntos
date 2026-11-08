//! One exact root-maintenance resume. The ticket owns both Replies and physical exclusion.

use super::*;
use nt_user_host::physical_execution_restore::RestoreStep;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use crate::service_sec_image::root_maintenance_owner::{
    RootMaintenanceAcceptedTransfer as AcceptedTransfer,
    RootMaintenanceTransferKind as TransferKind,
    RootMaintenanceTransferPhase as TransferPhase,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootMaintenanceResumeOutcome {
    DeferredRetry,
    RetainedFailure,
    Parked,
    Terminal,
}

static ROOT_REFUSAL_TRACES: AtomicU64 = AtomicU64::new(0);
static ROOT_REPARK_TRACES: AtomicU64 = AtomicU64::new(0);

/// One bounded, read-only record at the first refusal. The ticket is printed even when its
/// durable row can no longer be found; zero means an absent optional observation.
unsafe fn trace_root_refusal(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    stage: &[u8],
    detail: u64,
) {
    if ROOT_REFUSAL_TRACES.fetch_add(1, Ordering::Relaxed) >= 16 { return; }
    let lane = ticket.dispatch.lane();
    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    let phase = match root_maintenance_owner::transfer_phase(ticket) {
        Some(TransferPhase::Returned) => 1,
        Some(TransferPhase::Entering { .. }) => 2,
        Some(TransferPhase::Transferred { .. }) => 3,
        Some(TransferPhase::Indeterminate) => 4,
        None => 0,
    };
    let key = root_maintenance_owner::key(ticket);
    let frame_exact = key.is_some_and(|key| lanes.frame(lane, key).ok().flatten()
        .is_some_and(|frame| frame.key == key && frame.owner == ticket.owner
            && matches!(&frame.phase,
                nt_component_suspension::SuspensionPhase::MaintenanceResuming { .. })));
    print_str(b"[root-resume-refusal] stage="); print_str(stage);
    print_str(b" detail="); print_u64(detail);
    print_str(b" ticket="); print_u64(ticket.index as u64);
    print_str(b"/"); print_u64(ticket.generation);
    print_str(b" lane="); print_u64(lane.index as u64);
    print_str(b"/"); print_u64(lane.generation);
    print_str(b" epoch="); print_u64(ticket.dispatch.epoch());
    print_str(b" owner="); print_u64(ticket.owner.provider_domain);
    print_str(b"/"); print_u64(ticket.owner.provider_generation);
    print_str(b"/"); print_u64(ticket.owner.dispatch_id);
    print_str(b" reply="); print_u64(ticket.reply);
    print_str(b" origin-reply="); print_u64(ticket.origin_reply);
    print_str(b" root-reply="); print_u64(ticket.root_reply);
    print_str(b" phase="); print_u64(phase);
    print_str(b" token="); print_u64(root_maintenance_owner::callback_token(ticket).unwrap_or(0));
    print_str(b" key="); print_u64(key.map_or(0, |key| key.id));
    print_str(b" lane-running=");
    print_u64((lanes.phase(lane) == Ok(nt_component_suspension::LanePhase::Running)) as u64);
    print_str(b" frame-exact="); print_u64(frame_exact as u64);
    print_str(b" dispatch-exact=");
    print_u64((lanes.active_dispatch_identity(lane) == Ok(Some(ticket.dispatch))) as u64);
    print_str(b" binding-reply=");
    print_u64(lanes.binding(lane).ok().map_or(0, |binding| binding.reply_object));
    print_str(b"\n");
}

/// A bounded breadcrumb before a returned pump enters a repark path. A later refusal record
/// identifies the exact guard; this record distinguishes it from a pre-pump refusal.
fn trace_root_repark(ticket: root_maintenance_owner::RootMaintenanceTicket, kind: &[u8]) {
    if ROOT_REPARK_TRACES.fetch_add(1, Ordering::Relaxed) >= 16 { return; }
    print_str(b"[root-resume-repark] kind="); print_str(kind);
    print_str(b" ticket="); print_u64(ticket.index as u64);
    print_str(b"/"); print_u64(ticket.generation);
    print_str(b" reply="); print_u64(ticket.reply);
    print_str(b" root-reply="); print_u64(ticket.root_reply);
    print_str(b"\n");
}

fn restore_step_code(step: Option<Result<RestoreStep, runtime::Error>>) -> u64 {
    match step {
        Some(Ok(RestoreStep::Canonical)) => 1,
        Some(Ok(RestoreStep::Projection)) => 2,
        Some(Ok(RestoreStep::ProjectionEntered)) => 7,
        Some(Ok(RestoreStep::Release)) => 3,
        Some(Ok(RestoreStep::UncertainRelease)) => 4,
        Some(Ok(RestoreStep::Finalize)) => 5,
        Some(Ok(RestoreStep::Done)) => 6,
        Some(Err(_)) => 7,
        None => 0,
    }
}

fn physical_error_code(error: runtime::Error) -> u64 {
    match error {
        runtime::Error::Initialization => 1,
        runtime::Error::Source => 2,
        runtime::Error::Capacity => 3,
        runtime::Error::Publication => 4,
        runtime::Error::UnknownPeer => 5,
        runtime::Error::PhysicalIdentity => 6,
        runtime::Error::Startup => 7,
        runtime::Error::Receive => 8,
        runtime::Error::Retain => 9,
        runtime::Error::Protocol => 10,
        runtime::Error::Fault => 11,
        runtime::Error::Admission => 12,
        runtime::Error::Reply => 13,
        runtime::Error::Retirement => 14,
    }
}

fn lane_error_code(error: nt_component_suspension::LaneError) -> u64 {
    use nt_component_suspension::{LaneError, SuspensionError};
    match error {
        LaneError::InvalidIdentity => 1,
        LaneError::DuplicateBinding => 2,
        LaneError::NoCapacity => 3,
        LaneError::NotFound => 4,
        LaneError::StaleGeneration => 5,
        LaneError::WrongBinding => 6,
        LaneError::Busy => 7,
        LaneError::InvalidPhase => 8,
        LaneError::Suspension(inner) => 16 + match inner {
            SuspensionError::InvalidIdentity => 1,
            SuspensionError::DuplicateIdentity => 2,
            SuspensionError::Overflow => 3,
            SuspensionError::NoCapacity => 4,
            SuspensionError::NotFound => 5,
            SuspensionError::NotTop => 6,
            SuspensionError::InvalidPhase => 7,
        },
    }
}

fn retryable_pure_refusal(error: nt_component_suspension::LaneError) -> bool {
    matches!(error,
        nt_component_suspension::LaneError::Busy
        | nt_component_suspension::LaneError::NoCapacity
        | nt_component_suspension::LaneError::InvalidPhase
        | nt_component_suspension::LaneError::Suspension(
            nt_component_suspension::SuspensionError::NoCapacity
            | nt_component_suspension::SuspensionError::Overflow
            | nt_component_suspension::SuspensionError::InvalidPhase))
}

/// A pure refusal returns its offered value and leaves the old frame untouched. Exact old-frame
/// proof permits capacity or phase retry; identity disagreement is quarantined.
unsafe fn pure_transfer_refused(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    error: nt_component_suspension::LaneError,
) -> RootMaintenanceResumeOutcome {
    let retryable = retryable_pure_refusal(error);
    let no_effects = retryable
        && root_maintenance_owner::refuse_result_transfer_no_effects(ticket);
    if no_effects {
        RootMaintenanceResumeOutcome::DeferredRetry
    } else {
        trace_root_refusal(ticket, b"pure-transfer", lane_error_code(error));
        let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
        RootMaintenanceResumeOutcome::RetainedFailure
    }
}

/// Return true only when the exact pure transfer has yet to enter. A Transferred row may run
/// only its remaining retirement/backend steps and never repeats the pure transition.
unsafe fn need_pure_frame_transfer(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    kind: TransferKind,
    next_key: nt_component_suspension::SuspensionKey,
) -> Result<bool, RootMaintenanceResumeOutcome> {
    match root_maintenance_owner::transfer_phase(ticket) {
        Some(TransferPhase::Returned) => {
            if root_maintenance_owner::begin_result_transfer(ticket, kind, next_key) {
                Ok(true)
            } else {
                trace_root_refusal(ticket, b"frame-transfer-begin", kind as u64);
                Err(RootMaintenanceResumeOutcome::RetainedFailure)
            }
        }
        Some(TransferPhase::Transferred {
            kind: accepted_kind,
            accepted: AcceptedTransfer::Frame(accepted_key),
        }) if accepted_kind == kind && accepted_key == next_key => Ok(false),
        _ => {
            trace_root_refusal(ticket, b"frame-transfer-phase", kind as u64);
            Err(RootMaintenanceResumeOutcome::RetainedFailure)
        }
    }
}

unsafe fn exact_hosted(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    pending: win32k_glue::PendingRootMaintenanceDispatch,
    key: nt_component_suspension::SuspensionKey,
) -> Option<HostedNativeContinuation> {
    use nt_user_host::hosted_return_target::HostedReply;
    let lane = ticket.dispatch.lane();
    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    let Some(frame) = lanes.frame(lane, key).ok().flatten() else {
        trace_root_refusal(ticket, b"hosted-identity", 1 << 0);
        return None;
    };
    let Some(hosted) = frame.continuation.hosted() else {
        trace_root_refusal(ticket, b"hosted-identity", 1 << 1);
        return None;
    };
    let PendingComponentDispatch::RootMaintenance(held) = hosted.pending else {
        trace_root_refusal(ticket, b"hosted-identity", 1 << 2);
        return None;
    };
    let Some(reply) = hosted.return_target.delivery() else {
        trace_root_refusal(ticket, b"hosted-identity", 1 << 3);
        return None;
    };
    // The first set bit identifies the failed contract. Keep the original guard order so a
    // later predicate is not evaluated after an earlier identity disagreement.
    let mut mismatch = 0u64;
    if !matches!(reply, HostedReply::Syscall { reply_cap } if reply_cap == ticket.root_reply) {
        mismatch |= 1 << 4;
    }
    if mismatch == 0 && hosted.destination != HostedContinuationDestination::Win32k {
        mismatch |= 1 << 5;
    }
    if mismatch == 0 && (frame.owner != ticket.owner || frame.key != key) {
        mismatch |= 1 << 6;
    }
    if mismatch == 0 && (held.yielded.route != ticket.route || held.yielded.dispatch != ticket.dispatch
        || held.yielded.reply != ticket.origin_reply || held.yielded.owner != ticket.owner
    ) { mismatch |= 1 << 7; }
    if mismatch == 0 && (pending.yielded.route != held.yielded.route
        || pending.yielded.dispatch != held.yielded.dispatch
        || pending.yielded.reply != held.yielded.reply
        || pending.yielded.owner != held.yielded.owner
    ) { mismatch |= 1 << 8; }
    if mismatch == 0 && (pending.snapshot.dispatch.dispatch_id != held.snapshot.dispatch.dispatch_id
        || pending.snapshot.dispatch.lane != held.snapshot.dispatch.lane
    ) { mismatch |= 1 << 9; }
    if mismatch == 0 && (pending.snapshot.client.pi != held.snapshot.client.pi
        || pending.snapshot.client.generation != held.snapshot.client.generation
        || pending.snapshot.client.tid != held.snapshot.client.tid
        || pending.snapshot.client.badge != held.snapshot.client.badge
        || pending.snapshot.client.tcb != held.snapshot.client.tcb
    ) { mismatch |= 1 << 10; }
    if mismatch == 0 && (pending.snapshot.channel.tcb != held.snapshot.channel.tcb
        || pending.snapshot.channel.fault_ep != held.snapshot.channel.fault_ep
    ) { mismatch |= 1 << 11; }
    if mismatch == 0 && pending.snapshot.pump.reply_cap != ticket.origin_reply {
        mismatch |= 1 << 12;
    }
    if mismatch == 0 && lanes.active_dispatch_identity(lane).ok().flatten() != Some(ticket.dispatch) {
        mismatch |= 1 << 13;
    }
    if mismatch == 0 && !lanes.binding(lane).is_ok_and(|binding| {
            binding.reply_object == ticket.reply
                && binding.executor_id == pending.snapshot.channel.tcb
                && binding.receive_endpoint == pending.snapshot.channel.fault_ep
        }) { mismatch |= 1 << 14; }
    if mismatch == 0 && !win32k_glue::win32k_client_context_is_admitted(pending.snapshot.client) {
        mismatch |= 1 << 15;
    }
    if mismatch != 0 {
        trace_root_refusal(ticket, b"hosted-identity", mismatch);
        return None;
    }
    Some(*hosted)
}

unsafe fn transferred_hosted(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    next_key: nt_component_suspension::SuspensionKey,
) -> Option<HostedNativeContinuation> {
    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    let Some(frame) = lanes.frame(ticket.dispatch.lane(), next_key).ok().flatten() else {
        trace_root_refusal(ticket, b"transferred-hosted", 1);
        return None;
    };
    if frame.owner != ticket.owner || frame.key != next_key
        || lanes.active_dispatch_identity(ticket.dispatch.lane()).ok().flatten()
            != Some(ticket.dispatch)
    {
        trace_root_refusal(ticket, b"transferred-hosted", 2);
        return None;
    }
    let hosted = frame.continuation.hosted().copied();
    if hosted.is_none() { trace_root_refusal(ticket, b"transferred-hosted", 4); }
    hosted
}

unsafe fn restore_physical(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
) -> Option<Result<(), runtime::Error>> {
    root_maintenance_owner::with_physical(ticket, |physical| {
        if physical.restore_step()? == RestoreStep::Canonical { physical.canonical_restored()?; }
        if physical.restore_step()? == RestoreStep::Projection { physical.restore_projection()?; }
        if physical.restore_step()? == RestoreStep::Release { physical.release()?; }
        if physical.restore_step()? == RestoreStep::Finalize { physical.projection_restored()?; }
        if physical.restore_step()? == RestoreStep::Done { Ok(()) }
        else { Err(runtime::Error::Admission) }
    })
}

/// Resume the original receive half after a strictly newer independent outer service pass.
/// A native refusal retains the durable row and both Replies; it is never a provider result.
pub(crate) unsafe fn run_root_maintenance(
    nt_handler: *mut ExecNtHandler,
    mut ticket: root_maintenance_owner::RootMaintenanceTicket,
) -> RootMaintenanceResumeOutcome {
    let Some(pending) = root_maintenance_owner::pending(ticket) else {
        trace_root_refusal(ticket, b"pending-owner", 0);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    let Some(key) = root_maintenance_owner::key(ticket) else {
        trace_root_refusal(ticket, b"pending-key", 0);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    let continuation = match root_maintenance_owner::transfer_phase(ticket) {
        Some(TransferPhase::Transferred { accepted: AcceptedTransfer::Frame(next_key), .. }) =>
            transferred_hosted(ticket, next_key),
        _ => exact_hosted(ticket, pending, key),
    };
    let Some(continuation) = continuation else {
        // exact_hosted/transferred_hosted emitted a reason mask at the failed predicate.
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    let pump = if let Some(returned) = root_maintenance_owner::result(ticket) {
        // The physical receive half already returned. Its result is the sole authority for a
        // terminal or repark retry; repeating that native receive would duplicate effects.
        returned
    } else {
        let was_resuming = root_maintenance_owner::is_resuming(ticket);
        // Capacity is a no-effect preflight. Own it while the pure frame is still Ready.
        if root_maintenance_owner::with_callback(ticket, |_| ()).is_none() {
            let Ok(callback_transfer) = component_callback_transfer::CallbackTransfer::reserve() else {
                if was_resuming { trace_root_refusal(ticket, b"callback-reserve", 0); }
                return if was_resuming { RootMaintenanceResumeOutcome::RetainedFailure }
                    else { RootMaintenanceResumeOutcome::DeferredRetry };
            };
            if root_maintenance_owner::store_callback(ticket, callback_transfer).is_err() {
                trace_root_refusal(ticket, b"callback-reserve-store", 0);
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
        }
        if !was_resuming {
            if !root_maintenance_owner::is_admitted(ticket) {
                trace_root_refusal(ticket, b"owner-not-admitted", 0);
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
            match (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .begin_root_maintenance_resume(
                    ticket.dispatch.lane(), ticket.reply, ticket.dispatch, key, ticket.owner,
                ) {
                Ok(_) => {}
                Err(nt_component_suspension::LaneError::Busy) =>
                    return RootMaintenanceResumeOutcome::DeferredRetry,
                Err(error) => {
                    trace_root_refusal(ticket, b"begin-resume", lane_error_code(error));
                    return RootMaintenanceResumeOutcome::RetainedFailure;
                }
            }
            if !root_maintenance_owner::mark_resuming(ticket) {
                trace_root_refusal(ticket, b"mark-resuming", 0);
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
        }
        match restore_physical(ticket) {
            Some(Ok(())) => {}
            result => {
                let error = match result {
                    Some(Err(error)) => physical_error_code(error),
                    _ => 0,
                };
                let step = root_maintenance_owner::with_physical(ticket, |physical| {
                    physical.restore_step()
                });
                trace_root_refusal(ticket, b"physical-restore",
                    (error << 8) | restore_step_code(step));
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
        }
        let returned = win32k_glue::resume_suspended_root_maintenance_component(pending);
        ticket = match root_maintenance_owner::store_result(ticket, returned) {
            Ok(rebased) => rebased,
            Err(_) => {
                trace_root_refusal(ticket, b"store-pump-result", returned.reply_cap);
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
        };
        returned.completion
    };
    if matches!(&pump, win32k_glue::RootMaintenancePumpCompletion::Restored(
        win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended,
    )) {
        if matches!(root_maintenance_owner::transfer_phase(ticket),
            Some(TransferPhase::Transferred {
                kind: TransferKind::CallbackTerminal,
                accepted: AcceptedTransfer::Terminal(_),
            }))
        {
            return RootMaintenanceResumeOutcome::Terminal;
        }
        if root_maintenance_owner::transfer_phase(ticket) != Some(TransferPhase::Returned) {
            trace_root_refusal(ticket, b"callback-phase", 0);
            return RootMaintenanceResumeOutcome::RetainedFailure;
        }
        let token = if let Some(token) = root_maintenance_owner::callback_token(ticket) {
            token
        } else {
            let captured = root_maintenance_owner::with_callback(ticket, |callback_transfer| {
                callback_transfer.capture(
                    pending.snapshot.client, ticket.dispatch.lane(), ticket.owner.dispatch_id,
                )
            });
            let token = match captured {
                Some(Ok(token)) => token,
                Some(Err(status)) => {
                    trace_root_refusal(ticket, b"callback-capture", status as u64);
                    return RootMaintenanceResumeOutcome::RetainedFailure;
                }
                None => {
                    trace_root_refusal(ticket, b"callback-owner", 0);
                    return RootMaintenanceResumeOutcome::RetainedFailure;
                }
            };
            if !root_maintenance_owner::store_callback_token(ticket, token) {
                trace_root_refusal(ticket, b"callback-token-store", token);
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
            token
        };
        if !root_maintenance_owner::begin_result_transfer(
            ticket, TransferKind::CallbackTerminal, key,
        ) {
            trace_root_refusal(ticket, b"callback-transfer-begin", 0);
            return RootMaintenanceResumeOutcome::RetainedFailure;
        }
        return match component_terminal::retain_maintenance_callback_transfer(ticket, key, token) {
            Ok(identity) => {
                if root_maintenance_owner::accept_result_transfer(
                    ticket, AcceptedTransfer::Terminal(identity),
                ) { RootMaintenanceResumeOutcome::Terminal }
                else {
                    trace_root_refusal(ticket, b"callback-transfer-accept", 0);
                    let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
                    RootMaintenanceResumeOutcome::RetainedFailure
                }
            }
            Err(error) => pure_transfer_refused(ticket, error),
        };
    }
    // No callback was yielded. The reserved payload has no native effect to retain.
    let _ = root_maintenance_owner::take_callback(ticket);
    match pump {
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::Completed(dispatch),
        ) => {
            if matches!(root_maintenance_owner::transfer_phase(ticket),
                Some(TransferPhase::Transferred {
                    kind: TransferKind::Terminal,
                    accepted: AcceptedTransfer::Terminal(_),
                }))
            {
                return RootMaintenanceResumeOutcome::Terminal;
            }
            if !root_maintenance_owner::begin_result_transfer(
                ticket, TransferKind::Terminal, key,
            ) {
                trace_root_refusal(ticket, b"terminal-transfer-begin", key.id);
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
            let retained = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .retain_shared_root_maintenance_terminal_running(
                    ticket.route, ticket.dispatch, ticket.dispatch.lane(), ticket.reply,
                    key, ticket.owner, component_terminal::NativeTerminal::completed(dispatch),
                );
            match retained {
                Ok(identity) => {
                    if root_maintenance_owner::accept_result_transfer(
                        ticket, AcceptedTransfer::Terminal(identity),
                    ) { RootMaintenanceResumeOutcome::Terminal }
                    else {
                        trace_root_refusal(ticket, b"terminal-transfer-accept", key.id);
                        let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
                        RootMaintenanceResumeOutcome::RetainedFailure
                    }
                }
                Err((error, _payload)) => pure_transfer_refused(ticket, error),
            }
        }
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::Reparked(next),
        ) => {
            trace_root_repark(ticket, b"provider");
            repark_provider(nt_handler, ticket, key, continuation, next)
        }
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::LpcReparked(next),
        ) => {
            trace_root_repark(ticket, b"lpc");
            repark_lpc(nt_handler, ticket, key, continuation, next)
        }
        win32k_glue::RootMaintenancePumpCompletion::ServiceReparked(next) => {
            trace_root_repark(ticket, b"service");
            repark_service(ticket, key, continuation, next)
        }
        win32k_glue::RootMaintenancePumpCompletion::ReceiveReparked(next) => {
            trace_root_repark(ticket, b"receive");
            repark_receive(ticket, key, continuation, next)
        }
        win32k_glue::RootMaintenancePumpCompletion::MaintenanceReparked(next) => {
            trace_root_repark(ticket, b"maintenance");
            repark_maintenance(ticket, key, continuation, next)
        }
        win32k_glue::RootMaintenancePumpCompletion::RetainedFailure(status) => {
            trace_root_refusal(ticket, b"pump-retained", status as u64);
            RootMaintenanceResumeOutcome::RetainedFailure
        }
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::Failed(status),
        ) => {
            trace_root_refusal(ticket, b"pump-failed", status as u32 as u64);
            RootMaintenanceResumeOutcome::RetainedFailure
        }
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::ReceiveReparked(_)
            | win32k_glue::ProviderWaitPumpCompletion::ServiceReparked(_),
        ) => {
            trace_root_refusal(ticket, b"pump-unexpected-repark", 0);
            RootMaintenanceResumeOutcome::RetainedFailure
        }
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended,
        ) => {
            trace_root_refusal(ticket, b"callback-unexpected", 0);
            RootMaintenanceResumeOutcome::RetainedFailure
        }
    }
}

unsafe fn repark_service(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    key: nt_component_suspension::SuspensionKey,
    mut continuation: HostedNativeContinuation,
    next: win32k_glue::PendingServiceWaitDispatch,
) -> RootMaintenanceResumeOutcome {
    let Some(owner) = service_wait_expected_owner(next) else {
        trace_root_refusal(ticket, b"service-owner-missing", 0);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    if owner != ticket.owner {
        trace_root_refusal(ticket, b"service-owner-mismatch", 0);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    let pending = PendingComponentDispatch::ServiceWait(next);
    let next_key = component_suspension_key(pending);
    continuation.pending = pending;
    let needs_transfer = match need_pure_frame_transfer(ticket, TransferKind::ServiceWait, next_key) {
        Ok(needs_transfer) => needs_transfer,
        Err(outcome) => return outcome,
    };
    if needs_transfer {
        let sequence = next_dispatcher_wait_sequence();
        let yielded = next.yielded;
        match (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .rearm_service_wait_external_owned(
                ticket.dispatch.lane(), yielded.reply, yielded.dispatch, yielded.token,
                key, next_key, sequence, owner,
                ComponentNativeContinuation::Hosted(continuation),
            ) {
            Ok(_) => {
                if !root_maintenance_owner::accept_result_transfer(
                    ticket, AcceptedTransfer::Frame(next_key),
                ) {
                    trace_root_refusal(ticket, b"service-transfer-accept", next_key.id);
                    let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
                    return RootMaintenanceResumeOutcome::RetainedFailure;
                }
            }
            Err((error, _)) => return pure_transfer_refused(ticket, error),
        }
    }
    if root_maintenance_owner::retire_after_repark(ticket, next_key).is_none() {
        trace_root_refusal(ticket, b"service-retire", next_key.id);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    RootMaintenanceResumeOutcome::Parked
}

unsafe fn repark_receive(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    key: nt_component_suspension::SuspensionKey,
    mut continuation: HostedNativeContinuation,
    next: win32k_glue::PendingReceiveDispatch,
) -> RootMaintenanceResumeOutcome {
    let pending = PendingComponentDispatch::Receive(next);
    let next_key = component_suspension_key(pending);
    if next.yielded.replaces != Some(key) || next.yielded.owner != ticket.owner {
        trace_root_refusal(ticket, b"receive-parent", next_key.id);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    continuation.pending = pending;
    let needs_transfer = match need_pure_frame_transfer(ticket, TransferKind::Receive, next_key) {
        Ok(needs_transfer) => needs_transfer,
        Err(outcome) => return outcome,
    };
    if needs_transfer {
        let sequence = next_dispatcher_wait_sequence();
        let parked = runtime::with_bound_receive_scope(next.yielded.parent, |scope| {
            Ok::<_, runtime::Error>(
                (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                    .rearm_receive_owned(
                        scope, key, next_key, sequence, ticket.owner, next.yielded.child,
                        ComponentNativeContinuation::Hosted(continuation),
                    )
            )
        });
        match parked {
            Ok(Ok(_)) => {
                if !root_maintenance_owner::accept_result_transfer(
                    ticket, AcceptedTransfer::Frame(next_key),
                ) {
                    trace_root_refusal(ticket, b"receive-transfer-accept", next_key.id);
                    let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
                    return RootMaintenanceResumeOutcome::RetainedFailure;
                }
            }
            Ok(Err((error, _))) => return pure_transfer_refused(ticket, error),
            Err(_) => {
                trace_root_refusal(ticket, b"receive-scope", next_key.id);
                let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
        }
    }
    if root_maintenance_owner::retire_after_repark(ticket, next_key).is_some() {
        RootMaintenanceResumeOutcome::Parked
    } else {
        trace_root_refusal(ticket, b"receive-retire", next_key.id);
        RootMaintenanceResumeOutcome::RetainedFailure
    }
}

unsafe fn repark_provider(
    handler: *mut ExecNtHandler,
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    key: nt_component_suspension::SuspensionKey,
    mut continuation: HostedNativeContinuation,
    next: win32k_glue::PendingProviderWaitDispatch,
) -> RootMaintenanceResumeOutcome {
    let pending = PendingComponentDispatch::Provider(next);
    let Some(owner) = component_expected_owner(pending) else {
        trace_root_refusal(ticket, b"provider-owner-missing", 0);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    if owner != ticket.owner {
        trace_root_refusal(ticket, b"provider-owner-mismatch", 0);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    let next_key = component_suspension_key(pending);
    continuation.pending = pending;
    let needs_transfer = match need_pure_frame_transfer(ticket, TransferKind::Provider, next_key) {
        Ok(needs_transfer) => needs_transfer,
        Err(outcome) => return outcome,
    };
    if needs_transfer {
        let sequence = next_dispatcher_wait_sequence();
        match (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .rearm_running_owned(
                ticket.dispatch.lane(), ticket.reply, key, next_key, sequence, owner,
                ComponentNativeContinuation::Hosted(continuation),
            ) {
            Ok(_) => {
                if !root_maintenance_owner::accept_result_transfer(
                    ticket, AcceptedTransfer::Frame(next_key),
                ) {
                    trace_root_refusal(ticket, b"provider-transfer-accept", next_key.id);
                    let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
                    return RootMaintenanceResumeOutcome::RetainedFailure;
                }
            }
            Err((error, _)) => return pure_transfer_refused(ticket, error),
        }
    }
    let Some(sequence) = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .frame(ticket.dispatch.lane(), next_key).ok().flatten()
        .map(|frame| frame.admission_sequence) else {
        trace_root_refusal(ticket, b"provider-next-frame", next_key.id);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    if root_maintenance_owner::retire_after_repark(ticket, next_key).is_none() {
        trace_root_refusal(ticket, b"provider-retire", next_key.id);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    admit_provider_after_transfer(handler, next, owner, next_key, sequence);
    RootMaintenanceResumeOutcome::Parked
}

unsafe fn admit_provider_after_transfer(
    handler: *mut ExecNtHandler,
    next: win32k_glue::PendingProviderWaitDispatch,
    owner: nt_component_suspension::SuspensionOwner,
    next_key: nt_component_suspension::SuspensionKey,
    sequence: u64,
) {
    // The typed wait now owns the Reply. Its real backend outcome selects readiness or keeps
    // the wait parked; neither path supplies a fabricated maintenance completion.
    match (&mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER)).admit(
        &mut *handler, &next.request, owner, sequence, nt_time_snapshot(),
    ) {
        Ok(nt_provider_wait::ProviderDispatcherWaitAdmission::Parked { .. }) => {}
        Ok(nt_provider_wait::ProviderDispatcherWaitAdmission::Satisfied { wait_id, status }) => {
            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .select(provider_wait_key(wait_id), ComponentSuspensionCompletion::provider(status));
        }
        Ok(nt_provider_wait::ProviderDispatcherWaitAdmission::TimedOut { wait_id }) => {
            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .select(provider_wait_key(wait_id), ComponentSuspensionCompletion::provider(
                    nt_provider_wait::STATUS_TIMEOUT,
                ));
        }
        Err(error) => {
            let status = provider_wait_status_for_error(error);
            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .cancel(next_key, ComponentSuspensionCompletion::provider(status));
        }
    }
}

unsafe fn repark_lpc(
    handler: *mut ExecNtHandler,
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    key: nt_component_suspension::SuspensionKey,
    mut continuation: HostedNativeContinuation,
    next: win32k_glue::PendingLpcWaitDispatch,
) -> RootMaintenanceResumeOutcome {
    let pending = PendingComponentDispatch::Lpc(next);
    let Some(owner) = component_expected_owner(pending) else {
        trace_root_refusal(ticket, b"lpc-owner-missing", 0);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    if owner != ticket.owner {
        trace_root_refusal(ticket, b"lpc-owner-mismatch", 0);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    let next_key = component_suspension_key(pending);
    continuation.pending = pending;
    let needs_transfer = match need_pure_frame_transfer(ticket, TransferKind::Lpc, next_key) {
        Ok(needs_transfer) => needs_transfer,
        Err(outcome) => return outcome,
    };
    if needs_transfer {
        let sequence = next_dispatcher_wait_sequence();
        match (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .rearm_running_owned(
                ticket.dispatch.lane(), ticket.reply, key, next_key, sequence, owner,
                ComponentNativeContinuation::Hosted(continuation),
            ) {
            Ok(_) => {
                if !root_maintenance_owner::accept_result_transfer(
                    ticket, AcceptedTransfer::Frame(next_key),
                ) {
                    trace_root_refusal(ticket, b"lpc-transfer-accept", next_key.id);
                    let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
                    return RootMaintenanceResumeOutcome::RetainedFailure;
                }
            }
            Err((error, _)) => return pure_transfer_refused(ticket, error),
        }
    }
    let Some(sequence) = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .frame(ticket.dispatch.lane(), next_key).ok().flatten()
        .map(|frame| frame.admission_sequence) else {
        trace_root_refusal(ticket, b"lpc-next-frame", next_key.id);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    // Capacity can refuse after the pure transfer. The accepted frame remains durable, and
    // a later outer pass reserves a fresh backend row without re-entering the pure rearm.
    let Ok(reservation) = (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).reserve() else {
        return RootMaintenanceResumeOutcome::DeferredRetry;
    };
    if root_maintenance_owner::retire_after_repark(ticket, next_key).is_none() {
        let _ = (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).cancel(reservation);
        trace_root_refusal(ticket, b"lpc-retire", next_key.id);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    if lpc_wait_begin_after_stack_admission(&mut *handler, next, next_key, reservation) {
        RootMaintenanceResumeOutcome::Parked
    } else {
        // The exact typed next wait remains in the stack even if the backend selected it.
        RootMaintenanceResumeOutcome::Parked
    }
}

unsafe fn repark_maintenance(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    key: nt_component_suspension::SuspensionKey,
    mut continuation: HostedNativeContinuation,
    next: win32k_glue::PendingRootMaintenanceDispatch,
) -> RootMaintenanceResumeOutcome {
    if next.yielded.route != ticket.route
        || next.yielded.dispatch != ticket.dispatch
        || next.yielded.reply != ticket.reply
        || next.yielded.owner != ticket.owner
        || next.snapshot.pump.reply_cap != ticket.reply
    {
        trace_root_refusal(ticket, b"maintenance-next-identity", 0);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    let Some(new_ticket) = root_maintenance_owner::prepare_next_repark(ticket, next) else {
        return RootMaintenanceResumeOutcome::DeferredRetry;
    };
    let needs_transfer = match need_pure_frame_transfer(ticket, TransferKind::RootMaintenance, key) {
        Ok(needs_transfer) => needs_transfer,
        Err(outcome) => return outcome,
    };
    if needs_transfer {
        let acquisition = root_maintenance_owner::with_physical(new_ticket, |hold| {
            if hold.held() { Ok(()) } else { hold.acquire() }
        });
        if !acquisition.is_some_and(|result| result.is_ok()) {
            use nt_user_host::physical_execution_restore::AcquireStep;
            let step = root_maintenance_owner::with_physical(new_ticket, |hold| hold.acquire_step())
                .and_then(Result::ok);
            if matches!(step, Some(AcquireStep::Ready | AcquireStep::Held))
                && root_maintenance_owner::refuse_result_transfer_no_effects(ticket)
            {
                return RootMaintenanceResumeOutcome::DeferredRetry;
            }
            trace_root_refusal(ticket, b"maintenance-acquire", step.map_or(0, |step| match step {
                AcquireStep::Ready => 1,
                AcquireStep::EnteredUnknown => 2,
                AcquireStep::Held => 3,
                AcquireStep::ProjectionEntered => 4,
                AcquireStep::ProjectionHeld => 5,
            }));
            let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
            return RootMaintenanceResumeOutcome::RetainedFailure;
        }
    }
    continuation.pending = PendingComponentDispatch::RootMaintenance(next);
    if needs_transfer {
        let sequence = next_dispatcher_wait_sequence();
        match (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .repark_root_maintenance_owned(
                ticket.dispatch.lane(), ticket.reply, ticket.dispatch, key, ticket.owner,
                next.yielded.captured_pass, sequence,
                ComponentNativeContinuation::Hosted(continuation),
            ) {
            Ok(_) => {
                if !root_maintenance_owner::accept_result_transfer(
                    ticket, AcceptedTransfer::Frame(key),
                ) {
                    trace_root_refusal(ticket, b"maintenance-transfer-accept", key.id);
                    let _ = root_maintenance_owner::mark_result_transfer_indeterminate(ticket);
                    return RootMaintenanceResumeOutcome::RetainedFailure;
                }
            }
            Err((error, _)) => return pure_transfer_refused(ticket, error),
        }
    }
    if !root_maintenance_owner::is_admitted(new_ticket)
        && !root_maintenance_owner::mark_admitted(new_ticket, key)
    {
        trace_root_refusal(ticket, b"maintenance-next-admit", new_ticket.generation);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    if root_maintenance_owner::retire_after_maintenance_repark(ticket, new_ticket).is_some() {
        RootMaintenanceResumeOutcome::Parked
    } else {
        trace_root_refusal(ticket, b"maintenance-retire", new_ticket.generation);
        RootMaintenanceResumeOutcome::RetainedFailure
    }
}
