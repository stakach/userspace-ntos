//! One exact root-maintenance resume. The ticket owns both Replies and physical exclusion.

use super::*;
use nt_user_host::physical_execution_restore::RestoreStep;
use crate::spawn_hosts::shared_ingress::owner::runtime;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootMaintenanceResumeOutcome {
    DeferredRetry,
    RetainedFailure,
    Parked,
    Terminal,
}

unsafe fn exact_hosted(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    pending: win32k_glue::PendingRootMaintenanceDispatch,
    key: nt_component_suspension::SuspensionKey,
) -> Option<HostedNativeContinuation> {
    use nt_user_host::hosted_return_target::HostedReply;
    let lane = ticket.dispatch.lane();
    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    let frame = lanes.frame(lane, key).ok()??;
    let hosted = frame.continuation.hosted()?;
    let PendingComponentDispatch::RootMaintenance(held) = hosted.pending else { return None; };
    let reply = hosted.return_target.delivery()?;
    if !matches!(reply, HostedReply::Syscall { reply_cap } if reply_cap == ticket.root_reply)
        || hosted.destination != HostedContinuationDestination::Win32k
        || frame.owner != ticket.owner || frame.key != key
        || held.yielded.route != ticket.route
        || held.yielded.dispatch != ticket.dispatch
        || held.yielded.reply != ticket.reply
        || held.yielded.owner != ticket.owner
        || pending.yielded.route != held.yielded.route
        || pending.yielded.dispatch != held.yielded.dispatch
        || pending.yielded.reply != held.yielded.reply
        || pending.yielded.owner != held.yielded.owner
        || pending.snapshot.dispatch.dispatch_id != held.snapshot.dispatch.dispatch_id
        || pending.snapshot.dispatch.lane != held.snapshot.dispatch.lane
        || pending.snapshot.client.pi != held.snapshot.client.pi
        || pending.snapshot.client.generation != held.snapshot.client.generation
        || pending.snapshot.client.tid != held.snapshot.client.tid
        || pending.snapshot.client.badge != held.snapshot.client.badge
        || pending.snapshot.client.tcb != held.snapshot.client.tcb
        || pending.snapshot.channel.tcb != held.snapshot.channel.tcb
        || pending.snapshot.channel.fault_ep != held.snapshot.channel.fault_ep
        || pending.snapshot.pump.reply_cap != ticket.reply
        || lanes.active_dispatch_identity(lane).ok().flatten() != Some(ticket.dispatch)
        || !lanes.binding(lane).is_ok_and(|binding| {
            binding.reply_object == ticket.reply
                && binding.executor_id == pending.snapshot.channel.tcb
                && binding.receive_endpoint == pending.snapshot.channel.fault_ep
        })
        || !win32k_glue::win32k_client_context_is_admitted(pending.snapshot.client)
    {
        return None;
    }
    Some(*hosted)
}

unsafe fn restore_physical(ticket: root_maintenance_owner::RootMaintenanceTicket) -> bool {
    root_maintenance_owner::with_physical(ticket, |physical| {
        if physical.restore_step()? == RestoreStep::Canonical { physical.canonical_restored()?; }
        if physical.restore_step()? == RestoreStep::Projection { physical.restore_projection()?; }
        if physical.restore_step()? == RestoreStep::Release { physical.release()?; }
        if physical.restore_step()? == RestoreStep::Finalize { physical.projection_restored()?; }
        if physical.restore_step()? == RestoreStep::Done { Ok(()) }
        else { Err(runtime::Error::Admission) }
    }).is_some_and(|result: Result<(), runtime::Error>| result.is_ok())
}

/// Resume the original receive half after a strictly newer independent outer service pass.
/// A native refusal retains the durable row and both Replies; it is never a provider result.
pub(crate) unsafe fn run_root_maintenance(
    nt_handler: *mut ExecNtHandler,
    ticket: root_maintenance_owner::RootMaintenanceTicket,
) -> RootMaintenanceResumeOutcome {
    let Some(pending) = root_maintenance_owner::pending(ticket) else {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    let Some(key) = root_maintenance_owner::key(ticket) else {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    let Some(continuation) = exact_hosted(ticket, pending, key) else {
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
                return if was_resuming { RootMaintenanceResumeOutcome::RetainedFailure }
                    else { RootMaintenanceResumeOutcome::DeferredRetry };
            };
            if root_maintenance_owner::store_callback(ticket, callback_transfer).is_err() {
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
        }
        if !was_resuming {
            if !root_maintenance_owner::is_admitted(ticket) {
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
            match (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .begin_root_maintenance_resume(
                    ticket.dispatch.lane(), ticket.reply, ticket.dispatch, key, ticket.owner,
                ) {
                Ok(_) => {}
                Err(nt_component_suspension::LaneError::Busy) =>
                    return RootMaintenanceResumeOutcome::DeferredRetry,
                Err(_) => return RootMaintenanceResumeOutcome::RetainedFailure,
            }
            if !root_maintenance_owner::mark_resuming(ticket) {
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
        }
        if !restore_physical(ticket) {
            return RootMaintenanceResumeOutcome::RetainedFailure;
        }
        let returned = win32k_glue::resume_suspended_root_maintenance_component(pending);
        if root_maintenance_owner::store_result(ticket, returned).is_err() {
            return RootMaintenanceResumeOutcome::RetainedFailure;
        }
        returned
    };
    if matches!(&pump, win32k_glue::RootMaintenancePumpCompletion::Restored(
        win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended,
    )) {
        let token = if let Some(token) = root_maintenance_owner::callback_token(ticket) {
            token
        } else {
            let captured = root_maintenance_owner::with_callback(ticket, |callback_transfer| {
                callback_transfer.capture(
                    pending.snapshot.client, ticket.dispatch.lane(), ticket.owner.dispatch_id,
                )
            });
            let Some(Ok(token)) = captured else {
                return RootMaintenanceResumeOutcome::RetainedFailure;
            };
            if !root_maintenance_owner::store_callback_token(ticket, token) {
                return RootMaintenanceResumeOutcome::RetainedFailure;
            }
            token
        };
        if component_terminal::retain_maintenance_callback_transfer(ticket, key, token) {
            return RootMaintenanceResumeOutcome::Terminal;
        }
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    // No callback was yielded. The reserved payload has no native effect to retain.
    let _ = root_maintenance_owner::take_callback(ticket);
    match pump {
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::Completed(dispatch),
        ) => {
            let retained = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .retain_shared_root_maintenance_terminal_running(
                    ticket.route, ticket.dispatch, ticket.dispatch.lane(), ticket.reply,
                    key, ticket.owner, component_terminal::NativeTerminal::completed(dispatch),
                );
            if retained.is_ok() { RootMaintenanceResumeOutcome::Terminal }
            else { RootMaintenanceResumeOutcome::RetainedFailure }
        }
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::Reparked(next),
        ) => repark_provider(nt_handler, ticket, key, continuation, next),
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::LpcReparked(next),
        ) => repark_lpc(nt_handler, ticket, key, continuation, next),
        win32k_glue::RootMaintenancePumpCompletion::ServiceReparked(next) =>
            repark_service(ticket, key, continuation, next),
        win32k_glue::RootMaintenancePumpCompletion::ReceiveReparked(next) =>
            repark_receive(ticket, key, continuation, next),
        win32k_glue::RootMaintenancePumpCompletion::MaintenanceReparked(next) =>
            repark_maintenance(ticket, key, continuation, next),
        win32k_glue::RootMaintenancePumpCompletion::RetainedFailure(_)
        | win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::Failed(_)
            | win32k_glue::ProviderWaitPumpCompletion::ReceiveReparked(_)
            | win32k_glue::ProviderWaitPumpCompletion::ServiceReparked(_),
        ) => RootMaintenanceResumeOutcome::RetainedFailure,
        win32k_glue::RootMaintenancePumpCompletion::Restored(
            win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended,
        ) => RootMaintenanceResumeOutcome::RetainedFailure,
    }
}

unsafe fn repark_service(
    ticket: root_maintenance_owner::RootMaintenanceTicket,
    key: nt_component_suspension::SuspensionKey,
    mut continuation: HostedNativeContinuation,
    next: win32k_glue::PendingServiceWaitDispatch,
) -> RootMaintenanceResumeOutcome {
    let Some(owner) = service_wait_expected_owner(next) else {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    if owner != ticket.owner { return RootMaintenanceResumeOutcome::RetainedFailure; }
    let pending = PendingComponentDispatch::ServiceWait(next);
    let next_key = component_suspension_key(pending);
    continuation.pending = pending;
    let sequence = next_dispatcher_wait_sequence();
    let yielded = next.yielded;
    if (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
        .rearm_service_wait_external_owned(
            ticket.dispatch.lane(), yielded.reply, yielded.dispatch, yielded.token,
            key, next_key, sequence, owner,
            ComponentNativeContinuation::Hosted(continuation),
        ).is_err()
    {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    if root_maintenance_owner::retire_after_repark(ticket, next_key).is_none() {
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
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    continuation.pending = pending;
    let sequence = next_dispatcher_wait_sequence();
    let parked = runtime::with_bound_receive_scope(next.yielded.parent, |scope| {
        (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
            .rearm_receive_owned(
                scope, key, next_key, sequence, ticket.owner, next.yielded.child,
                ComponentNativeContinuation::Hosted(continuation),
            )
            .map(|_| ())
            .map_err(|_| runtime::Error::Admission)
    });
    if parked.is_err() || root_maintenance_owner::retire_after_repark(ticket, next_key).is_none() {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    RootMaintenanceResumeOutcome::Parked
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
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    if owner != ticket.owner { return RootMaintenanceResumeOutcome::RetainedFailure; }
    let next_key = component_suspension_key(pending);
    let sequence = next_dispatcher_wait_sequence();
    continuation.pending = pending;
    if (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
        .rearm_running(
            ticket.dispatch.lane(), ticket.reply, key, next_key, sequence, owner,
            ComponentNativeContinuation::Hosted(continuation),
        ).is_err()
    {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    if root_maintenance_owner::retire_after_repark(ticket, next_key).is_none() {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
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
    RootMaintenanceResumeOutcome::Parked
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
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    if owner != ticket.owner { return RootMaintenanceResumeOutcome::RetainedFailure; }
    let Ok(reservation) = (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).reserve() else {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    let next_key = component_suspension_key(pending);
    let sequence = next_dispatcher_wait_sequence();
    continuation.pending = pending;
    if (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
        .rearm_running(
            ticket.dispatch.lane(), ticket.reply, key, next_key, sequence, owner,
            ComponentNativeContinuation::Hosted(continuation),
        ).is_err()
    {
        let _ = (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).cancel(reservation);
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    if root_maintenance_owner::retire_after_repark(ticket, next_key).is_none() {
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
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    let Some(reservation) = root_maintenance_owner::reserve_capacity() else {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    };
    let new_ticket = match root_maintenance_owner::retain(reservation, next, ticket.root_reply) {
        Ok(ticket) => ticket,
        Err(_) => {
            root_maintenance_owner::cancel_reservation(reservation);
            return RootMaintenanceResumeOutcome::RetainedFailure;
        },
    };
    if !root_maintenance_owner::with_physical(new_ticket, |hold| hold.acquire())
        .is_some_and(|result| result.is_ok())
    {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    continuation.pending = PendingComponentDispatch::RootMaintenance(next);
    let sequence = next_dispatcher_wait_sequence();
    if (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
        .repark_root_maintenance_owned(
            ticket.dispatch.lane(), ticket.reply, ticket.dispatch, key, ticket.owner,
            next.yielded.captured_pass, sequence,
            ComponentNativeContinuation::Hosted(continuation),
        ).is_err()
    {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    if !root_maintenance_owner::mark_admitted(new_ticket, key)
        || root_maintenance_owner::retire_after_maintenance_repark(ticket, new_ticket).is_none()
    {
        return RootMaintenanceResumeOutcome::RetainedFailure;
    }
    RootMaintenanceResumeOutcome::Parked
}
