//! One exact hosted resume; no executive-state reference survives its provider pump.

use super::*;

pub(crate) unsafe fn run_hosted(
    nt_handler: *mut ExecNtHandler,
    candidate: Candidate,
) -> Option<ComponentSuspensionRuntimeOutcome> {
    let lane_resume = candidate.resume;
    let lane = lane_resume.lane;
    let reply_object = lane_resume.binding.reply_object;
    let resume = lane_resume.suspension;
    let frame = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .frame(lane, resume.key)
        .ok()??
        .clone();
    if frame.owner != candidate.owner || frame.admission_sequence != candidate.sequence {
        return None;
    }
    let continuation = match frame.continuation {
        ComponentNativeContinuation::Hosted(hosted) => hosted,
        ComponentNativeContinuation::Kernel(_) => return None,
    };
    if matches!(continuation.pending, PendingComponentDispatch::Receive(_)) {
        return None;
    }
    if !continuation.return_target.can_resume()
        || !win32k_glue::win32k_client_context_is_admitted(continuation.pending.client())
    {
        return None;
    }
    // Reserve all handoff storage before entering a provider that may yield a callback.
    // Refusal leaves the selected source wait and its reply authority unchanged.
    let Ok(callback_transfer) = component_callback_transfer::CallbackTransfer::reserve() else {
        return None;
    };
    let admitted = {
        let _durable = allocator::enter_durable();
        (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS)).begin_resume(
            lane,
            reply_object,
            resume.key,
        )
    };
    // Claim-time cancellation/completion is authoritative, not the earlier candidate snapshot.
    let Ok(resume) = admitted else {
        return None;
    };
    let admitted_dispatch = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .active_dispatch_identity(lane)
        .expect("resumed provider retains its dispatch identity")
        .expect("resumed provider retains an active dispatch");
    let provider_resume = matches!(continuation.pending, PendingComponentDispatch::Provider(_));
    if provider_resume {
        PROVIDER_WAIT_RESUMES.fetch_add(1, Ordering::Relaxed);
        if !resume.cancelled {
            PROVIDER_WAIT_SUCCESSFUL_RESUMES.fetch_add(1, Ordering::Relaxed);
        }
    }
    let pump_completion = match continuation.pending {
        PendingComponentDispatch::Provider(pending) => {
            match win32k_glue::resume_suspended_provider_wait_component(
                pending,
                resume.key.id,
                resume.completion.status,
            ) {
                win32k_glue::ProviderWaitPumpCompletion::Completed(dispatch) => {
                    ComponentPumpCompletion::Completed(dispatch)
                }
                win32k_glue::ProviderWaitPumpCompletion::Reparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::Provider(pending))
                }
                win32k_glue::ProviderWaitPumpCompletion::LpcReparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::Lpc(pending))
                }
                win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended => {
                    ComponentPumpCompletion::UserCallbackSuspended
                }
                win32k_glue::ProviderWaitPumpCompletion::Failed(status) => {
                    ComponentPumpCompletion::Failed(status)
                }
            }
        }
        PendingComponentDispatch::Lpc(pending) => {
            match win32k_glue::resume_suspended_lpc_wait_component(
                pending,
                resume.completion.lpc_message_id,
                resume.completion.status,
                resume.completion.lpc_reply(),
            ) {
                win32k_glue::LpcWaitPumpCompletion::Completed(dispatch) => {
                    ComponentPumpCompletion::Completed(dispatch)
                }
                win32k_glue::LpcWaitPumpCompletion::ProviderReparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::Provider(pending))
                }
                win32k_glue::LpcWaitPumpCompletion::Reparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::Lpc(pending))
                }
                win32k_glue::LpcWaitPumpCompletion::UserCallbackSuspended => {
                    ComponentPumpCompletion::UserCallbackSuspended
                }
                win32k_glue::LpcWaitPumpCompletion::Failed(status) => {
                    ComponentPumpCompletion::Failed(status)
                }
            }
        }
        PendingComponentDispatch::Receive(_) => {
            unreachable!("Receive requires its sealed child boundary")
        }
    };
    finish_hosted_resume(
        nt_handler,
        lane,
        lane_resume.binding,
        admitted_dispatch,
        resume,
        frame,
        continuation,
        callback_transfer,
        pump_completion,
    )
}

/// Resume only the exact Receive child boundary retained by the physical parent owner.
pub(crate) unsafe fn run_receive(
    nt_handler: *mut ExecNtHandler,
    boundary: crate::spawn_hosts::shared_ingress::owner::runtime::ReceiveSettlementBoundary,
) -> Option<crate::spawn_hosts::shared_ingress::owner::runtime::ReceiveSettlementBoundary> {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let prepared = (|| {
        let handle = boundary.parent.as_ref()?;
        let (lane, binding, dispatch, frame, continuation, pending) =
            runtime::nested::with_receive_restore(handle, |scope, permit| {
                // Settlement certifies the captured child lifetime. Its current row may have retired
                // or been reused after ACK; re-admission cannot revoke that exact settled receipt.
                let dispatch = scope.dispatch();
                let lane = dispatch.lane();
                let key = nt_component_suspension::SuspensionKey::receive(
                    permit.admission_key().admission_sequence(),
                );
                let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
                let frame = lanes
                    .frame(lane, key)
                    .map_err(|_| runtime::Error::Admission)?
                    .ok_or(runtime::Error::Admission)?
                    .clone();
                let ComponentNativeContinuation::Hosted(continuation) = frame.continuation else {
                    return Err(runtime::Error::Admission);
                };
                let PendingComponentDispatch::Receive(pending) = continuation.pending else {
                    return Err(runtime::Error::Admission);
                };
                if pending.yielded.parent != scope.identity()
                    || pending.yielded.child != permit.admission_key()
                    || pending.yielded.owner != frame.owner
                    || !continuation.return_target.can_resume()
                    || !win32k_glue::win32k_client_context_is_admitted(pending.client)
                {
                    return Err(runtime::Error::Admission);
                }
                let binding = lanes.binding(lane).map_err(|_| runtime::Error::Admission)?;
                Ok((lane, binding, dispatch, frame, continuation, pending))
            })
            .ok()?;
        let callback_transfer = component_callback_transfer::CallbackTransfer::reserve().ok()?;
        let resume = runtime::nested::with_receive_restore(handle, |scope, permit| {
            // Internal readiness only: no completion value is delivered to a provider or user.
            (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .begin_receive_restore(
                    scope,
                    frame.key,
                    frame.owner,
                    permit.settlement(),
                    ComponentSuspensionCompletion::receive_ready(),
                )
                .map_err(|_| runtime::Error::Admission)
        })
        .ok()?;
        Some((
            lane,
            binding,
            dispatch,
            frame,
            continuation,
            pending,
            callback_transfer,
            resume,
        ))
    })();
    let Some((lane, binding, dispatch, frame, continuation, pending, callback_transfer, resume)) =
        prepared
    else {
        return Some(boundary);
    };
    let pump_completion = match win32k_glue::resume_suspended_receive_component(pending, boundary) {
        win32k_glue::ReceivePumpCompletion::Restored(completion) => completion,
        win32k_glue::ReceivePumpCompletion::Reparked(next) => {
            assert!(
                next.yielded.replaces == Some(frame.key) && next.yielded.owner == frame.owner,
                "Receive repark retains the original exact continuation owner"
            );
            let next_key = component_suspension_key(PendingComponentDispatch::Receive(next));
            let sequence = next_dispatcher_wait_sequence();
            let next_continuation = ComponentNativeContinuation::Hosted(HostedNativeContinuation {
                pending: PendingComponentDispatch::Receive(next),
                return_target: continuation.return_target,
            });
            runtime::with_bound_receive_scope(next.yielded.parent, |scope| {
                (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                    .rearm_receive_owned(
                        scope,
                        frame.key,
                        next_key,
                        sequence,
                        frame.owner,
                        next.yielded.child,
                        next_continuation,
                    )
                    .map(|_| ())
                    .map_err(|_| runtime::Error::Admission)
            })
            .expect(
                "Receive repark retains both sealed child and original continuation on refusal",
            );
            return None;
        }
        win32k_glue::ReceivePumpCompletion::Deferred(boundary) => {
            // No callback input or capability has been captured into this reserved storage.
            // The exact Parent, child permit and Resuming frame remain retained by their owners.
            return Some(boundary);
        }
    };
    let pump_completion = match pump_completion {
        win32k_glue::ProviderWaitPumpCompletion::Completed(dispatch) => {
            ComponentPumpCompletion::Completed(dispatch)
        }
        win32k_glue::ProviderWaitPumpCompletion::Reparked(pending) => {
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::Provider(pending))
        }
        win32k_glue::ProviderWaitPumpCompletion::LpcReparked(pending) => {
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::Lpc(pending))
        }
        win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended => {
            ComponentPumpCompletion::UserCallbackSuspended
        }
        win32k_glue::ProviderWaitPumpCompletion::Failed(status) => {
            ComponentPumpCompletion::Failed(status)
        }
    };
    let outcome = finish_hosted_resume(
        nt_handler,
        lane,
        binding,
        dispatch,
        resume,
        frame,
        continuation,
        callback_transfer,
        pump_completion,
    );
    assert!(
        outcome.is_some(),
        "restored Receive retains its terminal or re-wait owner"
    );
    None
}

unsafe fn finish_hosted_resume(
    nt_handler: *mut ExecNtHandler,
    lane: nt_component_suspension::LaneHandle,
    original_binding: nt_component_suspension::LaneBinding,
    admitted_dispatch: nt_component_suspension::LaneDispatchIdentity,
    resume: nt_component_suspension::SuspensionResume<ComponentSuspensionCompletion>,
    frame: nt_component_suspension::SuspensionFrame<
        ComponentNativeContinuation,
        ComponentSuspensionCompletion,
    >,
    continuation: HostedNativeContinuation,
    mut callback_transfer: component_callback_transfer::CallbackTransfer,
    pump_completion: ComponentPumpCompletion,
) -> Option<ComponentSuspensionRuntimeOutcome> {
    // An authenticated interim Call may replace the lane's Reply while the provider runs.
    // Its dispatch epoch and physical executor remain the same, but the pre-pump Reply is stale.
    let current_binding = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .binding(lane)
        .expect("provider return retains its exact lane");
    assert_eq!(current_binding.executor_id, original_binding.executor_id);
    assert_eq!(
        current_binding.receive_endpoint,
        original_binding.receive_endpoint
    );
    let dispatch = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .active_dispatch_identity(lane)
        .expect("provider return retains its dispatch identity")
        .expect("provider return retains an active dispatch");
    assert_eq!(dispatch, admitted_dispatch);
    let reply_object = current_binding.reply_object;
    match pump_completion {
        ComponentPumpCompletion::Completed(dispatch) => {
            (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .retain_terminal_running(
                    lane,
                    reply_object,
                    resume.key,
                    frame.owner,
                    component_terminal::NativeTerminal::completed(dispatch),
                )
                .unwrap_or_else(|(error, _)| {
                    panic!("completed component lost its terminal owner: {:?}", error)
                });
            return Some(ComponentSuspensionRuntimeOutcome::Terminal);
        }
        ComponentPumpCompletion::UserCallbackSuspended => {
            let captured = callback_transfer.capture(
                continuation.pending.client(),
                lane,
                frame.owner.dispatch_id,
            );
            component_terminal::retain_callback_transfer(
                lane,
                reply_object,
                resume.key,
                frame.owner,
                callback_transfer,
                captured,
            );
            return Some(ComponentSuspensionRuntimeOutcome::Terminal);
        }
        ComponentPumpCompletion::Failed(status) => {
            // Failed includes pre-entry rejection, a still-parked provider, and uncertain
            // post-entry cleanup. Only Completed carries proof of an actual provider return.
            component_terminal::retain_incomplete_provider(
                lane,
                reply_object,
                resume.key,
                frame.owner,
                None,
                status as u32,
            );
            return Some(ComponentSuspensionRuntimeOutcome::Terminal);
        }
        ComponentPumpCompletion::Reparked(next) => {
            if matches!(next, PendingComponentDispatch::Provider(_)) {
                PROVIDER_WAIT_REARMS.fetch_add(1, Ordering::Relaxed);
            }
            let Some(next_owner) = component_expected_owner(next) else {
                component_terminal::retain_incomplete_provider(
                    lane,
                    reply_object,
                    resume.key,
                    frame.owner,
                    Some(next),
                    0xC000_000D,
                );
                return Some(ComponentSuspensionRuntimeOutcome::Terminal);
            };
            let lpc_reservation = if matches!(next, PendingComponentDispatch::Lpc(_)) {
                match (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).reserve() {
                    Ok(reservation) => Some(reservation),
                    Err(_) => {
                        component_terminal::retain_incomplete_provider(
                            lane,
                            reply_object,
                            resume.key,
                            frame.owner,
                            Some(next),
                            0xC000_009A,
                        );
                        return Some(ComponentSuspensionRuntimeOutcome::Terminal);
                    }
                }
            } else {
                None
            };
            let next_key = component_suspension_key(next);
            let sequence = next_dispatcher_wait_sequence();
            let mut next_continuation = continuation;
            next_continuation.pending = next;
            if (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .rearm_running(
                    lane,
                    reply_object,
                    resume.key,
                    next_key,
                    sequence,
                    next_owner,
                    ComponentNativeContinuation::Hosted(next_continuation),
                )
                .is_err()
            {
                if let Some(reservation) = lpc_reservation {
                    let _ =
                        (&mut *core::ptr::addr_of_mut!(LPC_COMPONENT_WAITS)).cancel(reservation);
                }
                component_terminal::retain_incomplete_provider(
                    lane,
                    reply_object,
                    resume.key,
                    frame.owner,
                    Some(next),
                    0xC000_000D,
                );
                return Some(ComponentSuspensionRuntimeOutcome::Terminal);
            }
            match next {
                PendingComponentDispatch::Provider(next) => {
                    let admission = (&mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER)).admit(
                        &mut *nt_handler,
                        &next.request,
                        next_owner,
                        sequence,
                        nt_time_snapshot(),
                    );
                    match admission {
                        Ok(nt_provider_wait::ProviderDispatcherWaitAdmission::Parked {
                            ..
                        }) => {
                            PROVIDER_WAIT_PARKED_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
                            trace_provider_wait_admission(
                                b"repark",
                                next.request.header.wait_id,
                                0x0000_0103,
                                next.request.header.object_count as u64,
                            );
                            return Some(ComponentSuspensionRuntimeOutcome::Parked);
                        }
                        Ok(nt_provider_wait::ProviderDispatcherWaitAdmission::Satisfied {
                            wait_id,
                            status,
                        }) => {
                            trace_provider_wait_admission(
                                b"ready-rearm",
                                wait_id,
                                status,
                                next.request.header.object_count as u64,
                            );
                            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS)).select(
                                provider_wait_key(wait_id),
                                ComponentSuspensionCompletion::provider(status),
                            );
                        }
                        Ok(nt_provider_wait::ProviderDispatcherWaitAdmission::TimedOut {
                            wait_id,
                        }) => {
                            trace_provider_wait_admission(
                                b"timeout-rearm",
                                wait_id,
                                nt_provider_wait::STATUS_TIMEOUT,
                                next.request.header.object_count as u64,
                            );
                            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS)).select(
                                provider_wait_key(wait_id),
                                ComponentSuspensionCompletion::provider(
                                    nt_provider_wait::STATUS_TIMEOUT,
                                ),
                            );
                        }
                        Err(error) => {
                            let status = provider_wait_status_for_error(error);
                            trace_provider_wait_admission(
                                b"reject-rearm",
                                next.request.header.wait_id,
                                status,
                                provider_wait_error_detail(error),
                            );
                            let _ = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                                .cancel(next_key, ComponentSuspensionCompletion::provider(status));
                        }
                    }
                }
                PendingComponentDispatch::Lpc(next) => {
                    if lpc_wait_begin_after_stack_admission(
                        &mut *nt_handler,
                        next,
                        next_key,
                        lpc_reservation.expect("LPC re-wait has readiness reservation"),
                    ) {
                        return Some(ComponentSuspensionRuntimeOutcome::Parked);
                    }
                }
                PendingComponentDispatch::Receive(_) => {
                    unreachable!("Receive is not a readiness wait")
                }
            }
        }
    }
    Some(ComponentSuspensionRuntimeOutcome::Rearmed)
}
