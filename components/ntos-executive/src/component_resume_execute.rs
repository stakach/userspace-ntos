//! One exact hosted resume; no executive-state reference survives its provider pump.

use super::*;

static REPARK_FAILURE_TRACE: AtomicU64 = AtomicU64::new(0);
static REPARK_CONFLICT_TRACE: AtomicU64 = AtomicU64::new(0);
static NESTED_PROVIDER_OUTER_TRACES: AtomicU64 = AtomicU64::new(0);

fn trace_nested_provider_outer(
    stage: &'static [u8], old_key: nt_component_suspension::SuspensionKey,
    dispatch_id: u64, next_wait: u64, detail: u64,
) {
    print_str(b"[nested-provider-outer] stage="); print_str(stage);
    print_str(b" old-wait/dispatch/next-wait/detail=");
    print_u64(old_key.id); print_str(b"/"); print_u64(dispatch_id);
    print_str(b"/"); print_u64(next_wait); print_str(b"/");
    print_u64(detail); print_str(b"\n");
}

fn trace_repark_failure(
    branch: &'static [u8], lane: nt_component_suspension::LaneHandle,
    key: nt_component_suspension::SuspensionKey, status: u32,
    next: Option<PendingComponentDispatch>,
    error: Option<nt_component_suspension::LaneError>,
) {
    if REPARK_FAILURE_TRACE.fetch_add(1, Ordering::Relaxed) >= 8 { return; }
    print_str(b"[component-repark-failure] branch="); print_str(branch);
    print_str(b" lane/generation/key-kind/key-id=");
    print_u64(u64::from(lane.index)); print_str(b"/"); print_u64(lane.generation);
    print_str(b"/"); print_u64(key.kind as u64); print_str(b"/"); print_u64(key.id);
    print_str(b" status=0x"); print_hex(status);
    print_str(b" next=");
    print_str(match next {
        None => b"none",
        Some(PendingComponentDispatch::Provider(_)) => b"provider",
        Some(PendingComponentDispatch::Lpc(_)) => b"lpc",
        Some(PendingComponentDispatch::Receive(_)) => b"receive",
        Some(PendingComponentDispatch::ServiceWait(_)) => b"service-wait",
        Some(PendingComponentDispatch::RootMaintenance(_)) => b"root-maintenance",
        Some(PendingComponentDispatch::NestedRestore(_)) => b"nested-restore",
    });
    print_str(b" error=");
    print_str(match error {
        None => b"none",
        Some(nt_component_suspension::LaneError::InvalidIdentity) => b"invalid-identity",
        Some(nt_component_suspension::LaneError::DuplicateBinding) => b"duplicate-binding",
        Some(nt_component_suspension::LaneError::NoCapacity) => b"no-capacity",
        Some(nt_component_suspension::LaneError::NotFound) => b"not-found",
        Some(nt_component_suspension::LaneError::StaleGeneration) => b"stale-generation",
        Some(nt_component_suspension::LaneError::WrongBinding) => b"wrong-binding",
        Some(nt_component_suspension::LaneError::Busy) => b"busy",
        Some(nt_component_suspension::LaneError::InvalidPhase) => b"invalid-phase",
        Some(nt_component_suspension::LaneError::Suspension(inner)) => match inner {
            nt_component_suspension::SuspensionError::InvalidPhase => b"suspension-invalid-phase",
            nt_component_suspension::SuspensionError::NotTop => b"suspension-not-top",
            nt_component_suspension::SuspensionError::DuplicateIdentity => b"suspension-duplicate-identity",
            _ => b"suspension-other",
        },
    });
    print_str(b"\n");
}

pub(crate) unsafe fn run_hosted(
    nt_handler: *mut ExecNtHandler,
    candidate: Candidate,
) -> Option<ComponentSuspensionRuntimeOutcome> {
    let trace_lane = candidate.resume.lane;
    let trace_key = candidate.resume.suspension.key;
    let trace_owner = candidate.owner;
    let root_blocked = crate::spawn_hosts::shared_ingress::owner::runtime::root_ingress_parent_blocks_provider_resume();
    let source_blocked = crate::spawn_hosts::shared_ingress::owner::runtime::nested::source_ioctl_parent_blocks_provider_resume(
            candidate.owner.dispatch_id,
        );
    if root_blocked || source_blocked {
        trace_preclaim_refusal(b"physical-parent-blocked", trace_lane, trace_key, trace_owner,
            u64::from(root_blocked) | (u64::from(source_blocked) << 1));
        return None;
    }
    let lane_resume = candidate.resume;
    let lane = lane_resume.lane;
    let reply_object = lane_resume.binding.reply_object;
    let resume = lane_resume.suspension;
    let Some(frame) = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .frame(lane, resume.key)
        .ok().flatten().cloned() else {
        trace_preclaim_refusal(b"frame-absent", trace_lane, trace_key, trace_owner, 0);
        return None;
    };
    if frame.owner != candidate.owner || frame.admission_sequence != candidate.sequence {
        trace_preclaim_refusal(b"frame-identity-changed", trace_lane, trace_key, trace_owner,
            frame.admission_sequence);
        return None;
    }
    let continuation = match frame.continuation {
        ComponentNativeContinuation::Hosted(hosted) => hosted,
        ComponentNativeContinuation::Kernel(_) => {
            trace_preclaim_refusal(b"became-kernel", trace_lane, trace_key, trace_owner, 0);
            return None;
        }
        ComponentNativeContinuation::RootIngress(_) => {
            trace_preclaim_refusal(b"became-root-ingress", trace_lane, trace_key, trace_owner, 0);
            return None;
        }
    };
    if matches!(continuation.pending, PendingComponentDispatch::Receive(_)
        | PendingComponentDispatch::RootMaintenance(_)
        | PendingComponentDispatch::NestedRestore(_)) {
        trace_preclaim_refusal(b"unsupported-pending-kind", trace_lane, trace_key, trace_owner, 0);
        return None;
    }
    let reply_ready = continuation.return_target.can_resume();
    let client_ready = win32k_glue::win32k_client_context_is_admitted(continuation.pending.client());
    if !reply_ready || !client_ready {
        trace_preclaim_refusal(b"claim-readiness-refused", trace_lane, trace_key, trace_owner,
            u64::from(reply_ready) | (u64::from(client_ready) << 1));
        return None;
    }
    // Reserve all handoff storage before entering a provider that may yield a callback.
    // Refusal leaves the selected source wait and its reply authority unchanged.
    let Ok(callback_transfer) = component_callback_transfer::CallbackTransfer::reserve() else {
        trace_preclaim_refusal(b"callback-transfer-capacity", trace_lane, trace_key, trace_owner, 0);
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
        trace_preclaim_refusal(b"begin-resume-refused", trace_lane, trace_key, trace_owner, 0);
        return None;
    };
    let admitted_dispatch = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .active_dispatch_identity(lane)
        .expect("resumed provider retains its dispatch identity")
        .expect("resumed provider retains an active dispatch");
    crate::spawn_hosts::shared_ingress::owner::runtime::nested::record_source_resume_transition(
        1, lane, admitted_dispatch, reply_object, resume.key, frame.owner,
    );
    let provider_resume = matches!(continuation.pending, PendingComponentDispatch::Provider(_));
    if provider_resume {
        PROVIDER_WAIT_RESUMES.fetch_add(1, Ordering::Relaxed);
        if !resume.cancelled {
            PROVIDER_WAIT_SUCCESSFUL_RESUMES.fetch_add(1, Ordering::Relaxed);
        }
    }
    let pump_completion = match continuation.pending {
        PendingComponentDispatch::Provider(pending) => {
            crate::spawn_hosts::shared_ingress::owner::runtime::nested::record_source_resume_transition(
                2, lane, admitted_dispatch, reply_object, resume.key, frame.owner,
            );
            let completion = win32k_glue::resume_suspended_provider_wait_component(
                nt_handler,
                pending,
                resume.key.id,
                resume.completion.status,
            );
            crate::spawn_hosts::shared_ingress::owner::runtime::nested::record_source_resume_transition(
                3, lane, admitted_dispatch, reply_object, resume.key, frame.owner,
            );
            match completion {
                win32k_glue::ProviderWaitPumpCompletion::NestedSourceDeferred => {
                    crate::spawn_hosts::shared_ingress::owner::runtime::nested::trace_deferred_resume_owner(
                        lane, resume.key, frame.owner,
                    );
                    return None;
                }
                win32k_glue::ProviderWaitPumpCompletion::Completed(dispatch) => {
                    ComponentPumpCompletion::Completed(dispatch)
                }
                win32k_glue::ProviderWaitPumpCompletion::Reparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::Provider(pending))
                }
                win32k_glue::ProviderWaitPumpCompletion::LpcReparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::Lpc(pending))
                }
                win32k_glue::ProviderWaitPumpCompletion::ReceiveReparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::Receive(pending))
                }
                win32k_glue::ProviderWaitPumpCompletion::ServiceReparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::ServiceWait(pending))
                }
                win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended => {
                    ComponentPumpCompletion::UserCallbackSuspended
                }
                win32k_glue::ProviderWaitPumpCompletion::Failed(status) => {
                    ComponentPumpCompletion::Failed(status)
                }
                win32k_glue::ProviderWaitPumpCompletion::CaptureRefused(_, pump, channel) => {
                    ComponentPumpCompletion::CaptureRefused(
                        continuation.pending, pump, channel,
                    )
                }
                win32k_glue::ProviderWaitPumpCompletion::RetainedFailure(pending, status) => {
                    ComponentPumpCompletion::FailedRetained(
                        PendingComponentDispatch::Provider(pending), status,
                    )
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
                win32k_glue::LpcWaitPumpCompletion::ReceiveReparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::Receive(pending))
                }
                win32k_glue::LpcWaitPumpCompletion::ServiceReparked(pending) => {
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::ServiceWait(pending))
                }
                win32k_glue::LpcWaitPumpCompletion::UserCallbackSuspended => {
                    ComponentPumpCompletion::UserCallbackSuspended
                }
                win32k_glue::LpcWaitPumpCompletion::Failed(status) => {
                    ComponentPumpCompletion::Failed(status)
                }
                win32k_glue::LpcWaitPumpCompletion::CaptureRefused(_, pump, channel) => {
                    ComponentPumpCompletion::CaptureRefused(
                        continuation.pending, pump, channel,
                    )
                }
                win32k_glue::LpcWaitPumpCompletion::RetainedFailure(pending, status) => {
                    ComponentPumpCompletion::FailedRetained(
                        PendingComponentDispatch::Lpc(pending), status,
                    )
                }
            }
        }
        PendingComponentDispatch::Receive(_) => {
            unreachable!("Receive requires its sealed child boundary")
        }
        PendingComponentDispatch::RootMaintenance(_) => return None,
        PendingComponentDispatch::NestedRestore(_) => return None,
        PendingComponentDispatch::ServiceWait(pending) => {
            match win32k_glue::resume_suspended_service_wait_component(pending) {
                win32k_glue::ServiceWaitPumpCompletion::Restored(completion) => match completion {
                    win32k_glue::ProviderWaitPumpCompletion::NestedSourceDeferred => {
                        crate::spawn_hosts::shared_ingress::owner::runtime::nested::trace_deferred_resume_owner(
                            lane, resume.key, frame.owner,
                        );
                        return None;
                    }
                    win32k_glue::ProviderWaitPumpCompletion::Completed(dispatch) =>
                        ComponentPumpCompletion::Completed(dispatch),
                    win32k_glue::ProviderWaitPumpCompletion::Reparked(pending) =>
                        ComponentPumpCompletion::Reparked(PendingComponentDispatch::Provider(pending)),
                    win32k_glue::ProviderWaitPumpCompletion::LpcReparked(pending) =>
                        ComponentPumpCompletion::Reparked(PendingComponentDispatch::Lpc(pending)),
                    win32k_glue::ProviderWaitPumpCompletion::ReceiveReparked(pending) =>
                        ComponentPumpCompletion::Reparked(PendingComponentDispatch::Receive(pending)),
                    win32k_glue::ProviderWaitPumpCompletion::ServiceReparked(pending) =>
                        ComponentPumpCompletion::Reparked(PendingComponentDispatch::ServiceWait(pending)),
                    win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended =>
                        ComponentPumpCompletion::UserCallbackSuspended,
                    win32k_glue::ProviderWaitPumpCompletion::Failed(status) =>
                        ComponentPumpCompletion::Failed(status),
                    win32k_glue::ProviderWaitPumpCompletion::CaptureRefused(_, pump, channel) =>
                        ComponentPumpCompletion::CaptureRefused(
                            continuation.pending, pump, channel,
                        ),
                    win32k_glue::ProviderWaitPumpCompletion::RetainedFailure(pending, status) =>
                        ComponentPumpCompletion::FailedRetained(
                            PendingComponentDispatch::Provider(pending), status,
                        ),
                },
                win32k_glue::ServiceWaitPumpCompletion::ServiceReparked(pending) =>
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::ServiceWait(pending)),
                win32k_glue::ServiceWaitPumpCompletion::ReceiveReparked(pending) =>
                    ComponentPumpCompletion::Reparked(PendingComponentDispatch::Receive(pending)),
                win32k_glue::ServiceWaitPumpCompletion::CaptureRefused(_, pump, channel) =>
                    ComponentPumpCompletion::CaptureRefused(
                        continuation.pending, pump, channel,
                    ),
            }
        }
    };
    let trace_nested_provider = matches!(continuation.pending,
        PendingComponentDispatch::Provider(pending) if pending.nested_user_callback)
        && NESTED_PROVIDER_OUTER_TRACES.fetch_add(1, Ordering::Relaxed) < 4096;
    if trace_nested_provider {
        let (next_wait, detail) = match &pump_completion {
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::Provider(next)) =>
                (next.request.header.wait_id, 1),
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::Receive(_)) => (0, 2),
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::ServiceWait(_)) => (0, 3),
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::Lpc(_)) => (0, 4),
            ComponentPumpCompletion::Reparked(_) => (0, 5),
            ComponentPumpCompletion::Completed(_) => (0, 6),
            ComponentPumpCompletion::FailedRetained(_, _) => (0, 7),
            ComponentPumpCompletion::Failed(_) => (0, 8),
            ComponentPumpCompletion::UserCallbackSuspended => (0, 9),
            ComponentPumpCompletion::CaptureRefused(_, _, _) => (0, 10),
        };
        trace_nested_provider_outer(b"pump-return", resume.key,
            frame.owner.dispatch_id, next_wait, detail);
    }
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
        trace_nested_provider,
    )
}

/// Resume only the exact Receive child boundary retained by the physical parent owner.
/// Keep its large retained frame and pending-dispatch copies off the outer service loop stack.
#[inline(never)]
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
                    || !win32k_glue::win32k_client_context_is_admitted(pending.snapshot.client)
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
        restored @ win32k_glue::ReceivePumpCompletion::Restored(_) => restored,
        refused @ win32k_glue::ReceivePumpCompletion::CaptureRefused(_, _, _) => refused,
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
                destination: continuation.destination,
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
        win32k_glue::ReceivePumpCompletion::ServiceReparked(next) => {
            let yielded = next.yielded;
            let next_owner = service_wait_expected_owner(next)
                .expect("restored Receive retains its service wait provider identity");
            let next_key = component_suspension_key(PendingComponentDispatch::ServiceWait(next));
            let next_continuation = ComponentNativeContinuation::Hosted(HostedNativeContinuation {
                pending: PendingComponentDispatch::ServiceWait(next),
                return_target: continuation.return_target,
                destination: continuation.destination,
            });
            (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .rearm_service_wait_external_owned(
                    lane, yielded.reply, yielded.dispatch, yielded.token,
                    frame.key, next_key, next_dispatcher_wait_sequence(), next_owner,
                    next_continuation,
                )
                .unwrap_or_else(|(error, _)| {
                    panic!("Receive to service wait transfer lost exact owner: {:?}", error)
                });
            return None;
        }
        win32k_glue::ReceivePumpCompletion::Deferred(boundary) => {
            // No callback input or capability has been captured into this reserved storage.
            // The exact Parent, child permit and Resuming frame remain retained by their owners.
            return Some(boundary);
        }
    };
    let pump_completion = match pump_completion {
        win32k_glue::ReceivePumpCompletion::CaptureRefused(_, pump, channel) => {
            ComponentPumpCompletion::CaptureRefused(continuation.pending, pump, channel)
        }
        win32k_glue::ReceivePumpCompletion::Restored(pump_completion) => match pump_completion {
        win32k_glue::ProviderWaitPumpCompletion::NestedSourceDeferred => {
            runtime::nested::trace_deferred_resume_owner(lane, frame.key, frame.owner);
            return None;
        }
        win32k_glue::ProviderWaitPumpCompletion::Completed(dispatch) => {
            ComponentPumpCompletion::Completed(dispatch)
        }
        win32k_glue::ProviderWaitPumpCompletion::Reparked(pending) => {
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::Provider(pending))
        }
        win32k_glue::ProviderWaitPumpCompletion::LpcReparked(pending) => {
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::Lpc(pending))
        }
        win32k_glue::ProviderWaitPumpCompletion::ReceiveReparked(pending) => {
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::Receive(pending))
        }
        win32k_glue::ProviderWaitPumpCompletion::ServiceReparked(pending) => {
            ComponentPumpCompletion::Reparked(PendingComponentDispatch::ServiceWait(pending))
        }
        win32k_glue::ProviderWaitPumpCompletion::UserCallbackSuspended => {
            ComponentPumpCompletion::UserCallbackSuspended
        }
        win32k_glue::ProviderWaitPumpCompletion::Failed(status) => {
            ComponentPumpCompletion::Failed(status)
        }
        win32k_glue::ProviderWaitPumpCompletion::CaptureRefused(_, pump, channel) => {
            ComponentPumpCompletion::CaptureRefused(continuation.pending, pump, channel)
        }
        win32k_glue::ProviderWaitPumpCompletion::RetainedFailure(pending, status) => {
            ComponentPumpCompletion::FailedRetained(
                PendingComponentDispatch::Provider(pending), status,
            )
        }
        },
        _ => unreachable!("receive repark and deferral return before classification"),
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
        false,
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
    trace_nested_provider: bool,
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
            trace_repark_failure(b"pump-failed", lane, resume.key, status as u32, None, None);
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
        ComponentPumpCompletion::FailedRetained(next, status) => {
            // Page restoration was refused before publishing a result or entering the
            // provider. Keep the exact suspended owner in the terminal quarantine.
            trace_repark_failure(b"pump-restore-refused", lane, resume.key,
                status as u32, Some(next), None);
            component_terminal::retain_incomplete_provider(
                lane,
                reply_object,
                resume.key,
                frame.owner,
                Some(next),
                status as u32,
            );
            return Some(ComponentSuspensionRuntimeOutcome::Terminal);
        }
        ComponentPumpCompletion::CaptureRefused(previous, pump, channel) => {
            let refusal = pump.provider_wait_capture_refusal
                .expect("capture refusal must retain its labelled Call observation");
            let status = match refusal.reason {
                spawn_hosts::ProviderWaitCaptureRefusalReason::BadBadge =>
                    nt_process::STATUS_INVALID_PARAMETER,
                spawn_hosts::ProviderWaitCaptureRefusalReason::MissingLanePage =>
                    nt_process::STATUS_INVALID_HANDLE,
            };
            component_terminal::retain_capture_refused(
                lane, reply_object, resume.key, frame.owner,
                previous, pump, channel, status,
            );
            return Some(ComponentSuspensionRuntimeOutcome::Terminal);
        }
        ComponentPumpCompletion::Reparked(next) => {
            if let PendingComponentDispatch::Receive(pending) = next {
                assert!(pending.yielded.replaces == Some(resume.key)
                    && pending.yielded.owner == frame.owner,
                    "service wait to Receive retains exact prior owner");
                let next_key = component_suspension_key(next);
                let sequence = next_dispatcher_wait_sequence();
                let mut next_continuation = continuation;
                next_continuation.pending = next;
                crate::spawn_hosts::shared_ingress::owner::runtime::with_bound_receive_scope(
                    pending.yielded.parent,
                    |scope| {
                        (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                            .rearm_receive_owned(
                                scope, resume.key, next_key, sequence, frame.owner,
                                pending.yielded.child,
                                ComponentNativeContinuation::Hosted(next_continuation),
                            )
                            .map(|_| ())
                            .map_err(|_| crate::spawn_hosts::shared_ingress::owner::runtime::Error::Admission)
                    },
                )
                .expect("service wait to Receive retains sealed child and continuation");
                return Some(ComponentSuspensionRuntimeOutcome::Parked);
            }
            if let PendingComponentDispatch::ServiceWait(pending) = next {
                let yielded = pending.yielded;
                let next_owner = service_wait_expected_owner(pending)
                    .expect("reparked service wait retains admitted provider identity");
                let next_key = component_suspension_key(next);
                let sequence = next_dispatcher_wait_sequence();
                let mut next_continuation = continuation;
                next_continuation.pending = next;
                (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                    .rearm_service_wait_external_owned(
                        lane, yielded.reply, yielded.dispatch, yielded.token,
                        resume.key, next_key, sequence, next_owner,
                        ComponentNativeContinuation::Hosted(next_continuation),
                    )
                    .unwrap_or_else(|(error, _)| {
                        panic!("service wait repark lost exact owner: {:?}", error)
                    });
                return Some(ComponentSuspensionRuntimeOutcome::Parked);
            }
            if matches!(next, PendingComponentDispatch::Provider(_)) {
                PROVIDER_WAIT_REARMS.fetch_add(1, Ordering::Relaxed);
            }
            let Some(next_owner) = component_expected_owner(next) else {
                trace_repark_failure(b"invalid-owner", lane, resume.key, 0xC000_000D, Some(next), None);
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
                        trace_repark_failure(b"lpc-capacity", lane, resume.key, 0xC000_009A, Some(next), None);
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
            if trace_nested_provider {
                trace_nested_provider_outer(b"rearm-begin", resume.key,
                    frame.owner.dispatch_id, next_key.id,
                    (frame.owner == next_owner) as u64);
            }
            let rearm_result = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                .rearm_running(
                    lane,
                    reply_object,
                    resume.key,
                    next_key,
                    sequence,
                    next_owner,
                    ComponentNativeContinuation::Hosted(next_continuation),
                );
            if trace_nested_provider {
                trace_nested_provider_outer(b"rearm-end", resume.key,
                    frame.owner.dispatch_id, next_key.id, rearm_result.is_ok() as u64);
            }
            if let Err(error) = rearm_result {
                trace_repark_failure(b"rearm", lane, resume.key, 0xC000_000D, Some(next), Some(error));
                if let Ok(Some(current)) = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                    .frame(lane, resume.key)
                {
                    print_str(b"[component-rearm-owner] old-key/new-key/same-owner/phase/old-dispatch/new-dispatch/old-pi/new-pi/old-tid/new-tid=");
                    print_u64(resume.key.id); print_str(b"/");
                    print_u64(next_key.id); print_str(b"/");
                    print_u64((current.owner == next_owner) as u64); print_str(b"/");
                    print_u64(match current.phase {
                        nt_component_suspension::SuspensionPhase::Resuming { .. } => 1,
                        nt_component_suspension::SuspensionPhase::ResumingChildParked { .. } => 2,
                        nt_component_suspension::SuspensionPhase::ResumingChildQuarantined { .. } => 3,
                        _ => 0,
                    }); print_str(b"/");
                    print_u64(current.owner.dispatch_id); print_str(b"/");
                    print_u64(next_owner.dispatch_id); print_str(b"/");
                    let old_client = current.owner.hosted_client();
                    let new_client = next_owner.hosted_client();
                    print_u64(old_client.map_or(0, |client| client.client_pi as u64)); print_str(b"/");
                    print_u64(new_client.map_or(0, |client| client.client_pi as u64)); print_str(b"/");
                    print_u64(old_client.map_or(0, |client| client.client_tid)); print_str(b"/");
                    print_u64(new_client.map_or(0, |client| client.client_tid)); print_str(b"\n");
                }
                if matches!(error, nt_component_suspension::LaneError::Suspension(
                    nt_component_suspension::SuspensionError::DuplicateIdentity,
                )) && REPARK_CONFLICT_TRACE.fetch_add(1, Ordering::Relaxed) < 8 {
                    if let PendingComponentDispatch::Provider(pending) = next {
                        let request_owner = pending.request.header.owner();
                        print_str(b"[component-rearm-request] wait/owner-valid/owner-matches-next/dispatch/pi/tid=");
                        print_u64(pending.request.header.wait_id); print_str(b"/");
                        print_u64(request_owner.is_some() as u64); print_str(b"/");
                        print_u64((request_owner == Some(next_owner)) as u64); print_str(b"/");
                        print_u64(request_owner.map_or(0, |owner| owner.dispatch_id)); print_str(b"/");
                        let client = request_owner.and_then(|owner| owner.hosted_client());
                        print_u64(client.map_or(0, |client| client.client_pi as u64)); print_str(b"/");
                        print_u64(client.map_or(0, |client| client.client_tid)); print_str(b"\n");
                    }
                    for (conflict_lane, conflict) in (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                        .frames().filter(|(_, frame)| frame.key == next_key)
                    {
                        print_str(b"[component-rearm-conflict] lane/generation/owner-matches-next/dispatch/pi/tid/phase=");
                        print_u64(u64::from(conflict_lane.index)); print_str(b"/");
                        print_u64(conflict_lane.generation); print_str(b"/");
                        print_u64((conflict.owner == next_owner) as u64); print_str(b"/");
                        print_u64(conflict.owner.dispatch_id); print_str(b"/");
                        let client = conflict.owner.hosted_client();
                        print_u64(client.map_or(0, |client| client.client_pi as u64)); print_str(b"/");
                        print_u64(client.map_or(0, |client| client.client_tid)); print_str(b"/");
                        print_u64(match conflict.phase {
                            nt_component_suspension::SuspensionPhase::Waiting => 1,
                            nt_component_suspension::SuspensionPhase::Selected { .. } => 2,
                            nt_component_suspension::SuspensionPhase::Resuming { .. } => 3,
                            _ => 0,
                        }); print_str(b"\n");
                    }
                }
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
                    if trace_nested_provider {
                        trace_nested_provider_outer(b"arbiter-begin", resume.key,
                            frame.owner.dispatch_id, next.request.header.wait_id, sequence);
                    }
                    let admission = (&mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_ARBITER)).admit(
                        &mut *nt_handler,
                        &next.request,
                        next_owner,
                        sequence,
                        nt_time_snapshot(),
                    );
                    if trace_nested_provider {
                        trace_nested_provider_outer(b"arbiter-end", resume.key,
                            frame.owner.dispatch_id, next.request.header.wait_id,
                            admission.is_ok() as u64);
                    }
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
                PendingComponentDispatch::Receive(_) | PendingComponentDispatch::ServiceWait(_)
                | PendingComponentDispatch::RootMaintenance(_)
                | PendingComponentDispatch::NestedRestore(_) => {
                    unreachable!("nested and service waits transfer before readiness admission")
                }
            }
        }
    }
    Some(ComponentSuspensionRuntimeOutcome::Rearmed)
}
