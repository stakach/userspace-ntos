//! Retained provider results and callback handoffs through client delivery and reply retirement.

use super::*;
use nt_component_suspension::{LaneDispatchIdentity, TerminalIdentity, TerminalPhase, TerminalStage, TerminalStageOutcome};
use nt_component_suspension::peer_registry::PeerRoute;
use nt_user_host::hosted_return_target::HostedReply;

#[derive(Clone, Copy)]
enum NativeReturn {
    Hosted(win32k_glue::CompletedWin32kDispatch),
    Kernel { caller: nt_user_host::provider_kernel_activation::KernelProviderCaller, status: u32 },
    Incomplete,
}

pub(crate) struct NativeTerminal {
    returned: NativeReturn,
    status: u64,
    rejected_repark: Option<PendingComponentDispatch>,
    callback: Option<component_callback_transfer::CallbackTransfer>,
}

impl NativeTerminal {
    pub(super) const fn completed(dispatch: win32k_glue::CompletedWin32kDispatch) -> Self {
        Self {
            returned: NativeReturn::Hosted(dispatch),
            status: dispatch.status,
            rejected_repark: None,
            callback: None,
        }
    }

    const fn blocked(status: u32) -> Self {
        Self {
            returned: NativeReturn::Incomplete,
            status: status as u64,
            rejected_repark: None,
            callback: None,
        }
    }

    pub(super) const fn kernel_return(
        caller: nt_user_host::provider_kernel_activation::KernelProviderCaller,
        status: u32,
    ) -> Self {
        let mut payload = Self::blocked(status);
        payload.returned = NativeReturn::Kernel { caller, status };
        payload
    }

    pub(super) fn kernel_result(
        &self,
    ) -> Option<(nt_user_host::provider_kernel_activation::KernelProviderCaller, u32)> {
        match self.returned {
            NativeReturn::Kernel { caller, status }
                if self.status == status as u64
                    && self.rejected_repark.is_none()
                    && self.callback.is_none() => Some((caller, status)),
            _ => None,
        }
    }

    fn metadata(&self) -> Self {
        Self {
            returned: self.returned,
            status: self.status,
            rejected_repark: self.rejected_repark,
            callback: None,
        }
    }
}

pub(super) unsafe fn retain_callback_transfer(
    lane: nt_component_suspension::LaneHandle,
    reply_object: u64,
    key: nt_component_suspension::SuspensionKey,
    owner: nt_component_suspension::SuspensionOwner,
    callback: component_callback_transfer::CallbackTransfer,
    captured: Result<u64, u32>,
) {
    let mut payload = NativeTerminal::blocked(0);
    payload.callback = Some(callback);
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let (identity, failure) = match captured {
        Ok(token) => match lanes.retain_external_terminal_running(
            lane, reply_object, key, owner, token, payload,
        ) {
            Ok(identity) => (identity, None),
            Err((_error, payload)) => (
                lanes.retain_terminal_running(lane, reply_object, key, owner, payload)
                    .unwrap_or_else(|(error, _)| panic!("callback handoff rejection lost its source owner: {:?}", error)),
                Some(0xC000_000D),
            ),
        },
        Err(status) => (
            lanes.retain_terminal_running(lane, reply_object, key, owner, payload)
                .unwrap_or_else(|(error, _)| panic!("callback capture failure lost its source owner: {:?}", error)),
            Some(status),
        ),
    };
    if let Some(status) = failure {
        let mut attempt = lanes.begin_terminal_stage(identity, reply_object, TerminalStage::Output)
            .expect("callback failure lost its delivery stage");
        lanes.record_terminal_stage(&mut attempt, reply_object, TerminalStageOutcome::Indeterminate(status))
            .expect("callback failure lost its retained payload");
        report_retained_failure(lane, b"callback-capture", Some(TerminalStage::Output), None, true);
    }
}

pub(super) unsafe fn retain_incomplete_provider(
    lane: nt_component_suspension::LaneHandle,
    reply_object: u64,
    key: nt_component_suspension::SuspensionKey,
    owner: nt_component_suspension::SuspensionOwner,
    next: Option<PendingComponentDispatch>,
    status: u32,
) {
    // A rejected new wait is not a provider return. Keep both the previous native authority and
    // the newly parked physical continuation; neither the lane nor the client reply is reusable.
    let mut payload = NativeTerminal::blocked(status);
    payload.rejected_repark = next;
    let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
    let identity = lanes
        .retain_terminal_running(lane, reply_object, key, owner, payload)
        .unwrap_or_else(|(error, _)| panic!("rejected component re-wait lost its retained authority: {:?}", error));
    let mut attempt = lanes
        .begin_terminal_stage(identity, reply_object, TerminalStage::Output)
        .expect("rejected component re-wait lost its uncertainty owner");
    lanes
        .record_terminal_stage(
            &mut attempt,
            reply_object,
            TerminalStageOutcome::Indeterminate(status),
        )
        .expect("rejected component re-wait uncertainty publication failed");
    report_retained_failure(lane, b"repark-rejected", Some(TerminalStage::Output), None, false);
}

static DELIVERY_FAILURES: AtomicU64 = AtomicU64::new(0);
static RETIRED: AtomicU64 = AtomicU64::new(0);
static CALLBACK_HANDOFFS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum SharedReturn {
    Complete,
    ContinueAndRepark(u64),
    Repark(u64),
}

#[derive(Clone, Copy)]
struct PendingSharedReturn {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply: u64,
    action: SharedReturn,
    entered: bool,
}

// A successful semantic retirement transfers the exact physical dispatch to this row. A
// refused final Call leaves it ready; an entered but failed completion remains owned and is never
// replayed. Index alone is not authority: every attempt also carries its lane generation/epoch.
static mut PENDING_SHARED_RETURNS: [Option<PendingSharedReturn>; COMPONENT_EXECUTION_LANE_CAPACITY] =
    [None; COMPONENT_EXECUTION_LANE_CAPACITY];
// Local Reply retirement may succeed before a later shared semantic finish refuses. Retain the
// exact terminal identity so a retry cannot release the same Reply twice.
static mut SHARED_RETIRED_REPLIES: [Option<TerminalIdentity>; COMPONENT_EXECUTION_LANE_CAPACITY] =
    [None; COMPONENT_EXECUTION_LANE_CAPACITY];

pub(super) unsafe fn drain_shared_returns() -> u64 {
    let mut completed = 0;
    for index in 0..COMPONENT_EXECUTION_LANE_CAPACITY {
        let Some(mut pending) = (&*core::ptr::addr_of!(PENDING_SHARED_RETURNS))[index] else { continue };
        if pending.entered {
            continue;
        }
        let needs_call = !matches!(pending.action, SharedReturn::Repark(_));
        if needs_call {
            let ready = spawn_hosts::shared_ingress::owner::runtime::next_message(pending.route)
                .ok()
                .flatten()
                .is_some_and(|(_, message)| {
                    message.badge() == pending.route.badge()
                        && message.info() == win32k_subsystem::W32_DISPATCH_LABEL << 12
                });
            if !ready {
                continue;
            }
        }
        pending.entered = true;
        (&mut *core::ptr::addr_of_mut!(PENDING_SHARED_RETURNS))[index] = Some(pending);
        let result = match pending.action {
            SharedReturn::Complete => {
                spawn_hosts::shared_ingress::owner::runtime::complete(
                    pending.route, pending.dispatch, pending.reply,
                    win32k_subsystem::W32_DISPATCH_LABEL,
                ).is_ok()
            }
            SharedReturn::ContinueAndRepark(token) => {
                spawn_hosts::shared_ingress::owner::runtime::continue_after_subcall(
                    pending.route, pending.dispatch, pending.reply,
                    win32k_subsystem::W32_DISPATCH_LABEL,
                ).is_ok()
                    && crate::service_sec_image::repark_external_component_execution_lane(
                        pending.dispatch.lane(), token,
                    )
            }
            SharedReturn::Repark(token) => {
                crate::service_sec_image::repark_external_component_execution_lane(
                    pending.dispatch.lane(), token,
                )
            }
        };
        if result {
            (&mut *core::ptr::addr_of_mut!(PENDING_SHARED_RETURNS))[index] = None;
            completed += 1;
        } else {
            report_retained_failure(
                pending.dispatch.lane(), b"shared-return", None, None,
                matches!(pending.action, SharedReturn::Repark(_)),
            );
        }
    }
    completed
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Stats {
    pub ready: u64,
    pub invoking: u64,
    pub indeterminate: u64,
    pub acknowledged: u64,
    pub retired: u64,
    pub rejected_reparks: u64,
    pub callback_transfers: u64,
    pub callback_handoffs: u64,
}

pub(super) unsafe fn stats() -> Stats {
    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    let mut stats = Stats {
        retired: RETIRED.load(Ordering::Relaxed),
        callback_handoffs: CALLBACK_HANDOFFS.load(Ordering::Relaxed),
        ..Stats::default()
    };
    for identity in lanes.terminal_identities() {
        let reply = lanes
            .binding(identity.lane())
            .expect("terminal binding")
            .reply_object;
        let terminal = lanes.terminal(identity, reply).expect("terminal inventory");
        stats.rejected_reparks += terminal.payload.rejected_repark.is_some() as u64;
        stats.callback_transfers += (identity.external_token().is_some()
            || terminal.payload.callback.is_some()) as u64;
        match terminal.phase {
            TerminalPhase::Ready { .. } => stats.ready += 1,
            TerminalPhase::Invoking { .. } => stats.invoking += 1,
            TerminalPhase::Indeterminate { .. } => stats.indeterminate += 1,
            TerminalPhase::Acknowledged { .. } => stats.acknowledged += 1,
        }
    }
    stats
}

fn report_retained_failure(
    lane: nt_component_suspension::LaneHandle,
    reason: &[u8],
    stage: Option<TerminalStage>,
    phase: Option<TerminalPhase>,
    callback_owned: bool,
) {
    if DELIVERY_FAILURES.fetch_add(1, Ordering::Relaxed) < 8 {
        print_str(b"[component-terminal] delivery retained after failure lane=");
        print_u64(lane.index as u64);
        print_str(b" generation=");
        print_u64(lane.generation);
        print_str(b" reason=");
        print_str(reason);
        print_str(b" stage=");
        print_str(match stage {
            Some(TerminalStage::LocalDelivery) => b"local-delivery",
            Some(TerminalStage::Output) => b"output",
            Some(TerminalStage::Context) => b"context",
            Some(TerminalStage::Publication) => b"publication",
            Some(TerminalStage::Reply) => b"reply",
            None => b"none",
        });
        print_str(b" phase=");
        print_str(match phase {
            Some(TerminalPhase::Ready { .. }) => b"ready",
            Some(TerminalPhase::Invoking { .. }) => b"invoking",
            Some(TerminalPhase::Indeterminate { .. }) => b"indeterminate",
            Some(TerminalPhase::Acknowledged { .. }) => b"acknowledged",
            None => b"none",
        });
        print_str(b" callback-owned=");
        print_u64(u64::from(callback_owned));
        print_str(b"\n");
    }
}

unsafe fn process_output(
    nt_handler: &mut ExecNtHandler,
    continuation: HostedNativeContinuation,
    terminal: &mut NativeTerminal,
    procs: &mut [ProcExec],
    pfilled: &mut [[u64; 512]],
) -> Result<(), u32> {
    if continuation.return_target.is_abandoned()
        && !matches!(continuation.destination, HostedContinuationDestination::InitialThread(_)) {
        if let NativeReturn::Hosted(dispatch) = terminal.returned {
            if let Some(context) = dispatch.dispatch_context {
                let client = continuation.pending.client();
                if !win32k_bulk_mapping::complete_dispatch(
                    context, client.pi, client.generation,
                    dispatch.dispatch_return, dispatch.status,
                ) {
                    return Err(nt_process::STATUS_INVALID_HANDLE);
                }
            }
        }
        return Ok(());
    }
    assert!(continuation.return_target.can_resume(), "retiring target cannot deliver output");
    let NativeReturn::Hosted(mut dispatch) = terminal.returned else {
        return Ok(());
    };
    let client = continuation.pending.client();
    if let HostedContinuationDestination::InitialThread(origin) = continuation.destination {
        let binding = origin.target();
        let exact_client = binding.pi == client.pi as usize
            && binding.tid == client.tid
            && binding.badge == client.badge
            && u64::from(binding.process.pid) == client.pid
            && matches!(binding.process.generation,
                nt_user_host::process_identity::ProcessGeneration::Hosted(generation)
                    if generation == client.generation)
            && client.logical_caller.is_some_and(|caller| {
                caller.pi() == binding.pi
                    && caller.process() == binding.process
                    && u64::from(caller.thread().thread_id()) == binding.tid
                    && caller.badge() == binding.badge
                    && caller.tcb() == binding.tcb
            })
            && nt_handler.capture_process_identity(binding.pi) == Some(binding.process)
            && dispatch.ssn == 0;
        let status = if exact_client {
            crate::exec_handler::initial_thread_creation::finish_suspended_initial_creation(
                nt_handler, binding, dispatch.status as u32, true,
                continuation.return_target.is_abandoned(),
            )
        } else {
            nt_process::STATUS_INVALID_HANDLE
        };
        if status != 0 { return Err(status); }
        terminal.status = 0;
        return Ok(());
    }
    if dispatch.logical_caller != client.logical_caller {
        // Identity disagreement removes evidence only, not retained output/Reply ownership.
        dispatch.logical_caller = None;
    }
    let pi = client.pi as usize;
    let copied = match (procs.get(pi), pfilled.get_mut(pi)) {
        (Some(process), Some(filled)) if process.pml4 != 0 => {
            process_completed_user_callback_outer_dispatch(
                nt_handler,
                pi,
                process.pml4,
                client.badge,
                client.tid,
                dispatch,
                filled,
                process.faults as usize,
                process.scratch_base,
            )
        }
        _ => false,
    };
    if !copied {
        // Copyout can have partial effects. Retain its terminal error; never replay the output.
        terminal.status = 0xC000_0001;
    }
    Ok(())
}

unsafe fn retire_reply(continuation: HostedNativeContinuation) -> Result<(), u32> {
    if continuation.return_target.is_abandoned() {
        return Ok(());
    }
    let reply = continuation
        .return_target
        .delivery()
        .ok_or(0xC000_0008u32)?;
    // This local mutation and finish_terminal below perform no IPC or allocation. The reply
    // remains reserved until its mechanism ACK, and the terminal row is the sole retiring owner.
    parked_reply::retire_sent(reply.reply_cap())
}

pub(super) unsafe fn drain(
    nt_handler: &mut ExecNtHandler,
    procs: &mut [ProcExec],
    pfilled: &mut [[u64; 512]],
) -> u64 {
    let mut retired = drain_shared_returns();
    let mut cursor = None;
    while let Some(identity) =
        (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).next_terminal_if(|identity, terminal| {
            terminal.frame.continuation.hosted().is_some_and(|hosted| {
                hosted.return_target.can_resume()
            })
                && cursor.is_none_or(|cursor| {
                    (terminal.frame.admission_sequence, identity.lane().index) > cursor
                })
        })
    {
        let reply_object = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
            .binding(identity.lane())
            .expect("terminal lane binding disappeared")
            .reply_object;
        let (continuation, mut payload, phase, order, callback_owned) = {
            let terminal = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                .terminal(identity, reply_object)
                .expect("selected terminal owner disappeared");
            (
                terminal.frame.continuation,
                terminal.payload.metadata(),
                terminal.phase,
                (terminal.frame.admission_sequence, identity.lane().index),
                identity.external_token().is_some() || terminal.payload.callback.is_some(),
            )
        };
        let continuation = match continuation {
            ComponentNativeContinuation::Hosted(hosted) => hosted,
            ComponentNativeContinuation::Kernel(_) => {
                cursor = Some(order);
                continue;
            }
        };
        assert!(
            !matches!(payload.returned, NativeReturn::Kernel { .. }),
            "kernel return cannot be delivered to a hosted recipient"
        );
        match phase {
            TerminalPhase::Ready { stage, .. } => {
                assert_ne!(stage, TerminalStage::LocalDelivery, "hosted terminal cannot acknowledge local delivery");
                let mut attempt = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                    .begin_terminal_stage(identity, reply_object, stage)
                    .expect("terminal stage changed before entry");
                if identity.external_token().is_some() {
                    let mut callback = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                        .with_terminal_payload(&attempt, reply_object, |payload| payload.callback.take())
                        .expect("callback stage lost its owner")
                        .expect("callback stage lost its owned payload");
                    // Only local payload ownership crosses IPC; the coordinator's Invoking
                    // phase fences new execution and teardown without retaining a global borrow.
                    let result = if continuation.return_target.is_abandoned() {
                        // Logical cancellation is not proof that the parked callback completed.
                        // Retain it for acknowledged cancellation/quiescence, never fake a Reply.
                        Err(0xC000_0120)
                    } else {
                        let reply = continuation.return_target.delivery()
                            .expect("retiring target cannot transfer a callback");
                        match stage {
                            TerminalStage::LocalDelivery => unreachable!("hosted callback cannot use kernel-local delivery"),
                            TerminalStage::Output => callback.prepare(),
                            TerminalStage::Context => callback.install(),
                            TerminalStage::Publication => callback.publish(),
                            TerminalStage::Reply => {
                                if callback.phase() != component_callback_transfer::TransferPhase::Published {
                                    Err(0xC000_000D)
                                } else if callback.restart(reply.reply_cap()) {
                                    Ok(())
                                } else {
                                    Err(0xC000_0001)
                                }
                            }
                        }
                    };
                    (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                        .with_terminal_payload(&attempt, reply_object, |payload| {
                            assert!(payload.callback.is_none());
                            payload.callback = Some(callback);
                        })
                        .expect("callback stage could not retain its entered outcome");
                    let outcome = match result {
                        Ok(()) => TerminalStageOutcome::Acknowledged,
                        Err(status) => TerminalStageOutcome::Indeterminate(status),
                    };
                    (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                        .record_terminal_stage(&mut attempt, reply_object, outcome)
                        .expect("callback stage ACK lost its original suspension");
                    if result.is_err() {
                        report_retained_failure(
                            identity.lane(), b"callback-stage", Some(stage), Some(phase), true,
                        );
                        cursor = Some(order);
                    }
                    continue;
                }
                if stage == TerminalStage::Output {
                    let result = process_output(nt_handler, continuation, &mut payload, procs, pfilled);
                    if let Err(status) = result {
                        let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
                        lanes.with_terminal_payload(&attempt, reply_object, |retained| *retained = payload)
                            .expect("terminal output lost its retained payload");
                        lanes.record_terminal_stage(&mut attempt, reply_object,
                            TerminalStageOutcome::Indeterminate(status))
                            .expect("uncertain initial-thread completion lost its owner");
                        report_retained_failure(identity.lane(), b"initial-output",
                            Some(stage), Some(phase), callback_owned);
                        cursor = Some(order);
                    } else {
                        (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                            .record_terminal_stage_with_payload(&mut attempt, reply_object, payload)
                            .expect("terminal output ACK lost its owner");
                    }
                    continue;
                }
                let accepted = if continuation.return_target.is_abandoned() {
                    true
                } else {
                    let reply = continuation.return_target.delivery()
                        .expect("retiring target cannot deliver a terminal result");
                    match stage {
                        TerminalStage::LocalDelivery => unreachable!("hosted return cannot use kernel-local delivery"),
                        TerminalStage::Context => match reply {
                            HostedReply::Syscall { .. } => true,
                            HostedReply::Callback { context, .. } => {
                                win32k_glue::complete_staged_user_callback_context(
                                    context,
                                    payload.status,
                                )
                            }
                        },
                        TerminalStage::Reply => match reply {
                            HostedReply::Callback { reply_cap, context } => {
                                win32k_glue::restart_staged_user_callback_context(context, reply_cap)
                            }
                            HostedReply::Syscall { reply_cap } => {
                                reply_parked_syscall(reply_cap, payload.status)
                            }
                        },
                        TerminalStage::Publication => true,
                        TerminalStage::Output => unreachable!(),
                    }
                };
                // These legacy bool adapters do not distinguish pre-entry rejection from an
                // uncertain entered operation. Preserve uncertainty rather than retrying effects.
                let outcome = if accepted {
                    TerminalStageOutcome::Acknowledged
                } else {
                    TerminalStageOutcome::Indeterminate(0xC000_0001)
                };
                (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                    .record_terminal_stage(&mut attempt, reply_object, outcome)
                    .expect("terminal mechanism outcome lost its owner");
                if !accepted {
                    report_retained_failure(
                        identity.lane(), b"delivery-stage", Some(stage), Some(phase), callback_owned,
                    );
                    cursor = Some(order);
                }
            }
            TerminalPhase::Acknowledged { .. } => {
                let shared = {
                    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
                    lanes.peer_route(identity.lane()).ok().flatten().and_then(|route| {
                        let dispatch = lanes.active_dispatch_identity(identity.lane()).ok().flatten()?;
                        let action = if let Some(token) = identity.external_token() {
                            SharedReturn::Repark(token)
                        } else if !matches!(payload.returned, NativeReturn::Hosted(_)) {
                            return None;
                        } else if let Some(token) = lanes.external_top(identity.lane()).ok().flatten() {
                            SharedReturn::ContinueAndRepark(token)
                        } else if lanes.suspension_count(identity.lane()) == Ok(1) {
                            SharedReturn::Complete
                        } else {
                            return None;
                        };
                        Some((route, dispatch, action))
                    })
                };
                let is_shared = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                    .peer_route(identity.lane()).ok().flatten().is_some();
                if is_shared && shared.is_none() {
                    report_retained_failure(
                        identity.lane(), b"shared-action-missing", None, Some(phase), callback_owned,
                    );
                    cursor = Some(order);
                    continue;
                }
                if let Some((route, dispatch, _)) = shared {
                    let index = identity.lane().index as usize;
                    if index >= COMPONENT_EXECUTION_LANE_CAPACITY
                        || (&*core::ptr::addr_of!(PENDING_SHARED_RETURNS))[index].is_some()
                        || (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).execution_busy()
                    {
                        report_retained_failure(
                            identity.lane(), b"shared-retirement-busy", None, Some(phase), callback_owned,
                        );
                        cursor = Some(order);
                        continue;
                    }
                    debug_assert_eq!(route.identity().lane, dispatch.lane());
                }
                let local = if shared.is_some() {
                    let index = identity.lane().index as usize;
                    match (&*core::ptr::addr_of!(SHARED_RETIRED_REPLIES))[index] {
                        Some(saved) if saved == identity => Ok(()),
                        Some(_) => {
                            report_retained_failure(
                                identity.lane(), b"retired-reply-identity", None, Some(phase), callback_owned,
                            );
                            cursor = Some(order);
                            continue;
                        }
                        None => {
                            let result = retire_reply(continuation);
                            if result.is_ok() {
                                (&mut *core::ptr::addr_of_mut!(SHARED_RETIRED_REPLIES))[index] =
                                    Some(identity);
                            }
                            result
                        }
                    }
                } else {
                    retire_reply(continuation)
                };
                let completed = if let Some((route, dispatch, action)) = shared {
                    match (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                        .finish_shared_terminal(route, dispatch, identity, reply_object, local)
                    {
                        Ok(Some(retired)) => {
                            let index = identity.lane().index as usize;
                            (&mut *core::ptr::addr_of_mut!(PENDING_SHARED_RETURNS))[index] =
                                Some(PendingSharedReturn {
                                    route, dispatch, reply: reply_object, action, entered: false,
                                });
                            (&mut *core::ptr::addr_of_mut!(SHARED_RETIRED_REPLIES))[index] = None;
                            Some(retired)
                        }
                        Ok(None) | Err(_) => None,
                    }
                } else {
                    (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                        .finish_terminal(identity, reply_object, local)
                        .expect("acknowledged terminal retirement lost its owner")
                };
                if completed.is_none() {
                    report_retained_failure(
                        identity.lane(),
                        if local.is_err() { b"reply-retirement" } else { b"semantic-retirement-refused" },
                        None, Some(phase), callback_owned,
                    );
                    cursor = Some(order);
                    continue;
                }
                crate::driver_launch::win32k_device_properties::retire_completed_transfers();
                if matches!(continuation.pending, PendingComponentDispatch::Provider(_)) {
                    PROVIDER_WAIT_DISPATCH_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                }
                COMPONENT_WAIT_DISPATCH_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                if identity.external_token().is_some() {
                    CALLBACK_HANDOFFS.fetch_add(1, Ordering::Relaxed);
                }
                RETIRED.fetch_add(1, Ordering::Relaxed);
                retired += 1;
                if shared.is_some() {
                    retired += drain_shared_returns();
                }
                cursor = Some(order);
            }
            _ => unreachable!("in-flight or uncertain terminal selected for replay"),
        }
    }
    retired
}
