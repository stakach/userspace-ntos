//! Retained provider results through client delivery and reply-cap retirement.

use super::*;
use nt_component_suspension::{TerminalPhase, TerminalStage, TerminalStageOutcome};

#[derive(Clone, Copy)]
pub(super) struct NativeTerminal {
    dispatch: Option<win32k_glue::CompletedWin32kDispatch>,
    status: u64,
    rejected_repark: Option<PendingComponentDispatch>,
}

impl NativeTerminal {
    pub(super) const fn completed(dispatch: win32k_glue::CompletedWin32kDispatch) -> Self {
        Self {
            dispatch: Some(dispatch),
            status: dispatch.status,
            rejected_repark: None,
        }
    }

    const fn blocked(status: u32) -> Self {
        Self {
            dispatch: None,
            status: status as u64,
            rejected_repark: None,
        }
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
        .expect("rejected component re-wait lost its retained authority");
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
    report_retained_failure(lane);
}

static DELIVERY_FAILURES: AtomicU64 = AtomicU64::new(0);
static RETIRED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Default)]
pub(crate) struct Stats {
    pub ready: u64,
    pub invoking: u64,
    pub indeterminate: u64,
    pub acknowledged: u64,
    pub retired: u64,
    pub rejected_reparks: u64,
}

pub(super) unsafe fn stats() -> Stats {
    let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    let mut stats = Stats {
        retired: RETIRED.load(Ordering::Relaxed),
        ..Stats::default()
    };
    for identity in lanes.terminal_identities() {
        let reply = lanes
            .binding(identity.lane())
            .expect("terminal binding")
            .reply_object;
        let terminal = lanes.terminal(identity, reply).expect("terminal inventory");
        stats.rejected_reparks += terminal.payload.rejected_repark.is_some() as u64;
        match terminal.phase {
            TerminalPhase::Ready { .. } => stats.ready += 1,
            TerminalPhase::Invoking { .. } => stats.invoking += 1,
            TerminalPhase::Indeterminate { .. } => stats.indeterminate += 1,
            TerminalPhase::Acknowledged { .. } => stats.acknowledged += 1,
        }
    }
    stats
}

fn report_retained_failure(lane: nt_component_suspension::LaneHandle) {
    if DELIVERY_FAILURES.fetch_add(1, Ordering::Relaxed) < 8 {
        print_str(b"[component-terminal] delivery retained after failure lane=");
        print_u64(lane.index as u64);
        print_str(b" generation=");
        print_u64(lane.generation);
        print_str(b"\n");
    }
}

unsafe fn process_output(
    nt_handler: &mut ExecNtHandler,
    continuation: ComponentNativeContinuation,
    terminal: &mut NativeTerminal,
    procs: &mut [ProcExec],
    pfilled: &mut [[u64; 512]],
) {
    if continuation.abandon_native_reply {
        assert_eq!(continuation.reply_cap, 0);
        return;
    }
    let Some(dispatch) = terminal.dispatch else {
        return;
    };
    let client = continuation.pending.client();
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
}

unsafe fn retire_reply(continuation: ComponentNativeContinuation) -> Result<(), u32> {
    if continuation.abandon_native_reply {
        assert_eq!(continuation.reply_cap, 0);
        return Ok(());
    }
    let record = wait_reply_pool_mut()
        .iter_mut()
        .find(|record| record.cap == continuation.reply_cap && record.used)
        .ok_or(0xC000_0008u32)?;
    // This local mutation and finish_terminal below perform no IPC or allocation. The reply
    // remains reserved until its mechanism ACK, and the terminal row is the sole retiring owner.
    record.used = false;
    Ok(())
}

pub(super) unsafe fn drain(
    nt_handler: &mut ExecNtHandler,
    procs: &mut [ProcExec],
    pfilled: &mut [[u64; 512]],
) -> u64 {
    let mut retired = 0;
    let mut cursor = None;
    while let Some(identity) =
        (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS)).next_terminal_if(|identity, terminal| {
            cursor.is_none_or(|cursor| {
                (terminal.frame.admission_sequence, identity.lane().index) > cursor
            })
        })
    {
        let reply_object = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
            .binding(identity.lane())
            .expect("terminal lane binding disappeared")
            .reply_object;
        let (continuation, mut payload, phase, order) = {
            let terminal = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
                .terminal(identity, reply_object)
                .expect("selected terminal owner disappeared");
            (
                terminal.frame.continuation,
                *terminal.payload,
                terminal.phase,
                (terminal.frame.admission_sequence, identity.lane().index),
            )
        };
        match phase {
            TerminalPhase::Ready { stage, .. } => {
                let mut attempt = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                    .begin_terminal_stage(identity, reply_object, stage)
                    .expect("terminal stage changed before entry");
                if stage == TerminalStage::Output {
                    process_output(nt_handler, continuation, &mut payload, procs, pfilled);
                    (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                        .record_terminal_stage_with_payload(&mut attempt, reply_object, payload)
                        .expect("terminal output ACK lost its owner");
                    continue;
                }
                let accepted = if continuation.abandon_native_reply {
                    assert_eq!(continuation.reply_cap, 0);
                    true
                } else {
                    match stage {
                        TerminalStage::Context => {
                            continuation.callback_context.is_none_or(|context| {
                                win32k_glue::complete_staged_user_callback_context(
                                    context,
                                    payload.status,
                                )
                            })
                        }
                        TerminalStage::Reply => {
                            if continuation.callback_context.is_some() {
                                client_reply_on(continuation.reply_cap, 0, 0, 0, 0, 0)
                            } else {
                                reply_parked_syscall(continuation.reply_cap, payload.status)
                            }
                        }
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
                    report_retained_failure(identity.lane());
                    cursor = Some(order);
                }
            }
            TerminalPhase::Acknowledged { .. } => {
                let local = retire_reply(continuation);
                let completed = (&mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS))
                    .finish_terminal(identity, reply_object, local)
                    .expect("acknowledged terminal retirement lost its owner");
                if completed.is_none() {
                    report_retained_failure(identity.lane());
                    cursor = Some(order);
                    continue;
                }
                crate::driver_launch::win32k_device_properties::retire_completed_transfers();
                if matches!(continuation.pending, PendingComponentDispatch::Provider(_)) {
                    PROVIDER_WAIT_DISPATCH_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                }
                COMPONENT_WAIT_DISPATCH_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
                RETIRED.fetch_add(1, Ordering::Relaxed);
                retired += 1;
                cursor = Some(order);
            }
            _ => unreachable!("in-flight or uncertain terminal selected for replay"),
        }
    }
    retired
}
