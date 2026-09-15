//! Memory-local kernel return delivery followed by exact terminal retirement.

use super::*;
use nt_component_suspension::{
    TerminalIdentity, TerminalPhase, TerminalStage, TerminalStageOutcome,
};

static DELIVERY_FAILURES: AtomicU64 = AtomicU64::new(0);

pub(super) unsafe fn has_ready() -> bool {
    (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
        .next_terminal_if(|_, view| {
            matches!(
                view.frame.continuation,
                ComponentNativeContinuation::Kernel(_)
            )
        })
        .is_some()
}

/// Called only inside the outer completion-delivery pass, never from nested pump IRQ hooks.
/// Failed local attempts advance the cursor without losing their retained result or Ps pair.
pub(super) unsafe fn drain() {
    let mut cursor = None;
    loop {
        let next = {
            let lanes = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
            lanes
                .next_terminal_if(|identity, view| {
                    matches!(
                        view.frame.continuation,
                        ComponentNativeContinuation::Kernel(_)
                    ) && cursor.is_none_or(|previous| {
                        (view.frame.admission_sequence, identity.lane().index) > previous
                    })
                })
                .map(|identity| {
                    let reply = lanes
                        .binding(identity.lane())
                        .expect("kernel terminal binding")
                        .reply_object;
                    let view = lanes
                        .terminal(identity, reply)
                        .expect("kernel terminal inventory");
                    let ComponentNativeContinuation::Kernel(capture) = view.frame.continuation
                    else {
                        unreachable!("hosted continuation selected for kernel-local delivery");
                    };
                    (
                        identity,
                        capture.caller(),
                        (view.frame.admission_sequence, identity.lane().index),
                    )
                })
        };
        let Some((identity, caller, order)) = next else {
            break;
        };
        cursor = Some(order);
        if let Err(status) = deliver_and_retire(caller, identity) {
            if DELIVERY_FAILURES.fetch_add(1, Ordering::Relaxed) < 16 {
                print_str(b"[kernel-terminal] retained provider=");
                print_u64(caller.owner().provider_domain);
                print_str(b" status=0x");
                print_hex(status);
                print_str(b"\n");
            }
        }
    }
}

unsafe fn deliver_and_retire(
    caller: KernelProviderCaller,
    identity: TerminalIdentity,
) -> Result<(), u32> {
    let reply = caller.binding().reply_object;
    let retired = with_provider_process_manager(|pm| {
        let activations = &mut *core::ptr::addr_of_mut!(ACTIVATIONS);
        let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
        activations.validate_terminal_completion(caller, pm, lanes, identity)?;
        let phase = lanes
            .terminal(identity, reply)
            .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?
            .phase;
        if let TerminalPhase::Ready {
            stage: TerminalStage::LocalDelivery,
            ..
        } = phase
        {
            let mut attempt = lanes
                .begin_terminal_stage(identity, reply, TerminalStage::LocalDelivery)
                .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
            let delivered = activations
                .with_terminal_recipient(
                    caller,
                    pm,
                    lanes,
                    identity,
                    &attempt,
                    |recipient, payload, status| {
                        if payload.kernel_result() != Some((caller, status)) {
                            return Err(nt_process::STATUS_INVALID_PARAMETER);
                        }
                        recipient.deliver_terminal_return(identity, status)
                    },
                )
                .and_then(|result| result);
            // The local operation validates everything before its one Option assignment.
            // No IPC, scheduling, allocation or partial copy can make this error uncertain.
            let outcome = match delivered {
                Ok(()) => TerminalStageOutcome::Acknowledged,
                Err(status) => TerminalStageOutcome::NoEffects(status),
            };
            lanes
                .record_terminal_stage(&mut attempt, reply, outcome)
                .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
            delivered?;
        }
        let terminal = lanes
            .terminal(identity, reply)
            .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
        if !matches!(terminal.phase, TerminalPhase::Acknowledged { .. }) {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let delivered = terminal
            .payload
            .kernel_result()
            .is_some_and(|(owner, status)| {
                owner == caller
                    && activations.recipient(caller).is_ok_and(|recipient| {
                        recipient.delivered_terminal_return(identity, status)
                    })
            });
        let local = if delivered {
            Ok(())
        } else {
            Err(nt_process::STATUS_INVALID_HANDLE)
        };
        activations.finish_terminal_completion(caller, pm, lanes, identity, local)
    })?;
    if retired.is_none() {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    // The original recipient and Ps references now belong to the Ready completion row.
    // Its existing outer delivery, not this local terminal, owns initialization and final ACK.
    crate::driver_launch::win32k_device_properties::retire_completed_transfers();
    Ok(())
}
