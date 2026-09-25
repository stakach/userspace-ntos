//! One-shot native SEH exchanges retained inside the owning hosted IRP pump.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_unwind::{
    exception_walk::{
        FirstRaiseStep, HandlerContexts, HandlerInvocation, SecondChanceReason, WalkOutcome,
        WalkStep,
    },
    raw_context::RawContext,
    seh_handler_packet::SehHandlerPacket,
    seh_transport::{SehCall, SehCommand, SehSecondChanceReason},
};

use super::PumpChannel;
use crate::driver_launch::{hosted_exception_stack as stack, hosted_seh_linkage};

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

enum Phase {
    Prepare(HandlerInvocation),
    Result {
        invocation: HandlerInvocation,
        expected: SehHandlerPacket,
        packet_va: u64,
    },
}

struct Active {
    token: u64,
    captured: RawContext,
    phase: Option<Phase>,
    packet_va: u64,
    restored_rsp: Option<u64>,
}

struct PendingCpuFault {
    token: u64,
    source: stack::FaultSourceIdentity,
    first: nt_unwind::seh_linkage_image::SehRaiseFirstPass,
    entry_rsp: u64,
}

impl Active {
    fn accept_step(
        &mut self,
        channel: &PumpChannel,
        reply: u64,
        badge: u64,
        step: FirstRaiseStep,
    ) -> Option<(SehCommand, bool)> {
        match step {
            FirstRaiseStep::Invoke(invocation) => {
                self.phase = Some(Phase::Prepare(invocation));
                Some((SehCommand::Prepare { token: self.token }, true))
            }
            FirstRaiseStep::Complete(WalkOutcome::Handled { context, .. })
            | FirstRaiseStep::Complete(WalkOutcome::TargetReached { context, .. }) => {
                let context_va = stack::publish_restore_context(
                    channel,
                    reply,
                    badge,
                    self.packet_va,
                    &self.captured,
                    context,
                )?
                .ok()?;
                self.restored_rsp = Some(context.rsp());
                Some((
                    SehCommand::Restore {
                        token: self.token,
                        context_va,
                    },
                    false,
                ))
            }
            FirstRaiseStep::Complete(WalkOutcome::Unhandled { exception, .. }) => Some((
                SehCommand::SecondChance {
                    token: self.token,
                    code: exception.code,
                    address: exception.address,
                    reason: SehSecondChanceReason::Unhandled,
                },
                false,
            )),
            FirstRaiseStep::Complete(WalkOutcome::SecondChance {
                exception, reason, ..
            }) => Some((
                SehCommand::SecondChance {
                    token: self.token,
                    code: exception.code,
                    address: exception.address,
                    reason: match reason {
                        SecondChanceReason::ExitUnwind => SehSecondChanceReason::ExitUnwind,
                        SecondChanceReason::TargetNotFound => SehSecondChanceReason::TargetNotFound,
                    },
                },
                false,
            )),
        }
    }
}

pub(super) struct SehPump {
    active: Vec<Active>,
    pending_cpu_fault: Option<PendingCpuFault>,
}

impl SehPump {
    pub(super) const fn new() -> Self {
        Self { active: Vec::new(), pending_cpu_fault: None }
    }

    pub(super) fn retained(&self) -> bool {
        !self.active.is_empty() || self.pending_cpu_fault.is_some()
    }

    /// Preserve fault ownership before any TCB mutation. The original fault Reply remains bound
    /// until the caller installs this continuation and acknowledges it exactly once.
    pub(super) fn begin_cpu_fault(
        &mut self,
        channel: &PumpChannel,
        reply: u64,
        badge: u64,
        label: u64,
        words: [u64; 5],
    ) -> bool {
        if self.pending_cpu_fault.is_some() || self.active.len() >= 64 {
            return false;
        }
        let Some(captured) = stack::capture_cpu_fault(channel, reply, badge, label, words) else {
            return false;
        };
        let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
        if token == 0 {
            return false;
        }
        let mut registers = captured.registers;
        registers[0] = captured.entry_va;
        registers[1] = captured.entry_rsp;
        registers[5] = token;
        let redirect = nt_thread_start::amd64_context::LegacyContextRestore {
            registers,
            register_mask: (1 << 0) | (1 << 1) | (1 << 5),
            floating_point: None,
            debug: None,
        };
        self.pending_cpu_fault = Some(PendingCpuFault {
            token,
            source: captured.source,
            first: captured.first,
            entry_rsp: captured.entry_rsp,
        });
        // A rejected syscall is not proof that no register was installed. Keep the pending fault
        // and let the pump wall/stop this exact physical dispatch; never issue the write again.
        unsafe { crate::thread_context::write(channel.tcb, &redirect, false).is_ok() }
    }

    fn retire_abandoned(&mut self, restored_rsp: Option<u64>) -> Option<()> {
        let Some(rsp) = restored_rsp else { return Some(()) };
        let packet_len = core::mem::size_of::<SehHandlerPacket>() as u64;
        for ancestor in &self.active {
            let end = ancestor.packet_va.checked_add(packet_len)?;
            if ancestor.packet_va == 0 || (ancestor.packet_va <= rsp && rsp <= end) {
                return None;
            }
        }
        self.active.retain(|ancestor| {
            ancestor.packet_va.checked_add(packet_len).is_some_and(|end| rsp < end)
        });
        Some(())
    }

    pub(super) fn call(
        &mut self,
        channel: &PumpChannel,
        reply: u64,
        badge: u64,
        call: SehCall,
    ) -> Option<SehCommand> {
        if let SehCall::FaultBegin { token, packet_va } = call {
            let pending = self.pending_cpu_fault.as_ref()?;
            if token != pending.token
                || stack::fault_source_identity(channel, reply, badge) != Some(pending.source)
                || packet_va.checked_add(core::mem::size_of::<SehHandlerPacket>() as u64)?
                    > pending.entry_rsp
            {
                return None;
            }
            self.active.try_reserve(1).ok()?;
            let linkage = hosted_seh_linkage(channel, reply)?;
            stack::initialize_restore_packet(
                channel, reply, badge, packet_va, token, linkage.resume_va,
            ).ok()?;
            // Move the pending fault into the retained active stack before a handler step may
            // perform any further native packet write. A failure then walls with its owner kept.
            let pending = self.pending_cpu_fault.take()?;
            self.active.push(Active {
                token,
                captured: pending.first.captured,
                phase: None,
                packet_va,
                restored_rsp: None,
            });
            let (command, keep) = self.active.last_mut()?.accept_step(
                channel, reply, badge, pending.first.step,
            )?;
            let active = self.active.pop()?;
            if self.retire_abandoned(active.restored_rsp).is_none() {
                self.active.push(active);
                return None;
            }
            if keep {
                self.active.push(active);
            }
            return Some(command);
        }
        if let SehCall::BeginUnwind {
            request_va,
            packet_va,
        } = call
        {
            let first = match stack::capture_unwind_first_step(
                channel, reply, badge, request_va, packet_va,
            )? {
                Ok(first) => first,
                Err(error) => {
                    let reason = match error {
                        stack::UnwindCaptureError::Packet => b"packet" as &[u8],
                        stack::UnwindCaptureError::Sidecar => b"sidecar",
                        stack::UnwindCaptureError::Caller => b"caller",
                        stack::UnwindCaptureError::Target => b"target",
                        stack::UnwindCaptureError::Record => b"record",
                        stack::UnwindCaptureError::Context(_) => b"context",
                        stack::UnwindCaptureError::Walk(error) => match error {
                            nt_unwind::exception_walk::WalkError::BadStack => {
                                b"walk-bad-stack" as &[u8]
                            }
                            nt_unwind::exception_walk::WalkError::UnwindData => b"walk-unwind-data",
                            nt_unwind::exception_walk::WalkError::StackRead => b"walk-stack-read",
                            nt_unwind::exception_walk::WalkError::BadFunctionTable => {
                                b"walk-function-table"
                            }
                            nt_unwind::exception_walk::WalkError::ImageLookup(_) => b"walk-image",
                            nt_unwind::exception_walk::WalkError::FrameLimit => b"walk-frame-limit",
                            _ => b"walk-other",
                        },
                    };
                    crate::print_str(b"[fsd-seh] unwind capture refused: ");
                    crate::print_str(reason);
                    crate::print_str(b"\n");
                    return None;
                }
            };
            let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
            if token == 0 || self.active.len() >= 64 {
                return None;
            }
            let linkage = hosted_seh_linkage(channel, reply)?;
            stack::initialize_restore_packet(
                channel,
                reply,
                badge,
                packet_va,
                token,
                linkage.resume_va,
            )
            .ok()?;
            let mut active = Active {
                token,
                captured: first.captured,
                phase: None,
                packet_va,
                restored_rsp: None,
            };
            let (command, keep) = active.accept_step(channel, reply, badge, first.step)?;
            self.retire_abandoned(active.restored_rsp)?;
            if keep {
                self.active.try_reserve(1).ok()?;
                self.active.push(active);
            }
            return Some(command);
        }
        if let SehCall::Raise { context_va, status } = call {
            let first = stack::capture_raise_first_step(
                channel,
                reply,
                badge,
                context_va,
                u64::from(status),
            )?
            .ok()?;
            let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
            if token == 0 || self.active.len() >= 64 {
                return None;
            }
            let mut active = Active {
                token,
                captured: first.captured,
                phase: None,
                packet_va: 0,
                restored_rsp: None,
            };
            let (command, keep) = active.accept_step(channel, reply, badge, first.step)?;
            self.retire_abandoned(active.restored_rsp)?;
            if keep {
                self.active.try_reserve(1).ok()?;
                self.active.push(active);
            }
            return Some(command);
        }

        let mut active = self.active.pop()?;
        let command = match call {
            SehCall::Prepare { token, packet_va } => {
                if token != active.token {
                    return None;
                }
                let Phase::Prepare(invocation) = active.phase.take()? else {
                    return None;
                };
                let linkage = hosted_seh_linkage(channel, reply)?;
                let mut packet = match invocation.contexts {
                    HandlerContexts::Search { .. } => {
                        SehHandlerPacket::prepare_search(&active.captured, &invocation, packet_va)
                    }
                    HandlerContexts::Unwind { .. } => SehHandlerPacket::prepare_unwind(
                        &active.captured,
                        &invocation,
                        invocation.dispatcher_unwound(),
                        packet_va,
                    ),
                }
                .ok()?;
                packet
                    .set_wrappers(
                        linkage.filter_va,
                        linkage.finally_va,
                        linkage.search_va,
                        linkage.unwind_va,
                        linkage.resume_va,
                    )
                    .ok()?;
                packet.set_token(active.token).ok()?;
                stack::write_handler_packet(channel, reply, badge, packet_va, &packet).ok()?;
                active.packet_va = packet_va;
                active.phase = Some(Phase::Result {
                    invocation,
                    expected: packet,
                    packet_va,
                });
                (SehCommand::Invoke { token }, true)
            }
            SehCall::HandlerResult {
                token,
                packet_va,
                disposition,
            } => {
                if token != active.token {
                    return None;
                }
                let Phase::Result {
                    mut invocation,
                    expected,
                    packet_va: expected_va,
                } = active.phase.take()?
                else {
                    return None;
                };
                if packet_va != expected_va {
                    return None;
                }
                stack::apply_handler_return(
                    channel,
                    reply,
                    badge,
                    packet_va,
                    &expected,
                    &mut invocation,
                    disposition,
                )?
                .ok()?;
                let step = match invocation.returned(disposition).ok()? {
                    WalkStep::Continue(walk) => {
                        stack::advance_raise_walk(channel, reply, badge, walk)?.ok()?
                    }
                    WalkStep::Invoke(next) => FirstRaiseStep::Invoke(next),
                    WalkStep::Complete(outcome) => FirstRaiseStep::Complete(outcome),
                };
                active.accept_step(channel, reply, badge, step)?
            }
            SehCall::UnwindRequest {
                token,
                target_frame,
                target_ip,
                packet_va,
            } => {
                if token != active.token {
                    return None;
                }
                let Phase::Result {
                    mut invocation,
                    expected,
                    packet_va: expected_va,
                } = active.phase.take()?
                else {
                    return None;
                };
                if packet_va != expected_va || target_frame != invocation.establisher_frame {
                    return None;
                }
                stack::apply_handler_return(
                    channel,
                    reply,
                    badge,
                    packet_va,
                    &expected,
                    &mut invocation,
                    1,
                )?
                .ok()?;
                let HandlerContexts::Search {
                    exception: context, ..
                } = invocation.contexts
                else {
                    return None;
                };
                let step = stack::start_target_unwind(
                    channel,
                    reply,
                    badge,
                    invocation.exception,
                    context,
                    target_frame,
                    target_ip,
                )?
                .ok()?;
                active.packet_va = packet_va;
                active.accept_step(channel, reply, badge, step)?
            }
            SehCall::Raise { .. } | SehCall::BeginUnwind { .. } | SehCall::FaultBegin { .. } => unreachable!(),
        };
        self.retire_abandoned(active.restored_rsp)?;
        if command.1 {
            self.active.push(active);
        }
        Some(command.0)
    }
}
