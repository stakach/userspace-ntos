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
}

impl SehPump {
    pub(super) const fn new() -> Self {
        Self { active: Vec::new() }
    }

    pub(super) fn retained(&self) -> bool {
        !self.active.is_empty()
    }

    pub(super) fn call(
        &mut self,
        channel: &PumpChannel,
        reply: u64,
        badge: u64,
        call: SehCall,
    ) -> Option<SehCommand> {
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
            };
            let (command, keep) = active.accept_step(channel, reply, badge, first.step)?;
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
            };
            let (command, keep) = active.accept_step(channel, reply, badge, first.step)?;
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
            SehCall::Raise { .. } | SehCall::BeginUnwind { .. } => unreachable!(),
        };
        if command.1 {
            self.active.push(active);
        }
        Some(command.0)
    }
}
