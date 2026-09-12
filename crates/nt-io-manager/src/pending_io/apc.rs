//! Retained APC interruption of a pending operation, without transferring its IRP owner.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFileApcEffect {
    CancelSelect,
    Stage,
    Send,
    RetireSentReply,
    RevokeReply,
    RetypeReply,
    ReleaseApcClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFileApcReceipt {
    CancelSelected,
    CancelNotSelected,
    Staged,
    Sent,
    SentReplyRetired,
    ReplyRevoked,
    ReplyRetyped,
    ApcClaimReleased,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFileApcOutcome {
    Completed(PendingFileApcReceipt),
    NotEntered(u32),
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFileApcDisposition {
    UserApc,
    Teardown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFileApcPhase {
    Ready {
        effect: PendingFileApcEffect,
        last_error: Option<u32>,
    },
    Invoking {
        effect: PendingFileApcEffect,
        attempt: u64,
    },
    Indeterminate {
        effect: PendingFileApcEffect,
        status: u32,
    },
    AwaitTerminal,
    Delivering {
        attempt: u64,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFileApcError {
    WrongIdentity,
    InvalidPhase,
    WrongReceipt,
    UnsettledSurfaces,
    InvalidTerminal,
    Exhausted,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Control {
    phase: PendingFileApcPhase,
    disposition: PendingFileApcDisposition,
    teardown_requested: bool,
    terminal_status: Option<u32>,
    selected: Option<bool>,
    claim_released: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct PendingFileApcView {
    pub pending: PendingFileIo,
    pub phase: PendingFileApcPhase,
    pub disposition: PendingFileApcDisposition,
    pub teardown_requested: bool,
    pub terminal_status: Option<u32>,
    pub selected: Option<bool>,
}

/// Single-use authority for one exact entered effect. Dropping retains the entered owner.
///
/// ```compile_fail
/// use nt_io_manager::PendingFileApcAttempt;
/// fn duplicate(attempt: PendingFileApcAttempt) { let _copy = attempt.clone(); }
/// ```
#[derive(Debug)]
pub struct PendingFileApcAttempt {
    identity: PendingFileIoIdentity,
    effect: PendingFileApcEffect,
    attempt: u64,
    view: PendingFileApcView,
    consumed: bool,
}

impl PendingFileApcAttempt {
    pub const fn identity(&self) -> PendingFileIoIdentity {
        self.identity
    }
    pub const fn effect(&self) -> PendingFileApcEffect {
        self.effect
    }
    pub const fn pending(&self) -> PendingFileIo {
        self.view.pending
    }
    pub const fn disposition(&self) -> PendingFileApcDisposition {
        self.view.disposition
    }
    pub const fn teardown_requested(&self) -> bool {
        self.view.teardown_requested
    }
    pub const fn terminal_status(&self) -> Option<u32> {
        self.view.terminal_status
    }
    pub const fn selected(&self) -> Option<bool> {
        self.view.selected
    }
}

/// An entered completion prefix, including provider terminal lookup. Ordinary rows use the same
/// lease to exclude an APC claim or a nested prefix midway through their terminal delivery.
///
/// ```compile_fail
/// use nt_io_manager::PendingFileApcDeliveryLease;
/// fn duplicate(lease: PendingFileApcDeliveryLease) { let _copy = lease.clone(); }
/// ```
#[derive(Debug)]
pub struct PendingFileApcDeliveryLease {
    identity: PendingFileIoIdentity,
    attempt: u64,
    consumed: bool,
}

impl PendingFileApcDeliveryLease {
    pub const fn identity(&self) -> PendingFileIoIdentity {
        self.identity
    }
}

impl PendingFileIoTable {
    pub(super) fn apc_owned_slot(&self, slot: usize) -> bool {
        self.apc_controls.get(slot).is_some_and(Option::is_some)
    }

    pub(super) fn apc_prefix_allows_mutation(&self, slot: usize) -> bool {
        self.apc_controls
            .get(slot)
            .and_then(Option::as_ref)
            .is_none_or(|control| matches!(control.phase, PendingFileApcPhase::Delivering { .. }))
    }

    fn apc_candidate(&self, slot: usize, pending: PendingFileIo) -> bool {
        !self.apc_owned_slot(slot)
            && self.delivery_attempts.get(slot).copied() == Some(0)
            && pending.reply_required
            && pending.reply_cap != 0
            && !pending.consumer_abandoned
            && pending.delivery_state == 0
            && match pending.operation {
                PendingFileIoOperation::Transfer => pending.busy.is_some_and(|busy| {
                    busy.owner().tid == pending.tid
                        && busy.owner().mode == nt_io_completion::FileIoMode::SynchronousAlertable
                        && busy.release_unstarted()
                }),
                PendingFileIoOperation::LocalByteLock(operation) => {
                    operation.alertable
                        && operation.status == nt_status::NtStatus::PENDING.raw() as u32
                }
                PendingFileIoOperation::LocalDirectoryNotify(operation) => {
                    operation.alertable
                        && operation.status == nt_status::NtStatus::PENDING.raw() as u32
                }
                _ => false,
            }
    }

    pub fn user_apc_interrupt_candidate(
        &self,
        tid: u64,
    ) -> Option<(PendingFileIoIdentity, PendingFileIo)> {
        self.drain_exact().find(|(identity, pending)| {
            pending.tid == tid && self.apc_candidate(identity.slot, *pending)
        })
    }

    /// The native adapter must reserve its provenance and claim the exact PM APC before entry.
    pub fn request_user_apc_interruption(
        &mut self,
        identity: PendingFileIoIdentity,
        expected_irp: u64,
    ) -> Result<(), PendingFileApcError> {
        let pending = self
            .get_exact(identity)
            .filter(|pending| pending.irp_id == expected_irp)
            .ok_or(PendingFileApcError::WrongIdentity)?;
        if !self.apc_candidate(identity.slot, pending) {
            return Err(PendingFileApcError::InvalidPhase);
        }
        self.apc_controls[identity.slot] = Some(Control {
            phase: Self::apc_ready(PendingFileApcEffect::CancelSelect),
            disposition: PendingFileApcDisposition::UserApc,
            teardown_requested: false,
            terminal_status: None,
            selected: None,
            claim_released: false,
        });
        Ok(())
    }

    pub fn apc(
        &self,
        identity: PendingFileIoIdentity,
    ) -> Result<PendingFileApcView, PendingFileApcError> {
        let pending = self
            .get_exact(identity)
            .ok_or(PendingFileApcError::WrongIdentity)?;
        let control = self.apc_controls[identity.slot].ok_or(PendingFileApcError::InvalidPhase)?;
        Ok(PendingFileApcView {
            pending,
            phase: control.phase,
            disposition: control.disposition,
            teardown_requested: control.teardown_requested,
            terminal_status: control.terminal_status,
            selected: control.selected,
        })
    }

    fn next_apc_attempt(&mut self) -> Result<u64, PendingFileApcError> {
        let attempt = self.next_apc_attempt;
        if attempt == 0 {
            return Err(PendingFileApcError::Exhausted);
        }
        self.next_apc_attempt = attempt.checked_add(1).unwrap_or(0);
        Ok(attempt)
    }

    fn apc_ready(effect: PendingFileApcEffect) -> PendingFileApcPhase {
        PendingFileApcPhase::Ready {
            effect,
            last_error: None,
        }
    }

    pub fn begin_apc_step(
        &mut self,
        identity: PendingFileIoIdentity,
    ) -> Result<PendingFileApcAttempt, PendingFileApcError> {
        let view = self.apc(identity)?;
        let PendingFileApcPhase::Ready { effect, .. } = view.phase else {
            return Err(PendingFileApcError::InvalidPhase);
        };
        let attempt = self.next_apc_attempt()?;
        self.apc_controls[identity.slot].as_mut().unwrap().phase =
            PendingFileApcPhase::Invoking { effect, attempt };
        Ok(PendingFileApcAttempt {
            identity,
            effect,
            attempt,
            view,
            consumed: false,
        })
    }

    pub fn record_apc_step(
        &mut self,
        ticket: &mut PendingFileApcAttempt,
        outcome: PendingFileApcOutcome,
    ) -> Result<PendingFileApcPhase, PendingFileApcError> {
        use PendingFileApcEffect as Effect;
        use PendingFileApcReceipt as Receipt;
        let view = self.apc(ticket.identity)?;
        if ticket.consumed
            || view.pending.irp_id != ticket.view.pending.irp_id
            || view.phase
                != (PendingFileApcPhase::Invoking {
                    effect: ticket.effect,
                    attempt: ticket.attempt,
                })
        {
            return Err(PendingFileApcError::InvalidPhase);
        }
        if let PendingFileApcOutcome::Completed(receipt) = outcome {
            if !matches!(
                (ticket.effect, receipt),
                (
                    Effect::CancelSelect,
                    Receipt::CancelSelected | Receipt::CancelNotSelected
                ) | (Effect::Stage, Receipt::Staged)
                    | (Effect::Send, Receipt::Sent)
                    | (Effect::RetireSentReply, Receipt::SentReplyRetired)
                    | (Effect::RevokeReply, Receipt::ReplyRevoked)
                    | (Effect::RetypeReply, Receipt::ReplyRetyped)
                    | (Effect::ReleaseApcClaim, Receipt::ApcClaimReleased)
            ) {
                return Err(PendingFileApcError::WrongReceipt);
            }
        }
        let control = self.apc_controls[ticket.identity.slot].as_mut().unwrap();
        let pending = self.slots[ticket.identity.slot].as_mut().unwrap();
        control.phase = match outcome {
            PendingFileApcOutcome::NotEntered(status) => PendingFileApcPhase::Ready {
                effect: ticket.effect,
                last_error: Some(status),
            },
            PendingFileApcOutcome::Indeterminate(status) => PendingFileApcPhase::Indeterminate {
                effect: ticket.effect,
                status,
            },
            PendingFileApcOutcome::Completed(receipt) => match receipt {
                Receipt::CancelSelected => {
                    control.selected = Some(true);
                    if control.teardown_requested {
                        Self::apc_ready(Effect::RevokeReply)
                    } else {
                        PendingFileApcPhase::AwaitTerminal
                    }
                }
                Receipt::CancelNotSelected => {
                    control.selected = Some(false);
                    Self::apc_ready(if control.teardown_requested {
                        Effect::RevokeReply
                    } else {
                        Effect::ReleaseApcClaim
                    })
                }
                Receipt::Staged => {
                    pending.delivery_state |= IO_DELIVERY_USER_APC_STAGED;
                    Self::apc_ready(if control.teardown_requested {
                        Effect::RevokeReply
                    } else {
                        Effect::Send
                    })
                }
                Receipt::Sent => {
                    pending.delivery_state |=
                        IO_DELIVERY_REPLY_CLAIMED | IO_DELIVERY_REPLY_PUBLISHED;
                    Self::apc_ready(Effect::RetireSentReply)
                }
                Receipt::ReplyRevoked => Self::apc_ready(Effect::RetypeReply),
                Receipt::SentReplyRetired | Receipt::ReplyRetyped => {
                    pending.reply_cap = 0;
                    if control.claim_released {
                        PendingFileApcPhase::Complete
                    } else {
                        Self::apc_ready(Effect::ReleaseApcClaim)
                    }
                }
                Receipt::ApcClaimReleased => {
                    control.claim_released = true;
                    if control.teardown_requested && pending.reply_cap != 0 {
                        Self::apc_ready(Effect::RevokeReply)
                    } else {
                        PendingFileApcPhase::Complete
                    }
                }
            },
        };
        ticket.consumed = true;
        if control.teardown_requested {
            self.apply_apc_teardown(ticket.identity.slot);
        }
        Ok(self.apc_controls[ticket.identity.slot].unwrap().phase)
    }

    pub fn begin_apc_delivery(
        &mut self,
        identity: PendingFileIoIdentity,
        expected_irp: u64,
    ) -> Result<PendingFileApcDeliveryLease, PendingFileApcError> {
        self.get_exact(identity)
            .filter(|pending| pending.irp_id == expected_irp)
            .ok_or(PendingFileApcError::WrongIdentity)?;
        if self.delivery_attempts[identity.slot] != 0
            || self.apc_controls[identity.slot]
                .is_some_and(|control| control.phase != PendingFileApcPhase::AwaitTerminal)
        {
            return Err(PendingFileApcError::InvalidPhase);
        }
        let attempt = self.next_apc_attempt()?;
        self.delivery_attempts[identity.slot] = attempt;
        if let Some(control) = self.apc_controls[identity.slot].as_mut() {
            control.phase = PendingFileApcPhase::Delivering { attempt };
        }
        Ok(PendingFileApcDeliveryLease {
            identity,
            attempt,
            consumed: false,
        })
    }

    /// Release only the entered prefix. Native must reacquire the exact owner before selecting
    /// Stage; teardown may have detached its consumer while this lease was active.
    pub fn finish_apc_delivery(
        &mut self,
        lease: &mut PendingFileApcDeliveryLease,
    ) -> Result<Option<PendingFileApcPhase>, PendingFileApcError> {
        self.get_exact(lease.identity)
            .ok_or(PendingFileApcError::WrongIdentity)?;
        if lease.consumed || self.delivery_attempts[lease.identity.slot] != lease.attempt {
            return Err(PendingFileApcError::InvalidPhase);
        }
        if self.apc_controls[lease.identity.slot].is_some_and(|control| {
            control.phase
                != (PendingFileApcPhase::Delivering {
                    attempt: lease.attempt,
                })
        }) {
            return Err(PendingFileApcError::InvalidPhase);
        }
        self.delivery_attempts[lease.identity.slot] = 0;
        lease.consumed = true;
        if let Some(control) = self.apc_controls[lease.identity.slot].as_mut() {
            control.phase = PendingFileApcPhase::AwaitTerminal;
            if control.teardown_requested {
                self.apply_apc_teardown(lease.identity.slot);
            }
        }
        Ok(self.apc_controls[lease.identity.slot].map(|control| control.phase))
    }

    /// Provider status must come from the exact canonical terminal completion, not cancellation
    /// intent. Local owners additionally validate against their retained filesystem result.
    pub fn ready_apc_terminal(
        &mut self,
        identity: PendingFileIoIdentity,
        expected_irp: u64,
        status: u32,
    ) -> Result<(), PendingFileApcError> {
        let view = self.apc(identity)?;
        if view.pending.irp_id != expected_irp {
            return Err(PendingFileApcError::WrongIdentity);
        }
        if view.phase != PendingFileApcPhase::AwaitTerminal || view.teardown_requested {
            return Err(PendingFileApcError::InvalidPhase);
        }
        if status == nt_status::NtStatus::PENDING.raw() as u32
            || view.pending.is_local()
                && view
                    .pending
                    .local_terminal_result()
                    .map(|(status, _)| status)
                    != Some(status)
        {
            return Err(PendingFileApcError::InvalidTerminal);
        }
        let required = Self::required_delivery_state(view.pending)
            & !(IO_DELIVERY_REPLY_CLAIMED
                | IO_DELIVERY_REPLY_PUBLISHED
                | IO_DELIVERY_BACKEND_ACKED);
        if !view.pending.busy_is_settled()
            || !Self::local_output_settled(view.pending)
            || view.pending.delivery_state & required != required
        {
            return Err(PendingFileApcError::UnsettledSurfaces);
        }
        let control = self.apc_controls[identity.slot].as_mut().unwrap();
        control.terminal_status = Some(status);
        control.phase = Self::apc_ready(PendingFileApcEffect::Stage);
        Ok(())
    }

    pub fn request_apc_teardown(
        &mut self,
        identity: PendingFileIoIdentity,
    ) -> Result<(), PendingFileApcError> {
        self.apc(identity)?;
        self.apc_controls[identity.slot]
            .as_mut()
            .unwrap()
            .teardown_requested = true;
        self.apply_apc_teardown(identity.slot);
        Ok(())
    }

    fn apply_apc_teardown(&mut self, slot: usize) {
        use PendingFileApcEffect as Effect;
        use PendingFileApcPhase as Phase;
        let control = self.apc_controls[slot].as_mut().unwrap();
        if matches!(
            control.phase,
            Phase::Delivering { .. }
                | Phase::Invoking {
                    effect: Effect::CancelSelect | Effect::Stage | Effect::Send,
                    ..
                }
                | Phase::Indeterminate {
                    effect: Effect::CancelSelect | Effect::Stage | Effect::Send,
                    ..
                }
        ) {
            return;
        }
        control.disposition = PendingFileApcDisposition::Teardown;
        let pending = self.slots[slot].as_mut().unwrap();
        Self::detach_transfer_surfaces(pending);
        // Detachment drops the consumer, not the capability. The controller retains the exact
        // unsent/sent Reply through its corresponding checked local retirement effect.
        if matches!(
            control.phase,
            Phase::AwaitTerminal
                | Phase::Ready {
                    effect: Effect::Stage | Effect::Send,
                    ..
                }
        ) || pending.reply_cap != 0
            && matches!(
                control.phase,
                Phase::Complete
                    | Phase::Ready {
                        effect: Effect::ReleaseApcClaim,
                        ..
                    }
            )
        {
            control.phase = Self::apc_ready(Effect::RevokeReply);
        }
    }

    /// Release protocol ownership only after native APC-claim cleanup and capability retirement.
    /// The original pending row remains responsible for backend ACK, Busy, and File references.
    pub fn finish_apc(
        &mut self,
        identity: PendingFileIoIdentity,
    ) -> Result<PendingFileApcView, PendingFileApcError> {
        let view = self.apc(identity)?;
        if view.phase != PendingFileApcPhase::Complete {
            return Err(PendingFileApcError::InvalidPhase);
        }
        self.apc_controls[identity.slot] = None;
        Ok(view)
    }

    pub fn has_apc_matching(&self, mut matches: impl FnMut(&PendingFileIo) -> bool) -> bool {
        self.drain_exact()
            .any(|(identity, pending)| self.apc_owned_slot(identity.slot) && matches(&pending))
    }
    pub fn has_apc_for_thread(&self, tid: u64) -> bool {
        self.has_apc_matching(|pending| pending.tid == tid)
    }
    pub fn has_apc_runtime_dependency_matching(
        &self,
        mut matches: impl FnMut(&PendingFileIo) -> bool,
    ) -> bool {
        self.drain_exact().any(|(identity, pending)| {
            self.apc_controls[identity.slot].is_some_and(|control| {
                control.disposition == PendingFileApcDisposition::UserApc
                    || matches!(
                        control.phase,
                        PendingFileApcPhase::Delivering { .. }
                            | PendingFileApcPhase::Invoking {
                                effect: PendingFileApcEffect::CancelSelect
                                    | PendingFileApcEffect::Stage
                                    | PendingFileApcEffect::Send,
                                ..
                            }
                            | PendingFileApcPhase::Indeterminate {
                                effect: PendingFileApcEffect::CancelSelect
                                    | PendingFileApcEffect::Stage
                                    | PendingFileApcEffect::Send,
                                ..
                            }
                    )
            }) && matches(&pending)
        })
    }
    pub fn next_apc_after(&self, cursor: Option<usize>) -> Option<PendingFileIoIdentity> {
        self.drain_exact().find_map(|(identity, _)| {
            (cursor.is_none_or(|cursor| identity.slot > cursor)
                && self.apc_controls[identity.slot].is_some_and(|control| {
                    matches!(
                        control.phase,
                        PendingFileApcPhase::Ready { .. } | PendingFileApcPhase::Complete
                    )
                }))
            .then_some(identity)
        })
    }
}

#[cfg(test)]
#[path = "apc_tests.rs"]
mod tests;
