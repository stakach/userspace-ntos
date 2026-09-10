//! Retained teardown and failed-publication rollback for counted File acquisition owners.

use super::*;
use nt_io_completion::FileReferenceRelease;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynchronousFileCancelEffect {
    Policy,
    Wake,
    HostedReference,
    ReferenceFollowup,
    RevokeReply,
    RetireReplyCap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynchronousFileCancelPhase {
    DeferredRetry,
    Ready {
        effect: SynchronousFileCancelEffect,
        last_error: Option<u32>,
    },
    Invoking {
        effect: SynchronousFileCancelEffect,
        attempt: u64,
    },
    Indeterminate {
        effect: SynchronousFileCancelEffect,
        status: u32,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynchronousFileCancelReceipt {
    HostedPolicy {
        waiters: u32,
    },
    /// nt-fs consumes the acquisition count/grant and its reference atomically.
    LocalPolicy {
        waiters: u32,
    },
    Wake,
    HostedReference(FileReferenceRelease),
    ReferenceFollowup,
    ReplyRevoked,
    ReplyCapRetired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynchronousFileCancelOutcome {
    Completed(SynchronousFileCancelReceipt),
    /// Definitive refusal before the effect committed any ownership change.
    NotEntered(u32),
    /// An uncertain or partially accepted effect cannot be replayed automatically.
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynchronousFileCancelError {
    WrongIdentity,
    InvalidPhase,
    WrongReceipt,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynchronousFileWaitIdentity {
    pub(super) table: u64,
    pub(super) slot: usize,
    pub(super) sequence: u64,
}

impl SynchronousFileWaitIdentity {
    pub const fn slot(self) -> usize {
        self.slot
    }
}

pub type SynchronousFileCancelIdentity = SynchronousFileWaitIdentity;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SynchronousFileCancelOwnership {
    pub waiting: usize,
    pub promoted: usize,
}

#[derive(Debug)]
pub(super) struct CancelState {
    pub(super) phase: SynchronousFileCancelPhase,
    policy_waiters: Option<u32>,
    reference_release: Option<FileReferenceRelease>,
}

impl CancelState {
    fn new(deferred: bool) -> Self {
        Self {
            phase: if deferred {
                SynchronousFileCancelPhase::DeferredRetry
            } else {
                SynchronousFileCancelPhase::Ready {
                    effect: SynchronousFileCancelEffect::Policy,
                    last_error: None,
                }
            },
            policy_waiters: None,
            reference_release: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SynchronousFileCancelView<'a> {
    pub waiter: &'a SynchronousFileWaiter,
    pub phase: SynchronousFileCancelPhase,
    pub policy_waiters: Option<u32>,
    pub reference_release: Option<FileReferenceRelease>,
}

/// Single-use authority over one effect. Dropping it retains Invoking without authorizing retry.
///
/// ```compile_fail
/// use nt_io_manager::SynchronousFileCancelAttempt;
/// fn duplicate(attempt: SynchronousFileCancelAttempt) { let _copy = attempt.clone(); }
/// ```
#[derive(Debug)]
pub struct SynchronousFileCancelAttempt {
    identity: SynchronousFileCancelIdentity,
    effect: SynchronousFileCancelEffect,
    attempt: u64,
    waiter: SynchronousFileWaiter,
    policy_waiters: Option<u32>,
    reference_release: Option<FileReferenceRelease>,
    consumed: bool,
}

impl SynchronousFileCancelAttempt {
    pub const fn effect(&self) -> SynchronousFileCancelEffect {
        self.effect
    }
    pub const fn waiter(&self) -> SynchronousFileWaiter {
        self.waiter
    }
    pub const fn policy_waiters(&self) -> Option<u32> {
        self.policy_waiters
    }
    pub const fn reference_release(&self) -> Option<FileReferenceRelease> {
        self.reference_release
    }
}

impl WaitRecord {
    fn cancellation_must_defer(&self) -> bool {
        matches!(
            self.ingress,
            Some(SynchronousFileIngressPhase::Adopting { .. })
        ) || matches!(
            self.retry,
            Some(
                SynchronousFileRetryPhase::Invoking { .. }
                    | SynchronousFileRetryPhase::Indeterminate { .. }
                    | SynchronousFileRetryPhase::Acknowledged { .. }
            )
        )
    }

    pub(super) fn activate_deferred_cancellation(&mut self) {
        if self.cancellation_must_defer() {
            return;
        }
        if let Some(cancel) = self.cancellation.as_mut() {
            if cancel.phase == SynchronousFileCancelPhase::DeferredRetry {
                cancel.phase = SynchronousFileCancelPhase::Ready {
                    effect: SynchronousFileCancelEffect::Policy,
                    last_error: None,
                };
            }
        }
    }
}

impl SynchronousFileWaitTable {
    /// Commit already-counted unpublished rollback into storage reserved before its effects.
    /// Unlike normal publication, rollback needs neither a retry frame nor a transferred reply.
    /// The caller still owns the canonical acquisition count and File reference at this boundary.
    pub fn cancel_reserved(
        &mut self,
        reservation: SynchronousFileWaitReservation,
        mut waiter: SynchronousFileWaiter,
    ) -> Option<SynchronousFileCancelIdentity> {
        if !self.reservation_matches(reservation)
            || !waiter.route.is_valid()
            || !waiter.mode.is_synchronous()
            || waiter.tid == 0
            || waiter.tid == u64::MAX
            || waiter.state != SynchronousFileWaitState::Waiting
            || waiter.reply_cap != 0
            || waiter.sequence != 0
        {
            return None;
        }
        waiter.sequence = reservation.sequence;
        self.slots[reservation.slot] = Some(WaitSlot::Owned(WaitRecord {
            waiter,
            queue_order: 0,
            retry: None,
            next_attempt: 1,
            cancellation: Some(CancelState::new(false)),
            ingress: None,
        }));
        Some(SynchronousFileCancelIdentity {
            table: self.identity,
            slot: reservation.slot,
            sequence: reservation.sequence,
        })
    }

    fn cancellation_record(
        &self,
        identity: SynchronousFileCancelIdentity,
    ) -> Result<&WaitRecord, SynchronousFileCancelError> {
        if identity.table == 0 || identity.table != self.identity {
            return Err(SynchronousFileCancelError::WrongIdentity);
        }
        self.record(identity.slot)
            .filter(|record| {
                record.waiter.sequence == identity.sequence && record.cancellation.is_some()
            })
            .ok_or(SynchronousFileCancelError::WrongIdentity)
    }

    pub fn cancellation_identity(
        &self,
        slot: usize,
        key: FileIoWaitKey,
        tid: u64,
    ) -> Option<SynchronousFileCancelIdentity> {
        let record = self.record(slot)?;
        (record.waiter.key() == key && record.waiter.tid == tid && record.cancellation.is_some())
            .then_some(SynchronousFileCancelIdentity {
                table: self.identity,
                slot,
                sequence: record.waiter.sequence,
            })
    }

    /// Capture identity before releasing a lookup borrow. A later cancellation request must use
    /// this generation, not repeat a slot/key/TID lookup that may now refer to a replacement.
    pub fn wait_identity(
        &self,
        slot: usize,
        key: FileIoWaitKey,
        tid: u64,
    ) -> Option<SynchronousFileWaitIdentity> {
        let record = self.record(slot)?;
        (record.waiter.key() == key && record.waiter.tid == tid).then_some(
            SynchronousFileWaitIdentity {
                table: self.identity,
                slot,
                sequence: record.waiter.sequence,
            },
        )
    }

    /// Retain teardown intent in the original row. Accepted/uncertain retry delivery keeps its
    /// obligations until its own receipt and cap retirement permit cancellation to take over.
    pub fn request_cancellation(
        &mut self,
        identity: SynchronousFileWaitIdentity,
    ) -> Result<SynchronousFileCancelIdentity, SynchronousFileCancelError> {
        if identity.table == 0 || identity.table != self.identity {
            return Err(SynchronousFileCancelError::WrongIdentity);
        }
        let record = self
            .record_mut(identity.slot)
            .filter(|record| record.waiter.sequence == identity.sequence)
            .ok_or(SynchronousFileCancelError::WrongIdentity)?;
        if record.cancellation.is_none() {
            record.cancellation = Some(CancelState::new(record.cancellation_must_defer()));
        }
        Ok(identity)
    }

    pub fn request_thread_cancellation(&mut self, tid: u64) -> usize {
        let mut marked = 0;
        for record in self
            .slots
            .iter_mut()
            .flatten()
            .filter_map(WaitSlot::record_mut)
        {
            if record.waiter.tid == tid && record.cancellation.is_none() {
                record.cancellation = Some(CancelState::new(record.cancellation_must_defer()));
                marked += 1;
            }
        }
        marked
    }

    pub fn has_cancellation_for_thread(&self, tid: u64) -> bool {
        self.records()
            .any(|(_, record)| record.waiter.tid == tid && record.cancellation.is_some())
    }

    pub fn has_cancellation_for_pi(&self, pi: u32) -> bool {
        self.records()
            .any(|(_, record)| record.waiter.pi == pi && record.cancellation.is_some())
    }

    pub fn cancellation(
        &self,
        identity: SynchronousFileCancelIdentity,
    ) -> Result<SynchronousFileCancelView<'_>, SynchronousFileCancelError> {
        let record = self.cancellation_record(identity)?;
        let cancel = record.cancellation.as_ref().unwrap();
        Ok(SynchronousFileCancelView {
            waiter: &record.waiter,
            phase: cancel.phase,
            policy_waiters: cancel.policy_waiters,
            reference_release: cancel.reference_release,
        })
    }

    /// Entered/deferred/uncertain work stays retained but is never offered for automatic replay.
    pub fn next_cancellation_after(
        &self,
        after: Option<usize>,
    ) -> Option<SynchronousFileCancelIdentity> {
        self.records().find_map(|(slot, record)| {
            if after.is_some_and(|after| slot <= after) {
                return None;
            }
            let cancel = record.cancellation.as_ref()?;
            matches!(
                cancel.phase,
                SynchronousFileCancelPhase::Ready { .. } | SynchronousFileCancelPhase::Complete
            )
            .then_some(SynchronousFileCancelIdentity {
                table: self.identity,
                slot,
                sequence: record.waiter.sequence,
            })
        })
    }

    /// Count canonical acquisition obligations hidden from normal FIFO/retry selection.
    pub fn cancellation_ownership(&self, key: FileIoWaitKey) -> SynchronousFileCancelOwnership {
        let mut ownership = SynchronousFileCancelOwnership::default();
        for (_, record) in self.records() {
            if record.waiter.key() != key
                || !record
                    .cancellation
                    .as_ref()
                    .is_some_and(|cancel| cancel.policy_waiters.is_none())
            {
                continue;
            }
            match record.waiter.state {
                SynchronousFileWaitState::Waiting => ownership.waiting += 1,
                SynchronousFileWaitState::Promoted => ownership.promoted += 1,
            }
        }
        ownership
    }

    pub fn begin_cancellation(
        &mut self,
        identity: SynchronousFileCancelIdentity,
    ) -> Result<SynchronousFileCancelAttempt, SynchronousFileCancelError> {
        let record = self.cancellation_record(identity)?;
        let cancel = record.cancellation.as_ref().unwrap();
        let SynchronousFileCancelPhase::Ready { effect, .. } = cancel.phase else {
            return Err(SynchronousFileCancelError::InvalidPhase);
        };
        let next = record
            .next_attempt
            .checked_add(1)
            .ok_or(SynchronousFileCancelError::Exhausted)?;
        let ticket = SynchronousFileCancelAttempt {
            identity,
            effect,
            attempt: record.next_attempt,
            waiter: record.waiter,
            policy_waiters: cancel.policy_waiters,
            reference_release: cancel.reference_release,
            consumed: false,
        };
        let record = self.record_mut(identity.slot).unwrap();
        record.cancellation.as_mut().unwrap().phase = SynchronousFileCancelPhase::Invoking {
            effect,
            attempt: record.next_attempt,
        };
        record.next_attempt = next;
        Ok(ticket)
    }

    pub fn record_cancellation(
        &mut self,
        ticket: &mut SynchronousFileCancelAttempt,
        outcome: SynchronousFileCancelOutcome,
    ) -> Result<SynchronousFileCancelPhase, SynchronousFileCancelError> {
        let record = self.cancellation_record(ticket.identity)?;
        let cancel = record.cancellation.as_ref().unwrap();
        if ticket.consumed
            || record.waiter != ticket.waiter
            || cancel.phase
                != (SynchronousFileCancelPhase::Invoking {
                    effect: ticket.effect,
                    attempt: ticket.attempt,
                })
        {
            return Err(SynchronousFileCancelError::InvalidPhase);
        }

        use SynchronousFileCancelEffect as Effect;
        use SynchronousFileCancelReceipt as Receipt;
        let reply_step = || (ticket.waiter.reply_cap != 0).then_some(Effect::RevokeReply);
        let next_effect = match outcome {
            SynchronousFileCancelOutcome::Completed(receipt) => match (ticket.effect, receipt) {
                (Effect::Policy, Receipt::HostedPolicy { .. })
                    if matches!(ticket.waiter.route, FileIoWaitRoute::Hosted { .. }) =>
                {
                    Some(Effect::Wake)
                }
                (Effect::Policy, Receipt::LocalPolicy { .. })
                    if matches!(ticket.waiter.route, FileIoWaitRoute::LocalOverlay { .. }) =>
                {
                    Some(Effect::Wake)
                }
                (Effect::Wake, Receipt::Wake) => match ticket.waiter.route {
                    FileIoWaitRoute::Hosted { .. } => Some(Effect::HostedReference),
                    FileIoWaitRoute::LocalOverlay { .. } => reply_step(),
                },
                (Effect::HostedReference, Receipt::HostedReference(release)) => {
                    if !matches!(ticket.waiter.route, FileIoWaitRoute::Hosted { device_id, .. } if device_id == release.device_id)
                    {
                        return Err(SynchronousFileCancelError::WrongReceipt);
                    }
                    if release.close_required
                        || release.cleanup_required
                        || release.port_id.is_some()
                    {
                        Some(Effect::ReferenceFollowup)
                    } else {
                        reply_step()
                    }
                }
                (Effect::ReferenceFollowup, Receipt::ReferenceFollowup) => reply_step(),
                (Effect::RevokeReply, Receipt::ReplyRevoked) => Some(Effect::RetireReplyCap),
                (Effect::RetireReplyCap, Receipt::ReplyCapRetired) => None,
                _ => return Err(SynchronousFileCancelError::WrongReceipt),
            },
            _ => None,
        };

        let record = self.record_mut(ticket.identity.slot).unwrap();
        let cancel = record.cancellation.as_mut().unwrap();
        cancel.phase = match outcome {
            SynchronousFileCancelOutcome::Completed(receipt) => {
                match receipt {
                    Receipt::HostedPolicy { waiters } | Receipt::LocalPolicy { waiters } => {
                        cancel.policy_waiters = Some(waiters)
                    }
                    Receipt::HostedReference(release) => cancel.reference_release = Some(release),
                    Receipt::ReplyCapRetired => record.waiter.reply_cap = 0,
                    _ => {}
                }
                match next_effect {
                    Some(effect) => SynchronousFileCancelPhase::Ready {
                        effect,
                        last_error: None,
                    },
                    None => SynchronousFileCancelPhase::Complete,
                }
            }
            SynchronousFileCancelOutcome::NotEntered(status) => SynchronousFileCancelPhase::Ready {
                effect: ticket.effect,
                last_error: Some(status),
            },
            SynchronousFileCancelOutcome::Indeterminate(status) => {
                SynchronousFileCancelPhase::Indeterminate {
                    effect: ticket.effect,
                    status,
                }
            }
        };
        ticket.consumed = true;
        Ok(cancel.phase)
    }

    pub fn finish_cancellation(
        &mut self,
        identity: SynchronousFileCancelIdentity,
    ) -> Option<SynchronousFileWaiter> {
        let record = self.cancellation_record(identity).ok()?;
        if record.cancellation.as_ref()?.phase != SynchronousFileCancelPhase::Complete {
            return None;
        }
        self.slots[identity.slot]
            .take()?
            .into_record()
            .map(|record| record.waiter)
    }
}

#[cfg(test)]
#[path = "cancellation/tests.rs"]
mod tests;
