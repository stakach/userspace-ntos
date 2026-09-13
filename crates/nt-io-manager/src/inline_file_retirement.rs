//! Retained retirement of an inline synchronous File acquisition, without a synthetic IRP.
//!
//! Reserve before acquiring Busy and its reference. Activation and transfer to an actual pending
//! operation do not allocate. Otherwise each retirement effect requires its own exact receipt;
//! teardown cannot discard an entered effect or the reference-release followup it produced.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_io_completion::FileReferenceRelease;

use crate::{FileIoBusyOwner, FileIoWaitKey};

static LAST_TABLE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InlineFileRetirementIdentity {
    table: u64,
    slot: usize,
    generation: u64,
}

impl InlineFileRetirementIdentity {
    pub const fn slot(self) -> usize {
        self.slot
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InlineFileRetirementReservation(InlineFileRetirementIdentity);

impl InlineFileRetirementReservation {
    pub const fn identity(self) -> InlineFileRetirementIdentity {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InlineFileRetirementEffect {
    ReleasePolicy,
    Wake,
    ReleaseReference,
    ReferenceFollowup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InlineFileRetirementPhase {
    Reserved,
    Active,
    Ready {
        effect: InlineFileRetirementEffect,
        last_error: Option<u32>,
    },
    Invoking {
        effect: InlineFileRetirementEffect,
        attempt: u64,
    },
    Indeterminate {
        effect: InlineFileRetirementEffect,
        status: u32,
    },
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InlineFileRetirementOutcome {
    Completed(InlineFileRetirementEffect),
    PolicyReleased {
        waiters: u32,
    },
    ReferenceReleased(FileReferenceRelease),
    /// Definite refusal before the invoked effect changed any ownership state.
    NotEntered(u32),
    /// The effect may have committed; retaining it never authorizes automatic replay.
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InlineFileRetirementError {
    ReservationFailed,
    InvalidOwner,
    WrongIdentity,
    InvalidPhase,
    WrongReceipt,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InlineFileRetirementView {
    pub owner: FileIoBusyOwner,
    pub phase: InlineFileRetirementPhase,
    pub policy_waiters: Option<u32>,
    pub reference_release: Option<FileReferenceRelease>,
}

#[derive(Debug)]
struct Row {
    generation: u64,
    view: InlineFileRetirementView,
}

#[derive(Debug)]
pub struct InlineFileRetirementTable {
    rows: Vec<Option<Row>>,
    identity: u64,
    next_generation: u64,
    next_attempt: u64,
}

impl Default for InlineFileRetirementTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Enter before invoking the effect. Dropping this authority retains Invoking without replay.
///
/// ```compile_fail
/// use nt_io_manager::inline_file_retirement::InlineFileRetirementAttempt;
/// fn duplicate(attempt: InlineFileRetirementAttempt) { let _copy = attempt.clone(); }
/// ```
#[derive(Debug)]
pub struct InlineFileRetirementAttempt {
    identity: InlineFileRetirementIdentity,
    effect: InlineFileRetirementEffect,
    attempt: u64,
    view: InlineFileRetirementView,
    consumed: bool,
}

impl InlineFileRetirementAttempt {
    pub const fn identity(&self) -> InlineFileRetirementIdentity {
        self.identity
    }
    pub const fn effect(&self) -> InlineFileRetirementEffect {
        self.effect
    }
    pub const fn owner(&self) -> FileIoBusyOwner {
        self.view.owner
    }
    pub const fn policy_waiters(&self) -> Option<u32> {
        self.view.policy_waiters
    }
    pub const fn reference_release(&self) -> Option<FileReferenceRelease> {
        self.view.reference_release
    }
}

impl InlineFileRetirementTable {
    pub const fn new() -> Self {
        Self {
            rows: Vec::new(),
            identity: 0,
            next_generation: 1,
            next_attempt: 1,
        }
    }

    /// Allocate all ownership storage and mint its identity before any File acquisition effect.
    pub fn reserve(
        &mut self,
        owner: FileIoBusyOwner,
    ) -> Result<InlineFileRetirementReservation, InlineFileRetirementError> {
        if !matches!(owner.key, FileIoWaitKey::Hosted(file_id) if file_id != 0)
            || owner.tid == 0
            || owner.tid == u64::MAX
            || !owner.mode.is_synchronous()
        {
            return Err(InlineFileRetirementError::InvalidOwner);
        }
        let generation = self.next_generation;
        if generation == 0 {
            return Err(InlineFileRetirementError::Exhausted);
        }
        let slot = self
            .rows
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.rows.len());
        if slot == self.rows.len() {
            self.rows
                .try_reserve(1)
                .map_err(|_| InlineFileRetirementError::ReservationFailed)?;
        }
        let identity = if self.identity == 0 {
            LAST_TABLE
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                    last.checked_add(1)
                })
                .map_err(|_| InlineFileRetirementError::Exhausted)?
                + 1
        } else {
            self.identity
        };
        let row = Some(Row {
            generation,
            view: InlineFileRetirementView {
                owner,
                phase: InlineFileRetirementPhase::Reserved,
                policy_waiters: None,
                reference_release: None,
            },
        });
        if slot == self.rows.len() {
            self.rows.push(row);
        } else {
            self.rows[slot] = row;
        }
        self.identity = identity;
        self.next_generation = generation.checked_add(1).unwrap_or(0);
        Ok(InlineFileRetirementReservation(
            InlineFileRetirementIdentity {
                table: identity,
                slot,
                generation,
            },
        ))
    }

    pub fn get(
        &self,
        identity: InlineFileRetirementIdentity,
    ) -> Result<InlineFileRetirementView, InlineFileRetirementError> {
        let row = self
            .rows
            .get(identity.slot)
            .and_then(Option::as_ref)
            .filter(|row| {
                identity.table != 0
                    && identity.table == self.identity
                    && identity.generation == row.generation
            })
            .ok_or(InlineFileRetirementError::WrongIdentity)?;
        Ok(row.view)
    }

    fn view_mut(
        &mut self,
        identity: InlineFileRetirementIdentity,
    ) -> &mut InlineFileRetirementView {
        &mut self.rows[identity.slot].as_mut().unwrap().view
    }

    fn require_phase(
        &self,
        identity: InlineFileRetirementIdentity,
        phase: InlineFileRetirementPhase,
    ) -> Result<InlineFileRetirementView, InlineFileRetirementError> {
        let view = self.get(identity)?;
        if view.phase != phase {
            return Err(InlineFileRetirementError::InvalidPhase);
        }
        Ok(view)
    }

    pub fn cancel_reserved(
        &mut self,
        reservation: InlineFileRetirementReservation,
    ) -> Result<(), InlineFileRetirementError> {
        self.require_phase(reservation.0, InlineFileRetirementPhase::Reserved)?;
        self.rows[reservation.0.slot] = None;
        Ok(())
    }

    /// Publish the Busy/reference pair after successful atomic acquisition. This cannot allocate.
    pub fn activate(
        &mut self,
        reservation: InlineFileRetirementReservation,
    ) -> Result<InlineFileRetirementIdentity, InlineFileRetirementError> {
        self.require_phase(reservation.0, InlineFileRetirementPhase::Reserved)?;
        self.view_mut(reservation.0).phase = InlineFileRetirementPhase::Active;
        Ok(reservation.0)
    }

    pub fn active_owner(
        &self,
        identity: InlineFileRetirementIdentity,
    ) -> Result<FileIoBusyOwner, InlineFileRetirementError> {
        Ok(self
            .require_phase(identity, InlineFileRetirementPhase::Active)?
            .owner)
    }

    /// The caller must first publish this owner on its real pending operation. No retirement
    /// effect may have entered, and this removes only that exact active acquisition.
    pub fn transfer_active(
        &mut self,
        identity: InlineFileRetirementIdentity,
    ) -> Result<FileIoBusyOwner, InlineFileRetirementError> {
        let owner = self.active_owner(identity)?;
        self.rows[identity.slot] = None;
        Ok(owner)
    }

    pub fn retire_active(
        &mut self,
        identity: InlineFileRetirementIdentity,
    ) -> Result<(), InlineFileRetirementError> {
        self.active_owner(identity)?;
        self.view_mut(identity).phase = Self::ready(InlineFileRetirementEffect::ReleasePolicy);
        Ok(())
    }

    fn ready(effect: InlineFileRetirementEffect) -> InlineFileRetirementPhase {
        InlineFileRetirementPhase::Ready {
            effect,
            last_error: None,
        }
    }

    pub fn begin_step(
        &mut self,
        identity: InlineFileRetirementIdentity,
    ) -> Result<InlineFileRetirementAttempt, InlineFileRetirementError> {
        let view = self.get(identity)?;
        let InlineFileRetirementPhase::Ready { effect, .. } = view.phase else {
            return Err(InlineFileRetirementError::InvalidPhase);
        };
        let attempt = self.next_attempt;
        if attempt == 0 {
            return Err(InlineFileRetirementError::Exhausted);
        }
        self.next_attempt = attempt.checked_add(1).unwrap_or(0);
        self.view_mut(identity).phase = InlineFileRetirementPhase::Invoking { effect, attempt };
        Ok(InlineFileRetirementAttempt {
            identity,
            effect,
            attempt,
            view,
            consumed: false,
        })
    }

    pub fn record_step(
        &mut self,
        ticket: &mut InlineFileRetirementAttempt,
        outcome: InlineFileRetirementOutcome,
    ) -> Result<InlineFileRetirementPhase, InlineFileRetirementError> {
        let view = self.get(ticket.identity)?;
        if ticket.consumed
            || view.phase
                != (InlineFileRetirementPhase::Invoking {
                    effect: ticket.effect,
                    attempt: ticket.attempt,
                })
        {
            return Err(InlineFileRetirementError::InvalidPhase);
        }
        use InlineFileRetirementEffect as Effect;
        use InlineFileRetirementOutcome as Outcome;
        let phase = match (ticket.effect, outcome) {
            (_, Outcome::NotEntered(status)) => InlineFileRetirementPhase::Ready {
                effect: ticket.effect,
                last_error: Some(status),
            },
            (_, Outcome::Indeterminate(status)) => InlineFileRetirementPhase::Indeterminate {
                effect: ticket.effect,
                status,
            },
            (Effect::ReleasePolicy, Outcome::PolicyReleased { .. }) => Self::ready(Effect::Wake),
            (Effect::Wake, Outcome::Completed(Effect::Wake)) => {
                Self::ready(Effect::ReleaseReference)
            }
            (Effect::ReleaseReference, Outcome::ReferenceReleased(_)) => {
                Self::ready(Effect::ReferenceFollowup)
            }
            (Effect::ReferenceFollowup, Outcome::Completed(Effect::ReferenceFollowup)) => {
                InlineFileRetirementPhase::Complete
            }
            _ => return Err(InlineFileRetirementError::WrongReceipt),
        };
        let view = self.view_mut(ticket.identity);
        match outcome {
            Outcome::PolicyReleased { waiters } => view.policy_waiters = Some(waiters),
            Outcome::ReferenceReleased(release) => view.reference_release = Some(release),
            _ => {}
        }
        view.phase = phase;
        ticket.consumed = true;
        Ok(phase)
    }

    pub fn finish(&mut self, identity: InlineFileRetirementIdentity) -> Option<FileIoBusyOwner> {
        let owner = self
            .require_phase(identity, InlineFileRetirementPhase::Complete)
            .ok()?
            .owner;
        self.rows[identity.slot] = None;
        Some(owner)
    }

    /// A cursor pass visits each ready or completed row at most once, including on reentry.
    pub fn next_ready_after(&self, after: Option<usize>) -> Option<InlineFileRetirementIdentity> {
        self.rows.iter().enumerate().find_map(|(slot, row)| {
            let row = row.as_ref()?;
            (after.is_none_or(|after| slot > after)
                && matches!(
                    row.view.phase,
                    InlineFileRetirementPhase::Ready { .. } | InlineFileRetirementPhase::Complete
                ))
            .then_some(InlineFileRetirementIdentity {
                table: self.identity,
                slot,
                generation: row.generation,
            })
        })
    }

    pub fn slot_len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.iter().all(Option::is_none)
    }

    /// Neither live ownership nor identity/attempt exhaustion can be erased by reset.
    pub fn reset(&mut self) -> bool {
        if !self.is_empty() {
            return false;
        }
        self.rows.clear();
        true
    }
}

#[cfg(test)]
#[path = "inline_file_retirement_tests.rs"]
mod tests;
