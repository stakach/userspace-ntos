//! Re-admission of unrelated root work after a refused hosted root handoff.
//!
//! A refusal publishes one exclusion. Only the owner that still holds the refused Call (its
//! `ExternalIngress`, and through it the original Reply) can turn the move-only refusal into a
//! readmission receipt, and only after it observes that the exact Call is sealed against any
//! delivery while its Reply has no record in the root Reply pool. The gate re-admits unrelated
//! work only for that exact receipt. The refused Call is never replayed and its numeric Reply is
//! never reused under another dispatch; its later settlement belongs to its owner alone.

use crate::thread_binding::ThreadBinding;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_component_suspension::{ExternalAdmissionKey, ExternalIngress};

/// Refusal epochs are globally issued, so a receipt from another gate or an earlier refusal of
/// the same Call cannot satisfy the current exclusion. Zero is never issued.
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);

/// The exact refused Call: its authenticated caller (including process generation, the caller's
/// execution epoch) and the receiver-issued admission key that names its physical Reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffKey<R> {
    binding: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
}

impl<R: Copy + Eq> HandoffKey<R> {
    pub fn new(binding: ThreadBinding<R>, admission: ExternalAdmissionKey) -> Option<Self> {
        (binding.process.is_valid() && binding.tid != 0 && binding.tcb > 1
            && admission.executor() == binding.tcb && admission.reply() != 0
            && admission.admission_sequence() != 0)
            .then_some(Self { binding, admission })
    }

    pub const fn binding(self) -> ThreadBinding<R> { self.binding }
    pub const fn admission(self) -> ExternalAdmissionKey { self.admission }
}

/// Why the selected Call could not be handed to the root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffRefusal {
    /// The caller's live hosted binding no longer matches the row; the importer was not entered.
    RetiredBinding,
    /// The physical Reply is not bound to the exact caller; the importer was not entered.
    ReplyUnbound,
    /// The root Reply-pool importer certified that it changed nothing.
    ImportNoEffect,
    /// The importer could not prove its pool effect; only reconciliation can establish one.
    ImportUncertain,
}

/// The holding owner's own row facts, observed in the same serialized step as the seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeldRowState {
    pub delivered: bool,
    /// A completion, release, or returned pool owner is recorded for the row.
    pub settled: bool,
    /// The row is a Receive child or RootIngress pass with a held parent.
    pub dependent: bool,
    /// The row already carries a quarantine seal.
    pub sealed: bool,
}

/// Fresh root Reply-pool facts for the refused Reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootPoolObservation {
    /// The importer was not entered for this Call.
    NotEntered { reply_recorded: bool },
    /// The importer was entered; the root selector and its pool record are compared exactly
    /// against the observation taken immediately before entry.
    Entered { reply_recorded: bool, selector_unchanged: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffResolution {
    /// A no-effect refusal: the Call is sealed in its owner and its Reply is outside the pool.
    Quarantined,
    /// An uncertain import was reconciled to no pool effect, then sealed as above.
    Reconciled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadmissionError {
    /// Another refusal is already excluded; it keeps its original identity.
    Excluding,
    NotExcluding,
    /// The refusal epoch was exhausted; the gate excludes with an unmatchable epoch.
    EpochExhausted,
    /// The receipt or token belongs to an earlier or foreign refusal.
    StaleRefusal,
    /// The observed caller's process generation differs from the refused execution.
    StaleExecution,
    KeyMismatch,
    Delivered,
    Settled,
    /// The Call entered a Reply, Stop, or Restart effect.
    CallEntered,
    Dependent,
    AlreadySealed,
    ObservationMismatch,
    ReplyInRootPool,
    SelectorChanged,
}

/// Move-only exclusion token issued by the gate for exactly one refused Call.
#[must_use = "only the owner holding the refused Call can turn this into a readmission"]
#[derive(Debug)]
pub struct RefusedHandoff<R> {
    epoch: u64,
    key: HandoffKey<R>,
    refusal: HandoffRefusal,
}

/// Row seal kept by the owner of the quarantined Call. It authorizes nothing by itself.
#[derive(Debug)]
pub struct HandoffQuarantine<R> {
    epoch: u64,
    key: HandoffKey<R>,
    refusal: HandoffRefusal,
}

/// The status NT returns for a system service whose resources could not be obtained.
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Proof that the refused Call is quarantined or reconciled; consumed by the gate.
#[must_use = "return the receipt to the admission gate"]
#[derive(Debug)]
pub struct HandoffReadmission<R> {
    epoch: u64,
    key: HandoffKey<R>,
    refusal: HandoffRefusal,
    resolution: HandoffResolution,
}

#[derive(Clone, Copy, Debug)]
struct Exclusion<R> {
    epoch: u64,
    key: HandoffKey<R>,
    refusal: HandoffRefusal,
}

/// Root admission gate. While excluding, the root admits no unrelated work.
pub struct HandoffAdmissionGate<R> {
    excluded: Option<Exclusion<R>>,
}

impl<R: Copy + Eq> Default for HandoffAdmissionGate<R> {
    fn default() -> Self { Self::new() }
}

impl<R: Copy + Eq> HandoffAdmissionGate<R> {
    pub const fn new() -> Self { Self { excluded: None } }

    pub fn admits_unrelated_work(&self) -> bool { self.excluded.is_none() }

    pub fn excluded(&self) -> Option<(HandoffKey<R>, HandoffRefusal)> {
        self.excluded.map(|exclusion| (exclusion.key, exclusion.refusal))
    }

    /// Exclude unrelated work for this exact refusal. Every call leaves the gate excluding:
    /// an existing exclusion keeps its original Call, and an exhausted epoch excludes with an
    /// unmatchable epoch rather than failing open.
    pub fn refuse(
        &mut self, key: HandoffKey<R>, refusal: HandoffRefusal,
    ) -> Result<RefusedHandoff<R>, ReadmissionError> {
        if self.excluded.is_some() {
            return Err(ReadmissionError::Excluding);
        }
        let Ok(epoch) = NEXT_EPOCH.try_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
            epoch.checked_add(1)
        }) else {
            self.excluded = Some(Exclusion { epoch: 0, key, refusal });
            return Err(ReadmissionError::EpochExhausted);
        };
        self.excluded = Some(Exclusion { epoch, key, refusal });
        Ok(RefusedHandoff { epoch, key, refusal })
    }

    /// Re-admit only for the receipt of the current exclusion. A refusal returns the receipt.
    pub fn readmit(
        &mut self, receipt: HandoffReadmission<R>,
    ) -> Result<HandoffResolution, (ReadmissionError, HandoffReadmission<R>)> {
        let Some(exclusion) = self.excluded else {
            return Err((ReadmissionError::NotExcluding, receipt));
        };
        if exclusion.epoch == 0 || receipt.epoch != exclusion.epoch {
            return Err((ReadmissionError::StaleRefusal, receipt));
        }
        if receipt.key != exclusion.key || receipt.refusal != exclusion.refusal {
            return Err((ReadmissionError::KeyMismatch, receipt));
        }
        self.excluded = None;
        Ok(receipt.resolution)
    }
}

impl<R: Copy + Eq> RefusedHandoff<R> {
    pub const fn key(&self) -> HandoffKey<R> { self.key }

    /// Called by the owner holding `call` in the same serialized step that stores the returned
    /// seal in its row. Any refusal returns this token; the gate keeps excluding meanwhile.
    pub fn seal<M>(
        self, binding: ThreadBinding<R>, call: &ExternalIngress<M>,
        row: HeldRowState, pool: RootPoolObservation,
    ) -> Result<(HandoffQuarantine<R>, HandoffReadmission<R>), (ReadmissionError, Self)> {
        match self.check(binding, call, row, pool) {
            Ok(resolution) => Ok((
                HandoffQuarantine { epoch: self.epoch, key: self.key, refusal: self.refusal },
                HandoffReadmission {
                    epoch: self.epoch, key: self.key, refusal: self.refusal, resolution,
                },
            )),
            Err(error) => Err((error, self)),
        }
    }

    fn check<M>(
        &self, binding: ThreadBinding<R>, call: &ExternalIngress<M>,
        row: HeldRowState, pool: RootPoolObservation,
    ) -> Result<HandoffResolution, ReadmissionError> {
        let key = self.key;
        if binding.process != key.binding.process {
            return Err(ReadmissionError::StaleExecution);
        }
        if binding != key.binding || call.admission_key() != key.admission
            || call.executor() != key.binding.tcb
        {
            return Err(ReadmissionError::KeyMismatch);
        }
        if row.sealed { return Err(ReadmissionError::AlreadySealed); }
        if row.delivered { return Err(ReadmissionError::Delivered); }
        if row.settled || call.is_acknowledged() { return Err(ReadmissionError::Settled); }
        if !call.can_park() { return Err(ReadmissionError::CallEntered); }
        if row.dependent { return Err(ReadmissionError::Dependent); }
        let (reply_recorded, selector_unchanged) = match (self.refusal, pool) {
            (HandoffRefusal::RetiredBinding | HandoffRefusal::ReplyUnbound,
                RootPoolObservation::NotEntered { reply_recorded }) => (reply_recorded, true),
            (HandoffRefusal::ImportNoEffect | HandoffRefusal::ImportUncertain,
                RootPoolObservation::Entered { reply_recorded, selector_unchanged }) =>
                (reply_recorded, selector_unchanged),
            _ => return Err(ReadmissionError::ObservationMismatch),
        };
        if reply_recorded { return Err(ReadmissionError::ReplyInRootPool); }
        if !selector_unchanged { return Err(ReadmissionError::SelectorChanged); }
        Ok(match self.refusal {
            HandoffRefusal::ImportUncertain => HandoffResolution::Reconciled,
            _ => HandoffResolution::Quarantined,
        })
    }
}

impl<R: Copy + Eq> HandoffQuarantine<R> {
    pub const fn key(&self) -> HandoffKey<R> { self.key }
    pub const fn epoch(&self) -> u64 { self.epoch }
    pub const fn refusal(&self) -> HandoffRefusal { self.refusal }

    /// The status the sealed Call's live caller receives. Only an import refused with proven
    /// no root-pool effect has a bound Reply and a live caller to answer: NT fails that system
    /// service. A retired or unbound caller is settled by its thread rundown instead.
    pub const fn failure_status(&self) -> Option<u32> {
        match self.refusal {
            HandoffRefusal::ImportNoEffect | HandoffRefusal::ImportUncertain =>
                Some(STATUS_INSUFFICIENT_RESOURCES),
            HandoffRefusal::RetiredBinding | HandoffRefusal::ReplyUnbound => None,
        }
    }
}

impl<R: Copy + Eq> HandoffReadmission<R> {
    pub const fn key(&self) -> HandoffKey<R> { self.key }
    pub const fn resolution(&self) -> HandoffResolution { self.resolution }
}

#[cfg(test)]
#[path = "root_handoff_readmission_tests.rs"]
mod tests;
