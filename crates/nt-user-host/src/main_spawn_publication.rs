//! Exact ownership across a main thread's VSpace, PEB, and runtime publication.
//!
//! The native adapter owns the physical mechanism and VSpace. It must retain this
//! value across refusals and classify an effect as `NoEffect` only when the backend
//! proves that no publication occurred. Neither a cap number nor a copied spawn is
//! authority to release the original owner.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::thread_physical_placement::PlacementIdentity;

static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationEffect {
    Applied,
    NoEffect,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationPhase {
    Constructed,
    VspacePending,
    VspaceUncertain,
    VspacePublished,
    PebPublished,
    RuntimePending,
    RuntimeUncertain,
    RuntimePublished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationError {
    InvalidIdentity,
    WrongIdentity,
    OutOfOrder,
    StaleAttempt,
    AttemptExhausted,
    UnverifiedEffect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Vspace,
    Runtime,
}

/// A one-shot receipt for exactly one entered publication effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationAttempt {
    identity: PlacementIdentity,
    sequence: u64,
    step: Step,
}

/// The original owners stay here until their respective checked publications.
/// The adapter must durably retain the value while a native result is uncertain.
pub struct MainSpawnPublication<M, V> {
    identity: PlacementIdentity,
    phase: PublicationPhase,
    active: Option<PublicationAttempt>,
    mechanism: Option<M>,
    vspace: Option<V>,
}

impl<M, V> MainSpawnPublication<M, V> {
    /// On invalid identity, return both physical owners to the caller unchanged.
    pub fn new(
        identity: PlacementIdentity,
        mechanism: M,
        vspace: V,
    ) -> Result<Self, (PublicationError, M, V)> {
        if !identity.process.is_valid()
            || identity.tid == 0
            || identity.tcb <= 1
            || identity.sched_context <= 1
        {
            return Err((PublicationError::InvalidIdentity, mechanism, vspace));
        }
        Ok(Self {
            identity,
            phase: PublicationPhase::Constructed,
            active: None,
            mechanism: Some(mechanism),
            vspace: Some(vspace),
        })
    }

    pub fn phase(&self) -> PublicationPhase {
        self.phase
    }

    /// Inspect the original mechanism without making a second owner.
    pub fn mechanism(&self) -> Option<&M> {
        self.mechanism.as_ref()
    }

    /// Let the native adapter publish from the original mechanism only after
    /// the exact runtime attempt has been recorded. An uncertain result closes
    /// this borrow path until reconciliation proves its effect.
    pub fn mechanism_mut(&mut self) -> Option<&mut M> {
        (self.phase == PublicationPhase::RuntimePending)
            .then(|| self.mechanism.as_mut())
            .flatten()
    }

    /// Inspect the original VSpace inventory without making a second owner.
    pub fn vspace(&self) -> Option<&V> {
        self.vspace.as_ref()
    }

    fn check_identity(&self, identity: PlacementIdentity) -> Result<(), PublicationError> {
        if identity == self.identity {
            Ok(())
        } else {
            Err(PublicationError::WrongIdentity)
        }
    }

    fn next_attempt(&self, step: Step) -> Result<PublicationAttempt, PublicationError> {
        let sequence = NEXT_ATTEMPT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| next.checked_add(1))
            .map_err(|_| PublicationError::AttemptExhausted)?;
        Ok(PublicationAttempt {
            identity: self.identity,
            sequence,
            step,
        })
    }

    /// Record the original VSpace owner before invoking its native publication.
    pub fn begin_vspace(
        &mut self,
        identity: PlacementIdentity,
    ) -> Result<PublicationAttempt, PublicationError> {
        self.check_identity(identity)?;
        if self.phase != PublicationPhase::Constructed {
            return Err(PublicationError::OutOfOrder);
        }
        let attempt = self.next_attempt(Step::Vspace)?;
        self.active = Some(attempt);
        self.phase = PublicationPhase::VspacePending;
        Ok(attempt)
    }

    /// Transfer the exact VSpace owner once; a definite refusal keeps it for retry.
    pub fn settle_vspace(
        &mut self,
        attempt: PublicationAttempt,
        effect: PublicationEffect,
    ) -> Result<Option<V>, PublicationError> {
        if self.phase != PublicationPhase::VspacePending
            || self.active != Some(attempt)
            || attempt.step != Step::Vspace
        {
            return Err(PublicationError::StaleAttempt);
        }
        self.active = None;
        match effect {
            PublicationEffect::Applied => {
                self.phase = PublicationPhase::VspacePublished;
                Ok(self.vspace.take())
            }
            PublicationEffect::NoEffect => {
                self.phase = PublicationPhase::Constructed;
                Ok(None)
            }
            PublicationEffect::Uncertain => {
                self.active = Some(attempt);
                self.phase = PublicationPhase::VspaceUncertain;
                Ok(None)
            }
        }
    }

    /// Resolve an uncertain VSpace effect from independent exact evidence. This
    /// does not invoke publication again; only `NoEffect` permits a new attempt.
    pub fn reconcile_vspace(
        &mut self,
        attempt: PublicationAttempt,
        verified_effect: PublicationEffect,
    ) -> Result<Option<V>, PublicationError> {
        if self.phase != PublicationPhase::VspaceUncertain
            || self.active != Some(attempt)
            || attempt.step != Step::Vspace
        {
            return Err(PublicationError::StaleAttempt);
        }
        if verified_effect == PublicationEffect::Uncertain {
            return Err(PublicationError::UnverifiedEffect);
        }
        self.phase = PublicationPhase::VspacePending;
        self.settle_vspace(attempt, verified_effect)
    }

    /// The caller records a confirmed PEB publication for this exact child.
    pub fn record_peb(&mut self, identity: PlacementIdentity) -> Result<(), PublicationError> {
        self.check_identity(identity)?;
        if self.phase != PublicationPhase::VspacePublished {
            return Err(PublicationError::OutOfOrder);
        }
        self.phase = PublicationPhase::PebPublished;
        Ok(())
    }

    /// Record the TCB/SC owner before attempting native runtime publication.
    pub fn begin_runtime(
        &mut self,
        identity: PlacementIdentity,
    ) -> Result<PublicationAttempt, PublicationError> {
        self.check_identity(identity)?;
        if self.phase != PublicationPhase::PebPublished {
            return Err(PublicationError::OutOfOrder);
        }
        let attempt = self.next_attempt(Step::Runtime)?;
        self.active = Some(attempt);
        self.phase = PublicationPhase::RuntimePending;
        Ok(attempt)
    }

    /// The mechanism transfers only after the exact runtime accepted it.
    pub fn settle_runtime(
        &mut self,
        attempt: PublicationAttempt,
        effect: PublicationEffect,
    ) -> Result<Option<M>, PublicationError> {
        if self.phase != PublicationPhase::RuntimePending
            || self.active != Some(attempt)
            || attempt.step != Step::Runtime
        {
            return Err(PublicationError::StaleAttempt);
        }
        self.active = None;
        match effect {
            PublicationEffect::Applied => {
                self.phase = PublicationPhase::RuntimePublished;
                Ok(self.mechanism.take())
            }
            PublicationEffect::NoEffect => {
                self.phase = PublicationPhase::PebPublished;
                Ok(None)
            }
            PublicationEffect::Uncertain => {
                self.active = Some(attempt);
                self.phase = PublicationPhase::RuntimeUncertain;
                Ok(None)
            }
        }
    }

    /// Resolve an uncertain runtime effect without replaying it.
    pub fn reconcile_runtime(
        &mut self,
        attempt: PublicationAttempt,
        verified_effect: PublicationEffect,
    ) -> Result<Option<M>, PublicationError> {
        if self.phase != PublicationPhase::RuntimeUncertain
            || self.active != Some(attempt)
            || attempt.step != Step::Runtime
        {
            return Err(PublicationError::StaleAttempt);
        }
        if verified_effect == PublicationEffect::Uncertain {
            return Err(PublicationError::UnverifiedEffect);
        }
        self.phase = PublicationPhase::RuntimePending;
        self.settle_runtime(attempt, verified_effect)
    }
}
