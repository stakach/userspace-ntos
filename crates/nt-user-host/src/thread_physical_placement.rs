//! Exact ownership of a hosted thread's physical scheduler placement.
//!
//! The native adapter stores this owner in the published runtime row alongside its TCB
//! and SC caps. A physical configure operation is recorded before invocation. The
//! caller classifies its terminal effect; an uncertain effect retains the original
//! attempt and cannot authorize a retry, identity query, or mechanism retirement.

use crate::process_identity::ProcessIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementIdentity {
    pub process: ProcessIdentity,
    pub tid: u64,
    pub tcb: u64,
    pub sched_context: u64,
}

impl PlacementIdentity {
    fn is_valid(self) -> bool {
        self.process.is_valid() && self.tid != 0 && self.tcb > 1 && self.sched_context > 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementAttempt {
    identity: PlacementIdentity,
    sequence: u64,
    from: u8,
    to: u8,
}

impl PlacementAttempt {
    pub const fn source_core(self) -> u8 {
        self.from
    }
    pub const fn target_core(self) -> u8 {
        self.to
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementEffect {
    /// The exact SC/TCB transition completed and the target core is authoritative.
    Applied,
    /// The backend proved that no physical placement effect occurred.
    NoEffect,
    /// The effect cannot yet be classified; the attempt remains retained.
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementError {
    InvalidIdentity,
    WrongIdentity,
    InvalidCore,
    SameCore,
    Busy,
    Uncertain,
    StaleAttempt,
    SequenceExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Known(u8),
    Pending(PlacementAttempt),
    Uncertain(PlacementAttempt),
}

/// The only authoritative core for this exact published runtime and mechanism pair.
#[derive(Debug)]
pub struct PhysicalPlacementOwner {
    identity: PlacementIdentity,
    state: State,
    next_sequence: u64,
}

impl PhysicalPlacementOwner {
    /// Construct only after the initial SC was configured, bound to this TCB, and published.
    pub fn new(
        identity: PlacementIdentity,
        core: u8,
        active_count: u8,
    ) -> Result<Self, PlacementError> {
        if !identity.is_valid() {
            return Err(PlacementError::InvalidIdentity);
        }
        if active_count == 0 || active_count > 64 || core >= active_count {
            return Err(PlacementError::InvalidCore);
        }
        Ok(Self {
            identity,
            state: State::Known(core),
            next_sequence: 1,
        })
    }

    pub fn current_core(&self, identity: PlacementIdentity) -> Result<u8, PlacementError> {
        self.check_identity(identity)?;
        match self.state {
            State::Known(core) => Ok(core),
            State::Pending(_) => Err(PlacementError::Busy),
            State::Uncertain(_) => Err(PlacementError::Uncertain),
        }
    }

    /// Record the exact owner before calling SchedControlConfigure. The native adapter
    /// must retain its TCB, SC, runtime row, and Reply while this attempt is pending.
    pub fn begin(
        &mut self,
        identity: PlacementIdentity,
        target_core: u8,
        active_count: u8,
    ) -> Result<PlacementAttempt, PlacementError> {
        self.check_identity(identity)?;
        let from = match self.state {
            State::Known(core) => core,
            State::Pending(_) => return Err(PlacementError::Busy),
            State::Uncertain(_) => return Err(PlacementError::Uncertain),
        };
        if active_count == 0
            || active_count > 64
            || from >= active_count
            || target_core >= active_count
        {
            return Err(PlacementError::InvalidCore);
        }
        if target_core == from {
            return Err(PlacementError::SameCore);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(PlacementError::SequenceExhausted)?;
        let attempt = PlacementAttempt {
            identity,
            sequence: self.next_sequence,
            from,
            to: target_core,
        };
        self.next_sequence = next_sequence;
        self.state = State::Pending(attempt);
        Ok(attempt)
    }

    /// A nonzero native label is not automatically `NoEffect`. Use that outcome only
    /// when the backend proves it performed no placement operation.
    pub fn settle(
        &mut self,
        attempt: PlacementAttempt,
        effect: PlacementEffect,
    ) -> Result<(), PlacementError> {
        self.check_identity(attempt.identity)?;
        if self.state != State::Pending(attempt) {
            return Err(PlacementError::StaleAttempt);
        }
        self.state = match effect {
            PlacementEffect::Applied => State::Known(attempt.to),
            PlacementEffect::NoEffect => State::Known(attempt.from),
            PlacementEffect::Uncertain => State::Uncertain(attempt),
        };
        Ok(())
    }

    /// Reconciliation may classify the retained attempt, but never invoke it again.
    pub fn reconcile(
        &mut self,
        attempt: PlacementAttempt,
        verified_effect: PlacementEffect,
    ) -> Result<(), PlacementError> {
        self.check_identity(attempt.identity)?;
        if self.state != State::Uncertain(attempt) {
            return Err(PlacementError::StaleAttempt);
        }
        self.state = match verified_effect {
            PlacementEffect::Applied => State::Known(attempt.to),
            PlacementEffect::NoEffect => State::Known(attempt.from),
            PlacementEffect::Uncertain => return Err(PlacementError::Uncertain),
        };
        Ok(())
    }

    /// This only says no transition pins the runtime; ordinary thread lifetime
    /// and mechanism retirement checks remain separate.
    pub fn transition_is_settled(&self) -> bool {
        matches!(self.state, State::Known(_))
    }

    fn check_identity(&self, identity: PlacementIdentity) -> Result<(), PlacementError> {
        if !identity.is_valid() {
            return Err(PlacementError::InvalidIdentity);
        }
        if identity != self.identity {
            return Err(PlacementError::WrongIdentity);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_identity::{ProcessGeneration, ProcessIdentity};

    fn identity(generation: u64, tcb: u64, sc: u64) -> PlacementIdentity {
        PlacementIdentity {
            process: ProcessIdentity {
                pid: 42,
                generation: ProcessGeneration::Hosted(generation),
            },
            tid: 512,
            tcb,
            sched_context: sc,
        }
    }

    #[test]
    fn physical_transition_is_invisible_until_its_exact_effect_is_known() {
        let owner = identity(7, 100, 200);
        let mut placement = PhysicalPlacementOwner::new(owner, 0, 4).unwrap();
        let attempt = placement.begin(owner, 2, 4).unwrap();
        assert_eq!(placement.current_core(owner), Err(PlacementError::Busy));
        assert_eq!(placement.begin(owner, 3, 4), Err(PlacementError::Busy));
        assert!(!placement.transition_is_settled());
        placement.settle(attempt, PlacementEffect::Applied).unwrap();
        assert_eq!(placement.current_core(owner), Ok(2));
        assert!(placement.transition_is_settled());
    }

    #[test]
    fn uncertain_effect_keeps_owner_and_forbids_replay_or_retirement() {
        let owner = identity(7, 100, 200);
        let mut placement = PhysicalPlacementOwner::new(owner, 0, 4).unwrap();
        let attempt = placement.begin(owner, 1, 4).unwrap();
        placement
            .settle(attempt, PlacementEffect::Uncertain)
            .unwrap();
        assert_eq!(
            placement.current_core(owner),
            Err(PlacementError::Uncertain)
        );
        assert_eq!(placement.begin(owner, 1, 4), Err(PlacementError::Uncertain));
        assert_eq!(
            placement.settle(attempt, PlacementEffect::Applied),
            Err(PlacementError::StaleAttempt)
        );
        assert!(!placement.transition_is_settled());
        assert_eq!(
            placement.reconcile(attempt, PlacementEffect::Uncertain),
            Err(PlacementError::Uncertain)
        );
        placement
            .reconcile(attempt, PlacementEffect::Applied)
            .unwrap();
        assert_eq!(placement.current_core(owner), Ok(1));
    }

    #[test]
    fn wrong_generation_tcb_or_sc_cannot_change_or_read_placement() {
        let owner = identity(7, 100, 200);
        let mut placement = PhysicalPlacementOwner::new(owner, 0, 4).unwrap();
        for wrong in [
            identity(8, 100, 200),
            identity(7, 101, 200),
            identity(7, 100, 201),
        ] {
            assert_eq!(
                placement.current_core(wrong),
                Err(PlacementError::WrongIdentity)
            );
            assert_eq!(
                placement.begin(wrong, 1, 4),
                Err(PlacementError::WrongIdentity)
            );
        }
        let first = placement.begin(owner, 1, 4).unwrap();
        assert_eq!(
            placement.settle(
                PlacementAttempt {
                    identity: identity(8, 100, 200),
                    ..first
                },
                PlacementEffect::Applied
            ),
            Err(PlacementError::WrongIdentity)
        );
        placement.settle(first, PlacementEffect::NoEffect).unwrap();
        assert_eq!(placement.current_core(owner), Ok(0));
        let second = placement.begin(owner, 2, 4).unwrap();
        assert_eq!(
            placement.settle(first, PlacementEffect::Applied),
            Err(PlacementError::StaleAttempt)
        );
        placement.settle(second, PlacementEffect::Applied).unwrap();
        assert_eq!(placement.current_core(owner), Ok(2));
    }

    #[test]
    fn invalid_core_and_identity_never_enter_a_transition() {
        let owner = identity(7, 100, 200);
        assert!(matches!(
            PhysicalPlacementOwner::new(owner, 0, 0),
            Err(PlacementError::InvalidCore)
        ));
        assert!(matches!(
            PhysicalPlacementOwner::new(owner, 0, 65),
            Err(PlacementError::InvalidCore)
        ));
        assert!(matches!(
            PhysicalPlacementOwner::new(identity(7, 1, 200), 0, 4),
            Err(PlacementError::InvalidIdentity)
        ));
        let mut placement = PhysicalPlacementOwner::new(owner, 0, 4).unwrap();
        assert_eq!(placement.begin(owner, 0, 4), Err(PlacementError::SameCore));
        assert_eq!(
            placement.begin(owner, 4, 4),
            Err(PlacementError::InvalidCore)
        );
        assert_eq!(placement.current_core(owner), Ok(0));
    }
}
