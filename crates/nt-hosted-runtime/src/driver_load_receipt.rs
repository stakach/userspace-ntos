//! Pure phase and effect transitions for a hosted driver load's physical receipt.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverLoadPhase {
    Allocating,
    CanonicalPublished,
    Suspended,
    Enrolled,
}

impl DriverLoadPhase {
    pub const fn publish_canonical(self) -> Option<Self> {
        match self {
            Self::Allocating => Some(Self::CanonicalPublished),
            _ => None,
        }
    }

    pub const fn record_suspended(self) -> Option<Self> {
        match self {
            Self::CanonicalPublished => Some(Self::Suspended),
            _ => None,
        }
    }

    pub const fn enroll(self) -> Option<Self> {
        match self {
            Self::Suspended => Some(Self::Enrolled),
            _ => None,
        }
    }

    pub const fn pre_enrollment(self) -> bool {
        !matches!(self, Self::Enrolled)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedEffectState {
    Ready,
    Entered,
}

impl RetainedEffectState {
    pub fn begin(&mut self) -> bool {
        if *self != Self::Ready {
            return false;
        }
        *self = Self::Entered;
        true
    }

    /// Failure leaves the effect entered; the caller must not replay it.
    pub fn acknowledge(&mut self, succeeded: bool) -> bool {
        if *self != Self::Entered || !succeeded {
            return false;
        }
        *self = Self::Ready;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_phase_requires_exact_publication_order() {
        let phase = DriverLoadPhase::Allocating;
        assert!(phase.record_suspended().is_none());
        let phase = phase.publish_canonical().unwrap();
        assert!(phase.enroll().is_none());
        let phase = phase.record_suspended().unwrap();
        assert!(phase.pre_enrollment());
        let phase = phase.enroll().unwrap();
        assert!(!phase.pre_enrollment());
        assert!(phase.publish_canonical().is_none());
    }

    #[test]
    fn uncertain_unmap_or_delete_cannot_be_replayed() {
        for _ in 0..2 {
            let mut effect = RetainedEffectState::Ready;
            assert!(effect.begin());
            assert!(!effect.acknowledge(false));
            assert!(!effect.begin());
            assert_eq!(effect, RetainedEffectState::Entered);
        }
    }

    #[test]
    fn acknowledged_effect_permits_next_distinct_effect() {
        let mut effect = RetainedEffectState::Ready;
        assert!(effect.begin());
        assert!(effect.acknowledge(true));
        assert!(effect.begin());
    }
}
