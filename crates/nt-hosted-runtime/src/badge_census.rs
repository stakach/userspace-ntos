//! Bounded attribution slots for executive ingress diagnostics.

/// Endpoint badges below this limit retain their exact numeric identity in the census.
pub const DIRECT_BADGE_SLOTS: usize = 64;
pub const TIMER_SLOT: usize = DIRECT_BADGE_SLOTS;
pub const HOSTED_IRQ_SLOT: usize = TIMER_SLOT + 1;
pub const GUARD_OR_ISR_SLOT: usize = HOSTED_IRQ_SLOT + 1;
pub const OVERFLOW_SLOT: usize = GUARD_OR_ISR_SLOT + 1;
pub const BADGE_CENSUS_SLOTS: usize = OVERFLOW_SLOT + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BadgeCensusSource {
    Endpoint(u64),
    DelayTimer,
    HostedIrq,
    GuardOrIsr,
}

impl BadgeCensusSource {
    pub const fn slot(self) -> usize {
        match self {
            Self::Endpoint(badge) if badge < DIRECT_BADGE_SLOTS as u64 => badge as usize,
            Self::Endpoint(_) => OVERFLOW_SLOT,
            Self::DelayTimer => TIMER_SLOT,
            Self::HostedIrq => HOSTED_IRQ_SLOT,
            Self::GuardOrIsr => GUARD_OR_ISR_SLOT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_hosted_badges_keep_distinct_slots() {
        for badge in 36..=43 {
            assert_eq!(BadgeCensusSource::Endpoint(badge).slot(), badge as usize);
        }
    }

    #[test]
    fn non_endpoint_deliveries_have_dedicated_slots_outside_direct_badges() {
        assert_eq!(BadgeCensusSource::DelayTimer.slot(), TIMER_SLOT);
        assert_eq!(BadgeCensusSource::HostedIrq.slot(), HOSTED_IRQ_SLOT);
        assert_eq!(BadgeCensusSource::GuardOrIsr.slot(), GUARD_OR_ISR_SLOT);
        for slot in [TIMER_SLOT, HOSTED_IRQ_SLOT, GUARD_OR_ISR_SLOT] {
            assert!(slot >= DIRECT_BADGE_SLOTS);
            assert_ne!(slot, OVERFLOW_SLOT);
        }
    }

    #[test]
    fn first_unrepresented_endpoint_and_larger_badges_use_explicit_overflow() {
        assert_eq!(BadgeCensusSource::Endpoint(63).slot(), 63);
        assert_eq!(BadgeCensusSource::Endpoint(64).slot(), OVERFLOW_SLOT);
        assert_eq!(BadgeCensusSource::Endpoint(u64::MAX).slot(), OVERFLOW_SLOT);
        assert_eq!(BADGE_CENSUS_SLOTS, OVERFLOW_SLOT + 1);
    }
}
