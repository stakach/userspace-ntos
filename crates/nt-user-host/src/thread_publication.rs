//! Exclusive, one-shot publication into an already allocated runtime reservation.
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationError {
    Busy,
    Exhausted,
    StaleAttempt,
    OwnerChanged,
}

/// Stored in the runtime row. Occupied rows must not be released, rebound or have their metadata
/// changed while construction holds a ticket. The table remains the resource/reservation owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadPublicationSlot {
    attempt: Option<u64>,
}

/// Non-cloneable ticket, consumed exactly once on cancellation or successful publication. Dropping
/// it does not release the slot: a failed constructor must return to its owner for cancellation.
#[must_use = "finish or cancel publication before releasing the runtime reservation"]
#[derive(Debug)]
pub struct PreparedThreadPublication<T> {
    attempt: u64,
    owner: T,
}

impl<T> PreparedThreadPublication<T> {
    pub fn owner(&self) -> &T {
        &self.owner
    }

    pub(crate) fn attempt(&self) -> u64 {
        self.attempt
    }
}

impl ThreadPublicationSlot {
    pub const fn empty() -> Self {
        Self { attempt: None }
    }
    pub const fn is_busy(&self) -> bool {
        self.attempt.is_some()
    }

    pub fn can_release_unbuilt(&self, tcb: u64, owns_resources: bool) -> bool {
        !self.is_busy() && tcb == 1 && !owns_resources
    }

    pub fn prepare<T>(
        &mut self,
        owner: T,
    ) -> Result<PreparedThreadPublication<T>, PublicationError> {
        self.prepare_with_counter(owner, &NEXT_ATTEMPT)
    }

    fn prepare_with_counter<T>(
        &mut self,
        owner: T,
        counter: &AtomicU64,
    ) -> Result<PreparedThreadPublication<T>, PublicationError> {
        if self.is_busy() {
            return Err(PublicationError::Busy);
        }
        let attempt = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| PublicationError::Exhausted)?;
        self.attempt = Some(attempt);
        Ok(PreparedThreadPublication { attempt, owner })
    }

    pub fn validate<T: Eq>(
        &self,
        ticket: &PreparedThreadPublication<T>,
        owner: &T,
    ) -> Result<(), PublicationError> {
        if self.attempt != Some(ticket.attempt) {
            return Err(PublicationError::StaleAttempt);
        }
        if &ticket.owner != owner {
            return Err(PublicationError::OwnerChanged);
        }
        Ok(())
    }

    /// Use after all fallible construction work, or on canonical construction failure. On rejection
    /// the ticket is returned intact and the slot remains occupied. This performs no resource cleanup.
    pub fn finish<T: Eq>(
        &mut self,
        ticket: PreparedThreadPublication<T>,
        owner: &T,
    ) -> Result<T, (PublicationError, PreparedThreadPublication<T>)> {
        if let Err(error) = self.validate(&ticket, owner) {
            return Err((error, ticket));
        }
        self.attempt = None;
        Ok(ticket.owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_is_exclusive_and_finishing_releases_once() {
        let mut slot = ThreadPublicationSlot::empty();
        let ticket = slot.prepare((27, 301)).unwrap();
        assert!(slot.is_busy());
        assert!(matches!(
            slot.prepare((27, 301)),
            Err(PublicationError::Busy)
        ));
        assert_eq!(ticket.owner(), &(27, 301));
        assert_eq!(slot.validate(&ticket, &(27, 301)), Ok(()));
        assert!(slot.finish(ticket, &(27, 301)).is_ok());
        assert!(!slot.is_busy());
    }

    #[test]
    fn failed_validation_retains_ticket_and_reservation_for_retry() {
        let mut slot = ThreadPublicationSlot::empty();
        let ticket = slot.prepare((27, 301)).unwrap();
        let (error, ticket) = slot.finish(ticket, &(28, 301)).err().unwrap();
        assert_eq!(error, PublicationError::OwnerChanged);
        assert!(slot.is_busy());
        assert!(slot.finish(ticket, &(27, 301)).is_ok());
    }

    #[test]
    fn same_identity_in_another_slot_cannot_consume_the_ticket() {
        let mut first = ThreadPublicationSlot::empty();
        let mut second = ThreadPublicationSlot::empty();
        let first_ticket = first.prepare(301).unwrap();
        let second_ticket = second.prepare(301).unwrap();
        let (error, first_ticket) = second.finish(first_ticket, &301).err().unwrap();
        assert_eq!(error, PublicationError::StaleAttempt);
        assert!(first.is_busy() && second.is_busy());
        assert!(first.finish(first_ticket, &301).is_ok());
        assert!(second.finish(second_ticket, &301).is_ok());
    }

    #[test]
    fn reused_slot_gets_a_new_attempt_even_for_the_same_tid() {
        let mut slot = ThreadPublicationSlot::empty();
        let first = slot.prepare(301).unwrap();
        let previous = first.attempt;
        assert!(slot.finish(first, &301).is_ok());
        let next = slot.prepare(301).unwrap();
        assert_ne!(previous, next.attempt);
        let stale = PreparedThreadPublication {
            attempt: previous,
            owner: 301,
        };
        let (error, _) = slot.finish(stale, &301).err().unwrap();
        assert_eq!(error, PublicationError::StaleAttempt);
        assert!(slot.is_busy());
        assert!(slot.finish(next, &301).is_ok());
    }

    #[test]
    fn exhaustion_never_wraps_or_occupies_an_empty_slot() {
        let counter = AtomicU64::new(u64::MAX - 1);
        let mut slot = ThreadPublicationSlot::empty();
        let last = slot.prepare_with_counter(301, &counter).unwrap();
        assert!(slot.finish(last, &301).is_ok());
        for _ in 0..3 {
            assert!(matches!(
                slot.prepare_with_counter(301, &counter),
                Err(PublicationError::Exhausted)
            ));
            assert!(!slot.is_busy());
            assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        }
    }

    #[test]
    fn dropping_a_ticket_does_not_make_construction_ownership_disappear() {
        let mut slot = ThreadPublicationSlot::empty();
        drop(slot.prepare(301).unwrap());
        assert!(slot.is_busy());
        assert!(matches!(slot.prepare(301), Err(PublicationError::Busy)));
    }

    #[test]
    fn only_an_idle_empty_reservation_can_release_its_pool_and_window() {
        let mut slot = ThreadPublicationSlot::empty();
        for tcb in [0, 1, 100] {
            for owns_resources in [false, true] {
                assert_eq!(
                    slot.can_release_unbuilt(tcb, owns_resources),
                    tcb == 1 && !owns_resources
                );
            }
        }
        let ticket = slot.prepare(301).unwrap();
        for tcb in [0, 1, 100] {
            for owns_resources in [false, true] {
                assert!(!slot.can_release_unbuilt(tcb, owns_resources));
            }
        }
        assert!(slot.finish(ticket, &301).is_ok());
        assert!(slot.can_release_unbuilt(1, false));
    }
}
