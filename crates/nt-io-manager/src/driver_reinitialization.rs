//! Retained one-shot driver reinitialization callback ownership.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverReinitializationIdentity {
    pub driver_id: u64,
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub driver_object: u64,
    pub routine: u64,
    pub context: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverReinitializationTicket {
    pub registration: u64,
    pub identity: DriverReinitializationIdentity,
    pub count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverReinitializationError {
    InvalidIdentity,
    Exhausted,
    WrongPhase,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Queued,
    Executing,
    Acknowledged,
}

struct Row {
    registration: u64,
    identity: DriverReinitializationIdentity,
    count: u32,
    phase: Phase,
}

pub struct DriverReinitializationQueue {
    rows: Vec<Row>,
    next_registration: u64,
}

impl Default for DriverReinitializationQueue {
    fn default() -> Self { Self::new() }
}

impl DriverReinitializationQueue {
    pub const fn new() -> Self {
        Self { rows: Vec::new(), next_registration: 1 }
    }

    pub fn register(
        &mut self,
        identity: DriverReinitializationIdentity,
    ) -> Result<u64, DriverReinitializationError> {
        if identity.driver_id == 0 || identity.domain_id == 0 || identity.domain_cookie == 0
            || identity.driver_object == 0 || identity.routine == 0
        {
            return Err(DriverReinitializationError::InvalidIdentity);
        }
        let registration = self.next_registration;
        let next = registration.checked_add(1).ok_or(DriverReinitializationError::Exhausted)?;
        self.rows.try_reserve(1).map_err(|_| DriverReinitializationError::Exhausted)?;
        self.rows.push(Row { registration, identity, count: 0, phase: Phase::Queued });
        self.next_registration = next;
        Ok(registration)
    }

    /// Claim the oldest queued callback. Repeated polling cannot replay an executing callback.
    pub fn begin_next(&mut self) -> Option<DriverReinitializationTicket> {
        self.begin_matching(|_| true)
    }

    pub fn begin_next_for(
        &mut self, driver_id: u64, domain_id: u64, domain_cookie: u64,
    ) -> Option<DriverReinitializationTicket> {
        self.begin_matching(|identity| {
            identity.driver_id == driver_id && identity.domain_id == domain_id
                && identity.domain_cookie == domain_cookie
        })
    }

    fn begin_matching(
        &mut self, matches: impl Fn(DriverReinitializationIdentity) -> bool,
    ) -> Option<DriverReinitializationTicket> {
        let index = self.rows.iter().position(|row| {
            row.phase == Phase::Queued && matches(row.identity) && !self.rows.iter().any(|other| {
                other.phase == Phase::Executing
                    && other.identity.driver_id == row.identity.driver_id
                    && other.identity.domain_id == row.identity.domain_id
                    && other.identity.domain_cookie == row.identity.domain_cookie
                    && other.identity.driver_object == row.identity.driver_object
            })
        })?;
        let identity = self.rows[index].identity;
        let count = self.rows.iter().filter(|row| {
            row.identity.driver_id == identity.driver_id
                && row.identity.domain_id == identity.domain_id
                && row.identity.domain_cookie == identity.domain_cookie
                && row.identity.driver_object == identity.driver_object
                && row.phase != Phase::Queued
        }).count().checked_add(1)?;
        let count = u32::try_from(count).ok()?;
        self.rows[index].count = count;
        self.rows[index].phase = Phase::Executing;
        Some(DriverReinitializationTicket {
            registration: self.rows[index].registration,
            identity,
            count,
        })
    }

    pub fn acknowledge(
        &mut self,
        ticket: DriverReinitializationTicket,
    ) -> Result<(), DriverReinitializationError> {
        let row = self.rows.iter_mut().find(|row| row.registration == ticket.registration)
            .ok_or(DriverReinitializationError::WrongPhase)?;
        if row.phase != Phase::Executing || row.identity != ticket.identity || row.count != ticket.count {
            return Err(DriverReinitializationError::WrongPhase);
        }
        row.phase = Phase::Acknowledged;
        Ok(())
    }

    pub fn quiesced(&self, driver_id: u64, domain_id: u64, domain_cookie: u64) -> bool {
        self.rows.iter().all(|row| {
            row.identity.driver_id != driver_id || row.identity.domain_id != domain_id
                || row.identity.domain_cookie != domain_cookie || row.phase == Phase::Acknowledged
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLASS: DriverReinitializationIdentity = DriverReinitializationIdentity {
        driver_id: 21,
        domain_id: 7,
        domain_cookie: 98,
        driver_object: 0x4000,
        routine: 0x1008,
        context: 0x5000,
    };

    #[test]
    fn callback_is_retained_until_acknowledged_and_never_replayed_after_uncertainty() {
        let mut queue = DriverReinitializationQueue::new();
        let first = queue.register(CLASS).unwrap();
        let dispatch = queue.begin_next().unwrap();
        assert_eq!(dispatch.registration, first);
        assert_eq!(dispatch.count, 1);
        assert!(queue.begin_next().is_none());
        assert!(!queue.quiesced(CLASS.driver_id, CLASS.domain_id, CLASS.domain_cookie));
        assert_eq!(queue.acknowledge(dispatch), Ok(()));
        assert!(queue.quiesced(CLASS.driver_id, CLASS.domain_id, CLASS.domain_cookie));
        let second = queue.register(CLASS).unwrap();
        let dispatch = queue.begin_next().unwrap();
        assert_eq!(dispatch.registration, second);
        assert_eq!(dispatch.count, 2);
    }

    #[test]
    fn stale_generation_cannot_acknowledge_current_callback() {
        let mut queue = DriverReinitializationQueue::new();
        queue.register(CLASS).unwrap();
        let current = queue.begin_next().unwrap();
        let wrong = DriverReinitializationTicket {
            identity: DriverReinitializationIdentity { domain_cookie: 99, ..CLASS },
            ..current
        };
        assert_eq!(queue.acknowledge(wrong), Err(DriverReinitializationError::WrongPhase));
        assert!(!queue.quiesced(CLASS.driver_id, CLASS.domain_id, CLASS.domain_cookie));
    }

    #[test]
    fn uncertain_callback_blocks_later_callback_for_the_same_driver() {
        let mut queue = DriverReinitializationQueue::new();
        queue.register(CLASS).unwrap();
        queue.register(DriverReinitializationIdentity { routine: 0x1010, ..CLASS }).unwrap();
        let first = queue.begin_next_for(CLASS.driver_id, CLASS.domain_id, CLASS.domain_cookie).unwrap();
        assert_eq!(first.count, 1);
        assert!(queue.begin_next_for(CLASS.driver_id, CLASS.domain_id, CLASS.domain_cookie).is_none());
        queue.acknowledge(first).unwrap();
        assert_eq!(
            queue.begin_next_for(CLASS.driver_id, CLASS.domain_id, CLASS.domain_cookie).unwrap().count,
            2,
        );
    }
}
