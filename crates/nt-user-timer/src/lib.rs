//! Native NT user waitable-timer state.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use nt_time::{Deadline, TimeSnapshot};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApcTarget {
    pub thread_id: u64,
    pub routine: u64,
    pub context: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Expiration {
    pub object_id: u64,
    pub system_time_100ns: u64,
    pub apc: ApcTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerError {
    InsufficientResources,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TimerRecord {
    object_id: u64,
    deadline: Deadline,
    period_100ns: u64,
    apc: ApcTarget,
}

impl TimerRecord {
    const fn inactive(object_id: u64) -> Self {
        Self {
            object_id,
            deadline: Deadline::Infinite,
            period_100ns: 0,
            apc: ApcTarget {
                thread_id: 0,
                routine: 0,
                context: 0,
            },
        }
    }
}

pub struct TimerTable {
    records: Vec<TimerRecord>,
}

impl Default for TimerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerTable {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            records: Vec::with_capacity(capacity),
        }
    }

    fn position(&self, object_id: u64) -> Option<usize> {
        self.records
            .iter()
            .position(|timer| timer.object_id == object_id)
    }

    pub fn ensure(&mut self, object_id: u64) -> Result<(), TimerError> {
        if self.position(object_id).is_some() {
            return Ok(());
        }
        if self.records.len() == self.records.capacity() {
            self.records
                .try_reserve(self.records.capacity().max(16))
                .map_err(|_| TimerError::InsufficientResources)?;
        }
        self.records.push(TimerRecord::inactive(object_id));
        Ok(())
    }

    pub fn remove(&mut self, object_id: u64) -> bool {
        let Some(position) = self.position(object_id) else {
            return false;
        };
        self.records.remove(position);
        true
    }

    pub fn cancel(&mut self, object_id: u64) -> bool {
        let Some(position) = self.position(object_id) else {
            return false;
        };
        let was_active = self.records[position].deadline != Deadline::Infinite;
        self.records[position].deadline = Deadline::Infinite;
        was_active
    }

    pub fn apc_target(&self, object_id: u64) -> Option<ApcTarget> {
        let position = self.position(object_id)?;
        Some(self.records[position].apc)
    }

    /// Cancel timers whose APC is associated with a terminating thread. Timers without an APC are
    /// dispatcher objects independent of the thread that last set them and remain active.
    pub fn cancel_apcs_for_thread(&mut self, thread_id: u64) -> usize {
        let mut cancelled = 0;
        for timer in self.records.iter_mut().filter(|timer| {
            timer.deadline != Deadline::Infinite
                && timer.apc.routine != 0
                && timer.apc.thread_id == thread_id
        }) {
            timer.deadline = Deadline::Infinite;
            cancelled += 1;
        }
        cancelled
    }

    pub fn set(
        &mut self,
        object_id: u64,
        deadline: Deadline,
        period_100ns: u64,
        apc: ApcTarget,
    ) -> Result<bool, TimerError> {
        self.ensure(object_id)?;
        let position = self
            .position(object_id)
            .expect("ensured timer must remain present");
        let was_active = self.records[position].deadline != Deadline::Infinite;
        self.records[position] = TimerRecord {
            object_id,
            deadline,
            period_100ns,
            apc,
        };
        Ok(was_active)
    }

    pub fn next_deadline(&self, now: TimeSnapshot) -> Option<u64> {
        self.records
            .iter()
            .filter_map(|timer| timer.deadline.monotonic_target(now))
            .min()
    }

    /// Expire one due timer and perform its state transition before returning it to the executive.
    /// Repeated calls drain all timers due in the same coherent snapshot without retaining a borrow
    /// across dispatcher signaling or APC delivery.
    pub fn expire_next_due(&mut self, now: TimeSnapshot) -> Option<Expiration> {
        let position = self
            .records
            .iter()
            .enumerate()
            .filter(|(_, timer)| timer.deadline.is_due(now))
            .min_by_key(|(_, timer)| timer.deadline.ordering_key(now))
            .map(|(position, _)| position)?;
        let timer = &mut self.records[position];
        timer.deadline = if timer.period_100ns == 0 {
            Deadline::Infinite
        } else {
            Deadline::Relative {
                monotonic_100ns: now.monotonic_100ns.saturating_add(timer.period_100ns),
            }
        };
        Some(Expiration {
            object_id: timer.object_id,
            system_time_100ns: now.system_time_100ns,
            apc: timer.apc,
        })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[cfg(test)]
    fn deadline(&self, object_id: u64) -> Option<Deadline> {
        self.position(object_id)
            .map(|position| self.records[position].deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_time::AdjustableClock;

    fn snapshot(monotonic_100ns: u64, system_time_100ns: u64) -> TimeSnapshot {
        TimeSnapshot {
            monotonic_100ns,
            system_time_100ns,
            clock_generation: 0,
        }
    }

    #[test]
    fn inactive_timer_has_no_deadline_and_cancel_reports_false() {
        let mut timers = TimerTable::new();
        timers.ensure(7).unwrap();
        assert_eq!(timers.next_deadline(snapshot(100, 1_000)), None);
        assert!(!timers.cancel(7));
        assert_eq!(timers.len(), 1);
    }

    #[test]
    fn relative_timer_ignores_system_clock_changes() {
        let mut clock = AdjustableClock::try_new(100, 1_000).unwrap();
        let mut timers = TimerTable::new();
        timers
            .set(
                1,
                Deadline::from_nt_timeout(Some(-500), clock.snapshot(100)),
                0,
                ApcTarget::default(),
            )
            .unwrap();
        clock.set_system_time(200, 50_000).unwrap();
        assert_eq!(timers.next_deadline(clock.snapshot(200)), Some(600));
        assert_eq!(timers.expire_next_due(clock.snapshot(599)), None);
        assert!(timers.expire_next_due(clock.snapshot(600)).is_some());
    }

    #[test]
    fn absolute_timer_reprojects_across_clock_changes() {
        let mut clock = AdjustableClock::try_new(100, 1_000).unwrap();
        let mut timers = TimerTable::new();
        timers
            .set(
                1,
                Deadline::Absolute {
                    system_time_100ns: 2_000,
                },
                0,
                ApcTarget::default(),
            )
            .unwrap();
        assert_eq!(timers.next_deadline(clock.snapshot(100)), Some(1_100));
        clock.set_system_time(200, 1_100).unwrap();
        assert_eq!(timers.next_deadline(clock.snapshot(200)), Some(1_100));
        clock.set_system_time(300, 2_500).unwrap();
        assert_eq!(timers.next_deadline(clock.snapshot(300)), Some(300));
        assert!(timers.expire_next_due(clock.snapshot(300)).is_some());
    }

    #[test]
    fn expiration_reports_system_time_and_period_becomes_relative() {
        let mut timers = TimerTable::new();
        let apc = ApcTarget {
            thread_id: 11,
            routine: 0x1234,
            context: 0x5678,
        };
        timers
            .set(
                9,
                Deadline::Absolute {
                    system_time_100ns: 2_000,
                },
                250,
                apc,
            )
            .unwrap();
        let expired = timers.expire_next_due(snapshot(500, 2_000)).unwrap();
        assert_eq!(expired.object_id, 9);
        assert_eq!(expired.system_time_100ns, 2_000);
        assert_eq!(expired.apc, apc);
        assert_eq!(
            timers.deadline(9),
            Some(Deadline::Relative {
                monotonic_100ns: 750
            })
        );
        assert_eq!(timers.next_deadline(snapshot(500, 90_000)), Some(750));
    }

    #[test]
    fn due_timers_expire_in_deadline_then_insertion_order() {
        let mut timers = TimerTable::new();
        timers
            .set(
                1,
                Deadline::Absolute {
                    system_time_100ns: 1_900,
                },
                0,
                ApcTarget::default(),
            )
            .unwrap();
        timers
            .set(
                2,
                Deadline::Absolute {
                    system_time_100ns: 1_800,
                },
                0,
                ApcTarget::default(),
            )
            .unwrap();
        timers
            .set(
                3,
                Deadline::Absolute {
                    system_time_100ns: 1_800,
                },
                0,
                ApcTarget::default(),
            )
            .unwrap();
        let now = snapshot(500, 2_000);
        assert_eq!(timers.expire_next_due(now).unwrap().object_id, 2);
        assert_eq!(timers.expire_next_due(now).unwrap().object_id, 3);
        assert_eq!(timers.expire_next_due(now).unwrap().object_id, 1);
        assert_eq!(timers.expire_next_due(now), None);
    }

    #[test]
    fn cancel_and_remove_delete_active_deadlines() {
        let mut timers = TimerTable::new();
        timers
            .set(
                4,
                Deadline::Relative {
                    monotonic_100ns: 400,
                },
                0,
                ApcTarget::default(),
            )
            .unwrap();
        assert!(timers.cancel(4));
        assert!(!timers.cancel(4));
        assert!(timers.remove(4));
        assert!(!timers.remove(4));
        assert!(timers.is_empty());
    }

    #[test]
    fn thread_rundown_cancels_only_apc_associated_timers() {
        let mut timers = TimerTable::new();
        let deadline = Deadline::Relative {
            monotonic_100ns: 400,
        };
        timers
            .set(
                1,
                deadline,
                0,
                ApcTarget {
                    thread_id: 9,
                    routine: 0x1000,
                    context: 0,
                },
            )
            .unwrap();
        timers.set(2, deadline, 0, ApcTarget::default()).unwrap();
        timers
            .set(
                3,
                deadline,
                0,
                ApcTarget {
                    thread_id: 10,
                    routine: 0x2000,
                    context: 0,
                },
            )
            .unwrap();

        assert_eq!(timers.cancel_apcs_for_thread(9), 1);
        assert_eq!(timers.deadline(1), Some(Deadline::Infinite));
        assert_eq!(timers.deadline(2), Some(deadline));
        assert_eq!(timers.deadline(3), Some(deadline));
    }

    #[test]
    fn table_grows_with_runtime_timer_demand() {
        let mut timers = TimerTable::new();
        for object_id in 0..128 {
            timers
                .set(
                    object_id,
                    Deadline::Relative {
                        monotonic_100ns: 1_000 + object_id,
                    },
                    0,
                    ApcTarget::default(),
                )
                .unwrap();
        }
        assert_eq!(timers.len(), 128);
        assert_eq!(timers.next_deadline(snapshot(100, 500)), Some(1_000));
    }
}
