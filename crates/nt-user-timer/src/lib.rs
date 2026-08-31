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
    retained_due_100ns: u64,
    period_100ns: u64,
    apc: ApcTarget,
}

impl TimerRecord {
    const fn inactive(object_id: u64) -> Self {
        Self {
            object_id,
            deadline: Deadline::Infinite,
            retained_due_100ns: 0,
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

    pub fn cancel(&mut self, object_id: u64, now: TimeSnapshot) -> bool {
        let Some(position) = self.position(object_id) else {
            return false;
        };
        let timer = &mut self.records[position];
        let was_active = timer.deadline != Deadline::Infinite;
        if was_active {
            timer.retained_due_100ns = active_due_100ns(timer, now);
            timer.deadline = Deadline::Infinite;
        }
        was_active
    }

    pub fn apc_target(&self, object_id: u64) -> Option<ApcTarget> {
        let position = self.position(object_id)?;
        Some(self.records[position].apc)
    }

    /// Cancel timers whose APC is associated with a terminating thread. Timers without an APC are
    /// dispatcher objects independent of the thread that last set them and remain active.
    pub fn cancel_apcs_for_thread(&mut self, thread_id: u64, now: TimeSnapshot) -> usize {
        let mut cancelled = 0;
        for timer in self.records.iter_mut().filter(|timer| {
            timer.deadline != Deadline::Infinite
                && timer.apc.routine != 0
                && timer.apc.thread_id == thread_id
        }) {
            timer.retained_due_100ns = active_due_100ns(timer, now);
            timer.deadline = Deadline::Infinite;
            cancelled += 1;
        }
        cancelled
    }

    pub fn set(
        &mut self,
        object_id: u64,
        deadline: Deadline,
        now: TimeSnapshot,
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
            retained_due_100ns: deadline_due_100ns(deadline, now),
            period_100ns,
            apc,
        };
        Ok(was_active)
    }

    /// Return the signed time remaining against one coherent clock snapshot.
    ///
    /// NT retains a timer's last due time when a timer is cancelled or a one-shot timer expires,
    /// so inactive timers use the retained interrupt-time due value rather than infinity.
    pub fn remaining_100ns(&self, object_id: u64, now: TimeSnapshot) -> Option<i64> {
        let position = self.position(object_id)?;
        let timer = &self.records[position];
        let due = if timer.deadline == Deadline::Infinite {
            timer.retained_due_100ns
        } else {
            active_due_100ns(timer, now)
        };
        Some(due.wrapping_sub(now.monotonic_100ns) as i64)
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
        timer.retained_due_100ns = active_due_100ns(timer, now);
        timer.deadline = if timer.period_100ns == 0 {
            Deadline::Infinite
        } else {
            Deadline::Relative {
                monotonic_100ns: now.monotonic_100ns.saturating_add(timer.period_100ns),
            }
        };
        if timer.period_100ns != 0 {
            timer.retained_due_100ns = now.monotonic_100ns.saturating_add(timer.period_100ns);
        }
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

fn active_due_100ns(timer: &TimerRecord, now: TimeSnapshot) -> u64 {
    match timer.deadline {
        Deadline::Absolute { .. } => deadline_due_100ns(timer.deadline, now),
        Deadline::Infinite | Deadline::Relative { .. } => timer.retained_due_100ns,
    }
}

fn deadline_due_100ns(deadline: Deadline, now: TimeSnapshot) -> u64 {
    match deadline {
        Deadline::Infinite => 0,
        Deadline::Relative { monotonic_100ns } => monotonic_100ns,
        Deadline::Absolute { system_time_100ns } => {
            (now.monotonic_100ns as i128 + system_time_100ns as i128
                - now.system_time_100ns as i128) as u64
        }
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
        assert_eq!(timers.remaining_100ns(99, snapshot(100, 1_000)), None);
        assert_eq!(timers.next_deadline(snapshot(100, 1_000)), None);
        assert_eq!(timers.remaining_100ns(7, snapshot(100, 1_000)), Some(-100));
        assert!(!timers.cancel(7, snapshot(100, 1_000)));
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
                clock.snapshot(100),
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
                clock.snapshot(100),
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
    fn cancelled_absolute_timer_freezes_its_interrupt_due_time() {
        let mut clock = AdjustableClock::try_new(100, 1_000).unwrap();
        let mut timers = TimerTable::new();
        timers
            .set(
                5,
                Deadline::Absolute {
                    system_time_100ns: 2_000,
                },
                clock.snapshot(100),
                0,
                ApcTarget::default(),
            )
            .unwrap();
        assert!(timers.cancel(5, clock.snapshot(200)));
        assert_eq!(timers.remaining_100ns(5, clock.snapshot(300)), Some(800));

        clock.set_system_time(300, 50_000).unwrap();
        assert_eq!(timers.remaining_100ns(5, clock.snapshot(400)), Some(700));
    }

    #[test]
    fn active_absolute_timer_tracks_clock_changes_without_clamping_overdue_time() {
        let mut clock = AdjustableClock::try_new(100, 1_000).unwrap();
        let mut timers = TimerTable::new();
        timers
            .set(
                5,
                Deadline::Absolute {
                    system_time_100ns: 2_000,
                },
                clock.snapshot(100),
                0,
                ApcTarget::default(),
            )
            .unwrap();
        assert_eq!(timers.remaining_100ns(5, clock.snapshot(200)), Some(900));

        clock.set_system_time(200, 2_500).unwrap();
        assert_eq!(timers.remaining_100ns(5, clock.snapshot(200)), Some(-500));

        clock.set_system_time(300, 1_000).unwrap();
        assert_eq!(timers.remaining_100ns(5, clock.snapshot(300)), Some(1_000));
    }

    #[test]
    fn remaining_time_uses_native_width_wrapping_subtraction() {
        let mut timers = TimerTable::new();
        timers.ensure(7).unwrap();
        assert_eq!(
            timers.remaining_100ns(7, snapshot(u64::MAX, 1_000)),
            Some(1)
        );
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
                snapshot(0, 1_500),
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
        assert_eq!(timers.remaining_100ns(9, snapshot(500, 90_000)), Some(250));
    }

    #[test]
    fn query_retains_last_due_time_after_cancel_and_one_shot_expiry() {
        let mut timers = TimerTable::new();
        timers
            .set(
                3,
                Deadline::Relative {
                    monotonic_100ns: 500,
                },
                snapshot(200, 2_000),
                0,
                ApcTarget::default(),
            )
            .unwrap();
        assert_eq!(timers.remaining_100ns(3, snapshot(200, 2_000)), Some(300));
        assert!(timers.cancel(3, snapshot(200, 2_000)));
        assert_eq!(timers.next_deadline(snapshot(200, 2_000)), None);
        assert_eq!(timers.remaining_100ns(3, snapshot(300, 2_100)), Some(200));

        timers
            .set(
                3,
                Deadline::Relative {
                    monotonic_100ns: 700,
                },
                snapshot(300, 2_100),
                0,
                ApcTarget::default(),
            )
            .unwrap();
        assert!(timers.expire_next_due(snapshot(800, 2_600)).is_some());
        assert_eq!(timers.next_deadline(snapshot(800, 2_600)), None);
        assert_eq!(timers.remaining_100ns(3, snapshot(800, 2_600)), Some(-100));
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
                snapshot(0, 1_500),
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
                snapshot(0, 1_500),
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
                snapshot(0, 1_500),
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
                snapshot(100, 1_000),
                0,
                ApcTarget::default(),
            )
            .unwrap();
        assert!(timers.cancel(4, snapshot(100, 1_000)));
        assert!(!timers.cancel(4, snapshot(100, 1_000)));
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
                snapshot(100, 1_000),
                0,
                ApcTarget {
                    thread_id: 9,
                    routine: 0x1000,
                    context: 0,
                },
            )
            .unwrap();
        timers
            .set(2, deadline, snapshot(100, 1_000), 0, ApcTarget::default())
            .unwrap();
        timers
            .set(
                3,
                deadline,
                snapshot(100, 1_000),
                0,
                ApcTarget {
                    thread_id: 10,
                    routine: 0x2000,
                    context: 0,
                },
            )
            .unwrap();

        assert_eq!(timers.cancel_apcs_for_thread(9, snapshot(100, 1_000)), 1);
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
                    snapshot(100, 500),
                    0,
                    ApcTarget::default(),
                )
                .unwrap();
        }
        assert_eq!(timers.len(), 128);
        assert_eq!(timers.next_deadline(snapshot(100, 500)), Some(1_000));
    }
}
