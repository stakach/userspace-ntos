#![no_std]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Due {
    Immediate,
    Monotonic100ns(u64),
}

pub fn due_time(interval: i64, monotonic_now: u64, system_now: u64) -> Due {
    if interval == 0 {
        return Due::Immediate;
    }
    if interval < 0 {
        let delta = interval.unsigned_abs();
        return Due::Monotonic100ns(monotonic_now.saturating_add(delta));
    }
    let absolute = interval as u64;
    if absolute <= system_now {
        Due::Immediate
    } else {
        Due::Monotonic100ns(monotonic_now.saturating_add(absolute - system_now))
    }
}

pub fn ticks_to_100ns(ticks: u64, period_fs: u64) -> u64 {
    ((ticks as u128 * period_fs as u128) / 100_000_000u128).min(u64::MAX as u128) as u64
}

pub fn counter_epoch_offset(epoch_now_100ns: u64, counter_now_100ns: u64) -> i64 {
    let delta = epoch_now_100ns as i128 - counter_now_100ns as i128;
    if delta > i64::MAX as i128 {
        i64::MAX
    } else if delta < i64::MIN as i128 {
        i64::MIN
    } else {
        delta as i64
    }
}

pub fn epoch_time_from_counter(counter_now_100ns: u64, offset_100ns: i64) -> u64 {
    if offset_100ns >= 0 {
        counter_now_100ns.saturating_add(offset_100ns as u64)
    } else {
        counter_now_100ns.saturating_sub(offset_100ns.unsigned_abs())
    }
}

pub fn counter_time_from_epoch(epoch_time_100ns: u64, offset_100ns: i64) -> u64 {
    if offset_100ns >= 0 {
        epoch_time_100ns.saturating_sub(offset_100ns as u64)
    } else {
        epoch_time_100ns.saturating_add(offset_100ns.unsigned_abs())
    }
}

pub fn hundred_ns_to_ticks_ceil(value: u64, period_fs: u64) -> u64 {
    if value == 0 || period_fs == 0 {
        return 0;
    }
    let numerator = value as u128 * 100_000_000u128;
    ((numerator + period_fs as u128 - 1) / period_fs as u128).min(u64::MAX as u128) as u64
}

pub fn timer_arm_target_ticks(
    deadline_100ns: u64,
    period_fs: u64,
    now_ticks: u64,
    min_delta_ticks: u64,
) -> u64 {
    let deadline_ticks = hundred_ns_to_ticks_ceil(deadline_100ns, period_fs);
    deadline_ticks.max(now_ticks.saturating_add(min_delta_ticks.max(1)))
}

pub fn timer_min_delta_ticks(min_delta_100ns: u64, period_fs: u64, floor_ticks: u64) -> u64 {
    hundred_ns_to_ticks_ceil(min_delta_100ns, period_fs)
        .max(floor_ticks)
        .max(1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Waiter {
    pub deadline_100ns: u64,
    pub sequence: u64,
    pub reply_cap: u64,
    pub resume_ip: u64,
    pub resume_sp: u64,
    pub resume_flags: u64,
    pub thread_id: u64,
    pub badge: u64,
}

pub struct Queue<const N: usize> {
    slots: [Option<Waiter>; N],
    next_sequence: u64,
}

impl<const N: usize> Queue<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            next_sequence: 0,
        }
    }

    pub fn insert(&mut self, mut waiter: Waiter) -> Result<(), Waiter> {
        let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_none()) else {
            return Err(waiter);
        };
        waiter.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        *slot = Some(waiter);
        Ok(())
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .map(|waiter| waiter.deadline_100ns)
            .min()
    }

    pub fn pop_due(&mut self, now_100ns: u64) -> Option<Waiter> {
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, waiter)| waiter.map(|waiter| (index, waiter)))
            .filter(|(_, waiter)| waiter.deadline_100ns <= now_100ns)
            .min_by_key(|(_, waiter)| (waiter.deadline_100ns, waiter.sequence))
            .map(|(index, _)| index)?;
        self.slots[index].take()
    }

    pub fn pop_thread(&mut self, thread_id: u64) -> Option<Waiter> {
        let index = self.slots.iter().position(|slot| {
            slot.map(|waiter| waiter.thread_id == thread_id)
                .unwrap_or(false)
        })?;
        self.slots[index].take()
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub fn has_badge_other_than(&self, badge: u64) -> bool {
        self.slots
            .iter()
            .flatten()
            .any(|waiter| waiter.badge != badge)
    }
}

impl<const N: usize> Default for Queue<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiter(deadline: u64, thread_id: u64) -> Waiter {
        Waiter {
            deadline_100ns: deadline,
            sequence: 99,
            reply_cap: thread_id + 100,
            resume_ip: 1,
            resume_sp: 2,
            resume_flags: 3,
            thread_id,
            badge: thread_id + 10,
        }
    }

    #[test]
    fn zero_and_past_absolute_are_immediate() {
        assert_eq!(due_time(0, 10, 100), Due::Immediate);
        assert_eq!(due_time(99, 10, 100), Due::Immediate);
        assert_eq!(due_time(100, 10, 100), Due::Immediate);
    }

    #[test]
    fn relative_and_future_absolute_use_monotonic_deadlines() {
        assert_eq!(due_time(-25, 10, 100), Due::Monotonic100ns(35));
        assert_eq!(due_time(125, 10, 100), Due::Monotonic100ns(35));
        assert_eq!(
            due_time(i64::MIN, 1, 100),
            Due::Monotonic100ns(1 + (1u64 << 63))
        );
    }

    #[test]
    fn hpet_conversion_rounds_deadlines_up() {
        let period_fs = 10_000_000;
        assert_eq!(ticks_to_100ns(10, period_fs), 1);
        assert_eq!(hundred_ns_to_ticks_ceil(1, period_fs), 10);
        assert_eq!(hundred_ns_to_ticks_ceil(2, period_fs), 20);
    }

    #[test]
    fn counter_epoch_offset_preserves_preexisting_epoch() {
        let offset = counter_epoch_offset(5_000, 4_250);
        assert_eq!(offset, 750);
        assert_eq!(epoch_time_from_counter(4_250, offset), 5_000);
        assert_eq!(counter_time_from_epoch(5_000, offset), 4_250);
    }

    #[test]
    fn counter_epoch_offset_can_shift_running_counter_back() {
        let offset = counter_epoch_offset(2_000, 3_250);
        assert_eq!(offset, -1_250);
        assert_eq!(epoch_time_from_counter(3_250, offset), 2_000);
        assert_eq!(counter_time_from_epoch(2_000, offset), 3_250);
    }

    #[test]
    fn counter_epoch_conversion_saturates_at_bounds() {
        assert_eq!(epoch_time_from_counter(u64::MAX - 1, 8), u64::MAX);
        assert_eq!(epoch_time_from_counter(4, -8), 0);
        assert_eq!(counter_time_from_epoch(4, 8), 0);
        assert_eq!(counter_time_from_epoch(u64::MAX - 1, -8), u64::MAX);
    }

    #[test]
    fn timer_arm_target_keeps_comparator_in_the_future() {
        let period_fs = 10_000_000;
        assert_eq!(timer_arm_target_ticks(200, period_fs, 1000, 32), 2000);
        assert_eq!(timer_arm_target_ticks(101, period_fs, 1000, 32), 1032);
        assert_eq!(timer_arm_target_ticks(90, period_fs, 1000, 32), 1032);
        assert_eq!(
            timer_arm_target_ticks(90, period_fs, u64::MAX - 5, 32),
            u64::MAX
        );
        assert_eq!(timer_arm_target_ticks(90, period_fs, 1000, 0), 1001);
    }

    #[test]
    fn timer_min_delta_uses_time_guard_with_tick_floor() {
        let period_fs = 10_000_000;
        assert_eq!(timer_min_delta_ticks(10_000, period_fs, 4096), 100_000);
        assert_eq!(timer_min_delta_ticks(1, period_fs, 4096), 4096);
        assert_eq!(timer_min_delta_ticks(0, period_fs, 0), 1);
    }

    #[test]
    fn queue_returns_due_waiters_in_deadline_then_fifo_order() {
        let mut queue = Queue::<4>::new();
        queue.insert(waiter(20, 1)).unwrap();
        queue.insert(waiter(10, 2)).unwrap();
        queue.insert(waiter(10, 3)).unwrap();
        assert_eq!(queue.next_deadline(), Some(10));
        assert_eq!(queue.pop_due(9), None);
        assert_eq!(queue.pop_due(10).unwrap().thread_id, 2);
        assert_eq!(queue.pop_due(10).unwrap().thread_id, 3);
        assert_eq!(queue.pop_due(20).unwrap().thread_id, 1);
    }

    #[test]
    fn queue_is_bounded_and_cancels_terminated_threads() {
        let mut queue = Queue::<3>::new();
        queue.insert(waiter(10, 1)).unwrap();
        queue.insert(waiter(20, 1)).unwrap();
        queue.insert(waiter(30, 2)).unwrap();
        assert!(queue.insert(waiter(40, 3)).is_err());
        assert_eq!(queue.pop_thread(1).unwrap().thread_id, 1);
        assert_eq!(queue.pop_thread(1).unwrap().thread_id, 1);
        assert_eq!(queue.pop_thread(1), None);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop_due(30).unwrap().thread_id, 2);
    }
}
