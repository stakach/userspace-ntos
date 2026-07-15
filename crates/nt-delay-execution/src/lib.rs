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

pub fn hundred_ns_to_ticks_ceil(value: u64, period_fs: u64) -> u64 {
    if value == 0 || period_fs == 0 {
        return 0;
    }
    let numerator = value as u128 * 100_000_000u128;
    ((numerator + period_fs as u128 - 1) / period_fs as u128).min(u64::MAX as u128) as u64
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
