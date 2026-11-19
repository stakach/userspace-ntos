//! Bounded per-badge syscall attribution: which SSNs a hot endpoint badge is issuing.
//!
//! Both levels use the space-saving heavy-hitter rule: a full table replaces its smallest row and
//! the newcomer inherits that row's count (recorded as `error`), so every badge or SSN issuing
//! more than 1/N of the traffic is guaranteed to be retained. Diagnostic only, allocation-free.

pub const BADGE_SSN_BADGES: usize = 16;
pub const BADGE_SSN_SSNS: usize = 12;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SsnCount {
    pub ssn: u32,
    pub calls: u64,
    pub ticks: u64,
    /// Calls inherited from an evicted SSN (an upper bound on over-attribution).
    pub error: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BadgeRow {
    pub badge: u64,
    pub calls: u64,
    pub ticks: u64,
    pub error: u64,
    pub ssns: [SsnCount; BADGE_SSN_SSNS],
    used: usize,
}

impl BadgeRow {
    fn ssn_mut(&mut self, ssn: u32) -> &mut SsnCount {
        if let Some(index) = self.ssns[..self.used].iter().position(|entry| entry.ssn == ssn) {
            return &mut self.ssns[index];
        }
        if self.used < BADGE_SSN_SSNS {
            self.ssns[self.used] = SsnCount { ssn, ..SsnCount::default() };
            self.used += 1;
            return &mut self.ssns[self.used - 1];
        }
        let index = (0..BADGE_SSN_SSNS).min_by_key(|&index| self.ssns[index].calls).unwrap();
        let inherited = self.ssns[index].calls;
        self.ssns[index] = SsnCount { ssn, calls: inherited, ticks: 0, error: inherited };
        &mut self.ssns[index]
    }

    /// The retained SSNs, most calls first.
    pub fn top_ssns(&self) -> impl Iterator<Item = SsnCount> + '_ {
        let mut order = [0usize; BADGE_SSN_SSNS];
        for (slot, index) in order.iter_mut().zip(0..) {
            *slot = index;
        }
        let used = self.used;
        order[..used].sort_unstable_by(|&a, &b| self.ssns[b].calls.cmp(&self.ssns[a].calls));
        (0..used).map(move |position| self.ssns[order[position]])
    }
}

pub struct BadgeSsnCensus {
    rows: [BadgeRow; BADGE_SSN_BADGES],
    used: usize,
}

impl BadgeSsnCensus {
    pub const fn new() -> Self {
        const EMPTY: BadgeRow = BadgeRow {
            badge: 0, calls: 0, ticks: 0, error: 0,
            ssns: [SsnCount { ssn: 0, calls: 0, ticks: 0, error: 0 }; BADGE_SSN_SSNS],
            used: 0,
        };
        Self { rows: [EMPTY; BADGE_SSN_BADGES], used: 0 }
    }

    fn row_mut(&mut self, badge: u64) -> &mut BadgeRow {
        if let Some(index) = self.rows[..self.used].iter().position(|row| row.badge == badge) {
            return &mut self.rows[index];
        }
        let index = if self.used < BADGE_SSN_BADGES {
            self.used += 1;
            self.used - 1
        } else {
            (0..BADGE_SSN_BADGES).min_by_key(|&index| self.rows[index].calls).unwrap()
        };
        let inherited = if index + 1 == self.used && self.rows[index].badge == 0
            && self.rows[index].calls == 0 { 0 } else { self.rows[index].calls };
        self.rows[index] = BadgeRow { badge, calls: inherited, error: inherited, ..BadgeRow::default() };
        &mut self.rows[index]
    }

    /// One syscall issued by `badge`.
    pub fn record_call(&mut self, badge: u64, ssn: u32) {
        let row = self.row_mut(badge);
        row.calls += 1;
        row.ssn_mut(ssn).calls += 1;
    }

    /// Executive time spent dispatching a call already counted by `record_call`.
    pub fn record_ticks(&mut self, badge: u64, ssn: u32, ticks: u64) {
        if let Some(row) = self.rows[..self.used].iter_mut().find(|row| row.badge == badge) {
            row.ticks += ticks;
            if let Some(entry) = row.ssns[..row.used].iter_mut().find(|entry| entry.ssn == ssn) {
                entry.ticks += ticks;
            }
        }
    }

    /// The retained badges, most calls first.
    pub fn top_badges(&self) -> impl Iterator<Item = &BadgeRow> + '_ {
        let mut order = [0usize; BADGE_SSN_BADGES];
        for (slot, index) in order.iter_mut().zip(0..) {
            *slot = index;
        }
        let used = self.used;
        order[..used].sort_unstable_by(|&a, &b| self.rows[b].calls.cmp(&self.rows[a].calls));
        (0..used).map(move |position| &self.rows[order[position]])
    }
}

impl Default for BadgeSsnCensus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    /// Boot 44549328390: one badge took ~92% of root time while the executive-wide histogram
    /// could not say which syscalls that badge issued.
    #[test]
    fn a_hot_badge_names_its_own_hot_ssns() {
        let mut census = BadgeSsnCensus::new();
        for _ in 0..370 {
            census.record_call(44, 0x118);
            census.record_ticks(44, 0x118, 81_000);
        }
        for _ in 0..20 {
            census.record_call(44, 0x7d);
        }
        for _ in 0..5 {
            census.record_call(30, 0x118);
        }
        let top: Vec<_> = census.top_badges().collect();
        assert_eq!(top[0].badge, 44);
        assert_eq!(top[0].calls, 390);
        assert_eq!(top[0].ticks, 370 * 81_000);
        let ssns: Vec<_> = top[0].top_ssns().collect();
        assert_eq!((ssns[0].ssn, ssns[0].calls, ssns[0].ticks, ssns[0].error), (0x118, 370, 370 * 81_000, 0));
        assert_eq!((ssns[1].ssn, ssns[1].calls), (0x7d, 20));
        assert_eq!((top[1].badge, top[1].calls), (30, 5));
    }

    #[test]
    fn heavy_hitters_survive_a_flood_of_rare_badges_and_ssns() {
        let mut census = BadgeSsnCensus::new();
        for round in 0..1000u64 {
            census.record_call(44, 0x118);
            census.record_call(1000 + round, 0x1b);
            census.record_call(44, 0x1000 + (round % 97) as u32);
        }
        let top: Vec<_> = census.top_badges().collect();
        assert_eq!(top[0].badge, 44);
        assert_eq!(top[0].calls, 2000);
        let first = top[0].top_ssns().next().unwrap();
        assert_eq!((first.ssn, first.calls), (0x118, 1000));
        assert!(census.top_badges().count() <= BADGE_SSN_BADGES);
    }
}
