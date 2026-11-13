//! Rate-limited observation of an outer receive with no future physical timer shot.
//! This only chooses when to print; it cannot arm a timer or settle retained work.

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootReceiveIdleObservation {
    pub physical_shot_armed: bool,
    pub physical_shot_due: bool,
    pub callback_depth: u64,
    pub continuation_depth: u64,
    pub dispatch_depth: u64,
    pub suspended_components: u64,
}

impl RootReceiveIdleObservation {
    fn needs_evidence(self) -> bool {
        !self.physical_shot_armed || self.physical_shot_due
    }

    fn key(self) -> u64 {
        let mut key = 0xcbf2_9ce4_8422_2325u64;
        for value in [
            u64::from(self.physical_shot_armed),
            u64::from(self.physical_shot_due),
            self.callback_depth,
            self.continuation_depth,
            self.dispatch_depth,
            self.suspended_components,
        ] {
            key = (key ^ value).wrapping_mul(0x100_0000_01b3);
        }
        key
    }
}

pub struct RootReceiveIdleProbe {
    last_key: AtomicU64,
    last_emit_at: AtomicU64,
    transition_prints: AtomicU64,
    periodic_prints: AtomicU64,
    transition_cap: u64,
    periodic_cap: u64,
    periodic_interval_100ns: u64,
}

impl RootReceiveIdleProbe {
    pub const fn new(transition_cap: u64, periodic_cap: u64, periodic_interval_100ns: u64) -> Self {
        Self {
            last_key: AtomicU64::new(0),
            last_emit_at: AtomicU64::new(0),
            transition_prints: AtomicU64::new(0),
            periodic_prints: AtomicU64::new(0),
            transition_cap,
            periodic_cap,
            periodic_interval_100ns,
        }
    }

    /// Reserve a diagnostic record; no owner state or physical clock is changed.
    pub fn observe(&self, state: RootReceiveIdleObservation, now_100ns: u64) -> bool {
        let key = state.key();
        let changed = self.last_key.swap(key, Ordering::Relaxed) != key;
        if !state.needs_evidence() {
            return false;
        }
        if changed && self.transition_prints.try_update(
            Ordering::Relaxed, Ordering::Relaxed,
            |count| (count < self.transition_cap).then_some(count + 1),
        ).is_ok() {
            self.last_emit_at.store(now_100ns, Ordering::Relaxed);
            return true;
        }
        let prior = self.last_emit_at.load(Ordering::Relaxed);
        if now_100ns.saturating_sub(prior) >= self.periodic_interval_100ns
            && self.periodic_prints.try_update(
                Ordering::Relaxed, Ordering::Relaxed,
                |count| (count < self.periodic_cap).then_some(count + 1),
            ).is_ok()
        {
            self.last_emit_at.store(now_100ns, Ordering::Relaxed);
            return true;
        }
        false
    }
}
