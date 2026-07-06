//! Isolated-driver health + restart policy.
//!
//! Every driver runs in its own process (its own seL4 VSpace). When one crashes,
//! the driver-host ("NT kernel") consults this policy: restart it (with exponential
//! backoff) or, if it keeps crashing without ever staying up, DISABLE it so it stops
//! taking resources and a human/userspace tool can investigate. "Stayed up" means the
//! driver reached a healthy checkpoint (it initialized + served work) before dying;
//! a crash before that checkpoint is a *rapid* crash and counts toward the crash-loop
//! threshold. A healthy checkpoint resets the rapid-crash streak, so a driver that
//! stabilizes and later hits a transient fault is treated leniently, not disabled.
//!
//! Pure `no_std` logic, unit-tested on the host; the seL4 side supplies the events.

#![no_std]

/// Tunables for the restart policy.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Consecutive rapid crashes before the driver is disabled.
    pub max_rapid_crashes: u32,
    /// Base backoff (abstract ticks) before the first restart.
    pub base_backoff: u64,
    /// Backoff ceiling (exponential growth is clamped here).
    pub max_backoff: u64,
}

impl Policy {
    pub const fn default_policy() -> Self {
        Self {
            max_rapid_crashes: 3,
            base_backoff: 10,
            max_backoff: 10_000,
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::default_policy()
    }
}

/// Per-driver health state (persist this alongside the driver's registry entry).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriverHealth {
    /// Rapid crashes since the last healthy checkpoint (drives backoff + disable).
    pub consecutive_rapid_crashes: u32,
    /// Lifetime crash count (persisted so userspace sees a flapping driver).
    pub total_crashes: u32,
    /// How many times we've restarted it.
    pub restarts: u32,
    /// Set once the crash-loop threshold trips; the driver won't be restarted again.
    pub disabled: bool,
}

/// What the supervisor should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Restart after waiting `backoff` ticks (exponential, clamped to `max_backoff`).
    Restart { backoff: u64 },
    /// Give up: the driver is a crash loop. Stop restarting; record the disable.
    Disable,
    /// The driver stayed up (reached a healthy checkpoint) — nothing to do.
    Recovered,
}

impl DriverHealth {
    /// The driver crashed *before* reaching a healthy checkpoint (a rapid/startup
    /// crash). Escalate: restart with exponential backoff until the threshold, then
    /// disable.
    pub fn on_rapid_crash(&mut self, p: &Policy) -> Action {
        self.total_crashes += 1;
        self.consecutive_rapid_crashes += 1;
        if self.consecutive_rapid_crashes >= p.max_rapid_crashes {
            self.disabled = true;
            Action::Disable
        } else {
            self.restarts += 1;
            // Exponential: base << (n-1), clamped. `checked_shl` guards huge shifts.
            let backoff = p
                .base_backoff
                .checked_shl(self.consecutive_rapid_crashes - 1)
                .unwrap_or(u64::MAX)
                .min(p.max_backoff);
            Action::Restart { backoff }
        }
    }

    /// The driver reached a healthy checkpoint (it stayed up). Reset the rapid-crash
    /// streak — a subsequent fault starts a fresh count, not an escalation.
    pub fn on_healthy(&mut self) -> Action {
        self.consecutive_rapid_crashes = 0;
        Action::Recovered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_backoff_then_disable() {
        let p = Policy::default_policy(); // max_rapid=3, base=10
        let mut h = DriverHealth::default();
        // First rapid crash → restart, backoff = 10 << 0 = 10.
        assert_eq!(h.on_rapid_crash(&p), Action::Restart { backoff: 10 });
        // Second → restart, backoff = 10 << 1 = 20.
        assert_eq!(h.on_rapid_crash(&p), Action::Restart { backoff: 20 });
        // Third → threshold reached → disable.
        assert_eq!(h.on_rapid_crash(&p), Action::Disable);
        assert!(h.disabled);
        assert_eq!(h.total_crashes, 3);
        assert_eq!(h.restarts, 2);
    }

    #[test]
    fn healthy_checkpoint_resets_the_streak() {
        let p = Policy::default_policy();
        let mut h = DriverHealth::default();
        h.on_rapid_crash(&p); // streak = 1
        h.on_rapid_crash(&p); // streak = 2
        assert_eq!(h.on_healthy(), Action::Recovered);
        assert_eq!(h.consecutive_rapid_crashes, 0);
        // A later crash starts fresh — not immediately disabled.
        assert_eq!(h.on_rapid_crash(&p), Action::Restart { backoff: 10 });
        assert!(!h.disabled);
        assert_eq!(h.total_crashes, 3); // lifetime count still accumulates
    }

    #[test]
    fn recover_after_one_restart() {
        let p = Policy::default_policy();
        let mut h = DriverHealth::default();
        assert_eq!(h.on_rapid_crash(&p), Action::Restart { backoff: 10 });
        assert_eq!(h.on_healthy(), Action::Recovered);
        assert!(!h.disabled);
        assert_eq!(h.restarts, 1);
    }

    #[test]
    fn backoff_is_clamped() {
        let p = Policy {
            max_rapid_crashes: 100,
            base_backoff: 10,
            max_backoff: 50,
        };
        let mut h = DriverHealth::default();
        assert_eq!(h.on_rapid_crash(&p), Action::Restart { backoff: 10 });
        assert_eq!(h.on_rapid_crash(&p), Action::Restart { backoff: 20 });
        assert_eq!(h.on_rapid_crash(&p), Action::Restart { backoff: 40 });
        assert_eq!(h.on_rapid_crash(&p), Action::Restart { backoff: 50 }); // clamped
        assert_eq!(h.on_rapid_crash(&p), Action::Restart { backoff: 50 });
    }
}
