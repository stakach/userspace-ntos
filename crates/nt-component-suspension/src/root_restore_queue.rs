//! Retained nested parents whose restore was refused and whose caller cannot own a retry
//! (#333). The root owns them: before it admits new work it retries each one whose refusal is
//! proven free of native effects. An uncertain refusal stays fenced with every resource held
//! and is never replayed.

/// A root-queued parent as the drain observes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuedRestoreState {
    /// A preflight refusal with no native effect: the exact row may be restored again.
    NoEffectRefusal,
    /// Native entry or identity is uncertain. Every resource is held; it is never retried.
    Quarantined,
    /// The row is inside a restore attempt or held by another owner; leave it alone.
    Busy,
}

/// What one drain did with the queued parents.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RootRestoreDrain {
    pub restored: u32,
    /// Retried and refused again; a no-effect refusal remains queued for the next drain.
    pub refused: u32,
    pub quarantined: u32,
    pub busy: u32,
}

impl RootRestoreDrain {
    /// Whether every queued parent is either restored or fenced: nothing is left to retry.
    pub const fn settled(&self) -> bool { self.refused == 0 && self.busy == 0 }
}

/// Retry each queued no-effect refusal once, in queue order. `restore` performs the exact
/// row's staged restore and reports whether it completed.
pub fn drain_root_restores<K: Copy>(
    queued: impl IntoIterator<Item = K>,
    state: impl Fn(K) -> QueuedRestoreState,
    mut restore: impl FnMut(K) -> bool,
) -> RootRestoreDrain {
    let mut drain = RootRestoreDrain::default();
    for key in queued {
        match state(key) {
            QueuedRestoreState::NoEffectRefusal => {
                if restore(key) { drain.restored += 1 } else { drain.refused += 1 }
            }
            QueuedRestoreState::Quarantined => drain.quarantined += 1,
            QueuedRestoreState::Busy => drain.busy += 1,
        }
    }
    drain
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    extern crate alloc;
    use alloc::vec::Vec;

    #[test]
    fn only_no_effect_refusals_are_retried() {
        let attempts = RefCell::new(Vec::new());
        let drain = drain_root_restores(
            [1u32, 2, 3, 4],
            |key| match key {
                1 | 4 => QueuedRestoreState::NoEffectRefusal,
                2 => QueuedRestoreState::Quarantined,
                _ => QueuedRestoreState::Busy,
            },
            |key| { attempts.borrow_mut().push(key); key == 1 },
        );
        assert_eq!(*attempts.borrow(), [1, 4], "a quarantined or busy row is never entered");
        assert_eq!(drain, RootRestoreDrain { restored: 1, refused: 1, quarantined: 1, busy: 1 });
        assert!(!drain.settled());
    }

    #[test]
    fn a_drain_of_restored_and_fenced_rows_is_settled() {
        let drain = drain_root_restores(
            [7u32, 8],
            |key| if key == 7 { QueuedRestoreState::NoEffectRefusal } else { QueuedRestoreState::Quarantined },
            |_| true,
        );
        assert_eq!(drain, RootRestoreDrain { restored: 1, quarantined: 1, ..Default::default() });
        assert!(drain.settled());
    }

    #[test]
    fn an_uncertain_refusal_is_never_replayed_across_drains() {
        let mut entered = 0;
        for _ in 0..3 {
            let _ = drain_root_restores([5u32], |_| QueuedRestoreState::Quarantined, |_| { entered += 1; true });
        }
        assert_eq!(entered, 0);
    }
}
