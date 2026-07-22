//! Host-testable module reference and callout metadata transitions.

pub const LOAD_COUNT_PINNED: u16 = u16::MAX;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReferenceReleasePlan {
    Pinned,
    DecrementTo(u16),
    TeardownRequired,
    Invalid,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ReferenceRelease {
    pub base: u64,
    pub releases: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceReleaseLedger<const N: usize> {
    entries: [ReferenceRelease; N],
    len: usize,
}

impl<const N: usize> ReferenceReleaseLedger<N> {
    pub const fn new() -> Self {
        Self {
            entries: [ReferenceRelease {
                base: 0,
                releases: 0,
            }; N],
            len: 0,
        }
    }

    pub fn record(&mut self, base: u64) -> bool {
        if let Some(entry) = self.entries[..self.len]
            .iter_mut()
            .find(|entry| entry.base == base)
        {
            let Some(next) = entry.releases.checked_add(1) else {
                return false;
            };
            entry.releases = next;
            return true;
        }
        if self.len == N {
            return false;
        }
        self.entries[self.len] = ReferenceRelease { base, releases: 1 };
        self.len += 1;
        true
    }

    pub fn as_slice(&self) -> &[ReferenceRelease] {
        &self.entries[..self.len]
    }
}

impl<const N: usize> Default for ReferenceReleaseLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn plan_reference_release(load_count: u16, releases: u32) -> ReferenceReleasePlan {
    if load_count == LOAD_COUNT_PINNED {
        return ReferenceReleasePlan::Pinned;
    }
    if releases == 0 || load_count == 0 || releases > u32::from(load_count) {
        return ReferenceReleasePlan::Invalid;
    }
    if releases == u32::from(load_count) {
        return ReferenceReleasePlan::TeardownRequired;
    }
    ReferenceReleasePlan::DecrementTo(load_count - releases as u16)
}

/// Persistent successful process-attach order, used in reverse for process shutdown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachLedger<const N: usize> {
    entries: [u64; N],
    len: usize,
}

impl<const N: usize> AttachLedger<N> {
    pub const fn new() -> Self {
        Self {
            entries: [0; N],
            len: 0,
        }
    }

    pub fn record(&mut self, base: u64) -> bool {
        if self.as_slice().contains(&base) {
            return true;
        }
        if self.len == N {
            return false;
        }
        self.entries[self.len] = base;
        self.len += 1;
        true
    }

    pub fn remove(&mut self, base: u64) -> bool {
        let Some(index) = self.as_slice().iter().position(|entry| *entry == base) else {
            return false;
        };
        self.entries.copy_within(index + 1..self.len, index);
        self.len -= 1;
        self.entries[self.len] = 0;
        true
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.entries[..self.len]
    }
}

impl<const N: usize> Default for AttachLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply `LdrAddRefDll` semantics to a loader entry's load count.
pub fn add_reference(load_count: u16, pin: bool) -> u16 {
    if load_count == LOAD_COUNT_PINNED || pin {
        LOAD_COUNT_PINNED
    } else {
        load_count.wrapping_add(1)
    }
}

/// Thread callouts may only be disabled for a module without an allocated TLS slot.
pub fn can_disable_thread_callouts(tls_index: u16) -> bool {
    tls_index == 0
}

/// Report whether the current TEB owns the active top-level loader callout transaction.
pub fn is_thread_within_loader_callout(owner_teb: u64, current_teb: u64) -> bool {
    owner_teb != 0 && owner_teb == current_teb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_references_increment_until_pinned() {
        assert_eq!(add_reference(1, false), 2);
        assert_eq!(add_reference(LOAD_COUNT_PINNED, false), LOAD_COUNT_PINNED);
    }

    #[test]
    fn pin_is_permanent() {
        assert_eq!(add_reference(1, true), LOAD_COUNT_PINNED);
        assert_eq!(add_reference(LOAD_COUNT_PINNED, true), LOAD_COUNT_PINNED);
    }

    #[test]
    fn tls_slot_prevents_disabling_thread_callouts() {
        assert!(can_disable_thread_callouts(0));
        assert!(!can_disable_thread_callouts(1));
    }

    #[test]
    fn loader_callout_state_is_teb_specific() {
        assert!(is_thread_within_loader_callout(0x1000, 0x1000));
        assert!(!is_thread_within_loader_callout(0x1000, 0x2000));
        assert!(!is_thread_within_loader_callout(0, 0));
    }

    #[test]
    fn reference_release_plans_never_publish_a_zero_count() {
        assert_eq!(
            plan_reference_release(LOAD_COUNT_PINNED, 99),
            ReferenceReleasePlan::Pinned
        );
        assert_eq!(
            plan_reference_release(3, 1),
            ReferenceReleasePlan::DecrementTo(2)
        );
        assert_eq!(
            plan_reference_release(3, 2),
            ReferenceReleasePlan::DecrementTo(1)
        );
        assert_eq!(
            plan_reference_release(1, 1),
            ReferenceReleasePlan::TeardownRequired
        );
        assert_eq!(
            plan_reference_release(2, 2),
            ReferenceReleasePlan::TeardownRequired
        );
        assert_eq!(plan_reference_release(0, 1), ReferenceReleasePlan::Invalid);
        assert_eq!(plan_reference_release(1, 0), ReferenceReleasePlan::Invalid);
        assert_eq!(plan_reference_release(1, 2), ReferenceReleasePlan::Invalid);
    }

    #[test]
    fn release_ledger_preserves_import_edge_multiplicity() {
        let mut ledger = ReferenceReleaseLedger::<3>::new();
        assert!(ledger.record(10));
        assert!(ledger.record(20));
        assert!(ledger.record(10));
        assert_eq!(
            ledger.as_slice(),
            &[
                ReferenceRelease {
                    base: 10,
                    releases: 2
                },
                ReferenceRelease {
                    base: 20,
                    releases: 1
                }
            ]
        );
        assert!(ledger.record(30));
        assert!(!ledger.record(40));
    }

    #[test]
    fn attach_ledger_preserves_success_order_and_deduplicates() {
        let mut ledger = AttachLedger::<3>::new();
        assert!(ledger.record(10));
        assert!(ledger.record(20));
        assert!(ledger.record(10));
        assert_eq!(ledger.as_slice(), &[10, 20]);
        assert!(ledger.record(30));
        assert!(!ledger.record(40));
    }

    #[test]
    fn attach_ledger_removes_rolled_back_modules() {
        let mut ledger = AttachLedger::<4>::new();
        ledger.record(10);
        ledger.record(20);
        ledger.record(30);
        assert!(ledger.remove(20));
        assert_eq!(ledger.as_slice(), &[10, 30]);
        assert!(!ledger.remove(40));
    }
}
