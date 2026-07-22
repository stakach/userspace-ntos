//! Host-testable module reference and callout metadata transitions.

pub const LOAD_COUNT_PINNED: u16 = u16::MAX;

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
