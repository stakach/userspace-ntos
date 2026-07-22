//! Host-testable module reference and callout metadata transitions.

pub const LOAD_COUNT_PINNED: u16 = u16::MAX;

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
}
