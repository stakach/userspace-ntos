//! Exclusion for timer scans that can encounter nested notification delivery through IPC.

use core::sync::atomic::{AtomicBool, Ordering};

pub struct TimerDeliveryGate {
    active: AtomicBool,
}

impl TimerDeliveryGate {
    pub const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
        }
    }

    /// Claim before borrowing dispatcher state or taking pending notifications. Refusal changes
    /// neither the current owner nor notification demand; callers must leave that demand pending.
    pub fn try_enter(&self) -> Option<TimerDeliveryGuard<'_>> {
        self.active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| TimerDeliveryGuard { gate: self })
    }
}

impl Default for TimerDeliveryGate {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use = "keep the guard alive until dispatcher borrows and timer effects have ended"]
pub struct TimerDeliveryGuard<'a> {
    gate: &'a TimerDeliveryGate,
}

impl Drop for TimerDeliveryGuard<'_> {
    fn drop(&mut self) {
        self.gate.active.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU64;

    #[test]
    fn refusal_preserves_coalesced_notifications_for_the_next_owner() {
        let gate = TimerDeliveryGate::new();
        let pending = AtomicU64::new(3);
        let outer = gate.try_enter().unwrap();
        assert_eq!(pending.swap(0, Ordering::Relaxed), 3);
        pending.fetch_add(2, Ordering::Relaxed);
        for _ in 0..4 {
            assert!(gate.try_enter().is_none());
            assert_eq!(pending.load(Ordering::Relaxed), 2);
        }
        drop(outer);
        let _next = gate.try_enter().unwrap();
        assert_eq!(pending.swap(0, Ordering::Relaxed), 2);
        assert!(gate.try_enter().is_none());
    }

    #[test]
    fn early_return_releases_owner() {
        fn empty_scan(gate: &TimerDeliveryGate) {
            let _guard = gate.try_enter().unwrap();
        }
        let gate = TimerDeliveryGate::new();
        empty_scan(&gate);
        let _guard = gate.try_enter().unwrap();
        assert!(gate.try_enter().is_none());
    }

    #[test]
    fn independent_gates_do_not_share_delivery_authority() {
        let first = TimerDeliveryGate::new();
        let second = TimerDeliveryGate::new();
        let _one = first.try_enter().unwrap();
        let _two = second.try_enter().unwrap();
        assert!(first.try_enter().is_none());
        assert!(second.try_enter().is_none());
    }
}
