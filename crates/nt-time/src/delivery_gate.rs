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

    /// Advisory suppression for nested scheduler yields, not a replacement for try_enter.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
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

/// A subset consumer's observation of a still-pending notification counter. The complete timer
/// owner retains the counter; this marker must be discarded when that ownership phase ends.
pub struct DeferredTimerProgress {
    observed: u64,
}

impl DeferredTimerProgress {
    pub const fn new() -> Self {
        Self { observed: 0 }
    }

    pub fn needs_scan(&self, pending: u64) -> bool {
        pending != 0 && pending != self.observed
    }

    /// Record the count sampled BEFORE a guarded scan, never a fresh count after IPC. A delivery
    /// arriving during the scan must remain distinguishable at the next receive barrier.
    pub fn record_scan(&mut self, sampled_pending: u64) {
        self.observed = sampled_pending;
    }
}

impl Default for DeferredTimerProgress {
    fn default() -> Self {
        Self::new()
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
    fn subset_scan_retains_new_deliveries_without_consuming_shared_count() {
        let pending = AtomicU64::new(2);
        let mut progress = DeferredTimerProgress::new();
        let sampled = pending.load(Ordering::Relaxed);
        assert!(progress.needs_scan(sampled));
        pending.fetch_add(1, Ordering::Relaxed);
        progress.record_scan(sampled);
        assert_eq!(pending.load(Ordering::Relaxed), 3);
        assert!(progress.needs_scan(3));
        progress.record_scan(3);
        assert!(!progress.needs_scan(3));
        assert!(!progress.needs_scan(0));
        // A new phase gets a fresh marker even if its first counter value is the same.
        assert!(DeferredTimerProgress::new().needs_scan(3));
    }

    #[test]
    fn active_delivery_suppresses_nested_yields_without_acknowledging_progress() {
        let gate = TimerDeliveryGate::new();
        let progress = DeferredTimerProgress::new();
        let outer = gate.try_enter().unwrap();
        assert!(gate.is_active());
        assert!(progress.needs_scan(1));
        assert!(gate.try_enter().is_none());
        drop(outer);
        assert!(!gate.is_active());
        assert!(progress.needs_scan(1));
    }

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
