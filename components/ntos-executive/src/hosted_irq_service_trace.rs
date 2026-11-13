//! Cumulative serviced-IRQ census and bounded claimed-delivery diagnostics.

use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct HostedIrqServiceTrace {
    total: AtomicU64,
}

impl HostedIrqServiceTrace {
    pub(crate) const fn new() -> Self { Self { total: AtomicU64::new(0) } }

    /// Count every serviced event; print claim detail only for the first sixteen overall.
    pub(crate) fn record(&self, claimed: u64) -> bool {
        let total = self.total.fetch_add(1, Ordering::Relaxed) + 1;
        claimed != 0 && total <= 16
    }

    pub(crate) fn total(&self) -> u64 { self.total.load(Ordering::Relaxed) }
}
