//! Name a polling site that keeps yielding without making progress.
//!
//! A yield loop waits for some other thread to run. When that thread can never run (it is
//! blocked on the very thread that is polling), the poller spins forever and nothing in the
//! log says where. One watch per executor counts consecutive yields from one site and reports
//! that site at exponentially spaced counts once the run is long enough to be a livelock.

/// Consecutive yields from one site before the site is reported.
pub const REPORT_AFTER: u64 = 1 << 16;

#[derive(Debug)]
pub struct SpinWatch {
    site: usize,
    yields: u64,
}

impl SpinWatch {
    pub const fn new() -> Self {
        Self { site: 0, yields: 0 }
    }

    /// Record one yield at `site`, an opaque nonzero site identity. Returns the consecutive
    /// count when it should be reported: at `REPORT_AFTER` and every power of two after it.
    pub fn observe(&mut self, site: usize) -> Option<u64> {
        if self.site != site {
            self.site = site;
            self.yields = 0;
        }
        self.yields = self.yields.saturating_add(1);
        (self.yields >= REPORT_AFTER && self.yields.is_power_of_two()).then_some(self.yields)
    }
}

impl Default for SpinWatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn a_short_contended_wait_is_never_reported() {
        let mut watch = SpinWatch::new();
        for _ in 0..REPORT_AFTER - 1 {
            assert_eq!(watch.observe(1), None);
        }
    }

    #[test]
    fn a_long_spin_at_one_site_is_reported_at_spaced_counts() {
        let mut watch = SpinWatch::new();
        let reports: Vec<u64> = (0..REPORT_AFTER * 4).filter_map(|_| watch.observe(7)).collect();
        assert_eq!(reports, [REPORT_AFTER, REPORT_AFTER * 2, REPORT_AFTER * 4]);
    }

    #[test]
    fn progress_through_another_site_restarts_the_count() {
        let mut watch = SpinWatch::new();
        for _ in 0..REPORT_AFTER - 1 {
            watch.observe(1);
        }
        assert_eq!(watch.observe(2), None);
        for _ in 0..REPORT_AFTER - 2 {
            assert_eq!(watch.observe(1), None);
        }
    }
}
