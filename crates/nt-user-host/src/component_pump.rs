//! Cumulative component-pump diagnostics and dispatch-depth bookkeeping across receive slices.
//! Copies are observational snapshots, never independent execution or endpoint authority.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PumpDepthDisposition {
    None,
    Retained,
    Suspended,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentPumpAccounting {
    faults: u64,
    demand: u64,
    assert_skips: u64,
    owns_depth: bool,
}

impl ComponentPumpAccounting {
    pub const fn new(owns_depth: bool) -> Self {
        Self {
            faults: 0,
            demand: 0,
            assert_skips: 0,
            owns_depth,
        }
    }

    pub const fn faults(self) -> u64 {
        self.faults
    }

    pub const fn demand(self) -> u64 {
        self.demand
    }

    pub const fn assert_skips(self) -> u64 {
        self.assert_skips
    }

    pub const fn owns_depth(self) -> bool {
        self.owns_depth
    }

    pub fn record_fault(&mut self) {
        self.faults = self.faults.saturating_add(1);
    }

    pub fn record_demand(&mut self) {
        self.demand = self.demand.saturating_add(1);
    }

    pub fn record_assert_skip(&mut self) {
        self.assert_skips = self.assert_skips.saturating_add(1);
    }

    /// A scheduler yield is not dispatch completion or component suspension. Carry this exact
    /// snapshot to the next receive slice; only the active owner applies the returned effect.
    /// Final suspension transfers depth to its retained continuation; other final exits release it.
    pub fn after_slice(
        &mut self,
        scheduler_yielded: bool,
        component_suspended: bool,
    ) -> PumpDepthDisposition {
        if !self.owns_depth {
            return PumpDepthDisposition::None;
        }
        if scheduler_yielded {
            return PumpDepthDisposition::Retained;
        }
        self.owns_depth = false;
        if component_suspended {
            PumpDepthDisposition::Suspended
        } else {
            PumpDepthDisposition::Released
        }
    }
}

#[cfg(test)]
#[path = "component_pump_tests.rs"]
mod tests;
