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
enum AccountingPhase {
    Active { owns_depth: bool },
    Suspended { transferred_depth: bool },
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentPumpAccounting {
    faults: u64,
    demand: u64,
    assert_skips: u64,
    phase: AccountingPhase,
}

impl ComponentPumpAccounting {
    pub const fn new(owns_depth: bool) -> Self {
        Self {
            faults: 0,
            demand: 0,
            assert_skips: 0,
            phase: AccountingPhase::Active { owns_depth },
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
        matches!(self.phase, AccountingPhase::Active { owns_depth: true })
    }

    /// Carry diagnostics into a genuine resumed suspension. The returned flag says whether
    /// its suspended-depth diagnostic must be consumed; an uncounted bootstrap wait returns
    /// Some(false). Snapshot metadata is not execution authority: the caller must own a unique
    /// resume claim before applying this transition or its diagnostic effect.
    pub fn resume_suspended(&mut self) -> Option<bool> {
        let AccountingPhase::Suspended { transferred_depth } = self.phase else {
            return None;
        };
        self.phase = AccountingPhase::Active {
            owns_depth: transferred_depth,
        };
        Some(transferred_depth)
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
        let AccountingPhase::Active { owns_depth } = self.phase else {
            return PumpDepthDisposition::None;
        };
        if scheduler_yielded {
            return if owns_depth {
                PumpDepthDisposition::Retained
            } else {
                PumpDepthDisposition::None
            };
        }
        if component_suspended {
            self.phase = AccountingPhase::Suspended {
                transferred_depth: owns_depth,
            };
            if owns_depth {
                PumpDepthDisposition::Suspended
            } else {
                PumpDepthDisposition::None
            }
        } else {
            self.phase = AccountingPhase::Finished;
            if owns_depth {
                PumpDepthDisposition::Released
            } else {
                PumpDepthDisposition::None
            }
        }
    }
}

#[cfg(test)]
#[path = "component_pump_tests.rs"]
mod tests;
