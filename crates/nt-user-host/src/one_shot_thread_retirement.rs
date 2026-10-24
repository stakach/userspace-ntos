//! Exact one-shot TCB retirement after a boot proof has finished.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Running,
    SuspendPending,
    Suspended,
    RetirementPending,
    Retired,
}

/// Retains the original TCB capability through acknowledged native effects.
pub struct OneShotThreadRetirement {
    tcb: u64,
    state: State,
}

impl OneShotThreadRetirement {
    pub const fn new(tcb: u64) -> Option<Self> {
        if tcb <= 1 { None } else { Some(Self { tcb, state: State::Running }) }
    }

    /// A second request is refused even if the first effect's result was uncertain.
    pub fn suspension_request(&mut self) -> Option<u64> {
        if self.state != State::Running { return None; }
        self.state = State::SuspendPending;
        Some(self.tcb)
    }

    pub fn acknowledge_suspension(&mut self, success: bool) -> bool {
        if self.state != State::SuspendPending || !success { return false; }
        self.state = State::Suspended;
        true
    }

    pub fn retirement_request(&mut self) -> Option<u64> {
        if self.state != State::Suspended { return None; }
        self.state = State::RetirementPending;
        Some(self.tcb)
    }

    pub fn acknowledge_retirement(&mut self, success: bool) -> bool {
        if self.state != State::RetirementPending || !success { return false; }
        self.state = State::Retired;
        true
    }

    pub const fn is_retired(&self) -> bool { matches!(self.state, State::Retired) }
}
