//! The pumped stages of a class driver's CONNECT forward (#420).
//!
//! A CONNECT submit projects two aliases (PortDO, then class DO) into the port domain and then
//! configures them, each a pump into the port driver, before its tail publishes the callback
//! thunk and parks the class driver's Call. Any stage may stop unfinished while the class
//! driver's lane is parked for it. That stage has entered the port driver, so its result is not
//! known yet: the submit keeps its whole state, resumes exactly that stage once the kept pump
//! finishes, and only a returned failure rolls the aliases and the captured source back.

/// The pumped stages, in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectSubmitStage {
    PortAlias,
    ClassAlias,
    Configure,
}

/// How one stage's pump ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectStageEnd {
    Returned(Result<(), i32>),
    /// Still running in the port driver; the caller's service keeps it.
    Kept,
}

/// What the submit does next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectSubmitNext {
    /// Run this stage's pump.
    Enter(ConnectSubmitStage),
    /// Keep the whole submit; finish this same stage on the kept pump's true result.
    Keep(ConnectSubmitStage),
    /// Every stage returned: publish the thunk and park the class driver's Call.
    Tail,
    /// A stage returned a failure: block the aliases, abort the source, reply this status.
    Rollback(i32),
}

impl ConnectSubmitStage {
    pub const FIRST: Self = Self::PortAlias;

    pub const fn after(self, end: ConnectStageEnd) -> ConnectSubmitNext {
        match end {
            ConnectStageEnd::Kept => ConnectSubmitNext::Keep(self),
            ConnectStageEnd::Returned(Err(status)) => ConnectSubmitNext::Rollback(status),
            ConnectStageEnd::Returned(Ok(())) => match self {
                Self::PortAlias => ConnectSubmitNext::Enter(Self::ClassAlias),
                Self::ClassAlias => ConnectSubmitNext::Enter(Self::Configure),
                Self::Configure => ConnectSubmitNext::Tail,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kept_stage_is_neither_rolled_back_nor_reentered() {
        for stage in [ConnectSubmitStage::PortAlias, ConnectSubmitStage::ClassAlias,
            ConnectSubmitStage::Configure]
        {
            assert_eq!(stage.after(ConnectStageEnd::Kept), ConnectSubmitNext::Keep(stage),
                "an unfinished port pump has entered the driver: no rollback, no second entry");
        }
    }

    #[test]
    fn the_stages_run_in_order_then_the_tail() {
        let ok = ConnectStageEnd::Returned(Ok(()));
        let mut next = ConnectSubmitNext::Enter(ConnectSubmitStage::FIRST);
        let mut entered = alloc::vec::Vec::new();
        while let ConnectSubmitNext::Enter(stage) = next {
            entered.push(stage);
            next = stage.after(ok);
        }
        assert_eq!(entered, [ConnectSubmitStage::PortAlias, ConnectSubmitStage::ClassAlias,
            ConnectSubmitStage::Configure]);
        assert_eq!(next, ConnectSubmitNext::Tail);
    }

    #[test]
    fn only_a_returned_failure_rolls_back() {
        assert_eq!(ConnectSubmitStage::ClassAlias.after(ConnectStageEnd::Returned(Err(-5))),
            ConnectSubmitNext::Rollback(-5));
    }
}
