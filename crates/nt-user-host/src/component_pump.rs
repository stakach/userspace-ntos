//! Component receive-boundary policy and cumulative dispatch-depth bookkeeping.
//! Demand snapshots select a scheduling boundary without owning a Reply, DPC, or endpoint.

use nt_component_suspension::{ComponentSuspensionLanes, LaneDispatchIdentity};

/// Which typed receive boundary a resumed Win32k pump may yield through.
/// The nested callback origin is retained with the pending dispatch across reparks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeYieldCaps {
    pub hosted_receive: bool,
    pub nested_service_wait: bool,
}

pub const fn resume_yield_caps(
    nested_callback: bool,
    has_logical_caller: bool,
) -> ResumeYieldCaps {
    ResumeYieldCaps {
        hosted_receive: has_logical_caller && !nested_callback,
        nested_service_wait: has_logical_caller && nested_callback,
    }
}

/// How a provider parked in `KeUserModeCallback` is being entered again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackResumeOrigin {
    /// The client's NtCallbackReturn. `enclosing_callback` says the client is still inside an
    /// outer callback, so the resumed dispatch is itself nested in that callback.
    Return { enclosing_callback: bool },
    /// The callback is being cancelled or failed and its provider unwound. The client will not
    /// run again, so no receive boundary can be left at the root for it.
    Unwind,
}

/// The typed receive boundaries a callback resume may yield through. A returned callback is
/// an ordinary resumed provider and keeps the authority of its nesting; an unwind has none.
pub const fn callback_resume_yield_caps(
    origin: CallbackResumeOrigin,
    has_logical_caller: bool,
) -> ResumeYieldCaps {
    match origin {
        CallbackResumeOrigin::Return { enclosing_callback } => {
            resume_yield_caps(enclosing_callback, has_logical_caller)
        }
        CallbackResumeOrigin::Unwind => ResumeYieldCaps {
            hosted_receive: false,
            nested_service_wait: false,
        },
    }
}

/// The yield a callback-return resume came back with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackReturnYield {
    Receive,
    ServiceWait,
}

/// Whether the callback-return consumer may transfer the completed callback into that yield.
/// A service wait is owned at any depth: only the completed callback's token is transferred
/// and every enclosing callback keeps its own. Receive ownership exists only for an outermost
/// dispatch, which is why a nested resume is never granted it.
pub const fn callback_return_yield_is_owned(
    yielded: CallbackReturnYield,
    enclosing_callback: bool,
) -> bool {
    match yielded {
        CallbackReturnYield::ServiceWait => true,
        CallbackReturnYield::Receive => !enclosing_callback,
    }
}

/// A refused root receive has either a certified pre-native owner conflict or an
/// uncertain native effect. Only the former may give the exact child another turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootReceiveRefusal {
    IdleExecutionBusyBeforeNativeReceive,
    NativeReceiveEffectUncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootReceiveDisposition {
    ResumeRetainedDispatch,
    RetainFailure,
}

/// Decide whether a yielded child still owns the precise running lane and Reply.
/// This is a read-only policy; the native owner retains the continuation and does
/// the next scheduler step. No Reply or receive is transferred here.
pub fn root_receive_disposition_after_yield<C, R, T>(
    lanes: &ComponentSuspensionLanes<C, R, T>,
    dispatch: LaneDispatchIdentity,
    physical_reply: u64,
    refusal: RootReceiveRefusal,
) -> RootReceiveDisposition {
    if refusal == RootReceiveRefusal::IdleExecutionBusyBeforeNativeReceive
        && lanes.running() == Some(dispatch.lane())
        && lanes.active_dispatch_identity(dispatch.lane()) == Ok(Some(dispatch))
        && lanes.binding(dispatch.lane()).ok().is_some_and(|binding|
            binding.reply_object == physical_reply)
    {
        RootReceiveDisposition::ResumeRetainedDispatch
    } else {
        RootReceiveDisposition::RetainFailure
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PumpDepthDisposition {
    None,
    Retained,
    Suspended,
    Released,
}

/// Scheduler demand observed after an authenticated service Reply has been sent.
/// This only selects the next receive boundary; Reply and DPC ownership stay with their
/// existing canonical owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostReplyReceiveDemand {
    pub timer_checkpoint_ready: bool,
    pub queued_dpc: bool,
}

impl PostReplyReceiveDemand {
    pub const fn scheduler_yield(self) -> bool {
        self.timer_checkpoint_ready || self.queued_dpc
    }
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
