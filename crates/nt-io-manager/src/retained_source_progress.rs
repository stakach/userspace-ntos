//! Side-effect-free nested-pump scheduling for retained source IRPs.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedSourceProgress {
    Indeterminate,
    AwaitingDispatch {
        provider_ready: bool,
    },
    PublishReply,
    AwaitingReply {
        acknowledged: bool,
    },
    AwaitingCompletion {
        completion_ready: bool,
        cancellation_pending: bool,
    },
    Stopped {
        cancellation_pending: bool,
        completion_ready: bool,
        broker_stopped: bool,
        source_lane_ready: bool,
    },
    Terminal {
        source_lane_ready: bool,
    },
    Retirement,
}

impl RetainedSourceProgress {
    pub const fn ready_for_nested_step(self) -> bool {
        match self {
            Self::Indeterminate => false,
            Self::AwaitingDispatch { provider_ready } => provider_ready,
            Self::PublishReply | Self::Retirement => true,
            Self::AwaitingReply { acknowledged } => acknowledged,
            Self::AwaitingCompletion {
                completion_ready,
                cancellation_pending,
            } => completion_ready || cancellation_pending,
            Self::Stopped {
                cancellation_pending,
                completion_ready,
                broker_stopped,
                source_lane_ready,
            } => cancellation_pending || (completion_ready && broker_stopped && source_lane_ready),
            Self::Terminal { source_lane_ready } => source_lane_ready,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RetainedSourceProgress as Progress;

    #[test]
    fn accepted_source_call_dispatches_inside_parked_parent_pump() {
        assert!(Progress::AwaitingDispatch {
            provider_ready: true
        }
        .ready_for_nested_step());
        assert!(!Progress::AwaitingDispatch {
            provider_ready: false
        }
        .ready_for_nested_step());
        assert!(Progress::PublishReply.ready_for_nested_step());
    }

    #[test]
    fn pending_provider_and_uncertain_reply_do_not_spin() {
        assert!(!Progress::AwaitingCompletion {
            completion_ready: false,
            cancellation_pending: false,
        }
        .ready_for_nested_step());
        assert!(Progress::AwaitingCompletion {
            completion_ready: false,
            cancellation_pending: true,
        }
        .ready_for_nested_step());
        assert!(!Progress::AwaitingReply {
            acknowledged: false
        }
        .ready_for_nested_step());
        assert!(!Progress::Indeterminate.ready_for_nested_step());
    }

    #[test]
    fn terminal_completion_requires_source_lane_but_retirement_does_not() {
        assert!(!Progress::Terminal {
            source_lane_ready: false
        }
        .ready_for_nested_step());
        assert!(Progress::Terminal {
            source_lane_ready: true
        }
        .ready_for_nested_step());
        assert!(Progress::Retirement.ready_for_nested_step());
    }

    #[test]
    fn stopped_owner_cancels_once_and_discards_only_at_a_sealed_broker_stop() {
        assert!(Progress::Stopped {
            cancellation_pending: true,
            completion_ready: false,
            broker_stopped: false,
            source_lane_ready: false,
        }
        .ready_for_nested_step());
        for broker_stopped in [false, true] {
            assert!(!Progress::Stopped {
                cancellation_pending: false,
                completion_ready: false,
                broker_stopped,
                source_lane_ready: true,
            }
            .ready_for_nested_step());
        }
        assert!(!Progress::Stopped {
            cancellation_pending: false,
            completion_ready: true,
            broker_stopped: false,
            source_lane_ready: true,
        }
        .ready_for_nested_step());
        assert!(Progress::Stopped {
            cancellation_pending: false,
            completion_ready: true,
            broker_stopped: true,
            source_lane_ready: true,
        }
        .ready_for_nested_step());
    }
}
