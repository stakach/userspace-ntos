//! Nested-pump readiness for retained kernel File reads and queries.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedFileQueryProgress {
    AwaitingDispatch {
        provider_ready: bool,
    },
    AwaitingCompletion {
        completion_ready: bool,
    },
    Cancellation {
        request_pending: bool,
        completion_ready: bool,
    },
    Terminal,
    AwaitingReply {
        acknowledged: bool,
        delivery_pending: bool,
    },
}

impl RetainedFileQueryProgress {
    pub const fn ready_for_nested_step(self) -> bool {
        match self {
            Self::AwaitingDispatch { provider_ready } => provider_ready,
            Self::AwaitingCompletion { completion_ready } => completion_ready,
            Self::Cancellation {
                request_pending,
                completion_ready,
            } => request_pending || completion_ready,
            Self::Terminal => true,
            Self::AwaitingReply {
                acknowledged,
                delivery_pending,
            } => acknowledged && !delivery_pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RetainedFileQueryProgress as Progress;

    #[test]
    fn accepted_query_can_progress_before_its_parent_dispatch_returns() {
        assert!(Progress::AwaitingDispatch {
            provider_ready: true
        }
        .ready_for_nested_step());
        assert!(!Progress::AwaitingDispatch {
            provider_ready: false
        }
        .ready_for_nested_step());
        assert!(!Progress::AwaitingCompletion {
            completion_ready: false
        }
        .ready_for_nested_step());
        assert!(Progress::AwaitingCompletion {
            completion_ready: true
        }
        .ready_for_nested_step());
        assert!(Progress::Terminal.ready_for_nested_step());
    }

    #[test]
    fn reply_and_delivery_waits_do_not_spin_the_nested_pump() {
        for acknowledged in [false, true] {
            assert!(!Progress::AwaitingReply {
                acknowledged,
                delivery_pending: true,
            }
            .ready_for_nested_step());
        }
        assert!(!Progress::AwaitingReply {
            acknowledged: false,
            delivery_pending: false,
        }
        .ready_for_nested_step());
        assert!(Progress::AwaitingReply {
            acknowledged: true,
            delivery_pending: false,
        }
        .ready_for_nested_step());
    }

    #[test]
    fn cancellation_enters_once_then_waits_for_provider_completion() {
        assert!(Progress::Cancellation {
            request_pending: true,
            completion_ready: false,
        }
        .ready_for_nested_step());
        assert!(!Progress::Cancellation {
            request_pending: false,
            completion_ready: false,
        }
        .ready_for_nested_step());
        assert!(Progress::Cancellation {
            request_pending: false,
            completion_ready: true,
        }
        .ready_for_nested_step());
    }
}
