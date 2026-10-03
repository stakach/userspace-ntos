//! Readiness of an exact retained File close inside an entered provider pump.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedFileCloseProgress {
    ClosePending,
    AwaitingCleanup { terminal: bool, lifecycle_ready: bool },
    Terminal,
    AwaitingReply { acknowledged: bool },
    Cancelled,
}

impl RetainedFileCloseProgress {
    pub const fn ready_for_nested_step(self) -> bool {
        match self {
            Self::ClosePending | Self::Terminal | Self::Cancelled => true,
            Self::AwaitingCleanup { terminal, lifecycle_ready } => terminal || lifecycle_ready,
            Self::AwaitingReply { acknowledged } => acknowledged,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RetainedFileCloseProgress as Progress;

    #[test]
    fn accepted_close_progresses_without_outer_service_loop() {
        assert!(Progress::ClosePending.ready_for_nested_step());
        assert!(Progress::Terminal.ready_for_nested_step());
        assert!(Progress::Cancelled.ready_for_nested_step());
    }

    #[test]
    fn pending_cleanup_and_reply_do_not_spin() {
        assert!(!Progress::AwaitingCleanup { terminal: false, lifecycle_ready: false }
            .ready_for_nested_step());
        assert!(Progress::AwaitingCleanup { terminal: false, lifecycle_ready: true }
            .ready_for_nested_step());
        assert!(Progress::AwaitingCleanup { terminal: true, lifecycle_ready: false }
            .ready_for_nested_step());
        assert!(!Progress::AwaitingReply { acknowledged: false }.ready_for_nested_step());
        assert!(Progress::AwaitingReply { acknowledged: true }.ready_for_nested_step());
    }
}
