//! Pure nested selection policy for retained Section metadata work.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionMetadataProgress {
    Query { provider_ready: bool },
    AwaitingCompletion { completion_ready: bool, cancel_pending: bool, provider_ready: bool },
    CopyOrAcknowledge { provider_ready: bool },
    Local,
    AwaitingReply { acknowledged: bool, cancelled: bool },
    Indeterminate,
}

impl SectionMetadataProgress {
    pub const fn ready(self) -> bool {
        match self {
            Self::Query { provider_ready } | Self::CopyOrAcknowledge { provider_ready } => provider_ready,
            Self::AwaitingCompletion { completion_ready, cancel_pending, provider_ready } =>
                completion_ready || (cancel_pending && provider_ready),
            Self::Local => true,
            Self::AwaitingReply { acknowledged, cancelled } => acknowledged || cancelled,
            Self::Indeterminate => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SectionMetadataProgress as P;

    #[test]
    fn queries_and_transfer_control_require_the_exact_provider_lane() {
        for ready in [false, true] {
            assert_eq!(P::Query { provider_ready: ready }.ready(), ready);
            assert_eq!(P::CopyOrAcknowledge { provider_ready: ready }.ready(), ready);
        }
    }

    #[test]
    fn pending_waits_need_a_terminal_receipt_or_one_admitted_cancel_step() {
        for completion_ready in [false, true] {
            for cancel_pending in [false, true] {
                for provider_ready in [false, true] {
                    assert_eq!(P::AwaitingCompletion { completion_ready, cancel_pending, provider_ready }.ready(),
                        completion_ready || (cancel_pending && provider_ready));
                }
            }
        }
    }

    #[test]
    fn local_steps_progress_but_entered_replies_do_not_spin() {
        assert!(P::Local.ready());
        assert!(!P::AwaitingReply { acknowledged: false, cancelled: false }.ready());
        assert!(P::AwaitingReply { acknowledged: true, cancelled: false }.ready());
        assert!(P::AwaitingReply { acknowledged: false, cancelled: true }.ready());
        assert!(!P::Indeterminate.ready());
    }
}
