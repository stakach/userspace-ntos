//! Pointer-free terminal reports from an authenticated provider channel.

pub const BUGCHECK_LABEL: u64 = 0x7ec;
pub const BUGCHECK_MESSAGE_INFO: u64 = (BUGCHECK_LABEL << 12) | 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderChannel {
    pub endpoint: u64,
    pub tcb: u64,
    pub vspace: u64,
    pub reply_object: u64,
    pub expected_badge: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportError {
    InvalidChannel,
    WrongSender,
    InvalidMessage,
    InvalidCode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatalReport {
    channel: ProviderChannel,
    code: u32,
    parameters: [u64; 4],
}

impl FatalReport {
    /// Channel identity comes from the receiver's retained endpoint/lane, never provider words.
    /// No capability transfer, truncated report, or widened ULONG is accepted.
    pub fn decode(
        channel: ProviderChannel,
        badge: u64,
        message_info: u64,
        words: [u64; 5],
    ) -> Result<Self, ReportError> {
        if channel.endpoint == 0
            || channel.tcb == 0
            || channel.vspace == 0
            || channel.reply_object == 0
        {
            return Err(ReportError::InvalidChannel);
        }
        if badge != channel.expected_badge {
            return Err(ReportError::WrongSender);
        }
        if message_info != BUGCHECK_MESSAGE_INFO {
            return Err(ReportError::InvalidMessage);
        }
        let code = u32::try_from(words[0]).map_err(|_| ReportError::InvalidCode)?;
        Ok(Self {
            channel,
            code,
            parameters: [words[1], words[2], words[3], words[4]],
        })
    }

    pub const fn channel(self) -> ProviderChannel {
        self.channel
    }
    pub const fn code(self) -> u32 {
        self.code
    }
    pub const fn parameters(self) -> [u64; 4] {
        self.parameters
    }
}

/// The first accepted report is immutable evidence. There is no reset or successful-resume path.
#[derive(Debug, Default)]
pub struct FatalState {
    first: Option<FatalReport>,
}

impl FatalState {
    pub const fn new() -> Self {
        Self { first: None }
    }
    pub const fn first(&self) -> Option<FatalReport> {
        self.first
    }
    pub fn record(&mut self, report: FatalReport) -> FatalReport {
        *self.first.get_or_insert(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> ProviderChannel {
        ProviderChannel {
            endpoint: 10,
            tcb: 11,
            vspace: 12,
            reply_object: 13,
            expected_badge: 0,
        }
    }

    #[test]
    fn reports_preserve_every_parameter_bit_and_receiver_identity() {
        let parameters = [u64::MAX, 0x1234_5678_9abc_def0, 1 << 63, 0];
        let report = FatalReport::decode(
            channel(),
            0,
            BUGCHECK_MESSAGE_INFO,
            [
                u32::MAX as u64,
                parameters[0],
                parameters[1],
                parameters[2],
                parameters[3],
            ],
        )
        .unwrap();
        assert_eq!(report.channel(), channel());
        assert_eq!(report.code(), u32::MAX);
        assert_eq!(report.parameters(), parameters);
    }

    #[test]
    fn zero_bugcheck_code_is_still_a_fatal_report() {
        let mut state = FatalState::new();
        state.record(FatalReport::decode(channel(), 0, BUGCHECK_MESSAGE_INFO, [0; 5]).unwrap());
        assert_eq!(state.first().unwrap().code(), 0);
    }

    #[test]
    fn incomplete_channel_authority_is_rejected() {
        for missing in 0..4 {
            let mut channel = channel();
            match missing {
                0 => channel.endpoint = 0,
                1 => channel.tcb = 0,
                2 => channel.vspace = 0,
                _ => channel.reply_object = 0,
            }
            assert_eq!(
                FatalReport::decode(channel, 0, BUGCHECK_MESSAGE_INFO, [0; 5]),
                Err(ReportError::InvalidChannel)
            );
        }
    }

    #[test]
    fn notification_or_wrong_lane_badge_cannot_report_bugcheck() {
        assert_eq!(
            FatalReport::decode(channel(), 1 << 63, BUGCHECK_MESSAGE_INFO, [0; 5]),
            Err(ReportError::WrongSender)
        );
        let mut badged = channel();
        badged.expected_badge = 42;
        assert!(FatalReport::decode(badged, 42, BUGCHECK_MESSAGE_INFO, [0; 5]).is_ok());
        assert_eq!(
            FatalReport::decode(badged, 0, BUGCHECK_MESSAGE_INFO, [0; 5]),
            Err(ReportError::WrongSender)
        );
    }

    #[test]
    fn framing_rejects_other_labels_lengths_and_capability_transfer() {
        for info in [
            5,
            (BUGCHECK_LABEL << 12) | 4,
            (BUGCHECK_LABEL << 12) | 6,
            BUGCHECK_MESSAGE_INFO | (1 << 7),
            BUGCHECK_MESSAGE_INFO | (1 << 9),
        ] {
            assert_eq!(
                FatalReport::decode(channel(), 0, info, [0; 5]),
                Err(ReportError::InvalidMessage)
            );
        }
    }

    #[test]
    fn code_must_fit_the_native_ulong() {
        assert_eq!(
            FatalReport::decode(
                channel(),
                0,
                BUGCHECK_MESSAGE_INFO,
                [u64::from(u32::MAX) + 1, 0, 0, 0, 0]
            ),
            Err(ReportError::InvalidCode)
        );
    }

    #[test]
    fn later_provider_cannot_replace_first_fatal_evidence() {
        let first =
            FatalReport::decode(channel(), 0, BUGCHECK_MESSAGE_INFO, [1, 2, 3, 4, 5]).unwrap();
        let mut later_channel = channel();
        later_channel.tcb = 99;
        let later = FatalReport::decode(later_channel, 0, BUGCHECK_MESSAGE_INFO, [9; 5]).unwrap();
        let mut state = FatalState::new();
        assert_eq!(state.first(), None);
        assert_eq!(state.record(first), first);
        assert_eq!(state.record(later), first);
        assert_eq!(state.first(), Some(first));
    }
}
