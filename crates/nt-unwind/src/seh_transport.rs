//! Typed messages for one hosted-driver SEH handler exchange.
//!
//! The message shape is not authority. The executive must additionally authenticate the exact
//! physical route, dispatch, Reply, thread, driver domain, and writable packet stack lease.

pub const RAISE_LABEL: u64 = 0x78f;
pub const PREPARE_LABEL: u64 = 0x790;
pub const HANDLER_RESULT_LABEL: u64 = 0x791;
pub const PREPARE_COMMAND_LABEL: u64 = 0x792;
pub const INVOKE_COMMAND_LABEL: u64 = 0x793;

pub const fn message_info(label: u64, length: u64) -> u64 {
    (label << 12) | length
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SehCall {
    Raise {
        context_va: u64,
        status: u32,
    },
    Prepare {
        token: u64,
        packet_va: u64,
    },
    HandlerResult {
        token: u64,
        packet_va: u64,
        disposition: i32,
    },
}

impl SehCall {
    pub fn parse(info: u64, words: [u64; 3]) -> Option<Self> {
        match info {
            x if x == message_info(RAISE_LABEL, 2) => Some(Self::Raise {
                context_va: aligned_nonzero(words[0])?,
                status: u32::try_from(words[1]).ok()?,
            }),
            x if x == message_info(PREPARE_LABEL, 2) => Some(Self::Prepare {
                token: nonzero(words[0])?,
                packet_va: aligned_nonzero(words[1])?,
            }),
            x if x == message_info(HANDLER_RESULT_LABEL, 3) => Some(Self::HandlerResult {
                token: nonzero(words[0])?,
                packet_va: aligned_nonzero(words[1])?,
                disposition: u32::try_from(words[2]).ok()? as i32,
            }),
            _ => None,
        }
    }

    pub const fn encode(self) -> (u64, [u64; 3]) {
        match self {
            Self::Raise { context_va, status } => {
                (message_info(RAISE_LABEL, 2), [context_va, status as u64, 0])
            }
            Self::Prepare { token, packet_va } => {
                (message_info(PREPARE_LABEL, 2), [token, packet_va, 0])
            }
            Self::HandlerResult {
                token,
                packet_va,
                disposition,
            } => (
                message_info(HANDLER_RESULT_LABEL, 3),
                [token, packet_va, disposition as u32 as u64],
            ),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SehCommand {
    Prepare { token: u64 },
    Invoke { token: u64 },
}

impl SehCommand {
    pub fn parse(info: u64, word: u64) -> Option<Self> {
        let token = nonzero(word)?;
        match info {
            x if x == message_info(PREPARE_COMMAND_LABEL, 1) => Some(Self::Prepare { token }),
            x if x == message_info(INVOKE_COMMAND_LABEL, 1) => Some(Self::Invoke { token }),
            _ => None,
        }
    }

    pub const fn encode(self) -> (u64, u64) {
        match self {
            Self::Prepare { token } => (message_info(PREPARE_COMMAND_LABEL, 1), token),
            Self::Invoke { token } => (message_info(INVOKE_COMMAND_LABEL, 1), token),
        }
    }
}

fn nonzero(word: u64) -> Option<u64> {
    (word != 0).then_some(word)
}

fn aligned_nonzero(word: u64) -> Option<u64> {
    (word != 0 && word & 15 == 0).then_some(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_round_trip_with_exact_labels_lengths_and_integer_shapes() {
        for call in [
            SehCall::Raise {
                context_va: 0x1000,
                status: 0xc000_0022,
            },
            SehCall::Prepare {
                token: 7,
                packet_va: 0x2000,
            },
            SehCall::HandlerResult {
                token: 7,
                packet_va: 0x2000,
                disposition: -1,
            },
        ] {
            let (info, words) = call.encode();
            assert_eq!(SehCall::parse(info, words), Some(call));
            assert_eq!(SehCall::parse(info + 1, words), None);
            assert_eq!(SehCall::parse(info | (1 << 7), words), None);
        }
        assert_eq!(
            SehCall::parse(message_info(RAISE_LABEL, 2), [0x1000, 0x1_c000_0022, 0]),
            None
        );
        assert_eq!(
            SehCall::parse(message_info(RAISE_LABEL, 2), [0x1008, 1, 0]),
            None
        );
        assert_eq!(
            SehCall::parse(message_info(PREPARE_LABEL, 2), [0, 0x2000, 0]),
            None
        );
        assert_eq!(
            SehCall::parse(message_info(HANDLER_RESULT_LABEL, 3), [7, 0x2000, u64::MAX]),
            None
        );
    }

    #[test]
    fn command_acknowledgement_is_typed_and_never_a_status_reply() {
        for command in [
            SehCommand::Prepare { token: 9 },
            SehCommand::Invoke { token: 9 },
        ] {
            let (info, word) = command.encode();
            assert_eq!(SehCommand::parse(info, word), Some(command));
            assert_eq!(SehCommand::parse(info + 1, word), None);
            assert_eq!(SehCommand::parse(info, 0), None);
        }
    }
}
