//! Typed messages for one hosted-driver SEH handler exchange.
//!
//! The message shape is not authority. The executive must additionally authenticate the exact
//! physical route, dispatch, Reply, thread, driver domain, and writable packet stack lease.

pub const RAISE_LABEL: u64 = 0x78f;
pub const PREPARE_LABEL: u64 = 0x790;
pub const HANDLER_RESULT_LABEL: u64 = 0x791;
pub const PREPARE_COMMAND_LABEL: u64 = 0x792;
pub const INVOKE_COMMAND_LABEL: u64 = 0x793;
pub const RESTORE_COMMAND_LABEL: u64 = 0x794;
pub const SECOND_CHANCE_COMMAND_LABEL: u64 = 0x795;
pub const UNWIND_REQUEST_LABEL: u64 = 0x796;
pub const BEGIN_UNWIND_LABEL: u64 = 0x797;

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
    UnwindRequest {
        token: u64,
        target_frame: u64,
        target_ip: u64,
        packet_va: u64,
    },
    BeginUnwind {
        request_va: u64,
    },
}

impl SehCall {
    pub fn parse(info: u64, words: [u64; 4]) -> Option<Self> {
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
            x if x == message_info(UNWIND_REQUEST_LABEL, 4) => Some(Self::UnwindRequest {
                token: nonzero(words[0])?,
                target_frame: aligned_or_zero(words[1])?,
                target_ip: words[2],
                packet_va: aligned_nonzero(words[3])?,
            }),
            x if x == message_info(BEGIN_UNWIND_LABEL, 1) => Some(Self::BeginUnwind {
                request_va: aligned_nonzero(words[0])?,
            }),
            _ => None,
        }
    }

    pub const fn encode(self) -> (u64, [u64; 4]) {
        match self {
            Self::Raise { context_va, status } => {
                (message_info(RAISE_LABEL, 2), [context_va, status as u64, 0, 0])
            }
            Self::Prepare { token, packet_va } => {
                (message_info(PREPARE_LABEL, 2), [token, packet_va, 0, 0])
            }
            Self::HandlerResult {
                token,
                packet_va,
                disposition,
            } => (
                message_info(HANDLER_RESULT_LABEL, 3),
                [token, packet_va, disposition as u32 as u64, 0],
            ),
            Self::UnwindRequest { token, target_frame, target_ip, packet_va } => (
                message_info(UNWIND_REQUEST_LABEL, 4),
                [token, target_frame, target_ip, packet_va],
            ),
            Self::BeginUnwind { request_va } => (
                message_info(BEGIN_UNWIND_LABEL, 1),
                [request_va, 0, 0, 0],
            ),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum SehSecondChanceReason {
    Unhandled = 0,
    ExitUnwind = 1,
    TargetNotFound = 2,
}

impl SehSecondChanceReason {
    fn parse(word: u64) -> Option<Self> {
        match word {
            0 => Some(Self::Unhandled),
            1 => Some(Self::ExitUnwind),
            2 => Some(Self::TargetNotFound),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SehCommand {
    Prepare { token: u64 },
    Invoke { token: u64 },
    Restore { token: u64, context_va: u64 },
    SecondChance {
        token: u64,
        code: u32,
        address: u64,
        reason: SehSecondChanceReason,
    },
}

impl SehCommand {
    pub fn parse(info: u64, words: [u64; 4]) -> Option<Self> {
        let token = nonzero(words[0])?;
        match info {
            x if x == message_info(PREPARE_COMMAND_LABEL, 1) => Some(Self::Prepare { token }),
            x if x == message_info(INVOKE_COMMAND_LABEL, 1) => Some(Self::Invoke { token }),
            x if x == message_info(RESTORE_COMMAND_LABEL, 2) => Some(Self::Restore {
                token,
                context_va: aligned_nonzero(words[1])?,
            }),
            x if x == message_info(SECOND_CHANCE_COMMAND_LABEL, 4) => Some(Self::SecondChance {
                token,
                code: u32::try_from(words[1]).ok()?,
                address: words[2],
                reason: SehSecondChanceReason::parse(words[3])?,
            }),
            _ => None,
        }
    }

    pub const fn encode(self) -> (u64, [u64; 4]) {
        match self {
            Self::Prepare { token } => (message_info(PREPARE_COMMAND_LABEL, 1), [token, 0, 0, 0]),
            Self::Invoke { token } => (message_info(INVOKE_COMMAND_LABEL, 1), [token, 0, 0, 0]),
            Self::Restore { token, context_va } => (message_info(RESTORE_COMMAND_LABEL, 2), [token, context_va, 0, 0]),
            Self::SecondChance { token, code, address, reason } => (
                message_info(SECOND_CHANCE_COMMAND_LABEL, 4),
                [token, code as u64, address, reason as u64],
            ),
        }
    }
}

fn nonzero(word: u64) -> Option<u64> {
    (word != 0).then_some(word)
}

fn aligned_nonzero(word: u64) -> Option<u64> {
    (word != 0 && word & 15 == 0).then_some(word)
}

fn aligned_or_zero(word: u64) -> Option<u64> {
    (word & 15 == 0).then_some(word)
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
            SehCall::UnwindRequest {
                token: 7,
                target_frame: 0x3000,
                target_ip: 0x1234,
                packet_va: 0x2000,
            },
            SehCall::BeginUnwind {
                request_va: 0x4000,
            },
        ] {
            let (info, words) = call.encode();
            assert_eq!(SehCall::parse(info, words), Some(call));
            assert_eq!(SehCall::parse(info + 1, words), None);
            assert_eq!(SehCall::parse(info | (1 << 7), words), None);
        }
        assert_eq!(
            SehCall::parse(message_info(RAISE_LABEL, 2), [0x1000, 0x1_c000_0022, 0, 0]),
            None
        );
        assert_eq!(
            SehCall::parse(message_info(RAISE_LABEL, 2), [0x1008, 1, 0, 0]),
            None
        );
        assert_eq!(
            SehCall::parse(message_info(PREPARE_LABEL, 2), [0, 0x2000, 0, 0]),
            None
        );
        assert_eq!(
            SehCall::parse(message_info(HANDLER_RESULT_LABEL, 3), [7, 0x2000, u64::MAX, 0]),
            None
        );
        assert_eq!(
            SehCall::parse(message_info(UNWIND_REQUEST_LABEL, 4), [7, 0x3008, 0x1234, 0x2000]),
            None
        );
        assert_eq!(
            SehCall::parse(message_info(UNWIND_REQUEST_LABEL, 3), [7, 0x3000, 0x1234, 0x2000]),
            None
        );
        for request_va in [0, 0x4008] {
            assert_eq!(
                SehCall::parse(message_info(BEGIN_UNWIND_LABEL, 1), [request_va, 0, 0, 0]),
                None
            );
        }
        assert_eq!(
            SehCall::parse(message_info(BEGIN_UNWIND_LABEL, 2), [0x4000, 0, 0, 0]),
            None
        );
    }

    #[test]
    fn command_acknowledgement_is_typed_and_never_a_status_reply() {
        for command in [
            SehCommand::Prepare { token: 9 },
            SehCommand::Invoke { token: 9 },
            SehCommand::Restore { token: 9, context_va: 0x2000 },
            SehCommand::SecondChance {
                token: 9,
                code: 0xc000_0022,
                address: 0x1234,
                reason: SehSecondChanceReason::Unhandled,
            },
            SehCommand::SecondChance {
                token: 9,
                code: 0xc000_0022,
                address: 0x1234,
                reason: SehSecondChanceReason::ExitUnwind,
            },
            SehCommand::SecondChance {
                token: 9,
                code: 0xc000_0022,
                address: 0x1234,
                reason: SehSecondChanceReason::TargetNotFound,
            },
        ] {
            let (info, words) = command.encode();
            assert_eq!(SehCommand::parse(info, words), Some(command));
            assert_eq!(SehCommand::parse(info + 1, words), None);
            assert_eq!(SehCommand::parse(info, [0, words[1], words[2], words[3]]), None);
        }
        assert_eq!(
            SehCommand::parse(message_info(RESTORE_COMMAND_LABEL, 2), [9, 0x2008, 0, 0]),
            None
        );
        assert_eq!(
            SehCommand::parse(message_info(SECOND_CHANCE_COMMAND_LABEL, 1), [9, 1, 0x1234, 0]),
            None
        );
        assert_eq!(
            SehCommand::parse(message_info(SECOND_CHANCE_COMMAND_LABEL, 4), [9, 0x1_c000_0022, 0x1234, 0]),
            None
        );
        assert_eq!(
            SehCommand::parse(message_info(SECOND_CHANCE_COMMAND_LABEL, 4), [9, 1, 0x1234, 3]),
            None
        );
    }
}
