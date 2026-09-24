//! Terminal provider IoCreateFile reply, with an explicit output-publication receipt.

const STATUS_PENDING: u32 = 0x0000_0103;
const COMPLETION_VALID: u64 = 1 << 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    Malformed,
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoCreateFileReply {
    Rejected {
        status: u32,
    },
    Completed {
        status: u32,
        iosb_status: u32,
        information: u64,
        handle: u64,
    },
}

impl IoCreateFileReply {
    pub fn words(self) -> Result<[u64; 4], ReplyError> {
        let words = match self {
            Self::Rejected { status } => {
                if status as i32 >= 0 {
                    return Err(ReplyError::Malformed);
                }
                [status as u64, 0, 0, 0]
            }
            Self::Completed {
                status,
                iosb_status,
                information,
                handle,
            } => {
                if status == STATUS_PENDING || iosb_status == STATUS_PENDING {
                    return Err(ReplyError::Pending);
                }
                if ((status as i32) >= 0 && ((iosb_status as i32) < 0 || handle == 0))
                    || ((status as i32) < 0 && handle != 0)
                {
                    return Err(ReplyError::Malformed);
                }
                [
                    status as u64 | COMPLETION_VALID,
                    iosb_status as u64,
                    information,
                    handle,
                ]
            }
        };
        Ok(words)
    }

    pub fn decode(words: [u64; 4]) -> Result<Self, ReplyError> {
        let [status_word, iosb_status, information, handle] = words;
        if status_word & !(COMPLETION_VALID | u32::MAX as u64) != 0 || iosb_status > u32::MAX as u64
        {
            return Err(ReplyError::Malformed);
        }
        let status = status_word as u32;
        if status == STATUS_PENDING {
            return Err(ReplyError::Pending);
        }
        let reply = if status_word & COMPLETION_VALID == 0 {
            if iosb_status != 0 || information != 0 || handle != 0 {
                return Err(ReplyError::Malformed);
            }
            Self::Rejected { status }
        } else {
            Self::Completed {
                status,
                iosb_status: iosb_status as u32,
                information,
                handle,
            }
        };
        reply.words()?;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_receipt_keeps_iosb_and_handle_distinct() {
        let reply = IoCreateFileReply::Completed {
            status: 0,
            iosb_status: 0,
            information: 2,
            handle: 0xffff_ffff_8000_0044,
        };
        assert_eq!(IoCreateFileReply::decode(reply.words().unwrap()), Ok(reply));
        let error = IoCreateFileReply::Completed {
            status: 0xc000_0034,
            iosb_status: 0xc000_0034,
            information: 0,
            handle: 0,
        };
        assert_eq!(IoCreateFileReply::decode(error.words().unwrap()), Ok(error));
    }

    #[test]
    fn rejection_never_publishes_caller_outputs() {
        let rejected = IoCreateFileReply::Rejected {
            status: 0xc000_000d,
        };
        assert_eq!(
            IoCreateFileReply::decode(rejected.words().unwrap()),
            Ok(rejected)
        );
        assert_eq!(
            IoCreateFileReply::Rejected { status: 0 }.words(),
            Err(ReplyError::Malformed)
        );
        assert_eq!(
            IoCreateFileReply::decode([0xc000_000d, 0, 1, 0]),
            Err(ReplyError::Malformed)
        );
    }

    #[test]
    fn pending_and_forged_success_are_not_terminal_replies() {
        assert_eq!(
            IoCreateFileReply::decode([STATUS_PENDING as u64, 0, 0, 0]),
            Err(ReplyError::Pending)
        );
        assert_eq!(
            IoCreateFileReply::decode([0, 0, 0, 0]),
            Err(ReplyError::Malformed)
        );
        assert_eq!(
            IoCreateFileReply::decode([COMPLETION_VALID, 0, 0, 0]),
            Err(ReplyError::Malformed)
        );
        assert_eq!(
            IoCreateFileReply::decode([COMPLETION_VALID | 1 << 40, 0, 0, 4]),
            Err(ReplyError::Malformed)
        );
        assert_eq!(
            IoCreateFileReply::decode([COMPLETION_VALID, STATUS_PENDING as u64, 0, 4]),
            Err(ReplyError::Pending)
        );
    }
}
