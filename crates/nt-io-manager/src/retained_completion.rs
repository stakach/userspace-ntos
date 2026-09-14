//! State carried by a driver-owned IRP while completion crosses a hosted-driver boundary.
//!
//! The request graph remains the authoritative owner until the executive consumes this record.
//! Completing in place avoids transferring the only completion edge into a second bounded table.

/// Bytes that may be transferred from a completed IRP's retained output buffer.
///
/// `IoStatus.Information` is result metadata, not universally a byte count. In particular, buffer
/// sizing responses preserve the required length even when it exceeds the supplied output buffer.
/// The metadata must remain unchanged while the actual transfer stays bounded by the request.
pub const fn completion_output_transfer_len(information: u64, output_capacity: u64) -> u64 {
    if information < output_capacity {
        information
    } else {
        output_capacity
    }
}

/// Native bytes retained before the caller's completion capture policy is applied.
///
/// Direct and neither device controls expose their whole output buffer independently of
/// `IoStatus.Information`. The method must come from the original request, not a driver-mutated
/// stack location. Other operations retain their existing byte-count behavior.
pub const fn retained_control_output_transfer_len(
    major: u8,
    original_method: u8,
    information: u64,
    output_capacity: u64,
) -> u64 {
    if (major == nt_io_abi::major::IRP_MJ_DEVICE_CONTROL
        || major == nt_io_abi::major::IRP_MJ_INTERNAL_DEVICE_CONTROL)
        && original_method >= nt_io_abi::ioctl::METHOD_IN_DIRECT as u8
        && original_method <= nt_io_abi::ioctl::METHOD_NEITHER as u8
    {
        output_capacity
    } else {
        completion_output_transfer_len(information, output_capacity)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedIrpCompletion {
    sequence: u64,
    information: u64,
    source: u64,
    reclaim: u64,
    status: u32,
    length: u32,
    flags: u32,
    state: u8,
    _reserved: [u8; 3],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedCompletion {
    pub sequence: u64,
    pub status: u32,
    pub information: u64,
    pub source: u64,
    /// Driver-owned replacement buffer that must be released with the request graph.
    pub reclaim: u64,
    pub length: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedCompletionError {
    InvalidSequence,
    AlreadyCompleted,
}

impl RetainedIrpCompletion {
    const PENDING: u8 = 0;
    const COMPLETED: u8 = 1;

    pub const fn pending() -> Self {
        Self {
            sequence: 0,
            information: 0,
            source: 0,
            reclaim: 0,
            status: 0,
            length: 0,
            flags: 0,
            state: Self::PENDING,
            _reserved: [0; 3],
        }
    }

    pub fn complete(
        &mut self,
        sequence: u64,
        status: u32,
        information: u64,
        source: u64,
        reclaim: u64,
        length: u32,
        flags: u32,
    ) -> Result<(), RetainedCompletionError> {
        if sequence == 0 {
            return Err(RetainedCompletionError::InvalidSequence);
        }
        if self.state != Self::PENDING {
            return Err(RetainedCompletionError::AlreadyCompleted);
        }
        self.sequence = sequence;
        self.information = information;
        self.source = source;
        self.reclaim = reclaim;
        self.status = status;
        self.length = length;
        self.flags = flags;
        self.state = Self::COMPLETED;
        Ok(())
    }

    pub fn completed(&self) -> Option<RetainedCompletion> {
        if self.state != Self::COMPLETED {
            return None;
        }
        Some(RetainedCompletion {
            sequence: self.sequence,
            status: self.status,
            information: self.information,
            source: self.source,
            reclaim: self.reclaim,
            length: self.length,
            flags: self.flags,
        })
    }
}

impl Default for RetainedIrpCompletion {
    fn default() -> Self {
        Self::pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_stays_pending_until_durably_published() {
        let mut state = RetainedIrpCompletion::pending();
        assert_eq!(state.completed(), None);
        state
            .complete(7, 0x8000_0005, 16, 0x1000, 0x2000, 16, 0x70)
            .unwrap();
        assert_eq!(
            state.completed(),
            Some(RetainedCompletion {
                sequence: 7,
                status: 0x8000_0005,
                information: 16,
                source: 0x1000,
                reclaim: 0x2000,
                length: 16,
                flags: 0x70,
            })
        );
    }

    #[test]
    fn duplicate_completion_cannot_overwrite_the_first_result() {
        let mut state = RetainedIrpCompletion::pending();
        state.complete(1, 0, 4, 0x2000, 0, 4, 0).unwrap();
        assert_eq!(
            state.complete(2, 0xc000_0001, 0, 0, 0, 0, 0),
            Err(RetainedCompletionError::AlreadyCompleted)
        );
        assert_eq!(state.completed().unwrap().sequence, 1);
        assert_eq!(state.completed().unwrap().source, 0x2000);
    }

    #[test]
    fn zero_sequence_is_rejected_without_mutating_state() {
        let mut state = RetainedIrpCompletion::pending();
        assert_eq!(
            state.complete(0, 0, 0, 0, 0, 0, 0),
            Err(RetainedCompletionError::InvalidSequence)
        );
        assert_eq!(state.completed(), None);
    }

    #[test]
    fn retained_completion_abi_is_stable() {
        assert_eq!(core::mem::size_of::<RetainedIrpCompletion>(), 48);
        assert_eq!(core::mem::align_of::<RetainedIrpCompletion>(), 8);
    }

    #[test]
    fn required_length_metadata_does_not_expand_the_output_transfer() {
        assert_eq!(completion_output_transfer_len(4_748, 20), 20);
        assert_eq!(completion_output_transfer_len(12, 20), 12);
        assert_eq!(completion_output_transfer_len(0, 20), 0);
    }

    #[test]
    fn native_control_retention_preserves_method_specific_output_extent() {
        use nt_io_abi::major;

        for major in [
            major::IRP_MJ_DEVICE_CONTROL,
            major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
        ] {
            for method in 0..=4 {
                for capacity in [0, 20, u32::MAX as u64 + 1] {
                    for information in [0, 12, 4_748, u64::MAX] {
                        let expected = if (1..=3).contains(&method) {
                            capacity
                        } else {
                            information.min(capacity)
                        };
                        assert_eq!(
                            retained_control_output_transfer_len(
                                major,
                                method,
                                information,
                                capacity
                            ),
                            expected,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn other_native_majors_keep_information_bounded_retention() {
        use nt_io_abi::major;

        for major in [
            major::IRP_MJ_READ,
            major::IRP_MJ_QUERY_INFORMATION,
            major::IRP_MJ_FILE_SYSTEM_CONTROL,
            major::IRP_MJ_PNP,
            u8::MAX,
        ] {
            for method in 0..=4 {
                for information in [0, 12, 4_748] {
                    assert_eq!(
                        retained_control_output_transfer_len(major, method, information, 20),
                        information.min(20),
                    );
                }
            }
        }
    }
}
