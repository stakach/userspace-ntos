//! Allocation-free scalar protocol for canonical Device pointer-reference operations.
//!
//! Message labels, lengths, caller authentication, and handling of an ambiguous reply belong to
//! the transport adapter. A mutating request must never be retried merely because decoding failed.

use core::num::NonZeroU64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum DevicePointerOperation {
    Reference = 1,
    Dereference = 2,
}

impl DevicePointerOperation {
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::Reference),
            2 => Some(Self::Dereference),
            _ => None,
        }
    }

    pub const fn raw(self) -> u64 {
        self as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MalformedDevicePointerReply {
    StatusUpperBits,
    UnexpectedStatus,
    FailureCount,
    SuccessCount,
}

/// A validated operation outcome. Counts describe canonical references, including the retained
/// registration anchor; even a successful final caller dereference must leave a nonzero count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevicePointerReply {
    Success(NonZeroU64),
    Rejected(i32),
}

impl DevicePointerReply {
    /// Decode a zero-extended 32-bit NTSTATUS and its count. No count from an ambiguous reply may
    /// be used to infer whether an increment or decrement happened.
    pub const fn decode(status: u64, count: u64) -> Result<Self, MalformedDevicePointerReply> {
        if status > u32::MAX as u64 {
            return Err(MalformedDevicePointerReply::StatusUpperBits);
        }
        if status != 0 {
            // There is no pending or informational completion for a pointer-reference mutation.
            // Returning one as an error would still satisfy the native caller's NT_SUCCESS test.
            if status & 0x8000_0000 == 0 {
                return Err(MalformedDevicePointerReply::UnexpectedStatus);
            }
            if count != 0 {
                return Err(MalformedDevicePointerReply::FailureCount);
            }
            return Ok(Self::Rejected(status as u32 as i32));
        }
        match NonZeroU64::new(count) {
            Some(count) => Ok(Self::Success(count)),
            None => Err(MalformedDevicePointerReply::SuccessCount),
        }
    }

    pub const fn into_result(self) -> Result<u64, i32> {
        match self {
            Self::Success(count) => Ok(count.get()),
            Self::Rejected(status) => Err(status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_values_round_trip_without_truncation() {
        for operation in [
            DevicePointerOperation::Reference,
            DevicePointerOperation::Dereference,
        ] {
            assert_eq!(
                DevicePointerOperation::from_raw(operation.raw()),
                Some(operation)
            );
        }
        for raw in [0, 3, 255, 0x1_0000_0001, 0x1_0000_0002, u64::MAX] {
            assert_eq!(DevicePointerOperation::from_raw(raw), None);
        }
    }

    #[test]
    fn success_preserves_the_complete_nonzero_canonical_count() {
        for count in [1, 2, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
            let reply = DevicePointerReply::decode(0, count).unwrap();
            assert_eq!(
                reply,
                DevicePointerReply::Success(NonZeroU64::new(count).unwrap())
            );
            assert_eq!(reply.into_result(), Ok(count));
        }
    }

    #[test]
    fn rejected_reply_preserves_exact_status_and_cannot_supply_a_count() {
        for raw in [0x8000_0005u32, 0xc000_000d, 0xc000_0022, u32::MAX] {
            let reply = DevicePointerReply::decode(u64::from(raw), 0).unwrap();
            assert_eq!(reply, DevicePointerReply::Rejected(raw as i32));
            assert_eq!(reply.into_result(), Err(raw as i32));
            for count in [1, 2, u64::MAX] {
                assert_eq!(
                    DevicePointerReply::decode(u64::from(raw), count),
                    Err(MalformedDevicePointerReply::FailureCount)
                );
            }
        }
    }

    #[test]
    fn pending_and_informational_statuses_are_never_reference_success() {
        for status in [1, 0x103, 0x4000_0000, 0x7fff_ffff] {
            for count in [0, 1, 2, u64::MAX] {
                assert_eq!(
                    DevicePointerReply::decode(status, count),
                    Err(MalformedDevicePointerReply::UnexpectedStatus)
                );
            }
        }
    }

    #[test]
    fn successful_zero_count_is_ambiguous_not_an_authoritative_rejection() {
        assert_eq!(
            DevicePointerReply::decode(0, 0),
            Err(MalformedDevicePointerReply::SuccessCount)
        );
    }

    #[test]
    fn noncanonical_status_width_cannot_hide_success_or_failure() {
        for status in [
            0x1_0000_0000,
            0x1_c000_000d,
            0xffff_ffff_c000_0022,
            u64::MAX,
        ] {
            for count in [0, 1, u64::MAX] {
                assert_eq!(
                    DevicePointerReply::decode(status, count),
                    Err(MalformedDevicePointerReply::StatusUpperBits)
                );
            }
        }
    }
}
