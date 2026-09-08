//! Scalar reply contract for hosted Device creation, attachment, detachment and deletion.
//! Transport adapters validate the exact envelope separately and must not retry an ambiguous
//! mutation or release its native projection merely because decoding failed.

use core::num::NonZeroU64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MalformedDeviceMutationReply {
    StatusUpperBits,
    UnexpectedStatus,
    ReservedWords,
    FailureValue,
    SuccessValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceMutationReply {
    Success(Option<NonZeroU64>),
    Rejected(i32),
}

impl DeviceMutationReply {
    /// CREATE/ATTACH/DETACH return a nonzero canonical device identity; DELETE returns no value.
    pub const fn decode(
        status: u64,
        value: u64,
        reserved: [u64; 2],
        returns_device: bool,
    ) -> Result<Self, MalformedDeviceMutationReply> {
        if status > u32::MAX as u64 {
            return Err(MalformedDeviceMutationReply::StatusUpperBits);
        }
        if reserved[0] != 0 || reserved[1] != 0 {
            return Err(MalformedDeviceMutationReply::ReservedWords);
        }
        if status != 0 {
            if status & 0x8000_0000 == 0 {
                return Err(MalformedDeviceMutationReply::UnexpectedStatus);
            }
            if value != 0 {
                return Err(MalformedDeviceMutationReply::FailureValue);
            }
            return Ok(Self::Rejected(status as u32 as i32));
        }
        let device = NonZeroU64::new(value);
        if device.is_some() != returns_device {
            return Err(MalformedDeviceMutationReply::SuccessValue);
        }
        Ok(Self::Success(device))
    }

    pub const fn into_result(self) -> Result<Option<NonZeroU64>, i32> {
        match self {
            Self::Success(device) => Ok(device),
            Self::Rejected(status) => Err(status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_has_exact_operation_value_shape() {
        assert_eq!(
            DeviceMutationReply::decode(0, 0, [0; 2], false)
                .unwrap()
                .into_result(),
            Ok(None)
        );
        for value in [1, u32::MAX as u64 + 1, u64::MAX] {
            assert_eq!(
                DeviceMutationReply::decode(0, value, [0; 2], true)
                    .unwrap()
                    .into_result(),
                Ok(NonZeroU64::new(value))
            );
            assert_eq!(
                DeviceMutationReply::decode(0, value, [0; 2], false),
                Err(MalformedDeviceMutationReply::SuccessValue)
            );
        }
        assert_eq!(
            DeviceMutationReply::decode(0, 0, [0; 2], true),
            Err(MalformedDeviceMutationReply::SuccessValue)
        );
    }

    #[test]
    fn failure_preserves_status_but_never_returns_an_identity() {
        for status in [0x8000_0005u32, 0xc000_000d, 0xc000_0022, u32::MAX] {
            for returns_device in [false, true] {
                assert_eq!(
                    DeviceMutationReply::decode(status as u64, 0, [0; 2], returns_device)
                        .unwrap()
                        .into_result(),
                    Err(status as i32)
                );
                assert_eq!(
                    DeviceMutationReply::decode(status as u64, 1, [0; 2], returns_device),
                    Err(MalformedDeviceMutationReply::FailureValue)
                );
            }
        }
    }

    #[test]
    fn pending_and_informational_replies_do_not_authorize_projection_rollback() {
        for status in [1, 0x103, 0x4000_0000, 0x7fff_ffff] {
            for value in [0, 1, u64::MAX] {
                assert_eq!(
                    DeviceMutationReply::decode(status, value, [0; 2], true),
                    Err(MalformedDeviceMutationReply::UnexpectedStatus)
                );
            }
        }
    }

    #[test]
    fn noncanonical_status_width_and_reserved_words_are_ambiguous() {
        for status in [0x1_0000_0000, 0xffff_ffff_c000_0022, u64::MAX] {
            assert_eq!(
                DeviceMutationReply::decode(status, 0, [0; 2], false),
                Err(MalformedDeviceMutationReply::StatusUpperBits)
            );
        }
        for reserved in [[1, 0], [0, 1], [u64::MAX; 2]] {
            for status in [0, 0xc000_000d] {
                assert_eq!(
                    DeviceMutationReply::decode(status, 0, reserved, false),
                    Err(MalformedDeviceMutationReply::ReservedWords)
                );
            }
        }
    }
}
