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

/// CREATE alone can return a failed publication whose physical ownership is still retained.
/// This outcome must not be flattened into a status that authorizes local projection rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceCreationReply {
    Success(NonZeroU64),
    Rejected(i32),
    Retained(i32),
}

impl DeviceCreationReply {
    pub const RETAINED_MARKER: u64 = 1;

    pub const fn decode(
        status: u64,
        value: u64,
        reserved: [u64; 2],
    ) -> Result<Self, MalformedDeviceMutationReply> {
        if reserved[0] == Self::RETAINED_MARKER && reserved[1] == 0 {
            if status > u32::MAX as u64 {
                return Err(MalformedDeviceMutationReply::StatusUpperBits);
            }
            if status & 0x8000_0000 == 0 {
                return Err(MalformedDeviceMutationReply::UnexpectedStatus);
            }
            if value != 0 {
                return Err(MalformedDeviceMutationReply::FailureValue);
            }
            return Ok(Self::Retained(status as u32 as i32));
        }
        match DeviceMutationReply::decode(status, value, reserved, true) {
            Ok(DeviceMutationReply::Success(Some(device))) => Ok(Self::Success(device)),
            Ok(DeviceMutationReply::Rejected(status)) => Ok(Self::Rejected(status)),
            Ok(DeviceMutationReply::Success(None)) => {
                Err(MalformedDeviceMutationReply::SuccessValue)
            }
            Err(error) => Err(error),
        }
    }
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
    fn creation_retained_failure_is_not_clean_rejection() {
        for status in [0x8000_0005u64, 0xc000_000d, 0xc000_009a] {
            assert_eq!(
                DeviceCreationReply::decode(status, 0, [1, 0]),
                Ok(DeviceCreationReply::Retained(status as u32 as i32))
            );
            assert_eq!(
                DeviceCreationReply::decode(status, 0, [0, 0]),
                Ok(DeviceCreationReply::Rejected(status as u32 as i32))
            );
            assert_eq!(
                DeviceMutationReply::decode(status, 0, [1, 0], true),
                Err(MalformedDeviceMutationReply::ReservedWords)
            );
        }
        assert_eq!(
            DeviceCreationReply::decode(0, 7, [0, 0]),
            Ok(DeviceCreationReply::Success(NonZeroU64::new(7).unwrap()))
        );
    }

    #[test]
    fn creation_retained_marker_requires_exact_failure_envelope() {
        for status in [0, 1, 0x103, 0x4000_0000, 0xffff_ffff_c000_0022] {
            assert!(DeviceCreationReply::decode(status, 0, [1, 0]).is_err());
        }
        for reserved in [[1, 1], [2, 0], [0, 1], [u64::MAX, 0]] {
            assert!(DeviceCreationReply::decode(0xc000_000d, 0, reserved).is_err());
        }
        assert_eq!(
            DeviceCreationReply::decode(0xc000_000d, 9, [1, 0]),
            Err(MalformedDeviceMutationReply::FailureValue)
        );
        assert_eq!(
            DeviceCreationReply::decode(0, 0, [0, 0]),
            Err(MalformedDeviceMutationReply::SuccessValue)
        );
    }

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
