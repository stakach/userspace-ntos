//! Admission and original inline completion policy for local SET_INFORMATION operations.

use nt_status::NtStatus;

const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_ALLOCATION_INFORMATION: u32 = 19;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;
const STATUS_INFO_LENGTH_MISMATCH: NtStatus = NtStatus(0xc000_0004u32 as i32);

/// Capture before mutation: a mode SET must not change its own completion policy.
/// Class, access and buffer-length contracts are validated separately by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalSetInformationPolicy {
    position_fast_path: bool,
}

impl LocalSetInformationPolicy {
    pub const fn capture(class: u32, synchronous_file: bool) -> Self {
        Self {
            position_fast_path: class == FILE_POSITION_INFORMATION && synchronous_file,
        }
    }

    /// False selects retain-only admission, preserving the FILE_OBJECT's existing signal state.
    pub const fn resets_file_signal(self) -> bool {
        !self.position_fast_path
    }

    /// Transport parking does not turn an original inline SET into a pending driver completion.
    pub const fn publishes_iosb(self, status: u32) -> bool {
        if self.position_fast_path {
            status == NtStatus::SUCCESS.raw() as u32
        } else {
            status != NtStatus::PENDING.raw() as u32 && status >> 30 != 3
        }
    }

    pub const fn signals_file(self, status: u32) -> bool {
        !self.position_fast_path && self.publishes_iosb(status)
    }
}

/// Reject negative signed LARGE_INTEGER values before a local scalar SET mutates its owner.
/// Other classes retain their own payload validators. Device alignment is a separate contract.
pub fn validate_local_set_information_value(class: u32, payload: &[u8]) -> Result<(), NtStatus> {
    if !matches!(
        class,
        FILE_POSITION_INFORMATION | FILE_ALLOCATION_INFORMATION | FILE_END_OF_FILE_INFORMATION
    ) {
        return Ok(());
    }
    let bytes: [u8; 8] = payload
        .get(..8)
        .ok_or(STATUS_INFO_LENGTH_MISMATCH)?
        .try_into()
        .map_err(|_| STATUS_INFO_LENGTH_MISMATCH)?;
    if i64::from_le_bytes(bytes) < 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synchronous_position_preserves_signal_and_only_publishes_success() {
        let policy = LocalSetInformationPolicy::capture(FILE_POSITION_INFORMATION, true);
        assert!(!policy.resets_file_signal());
        assert!(policy.publishes_iosb(0));
        for status in [0, 0x103, 0x4000_0001, 0x8000_0001, 0xc000_000d] {
            assert!(!policy.signals_file(status));
            assert_eq!(policy.publishes_iosb(status), status == 0);
        }
    }

    #[test]
    fn ordinary_inline_set_uses_identical_completion_policy_in_both_modes() {
        for synchronous in [false, true] {
            for class in [4, 10, 11, 13, 16, 19, 20, 40, 64] {
                let policy = LocalSetInformationPolicy::capture(class, synchronous);
                assert!(policy.resets_file_signal());
                for (status, publishes) in [
                    (0, true),
                    (0x4000_0001, true),
                    (0x8000_0001, true),
                    (0x8000_0005, true),
                    (0x103, false),
                    (0xc000_000d, false),
                    (0xffff_ffff, false),
                ] {
                    assert_eq!(policy.publishes_iosb(status), publishes);
                    assert_eq!(policy.signals_file(status), publishes);
                }
            }
        }
    }

    #[test]
    fn asynchronous_position_uses_ordinary_inline_set_not_flush_api_policy() {
        let policy = LocalSetInformationPolicy::capture(FILE_POSITION_INFORMATION, false);
        assert!(policy.resets_file_signal());
        assert!(policy.publishes_iosb(0));
        assert!(policy.signals_file(0));
        assert!(policy.publishes_iosb(0x8000_0001));
        assert!(policy.signals_file(0x8000_0001));
        assert!(!policy.publishes_iosb(0xc000_000d));
        assert!(!policy.signals_file(0xc000_000d));
        assert!(!policy.publishes_iosb(0x103));
    }

    #[test]
    fn every_signed_scalar_class_rejects_negative_and_accepts_nonnegative_values() {
        for class in [
            FILE_POSITION_INFORMATION,
            FILE_ALLOCATION_INFORMATION,
            FILE_END_OF_FILE_INFORMATION,
        ] {
            for value in [i64::MIN, -2, -1] {
                assert_eq!(
                    validate_local_set_information_value(class, &value.to_le_bytes()),
                    Err(NtStatus::INVALID_PARAMETER)
                );
            }
            for value in [0i64, 1, u32::MAX as i64, i64::MAX] {
                assert_eq!(
                    validate_local_set_information_value(class, &value.to_le_bytes()),
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn scalar_validation_requires_eight_bytes_and_ignores_trailing_bytes() {
        for class in [
            FILE_POSITION_INFORMATION,
            FILE_ALLOCATION_INFORMATION,
            FILE_END_OF_FILE_INFORMATION,
        ] {
            for length in 0..8 {
                assert_eq!(
                    validate_local_set_information_value(class, &[0; 8][..length]),
                    Err(STATUS_INFO_LENGTH_MISMATCH)
                );
            }
            let mut payload = [0xff; 16];
            payload[..8].copy_from_slice(&0i64.to_le_bytes());
            assert_eq!(
                validate_local_set_information_value(class, &payload),
                Ok(())
            );
        }
    }

    #[test]
    fn unrelated_class_payloads_keep_their_existing_validation_contracts() {
        for class in [0, 4, 10, 11, 13, 16, 39, 40, 64, u32::MAX] {
            assert_eq!(validate_local_set_information_value(class, &[]), Ok(()));
            assert_eq!(
                validate_local_set_information_value(class, &(-1i64).to_le_bytes()),
                Ok(())
            );
        }
    }
}
