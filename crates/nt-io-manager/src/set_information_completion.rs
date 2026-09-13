//! Payload capture and original inline completion policy for SET_INFORMATION operations.

use alloc::vec::Vec;
use nt_status::NtStatus;

const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_ALLOCATION_INFORMATION: u32 = 19;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;
const STATUS_INFO_LENGTH_MISMATCH: NtStatus = NtStatus(0xc000_0004u32 as i32);

/// Capture before mutation: a mode SET must not change its own completion policy.
/// Class, access and buffer-length contracts are validated separately by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetInformationCompletionPolicy {
    position_fast_path: bool,
}

impl SetInformationCompletionPolicy {
    pub const fn capture(class: u32, synchronous_file: bool) -> Self {
        Self {
            position_fast_path: class == FILE_POSITION_INFORMATION && synchronous_file,
        }
    }

    /// A real driver dispatch uses ordinary inline completion policy even for
    /// a synchronous position SET; it is not the local position fast path.
    pub const fn immediate_driver() -> Self {
        Self {
            position_fast_path: false,
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

/// Copy a SET payload into owned fallibly allocated storage without publishing
/// an IOSB or changing event state. The caller owns admission and completion.
pub fn capture_set_information_payload(
    length: usize,
    copy: impl FnOnce(&mut [u8]) -> Result<(), NtStatus>,
) -> Result<Vec<u8>, NtStatus> {
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
    payload.resize(length, 0);
    copy(&mut payload)?;
    Ok(payload)
}

/// Publish an eligible original driver SET completion in NT IOSB order. A user
/// store fault does not replace the operation's result; an Information fault
/// stops publication before Status. Local position-fast-path publication is separate.
pub fn publish_immediate_set_iosb(
    status: u32,
    information: u64,
    mut store: impl FnMut(usize, &[u8]) -> Result<(), NtStatus>,
) {
    if !SetInformationCompletionPolicy::immediate_driver().publishes_iosb(status) {
        return;
    }
    if store(8, &information.to_le_bytes()).is_err() {
        return;
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    let _ = store(0, &status.to_le_bytes());
}

/// Reject negative signed LARGE_INTEGER values before a scalar SET mutates its owner.
/// Other classes retain their own payload validators. Device alignment is a separate contract.
pub fn validate_set_information_value(class: u32, payload: &[u8]) -> Result<(), NtStatus> {
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
        let policy = SetInformationCompletionPolicy::capture(FILE_POSITION_INFORMATION, true);
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
                let policy = SetInformationCompletionPolicy::capture(class, synchronous);
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
        let policy = SetInformationCompletionPolicy::capture(FILE_POSITION_INFORMATION, false);
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
                    validate_set_information_value(class, &value.to_le_bytes()),
                    Err(NtStatus::INVALID_PARAMETER)
                );
            }
            for value in [0i64, 1, u32::MAX as i64, i64::MAX] {
                assert_eq!(
                    validate_set_information_value(class, &value.to_le_bytes()),
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
                    validate_set_information_value(class, &[0; 8][..length]),
                    Err(STATUS_INFO_LENGTH_MISMATCH)
                );
            }
            let mut payload = [0xff; 16];
            payload[..8].copy_from_slice(&0i64.to_le_bytes());
            assert_eq!(validate_set_information_value(class, &payload), Ok(()));
        }
    }

    #[test]
    fn unrelated_class_payloads_keep_their_existing_validation_contracts() {
        for class in [0, 4, 10, 11, 13, 16, 39, 40, 64, u32::MAX] {
            assert_eq!(validate_set_information_value(class, &[]), Ok(()));
            assert_eq!(
                validate_set_information_value(class, &(-1i64).to_le_bytes()),
                Ok(())
            );
        }
    }

    #[test]
    fn immediate_driver_policy_does_not_take_a_synchronous_position_fast_path() {
        for synchronous in [false, true] {
            let policy = SetInformationCompletionPolicy::immediate_driver();
            let position =
                SetInformationCompletionPolicy::capture(FILE_POSITION_INFORMATION, synchronous);
            assert!(policy.resets_file_signal());
            assert_eq!(position.resets_file_signal(), !synchronous);
            for (status, publishes) in [
                (0, true),
                (0x4000_0001, true),
                (0x8000_0005, true),
                (0x103, false),
                (0xc000_000d, false),
            ] {
                assert_eq!(policy.publishes_iosb(status), publishes);
                assert_eq!(policy.signals_file(status), publishes);
            }
        }
    }

    #[test]
    fn set_information_payload_allocation_refusal_does_not_invoke_copy() {
        assert_eq!(
            capture_set_information_payload(usize::MAX, |_| panic!("allocation must precede copy")),
            Err(NtStatus::INSUFFICIENT_RESOURCES)
        );
    }

    #[test]
    fn set_information_payload_copy_failure_preserves_status_and_discards_partial_bytes() {
        let mut copies = 0;
        let result = capture_set_information_payload(8, |bytes| {
            copies += 1;
            assert_eq!(bytes, &[0; 8]);
            bytes[..4].copy_from_slice(&[1, 2, 3, 4]);
            Err(NtStatus::ACCESS_VIOLATION)
        });
        assert_eq!(copies, 1);
        assert_eq!(result, Err(NtStatus::ACCESS_VIOLATION));
    }

    #[test]
    fn set_information_payload_returns_exact_owned_bytes_including_empty_input() {
        for length in [0, 1, 8, 64] {
            let mut input = alloc::vec![0x5a; length];
            let mut copies = 0;
            let payload = capture_set_information_payload(length, |bytes| {
                copies += 1;
                bytes.copy_from_slice(&input);
                Ok(())
            })
            .unwrap();
            input.fill(0xaa);
            assert_eq!(copies, 1);
            assert_eq!(payload, alloc::vec![0x5a; length]);
        }
    }

    #[test]
    fn immediate_set_iosb_publishes_information_before_status_for_success_and_warnings() {
        for status in [0u32, 0x4000_0001, 0x8000_0005] {
            let mut writes = Vec::new();
            let information = 0x1234_5678_9abc_def0u64;
            publish_immediate_set_iosb(status, information, |offset, bytes| {
                writes.push((offset, bytes.to_vec()));
                Ok(())
            });
            assert_eq!(
                writes,
                alloc::vec![
                    (8, information.to_le_bytes().to_vec()),
                    (0, status.to_le_bytes().to_vec()),
                ]
            );
        }
    }

    #[test]
    fn immediate_set_iosb_does_not_publish_pending_or_error_status() {
        for status in [0x103, 0xc000_000d, 0xc000_0005, u32::MAX] {
            publish_immediate_set_iosb(status, 17, |_, _| {
                panic!("pending and NT_ERROR must not publish an immediate IOSB")
            });
        }
    }

    #[test]
    fn immediate_set_iosb_ignores_store_failures_and_stops_after_information_fault() {
        for fail_at in [8, 0] {
            let mut offsets = Vec::new();
            publish_immediate_set_iosb(0x8000_0005, 17, |offset, _| {
                offsets.push(offset);
                if offset == fail_at {
                    Err(NtStatus::ACCESS_VIOLATION)
                } else {
                    Ok(())
                }
            });
            assert_eq!(
                offsets,
                if fail_at == 8 {
                    alloc::vec![8]
                } else {
                    alloc::vec![8, 0]
                }
            );
        }
    }
}
