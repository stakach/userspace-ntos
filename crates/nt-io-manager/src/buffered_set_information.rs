//! Capture buffered EA/quota updates after the caller has acquired File I/O ownership.

use alloc::vec::Vec;
use nt_status::NtStatus;

use crate::{validate_ea_buffer, validate_set_quota_buffer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferedSetInformationKind {
    Ea,
    Quota,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferedSetInformationError {
    Capture(NtStatus),
    Malformed { status: NtStatus, offset: usize },
}

impl BufferedSetInformationError {
    /// Publish only malformed-list diagnostics. The caller must retain File ownership until
    /// this returns. Allocation/copy failures leave the IOSB untouched.
    pub fn publish(self, mut write: impl FnMut(usize, &[u8]) -> bool) -> NtStatus {
        match self {
            Self::Capture(status) => status,
            Self::Malformed { status, offset } => {
                if !write(0, &status.raw().to_le_bytes())
                    || !write(8, &(offset as u64).to_le_bytes())
                {
                    NtStatus::ACCESS_VIOLATION
                } else {
                    status
                }
            }
        }
    }
}

/// The caller retains the authenticated File and has completed any required Busy acquisition.
/// The copy callback may reenter; this helper does not acquire or release File ownership.
pub fn capture_buffered_set_information(
    kind: BufferedSetInformationKind,
    length: usize,
    copy: impl FnOnce(&mut [u8]) -> Result<(), NtStatus>,
) -> Result<Vec<u8>, BufferedSetInformationError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| BufferedSetInformationError::Capture(NtStatus::INSUFFICIENT_RESOURCES))?;
    bytes.resize(length, 0);
    if length != 0 {
        copy(&mut bytes).map_err(BufferedSetInformationError::Capture)?;
    }
    match kind {
        BufferedSetInformationKind::Ea if length == 0 => {}
        BufferedSetInformationKind::Ea => {
            validate_ea_buffer(&bytes).map_err(|error| BufferedSetInformationError::Malformed {
                status: NtStatus::EA_LIST_INCONSISTENT,
                offset: error.offset,
            })?;
        }
        BufferedSetInformationKind::Quota => {
            validate_set_quota_buffer(&bytes).map_err(|error| {
                BufferedSetInformationError::Malformed {
                    status: NtStatus::QUOTA_LIST_INCONSISTENT,
                    offset: error.offset,
                }
            })?;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn ea() -> Vec<u8> {
        vec![0, 0, 0, 0, 0, 1, 1, 0, b'A', 0, 7]
    }

    fn quota() -> Vec<u8> {
        let mut bytes = vec![0; 40];
        let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        bytes[4..8].copy_from_slice(&(sid.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&sid);
        bytes
    }

    fn capture(
        kind: BufferedSetInformationKind,
        input: &[u8],
    ) -> Result<Vec<u8>, BufferedSetInformationError> {
        capture_buffered_set_information(kind, input.len(), |bytes| {
            assert!(bytes.iter().all(|byte| *byte == 0));
            bytes.copy_from_slice(input);
            Ok(())
        })
    }

    #[test]
    fn valid_updates_preserve_exact_copied_bytes() {
        for (kind, bytes) in [
            (BufferedSetInformationKind::Ea, ea()),
            (BufferedSetInformationKind::Quota, quota()),
        ] {
            assert_eq!(capture(kind, &bytes), Ok(bytes));
        }
    }

    #[test]
    fn capacity_refusal_does_not_copy_or_publish_iosb() {
        for kind in [
            BufferedSetInformationKind::Ea,
            BufferedSetInformationKind::Quota,
        ] {
            let error = capture_buffered_set_information(kind, usize::MAX, |_| {
                panic!("refused allocation must not copy input")
            })
            .unwrap_err();
            assert_eq!(
                error,
                BufferedSetInformationError::Capture(NtStatus::INSUFFICIENT_RESOURCES)
            );
            assert_eq!(
                error.publish(|_, _| panic!("allocation refusal must not touch IOSB")),
                NtStatus::INSUFFICIENT_RESOURCES,
            );
        }
    }

    #[test]
    fn copy_fault_discards_partial_bytes_without_validation_or_iosb() {
        for kind in [
            BufferedSetInformationKind::Ea,
            BufferedSetInformationKind::Quota,
        ] {
            let error = capture_buffered_set_information(kind, 64, |bytes| {
                bytes[0] = 0xff;
                Err(NtStatus::ACCESS_VIOLATION)
            })
            .unwrap_err();
            assert_eq!(
                error,
                BufferedSetInformationError::Capture(NtStatus::ACCESS_VIOLATION)
            );
            assert_eq!(
                error.publish(|_, _| panic!("copy failure must not touch IOSB")),
                NtStatus::ACCESS_VIOLATION,
            );
        }
    }

    #[test]
    fn zero_length_ea_is_empty_but_quota_is_malformed_without_copy() {
        assert_eq!(
            capture_buffered_set_information(BufferedSetInformationKind::Ea, 0, |_| {
                panic!("zero-length EA must not copy input")
            }),
            Ok(Vec::new()),
        );
        assert_eq!(
            capture_buffered_set_information(BufferedSetInformationKind::Quota, 0, |_| {
                panic!("zero-length quota must not copy input")
            }),
            Err(BufferedSetInformationError::Malformed {
                status: NtStatus::QUOTA_LIST_INCONSISTENT,
                offset: 0,
            }),
        );
    }

    #[test]
    fn malformed_updates_report_the_exact_nonzero_record_offset() {
        let mut bad_ea = ea();
        bad_ea.resize(12, 0);
        bad_ea[..4].copy_from_slice(&12_u32.to_le_bytes());
        bad_ea.extend_from_slice(&[0; 7]);
        let mut bad_quota = quota();
        bad_quota.resize(56, 0);
        bad_quota[..4].copy_from_slice(&56_u32.to_le_bytes());
        bad_quota.extend_from_slice(&[0; 7]);
        for (kind, bytes, status, offset) in [
            (
                BufferedSetInformationKind::Ea,
                bad_ea,
                NtStatus::EA_LIST_INCONSISTENT,
                12,
            ),
            (
                BufferedSetInformationKind::Quota,
                bad_quota,
                NtStatus::QUOTA_LIST_INCONSISTENT,
                56,
            ),
        ] {
            assert_eq!(
                capture(kind, &bytes),
                Err(BufferedSetInformationError::Malformed { status, offset })
            );
        }
    }

    #[test]
    fn malformed_publication_writes_status_then_information_without_padding() {
        let mut iosb = [0xa5; 16];
        let mut writes = Vec::new();
        let status = NtStatus::EA_LIST_INCONSISTENT;
        let result = BufferedSetInformationError::Malformed { status, offset: 12 }.publish(
            |offset, bytes| {
                writes.push((offset, bytes.len()));
                iosb[offset..offset + bytes.len()].copy_from_slice(bytes);
                true
            },
        );
        assert_eq!(result, status);
        assert_eq!(writes, [(0, 4), (8, 8)]);
        assert_eq!(&iosb[..4], &status.raw().to_le_bytes());
        assert_eq!(&iosb[4..8], &[0xa5; 4]);
        assert_eq!(&iosb[8..], &12_u64.to_le_bytes());
    }

    #[test]
    fn status_write_fault_stops_before_information() {
        let mut writes = Vec::new();
        let result = BufferedSetInformationError::Malformed {
            status: NtStatus::EA_LIST_INCONSISTENT,
            offset: 12,
        }
        .publish(|offset, bytes| {
            writes.push((offset, bytes.len()));
            false
        });
        assert_eq!(result, NtStatus::ACCESS_VIOLATION);
        assert_eq!(writes, [(0, 4)]);
    }

    #[test]
    fn information_write_fault_preserves_written_status_and_padding() {
        let mut iosb = [0xa5; 16];
        let mut writes = Vec::new();
        let status = NtStatus::QUOTA_LIST_INCONSISTENT;
        let result = BufferedSetInformationError::Malformed { status, offset: 56 }.publish(
            |offset, bytes| {
                writes.push((offset, bytes.len()));
                if offset != 0 {
                    return false;
                }
                iosb[..bytes.len()].copy_from_slice(bytes);
                true
            },
        );
        assert_eq!(result, NtStatus::ACCESS_VIOLATION);
        assert_eq!(writes, [(0, 4), (8, 8)]);
        assert_eq!(&iosb[..4], &status.raw().to_le_bytes());
        assert_eq!(&iosb[4..], &[0xa5; 12]);
    }
}
