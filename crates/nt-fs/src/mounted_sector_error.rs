//! Failure identity for a retained installed-volume sector claim.
//!
//! A lower device's authenticated NTSTATUS is distinct from a FAT parser failure. The
//! mounted File IRP must preserve the former and translate only the latter.

use nt_status::NtStatus;

use crate::{FatPathError, STATUS_DATA_ERROR};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountedSectorError {
    Provider(NtStatus),
    Fat(FatPathError),
}

impl MountedSectorError {
    pub const fn status(self) -> NtStatus {
        match self {
            Self::Provider(status) => status,
            Self::Fat(FatPathError::NoCapacity) => NtStatus::INSUFFICIENT_RESOURCES,
            Self::Fat(_) => NtStatus(STATUS_DATA_ERROR as i32),
        }
    }
}

impl From<FatPathError> for MountedSectorError {
    fn from(error: FatPathError) -> Self { Self::Fat(error) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_failure_survives_and_fat_corruption_is_data_error() {
        assert_eq!(MountedSectorError::Provider(NtStatus::INSUFFICIENT_RESOURCES).status(),
            NtStatus::INSUFFICIENT_RESOURCES);
        assert_eq!(MountedSectorError::Fat(FatPathError::NoCapacity).status(),
            NtStatus::INSUFFICIENT_RESOURCES);
        assert_eq!(MountedSectorError::Fat(FatPathError::Corrupt).status(),
            NtStatus(STATUS_DATA_ERROR as i32));
        assert_eq!(MountedSectorError::Fat(FatPathError::WrongRequest).status(),
            NtStatus(STATUS_DATA_ERROR as i32));
    }
}
