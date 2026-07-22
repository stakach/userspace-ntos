//! Pure policy helpers for the target-side privilege acquisition wrappers.

use crate::{NtStatus, STATUS_INVALID_PARAMETER};

pub const RTL_ACQUIRE_PRIVILEGE_IMPERSONATE: u32 = 0x1;
pub const RTL_ACQUIRE_PRIVILEGE_PROCESS: u32 = 0x2;
pub const STATUS_NOT_ALL_ASSIGNED: NtStatus = 0x0000_0106;
pub const STATUS_PRIVILEGE_NOT_HELD: NtStatus = 0xC000_0061;

/// The token-selection action performed before privileges are adjusted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcquireStrategy {
    OpenExistingThreadToken,
    RevertThenDuplicateProcessToken,
    OpenProcessToken,
    DuplicateProcessToken,
}

/// Reject unsupported bits and apply ReactOS's PROCESS-implies-IMPERSONATE rule.
pub fn normalize_acquire_flags(flags: u32) -> Result<u32, NtStatus> {
    if flags & !(RTL_ACQUIRE_PRIVILEGE_IMPERSONATE | RTL_ACQUIRE_PRIVILEGE_PROCESS) != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(if flags & RTL_ACQUIRE_PRIVILEGE_PROCESS != 0 {
        flags | RTL_ACQUIRE_PRIVILEGE_IMPERSONATE
    } else {
        flags
    })
}

pub fn acquire_strategy(is_impersonating: bool, normalized_flags: u32) -> AcquireStrategy {
    if is_impersonating {
        if normalized_flags & RTL_ACQUIRE_PRIVILEGE_IMPERSONATE != 0 {
            AcquireStrategy::OpenExistingThreadToken
        } else {
            AcquireStrategy::RevertThenDuplicateProcessToken
        }
    } else if normalized_flags & RTL_ACQUIRE_PRIVILEGE_PROCESS != 0 {
        AcquireStrategy::OpenProcessToken
    } else {
        AcquireStrategy::DuplicateProcessToken
    }
}

/// Allocation used by ReactOS: state + one TOKEN_PRIVILEGES entry, plus the remaining entries.
/// The count subtraction is deliberately 32-bit wrapping to match the native ULONG expression.
pub fn acquire_allocation_size(count: u32) -> Option<usize> {
    const RTL_ACQUIRE_STATE_SIZE: usize = 0x428;
    const TOKEN_PRIVILEGES_ONE_SIZE: usize = 16;
    const LUID_AND_ATTRIBUTES_SIZE: usize = 12;
    RTL_ACQUIRE_STATE_SIZE
        .checked_add(TOKEN_PRIVILEGES_ONE_SIZE)?
        .checked_add(
            (count.wrapping_sub(1) as usize).checked_mul(LUID_AND_ATTRIBUTES_SIZE)?,
        )
}

/// ReactOS turns a one-privilege partial assignment into the more useful failure status.
pub fn normalize_adjust_status(count: u32, status: NtStatus) -> NtStatus {
    if count == 1 && status == STATUS_NOT_ALL_ASSIGNED {
        STATUS_PRIVILEGE_NOT_HELD
    } else {
        status
    }
}

#[inline]
pub const fn nt_success(status: NtStatus) -> bool {
    (status as i32) >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_validated_and_process_implies_impersonation() {
        assert_eq!(normalize_acquire_flags(0), Ok(0));
        assert_eq!(normalize_acquire_flags(1), Ok(1));
        assert_eq!(normalize_acquire_flags(2), Ok(3));
        assert_eq!(normalize_acquire_flags(3), Ok(3));
        assert_eq!(normalize_acquire_flags(4), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn strategy_covers_existing_and_new_token_paths() {
        assert_eq!(
            acquire_strategy(true, 1),
            AcquireStrategy::OpenExistingThreadToken
        );
        assert_eq!(
            acquire_strategy(true, 0),
            AcquireStrategy::RevertThenDuplicateProcessToken
        );
        assert_eq!(
            acquire_strategy(false, 3),
            AcquireStrategy::OpenProcessToken
        );
        assert_eq!(
            acquire_strategy(false, 0),
            AcquireStrategy::DuplicateProcessToken
        );
    }

    #[test]
    fn allocation_matches_native_flexible_array_layout() {
        assert_eq!(acquire_allocation_size(1), Some(1080));
        assert_eq!(acquire_allocation_size(2), Some(1092));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(acquire_allocation_size(0), Some(51_539_608_620));
    }

    #[test]
    fn only_single_privilege_partial_assignment_becomes_failure() {
        assert_eq!(
            normalize_adjust_status(1, STATUS_NOT_ALL_ASSIGNED),
            STATUS_PRIVILEGE_NOT_HELD
        );
        assert_eq!(
            normalize_adjust_status(2, STATUS_NOT_ALL_ASSIGNED),
            STATUS_NOT_ALL_ASSIGNED
        );
        assert_eq!(normalize_adjust_status(1, 0), 0);
        assert!(nt_success(STATUS_NOT_ALL_ASSIGNED));
        assert!(!nt_success(STATUS_PRIVILEGE_NOT_HELD));
    }
}
