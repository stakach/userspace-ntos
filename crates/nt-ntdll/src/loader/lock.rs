//! Host-testable contract helpers for `LdrLockLoaderLock` and `LdrUnlockLoaderLock`.

pub const LOCK_FLAG_RAISE_ON_ERRORS: u32 = 0x0000_0001;
pub const LOCK_FLAG_TRY_ONLY: u32 = 0x0000_0002;
pub const UNLOCK_FLAG_RAISE_ON_ERRORS: u32 = 0x0000_0001;

pub const DISPOSITION_INVALID: u32 = 0;
pub const DISPOSITION_LOCK_ACQUIRED: u32 = 1;
pub const DISPOSITION_LOCK_NOT_ACQUIRED: u32 = 2;

pub const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
pub const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
pub const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;

/// Validate a loader-lock request in the same parameter order as ReactOS ntdll.
pub fn validate_lock_request(
    flags: u32,
    has_disposition: bool,
    has_cookie: bool,
) -> Result<(), u32> {
    if flags & !(LOCK_FLAG_RAISE_ON_ERRORS | LOCK_FLAG_TRY_ONLY) != 0 {
        return Err(STATUS_INVALID_PARAMETER_1);
    }
    if !has_cookie {
        return Err(STATUS_INVALID_PARAMETER_3);
    }
    if flags & LOCK_FLAG_TRY_ONLY != 0 && !has_disposition {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    Ok(())
}

/// Build the opaque unlock cookie from the current thread and acquisition sequence.
pub fn make_cookie(thread_id: u64, acquisition_count: u32) -> usize {
    ((((thread_id as usize) & 0x0fff) << 16) | ((acquisition_count as usize) & 0xffff)) as usize
}

/// Validate unlock flags and ensure the cookie belongs to the current thread.
pub fn validate_unlock(flags: u32, cookie: usize, thread_id: u64) -> Result<(), u32> {
    if flags & !UNLOCK_FLAG_RAISE_ON_ERRORS != 0 {
        return Err(STATUS_INVALID_PARAMETER_1);
    }
    if cookie == 0 {
        return Ok(());
    }
    if cookie & 0xf000_0000 != 0 || ((cookie >> 16) ^ ((thread_id as usize) & 0x0fff)) != 0 {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_request_validation_matches_parameter_contract() {
        assert_eq!(
            validate_lock_request(4, true, true),
            Err(STATUS_INVALID_PARAMETER_1)
        );
        assert_eq!(
            validate_lock_request(0, true, false),
            Err(STATUS_INVALID_PARAMETER_3)
        );
        assert_eq!(
            validate_lock_request(LOCK_FLAG_TRY_ONLY, false, true),
            Err(STATUS_INVALID_PARAMETER_2)
        );
        assert_eq!(
            validate_lock_request(LOCK_FLAG_TRY_ONLY, true, true),
            Ok(())
        );
    }

    #[test]
    fn cookie_contains_low_thread_and_sequence_bits() {
        assert_eq!(make_cookie(0x1234, 0x1_0002), 0x0234_0002);
    }

    #[test]
    fn unlock_rejects_foreign_and_malformed_cookies() {
        let cookie = make_cookie(0x1234, 7);
        assert_eq!(validate_unlock(0, cookie, 0x2234), Ok(()));
        assert_eq!(
            validate_unlock(0, cookie, 0x1235),
            Err(STATUS_INVALID_PARAMETER_2)
        );
        assert_eq!(
            validate_unlock(0, cookie | 0x1000_0000, 0x1234),
            Err(STATUS_INVALID_PARAMETER_2)
        );
        assert_eq!(
            validate_unlock(2, cookie, 0x1234),
            Err(STATUS_INVALID_PARAMETER_1)
        );
        assert_eq!(validate_unlock(0, 0, 0x1234), Ok(()));
    }
}
