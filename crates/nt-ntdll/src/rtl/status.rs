//! `Rtl*` status / error / version helpers.
//!
//! `RtlNtStatusToDosError` maps an `NTSTATUS` to a Win32 error code; `RtlGetLastNtStatus` /
//! `RtlSetLastWin32Error` read/write the per-thread error fields (`TEB.LastStatusValue @ 0x1250`,
//! `TEB.LastErrorValue @ 0x068` — see `nt-ntdll-layout`); `RtlGetVersion` reports the OS version.
//! The TEB-backed accessors are modelled over an explicit TEB reference so the logic is
//! host-testable; the real ntdll reads `NtCurrentTeb()`.
//!
//! Category A. Host-tested.

use nt_ntdll_layout::Teb;

/// A subset of the `NTSTATUS` → Win32 `RtlNtStatusToDosError` mapping covering the codes the early
/// boot / loader path produces. The full table is ~600 entries; this covers the common ones and
/// falls through to `ERROR_MR_MID_NOT_FOUND` (13, the Windows default for an unmapped status),
/// matching real ntdll's behaviour for statuses absent from its table.
pub fn nt_status_to_dos_error(status: u32) -> u32 {
    match status {
        0x0000_0000 => 0,    // STATUS_SUCCESS -> ERROR_SUCCESS
        0x0000_0103 => 997,  // STATUS_PENDING -> ERROR_IO_PENDING
        0xC000_0001 => 31,   // STATUS_UNSUCCESSFUL -> ERROR_GEN_FAILURE
        0xC000_0002 => 1,    // STATUS_NOT_IMPLEMENTED -> ERROR_INVALID_FUNCTION
        0xC000_0008 => 6,    // STATUS_INVALID_HANDLE -> ERROR_INVALID_HANDLE
        0xC000_000D => 87,   // STATUS_INVALID_PARAMETER -> ERROR_INVALID_PARAMETER
        0xC000_000F => 2,    // STATUS_NO_SUCH_FILE -> ERROR_FILE_NOT_FOUND
        0xC000_0011 => 38,   // STATUS_END_OF_FILE -> ERROR_HANDLE_EOF
        0xC000_0022 => 5,    // STATUS_ACCESS_DENIED -> ERROR_ACCESS_DENIED
        0xC000_0023 => 122,  // STATUS_BUFFER_TOO_SMALL -> ERROR_INSUFFICIENT_BUFFER
        0xC000_0034 => 2,    // STATUS_OBJECT_NAME_NOT_FOUND -> ERROR_FILE_NOT_FOUND
        0xC000_0035 => 183,  // STATUS_OBJECT_NAME_COLLISION -> ERROR_ALREADY_EXISTS
        0xC000_003A => 3,    // STATUS_OBJECT_PATH_NOT_FOUND -> ERROR_PATH_NOT_FOUND
        0xC000_009A => 1450, // STATUS_INSUFFICIENT_RESOURCES -> ERROR_NO_SYSTEM_RESOURCES
        0xC000_00BB => 50,   // STATUS_NOT_SUPPORTED -> ERROR_NOT_SUPPORTED
        0xC000_0135 => 126,  // STATUS_DLL_NOT_FOUND -> ERROR_MOD_NOT_FOUND
        0xC000_0139 => 127,  // STATUS_ENTRYPOINT_NOT_FOUND -> ERROR_PROC_NOT_FOUND
        0x8000_0005 => 234,  // STATUS_BUFFER_OVERFLOW -> ERROR_MORE_DATA
        0x0000_0102 => 258,  // STATUS_TIMEOUT -> WAIT_TIMEOUT
        _ => 13,             // ERROR_MR_MID_NOT_FOUND (Windows default for unmapped)
    }
}

/// `RtlGetLastNtStatus`: read `TEB.LastStatusValue`.
pub fn get_last_nt_status(teb: &Teb) -> u32 {
    teb.last_status_value
}

/// `RtlSetLastNtStatus`-ish: write `TEB.LastStatusValue` (ntdll sets both the status and the
/// derived Win32 error via `RtlSetLastWin32ErrorAndNtStatusFromNtStatus`).
pub fn set_last_nt_status(teb: &mut Teb, status: u32) {
    teb.last_status_value = status;
}

/// `RtlGetLastWin32Error`: read `TEB.LastErrorValue`.
pub fn get_last_win32_error(teb: &Teb) -> u32 {
    teb.last_error_value
}

/// `RtlSetLastWin32Error`: write `TEB.LastErrorValue`.
pub fn set_last_win32_error(teb: &mut Teb, error: u32) {
    teb.last_error_value = error;
}

/// `RtlSetLastWin32ErrorAndNtStatusFromNtStatus`: set both, deriving the Win32 error from the
/// status. Returns the status (matching ntdll, which returns it for tail-call convenience).
pub fn set_last_error_from_status(teb: &mut Teb, status: u32) -> u32 {
    teb.last_status_value = status;
    teb.last_error_value = nt_status_to_dos_error(status);
    status
}

/// `RtlGetNtGlobalFlags`: read `PEB.NtGlobalFlag` — modelled here as a direct accessor over the
/// value (the PEB read is a loader concern). Provided so callers have the pure accessor.
pub fn nt_global_flags(peb_nt_global_flag: u32) -> u32 {
    peb_nt_global_flag
}

/// `RTL_OSVERSIONINFOW`-style version triple. `RtlGetVersion` fills this in.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OsVersion {
    /// Major version (Windows 7 == 6).
    pub major: u32,
    /// Minor version (Windows 7 == 1).
    pub minor: u32,
    /// Build number.
    pub build: u32,
    /// Platform id (2 == `VER_PLATFORM_WIN32_NT`).
    pub platform_id: u32,
}

/// `RTL_OSVERSIONINFOEXW` fields used by `RtlVerifyVersionInfo`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OsVersionInfoEx {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform_id: u32,
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub suite_mask: u16,
    pub product_type: u8,
}

/// `RtlGetVersion`: the reported OS version. We report Windows 7 (6.1.7601) to match the ReactOS/
/// Win7 hosted binaries' expectations.
pub const fn get_version() -> OsVersion {
    OsVersion {
        major: 6,
        minor: 1,
        build: 7601,
        platform_id: 2,
    }
}

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_REVISION_MISMATCH: u32 = 0xC000_0059;

pub const VER_MINORVERSION: u32 = 0x0000_0001;
pub const VER_MAJORVERSION: u32 = 0x0000_0002;
pub const VER_BUILDNUMBER: u32 = 0x0000_0004;
pub const VER_PLATFORMID: u32 = 0x0000_0008;
pub const VER_SERVICEPACKMINOR: u32 = 0x0000_0010;
pub const VER_SERVICEPACKMAJOR: u32 = 0x0000_0020;
pub const VER_SUITENAME: u32 = 0x0000_0040;
pub const VER_PRODUCT_TYPE: u32 = 0x0000_0080;

pub const VER_EQUAL: u8 = 1;
pub const VER_GREATER: u8 = 2;
pub const VER_GREATER_EQUAL: u8 = 3;
pub const VER_LESS: u8 = 4;
pub const VER_LESS_EQUAL: u8 = 5;
pub const VER_AND: u8 = 6;
pub const VER_OR: u8 = 7;

const VER_CONDITION_MASK: u8 = 7;
const VER_NUM_BITS_PER_CONDITION_MASK: u32 = 3;

/// `RtlVerifyVersionInfo` (the numeric-compare core): compare `(major, minor, build)` against a
/// required triple using a simple GTE test (the common `VerifyVersionInfo` "at least" query).
pub fn version_at_least(
    have: &OsVersion,
    want_major: u32,
    want_minor: u32,
    want_build: u32,
) -> bool {
    (have.major, have.minor, have.build) >= (want_major, want_minor, want_build)
}

#[inline]
fn ver_compare(left: u32, right: u32, condition: u8) -> bool {
    match condition {
        VER_EQUAL => left == right,
        VER_GREATER => left > right,
        VER_GREATER_EQUAL => left >= right,
        VER_LESS => left < right,
        VER_LESS_EQUAL => left <= right,
        _ => false,
    }
}

/// Extract the 3-bit condition for a single `VER_*` type, matching ReactOS' bit positions.
pub fn version_condition(condition_mask: u64, type_mask: u32) -> u8 {
    let shift = if type_mask & VER_PRODUCT_TYPE != 0 {
        7
    } else if type_mask & VER_SUITENAME != 0 {
        6
    } else if type_mask & VER_PLATFORMID != 0 {
        3
    } else if type_mask & VER_BUILDNUMBER != 0 {
        2
    } else if type_mask & VER_MAJORVERSION != 0 {
        1
    } else if type_mask & VER_MINORVERSION != 0 {
        0
    } else if type_mask & VER_SERVICEPACKMAJOR != 0 {
        5
    } else if type_mask & VER_SERVICEPACKMINOR != 0 {
        4
    } else {
        return 0;
    };
    ((condition_mask >> (shift * VER_NUM_BITS_PER_CONDITION_MASK)) as u8) & VER_CONDITION_MASK
}

/// `VerSetConditionMask`: pack one condition into the Windows/ReactOS 3-bit condition mask.
pub fn version_condition_set(condition_mask: u64, type_mask: u32, condition: u8) -> u64 {
    if type_mask == 0 {
        return condition_mask;
    }
    let condition = condition & VER_CONDITION_MASK;
    if condition == 0 {
        return condition_mask;
    }
    let shift = if type_mask & VER_PRODUCT_TYPE != 0 {
        7
    } else if type_mask & VER_SUITENAME != 0 {
        6
    } else if type_mask & VER_SERVICEPACKMAJOR != 0 {
        5
    } else if type_mask & VER_SERVICEPACKMINOR != 0 {
        4
    } else if type_mask & VER_PLATFORMID != 0 {
        3
    } else if type_mask & VER_BUILDNUMBER != 0 {
        2
    } else if type_mask & VER_MAJORVERSION != 0 {
        1
    } else if type_mask & VER_MINORVERSION != 0 {
        0
    } else {
        return condition_mask;
    };
    condition_mask | ((condition as u64) << (shift * VER_NUM_BITS_PER_CONDITION_MASK))
}

/// ReactOS-compatible `RtlVerifyVersionInfo` comparison core.
pub fn verify_version_info(
    have: &OsVersionInfoEx,
    want: &OsVersionInfoEx,
    type_mask: u32,
    condition_mask: u64,
) -> u32 {
    if type_mask == 0 || condition_mask == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    if type_mask & VER_PRODUCT_TYPE != 0
        && !ver_compare(
            have.product_type as u32,
            want.product_type as u32,
            version_condition(condition_mask, VER_PRODUCT_TYPE),
        )
    {
        return STATUS_REVISION_MISMATCH;
    }

    if type_mask & VER_SUITENAME != 0 {
        match version_condition(condition_mask, VER_SUITENAME) {
            VER_AND => {
                if (want.suite_mask & have.suite_mask) != want.suite_mask {
                    return STATUS_REVISION_MISMATCH;
                }
            }
            VER_OR => {
                if (want.suite_mask & have.suite_mask) == 0 && want.suite_mask != 0 {
                    return STATUS_REVISION_MISMATCH;
                }
            }
            _ => return STATUS_INVALID_PARAMETER,
        }
    }

    if type_mask & VER_PLATFORMID != 0
        && !ver_compare(
            have.platform_id,
            want.platform_id,
            version_condition(condition_mask, VER_PLATFORMID),
        )
    {
        return STATUS_REVISION_MISMATCH;
    }

    if type_mask & VER_BUILDNUMBER != 0
        && !ver_compare(
            have.build,
            want.build,
            version_condition(condition_mask, VER_BUILDNUMBER),
        )
    {
        return STATUS_REVISION_MISMATCH;
    }

    let mut do_next_check = true;
    let mut condition = VER_EQUAL;

    if type_mask & VER_MAJORVERSION != 0 {
        condition = version_condition(condition_mask, VER_MAJORVERSION);
        do_next_check = want.major == have.major;
        let comparison = ver_compare(have.major, want.major, condition);
        if !comparison && !do_next_check {
            return STATUS_REVISION_MISMATCH;
        }
    }

    if do_next_check && type_mask & VER_MINORVERSION != 0 {
        if condition == VER_EQUAL {
            condition = version_condition(condition_mask, VER_MINORVERSION);
        }
        do_next_check = want.minor == have.minor;
        let comparison = ver_compare(have.minor, want.minor, condition);
        if !comparison && !do_next_check {
            return STATUS_REVISION_MISMATCH;
        }
    }

    if do_next_check && type_mask & VER_SERVICEPACKMAJOR != 0 {
        if condition == VER_EQUAL {
            condition = version_condition(condition_mask, VER_SERVICEPACKMAJOR);
        }
        do_next_check = want.service_pack_major == have.service_pack_major;
        let comparison = ver_compare(
            have.service_pack_major as u32,
            want.service_pack_major as u32,
            condition,
        );
        if !comparison && !do_next_check {
            return STATUS_REVISION_MISMATCH;
        }

        if do_next_check && type_mask & VER_SERVICEPACKMINOR != 0 {
            if condition == VER_EQUAL {
                condition = version_condition(condition_mask, VER_SERVICEPACKMINOR);
            }
            let comparison = ver_compare(
                have.service_pack_minor as u32,
                want.service_pack_minor as u32,
                condition,
            );
            if !comparison {
                return STATUS_REVISION_MISMATCH;
            }
        }
    }

    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win_52() -> OsVersionInfoEx {
        OsVersionInfoEx {
            major: 5,
            minor: 2,
            build: 3790,
            platform_id: 2,
            service_pack_major: 0,
            service_pack_minor: 0,
            suite_mask: 0x0100,
            product_type: 1,
        }
    }

    fn condition_mask(type_mask: u32, condition: u8) -> u64 {
        super::version_condition_set(0, type_mask, condition)
    }

    fn zeroed_teb() -> Teb {
        // SAFETY: Teb is a plain `#[repr(C)]` POD (no Drop, all-integer fields); an all-zero bit
        // pattern is a valid initialised value.
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn status_map_known() {
        assert_eq!(nt_status_to_dos_error(0), 0);
        assert_eq!(nt_status_to_dos_error(0xC000_0022), 5); // ACCESS_DENIED
        assert_eq!(nt_status_to_dos_error(0xC000_0135), 126); // DLL_NOT_FOUND -> MOD_NOT_FOUND
        assert_eq!(nt_status_to_dos_error(0x8000_0005), 234); // BUFFER_OVERFLOW -> MORE_DATA
        assert_eq!(nt_status_to_dos_error(0xDEAD_BEEF), 13); // unmapped default
    }

    #[test]
    fn teb_error_accessors() {
        let mut teb = zeroed_teb();
        set_last_win32_error(&mut teb, 5);
        assert_eq!(get_last_win32_error(&teb), 5);
        set_last_nt_status(&mut teb, 0xC000_0008);
        assert_eq!(get_last_nt_status(&teb), 0xC000_0008);
        // Combined setter derives the Win32 error from the status.
        set_last_error_from_status(&mut teb, 0xC000_0022);
        assert_eq!(get_last_nt_status(&teb), 0xC000_0022);
        assert_eq!(get_last_win32_error(&teb), 5); // ACCESS_DENIED
    }

    #[test]
    fn version() {
        let v = get_version();
        assert_eq!((v.major, v.minor, v.build), (6, 1, 7601));
        assert!(version_at_least(&v, 6, 0, 6000)); // >= Vista
        assert!(!version_at_least(&v, 6, 2, 9200)); // < Win8
    }

    #[test]
    fn verify_version_info_uses_reactos_lexicographic_version_checks() {
        let have = win_52();
        let mut want = have;
        want.major = 5;
        want.minor = 1;
        assert_eq!(
            verify_version_info(
                &have,
                &want,
                VER_MAJORVERSION | VER_MINORVERSION,
                condition_mask(VER_MAJORVERSION, VER_GREATER_EQUAL)
            ),
            STATUS_SUCCESS
        );

        want.minor = 3;
        assert_eq!(
            verify_version_info(
                &have,
                &want,
                VER_MAJORVERSION | VER_MINORVERSION,
                condition_mask(VER_MAJORVERSION, VER_GREATER_EQUAL)
            ),
            STATUS_REVISION_MISMATCH
        );

        want.major = 6;
        want.minor = 0;
        assert_eq!(
            verify_version_info(
                &have,
                &want,
                VER_MAJORVERSION | VER_MINORVERSION,
                condition_mask(VER_MAJORVERSION, VER_GREATER_EQUAL)
            ),
            STATUS_REVISION_MISMATCH
        );
    }

    #[test]
    fn verify_version_info_checks_build_platform_product_and_suite() {
        let have = win_52();
        let mut want = have;
        want.build = 3790;
        assert_eq!(
            verify_version_info(
                &have,
                &want,
                VER_BUILDNUMBER,
                condition_mask(VER_BUILDNUMBER, VER_EQUAL)
            ),
            STATUS_SUCCESS
        );
        want.platform_id = 1;
        assert_eq!(
            verify_version_info(
                &have,
                &want,
                VER_PLATFORMID,
                condition_mask(VER_PLATFORMID, VER_EQUAL)
            ),
            STATUS_REVISION_MISMATCH
        );
        want.product_type = 1;
        assert_eq!(
            verify_version_info(
                &have,
                &want,
                VER_PRODUCT_TYPE,
                condition_mask(VER_PRODUCT_TYPE, VER_EQUAL)
            ),
            STATUS_SUCCESS
        );
        want.suite_mask = 0x0100;
        assert_eq!(
            verify_version_info(
                &have,
                &want,
                VER_SUITENAME,
                condition_mask(VER_SUITENAME, VER_AND)
            ),
            STATUS_SUCCESS
        );
    }

    #[test]
    fn verify_version_info_rejects_missing_or_bad_conditions() {
        let have = win_52();
        assert_eq!(
            verify_version_info(&have, &have, 0, condition_mask(VER_MAJORVERSION, VER_EQUAL)),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            verify_version_info(&have, &have, VER_MAJORVERSION, 0),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            verify_version_info(
                &have,
                &have,
                VER_SUITENAME,
                condition_mask(VER_SUITENAME, VER_EQUAL)
            ),
            STATUS_INVALID_PARAMETER
        );
    }
}
