//! `Rtl*` status / error / version helpers.
//!
//! `RtlNtStatusToDosError` maps an `NTSTATUS` to a Win32 error code; `RtlGetLastNtStatus` /
//! `RtlSetLastWin32Error` read/write the per-thread error fields (`TEB.LastStatusValue @ 0x1250`,
//! `TEB.LastErrorValue @ 0x068` — see `nt-ntdll-layout`); `RtlGetVersion` reports the OS version.
//! The TEB-backed accessors are modelled over an explicit TEB reference so the logic is
//! host-testable; the real ntdll reads `NtCurrentTeb()`.
//!
//! Category A. Host-tested.

mod ntstatus_to_dos_error_map;

use nt_ntdll_layout::Teb;

use ntstatus_to_dos_error_map::*;

const ERROR_MR_MID_NOT_FOUND: u32 = 317;

fn nt_status_table_entry(status: u32) -> Option<u32> {
    let (start, table): (u32, &[u32]) = match status {
        0x0000_0102..=0x0000_0121 => (0x0000_0102, &TABLE_00000102),
        0x4000_0002..=0x4000_0025 => (0x4000_0002, &TABLE_40000002),
        0x4000_0370 => (0x4000_0370, &TABLE_40000370),
        0x4002_0056 => (0x4002_0056, &TABLE_40020056),
        0x4002_00AF => (0x4002_00AF, &TABLE_400200AF),
        0x8000_0001..=0x8000_0027 => (0x8000_0001, &TABLE_80000001),
        0x8000_0288..=0x8000_0289 => (0x8000_0288, &TABLE_80000288),
        0x8009_0300..=0x8009_0347 => (0x8009_0300, &TABLE_80090300),
        0x8009_2010..=0x8009_2013 => (0x8009_2010, &TABLE_80092010),
        0x8009_6004 => (0x8009_6004, &TABLE_80096004),
        0x8013_0001..=0x8013_0005 => (0x8013_0001, &TABLE_80130001),
        0xC000_0001..=0xC000_019B => (0xC000_0001, &TABLE_C0000001),
        0xC000_0202..=0xC000_038D => (0xC000_0202, &TABLE_C0000202),
        0xC002_0001..=0xC002_0063 => (0xC002_0001, &TABLE_C0020001),
        0xC003_0001..=0xC003_000C => (0xC003_0001, &TABLE_C0030001),
        0xC003_0059..=0xC003_0061 => (0xC003_0059, &TABLE_C0030059),
        0xC00A_0001..=0xC00A_0036 => (0xC00A_0001, &TABLE_C00A0001),
        0xC013_0001..=0xC013_0016 => (0xC013_0001, &TABLE_C0130001),
        0xC015_0001..=0xC015_0027 => (0xC015_0001, &TABLE_C0150001),
        _ => return None,
    };
    Some(table[(status - start) as usize])
}

/// Convert an `NTSTATUS` to the corresponding Win32 error.
///
/// This follows ReactOS `sdk/lib/rtl/error.c:RtlNtStatusToDosErrorNoTeb`, including its complete
/// 19-range table, intentional zero holes, customer-bit passthrough, `0xD...` aliases, and the
/// `FACILITY_NTWIN32`/Win32-HRESULT low-word cases.
pub fn nt_status_to_dos_error(mut status: u32) -> u32 {
    if status == 0 || status & 0x2000_0000 != 0 {
        return status;
    }

    // Customer-severity 0xD statuses alias their ordinary 0xC status.
    if status & 0xF000_0000 == 0xD000_0000 {
        status &= !0x1000_0000;
    }

    match nt_status_table_entry(status) {
        Some(0) => return ERROR_MR_MID_NOT_FOUND,
        Some(error) => return error,
        None => {}
    }

    if matches!(status >> 16, 0xC001 | 0x8007) {
        return status & 0xFFFF;
    }

    ERROR_MR_MID_NOT_FOUND
}

/// Translate an I/O completion packet into the first two arguments documented for
/// `LPOVERLAPPED_COMPLETION_ROUTINE`.
pub fn io_completion_callback_arguments(status: u32, information: u64) -> (u32, u32) {
    if status == 0 {
        (0, information as u32)
    } else {
        (nt_status_to_dos_error(status), 0)
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
    fn status_map_preserves_existing_exact_mappings() {
        assert_eq!(nt_status_to_dos_error(0), 0);
        assert_eq!(nt_status_to_dos_error(0x0000_0102), 1460); // STATUS_TIMEOUT
        assert_eq!(nt_status_to_dos_error(0x0000_0103), 997); // STATUS_PENDING
        assert_eq!(nt_status_to_dos_error(0xC000_0001), 31); // STATUS_UNSUCCESSFUL
        assert_eq!(nt_status_to_dos_error(0xC000_0002), 1); // STATUS_NOT_IMPLEMENTED
        assert_eq!(nt_status_to_dos_error(0xC000_0008), 6); // STATUS_INVALID_HANDLE
        assert_eq!(nt_status_to_dos_error(0xC000_000D), 87); // STATUS_INVALID_PARAMETER
        assert_eq!(nt_status_to_dos_error(0xC000_000F), 2); // STATUS_NO_SUCH_FILE
        assert_eq!(nt_status_to_dos_error(0xC000_0011), 38); // STATUS_END_OF_FILE
        assert_eq!(nt_status_to_dos_error(0xC000_0022), 5); // ACCESS_DENIED
        assert_eq!(nt_status_to_dos_error(0xC000_0023), 122); // BUFFER_TOO_SMALL
        assert_eq!(nt_status_to_dos_error(0xC000_0034), 2); // OBJECT_NAME_NOT_FOUND
        assert_eq!(nt_status_to_dos_error(0xC000_0035), 183); // OBJECT_NAME_COLLISION
        assert_eq!(nt_status_to_dos_error(0xC000_003A), 3); // OBJECT_PATH_NOT_FOUND
        assert_eq!(nt_status_to_dos_error(0xC000_009A), 1450); // INSUFFICIENT_RESOURCES
        assert_eq!(nt_status_to_dos_error(0xC000_00BB), 50); // NOT_SUPPORTED
        assert_eq!(nt_status_to_dos_error(0xC000_0135), 126); // DLL_NOT_FOUND -> MOD_NOT_FOUND
        assert_eq!(nt_status_to_dos_error(0x8000_0005), 234); // BUFFER_OVERFLOW -> MORE_DATA
        assert_eq!(nt_status_to_dos_error(0x8000_000D), 299); // PARTIAL_COPY
        assert_eq!(nt_status_to_dos_error(0xDEAD_BEEF), 317); // unmapped default
    }

    #[test]
    fn status_map_covers_every_reactos_range_boundary() {
        let boundaries = [
            (0x0000_0102, 1460),
            (0x0000_0121, 8201),
            (0x4000_0002, 87),
            (0x4000_0025, 722),
            (0x4000_0370, 8364),
            (0x4002_0056, 1824),
            (0x4002_00AF, 1913),
            (0x8000_0001, 0x8000_0001),
            (0x8000_0027, 4340),
            (0x8000_0288, 1165),
            (0x8000_0289, 1166),
            (0x8009_0300, 1450),
            (0x8009_0347, 1368),
            (0x8009_2010, 1397),
            (0x8009_2013, 1397),
            (0x8009_6004, 1397),
            (0x8013_0001, 5061),
            (0x8013_0005, 5065),
            (0xC000_0001, 31),
            (0xC000_019B, 1810),
            (0xC000_0202, 1394),
            (0xC000_038D, 0x8009_0355),
            (0xC002_0001, 1700),
            (0xC002_0063, 1915),
            (0xC003_0001, 1772),
            (0xC003_000C, 1783),
            (0xC003_0059, 1827),
            (0xC003_0061, 1918),
            (0xC00A_0001, 7001),
            (0xC00A_0036, 7057),
            (0xC013_0001, 5039),
            (0xC013_0016, 5060),
            (0xC015_0001, 14000),
            (0xC015_0027, 14110),
        ];
        for (status, error) in boundaries {
            assert_eq!(nt_status_to_dos_error(status), error, "{status:#010x}");
        }
    }

    #[test]
    fn status_map_handles_holes_aliases_and_facilities() {
        assert_eq!(nt_status_to_dos_error(0x0000_0101), ERROR_MR_MID_NOT_FOUND);
        assert_eq!(nt_status_to_dos_error(0x0000_0104), ERROR_MR_MID_NOT_FOUND);
        assert_eq!(nt_status_to_dos_error(0x0000_0122), ERROR_MR_MID_NOT_FOUND);
        assert_eq!(nt_status_to_dos_error(0xC015_0028), ERROR_MR_MID_NOT_FOUND);

        assert_eq!(nt_status_to_dos_error(0x2000_1234), 0x2000_1234);
        assert_eq!(nt_status_to_dos_error(0xD000_0022), 5);
        assert_eq!(nt_status_to_dos_error(0xC001_1234), 0x1234);
        assert_eq!(nt_status_to_dos_error(0x8007_0057), 0x57);
    }

    #[test]
    fn io_completion_callback_uses_win32_error_and_dword_byte_count() {
        assert_eq!(io_completion_callback_arguments(0, 0x1_0000_0003), (0, 3));
        assert_eq!(io_completion_callback_arguments(0xC000_0022, 99), (5, 0));
        assert_eq!(io_completion_callback_arguments(0x8000_0005, 99), (234, 0));
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
