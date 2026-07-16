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
        0x0000_0000 => 0,          // STATUS_SUCCESS -> ERROR_SUCCESS
        0x0000_0103 => 997,        // STATUS_PENDING -> ERROR_IO_PENDING
        0xC000_0001 => 31,         // STATUS_UNSUCCESSFUL -> ERROR_GEN_FAILURE
        0xC000_0002 => 1,          // STATUS_NOT_IMPLEMENTED -> ERROR_INVALID_FUNCTION
        0xC000_0008 => 6,          // STATUS_INVALID_HANDLE -> ERROR_INVALID_HANDLE
        0xC000_000D => 87,         // STATUS_INVALID_PARAMETER -> ERROR_INVALID_PARAMETER
        0xC000_000F => 2,          // STATUS_NO_SUCH_FILE -> ERROR_FILE_NOT_FOUND
        0xC000_0011 => 38,         // STATUS_END_OF_FILE -> ERROR_HANDLE_EOF
        0xC000_0022 => 5,          // STATUS_ACCESS_DENIED -> ERROR_ACCESS_DENIED
        0xC000_0023 => 122,        // STATUS_BUFFER_TOO_SMALL -> ERROR_INSUFFICIENT_BUFFER
        0xC000_0034 => 2,          // STATUS_OBJECT_NAME_NOT_FOUND -> ERROR_FILE_NOT_FOUND
        0xC000_0035 => 183,        // STATUS_OBJECT_NAME_COLLISION -> ERROR_ALREADY_EXISTS
        0xC000_003A => 3,          // STATUS_OBJECT_PATH_NOT_FOUND -> ERROR_PATH_NOT_FOUND
        0xC000_009A => 1450,       // STATUS_INSUFFICIENT_RESOURCES -> ERROR_NO_SYSTEM_RESOURCES
        0xC000_00BB => 50,         // STATUS_NOT_SUPPORTED -> ERROR_NOT_SUPPORTED
        0xC000_0135 => 126,        // STATUS_DLL_NOT_FOUND -> ERROR_MOD_NOT_FOUND
        0xC000_0139 => 127,        // STATUS_ENTRYPOINT_NOT_FOUND -> ERROR_PROC_NOT_FOUND
        0x8000_0005 => 234,        // STATUS_BUFFER_OVERFLOW -> ERROR_MORE_DATA
        0x0000_0102 => 258,        // STATUS_TIMEOUT -> WAIT_TIMEOUT
        _ => 13,                   // ERROR_MR_MID_NOT_FOUND (Windows default for unmapped)
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

/// `RtlVerifyVersionInfo` (the numeric-compare core): compare `(major, minor, build)` against a
/// required triple using a simple GTE test (the common `VerifyVersionInfo` "at least" query).
pub fn version_at_least(have: &OsVersion, want_major: u32, want_minor: u32, want_build: u32) -> bool {
    (have.major, have.minor, have.build) >= (want_major, want_minor, want_build)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
