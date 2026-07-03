//! # `nt-status` — NTSTATUS-style status codes
//!
//! A thin, `no_std` wrapper over the Windows NT `NTSTATUS` code space, used at
//! every public NT boundary in the userspace-ntos personality. Values are the
//! real Windows codes (behavioural compatibility is the goal), so a status that
//! escapes to a native client matches what NT would return.
//!
//! An `NTSTATUS` is an `i32`; its top two bits are the *severity* (0 success,
//! 1 informational, 2 warning, 3 error). "Success" — the `NT_SUCCESS` macro —
//! is simply `status >= 0` (top bit clear), which is what [`NtStatus::is_success`]
//! reports.

#![no_std]

/// An NT status code. See the module docs.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NtStatus(pub i32);

impl NtStatus {
    /// The raw `i32` value.
    #[inline]
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// `NT_SUCCESS`: severity success or informational (top bit clear).
    #[inline]
    pub const fn is_success(self) -> bool {
        self.0 >= 0
    }

    /// Severity error or warning (top bit set / negative).
    #[inline]
    pub const fn is_error(self) -> bool {
        self.0 < 0
    }

    /// `Ok(())` on success, `Err(self)` on error — for `?` at NT boundaries.
    #[inline]
    pub const fn to_result(self) -> Result<(), NtStatus> {
        if self.is_success() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

impl core::fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Show the canonical name when known, else the hex code.
        match KNOWN.iter().find(|(v, _)| *v == self.0) {
            Some((_, name)) => write!(f, "NtStatus({name})"),
            None => write!(f, "NtStatus(0x{:08X})", self.0 as u32),
        }
    }
}

/// Declare the status constants once, and build the name table for `Debug` from
/// the same list so they can never drift.
macro_rules! statuses {
    ($( $(#[$m:meta])* $name:ident = $val:expr; )+) => {
        impl NtStatus {
            $( $(#[$m])* pub const $name: NtStatus = NtStatus($val as u32 as i32); )+
        }
        const KNOWN: &[(i32, &str)] = &[
            $( ($val as u32 as i32, stringify!($name)), )+
        ];
    };
}

statuses! {
    /// The operation completed successfully.
    SUCCESS = 0x0000_0000u32;
    /// The operation is pending / asynchronous.
    PENDING = 0x0000_0103u32;
    /// The object name was not found.
    OBJECT_NAME_NOT_FOUND = 0xC000_0034u32;
    /// An object with that name already exists.
    OBJECT_NAME_COLLISION = 0xC000_0035u32;
    /// A component of the object path was not found.
    OBJECT_PATH_NOT_FOUND = 0xC000_003Au32;
    /// The handle is invalid (unknown or stale).
    INVALID_HANDLE = 0xC000_0008u32;
    /// A parameter was invalid.
    INVALID_PARAMETER = 0xC000_000Du32;
    /// Access was denied.
    ACCESS_DENIED = 0xC000_0022u32;
    /// Insufficient resources (out of slots/memory).
    INSUFFICIENT_RESOURCES = 0xC000_009Au32;
    /// The object is not of the expected type.
    OBJECT_TYPE_MISMATCH = 0xC000_0024u32;
    /// The object is being deleted.
    DELETE_PENDING = 0xC000_0056u32;
    /// The requested operation is not implemented.
    NOT_IMPLEMENTED = 0xC000_0002u32;
    /// The request is not supported.
    NOT_SUPPORTED = 0xC000_00BBu32;
    /// A general failure (catch-all, e.g. a faulted transport).
    UNSUCCESSFUL = 0xC000_0001u32;
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn success_vs_error() {
        assert!(NtStatus::SUCCESS.is_success());
        assert!(NtStatus::PENDING.is_success()); // informational, top bit clear
        assert!(!NtStatus::SUCCESS.is_error());
        assert!(NtStatus::OBJECT_NAME_NOT_FOUND.is_error());
        assert!(NtStatus::INVALID_HANDLE.is_error());
        assert!(!NtStatus::INVALID_HANDLE.is_success());
    }

    #[test]
    fn to_result_maps() {
        assert_eq!(NtStatus::SUCCESS.to_result(), Ok(()));
        assert_eq!(
            NtStatus::ACCESS_DENIED.to_result(),
            Err(NtStatus::ACCESS_DENIED)
        );
    }

    #[test]
    fn real_ntstatus_values() {
        // Guard against typos — these are the real Windows codes.
        assert_eq!(NtStatus::SUCCESS.raw(), 0);
        assert_eq!(NtStatus::OBJECT_NAME_NOT_FOUND.0 as u32, 0xC000_0034);
        assert_eq!(NtStatus::INVALID_HANDLE.0 as u32, 0xC000_0008);
        assert_eq!(NtStatus::OBJECT_TYPE_MISMATCH.0 as u32, 0xC000_0024);
    }

    #[test]
    fn debug_names_known_codes() {
        use std::format;
        assert_eq!(
            format!("{:?}", NtStatus::ACCESS_DENIED),
            "NtStatus(ACCESS_DENIED)"
        );
        assert_eq!(format!("{:?}", NtStatus(0x1234)), "NtStatus(0x00001234)");
    }
}
