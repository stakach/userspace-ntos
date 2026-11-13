//! Storage operations for the legacy lock-based `ExInterlockedAdd*` exports.
//!
//! The native caller holds its supplied `KSPIN_LOCK` across each operation.

use core::ptr::{read_unaligned, write_unaligned};

/// Add to a possibly unaligned `LARGE_INTEGER`, returning its previous value.
///
/// # Safety
/// `addend` must point to a valid writable `i64`; the caller must hold the
/// corresponding spin lock.
pub unsafe fn add_large_integer(addend: *mut i64, increment: i64) -> i64 {
    let old = unsafe { read_unaligned(addend) };
    unsafe { write_unaligned(addend, old.wrapping_add(increment)) };
    old
}

/// Add to a possibly unaligned `ULONG`, returning its previous value.
///
/// # Safety
/// `addend` must point to a valid writable `u32`; the caller must hold the
/// corresponding spin lock.
pub unsafe fn add_ulong(addend: *mut u32, increment: u32) -> u32 {
    let old = unsafe { read_unaligned(addend) };
    unsafe { write_unaligned(addend, old.wrapping_add(increment)) };
    old
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_integer_returns_old_value_and_wraps() {
        let mut value = i64::MAX;
        assert_eq!(unsafe { add_large_integer(&mut value, 1) }, i64::MAX);
        assert_eq!(value, i64::MIN);
        assert_eq!(unsafe { add_large_integer(&mut value, -1) }, i64::MIN);
        assert_eq!(value, i64::MAX);
    }

    #[test]
    fn ulong_returns_old_value_and_wraps() {
        let mut value = u32::MAX;
        assert_eq!(unsafe { add_ulong(&mut value, 1) }, u32::MAX);
        assert_eq!(value, 0);
        assert_eq!(unsafe { add_ulong(&mut value, 3) }, 0);
        assert_eq!(value, 3);
    }

    #[test]
    fn writes_only_the_requested_unaligned_storage() {
        let mut bytes = [0xa5u8; 16];
        let ptr = unsafe { bytes.as_mut_ptr().add(1).cast::<i64>() };
        unsafe {
            write_unaligned(ptr, 7);
            assert_eq!(add_large_integer(ptr, 2), 7);
            assert_eq!(read_unaligned(ptr), 9);
        }
        assert_eq!(bytes[0], 0xa5);
        assert_eq!(&bytes[9..], &[0xa5; 7]);
    }
}
