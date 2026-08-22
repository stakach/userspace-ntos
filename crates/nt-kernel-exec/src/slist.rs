//! x64 sequenced singly-linked lists (`SLIST_HEADER`).
//!
//! NT's 16-byte header stores `Depth` and `Sequence` in the first word and an aligned
//! `NextEntry` plus the `HeaderType`/`Init` bits in the second. Hosted kernel components are
//! single-threaded at an import boundary, so they do not need `cmpxchg16b`, but they must preserve
//! the native encoding because callers may inspect the header through public WDK macros.

use core::ptr::{read_unaligned, write_unaligned};

const DEPTH_MASK: u64 = 0xffff;
const SEQUENCE_MASK: u64 = !DEPTH_MASK;
const HEADER_FLAGS: u64 = 0b11;
const POINTER_MASK: u64 = !0x0f;

/// Return the current `SLIST_HEADER.Depth` value.
///
/// # Safety
/// `head` must address a readable 16-byte x64 `SLIST_HEADER`.
pub unsafe fn query_depth(head: *const u8) -> u16 {
    read_unaligned(head as *const u16)
}

/// Push one 16-byte-aligned entry and return the previous head entry.
///
/// # Safety
/// `head` must address a writable 16-byte x64 `SLIST_HEADER`; `entry` must be either zero or a
/// writable, 16-byte-aligned `SLIST_ENTRY` whose first word is available for `Next`.
pub unsafe fn push(head: *mut u8, entry: u64) -> u64 {
    if head.is_null() || entry == 0 || entry & 0x0f != 0 {
        return 0;
    }

    let alignment = read_unaligned(head as *const u64);
    let region = read_unaligned(head.add(8) as *const u64);
    let previous = region & POINTER_MASK;
    write_unaligned(entry as *mut u64, previous);

    let depth = (alignment as u16).wrapping_add(1) as u64;
    let sequence = ((alignment >> 16).wrapping_add(1)) & (SEQUENCE_MASK >> 16);
    write_unaligned(head as *mut u64, (sequence << 16) | depth);
    write_unaligned(head.add(8) as *mut u64, entry | HEADER_FLAGS);
    previous
}

/// Pop one entry and return it, or zero when the list is empty.
///
/// # Safety
/// `head` must address a writable 16-byte x64 `SLIST_HEADER`; every linked entry must be readable
/// for its first `Next` word.
pub unsafe fn pop(head: *mut u8) -> u64 {
    if head.is_null() {
        return 0;
    }

    let region = read_unaligned(head.add(8) as *const u64);
    let entry = region & POINTER_MASK;
    if entry == 0 {
        return 0;
    }

    let next = read_unaligned(entry as *const u64);
    let alignment = read_unaligned(head as *const u64);
    let depth = (alignment as u16).wrapping_sub(1) as u64;
    write_unaligned(head as *mut u64, (alignment & SEQUENCE_MASK) | depth);
    write_unaligned(
        head.add(8) as *mut u64,
        (next & POINTER_MASK) | HEADER_FLAGS,
    );
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(16))]
    struct Entry {
        next: u64,
        payload: u64,
    }

    #[test]
    fn push_pop_preserves_native_header_encoding() {
        let mut header = [0u64; 2];
        let mut first = Entry {
            next: 0,
            payload: 1,
        };
        let mut second = Entry {
            next: 0,
            payload: 2,
        };
        let first_ptr = &mut first as *mut Entry as u64;
        let second_ptr = &mut second as *mut Entry as u64;

        unsafe {
            assert_eq!(push(header.as_mut_ptr() as *mut u8, first_ptr), 0);
            assert_eq!(query_depth(header.as_ptr() as *const u8), 1);
            assert_eq!(header[0] >> 16, 1);
            assert_eq!(header[1], first_ptr | HEADER_FLAGS);

            assert_eq!(push(header.as_mut_ptr() as *mut u8, second_ptr), first_ptr);
            assert_eq!(query_depth(header.as_ptr() as *const u8), 2);
            assert_eq!(second.next, first_ptr);

            assert_eq!(pop(header.as_mut_ptr() as *mut u8), second_ptr);
            assert_eq!(query_depth(header.as_ptr() as *const u8), 1);
            assert_eq!(header[1], first_ptr | HEADER_FLAGS);
            assert_eq!(pop(header.as_mut_ptr() as *mut u8), first_ptr);
            assert_eq!(query_depth(header.as_ptr() as *const u8), 0);
            assert_eq!(header[1], HEADER_FLAGS);
            assert_eq!(pop(header.as_mut_ptr() as *mut u8), 0);
        }
    }

    #[test]
    fn rejects_unaligned_entries_without_mutating_header() {
        let mut header = [0u64; 2];
        unsafe {
            assert_eq!(push(header.as_mut_ptr() as *mut u8, 0x123), 0);
        }
        assert_eq!(header, [0, 0]);
    }
}
