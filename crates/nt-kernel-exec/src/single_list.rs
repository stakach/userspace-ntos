//! Legacy `SINGLE_LIST_ENTRY` operations used by the interlocked kernel exports.
//!
//! A list head and each entry contain one `Next` pointer. The caller provides the
//! exclusion required by `ExInterlocked{Push,Pop}EntryList`; these operations only
//! change the linked storage while that exclusion is held.

use core::ptr::{read_unaligned, write_unaligned};

/// The x64 `SINGLE_LIST_ENTRY` layout.
#[repr(C)]
pub struct SingleListEntry {
    pub next: *mut SingleListEntry,
}

/// Push `entry` after `head`, returning the previous first entry.
///
/// # Safety
/// `head` and `entry` must be valid writable pointers to distinct entries, and
/// the caller must hold the list's spin lock for the entire operation.
pub unsafe fn push(
    head: *mut SingleListEntry,
    entry: *mut SingleListEntry,
) -> *mut SingleListEntry {
    let previous = unsafe { read_unaligned(head.cast::<*mut SingleListEntry>()) };
    unsafe {
        write_unaligned(entry.cast::<*mut SingleListEntry>(), previous);
        write_unaligned(head.cast::<*mut SingleListEntry>(), entry);
    }
    previous
}

/// Remove and return the first entry, or null for an empty list.
///
/// # Safety
/// `head` must be valid and writable; any linked first entry must be readable.
/// The caller must hold the list's spin lock for the entire operation.
pub unsafe fn pop(head: *mut SingleListEntry) -> *mut SingleListEntry {
    let first = unsafe { read_unaligned(head.cast::<*mut SingleListEntry>()) };
    if !first.is_null() {
        let next = unsafe { read_unaligned(first.cast::<*mut SingleListEntry>()) };
        unsafe { write_unaligned(head.cast::<*mut SingleListEntry>(), next) };
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null_mut;

    #[test]
    fn push_and_pop_return_previous_and_first_in_lifo_order() {
        assert_eq!(core::mem::size_of::<SingleListEntry>(), 8);
        let mut head = SingleListEntry { next: null_mut() };
        let mut a = SingleListEntry { next: null_mut() };
        let mut b = SingleListEntry { next: null_mut() };
        let head = &mut head as *mut _;
        let a = &mut a as *mut _;
        let b = &mut b as *mut _;
        unsafe {
            assert_eq!(pop(head), null_mut());
            assert_eq!(push(head, a), null_mut());
            assert_eq!((*head).next, a);
            assert_eq!((*a).next, null_mut());
            assert_eq!(push(head, b), a);
            assert_eq!((*head).next, b);
            assert_eq!((*b).next, a);
            assert_eq!(pop(head), b);
            assert_eq!((*head).next, a);
            assert_eq!(pop(head), a);
            assert_eq!((*head).next, null_mut());
            assert_eq!(pop(head), null_mut());
        }
    }

    #[test]
    fn operations_do_not_modify_other_entry_storage() {
        let mut head = SingleListEntry { next: null_mut() };
        let mut entry = [0u64, 0xdead_beef_cafe_babe];
        let entry_ptr = entry.as_mut_ptr().cast::<SingleListEntry>();
        unsafe {
            assert_eq!(push(&mut head, entry_ptr), null_mut());
            assert_eq!(pop(&mut head), entry_ptr);
        }
        assert_eq!(entry[1], 0xdead_beef_cafe_babe);
    }
}
