//! A proof-of-pattern `Rtl*` slice.
//!
//! The `Rtl*` surface is *not* syscall stubs — it is real userspace library code that runs
//! in-process (string ops, heap, SIDs, time). Much of it already exists, host-tested, in
//! `nt-kernel-exec` and `nt-compat-exports::rtl`. Our ntdll's job is to **re-export** those impls
//! under the ntdll `Rtl*` names, not to reimplement them. This module wires a few representative
//! `Rtl*` functions over `nt-compat-exports::rtl` to prove that reuse pattern; the bulk 244-entry
//! port is Step 2b.

pub use nt_compat_exports::rtl::UnicodeString;

/// `RtlInitUnicodeString`: initialise a counted UTF-16 string descriptor from a slice (a read-only
/// view; `Length == MaximumLength == slice byte length`). Reused from `nt-compat-exports::rtl`.
pub fn rtl_init_unicode_string(src: &[u16]) -> UnicodeString {
    UnicodeString::init(src)
}

/// `RtlCreateUnicodeString`: allocate a NUL-terminated copy (`MaximumLength` includes the NUL).
pub fn rtl_create_unicode_string(src: &[u16]) -> UnicodeString {
    UnicodeString::create(src)
}

/// `RtlCompareMemory`: count of leading equal bytes. Reused from `nt-compat-exports::rtl`.
pub fn rtl_compare_memory(a: &[u8], b: &[u8]) -> usize {
    nt_compat_exports::rtl::compare_memory(a, b)
}

/// `RtlCompareUnicodeString`: lexical comparison (`Less`/`Equal`/`Greater`), optionally
/// case-insensitive. Reused from `nt-compat-exports::rtl`.
pub fn rtl_compare_unicode_string(
    a: &[u16],
    b: &[u16],
    case_insensitive: bool,
) -> core::cmp::Ordering {
    nt_compat_exports::rtl::compare_unicode(a, b, case_insensitive)
}

/// `RtlEqualUnicodeString`: equality wrapper over [`rtl_compare_unicode_string`].
pub fn rtl_equal_unicode_string(a: &[u16], b: &[u16], case_insensitive: bool) -> bool {
    nt_compat_exports::rtl::equal_unicode(a, b, case_insensitive)
}

/// `RtlUpcaseUnicodeChar`: upper-case a single UTF-16 code unit. Reused from
/// `nt-compat-exports::rtl`.
pub fn rtl_upcase_unicode_char(c: u16) -> u16 {
    nt_compat_exports::rtl::upcase_char(c)
}
