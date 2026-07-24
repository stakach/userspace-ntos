//! The `Rtl*` surface — real userspace library code that runs in-process (strings, conversion,
//! integers, time, GUID, path, status, random, bitmap, heap, sync primitives).
//!
//! The `Rtl*` functions are *not* syscall stubs; they are pure(-ish) library routines. Wherever an
//! impl already exists host-tested elsewhere we **re-export** it (`nt-compat-exports::rtl` for the
//! string core, `nt-kernel-exec::rtl_bitmap` for the bitmap primitives) rather than reimplement;
//! the rest is authored here as Category-A pure logic. The load-bearing subsystems — the heap
//! ([`crate::heap`]) and the critical-section / SRW sync primitives ([`crate::sync`]) — live in
//! their own top-level modules.
//!
//! Step 2b lands the bulk of the 244-entry `Rtl*` surface. See `ntdll_plan.md` for the categorised
//! coverage (A pure / A' CRT / B heap / C sync).

pub mod activation;
pub mod activation_dependency;
pub mod activation_manifest;
pub mod activation_query;
pub mod activation_redirection;
pub mod activation_section;
pub mod activation_settings;
pub mod atom;
pub mod avl_table;
pub mod bitmap;
pub mod compression;
pub mod convert;
pub mod debug_buffer;
pub mod dos8dot3;
pub mod dynamic_function_table;
pub mod encode;
pub mod environment;
pub mod exception;
pub mod fls;
pub mod generic_table;
pub mod guid;
pub mod image;
pub mod image_verify;
pub mod import_table_hash;
pub mod integer;
pub mod locale;
pub mod memory;
pub mod memstream;
pub mod message;
pub mod network;
pub mod path;
pub mod pe_manifest;
pub mod pe_resource;
pub mod prefix;
pub mod privilege;
pub mod process_params;
pub mod propvariant;
pub mod random;
pub mod registry;
pub mod resource;
pub mod security;
pub mod splay;
pub mod status;
pub mod strings;
pub mod text_unicode;
pub mod time;
pub mod timezone;
pub mod trace_database;
pub mod user_stack;
pub mod vectored_handler;

// Re-export the counted-string type at the `rtl` root (used across the surface).
pub use nt_compat_exports::rtl::UnicodeString;

// --- Proof-of-pattern thin wrappers (kept from Step 2a; now backed by the strings module) ------

/// `RtlInitUnicodeString`.
pub fn rtl_init_unicode_string(src: &[u16]) -> UnicodeString {
    strings::init_unicode_string(src)
}

/// `RtlCreateUnicodeString`.
pub fn rtl_create_unicode_string(src: &[u16]) -> UnicodeString {
    strings::create_unicode_string(src)
}

/// `RtlCompareMemory`.
pub fn rtl_compare_memory(a: &[u8], b: &[u8]) -> usize {
    nt_compat_exports::rtl::compare_memory(a, b)
}

/// `RtlCompareUnicodeString`.
pub fn rtl_compare_unicode_string(a: &[u16], b: &[u16], ci: bool) -> core::cmp::Ordering {
    strings::compare_unicode_string(a, b, ci)
}

/// `RtlEqualUnicodeString`.
pub fn rtl_equal_unicode_string(a: &[u16], b: &[u16], ci: bool) -> bool {
    strings::equal_unicode_string(a, b, ci)
}

/// `RtlUpcaseUnicodeChar`.
pub fn rtl_upcase_unicode_char(c: u16) -> u16 {
    strings::upcase_char(c)
}
