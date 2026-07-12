//! Session-space section objects as a raw-memory primitive (`MmCreateSection` +
//! `MmMapViewInSessionSpace` / `MmMapViewOfSection` for the win32k global user heap).
//!
//! win32k creates its global USER heap (and several session-space views) as *section objects*:
//! `UserCreateHeap` calls `MmCreateSection(&SectionObject, ..., &Size, PAGE_READWRITE, SEC_RESERVE)`
//! then `MmMapViewInSessionSpace(SectionObject, &SystemBase, &Size)` to map the kernel view, and
//! later `MapGlobalUserHeap` calls `MmMapViewOfSection(SectionObject, Process, &UserBase, ...)` to
//! project the *same* backing into each connecting process. For the heap to be coherent the two
//! mappings must resolve to the same memory, so a section object must remember the base it was
//! mapped at and hand it back on every subsequent map.
//!
//! Like [`crate::`]-level object tables this would normally be a runtime registry, but the win32k
//! host is allocation-free (its bump heap is spent by the time win32k runs), so the section object
//! *carries its own state*: the caller allocates a small descriptor from its pool, and these pure
//! layout functions (mirroring `nt-kernel-exec`'s `init_general_lookaside`) manage it. The field
//! offsets + idempotent-map rule are the real semantics, unit-tested here and reused by every
//! hosted binary that maps section-backed session memory.

/// `MM_SESSION_SECTION` descriptor field offsets (a compact section object; not a Windows-ABI
/// struct — it is win32k-opaque, only round-tripped through the `Mm*` trampolines).
pub mod section_object {
    /// `SIZE_T SizeBytes` — the section's committed size (rounded up to a page).
    pub const SIZE: usize = 0x00;
    /// `PVOID MappedBase` — the VA the section is mapped at (0 = not yet mapped). Assigned on the
    /// first `MmMapView*` and reused thereafter so kernel + per-process views stay coherent.
    pub const BASE: usize = 0x08;
    /// `ULONG64 Magic` — validates that a `Section` pointer handed to `MmMapView*` really is one of
    /// ours (win32k also maps sections created elsewhere in some paths; skip those).
    pub const MAGIC: usize = 0x10;
    /// Total descriptor size the caller must allocate.
    pub const SIZE_OF: usize = 0x18;
}

/// Descriptor magic ("MmSeSeCt" truncated) — a live section descriptor created by [`init_section`].
pub const SECTION_MAGIC: u64 = 0x744365_5365_536d4d;

/// Round `n` up to a 4 KiB page.
pub const fn round_up_page(n: u64) -> u64 {
    (n + 0xFFF) & !0xFFF
}

/// Initialize a section descriptor at `desc`: record `size` (page-rounded), mark it unmapped, and
/// stamp the magic. Mirrors the effect of `MmCreateSection` writing `*SectionObject`.
///
/// # Safety
/// `desc` must point to at least [`section_object::SIZE_OF`] writable bytes.
pub unsafe fn init_section(desc: *mut u8, size: u64) {
    use section_object as o;
    core::ptr::write_unaligned(desc.add(o::SIZE) as *mut u64, round_up_page(size).max(0x1000));
    core::ptr::write_unaligned(desc.add(o::BASE) as *mut u64, 0);
    core::ptr::write_unaligned(desc.add(o::MAGIC) as *mut u64, SECTION_MAGIC);
}

/// `true` if `desc` is a live section descriptor created by [`init_section`].
///
/// # Safety
/// `desc` must be readable for at least [`section_object::SIZE_OF`] bytes (or null).
pub unsafe fn is_section(desc: *const u8) -> bool {
    !desc.is_null()
        && core::ptr::read_unaligned(desc.add(section_object::MAGIC) as *const u64) == SECTION_MAGIC
}

/// The section's committed size in bytes.
///
/// # Safety
/// `desc` must be a valid section descriptor (see [`is_section`]).
pub unsafe fn section_size(desc: *const u8) -> u64 {
    core::ptr::read_unaligned(desc.add(section_object::SIZE) as *const u64)
}

/// The section's mapped base (0 if not yet mapped).
///
/// # Safety
/// `desc` must be a valid section descriptor.
pub unsafe fn section_base(desc: *const u8) -> u64 {
    core::ptr::read_unaligned(desc.add(section_object::BASE) as *const u64)
}

/// Resolve the base to hand back for a `MmMapView*` of this section. If the section is not yet
/// mapped, `alloc()` is invoked once to allocate `section_size` bytes of backing, the result is
/// recorded, and every subsequent map returns that same base (coherent kernel + per-process views).
/// Returns 0 if `alloc` failed.
///
/// # Safety
/// `desc` must be a valid section descriptor; `alloc(size)` must return a base for `size` writable
/// bytes (or 0 on failure).
pub unsafe fn map_section(desc: *mut u8, alloc: impl FnOnce(u64) -> u64) -> u64 {
    let existing = section_base(desc);
    if existing != 0 {
        return existing;
    }
    let base = alloc(section_size(desc));
    if base != 0 {
        core::ptr::write_unaligned(desc.add(section_object::BASE) as *mut u64, base);
    }
    base
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::section_object as o;
    use super::*;

    #[test]
    fn creates_and_reports_section() {
        let mut buf = [0xAAu8; o::SIZE_OF];
        let desc = buf.as_mut_ptr();
        unsafe {
            init_section(desc, 1 * 1024 * 1024);
            assert!(is_section(desc));
            assert_eq!(section_size(desc), 1 * 1024 * 1024);
            assert_eq!(section_base(desc), 0); // unmapped
        }
    }

    #[test]
    fn rounds_size_up_to_a_page_and_has_a_minimum() {
        let mut buf = [0u8; o::SIZE_OF];
        let desc = buf.as_mut_ptr();
        unsafe {
            init_section(desc, 0x1234);
            assert_eq!(section_size(desc), 0x2000);
            init_section(desc, 0);
            assert_eq!(section_size(desc), 0x1000);
        }
    }

    #[test]
    fn map_is_idempotent_and_coherent() {
        let mut buf = [0u8; o::SIZE_OF];
        let desc = buf.as_mut_ptr();
        let mut alloc_calls = 0;
        unsafe {
            init_section(desc, 0x4000);
            let kernel_view = map_section(desc, |sz| {
                alloc_calls += 1;
                assert_eq!(sz, 0x4000);
                0x1_0000
            });
            assert_eq!(kernel_view, 0x1_0000);
            // A second map (the per-process view) must return the SAME base without re-allocating.
            let user_view = map_section(desc, |_| {
                alloc_calls += 1;
                0xDEAD_0000
            });
            assert_eq!(user_view, 0x1_0000);
            assert_eq!(alloc_calls, 1);
            assert_eq!(section_base(desc), 0x1_0000);
        }
    }

    #[test]
    fn non_section_pointers_are_rejected() {
        let mut buf = [0u8; o::SIZE_OF];
        unsafe {
            assert!(!is_section(core::ptr::null()));
            assert!(!is_section(buf.as_ptr())); // zeroed, no magic
            init_section(buf.as_mut_ptr(), 0x1000);
            assert!(is_section(buf.as_ptr()));
        }
    }
}
