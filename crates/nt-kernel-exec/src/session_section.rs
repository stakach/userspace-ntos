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
//! This would normally be a runtime registry, but the win32k host needs section metadata that can be
//! allocated before the hosted image starts, so the section object *carries its own state*: the
//! caller allocates a small descriptor from its pool, and these pure layout functions (mirroring this
//! crate's [`init_general_lookaside`](crate::init_general_lookaside)) manage it. The field offsets,
//! map-count, and idempotent-map rule are the modelled Mm section-object semantics, unit-tested here
//! and reused by every hosted binary that maps section-backed session memory. (Lives in
//! `nt-kernel-exec` beside the lookaside primitive — rather than `nt-memory-manager`, whose
//! `alloc`/cache-manager section table would bloat the executive image past its 512 KiB budget.)

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
    /// `ULONG64 MapCount` — logical map count across session/system/process views. The backing stays
    /// resident until the final unmap.
    pub const MAP_COUNT: usize = 0x18;
    /// `PVOID Next` — host-owned intrusive link used by the import layer to resolve unmap-by-base.
    pub const NEXT: usize = 0x20;
    /// Total descriptor size the caller must allocate.
    pub const SIZE_OF: usize = 0x28;
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
    core::ptr::write_unaligned(
        desc.add(o::SIZE) as *mut u64,
        round_up_page(size).max(0x1000),
    );
    core::ptr::write_unaligned(desc.add(o::BASE) as *mut u64, 0);
    core::ptr::write_unaligned(desc.add(o::MAGIC) as *mut u64, SECTION_MAGIC);
    core::ptr::write_unaligned(desc.add(o::MAP_COUNT) as *mut u64, 0);
    core::ptr::write_unaligned(desc.add(o::NEXT) as *mut u64, 0);
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

/// The section's logical map count.
///
/// # Safety
/// `desc` must be a valid section descriptor.
pub unsafe fn section_map_count(desc: *const u8) -> u64 {
    core::ptr::read_unaligned(desc.add(section_object::MAP_COUNT) as *const u64)
}

/// `true` when `addr` lies inside the current mapped view for this section.
///
/// # Safety
/// `desc` must be a valid section descriptor.
pub unsafe fn section_contains_addr(desc: *const u8, addr: u64) -> bool {
    let base = section_base(desc);
    let size = section_size(desc);
    base != 0 && addr >= base && base.checked_add(size).is_some_and(|end| addr < end)
}

/// Intrusive next pointer owned by the host import layer.
///
/// # Safety
/// `desc` must be a valid section descriptor.
pub unsafe fn section_next(desc: *const u8) -> u64 {
    core::ptr::read_unaligned(desc.add(section_object::NEXT) as *const u64)
}

/// Set the intrusive next pointer owned by the host import layer.
///
/// # Safety
/// `desc` must be a valid section descriptor.
pub unsafe fn set_section_next(desc: *mut u8, next: u64) {
    core::ptr::write_unaligned(desc.add(section_object::NEXT) as *mut u64, next);
}

unsafe fn increment_map_count(desc: *mut u8) {
    let count = section_map_count(desc);
    core::ptr::write_unaligned(
        desc.add(section_object::MAP_COUNT) as *mut u64,
        count.saturating_add(1),
    );
}

/// Resolve the base to hand back for a `MmMapView*` of this section. If the section is not yet
/// mapped, `alloc()` is invoked once to allocate `section_size` bytes of backing, the result is
/// recorded, and every subsequent map returns that same base (coherent kernel + per-process views).
/// A successful map increments the logical map count. Returns 0 if `alloc` failed.
///
/// # Safety
/// `desc` must be a valid section descriptor; `alloc(size)` must return a base for `size` writable
/// bytes (or 0 on failure).
pub unsafe fn map_section(desc: *mut u8, alloc: impl FnOnce(u64) -> u64) -> u64 {
    let existing = section_base(desc);
    if existing != 0 {
        increment_map_count(desc);
        return existing;
    }
    let base = alloc(section_size(desc));
    if base != 0 {
        core::ptr::write_unaligned(desc.add(section_object::BASE) as *mut u64, base);
        increment_map_count(desc);
    }
    base
}

/// Unmap a logical view containing `addr`. When this removes the final logical map, the stored
/// backing base is handed to `free()` and the descriptor becomes unmapped again.
///
/// # Safety
/// `desc` must be a valid section descriptor; `free(base)` must release a backing base previously
/// returned by the `alloc` closure passed to [`map_section`].
pub unsafe fn unmap_section(desc: *mut u8, addr: u64, free: impl FnOnce(u64) -> bool) -> bool {
    if !section_contains_addr(desc, addr) {
        return false;
    }
    let count = section_map_count(desc);
    if count == 0 {
        return false;
    }
    if count > 1 {
        core::ptr::write_unaligned(desc.add(section_object::MAP_COUNT) as *mut u64, count - 1);
        return true;
    }

    let base = section_base(desc);
    if !free(base) {
        return false;
    }
    core::ptr::write_unaligned(desc.add(section_object::BASE) as *mut u64, 0);
    core::ptr::write_unaligned(desc.add(section_object::MAP_COUNT) as *mut u64, 0);
    true
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
            assert_eq!(section_map_count(desc), 0);
            assert_eq!(section_next(desc), 0);
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
            assert_eq!(section_map_count(desc), 2);
        }
    }

    #[test]
    fn unmap_counts_logical_views_and_frees_final_backing() {
        let mut buf = [0u8; o::SIZE_OF];
        let desc = buf.as_mut_ptr();
        let mut alloc_calls = 0;
        let mut free_calls = 0;
        unsafe {
            init_section(desc, 0x4000);
            assert_eq!(
                map_section(desc, |_| {
                    alloc_calls += 1;
                    0x2_0000
                }),
                0x2_0000
            );
            assert_eq!(map_section(desc, |_| 0xDEAD_0000), 0x2_0000);

            assert!(section_contains_addr(desc, 0x2_0100));
            assert!(unmap_section(desc, 0x2_0100, |_| {
                free_calls += 1;
                false
            }));
            assert_eq!(section_map_count(desc), 1);
            assert_eq!(section_base(desc), 0x2_0000);
            assert_eq!(free_calls, 0);

            assert!(unmap_section(desc, 0x2_0000, |base| {
                free_calls += 1;
                assert_eq!(base, 0x2_0000);
                true
            }));
            assert_eq!(section_map_count(desc), 0);
            assert_eq!(section_base(desc), 0);
            assert_eq!(free_calls, 1);

            assert_eq!(
                map_section(desc, |_| {
                    alloc_calls += 1;
                    0x3_0000
                }),
                0x3_0000
            );
            assert_eq!(alloc_calls, 2);
        }
    }

    #[test]
    fn host_link_is_independent_of_map_state() {
        let mut buf = [0u8; o::SIZE_OF];
        let desc = buf.as_mut_ptr();
        unsafe {
            init_section(desc, 0x1000);
            set_section_next(desc, 0xABCD);
            assert_eq!(section_next(desc), 0xABCD);
            assert_eq!(map_section(desc, |_| 0x4_0000), 0x4_0000);
            assert_eq!(section_next(desc), 0xABCD);
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
