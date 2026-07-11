//! # `nt-dll-registry` — a generic registry for demand-loaded, shared-text DLL images
//!
//! The ntos executive demand-loads real Windows DLLs (csrsrv, basesrv, winsrv, and — later — the
//! Win32 client stack) into hosted NT processes: the loader opens each by name, sections it, maps
//! it at a fixed base, and the executive demand-pages it from a parsed PE with its executable text
//! shared read-only across processes. That flow was hand-coded per DLL (per-DLL handles/bases +
//! ad-hoc name matches), which doesn't scale and hides bugs behind ~3-minute QEMU boots.
//!
//! This crate owns the **pure decision half** of that flow so it's `cargo test`-able on the host:
//!
//! - **Name resolution** ([`Registry::resolve_name`]) — a folded-lowercase substring match that
//!   rejects SxS/actctx probes (`.local` / `.manifest` / `.config`), which historically diverted the
//!   loader down the DLL-redirection / manifest path instead of the plain System32 search.
//! - **Handle tracking** — file handle (NtOpenFile) → section handle (NtCreateSection) → mapped view
//!   (NtMapViewOfSection), each looked up by handle.
//! - **Base assignment** — each DLL gets a fixed system-wide load slot; the first registered keeps
//!   its preferred ImageBase (no relocation), so its text is byte-identical and shareable.
//! - **Faulting-VA lookup** ([`Registry::dll_for_page`]) — which mapped DLL owns a demand-fault
//!   address, and at what RVA.
//! - **`SECTION_IMAGE_INFORMATION`** ([`image_info`]) — the 64-byte x64 structure the loader reads
//!   from NtQuerySection (TransferAddress, image characteristics, size).
//!
//! The **effectful half** (frame alloc/fill, page-table reservation, out-param copyout) stays in the
//! executive, which drives this registry. Pure, no `unsafe`, `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// One registered DLL image and the handles/state the load flow accumulates for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dll {
    /// Lowercase ASCII stem matched against a (folded) object name, e.g. `b"csrsrv"`.
    pub name: &'static [u8],
    /// Fixed system-wide load base (the VA the view is mapped at in every process).
    pub base: u64,
    /// Page-aligned image extent (PE `SizeOfImage`), for VA-range containment.
    pub image_size: u64,
    /// `AddressOfEntryPoint` (RVA), for the `SECTION_IMAGE_INFORMATION` transfer address.
    pub entry_rva: u32,
    /// File handle from NtOpenFile (0 until opened).
    pub file_handle: u64,
    /// Section handle from NtCreateSection (0 until sectioned).
    pub section_handle: u64,
    /// Set once NtMapViewOfSection has reserved this DLL's VA range.
    pub mapped: bool,
}

/// A by-name/handle/VA registry of the DLL images a hosted process demand-loads.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    dlls: Vec<Dll>,
    next_base: u64,
    slot: u64,
}

impl Registry {
    /// A registry that assigns bases starting at `base_start`, one `slot_size`-byte slot per DLL.
    /// `slot_size` must exceed the largest image (distinct slots ⇒ distinct page-table ranges).
    pub fn new(base_start: u64, slot_size: u64) -> Self {
        Self { dlls: Vec::new(), next_base: base_start, slot: slot_size }
    }

    /// Register `name` (lowercase ASCII stem) with its image extent + entry RVA. Assigns the next
    /// base slot and returns the DLL's index. The first registered keeps `base_start` as its base —
    /// give it a DLL whose preferred ImageBase equals `base_start` so the loader never relocates it.
    pub fn register(&mut self, name: &'static [u8], image_size: u64, entry_rva: u32) -> usize {
        let base = self.next_base;
        self.next_base += self.slot;
        self.dlls.push(Dll {
            name,
            base,
            image_size,
            entry_rva,
            file_handle: 0,
            section_handle: 0,
            mapped: false,
        });
        self.dlls.len() - 1
    }

    /// Number of registered DLLs.
    pub fn len(&self) -> usize {
        self.dlls.len()
    }

    /// True if nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.dlls.is_empty()
    }

    /// Immutable access to DLL `i`.
    pub fn get(&self, i: usize) -> Option<&Dll> {
        self.dlls.get(i)
    }

    /// The load base of DLL `i` (0 if out of range).
    pub fn base(&self, i: usize) -> u64 {
        self.dlls.get(i).map(|d| d.base).unwrap_or(0)
    }

    /// The lowercase stem of DLL `i` (empty if out of range) — for diagnostics.
    pub fn name(&self, i: usize) -> &[u8] {
        self.dlls.get(i).map(|d| d.name).unwrap_or(b"")
    }

    /// True if `name` (any case) is an SxS/actctx probe the loader must be steered away from:
    /// `foo.local`, `foo.manifest`, or `foo.config`. Matching such a probe as a real DLL diverts
    /// the loader into DLL-redirection / manifest parsing instead of the normal System32 search.
    pub fn is_sxs_probe(name: &[u8]) -> bool {
        contains(name, b".local") || contains(name, b".manifest") || contains(name, b".config")
    }

    /// Resolve a (possibly full-path, any-case) object name to a registered DLL index. Returns
    /// `None` for an SxS probe or an unregistered name. Matches the DLL stem as a substring of the
    /// lowercased name (registration order breaks ties). The caller passes a lowercased-ASCII fold
    /// of the UTF-16 object name.
    pub fn resolve_name(&self, name: &[u8]) -> Option<usize> {
        if Self::is_sxs_probe(name) {
            return None;
        }
        self.dlls.iter().position(|d| contains(name, d.name))
    }

    /// Record the NtOpenFile handle for DLL `i`.
    pub fn set_file_handle(&mut self, i: usize, handle: u64) {
        if let Some(d) = self.dlls.get_mut(i) {
            d.file_handle = handle;
        }
    }

    /// The DLL a (non-zero) file handle belongs to.
    pub fn index_for_file(&self, handle: u64) -> Option<usize> {
        if handle == 0 {
            return None;
        }
        self.dlls.iter().position(|d| d.file_handle == handle)
    }

    /// Record the NtCreateSection handle for DLL `i`.
    pub fn set_section_handle(&mut self, i: usize, handle: u64) {
        if let Some(d) = self.dlls.get_mut(i) {
            d.section_handle = handle;
        }
    }

    /// The DLL a (non-zero) section handle belongs to.
    pub fn index_for_section(&self, handle: u64) -> Option<usize> {
        if handle == 0 {
            return None;
        }
        self.dlls.iter().position(|d| d.section_handle == handle)
    }

    /// Mark DLL `i`'s view mapped (its VA range is now reserved + demand-pageable).
    pub fn set_mapped(&mut self, i: usize) {
        if let Some(d) = self.dlls.get_mut(i) {
            d.mapped = true;
        }
    }

    /// True once DLL `i` has been mapped.
    pub fn is_mapped(&self, i: usize) -> bool {
        self.dlls.get(i).map(|d| d.mapped).unwrap_or(false)
    }

    /// Which **mapped** DLL contains virtual address `va`, and at what RVA. Unmapped DLLs (whose VA
    /// range isn't reserved yet) are excluded, so a stray address in an about-to-be-mapped range
    /// isn't misrouted. Slots are distinct, so at most one matches.
    pub fn dll_for_page(&self, va: u64) -> Option<(usize, u32)> {
        self.dlls.iter().enumerate().find_map(|(i, d)| {
            if d.mapped && va >= d.base && va < d.base + d.image_size {
                Some((i, (va - d.base) as u32))
            } else {
                None
            }
        })
    }

    /// The 64-byte `SECTION_IMAGE_INFORMATION` for DLL `i` (see [`image_info`]).
    pub fn image_info(&self, i: usize) -> Option<[u8; 64]> {
        self.dlls
            .get(i)
            .map(|d| image_info(d.base, d.entry_rva, d.image_size as u32, true))
    }
}

/// True if `hay` contains the byte sub-slice `needle`.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return needle.is_empty();
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Build the 64-byte x64 `SECTION_IMAGE_INFORMATION` the loader reads from NtQuerySection (class 1)
/// for an image loaded at `base` with entry RVA `entry_rva` and `SizeOfImage` `image_size`. `is_dll`
/// sets the DLL characteristic bit (0x2000) — the loader rejects a DLL section whose info says EXE
/// (and vice-versa) with STATUS_INVALID_IMAGE_FORMAT. Fields not consulted by the loaders we run
/// (times, checksum, os/subsystem version) are left zero; the ones that matter mirror the values
/// smss's RtlCreateUserProcess expects (NATIVE subsystem, 1 MiB stack, AMD64 machine).
pub fn image_info(base: u64, entry_rva: u32, image_size: u32, is_dll: bool) -> [u8; 64] {
    let mut b = [0u8; 64];
    let put = |b: &mut [u8; 64], off: usize, v: u64| {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    };
    // ImageCharacteristics: EXECUTABLE_IMAGE|LARGE_ADDRESS_AWARE (0x0022), + DLL (0x2000) for a DLL.
    let img_char: u64 = if is_dll { 0x2022 } else { 0x0022 };
    put(&mut b, 0x00, base + entry_rva as u64); // TransferAddress (entry VA)
    put(&mut b, 0x08, 0); // ZeroBits + pad
    put(&mut b, 0x10, 0x10_0000); // MaximumStackSize (1 MiB)
    put(&mut b, 0x18, 0x1_0000); // CommittedStackSize (64 KiB)
    put(&mut b, 0x20, 1); // SubSystemType = NATIVE(1) | SubSystemVersion = 0
    put(&mut b, 0x28, img_char << 32); // OSVersion(@0x28) | ImageCharacteristics(u16 @0x2c)
    put(&mut b, 0x30, 0x8664 | (1u64 << 16)); // Machine=0x8664(@0x30) | ImageContainsCode=1(@0x32)
    put(&mut b, 0x38, image_size as u64); // ImageFileSize(@0x38) | CheckSum(@0x3c)
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    // csrsrv keeps its preferred base; basesrv/winsrv fall on the next 16 MiB slots.
    fn seeded() -> Registry {
        let mut r = Registry::new(0x8000_0000, 0x0100_0000);
        assert_eq!(r.register(b"csrsrv", 0x1_1000, 0x1200), 0);
        assert_eq!(r.register(b"basesrv", 0xD000, 0x2400), 1);
        assert_eq!(r.register(b"winsrv", 0x6_0000, 0x8800), 2);
        r
    }

    #[test]
    fn base_assignment_is_slotted() {
        let r = seeded();
        assert_eq!(r.base(0), 0x8000_0000);
        assert_eq!(r.base(1), 0x8100_0000);
        assert_eq!(r.base(2), 0x8200_0000);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn resolve_matches_full_path_any_case() {
        let r = seeded();
        assert_eq!(r.resolve_name(b"\\systemroot\\system32\\csrsrv.dll"), Some(0));
        assert_eq!(r.resolve_name(b"c:\\windows\\system32\\basesrv.dll"), Some(1));
        assert_eq!(r.resolve_name(b"winsrv"), Some(2));
        // The caller folds case before calling; a bare uppercase stem won't match (by design —
        // resolve_name is the pure substring step over already-lowercased input).
        assert_eq!(r.resolve_name(b"csrsrv"), Some(0));
    }

    #[test]
    fn csrss_exe_is_not_a_registered_dll() {
        // csrss.exe is the main EXE (handled separately); it must not resolve to csrsrv or any DLL.
        let r = seeded();
        assert_eq!(r.resolve_name(b"\\systemroot\\system32\\csrss.exe"), None);
    }

    #[test]
    fn sxs_probes_are_rejected() {
        let r = seeded();
        assert!(Registry::is_sxs_probe(b"csrsrv.dll.local"));
        assert!(Registry::is_sxs_probe(b"\\??\\c:\\windows\\csrss.exe.manifest"));
        assert!(Registry::is_sxs_probe(b"basesrv.dll.config"));
        assert_eq!(r.resolve_name(b"csrsrv.dll.local"), None);
        assert_eq!(r.resolve_name(b"basesrv.manifest"), None);
        assert!(!Registry::is_sxs_probe(b"csrsrv.dll"));
    }

    #[test]
    fn handle_round_trips() {
        let mut r = seeded();
        assert_eq!(r.index_for_file(0), None); // a zero handle never matches
        r.set_file_handle(1, 0x5a5a_0007);
        assert_eq!(r.index_for_file(0x5a5a_0007), Some(1));
        assert_eq!(r.index_for_file(0x1234), None);
        r.set_section_handle(1, 0x5a5a_0009);
        assert_eq!(r.index_for_section(0x5a5a_0009), Some(1));
        assert_eq!(r.index_for_section(0), None);
    }

    #[test]
    fn page_lookup_needs_a_mapped_view() {
        let mut r = seeded();
        // Before mapping, its range doesn't resolve.
        assert_eq!(r.dll_for_page(0x8100_0000), None);
        r.set_mapped(1);
        assert!(r.is_mapped(1));
        assert_eq!(r.dll_for_page(0x8100_0000), Some((1, 0))); // at base → rva 0
        assert_eq!(r.dll_for_page(0x8100_2345), Some((1, 0x2345)));
        assert_eq!(r.dll_for_page(0x8100_0000 + 0xD000 - 1), Some((1, 0xCFFF))); // last byte
        assert_eq!(r.dll_for_page(0x8100_0000 + 0xD000), None); // one past the end
        assert_eq!(r.dll_for_page(0x8000_0000), None); // csrsrv's range, but it's unmapped
    }

    #[test]
    fn image_info_dll_vs_exe() {
        let dll = image_info(0x8000_0000, 0x1200, 0x1_1000, true);
        // TransferAddress = base + entry.
        assert_eq!(u64::from_le_bytes(dll[0x00..0x08].try_into().unwrap()), 0x8000_1200);
        // ImageCharacteristics (u16 @ 0x2c) has the DLL bit (0x2000).
        assert_eq!(u16::from_le_bytes(dll[0x2c..0x2e].try_into().unwrap()), 0x2022);
        // Machine = AMD64.
        assert_eq!(u16::from_le_bytes(dll[0x30..0x32].try_into().unwrap()), 0x8664);
        // ImageFileSize.
        assert_eq!(u32::from_le_bytes(dll[0x38..0x3c].try_into().unwrap()), 0x1_1000);

        let exe = image_info(0x0001_0000, 0x40, 0x8000, false);
        assert_eq!(u16::from_le_bytes(exe[0x2c..0x2e].try_into().unwrap()), 0x0022); // no DLL bit

        // The registry produces the same bytes for a registered DLL.
        let r = seeded();
        assert_eq!(r.image_info(0), Some(image_info(0x8000_0000, 0x1200, 0x1_1000, true)));
    }

    #[test]
    fn distinct_slots_never_overlap() {
        // A registry-owned invariant: every DLL's [base, base+image_size) fits inside its slot.
        let r = seeded();
        for i in 0..r.len() {
            let d = r.get(i).unwrap();
            assert!(d.image_size <= 0x0100_0000, "image must fit its slot");
            if i + 1 < r.len() {
                assert!(d.base + d.image_size <= r.base(i + 1), "no overlap into next slot");
            }
        }
    }
}
