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
//! - **Name resolution** ([`Registry::resolve_name`]) — exact folded-lowercase DLL identity matching
//!   on a bare name or the final component of a path, while rejecting SxS/actctx probes (`.local` /
//!   `.manifest` / `.config`) that historically diverted the loader down DLL redirection instead of
//!   the plain System32 search.
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

/// Per-process (per-owner) handle capacity **pre-reserved** for each DLL at `register()` time.
/// Handle VALUES are **process-local** (each hosted process has its own NT handle namespace), so
/// the same DLL, loaded by two processes, gets a distinct file/section handle **per process** — and
/// those values may COLLIDE across processes (real NT dense per-process handles reuse small
/// integers). Every handle store/lookup is therefore keyed by the owning process index `pi`
/// (0 = smss, 1 = csrss, 2 = winlogon, 3 = services, 4 = lsass, 5+ = userinit/explorer/shell after
/// login; the executive's fault-badge → pi mapping). Path 1b of the convergence.
///
/// **This is a RESERVE, not a ceiling.** The per-pi handle stores ([`Dll::file_handle`] /
/// [`Dll::section_handle`]) are growable `Vec`s: `set_*_handle(pi, …)` extends them on demand, so
/// there is NO hard process ceiling. The reserve exists purely for the executive's **per-syscall
/// bump-heap-reset discipline**: DLLs are `register()`ed at BOOT (below the executive's `heap_mark`),
/// so their per-pi `Vec`s are pre-allocated to `PI_RESERVE` capacity in the persistent (below-mark)
/// heap region and every runtime `set_*_handle(pi, …)` for `pi < PI_RESERVE` writes into that
/// already-allocated capacity — no heap growth, so the write SURVIVES the per-syscall `reset_to()`.
/// A runtime `set_*_handle(pi ≥ PI_RESERVE)` DOES grow the `Vec` above the mark (would be rewound by
/// the next reset) — so keep `PI_RESERVE` comfortably above the live process count (16 ⇒ the 5
/// current + all post-login processes fit with headroom). If a boot ever needs > `PI_RESERVE`
/// processes, either bump this constant OR advance `heap_mark` after the growing syscall (the
/// `RegistryOverlay` `overlay_dirty` precedent).
pub const PI_RESERVE: usize = 16;

/// Max length of a DLL stem stored inline (see [`Dll::name_buf`]). Long enough for every real
/// System32 DLL stem (`kernel32_vista` = 14) with headroom.
pub const MAX_STEM: usize = 32;

/// One registered DLL image and the handles/state the load flow accumulates for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dll {
    /// Lowercase ASCII stem matched against a (folded) object name, stored INLINE (not a `&'static`)
    /// so a slot can be **activated on demand** (its stem filled in at syscall time from an FS
    /// request) without needing a `'static` name. A reserved-but-unactivated slot has `name_len == 0`
    /// and matches nothing. Read via [`Dll::name`].
    name_buf: [u8; MAX_STEM],
    /// Number of valid bytes in `name_buf`. 0 = a reserved (unactivated) slot.
    name_len: usize,
    /// Fixed system-wide load base (the VA the view is mapped at in every process). Assigned at
    /// `register`/`reserve` time from the slotted allocator, so it is collision-free and stable even
    /// for a slot activated later on demand.
    pub base: u64,
    /// Page-aligned image extent (PE `SizeOfImage`), for VA-range containment.
    pub image_size: u64,
    /// `AddressOfEntryPoint` (RVA), for the `SECTION_IMAGE_INFORMATION` transfer address.
    pub entry_rva: u32,
    /// File handle from NtOpenFile, **per owning process** (`file_handle[pi]`; 0 until opened by
    /// that process). A GROWABLE per-pi store (pre-reserved to `PI_RESERVE`, extended on demand —
    /// no fixed process ceiling). Two processes loading the same DLL each store their own (possibly
    /// equal) handle VALUE here, so the lookup must be keyed by `pi`. Accessed via the
    /// `file_handle(pi)` / `set_file_handle(pi, …)` methods, never as a raw array.
    file_handle: Vec<u64>,
    /// Section handle from NtCreateSection, **per owning process** (growable; `section_handle(pi)`;
    /// 0 until sectioned by that process).
    section_handle: Vec<u64>,
    /// Set once NtMapViewOfSection has reserved this DLL's VA range.
    pub mapped: bool,
}

/// Grow `v` so index `pi` is addressable (padding new slots with 0 = "no handle"), then return
/// `&mut v[pi]`. Growth past the pre-`register()` reserve allocates in the transient heap (see
/// [`PI_RESERVE`]); within the reserve it's a pure in-place write.
#[inline]
fn slot_mut(v: &mut Vec<u64>, pi: usize) -> &mut u64 {
    if pi >= v.len() {
        v.resize(pi + 1, 0);
    }
    &mut v[pi]
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
    pub fn register(&mut self, name: &[u8], image_size: u64, entry_rva: u32) -> usize {
        let i = self.reserve();
        self.activate(i, name, image_size, entry_rva);
        i
    }

    /// Pre-**reserve** an EMPTY slot: assign it a fixed base (so its VA range is stable + collision-
    /// free) and pre-allocate its per-pi handle stores, but leave it nameless (`name_len == 0`) so it
    /// matches nothing until [`activate`](Self::activate)d. Returns the slot index.
    ///
    /// This is the demand-load enabler: reserving all slots at BOOT (below the executive's per-syscall
    /// `heap_mark`) makes the `dlls` Vec growth + the per-pi handle-store allocations PERSISTENT, so a
    /// later on-demand `activate` (at syscall time) needs NO heap growth here — only the inline
    /// `name_buf` fill, which is in-place. The executive then advances `heap_mark` past whatever it
    /// itself allocated for the load (pool bytes live in a separate cap-mapped arena). See the module
    /// docs + `PI_RESERVE`.
    pub fn reserve(&mut self) -> usize {
        let base = self.next_base;
        self.next_base += self.slot;
        // Pre-reserve the per-pi handle stores to `PI_RESERVE` slots (see [`PI_RESERVE`]).
        let mut file_handle = Vec::new();
        let mut section_handle = Vec::new();
        file_handle.resize(PI_RESERVE, 0);
        section_handle.resize(PI_RESERVE, 0);
        self.dlls.push(Dll {
            name_buf: [0u8; MAX_STEM],
            name_len: 0,
            base,
            image_size: 0,
            entry_rva: 0,
            file_handle,
            section_handle,
            mapped: false,
        });
        self.dlls.len() - 1
    }

    /// Fill a reserved slot's identity (stem + geometry) IN PLACE — no heap growth, so it's safe to
    /// call at syscall time under the bump-heap reset. The base was fixed at [`reserve`](Self::reserve)
    /// time and is left unchanged. `name` is truncated to [`MAX_STEM`]. Idempotent on the geometry.
    pub fn activate(&mut self, i: usize, name: &[u8], image_size: u64, entry_rva: u32) {
        if let Some(d) = self.dlls.get_mut(i) {
            let n = name.len().min(MAX_STEM);
            d.name_buf[..n].copy_from_slice(&name[..n]);
            d.name_len = n;
            d.image_size = image_size;
            d.entry_rva = entry_rva;
        }
    }

    /// The index of the first reserved (unactivated) slot, or `None` if all slots are in use. The
    /// demand-load path claims one of these on a `resolve_name` miss.
    pub fn first_free(&self) -> Option<usize> {
        self.dlls.iter().position(|d| d.name_len == 0)
    }

    /// True if slot `i` is activated (has a stem).
    pub fn is_active(&self, i: usize) -> bool {
        self.dlls.get(i).map(|d| d.name_len != 0).unwrap_or(false)
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

    /// The lowercase stem of DLL `i` (empty if out of range or a reserved slot) — for diagnostics.
    pub fn name(&self, i: usize) -> &[u8] {
        self.dlls.get(i).map(|d| &d.name_buf[..d.name_len]).unwrap_or(b"")
    }

    /// True if `name` (any case) is an SxS/actctx probe the loader must be steered away from:
    /// `foo.local`, `foo.manifest`, or `foo.config`. Matching such a probe as a real DLL diverts
    /// the loader into DLL-redirection / manifest parsing instead of the normal System32 search.
    pub fn is_sxs_probe(name: &[u8]) -> bool {
        contains(name, b".local") || contains(name, b".manifest") || contains(name, b".config")
    }

    /// Resolve a possibly-full object name to a registered DLL index. Returns `None` for an SxS
    /// probe, a non-DLL leaf, or an unregistered identity. The final `\`- or `/`-delimited component
    /// must equal either the registered stem or `<stem>.dll`; arbitrary substring and suffix matches
    /// are deliberately rejected so identities such as `sfc`, `sfc_os`, and `sfcfiles` cannot alias.
    /// The caller passes a lowercased-ASCII fold of the UTF-16 object name.
    pub fn resolve_name(&self, name: &[u8]) -> Option<usize> {
        if Self::is_sxs_probe(name) {
            return None;
        }
        let stem = dll_stem(name)?;
        self.dlls
            .iter()
            .enumerate()
            .find(|(_, d)| d.name_len != 0 && stem == &d.name_buf[..d.name_len])
            .map(|(i, _)| i)
    }

    /// The NtOpenFile handle DLL `i` has in process `pi`'s handle namespace (0 = none / out of
    /// range). The per-pi read half of the growable store.
    pub fn file_handle(&self, pi: usize, i: usize) -> u64 {
        self.dlls.get(i).and_then(|d| d.file_handle.get(pi)).copied().unwrap_or(0)
    }

    /// Record the NtOpenFile handle for DLL `i`, owned by process `pi` (handles are process-local).
    /// Grows the per-pi store on demand — no fixed process ceiling (see [`PI_RESERVE`] for the
    /// bump-heap-reset caveat past the reserve).
    pub fn set_file_handle(&mut self, pi: usize, i: usize, handle: u64) {
        if let Some(d) = self.dlls.get_mut(i) {
            *slot_mut(&mut d.file_handle, pi) = handle;
        }
    }

    /// The DLL a (non-zero) file handle belongs to, **within process `pi`'s handle namespace**.
    /// The same handle VALUE in a different process is a different handle, so the lookup is scoped
    /// to `pi` and never matches another process's identical value.
    pub fn index_for_file(&self, pi: usize, handle: u64) -> Option<usize> {
        if handle == 0 {
            return None;
        }
        self.dlls.iter().position(|d| d.file_handle.get(pi).copied() == Some(handle))
    }

    /// The NtCreateSection handle DLL `i` has in process `pi`'s handle namespace (0 = none).
    pub fn section_handle(&self, pi: usize, i: usize) -> u64 {
        self.dlls.get(i).and_then(|d| d.section_handle.get(pi)).copied().unwrap_or(0)
    }

    /// Record the NtCreateSection handle for DLL `i`, owned by process `pi`. Grows on demand.
    pub fn set_section_handle(&mut self, pi: usize, i: usize, handle: u64) {
        if let Some(d) = self.dlls.get_mut(i) {
            *slot_mut(&mut d.section_handle, pi) = handle;
        }
    }

    /// The DLL a (non-zero) section handle belongs to, **within process `pi`'s handle namespace**.
    pub fn index_for_section(&self, pi: usize, handle: u64) -> Option<usize> {
        if handle == 0 {
            return None;
        }
        self.dlls.iter().position(|d| d.section_handle.get(pi).copied() == Some(handle))
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

/// Extract the exact folded DLL identity from a bare name or final path component.
fn dll_stem(name: &[u8]) -> Option<&[u8]> {
    let leaf_start = name
        .iter()
        .rposition(|&byte| byte == b'\\' || byte == b'/')
        .map(|index| index + 1)
        .unwrap_or(0);
    let leaf = &name[leaf_start..];
    let stem = leaf.strip_suffix(b".dll".as_slice()).unwrap_or(leaf);
    (!stem.is_empty()).then_some(stem)
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
        // The caller folds case before calling; resolve_name compares the already-folded identity.
        assert_eq!(r.resolve_name(b"csrsrv"), Some(0));
    }

    #[test]
    fn vista_supersets_are_distinct_exact_identities() {
        // ReactOS ships kernel32_vista.dll / advapi32_vista.dll whose stems are supersets of the
        // base names. Exact identity matching must select each entry independent of registration
        // order rather than depending on a longest-substring heuristic.
        let mut r = Registry::new(0x8000_0000, 0x0100_0000);
        r.register(b"kernel32", 0x2A_8000, 0x1000); // base name registered FIRST
        r.register(b"kernel32_vista", 0x8000, 0x2000);
        r.register(b"advapi32_vista", 0x5A00, 0x3000);
        r.register(b"advapi32", 0x7_1E00, 0x4000);
        let k = r.resolve_name(b"\\systemroot\\system32\\kernel32_vista.dll").unwrap();
        assert_eq!(r.name(k), b"kernel32_vista");
        let a = r.resolve_name(b"advapi32_vista.dll").unwrap();
        assert_eq!(r.name(a), b"advapi32_vista");
        // The base names still resolve to themselves (they don't contain the longer stems).
        assert_eq!(r.name(r.resolve_name(b"kernel32.dll").unwrap()), b"kernel32");
        assert_eq!(r.name(r.resolve_name(b"advapi32.dll").unwrap()), b"advapi32");
    }

    #[test]
    fn sfc_family_names_never_alias() {
        let mut r = Registry::new(0x8000_0000, 0x0100_0000);
        let sfc = r.register(b"sfc", 0x1000, 0x100);
        let sfcfiles = r.register(b"sfcfiles", 0x2000, 0x200);
        let sfc_os_slot = r.reserve();

        assert_eq!(r.resolve_name(b"sfc.dll"), Some(sfc));
        assert_eq!(r.resolve_name(b"sfcfiles.dll"), Some(sfcfiles));
        assert_eq!(r.resolve_name(b"sfc_os.dll"), None);
        assert_eq!(r.resolve_name(b"not-sfc.dll"), None);

        r.activate(sfc_os_slot, b"sfc_os", 0x3000, 0x300);
        assert_eq!(r.resolve_name(b"sfc_os.dll"), Some(sfc_os_slot));
        assert_eq!(r.resolve_name(b"sfc_os"), Some(sfc_os_slot));
        assert_eq!(r.resolve_name(b"sfc.dll"), Some(sfc));
        assert_eq!(r.resolve_name(b"sfcfiles.dll"), Some(sfcfiles));
    }

    #[test]
    fn resolve_accepts_nt_dos_and_forward_slash_paths() {
        let r = seeded();
        assert_eq!(r.resolve_name(b"\\??\\c:\\reactos\\system32\\csrsrv.dll"), Some(0));
        assert_eq!(r.resolve_name(b"c:/reactos/system32/basesrv.dll"), Some(1));
        assert_eq!(r.resolve_name(b"\\systemroot\\system32\\\\winsrv.dll"), Some(2));
    }

    #[test]
    fn malformed_or_nonfinal_substrings_do_not_resolve() {
        let r = seeded();
        assert_eq!(r.resolve_name(b"c:\\reactos\\system32\\prefixwinsrv.dll"), None);
        assert_eq!(r.resolve_name(b"c:\\reactos\\system32winsrv.dll"), None);
        assert_eq!(r.resolve_name(b"c:\\reactos\\winsrv.dll\\trailer"), None);
        assert_eq!(r.resolve_name(b"c:\\reactos\\system32\\winsrv.dll.bak"), None);
        assert_eq!(r.resolve_name(b"c:\\reactos\\system32\\winsrv"), Some(2));
        assert_eq!(r.resolve_name(b"c:\\reactos\\system32\\"), None);
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
        assert_eq!(r.index_for_file(1, 0), None); // a zero handle never matches
        r.set_file_handle(1, 1, 0x5a5a_0007); // csrss (pi 1) opens basesrv
        assert_eq!(r.index_for_file(1, 0x5a5a_0007), Some(1));
        assert_eq!(r.index_for_file(1, 0x1234), None);
        r.set_section_handle(1, 1, 0x5a5a_0009);
        assert_eq!(r.index_for_section(1, 0x5a5a_0009), Some(1));
        assert_eq!(r.index_for_section(1, 0), None);
    }

    #[test]
    fn handles_are_process_local() {
        // The load-bearing property for path 1b: process-local handle VALUES may COLLIDE across
        // processes yet refer to DIFFERENT DLLs, and the per-pi lookup resolves each correctly.
        let mut r = seeded();
        // csrss (pi 1) and winlogon (pi 2) BOTH get dense handle value 0x4 — csrss's 0x4 is csrsrv,
        // winlogon's 0x4 is winsrv. No global scheme could tell these apart; the per-pi key does.
        r.set_file_handle(1, 0, 0x4); // csrss: handle 0x4 -> csrsrv (dll 0)
        r.set_file_handle(2, 2, 0x4); // winlogon: handle 0x4 -> winsrv (dll 2)
        assert_eq!(r.index_for_file(1, 0x4), Some(0)); // csrss's 0x4
        assert_eq!(r.index_for_file(2, 0x4), Some(2)); // winlogon's 0x4 — a different object
        // A process that never opened handle 0x4 doesn't see the other process's binding.
        assert_eq!(r.index_for_file(0, 0x4), None); // smss
        // Same for section handles.
        r.set_section_handle(1, 0, 0x8);
        r.set_section_handle(2, 2, 0x8);
        assert_eq!(r.index_for_section(1, 0x8), Some(0));
        assert_eq!(r.index_for_section(2, 0x8), Some(2));
        // A never-set owner index reads back 0 and matches nothing (no panic, no ceiling).
        assert_eq!(r.file_handle(7, 0), 0);
        assert_eq!(r.index_for_file(7, 0x4), None);
    }

    #[test]
    fn per_pi_handles_grow_past_the_reserve_no_ceiling() {
        // The load-bearing property for > PI_RESERVE processes: set/get handles for pi 0..24
        // (well past PI_RESERVE) with NO fixed ceiling — the per-pi store grows on demand and
        // every prior pi's value is retained (dynamic, not a hard 5- or 16-slot array).
        let mut r = seeded();
        let n = PI_RESERVE + 8; // 24 processes: past the pre-reserve
        for pi in 0..n {
            // Each process gets a distinct handle value for csrsrv (dll 0) + winsrv (dll 2).
            r.set_file_handle(pi, 0, 0x1000 + pi as u64);
            r.set_section_handle(pi, 2, 0x2000 + pi as u64);
        }
        // Read them all back — none clobbered, none lost past the reserve.
        for pi in 0..n {
            assert_eq!(r.file_handle(pi, 0), 0x1000 + pi as u64, "file handle pi={pi}");
            assert_eq!(r.index_for_file(pi, 0x1000 + pi as u64), Some(0));
            assert_eq!(r.section_handle(pi, 2), 0x2000 + pi as u64, "section handle pi={pi}");
            assert_eq!(r.index_for_section(pi, 0x2000 + pi as u64), Some(2));
        }
        // A high pi's value never leaks into a different pi's namespace.
        assert_eq!(r.index_for_file(0, 0x1000 + 23), None);
        // Unset dll/pi combos still read 0.
        assert_eq!(r.file_handle(23, 1), 0); // pi 23 never opened basesrv (dll 1)
    }

    #[test]
    fn reserve_capacity_is_preallocated_at_register() {
        // register() pre-reserves PI_RESERVE slots so runtime sets within the reserve are pure
        // in-place writes (bump-heap-reset-safe). The store starts zeroed for every reserved pi.
        let r = seeded();
        for pi in 0..PI_RESERVE {
            assert_eq!(r.file_handle(pi, 0), 0);
            assert_eq!(r.section_handle(pi, 0), 0);
        }
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
    fn reserved_slots_match_nothing_until_activated() {
        // The demand-load enabler: reserving a slot at boot fixes its base + pre-allocates its
        // handle stores, but it must resolve to NOTHING (name_len == 0) until activated on demand.
        let mut r = Registry::new(0x8000_0000, 0x0100_0000);
        r.register(b"csrsrv", 0x1_1000, 0x1200); // slot 0 = the pinned base 0x8000_0000
        let free0 = r.reserve(); // slot 1 (base 0x8100_0000), empty
        let free1 = r.reserve(); // slot 2 (base 0x8200_0000), empty
        assert_eq!((free0, free1), (1, 2));
        assert!(!r.is_active(free0));
        assert_eq!(r.first_free(), Some(1));
        // A DLL name that WOULD land in a reserved slot resolves to None while the slot is empty
        // (so the caller knows to demand-load it), and to csrsrv only for csrsrv paths.
        assert_eq!(r.resolve_name(b"\\systemroot\\system32\\version.dll"), None);
        assert_eq!(r.name(free0), b""); // reserved → empty diagnostic name
        assert_eq!(r.base(free0), 0x8100_0000); // base fixed at reserve time (collision-free)
        // Activate slot 1 on demand (as the executive would after an FS load) — base UNCHANGED.
        r.activate(free0, b"version", 0x9000, 0x2100);
        assert!(r.is_active(free0));
        assert_eq!(r.base(free0), 0x8100_0000); // still its reserved base
        assert_eq!(r.resolve_name(b"\\systemroot\\system32\\version.dll"), Some(1));
        assert_eq!(r.name(free0), b"version");
        assert_eq!(r.image_info(free0), Some(image_info(0x8100_0000, 0x2100, 0x9000, true)));
        // first_free now points past the activated slot.
        assert_eq!(r.first_free(), Some(2));
    }

    #[test]
    fn register_is_reserve_plus_activate() {
        // register() must be exactly reserve()+activate() — same base assignment, resolvable name.
        let mut a = Registry::new(0x8000_0000, 0x0100_0000);
        a.register(b"csrsrv", 0x1_1000, 0x1200);
        a.register(b"basesrv", 0xD000, 0x2400);
        let mut b = Registry::new(0x8000_0000, 0x0100_0000);
        b.register(b"csrsrv", 0x1_1000, 0x1200);
        let i = b.reserve();
        b.activate(i, b"basesrv", 0xD000, 0x2400);
        assert_eq!(a.base(1), b.base(1));
        assert_eq!(a.name(1), b.name(1));
        assert_eq!(a.image_info(1), b.image_info(1));
        assert_eq!(a.resolve_name(b"basesrv.dll"), b.resolve_name(b"basesrv.dll"));
    }

    #[test]
    fn all_slots_can_be_reserved_then_first_free_returns_none() {
        let mut r = Registry::new(0x8000_0000, 0x0100_0000);
        for _ in 0..4 {
            r.reserve();
        }
        for i in 0..4 {
            assert!(!r.is_active(i));
        }
        // Activate all → first_free exhausts.
        for i in 0..4 {
            r.activate(i, b"x", 0x1000, 0);
        }
        assert_eq!(r.first_free(), None);
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
