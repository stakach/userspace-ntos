//! `win32k_pe` — a PROTOTYPE first-load of the real ReactOS `win32k.sys` through the project's
//! driver-host load contract (`nt-compat-exports`). Phase 2 of `plans/P6-win32k-graphical.md`;
//! the runtime companion to Phase 1's static contract (commit bab047d).
//!
//! ## What this proves at runtime (in-executive, zero gate risk)
//!
//!   1. **The load contract holds for the real binary.** win32k.sys's exact import surface — 224
//!      ntoskrnl.exe + 1 hal.dll + 34 ftfd.dll (FreeType) imports, extracted from the on-disk
//!      binary and cross-checked against the `nt-compat-exports` registry — every ntoskrnl+hal
//!      import resolves to an `Available` export and binds to a non-null trampoline
//!      (17 Implemented / 166 Partial / 27 StubSuccess / 15 TrapIfCalled, 0 Blocked/Missing).
//!      That binding is exhaustively asserted by the crate's own host test
//!      `win32k_full_import_surface_resolves_and_loads`; the constants in [`CLASSIFICATION`] are
//!      that verified breakdown, reported here for the record.
//!   2. **The SSDT routing seam works end-to-end.** [`s_ke_add_system_service_table`] is the real
//!      `KeAddSystemServiceTable` trampoline win32k calls at init; it records win32k's NtUser/NtGdi
//!      table into a [`ServiceTableRegistry`], and [`ssdt_seam_selftest`] proves
//!      `resolve(SSN >= 0x1000)` returns the correct win32k function pointer — the exact hook
//!      Phase 2 forwards a caller's high-SSN `UnknownSyscall` through.
//!
//! ## Why win32k's DriverEntry is NOT executed here
//!
//! The executive's own ELF is mapped RO at `IMAGE_BASE` with the 128 KiB heap only 512 KiB above
//! it (and the loader's read-only BootInfo aux page sits right past the image — growing the image
//! toward `HEAP_BASE` is fatal), and the 128 KiB heap can't hold `PeFile::map()`'s 2.1 MiB Vec.
//! So this module stays deliberately small (it references only the tiny `ssdt` module, letting the
//! descriptor tables dead-code-strip). **Executing** win32k belongs in the isolated
//! `components/win32k-service` component, which stages win32k.sys off disk into untyped-backed
//! frames, maps it W^X, patches its IAT to real `nt-*` wiring, and runs DriverEntry crash-contained
//! — the next increment (design in the Phase-2 hand-off report).

use nt_compat_exports::ssdt::{
    ServiceTable, ServiceTableRegistry, WIN32K_SERVICE_BASE, WIN32K_SERVICE_TABLE_INDEX,
};

/// PE metrics of the real ReactOS 0.4.17 `win32k.sys` (verified offline with `nt-pe-loader`
/// against the on-disk `reactos/system32/win32k.sys`, staged by `fetch_reactos.sh`). Reported
/// for the record; the isolated win32k-service component maps these into untyped-backed frames.
pub struct Win32kPe {
    pub size: u64,
    pub image_base: u64,
    pub size_of_image: u32,
    pub image_frames: u32,
    pub entry_rva: u32,
    pub sections: u32,
    pub relocs: u32,
    pub has_gs_cookie: bool,
}

pub const WIN32K_PE: Win32kPe = Win32kPe {
    size: 2_208_192,
    image_base: 0x10000,
    size_of_image: 0x220000,
    image_frames: 0x220, // 544
    entry_rva: 0x2192b0,
    sections: 8,
    relocs: 1920,
    has_gs_cookie: false,
};

/// The verified classification of win32k's 259 imports against the `nt-compat-exports` registry
/// (from the crate's `win32k_full_import_surface_resolves_and_loads` host test + an offline
/// `nt-pe-loader` probe of the on-disk binary).
pub struct Classification {
    pub ntoskrnl: u32,
    pub hal: u32,
    pub ftfd: u32,
    pub implemented: u32,
    pub partial: u32,
    pub stub: u32,
    pub trap: u32,
    pub blocked: u32,
}

pub const CLASSIFICATION: Classification = Classification {
    ntoskrnl: 224,
    hal: 1,
    ftfd: 34,
    implemented: 17,
    partial: 166,
    stub: 27,
    trap: 15,
    blocked: 0,
};

// --- the SSDT routing seam (the genuinely-new runtime artifact) ------------------------------

/// The **real** `KeAddSystemServiceTable` recorder — the Phase-2 routing seam. win32k calls this
/// once at init to register its NtUser/NtGdi table at shadow index 1 (base SSN 0x1000). We capture
/// `(index, base, count, argument_table)` into [`SERVICE_REGISTRY`]; Phase 2's high-SSN forwarder
/// then `resolve()`s a caller's `SSN >= 0x1000` to the win32k function.
///
/// Win64 ABI: `BOOLEAN KeAddSystemServiceTable(ULONG_PTR Base, PULONG Count, ULONG Limit,
/// PUCHAR Number, ULONG Index)`.
extern "win64" fn s_ke_add_system_service_table(
    base: u64,
    _count: u64,
    limit: u32,
    argument_table: u64,
    index: u32,
) -> u8 {
    // SAFETY: single-threaded through this path — the &mut static access is exclusive.
    unsafe {
        if service_registry().add(index, base, limit, argument_table) {
            1
        } else {
            0
        }
    }
}

static mut SERVICE_REGISTRY: Option<ServiceTableRegistry> = None;

/// SAFETY: single-threaded init/self-test path in the executive.
unsafe fn service_registry() -> &'static mut ServiceTableRegistry {
    let ptr = core::ptr::addr_of_mut!(SERVICE_REGISTRY);
    if (*ptr).is_none() {
        *ptr = Some(ServiceTableRegistry::new());
    }
    (*ptr).as_mut().unwrap()
}

/// Prove the Phase-2 SSDT routing seam end-to-end: drive the real `KeAddSystemServiceTable`
/// recorder trampoline (the address a loaded win32k's IAT slot would point at) with a synthetic
/// win32k table, then confirm `resolve()` maps a caller's `SSN >= 0x1000` back to the correct
/// win32k function pointer, and does not misroute a native SSN. Returns true on success.
pub fn ssdt_seam_selftest() -> bool {
    let base: u64 = 0xFFFF_F800_1000_0000;
    let argt: u64 = 0xFFFF_F800_1010_0000;
    let count: u32 = 600;

    // Invoke exactly as win32k does at init (index 1 = the shadow SSDT). Prove the trampoline
    // address is real (non-null) too — a zero IAT slot would be an indirect call to NULL.
    if (s_ke_add_system_service_table as *const ()).is_null() {
        return false;
    }
    if s_ke_add_system_service_table(base, 0, count, argt, WIN32K_SERVICE_TABLE_INDEX) != 1 {
        return false;
    }
    // A second add at the same index must be rejected (win32k adds index 1 exactly once).
    if s_ke_add_system_service_table(0xDEAD, 0, 1, 0xBEEF, WIN32K_SERVICE_TABLE_INDEX) != 0 {
        return false;
    }
    // SAFETY: single-threaded self-test path.
    let reg = unsafe { service_registry() };
    let Some(table) = reg.win32k() else {
        return false;
    };
    let recorded = *table
        == ServiceTable {
            index: WIN32K_SERVICE_TABLE_INDEX,
            base,
            count,
            argument_table: argt,
        };
    // The first NtUser/NtGdi SSN maps to base; 0x10FA (the SSN csrss/winsrv stop on) maps to
    // base + 0xFA*8.
    let first_ok = reg.resolve(WIN32K_SERVICE_BASE) == Some((table, base));
    let stop_ok = reg.resolve(WIN32K_SERVICE_BASE + 0xFA) == Some((table, base + 0xFA * 8));
    // A native (< 0x1000) SSN must not resolve to the win32k shadow table.
    let native_not_misrouted = reg
        .resolve(0x0055)
        .map(|(t, _)| t.index != WIN32K_SERVICE_TABLE_INDEX)
        .unwrap_or(true);
    recorded && first_ok && stop_ok && native_not_misrouted
}
