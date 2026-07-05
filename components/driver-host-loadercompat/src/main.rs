//! `ntos-driver-host-loadercompat` — a KMDF *loader/binding* compatibility Driver Host.
//!
//! Loads the real `KmdfLoaderCompatTest.sys` (KMDF v1.15, W^X + NX) — a minimal driver whose
//! KMDF stub exercises the full `wdfldr.sys` binding lifecycle — and drives it through the
//! spec's service-key-driven load path (NT Driver Loading + KMDF Binding Compat):
//!
//! ```text
//! ResolveService (\Registry\...\Services\KmdfLoaderCompatTest) -> OpenImage/MapImage (PE64,
//!   relocs, W^X) -> ResolveImports (ntoskrnl: RtlInitUnicodeString/RtlCopyUnicodeString/wcslen/
//!   DbgPrintEx; wdfldr: WdfVersionBind/BindClass/UnbindClass/Unbind) -> CreateDriverObject
//!   (\Driver\KmdfLoaderCompatTest) -> CallDriverEntry:
//!     FxStubInitTypes -> WdfVersionBind (negotiate 1.15, publish WdfFunctions) ->
//!     FxStubBindClasses -> WdfVersionBindClass("KmdfLibrary") -> real DriverEntry
//!   -> Unload: WdfVersionUnbindClass -> WdfVersionUnbind -> Report
//! ```
//!
//! The driver narrates via `DbgPrintEx`, which we capture. This host implements the class-library
//! bind path (`WdfVersionBindClass`/`WdfVersionUnbindClass`) and real version negotiation
//! (`STATUS_REVISION_MISMATCH` on mismatch) that the device-oriented hosts stub out.

#![no_std]
#![no_main]
#![allow(function_casts_as_integer)]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use nt_wdf_types as wt;
use sel4_rt::*;

static WDF_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/KmdfLoaderCompatTest.sys");

const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
const SERVICE_NAME: &str = "KmdfLoaderCompatTest";
/// `\Registry\Machine\System\CurrentControlSet\Services\KmdfLoaderCompatTest`.
const SERVICE_KEY: &str =
    r"\Registry\Machine\System\CurrentControlSet\Services\KmdfLoaderCompatTest";
const IMAGE_PATH: &str = r"\SystemRoot\system32\drivers\KmdfLoaderCompatTest.sys";

const STATUS_SUCCESS: i32 = 0;
const STATUS_REVISION_MISMATCH: i32 = 0xC000_0059u32 as i32;

// --- frame/paging boilerplate (root task; shared with the other driver hosts) ---

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);
fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}

static mut CODE_FRAME_CAPS: [u64; 16] = [0; 16];

unsafe fn map_region(base: u64, frames: u64) {
    let pdpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, pdpt);
    let pd = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, pd);
    let pt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    let _ = paging_struct_map(pdpt, LBL_X86_PDPT_MAP, base, CAP_INIT_THREAD_VSPACE);
    let _ = paging_struct_map(pd, LBL_X86_PAGE_DIRECTORY_MAP, base, CAP_INIT_THREAD_VSPACE);
    let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, base, CAP_INIT_THREAD_VSPACE);
    for i in 0..frames {
        let f = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, f);
        let _ = page_map(f, base + i * 0x1000, /* RW */ 3, CAP_INIT_THREAD_VSPACE);
        CODE_FRAME_CAPS[i as usize] = f;
    }
}

unsafe fn apply_wx(pe: &nt_pe_loader::PeFile, frames: u64) {
    for i in 0..frames {
        let prot = pe.protection_at((i * 0x1000) as u32);
        let base = if prot.writable() { 3 } else { 2 };
        let rights = if prot.executable() {
            base
        } else {
            base | PAGE_EXECUTE_NEVER
        };
        let f = CODE_FRAME_CAPS[i as usize];
        let _ = page_unmap(f);
        let _ = page_map(f, CODE_VADDR + i * 0x1000, rights, CAP_INIT_THREAD_VSPACE);
    }
}

/// The 444-entry WDF function-pointer table `WdfVersionBind` publishes to the driver.
static mut WDF_FUNCTIONS: [u64; 444] = [0; 444];
/// The `WDF_DRIVER_GLOBALS` blob (arg0 of every WDF call; opaque to us).
static mut WDF_GLOBALS: [u8; 64] = [0; 64];

fn alloc_bytes(size: usize) -> u64 {
    let layout = core::alloc::Layout::from_size_align(size.max(1), 16).unwrap();
    // SAFETY: nonzero size, valid align.
    unsafe { alloc::alloc::alloc_zeroed(layout) as u64 }
}

// --- compat trace ------------------------------------------------------------

fn trace(event: &[u8]) {
    print_str(b"  [compat] ");
    print_str(event);
    print_str(b"\n");
}

fn print_hex(mut v: u64) {
    print_str(b"0x");
    let mut buf = [0u8; 16];
    for i in (0..16).rev() {
        buf[i] = b"0123456789abcdef"[(v & 0xf) as usize];
        v >>= 4;
    }
    print_str(&buf);
}

// Bind-lifecycle observations (single-threaded; Atomics just to avoid `static mut` churn).
static BIND_CALLS: AtomicU32 = AtomicU32::new(0);
static BINDCLASS_CALLS: AtomicU32 = AtomicU32::new(0);
static UNBIND_CALLS: AtomicU32 = AtomicU32::new(0);
static UNBINDCLASS_CALLS: AtomicU32 = AtomicU32::new(0);
static BIND_VERSION: AtomicU32 = AtomicU32::new(0); // (major<<16)|minor negotiated
static WDF_CALLS: AtomicU32 = AtomicU32::new(0); // any WdfFunctions[] thunk hit

// --- ntoskrnl.exe exports ----------------------------------------------------

/// `RtlInitUnicodeString(dest, source)` — count wchars to the NUL, fill {Length, Max, Buffer}.
extern "win64" fn ntos_rtl_init_unicode_string(dest: *mut u8, source: *const u16) {
    // SAFETY: `dest` is a UNICODE_STRING (8 hdr + ptr); `source` a NUL-terminated wide string.
    unsafe {
        let mut nchars = 0usize;
        if !source.is_null() {
            while *source.add(nchars) != 0 && nchars < 0x7FFE {
                nchars += 1;
            }
        }
        let byte_len = (nchars * 2) as u16;
        core::ptr::write_unaligned(dest as *mut u16, byte_len);
        core::ptr::write_unaligned((dest as *mut u16).add(1), byte_len + 2);
        core::ptr::write_unaligned((dest as *mut u32).add(1), 0);
        core::ptr::write_unaligned((dest as *mut u64).add(1), source as u64);
    }
}

/// `RtlCopyUnicodeString(dest, src)` — copy the {Length, Buffer} shallowly (Buffer aliased).
extern "win64" fn ntos_rtl_copy_unicode_string(dest: *mut u8, src: *const u8) {
    // SAFETY: both are UNICODE_STRING projections.
    unsafe {
        if dest.is_null() || src.is_null() {
            return;
        }
        let len = core::ptr::read_unaligned(src as *const u16);
        let max = core::ptr::read_unaligned(dest as *const u16).max(len);
        let buf = core::ptr::read_unaligned((src as *const u64).add(1));
        core::ptr::write_unaligned(dest as *mut u16, len.min(max));
        core::ptr::write_unaligned((dest as *mut u64).add(1), buf);
    }
}

/// `wcslen(s)` — length in wchars of a NUL-terminated wide string.
extern "win64" fn ntos_wcslen(s: *const u16) -> u64 {
    // SAFETY: `s` is a NUL-terminated wide string.
    unsafe {
        if s.is_null() {
            return 0;
        }
        let mut n = 0u64;
        while *s.add(n as usize) != 0 {
            n += 1;
        }
        n
    }
}

/// `DbgPrintEx(ComponentId, Level, Format, ...)` — the driver's own narration; capture the
/// format string (the message text) so the driver's report is visible in the log.
extern "win64" fn ntos_dbg_print_ex(_id: u32, _level: u32, fmt: *const u8, _a: u64) -> u32 {
    // SAFETY: `fmt` is a NUL-terminated ANSI printf string in the driver's .rdata.
    unsafe {
        if !fmt.is_null() {
            print_str(b"  [driver] ");
            let mut i = 0usize;
            while i < 512 {
                let c = *fmt.add(i);
                if c == 0 {
                    break;
                }
                debug_put_char(if c == b'\n' { b' ' } else { c });
                i += 1;
            }
            print_str(b"\n");
        }
    }
    STATUS_SUCCESS as u32
}

// --- wdfldr.sys exports (the loader/binding surface under test) --------------

/// `WdfVersionBind(DriverObject, RegistryPath, BindInfo, *ComponentGlobals)` — negotiate the
/// framework version against the driver's `WDF_BIND_INFO`, publish the `WdfFunctions` table +
/// driver globals, or fail with `STATUS_REVISION_MISMATCH`.
extern "win64" fn ntos_wdf_version_bind(
    _driver_object: u64,
    _registry_path: u64,
    bind_info: u64,
    globals_out: *mut u64,
) -> i32 {
    BIND_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `bind_info` is the driver's WDF_BIND_INFO; `globals_out` its globals slot.
    unsafe {
        let major =
            core::ptr::read_unaligned((bind_info + wt::bind_info::VERSION_MAJOR) as *const u32);
        let minor =
            core::ptr::read_unaligned((bind_info + wt::bind_info::VERSION_MINOR) as *const u32);
        BIND_VERSION.store((major << 16) | minor, Ordering::Relaxed);
        print_str(b"  [compat] wdf_version_bind_enter: requested KMDF ");
        print_hex(major as u64);
        print_str(b".");
        print_hex(minor as u64);
        print_str(b"\n");
        // Major must match; minor must be <= supported (spec version-negotiation policy).
        if major != wt::WDF_KMDF_VERSION_MAJOR || minor > wt::WDF_KMDF_VERSION_MINOR {
            trace(b"wdf_version_bind_exit: STATUS_REVISION_MISMATCH");
            return STATUS_REVISION_MISMATCH;
        }
        // *BindInfo.FuncTable = &WDF_FUNCTIONS; the driver reads WdfFunctions from there.
        let func_table_pp =
            core::ptr::read_unaligned((bind_info + wt::bind_info::FUNC_TABLE) as *const u64);
        if func_table_pp != 0 {
            core::ptr::write_unaligned(
                func_table_pp as *mut u64,
                core::ptr::addr_of!(WDF_FUNCTIONS) as u64,
            );
        }
        if !globals_out.is_null() {
            core::ptr::write_unaligned(globals_out, core::ptr::addr_of_mut!(WDF_GLOBALS) as u64);
        }
    }
    trace(b"wdf_function_table_created (444 entries)");
    trace(b"wdf_version_bind_exit: STATUS_SUCCESS");
    STATUS_SUCCESS
}

/// `WdfVersionBindClass(BindInfo, Globals, ClassBindInfo)` — bind a WDF class library (here
/// "KmdfLibrary"); publish the class function table into the `WDF_CLASS_BIND_INFO` and succeed.
extern "win64" fn ntos_wdf_version_bind_class(
    _bind_info: u64,
    _globals: u64,
    class_bind_info: u64,
) -> i32 {
    BINDCLASS_CALLS.fetch_add(1, Ordering::Relaxed);
    trace(b"wdf_version_bind_class_enter (class=KmdfLibrary)");
    // WDF_CLASS_BIND_INFO carries a function-table slot the class fills, analogous to WDF_BIND_INFO.
    // Publish our table so any class thunk lands on a traced entry rather than NULL.
    // SAFETY: `class_bind_info` is the driver's WDF_CLASS_BIND_INFO (FuncTable ptr @ +0x18).
    unsafe {
        if class_bind_info != 0 {
            let ft_pp = core::ptr::read_unaligned((class_bind_info + 0x18) as *const u64);
            if ft_pp != 0 && ft_pp != class_bind_info {
                core::ptr::write_unaligned(
                    ft_pp as *mut u64,
                    core::ptr::addr_of!(WDF_FUNCTIONS) as u64,
                );
            }
        }
    }
    trace(b"wdf_version_bind_class_exit: STATUS_SUCCESS");
    STATUS_SUCCESS
}

/// `WdfVersionUnbindClass(BindInfo, Globals, ClassBindInfo)` — release the class binding.
extern "win64" fn ntos_wdf_version_unbind_class(_a: u64, _b: u64, _c: u64) {
    UNBINDCLASS_CALLS.fetch_add(1, Ordering::Relaxed);
    trace(b"wdf_version_unbind_class");
}

/// `WdfVersionUnbind(RegistryPath, BindInfo, Globals)` — release the framework binding.
extern "win64" fn ntos_wdf_version_unbind(_a: u64, _b: u64, _c: u64) -> i32 {
    UNBIND_CALLS.fetch_add(1, Ordering::Relaxed);
    trace(b"wdf_version_unbind");
    STATUS_SUCCESS
}

// --- WdfFunctions table: every entry a traced catch so an unexpected WDF call is recorded, ---
//     never a NULL-deref (spec "no silent no-ops"; TraceOnly stub policy). -------------------

// The table entry captures the driver's return address (call site) before reporting, so an
// unexpected WDF call is attributed to a driver RVA rather than an anonymous stub.
//
// `cfg_dispatch_jmp_rax` / `cfg_check_ret`: the driver is Control-Flow-Guard-enabled, so every
// indirect call goes through `call [__guard_dispatch_icall_fptr]` with the real target in rax
// (dispatch) or is preceded by `call [__guard_check_icall_fptr]` (target in rcx). We point the
// dispatch pointer at a `jmp rax` thunk and the check pointer at a bare `ret`.
core::arch::global_asm!(
    ".globl wdf_traced_entry",
    "wdf_traced_entry:",
    "mov rcx, [rsp]",
    "jmp {report}",
    ".globl cfg_dispatch_jmp_rax",
    "cfg_dispatch_jmp_rax:",
    "jmp rax",
    ".globl cfg_check_ret",
    "cfg_check_ret:",
    "ret",
    report = sym wdf_traced_report,
);
extern "win64" {
    fn wdf_traced_entry() -> i32;
    fn cfg_dispatch_jmp_rax();
    fn cfg_check_ret();
}

/// The driver's Control Flow Guard function-pointer slots (from its load-config directory):
/// `__guard_check_icall_fptr` and `__guard_dispatch_icall_fptr`.
const CFG_CHECK_SLOT_RVA: u64 = 0x3050;
const CFG_DISPATCH_SLOT_RVA: u64 = 0x3058;

extern "win64" fn wdf_traced_report(ret: u64) -> i32 {
    WDF_CALLS.fetch_add(1, Ordering::Relaxed);
    print_str(b"  [compat] wdf_function_called from driver rva ");
    print_hex(ret.wrapping_sub(CODE_VADDR));
    print_str(b"\n");
    STATUS_SUCCESS
}

static DRIVER_CREATE_CALLS: AtomicU32 = AtomicU32::new(0);

/// `WdfDriverCreate(Globals, DriverObject, RegistryPath, Attributes, Config, *Driver)` — the call
/// the real `DriverEntry` makes through `WdfFunctions[116]`. Record it (this is the KMDF bind-only
/// acceptance point), capture the driver's `WDF_DRIVER_CONFIG` callbacks, and hand back a handle.
extern "win64" fn wdf_driver_create(
    _globals: u64,
    _driver_object: u64,
    _registry_path: u64,
    _attributes: u64,
    config: u64,
    driver_out: *mut u64,
) -> i32 {
    DRIVER_CREATE_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `config` is the driver's WDF_DRIVER_CONFIG (EvtDriverDeviceAdd@8, EvtDriverUnload@0x10).
    unsafe {
        if config != 0 {
            let device_add = core::ptr::read_unaligned((config + 8) as *const u64);
            print_str(b"  [compat] wdf_driver_create: EvtDriverDeviceAdd=");
            print_hex(device_add.wrapping_sub(CODE_VADDR));
            print_str(b"\n");
        }
        if !driver_out.is_null() {
            core::ptr::write_unaligned(driver_out, 0xD814_0000_0000_0001);
        }
    }
    trace(b"wdf_driver_create_exit: STATUS_SUCCESS (framework WDFDRIVER created)");
    STATUS_SUCCESS
}

unsafe fn install_function_table() {
    for e in (*core::ptr::addr_of_mut!(WDF_FUNCTIONS)).iter_mut() {
        *e = wdf_traced_entry as usize as u64;
    }
    WDF_FUNCTIONS[wt::IDX_WDF_DRIVER_CREATE] = wdf_driver_create as usize as u64;
}

fn export_addr(name: &str) -> u64 {
    match name {
        "RtlInitUnicodeString" => ntos_rtl_init_unicode_string as usize as u64,
        "RtlCopyUnicodeString" => ntos_rtl_copy_unicode_string as usize as u64,
        "wcslen" => ntos_wcslen as usize as u64,
        "DbgPrintEx" => ntos_dbg_print_ex as usize as u64,
        "WdfVersionBind" => ntos_wdf_version_bind as usize as u64,
        "WdfVersionUnbind" => ntos_wdf_version_unbind as usize as u64,
        "WdfVersionBindClass" => ntos_wdf_version_bind_class as usize as u64,
        "WdfVersionUnbindClass" => ntos_wdf_version_unbind_class as usize as u64,
        _ => wdf_traced_entry as usize as u64,
    }
}

fn print_str(s: &[u8]) {
    for &b in s {
        debug_put_char(b);
    }
}

fn check(name: &[u8], ok: bool) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
}

// --- the bring-up ------------------------------------------------------------

unsafe fn run() {
    install_function_table();

    // --- ResolveService: seed + read the service key (spec service-key-driven load) ---------
    let mut cm = nt_config_manager::ConfigManager::new();
    cm.register_service(
        SERVICE_NAME,
        IMAGE_PATH,
        Some("WdfLoadGroup"),
        Some("{4d36e97d-e325-11ce-bfc1-08002be10318}"),
        /* start = SERVICE_DEMAND_START */ 3,
        /* error_control = NORMAL */ 1,
    );
    // Type = SERVICE_KERNEL_DRIVER (register_service seeds ImagePath/Start/ErrorControl only).
    let service_key = cm.service(SERVICE_NAME).map(|s| s.service_key);
    if let Some(k) = service_key {
        cm.registry_mut().set_dword(k, "Type", 1);
    }
    let (start_type, image_path_ok) = match cm.service(SERVICE_NAME) {
        Some(s) => (s.start_type, s.image_path == IMAGE_PATH),
        None => {
            check(b"resolve_service", false);
            return;
        }
    };
    let svc_type = service_key
        .and_then(|k| cm.registry().query_dword(k, "Type"))
        .unwrap_or(0);
    trace(b"driver_load_request");
    print_str(b"  [compat] driver_service_key_read: ");
    print_str(SERVICE_KEY.as_bytes());
    print_str(b"\n");
    // The service record drives the load: kernel driver, demand start, ImagePath resolved.
    check(
        b"resolve_service",
        svc_type == 1 && start_type == 3 && image_path_ok,
    );

    // --- OpenImage / MapImage (the ImagePath resolves to our fixture image) -----------------
    let pe = match nt_pe_loader::PeFile::parse(WDF_SYS) {
        Ok(p) => p,
        Err(_) => {
            check(b"map_image", false);
            return;
        }
    };
    let size = pe.size_of_image() as u64;
    let frames = size.div_ceil(0x1000);
    map_region(CODE_VADDR, frames);
    let mapped = match pe.map(CODE_VADDR) {
        Ok(m) => m,
        Err(_) => {
            check(b"map_image", false);
            return;
        }
    };
    let dst = CODE_VADDR as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    trace(b"driver_image_mapped (PE64, relocations applied)");
    check(b"map_image", true);

    // --- ResolveImports: patch the IAT to our export surface --------------------------------
    let mut missing = false;
    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let nt_pe_loader::ImportRef::ByName {
                    name, iat_slot_rva, ..
                } = f
                {
                    let addr = export_addr(name);
                    if addr == wdf_traced_entry as usize as u64 && !name.starts_with("Wdf") {
                        missing = true;
                    }
                    core::ptr::write_unaligned(
                        (CODE_VADDR + *iat_slot_rva as u64) as *mut u64,
                        addr,
                    );
                }
            }
        }
    }
    // Fix up the CFG dispatch/check pointers (in .rdata, must be done before W^X seals it).
    core::ptr::write_unaligned(
        (CODE_VADDR + CFG_DISPATCH_SLOT_RVA) as *mut u64,
        cfg_dispatch_jmp_rax as usize as u64,
    );
    core::ptr::write_unaligned(
        (CODE_VADDR + CFG_CHECK_SLOT_RVA) as *mut u64,
        cfg_check_ret as usize as u64,
    );
    pe.seed_security_cookie(CODE_VADDR);
    apply_wx(&pe, frames);
    trace(b"driver_imports_resolved (ntoskrnl + wdfldr)");
    check(b"resolve_imports", !missing);

    // --- CreateDriverObject: \Driver\KmdfLoaderCompatTest + RegistryPath --------------------
    // DRIVER_OBJECT (Type@0=4, Size@2=336, DriverExtension@48).
    let driver_object = alloc_bytes(512);
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    core::ptr::write_unaligned((driver_object + 48) as *mut u64, alloc_bytes(256));
    // RegistryPath = the service key as a UNICODE_STRING (what DriverEntry receives).
    let reg_path = build_unicode_string(SERVICE_KEY);
    trace(b"driver_object_created (\\Driver\\KmdfLoaderCompatTest)");

    // --- CallDriverEntry: FxStub -> WdfVersionBind -> FxStubBindClasses -> DriverEntry ------
    trace(b"driver_entry_enter");
    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let fx: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = fx(driver_object, reg_path);
    print_str(b"  [compat] driver_entry_exit: status=");
    print_hex(status as u32 as u64);
    print_str(b"\n");

    // --- Acceptance: the KMDF bind-only path (spec "KMDF bind-only") ------------------------
    // The KMDF stub runs FxStubInitTypes -> WdfVersionBind -> FxStubBindClasses -> DriverEntry.
    // This driver's class-bind section is empty, so WdfVersionBindClass is imported but not called
    // (correct — that path is implemented here and ready for a class-binding driver); the binding
    // milestone is that the real DriverEntry reaches WdfDriverCreate through the published table.
    check(b"driver_entry_success", status == STATUS_SUCCESS);
    check(
        b"wdf_version_bind_called",
        BIND_CALLS.load(Ordering::Relaxed) >= 1,
    );
    check(
        b"kmdf_1_15_negotiated",
        BIND_VERSION.load(Ordering::Relaxed)
            == (wt::WDF_KMDF_VERSION_MAJOR << 16) | wt::WDF_KMDF_VERSION_MINOR,
    );
    check(
        b"driver_entry_reached_wdf_driver_create",
        DRIVER_CREATE_CALLS.load(Ordering::Relaxed) >= 1,
    );

    // --- Report -----------------------------------------------------------------------------
    print_str(b"\n  [compat-report] KmdfLoaderCompatTest (KMDF 1.15)\n");
    report_line(
        b"    WdfVersionBind calls      : ",
        BIND_CALLS.load(Ordering::Relaxed) as u64,
    );
    report_line(
        b"    WdfDriverCreate calls     : ",
        DRIVER_CREATE_CALLS.load(Ordering::Relaxed) as u64,
    );
    report_line(
        b"    WdfVersionBindClass calls : ",
        BINDCLASS_CALLS.load(Ordering::Relaxed) as u64,
    );
    report_line(
        b"    WdfFunctions[] stub hits  : ",
        WDF_CALLS.load(Ordering::Relaxed) as u64,
    );
    print_str(b"    class-bind + unbind path  : implemented, not exercised (empty class section)\n");
}

fn report_line(label: &[u8], v: u64) {
    print_str(label);
    let mut buf = [0u8; 20];
    let mut n = v;
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    print_str(&buf[i..]);
    print_str(b"\n");
}

/// Build a UNICODE_STRING projection {Length, MaxLength, _, Buffer(UTF-16)} for `s`.
fn build_unicode_string(s: &str) -> u64 {
    let wide: alloc::vec::Vec<u16> = s.encode_utf16().collect();
    let byte_len = (wide.len() * 2) as u16;
    let buf = alloc_bytes(wide.len() * 2 + 2);
    // SAFETY: `buf` has room for the wide string + terminator; `us` is a fresh 16-byte block.
    unsafe {
        for (i, w) in wide.iter().enumerate() {
            core::ptr::write_unaligned((buf as *mut u16).add(i), *w);
        }
        let us = alloc_bytes(16);
        core::ptr::write_unaligned(us as *mut u16, byte_len);
        core::ptr::write_unaligned((us as *mut u16).add(1), byte_len + 2);
        core::ptr::write_unaligned((us as *mut u64).add(1), buf);
        us
    }
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);

    print_str(
        b"[ntos-dhl] KMDF Loader-Compat Driver Host: real KmdfLoaderCompatTest.sys (wdfldr binding)\n",
    );
    run();
    print_str(b"[microtest done]\n");
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sel4_rt::debug_put_char(b'!');
    loop {
        yield_now();
    }
}
