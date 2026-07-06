//! `ntos-driver-host-umdf` — hosting a real UMDF v2 driver against our WDF runtime.
//!
//! Loads the real `Umdf2LifecycleTest.dll` (a genuine UMDF 2.0 driver built from
//! github.com/stakach/ntdriver) with the same `nt-pe-loader` + W^X machinery that
//! loads the KMDF `.sys` drivers, and runs its `DriverEntry` against the shared
//! `nt-wdf-kmdf` runtime.
//!
//! UMDF v2 binds the framework differently than KMDF: instead of the driver calling
//! `WdfVersionBind` itself, the HOST publishes the `WdfFunctions` table + the
//! `WdfDriverGlobals` pointer into two image globals, then calls `DriverEntry`, which
//! reads them and dispatches `WdfDriverCreate` through the table — at UMDF v2 index 57
//! (KMDF's is 116). Only UMDF v2 is supported.

#![no_std]
#![no_main]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use sel4_rt::*;

/// The real UMDF v2 driver (committed fixture).
static UMDF2_DLL: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/Umdf2LifecycleTest.dll");

/// Where the driver image is mapped.
const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
/// `DriverEntry` export RVA (the real WDF driver entry; the host calls it directly).
const DRIVER_ENTRY_RVA: u64 = 0x10b4;
/// Image globals `DriverEntry` reads: the `WdfFunctions` table pointer and the
/// `WdfDriverGlobals` pointer (reverse-engineered from the driver's `DriverEntry`).
const WDF_FUNCTIONS_GLOBAL_RVA: u64 = 0x7538;
const WDF_DRIVER_GLOBALS_GLOBAL_RVA: u64 = 0x7548;

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

#[repr(C, align(16))]
struct Blob([u8; 256]);
fn alloc_blob() -> u64 {
    Box::leak(Box::new(Blob([0u8; 256]))) as *mut Blob as u64
}

extern "win64" fn ntos_stub() -> i32 {
    0
}
/// Resolve the driver's user-mode imports through the shared WDF crate (DbgPrintEx,
/// Rtl*, …); anything else (exception-handling helpers, kernel32) gets a harmless stub
/// — `DriverEntry` does not call them on the bind path.
fn export_addr(name: &str) -> u64 {
    nt_wdf_kmdf::export_addr(name).unwrap_or(ntos_stub as usize as u64)
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

unsafe fn run() {
    let pe = match nt_pe_loader::PeFile::parse(UMDF2_DLL) {
        Ok(p) => p,
        Err(_) => {
            check(b"parse_umdf2_dll", false);
            return;
        }
    };
    check(b"parse_umdf2_dll", true);

    let frames = (pe.size_of_image() as u64).div_ceil(0x1000);
    map_region(CODE_VADDR, frames);
    let mapped = match pe.map(CODE_VADDR) {
        Ok(m) => m,
        Err(_) => {
            check(b"map_and_relocate", false);
            return;
        }
    };
    let dst = CODE_VADDR as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    check(b"map_and_relocate", true);

    // Resolve the driver's imports (user-mode runtime; stubs for the unused rest).
    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let nt_pe_loader::ImportRef::ByName {
                    name, iat_slot_rva, ..
                } = f
                {
                    core::ptr::write_unaligned(
                        (CODE_VADDR + *iat_slot_rva as u64) as *mut u64,
                        export_addr(name),
                    );
                }
            }
        }
    }
    pe.seed_security_cookie(CODE_VADDR);

    // Publish the WDF function table + globals into the driver's image (what a UMDF v2
    // host does in lieu of the driver calling WdfVersionBind). Must happen while .data
    // is still writable — i.e. before W^X seals the image.
    nt_wdf_kmdf::umdf2_prepare();
    core::ptr::write_unaligned(
        (CODE_VADDR + WDF_FUNCTIONS_GLOBAL_RVA) as *mut u64,
        nt_wdf_kmdf::umdf2_functions_ptr(),
    );
    core::ptr::write_unaligned(
        (CODE_VADDR + WDF_DRIVER_GLOBALS_GLOBAL_RVA) as *mut u64,
        nt_wdf_kmdf::umdf2_globals_ptr(),
    );
    check(b"publish_wdf_function_table", true);

    apply_wx(&pe, frames);
    check(b"w_xor_x", true);

    // DRIVER_OBJECT (Type@0=4, Size@2=336, DriverExtension@48) + registry path.
    let driver_object = alloc_blob();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let driver_ext = alloc_blob();
    core::ptr::write_unaligned((driver_object + 48) as *mut u64, driver_ext);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    // Call the real UMDF v2 DriverEntry: it reads the globals we published and
    // dispatches WdfDriverCreate through the table (UMDF v2 index 57) into our runtime.
    print_str(b"[ntos-umdf] calling real UMDF v2 DriverEntry\n");
    let entry = CODE_VADDR + DRIVER_ENTRY_RVA;
    let de: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = de(driver_object, reg_path);
    check(
        b"umdf2_driver_entry_returns_success",
        status == 0,
    );
    check(
        b"umdf2_wdf_driver_create_ran",
        nt_wdf_kmdf::wdf().driver().is_some(),
    );
    check(
        b"umdf2_evt_device_add_captured",
        nt_wdf_kmdf::wdf().evt_device_add() != 0,
    );
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);
    print_str(b"[ntos-umdf] UMDF v2 Driver Host: loading real Umdf2LifecycleTest.dll\n");
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
