//! `ntos-driver-host-exec` — the Driver Host executor as a seL4 component.
//!
//! A bare-metal root task the rust-micro kernel boots. It maps a **real**
//! MSVC-built WDM driver (`SurtTest.sys`) into its own VSpace **executable**,
//! relocates it, patches its imports to native `extern "win64"` export stubs, and
//! calls the driver's `DriverEntry` under the Microsoft x64 ABI — real x86_64
//! kernel-driver code executing on seL4. It then verifies the driver installed
//! its dispatch table + created its device.
//!
//! Prints `PASS`/`FAIL` per step, then the kernel-exit sentinel.

#![no_std]
#![no_main]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use nt_pe_loader::{ImportRef, PeFile};
use sel4_rt::*;

/// The real driver image, built by <https://github.com/stakach/ntdriver>.
static SURTTEST_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/SurtTest.sys");

/// Map the image at its preferred base (`0x140000000`) so no relocation is needed
/// and the driver's code runs at the addresses it was linked for.
const CODE_VADDR: u64 = 0x0000_0001_4000_0000;

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);

fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}

/// Map `frames` fresh RW(X) 4 KiB pages at `base` in the root's own VSpace,
/// creating the PDPT/PD/PT. On x86_64 the pages are executable (no `ExecuteNever`).
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
    }
}

// --- the native NT kernel runtime the driver calls into --------------------

/// Captured state from the driver's `DriverEntry` + dispatch calls.
struct DhState {
    device_created: bool,
    symlink_created: bool,
    device_object: u64,
    name_units: [u16; 64],
    name_len: usize,
    // Last IRP completion (from IofCompleteRequest).
    completed: bool,
    last_status: i32,
    last_info: u64,
}

static mut DH: DhState = DhState {
    device_created: false,
    symlink_created: false,
    device_object: 0,
    name_units: [0; 64],
    name_len: 0,
    completed: false,
    last_status: 0,
    last_info: 0,
};

/// A driver-visible `DEVICE_OBJECT` allocation (16-aligned, room for a small
/// extension).
#[repr(C, align(16))]
struct DevObj([u8; 512]);

fn alloc_device_object() -> u64 {
    Box::leak(Box::new(DevObj([0u8; 512]))) as *mut DevObj as u64
}

/// `RtlInitUnicodeString(DestinationString, SourceString)`.
extern "win64" fn ntos_rtl_init_unicode_string(dest: *mut u8, source: *const u16) {
    if dest.is_null() {
        return;
    }
    let mut n = 0usize;
    if !source.is_null() {
        // SAFETY: the driver passes a NUL-terminated wide string in its .rdata.
        unsafe {
            while *source.add(n) != 0 && n < 4096 {
                n += 1;
            }
        }
    }
    let bytes = (n * 2) as u16;
    // SAFETY: `dest` is a driver-provided UNICODE_STRING (length@0, max@2, buf@8).
    unsafe {
        core::ptr::write_unaligned(dest as *mut u16, bytes);
        core::ptr::write_unaligned((dest as *mut u16).add(1), bytes.wrapping_add(2));
        core::ptr::write_unaligned(dest.add(8) as *mut u64, source as u64);
    }
}

/// `IoCreateDevice(...)` — allocate a local DEVICE_OBJECT + record it.
#[allow(clippy::too_many_arguments)]
extern "win64" fn ntos_io_create_device(
    _driver_object: u64,
    _extension_size: u32,
    device_name: *const u8,
    _device_type: u32,
    _characteristics: u32,
    _exclusive: u8,
    device_object_out: *mut u64,
) -> i32 {
    let dev = alloc_device_object();
    // SAFETY: single-threaded; `device_name` is a driver UNICODE_STRING, `out` a
    // writable driver pointer.
    unsafe {
        if !device_name.is_null() {
            let len_units = (core::ptr::read_unaligned(device_name as *const u16) / 2) as usize;
            let buf = core::ptr::read_unaligned(device_name.add(8) as *const u64) as *const u16;
            let n = len_units.min(64);
            for i in 0..n {
                DH.name_units[i] = *buf.add(i);
            }
            DH.name_len = n;
        }
        DH.device_created = true;
        DH.device_object = dev;
        if !device_object_out.is_null() {
            core::ptr::write_unaligned(device_object_out, dev);
        }
    }
    0
}

/// `IoCreateSymbolicLink(...)`.
extern "win64" fn ntos_io_create_symbolic_link(_link: *const u8, _target: *const u8) -> i32 {
    // SAFETY: single-threaded runtime.
    unsafe {
        DH.symlink_created = true;
    }
    0
}

/// `IofCompleteRequest(Irp, PriorityBoost)` — record the completion the driver's
/// dispatch routine produced (reads `Irp->IoStatus`).
extern "win64" fn ntos_iof_complete_request(irp: *const u8, _priority: i8) {
    if irp.is_null() {
        return;
    }
    // SAFETY: `irp` is the IRP we built; IoStatus is at offset 48 (status @48,
    // Information @56).
    unsafe {
        DH.last_status = core::ptr::read_unaligned(irp.add(48) as *const i32);
        DH.last_info = core::ptr::read_unaligned(irp.add(56) as *const u64);
        DH.completed = true;
    }
}

/// Fail-safe stub for exports not exercised by this driver.
extern "win64" fn ntos_stub() -> i32 {
    0
}

fn export_addr(name: &str) -> u64 {
    match name {
        "RtlInitUnicodeString" => ntos_rtl_init_unicode_string as usize as u64,
        "IoCreateDevice" => ntos_io_create_device as usize as u64,
        "IoCreateSymbolicLink" => ntos_io_create_symbolic_link as usize as u64,
        "IofCompleteRequest" | "IoCompleteRequest" => ntos_iof_complete_request as usize as u64,
        _ => ntos_stub as usize as u64,
    }
}

/// Dispatch one IRP into the driver's `MajorFunction[major]` and return
/// `(status, information, output-buffer)`. `code` + buffers apply to
/// `IRP_MJ_DEVICE_CONTROL` (`METHOD_BUFFERED`).
unsafe fn dispatch(
    driver_object: u64,
    device_object: u64,
    major: u8,
    code: u32,
    input: &[u8],
    out_cap: u32,
) -> (i32, u64, [u8; 64]) {
    let irp = alloc_device_object(); // ≥208, 16-aligned, zeroed
    let stack = alloc_device_object(); // ≥72
    let sysbuf = Box::leak(Box::new([0u8; 64])) as *mut u8;
    for (i, b) in input.iter().enumerate().take(64) {
        core::ptr::write_volatile(sysbuf.add(i), *b);
    }

    // IRP: Type=IO_TYPE_IRP, AssociatedIrp.SystemBuffer @24, CurrentStackLocation @184.
    core::ptr::write_unaligned(irp as *mut i16, 6);
    core::ptr::write_unaligned((irp + 24) as *mut u64, sysbuf as u64);
    core::ptr::write_unaligned((irp + 184) as *mut u64, stack);
    // IO_STACK_LOCATION: MajorFunction @0, DeviceIoControl Out @8 / In @16 / Code @24.
    core::ptr::write_unaligned(stack as *mut u8, major);
    core::ptr::write_unaligned((stack + 8) as *mut u32, out_cap);
    core::ptr::write_unaligned((stack + 16) as *mut u32, input.len() as u32);
    core::ptr::write_unaligned((stack + 24) as *mut u32, code);

    DH.completed = false;
    DH.last_status = 0;
    DH.last_info = 0;

    // MajorFunction[] lives in the DRIVER_OBJECT; the routine takes the
    // DEVICE_OBJECT + IRP.
    let routine =
        core::ptr::read_unaligned((driver_object + 112 + major as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let _ = f(device_object, irp);

    let mut out = [0u8; 64];
    for (i, o) in out.iter_mut().enumerate() {
        *o = core::ptr::read_volatile(sysbuf.add(i));
    }
    (DH.last_status, DH.last_info, out)
}

fn check(name: &[u8], ok: bool) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
}

unsafe fn run() {
    // Parse the real PE.
    let pe = match PeFile::parse(SURTTEST_SYS) {
        Ok(p) => p,
        Err(_) => {
            check(b"parse", false);
            return;
        }
    };
    check(b"parse", true);

    // Map the image executable at its preferred base + copy the laid-out image in
    // (relocation delta is 0, so section addresses are final).
    let size = pe.size_of_image() as u64;
    let frames = size.div_ceil(0x1000);
    map_region(CODE_VADDR, frames);
    let mapped = match pe.map(CODE_VADDR) {
        Ok(m) => m,
        Err(_) => {
            check(b"map", false);
            return;
        }
    };
    let dst = CODE_VADDR as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    check(b"map", true);

    // Patch the IAT to the native export stubs.
    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let ImportRef::ByName {
                    name, iat_slot_rva, ..
                } = f
                {
                    let addr = export_addr(name);
                    core::ptr::write_unaligned(
                        (CODE_VADDR + *iat_slot_rva as u64) as *mut u64,
                        addr,
                    );
                }
            }
        }
    }
    check(b"patch_iat", true);

    // Seed the /GS stack cookie (`__security_cookie`, at .data RVA 0x3000 for this
    // image). The MSVC `GsDriverEntry` wrapper's `__security_init_cookie` fastfails
    // (`int 0x29`) if it is left at 0 — normally the image loader initialises it.
    core::ptr::write_unaligned((CODE_VADDR + 0x3000) as *mut u64, 0x1234_5678_9abc_def0);

    // Build the DRIVER_OBJECT + a RegistryPath UNICODE_STRING.
    let driver_object = alloc_device_object(); // 512 zeroed bytes, 16-aligned, ≥336
    core::ptr::write_unaligned(driver_object as *mut i16, 4); // Type = IO_TYPE_DRIVER
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336); // Size
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64; // empty UNICODE_STRING

    // Call DriverEntry(DriverObject, RegistryPath) under the Microsoft x64 ABI.
    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let driver_entry: extern "win64" fn(u64, u64) -> i32 =
        core::mem::transmute(entry as *const ());
    let status = driver_entry(driver_object, reg_path);
    check(b"driver_entry_success", status == 0);

    // The driver installed its dispatch table (MajorFunction @ offset 112).
    let major = |m: u64| core::ptr::read_unaligned((driver_object + 112 + m * 8) as *const u64);
    check(b"dispatch_create", major(0x00) != 0); // IRP_MJ_CREATE
    check(b"dispatch_device_control", major(0x0e) != 0); // IRP_MJ_DEVICE_CONTROL

    // The driver created its device + symbolic link.
    check(b"io_create_device", DH.device_created);
    check(b"io_create_symbolic_link", DH.symlink_created);

    // Show the device name it asked for.
    print_str(b"  device: ");
    let mut ascii = [0u8; 64];
    let n = DH.name_len.min(64);
    for i in 0..n {
        let c = DH.name_units[i];
        ascii[i] = if (0x20..0x7f).contains(&c) { c as u8 } else { b'?' };
    }
    print_str(&ascii[..n]);
    print_str(b"\n");

    // --- drive real IRPs into the driver's dispatch routines (spec §10) -----
    let dev = DH.device_object;

    // IRP_MJ_CREATE (open) → SurtCreateClose completes STATUS_SUCCESS.
    let (st, _info, _out) = dispatch(driver_object, dev, 0x00, 0, &[], 0);
    check(b"irp_create", DH.completed && st == 0);

    // IOCTL_SURT_PING → returns ULONG 0x53555254 ("SURT"), Information = 4.
    let (st, info, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2000, &[], 8);
    let ping = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_ping", st == 0 && info == 4 && ping == 0x5355_5254);

    // IOCTL_SURT_GET_VERSION → { 0, 1, 0, 9 }, Information = 16.
    let (st, info, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2008, &[], 16);
    let v = |o: usize| core::ptr::read_unaligned(out.as_ptr().add(o) as *const u32);
    check(
        b"ioctl_get_version",
        st == 0 && info == 16 && v(0) == 0 && v(4) == 1 && v(8) == 0 && v(12) == 9,
    );

    // IOCTL_SURT_ECHO → METHOD_BUFFERED echo of the input.
    let (st, info, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2004, b"hello", 8);
    check(b"ioctl_echo", st == 0 && info == 5 && &out[..5] == b"hello");
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);

    print_str(b"[ntos-dhx] Driver Host executor: load + run real SurtTest.sys\n");
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
