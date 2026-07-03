//! The isolated Driver Host child: maps the real `SurtTest.sys` into its
//! (broker-provided) executable region, runs `DriverEntry`, drives a few IRPs
//! into the driver's dispatch routines, and reports the pass count to the broker.

use alloc::boxed::Box;
use nt_pe_loader::{ImportRef, PeFile};

use crate::{CODE_VADDR, CT_RESULT, STATE_VADDR};

/// Total checks the child performs (for the broker's failed count).
pub const CHECKS: u64 = 9;

static SURTTEST_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/SurtTest.sys");

// --- the native NT runtime the driver calls into ---------------------------

/// Captured state from the driver's `DriverEntry` + dispatch calls. Lives on the
/// broker-provided RW [`STATE_VADDR`] page (the image `.bss` is read-only).
struct DhState {
    device_created: bool,
    symlink_created: bool,
    device_object: u64,
    completed: bool,
    last_status: i32,
    last_info: u64,
}

#[inline(always)]
fn dh() -> &'static mut DhState {
    // SAFETY: single-threaded component; `DhState` lives at the RW STATE_VADDR page
    // the broker mapped (retype-zeroed → a valid all-default value).
    unsafe { &mut *(STATE_VADDR as *mut DhState) }
}

#[repr(C, align(16))]
struct DevObj([u8; 512]);

fn alloc_obj() -> u64 {
    Box::leak(Box::new(DevObj([0u8; 512]))) as *mut DevObj as u64
}

extern "win64" fn ntos_rtl_init_unicode_string(dest: *mut u8, source: *const u16) {
    if dest.is_null() {
        return;
    }
    let mut n = 0usize;
    if !source.is_null() {
        // SAFETY: NUL-terminated wide string in the driver's .rdata.
        unsafe {
            while *source.add(n) != 0 && n < 4096 {
                n += 1;
            }
        }
    }
    let bytes = (n * 2) as u16;
    // SAFETY: `dest` is a driver UNICODE_STRING (length@0, max@2, buffer@8).
    unsafe {
        core::ptr::write_unaligned(dest as *mut u16, bytes);
        core::ptr::write_unaligned((dest as *mut u16).add(1), bytes.wrapping_add(2));
        core::ptr::write_unaligned(dest.add(8) as *mut u64, source as u64);
    }
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn ntos_io_create_device(
    _driver_object: u64,
    _extension_size: u32,
    _device_name: *const u8,
    _device_type: u32,
    _characteristics: u32,
    _exclusive: u8,
    device_object_out: *mut u64,
) -> i32 {
    let dev = alloc_obj();
    // SAFETY: single-threaded; `out` is a writable driver pointer.
    unsafe {
        dh().device_created = true;
        dh().device_object = dev;
        if !device_object_out.is_null() {
            core::ptr::write_unaligned(device_object_out, dev);
        }
    }
    0
}

extern "win64" fn ntos_io_create_symbolic_link(_link: *const u8, _target: *const u8) -> i32 {
    dh().symlink_created = true;
    0
}

extern "win64" fn ntos_iof_complete_request(irp: *const u8, _priority: i8) {
    if irp.is_null() {
        return;
    }
    // SAFETY: `irp` is the IRP we built; IoStatus is at offset 48.
    unsafe {
        dh().last_status = core::ptr::read_unaligned(irp.add(48) as *const i32);
        dh().last_info = core::ptr::read_unaligned(irp.add(56) as *const u64);
        dh().completed = true;
    }
}

extern "win64" fn ntos_stub() -> i32 {
    0
}

#[allow(function_casts_as_integer)] // taking each stub's address for the IAT
fn export_addr(name: &str) -> u64 {
    match name {
        "RtlInitUnicodeString" => ntos_rtl_init_unicode_string as usize as u64,
        "IoCreateDevice" => ntos_io_create_device as usize as u64,
        "IoCreateSymbolicLink" => ntos_io_create_symbolic_link as usize as u64,
        "IofCompleteRequest" | "IoCompleteRequest" => ntos_iof_complete_request as usize as u64,
        _ => ntos_stub as usize as u64,
    }
}

unsafe fn dispatch(
    driver_object: u64,
    device_object: u64,
    major: u8,
    code: u32,
    input: &[u8],
    out_cap: u32,
) -> (i32, u64, [u8; 64]) {
    let irp = alloc_obj();
    let stack = alloc_obj();
    let sysbuf = Box::leak(Box::new([0u8; 64])) as *mut u8;
    for (i, b) in input.iter().enumerate().take(64) {
        core::ptr::write_volatile(sysbuf.add(i), *b);
    }
    core::ptr::write_unaligned(irp as *mut i16, 6);
    core::ptr::write_unaligned((irp + 24) as *mut u64, sysbuf as u64);
    core::ptr::write_unaligned((irp + 184) as *mut u64, stack);
    core::ptr::write_unaligned(stack as *mut u8, major);
    core::ptr::write_unaligned((stack + 8) as *mut u32, out_cap);
    core::ptr::write_unaligned((stack + 16) as *mut u32, input.len() as u32);
    core::ptr::write_unaligned((stack + 24) as *mut u32, code);

    dh().completed = false;
    dh().last_status = 0;
    dh().last_info = 0;

    let routine =
        core::ptr::read_unaligned((driver_object + 112 + major as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let _ = f(device_object, irp);

    let mut out = [0u8; 64];
    for (i, o) in out.iter_mut().enumerate() {
        *o = core::ptr::read_volatile(sysbuf.add(i));
    }
    (dh().last_status, dh().last_info, out)
}

fn tick(name: &[u8], ok: bool, passed: &mut u64) {
    crate::print_str(if ok { b"  PASS " } else { b"  FAIL " });
    crate::print_str(name);
    crate::print_str(b"\n");
    if ok {
        *passed += 1;
    }
}

unsafe fn run() -> u64 {
    let mut passed = 0u64;

    let pe = match PeFile::parse(SURTTEST_SYS) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Copy the laid-out image into the broker-provided executable region.
    let mapped = match pe.map(CODE_VADDR) {
        Ok(m) => m,
        Err(_) => return 0,
    };
    let dst = CODE_VADDR as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }

    // Patch the IAT to the native export stubs.
    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let ImportRef::ByName { name, iat_slot_rva, .. } = f {
                    core::ptr::write_unaligned(
                        (CODE_VADDR + *iat_slot_rva as u64) as *mut u64,
                        export_addr(name),
                    );
                }
            }
        }
    }

    // Seed __security_cookie (.data RVA 0x3000 for this image).
    core::ptr::write_unaligned((CODE_VADDR + 0x3000) as *mut u64, 0x1234_5678_9abc_def0);

    // Build DRIVER_OBJECT + RegistryPath, call DriverEntry.
    let driver_object = alloc_obj();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let driver_entry: extern "win64" fn(u64, u64) -> i32 =
        core::mem::transmute(entry as *const ());
    let status = driver_entry(driver_object, reg_path);
    tick(b"driver_entry_success", status == 0, &mut passed);

    let major = |m: u64| core::ptr::read_unaligned((driver_object + 112 + m * 8) as *const u64);
    tick(b"dispatch_create", major(0x00) != 0, &mut passed);
    tick(b"dispatch_device_control", major(0x0e) != 0, &mut passed);
    tick(b"io_create_device", dh().device_created, &mut passed);
    tick(b"io_create_symbolic_link", dh().symlink_created, &mut passed);

    let dev = dh().device_object;

    let (st, _i, _o) = dispatch(driver_object, dev, 0x00, 0, &[], 0);
    tick(b"irp_create", dh().completed && st == 0, &mut passed);

    let (st, info, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2000, &[], 8);
    let ping = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    tick(b"ioctl_ping", st == 0 && info == 4 && ping == 0x5355_5254, &mut passed);

    let (st, info, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2008, &[], 16);
    let v = |o: usize| core::ptr::read_unaligned(out.as_ptr().add(o) as *const u32);
    tick(
        b"ioctl_get_version",
        st == 0 && info == 16 && v(0) == 0 && v(4) == 1 && v(8) == 0 && v(12) == 9,
        &mut passed,
    );

    let (st, info, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2004, b"hello", 8);
    tick(b"ioctl_echo", st == 0 && info == 5 && &out[..5] == b"hello", &mut passed);

    passed
}

#[no_mangle]
#[link_section = ".text.driver_host_entry"]
pub unsafe extern "C" fn driver_host_entry() -> ! {
    let passed = run();
    let _ = crate::ep_send_one(CT_RESULT, passed);
    loop {
        crate::yield_now();
    }
}
