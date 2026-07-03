//! The isolated Driver Host child: maps the real `SurtTest.sys` into its
//! (broker-provided) executable region, runs `DriverEntry`, then serves
//! `DH_OP_DISPATCH_IRP` requests over SURT — running the real driver's dispatch
//! routine per request and replying with the completion.

use alloc::boxed::Box;
use nt_driver_abi::opcode::DH_OP_DISPATCH_IRP;
use nt_pe_loader::{ImportRef, PeFile};
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

use crate::{
    CODE_FRAMES, CODE_VADDR, COMP_RING_VADDR, CT_CODE_BASE, CT_N_COMP, CT_N_SUB, CT_PML4, ENV,
    REP_DATA_VADDR, REQ_DATA_VADDR, RING_LEN, STATE_VADDR, SUB_RING_VADDR,
};

static SURTTEST_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/SurtTest.sys");

// --- the native NT runtime the driver calls into ---------------------------

struct DhState {
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
    dh().device_object = dev;
    if !device_object_out.is_null() {
        // SAFETY: `out` is a writable driver pointer.
        unsafe {
            core::ptr::write_unaligned(device_object_out, dev);
        }
    }
    0
}

extern "win64" fn ntos_io_create_symbolic_link(_link: *const u8, _target: *const u8) -> i32 {
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
    }
    dh().completed = true;
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

/// Dispatch one IRP into the driver; returns `(status, information, output)`.
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

/// Load + relocate the image, patch the IAT, run `DriverEntry`. Returns the
/// `DRIVER_OBJECT` address on success.
unsafe fn setup() -> Option<u64> {
    let pe = PeFile::parse(SURTTEST_SYS).ok()?;
    let mapped = pe.map(CODE_VADDR).ok()?;
    let dst = CODE_VADDR as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
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
    // Seed the /GS cookie, resolved from the load-config directory.
    if let Some(rva) = pe.security_cookie_rva() {
        core::ptr::write_unaligned((CODE_VADDR + rva as u64) as *mut u64, 0x1234_5678_9abc_def0);
    }

    // Re-map the image W^X: code + read-only data become read-only; only writable
    // data stays writable. No page is left both writable and executable.
    for i in 0..CODE_FRAMES {
        let rights = if pe.protection_at((i * 0x1000) as u32).writable() {
            3
        } else {
            2
        };
        let _ = crate::page_unmap(CT_CODE_BASE + i);
        let _ = crate::page_map(CT_CODE_BASE + i, CODE_VADDR + i * 0x1000, rights, CT_PML4);
    }

    let driver_object = alloc_obj();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let driver_entry: extern "win64" fn(u64, u64) -> i32 =
        core::mem::transmute(entry as *const ());
    if driver_entry(driver_object, reg_path) != 0 {
        return None;
    }
    Some(driver_object)
}

/// Serve one `DH_OP_DISPATCH_IRP`: read `[major, code, in_len, out_len, input]`
/// from the request frame, run the driver's dispatch, write the output to the
/// reply frame. Returns `(status, information)`.
unsafe fn serve(driver_object: u64, device_object: u64) -> (i32, u64) {
    let base = REQ_DATA_VADDR as *const u8;
    let major = core::ptr::read_volatile(base);
    let code = core::ptr::read_unaligned(base.add(4) as *const u32);
    let in_len = core::ptr::read_unaligned(base.add(8) as *const u32) as usize;
    let out_cap = core::ptr::read_unaligned(base.add(12) as *const u32);
    let mut input = [0u8; 64];
    let n = in_len.min(64);
    for (i, b) in input.iter_mut().enumerate().take(n) {
        *b = core::ptr::read_volatile(base.add(16 + i));
    }
    let (status, info, out) = dispatch(driver_object, device_object, major, code, &input[..n], out_cap);
    let rep = REP_DATA_VADDR as *mut u8;
    for (i, b) in out.iter().enumerate().take((info as usize).min(64)) {
        core::ptr::write_volatile(rep.add(i), *b);
    }
    (status, info)
}

fn park() -> ! {
    loop {
        crate::yield_now();
    }
}

#[no_mangle]
#[link_section = ".text.driver_host_entry"]
pub unsafe extern "C" fn driver_host_entry() -> ! {
    let driver_object = match setup() {
        Some(d) => d,
        None => park(),
    };
    let device_object = dh().device_object;

    let mut submissions = match Consumer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let mut completions = match Producer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let wait_requests = Sel4Notify::new(&ENV, CT_N_SUB);
    let signal_completion = Sel4Notify::new(&ENV, CT_N_COMP);

    let _ = drain_blocking(&mut submissions, &wait_requests, |sqe: &SurtSqe| {
        if sqe.opcode == DH_OP_DISPATCH_IRP as u16 {
            let (status, information) = serve(driver_object, device_object);
            let cqe = SurtCqe {
                request_id: sqe.request_id,
                status,
                information,
                ..Default::default()
            };
            while completions.try_push(cqe).is_err() {
                crate::yield_now();
            }
            let _ = completions.notify_consumer(&signal_completion);
        }
        true
    });
    park()
}
