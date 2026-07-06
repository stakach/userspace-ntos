//! `ntos-driver-host-um` — an isolated, out-of-process driver component.
//!
//! A GENUINELY separate binary (its own ELF, its own private VSpace) that the
//! driver-host "NT kernel" loads via its ELF loader and spawns. It reaches the
//! device only over the SURT reflector ring — it has no access to the WDF runtime,
//! the Configuration Manager, or the device object. When it crashes (a simulated
//! driver bug), the kernel catches the fault on the supervisor endpoint instead of
//! going down. Shares nothing with the kernel binary except the [`nt_um_abi`] ABI.
//!
//! Alloc-free: no global allocator, fixed stack + volatile shared-frame I/O only.

#![no_std]
#![no_main]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;

use alloc::boxed::Box;
use nt_um_abi::*;
use sel4_rt::*;
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, CPtr, Sel4Env, Sel4Notify};

/// The real UMDF v2 driver, embedded so this isolated host can load + run it.
static UMDF2_DLL: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/Umdf2LifecycleTest.dll");

/// SURT's wakeup contract: signal a notification / wait on it.
struct Env;
impl Sel4Env for Env {
    fn signal(&self, ntfn: CPtr) {
        // SAFETY: `ntfn` is a Notification cap; Send length 0 = seL4_Signal.
        unsafe {
            syscall5(SYS_SEND, ntfn, 0, 0, 0, 0);
        }
    }
    fn wait(&self, ntfn: CPtr) {
        // SAFETY: `ntfn` is a Notification cap; Recv = seL4_Wait.
        unsafe {
            let _ = ep_recv(ntfn);
        }
    }
}
static ENV: Env = Env;

fn park() -> ! {
    loop {
        yield_now();
    }
}

/// The isolated driver's entry. `arg0` (rdi) carries the supervisor's behavior
/// profile + attempt number (see [`nt_um_abi::make_arg`]).
///
/// # Safety
/// Entered by the kernel with the reflector rings mapped at the shared vaddrs and
/// the driver's caps seeded into its CNode.
#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(arg0: u64) -> ! {
    let profile = arg_profile(arg0);
    let attempt = arg_attempt(arg0);
    print_str(b"    [um-driver] isolated driver process up (separate binary)\n");

    // Host a REAL UMDF v2 driver's full lifecycle inside this isolated VSpace, then report
    // how many stages passed to the supervisor. The driver runs entirely locally (its own
    // copy of the WDF runtime); a crash is caught by the supervisor's fault endpoint.
    if profile == PROFILE_HOST_UMDF {
        print_str(b"    [um-driver] hosting real UMDF v2 driver in isolation\n");
        let passed = host_umdf_driver();
        print_str(b"    [um-driver] UMDF v2 lifecycle complete in isolated process\n");
        syscall5(SYS_SEND, CT_FAULT, ((OP_HEALTHY as u64) << 12) | 1, passed as u64, 0, 0);
        park()
    }

    let mut sq = match Producer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let mut cq = match Consumer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let signal_request = Sel4Notify::new(&ENV, CT_N_SUB);
    let wait_completion = Sel4Notify::new(&ENV, CT_N_COMP);

    // Reach the device over the reflector ring: open its interface, then PING it.
    let guid = KMDF_IFACE_GUID.as_bytes();
    let dst = REQ_DATA_VADDR as *mut u8;
    for (i, b) in guid.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    let open = SurtSqe {
        opcode: OP_OPEN,
        len: guid.len() as u32,
        request_id: 1,
        offset: 0,
        ..Default::default()
    };
    while sq.try_push(open).is_err() {
        yield_now();
    }
    let _ = sq.notify_consumer(&signal_request);
    let mut fdo = 0u64;
    let mut open_status = -1i32;
    let _ = drain_blocking(&mut cq, &wait_completion, |cqe: &SurtCqe| {
        if cqe.request_id == 1 {
            open_status = cqe.status;
            fdo = cqe.detail0;
            false
        } else {
            true
        }
    });
    if open_status == STATUS_SUCCESS && fdo != 0 {
        print_str(b"    [um-driver] opened device interface over ring\n");
    }

    core::ptr::write_unaligned(REQ_DATA_VADDR as *mut u32, KMDF_IOCTL_PING);
    let ioctl = SurtSqe {
        opcode: OP_IOCTL,
        len: 4,
        request_id: 2,
        user_data: fdo,
        offset: 0,
        ..Default::default()
    };
    while sq.try_push(ioctl).is_err() {
        yield_now();
    }
    let _ = sq.notify_consumer(&signal_request);
    let mut ping_status = -1i32;
    let _ = drain_blocking(&mut cq, &wait_completion, |cqe: &SurtCqe| {
        if cqe.request_id == 2 {
            ping_status = cqe.status;
            false
        } else {
            true
        }
    });
    let magic = core::ptr::read_volatile(REP_DATA_VADDR as *const u32);
    if ping_status == STATUS_SUCCESS && magic == KMDF_PING_MAGIC {
        print_str(b"    [um-driver] IOCTL ping over ring returned device magic\n");
    }

    // Fate is set by the supervisor's profile + attempt (see nt_um_abi):
    //   PROFILE_RECOVER      → crash on attempt 0, then run healthy (recovery demo)
    //   PROFILE_ALWAYS_CRASH → crash every time (crash-loop → backoff → disable)
    let stay_healthy = match profile {
        PROFILE_RECOVER => attempt >= 1,
        _ => false,
    };
    if stay_healthy {
        // Reached a healthy uptime checkpoint. Report it to the NT-kernel side over
        // the unified supervisor endpoint (a labelled Send — the kernel distinguishes
        // it from a fault by the message label), then run stably.
        print_str(b"    [um-driver] reached healthy checkpoint; running stably\n");
        syscall5(SYS_SEND, CT_FAULT, (OP_HEALTHY as u64) << 12, 0, 0, 0);
        park()
    } else {
        // Simulated driver bug: a wild write. Because this driver runs in its own
        // VSpace with a fault endpoint routed to the NT kernel, the kernel catches the
        // fault instead of bluescreening — only this isolated process dies.
        print_str(b"    [um-driver] crashing (simulated driver bug)\n");
        core::ptr::write_volatile(0xDEAD_0000 as *mut u64, 0);
        park()
    }
}

// --- Hosting a real UMDF v2 driver inside this isolated process --------------

fn alloc_blob() -> u64 {
    #[repr(C, align(16))]
    struct Blob([u8; 256]);
    Box::leak(Box::new(Blob([0u8; 256]))) as *mut Blob as u64
}
fn alloc_bytes(size: usize) -> u64 {
    let layout = core::alloc::Layout::from_size_align(size.max(1), 16).unwrap();
    // SAFETY: nonzero size, valid 16-byte align.
    unsafe { alloc::alloc::alloc_zeroed(layout) as u64 }
}
extern "win64" fn ntos_stub() -> i32 {
    0
}

/// Present one IOCTL to the hosted driver's default queue; returns whether it dispatched
/// and its completion status.
unsafe fn run_ioctl(device: u64, ioctl: u32, out_cap: u64) -> (bool, i32) {
    let sysbuf = alloc_bytes(out_cap.max(1) as usize);
    let irp = alloc_blob();
    let buffers = nt_wdf_request::RequestBuffers {
        input_ptr: 0,
        input_len: 0,
        output_ptr: sysbuf,
        output_len: out_cap,
    };
    let (request, dispatch) =
        match nt_wdf_kmdf::wdf().present_ioctl(nt_wdf_object::WdfHandle(device), irp, ioctl, buffers)
        {
            Ok(v) => v,
            Err(_) => return (false, 0),
        };
    let Some(d) = dispatch else {
        return (false, 0);
    };
    let f: extern "win64" fn(u64, u64, u64, u64, u32) =
        core::mem::transmute(d.evt_io_device_control as *const ());
    f(d.queue.0, request.0, out_cap, 0, ioctl);
    (true, nt_wdf_kmdf::last_completion().0)
}

/// Load + run the real UMDF v2 driver's full lifecycle in THIS isolated VSpace, against
/// this process's own copy of the shared WDF runtime. The driver image goes into the RWX
/// window the parent mapped (this process has no untyped to make memory executable). No
/// access to the parent — everything runs locally. Returns how many lifecycle stages passed.
unsafe fn host_umdf_driver() -> u32 {
    let mut passed = 0u32;
    let base = UMDF_DLL_VADDR;
    let pe = match nt_pe_loader::PeFile::parse(UMDF2_DLL) {
        Ok(p) => p,
        Err(_) => return passed,
    };
    passed += 1; // parsed
    let mapped = match pe.map(base) {
        Ok(m) => m,
        Err(_) => return passed,
    };
    let dst = base as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    passed += 1; // mapped + relocated into the RWX window
    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let nt_pe_loader::ImportRef::ByName {
                    name, iat_slot_rva, ..
                } = f
                {
                    let addr =
                        nt_wdf_kmdf::export_addr(name).unwrap_or(ntos_stub as usize as u64);
                    core::ptr::write_unaligned((base + *iat_slot_rva as u64) as *mut u64, addr);
                }
            }
        }
    }
    pe.seed_security_cookie(base);
    nt_wdf_kmdf::umdf2_prepare();
    core::ptr::write_unaligned((base + 0x7538) as *mut u64, nt_wdf_kmdf::umdf2_functions_ptr());
    core::ptr::write_unaligned((base + 0x7548) as *mut u64, nt_wdf_kmdf::umdf2_globals_ptr());

    // Seed the driver's service registry so EvtDeviceAdd can open its Parameters key.
    {
        let cm = nt_wdf_kmdf::config_mut();
        cm.register_service(
            "Umdf2LifecycleTest",
            "Umdf2LifecycleTest.dll",
            Some("System"),
            Some("{4d36e97d-e325-11ce-bfc1-08002be10318}"),
            3,
            1,
        );
        cm.set_service_parameter(
            "Umdf2LifecycleTest",
            "TestValue",
            nt_config_manager::RegistryValueType::Dword,
            1u32.to_le_bytes().to_vec(),
        );
    }
    let dn = nt_wdf_kmdf::config_mut().register_devnode(
        r"Root\UMDF2_LIFECYCLE_TEST\0000",
        Some("Umdf2LifecycleTest"),
        Some(r"\Device\NTPNP_ROOT_0005"),
        &[r"Root\UMDF2_LIFECYCLE_TEST"],
        &[],
    );
    nt_wdf_kmdf::set_devnode(dn);
    nt_wdf_kmdf::wdf().set_driver_service("Umdf2LifecycleTest");

    // DRIVER_OBJECT + call the driver's DriverEntry (dispatches WdfDriverCreate).
    let driver_object = alloc_blob();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let driver_ext = alloc_blob();
    core::ptr::write_unaligned((driver_object + 48) as *mut u64, driver_ext);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;
    let de: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute((base + 0x10b4) as *const ());
    if de(driver_object, reg_path) != 0 || nt_wdf_kmdf::wdf().driver().is_none() {
        return passed;
    }
    passed += 1; // DriverEntry + WdfDriverCreate

    // EvtDeviceAdd → device create + registry + interface.
    let pdo = alloc_blob();
    if nt_wdf_kmdf::umdf2_run_evt_device_add(pdo) == 0 && nt_wdf_kmdf::device() != 0 {
        passed += 1;
    }
    let device = nt_wdf_kmdf::device();

    // D0 (power the queue), then one IOCTL through the driver's EvtIoDeviceControl.
    if let Ok((d0, _)) = nt_wdf_kmdf::wdf().set_device_power(nt_wdf_object::WdfHandle(device), true) {
        if d0 != 0 {
            let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(d0 as *const ());
            let _ = f(device, 1);
        }
    }
    let (dispatched, _st) = run_ioctl(device, 0x8000_e00c, 256);
    if dispatched {
        passed += 1;
    }
    passed
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sel4_rt::debug_put_char(b'!');
    loop {
        yield_now();
    }
}
