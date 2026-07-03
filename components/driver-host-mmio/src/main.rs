//! `ntos-driver-host-mmio` — the MMIO + interrupt Driver Host as a seL4 component.
//!
//! A bare-metal root task that maps the real MSVC-built `MmioInterruptTest.sys` WDM
//! driver (W^X + NX), runs its `DriverEntry`, and drives the first hardware-shaped
//! vertical slice (spec: NT HAL, Resource Manager, Interrupt Delivery — Milestone
//! 11) against a **simulated** device hosted in-process:
//!
//! ```text
//! DriverEntry -> IoCreateDevice -> MmMapIoSpace(0x10000000) -> READ_REGISTER(ID)
//!   -> IoConnectInterrupt(vector 5)
//! IOCTL WAIT_FOR_INTERRUPT -> IRP pends
//! test injects interrupt -> ISR reads status / acks / queues DPC
//!   -> DPC completes the pending IRP
//! ```
//!
//! The Resource Manager validates every map/connect against a static fixture; the
//! register bank is real Driver-Host memory (register macros are inlined, so the
//! driver dereferences the mapping directly). Prints `PASS`/`FAIL`, then the sentinel.

#![no_std]
#![no_main]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use nt_kernel_exec::{CompleteResult, FakeClock, KernelExecRuntime};
use nt_pe_loader::{ImportRef, PeFile};
use nt_resource_manager::{ResourceManager, ResourceOwner};
use nt_sim_device::SimDevice;
use sel4_rt::*;

static MMIO_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/MmioInterruptTest.sys");

const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
const STATUS_PENDING: i32 = 0x0000_0103;

/// The driver's fixture identity (matches `with_mmio_test_fixture`).
const DRIVER_HOST_ID: u64 = 1;
const DEVICE_OBJECT_ID: u64 = 10;
const INT_VECTOR: u32 = 5;
const INT_RESOURCE_ID: u64 = 200;

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

unsafe fn apply_wx(pe: &PeFile, frames: u64) {
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

// --- global services (root task .bss is RW) ---------------------------------

static mut RT: Option<KernelExecRuntime<FakeClock>> = None;
static mut RM: Option<ResourceManager> = None;
static mut SIM: Option<SimDevice> = None;

unsafe fn rt() -> &'static mut KernelExecRuntime<FakeClock> {
    (*core::ptr::addr_of_mut!(RT)).as_mut().unwrap()
}
unsafe fn rm() -> &'static mut ResourceManager {
    (*core::ptr::addr_of_mut!(RM)).as_mut().unwrap()
}
unsafe fn sim() -> &'static mut SimDevice {
    (*core::ptr::addr_of_mut!(SIM)).as_mut().unwrap()
}

fn owner() -> ResourceOwner {
    ResourceOwner::new(DRIVER_HOST_ID, DEVICE_OBJECT_ID)
}

struct DhState {
    device_created: bool,
    device_object: u64,
    completed: bool,
    last_status: i32,
    last_info: u64,
    mmio_base: u64,
    mmio_mapping_id: u64,
    interrupt_id: u64,
    interrupt_projection: u64,
    isr_routine: u64,
    isr_context: u64,
    bad_irql: u32,
}

static mut DH: DhState = DhState {
    device_created: false,
    device_object: 0,
    completed: false,
    last_status: 0,
    last_info: 0,
    mmio_base: 0,
    mmio_mapping_id: 0,
    interrupt_id: 0,
    interrupt_projection: 0,
    isr_routine: 0,
    isr_context: 0,
    bad_irql: 0,
};

fn dh() -> &'static mut DhState {
    // SAFETY: single-threaded root task; .bss is writable.
    unsafe { &mut *core::ptr::addr_of_mut!(DH) }
}

#[repr(C, align(16))]
struct Blob([u8; 512]);

fn alloc_blob() -> u64 {
    Box::leak(Box::new(Blob([0u8; 512]))) as *mut Blob as u64
}

// --- compatibility exports --------------------------------------------------

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
    // SAFETY: `dest` is a driver UNICODE_STRING (length@0, max@2, buf@8).
    unsafe {
        core::ptr::write_unaligned(dest as *mut u16, bytes);
        core::ptr::write_unaligned((dest as *mut u16).add(1), bytes.wrapping_add(2));
        core::ptr::write_unaligned(dest.add(8) as *mut u64, source as u64);
    }
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn ntos_io_create_device(
    _driver_object: u64,
    extension_size: u32,
    _device_name: *const u8,
    _device_type: u32,
    _characteristics: u32,
    _exclusive: u8,
    device_object_out: *mut u64,
) -> i32 {
    let dev = alloc_blob();
    let ext = if extension_size > 0 {
        let layout =
            core::alloc::Layout::from_size_align((extension_size as usize).max(1), 16).unwrap();
        // SAFETY: nonzero size, 16-align.
        unsafe { alloc::alloc::alloc_zeroed(layout) as u64 }
    } else {
        0
    };
    // SAFETY: DeviceExtension@offset 64; `out` a writable driver pointer.
    unsafe {
        core::ptr::write_unaligned((dev + 64) as *mut u64, ext);
        dh().device_created = true;
        dh().device_object = dev;
        if !device_object_out.is_null() {
            core::ptr::write_unaligned(device_object_out, dev);
        }
    }
    0
}

extern "win64" fn ntos_io_ok2(_a: u64, _b: u64) -> i32 {
    0
}

extern "win64" fn ntos_iof_complete_request(irp: *const u8, _priority: i8) {
    if irp.is_null() {
        return;
    }
    // SAFETY: `irp` is an IRP we built; IoStatus.Status@48, .Information@56.
    unsafe {
        let status = core::ptr::read_unaligned(irp.add(48) as *const i32);
        let information = core::ptr::read_unaligned(irp.add(56) as *const u64);
        match rt().complete_irp(irp as u64, status, information) {
            CompleteResult::Completed => {
                dh().last_status = status;
                dh().last_info = information;
                dh().completed = true;
            }
            CompleteResult::AlreadyFinal => {}
        }
    }
}

/// `MmMapIoSpace(PhysicalAddress, NumberOfBytes, CacheType)` — validate against the
/// resource fixture, then return the (real) simulated register-bank pointer the
/// driver dereferences directly (spec §8.2). NULL on failure.
extern "win64" fn ntos_mm_map_io_space(phys: u64, length: u64, cache: u32) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        match rm().map_io_space(owner(), phys, length, cache) {
            Ok(g) => {
                dh().mmio_mapping_id = g.mapping_id;
                let base = sim().mmio_ptr() as u64;
                dh().mmio_base = base;
                base
            }
            Err(_) => 0,
        }
    }
}

/// `MmUnmapIoSpace(BaseAddress, NumberOfBytes)` (spec §8.4).
extern "win64" fn ntos_mm_unmap_io_space(_base: u64, _length: u64) {
    // SAFETY: single-threaded service access.
    unsafe {
        let _ = rm().unmap_io_space(owner(), dh().mmio_mapping_id);
        dh().mmio_base = 0;
    }
}

/// `IoConnectInterrupt(...)` (spec §9.3). Validates ownership via the Resource
/// Manager, registers the ISR tokens, and returns a local `PKINTERRUPT` projection.
#[allow(clippy::too_many_arguments)]
extern "win64" fn ntos_io_connect_interrupt(
    interrupt_obj_out: *mut u64,
    service_routine: u64,
    service_context: u64,
    _spin_lock: u64,
    _vector: u32,
    _irql: u8,
    _sync_irql: u8,
    _mode: u32,
    _share: u8,
    _affinity: u64,
    _floating: u8,
) -> i32 {
    // SAFETY: single-threaded service access.
    unsafe {
        match rm().connect_interrupt(owner(), INT_RESOURCE_ID, service_routine, service_context) {
            Ok(interrupt_id) => {
                let proj = alloc_blob();
                core::ptr::write_unaligned(proj as *mut u64, interrupt_id);
                dh().interrupt_id = interrupt_id;
                dh().interrupt_projection = proj;
                dh().isr_routine = service_routine;
                dh().isr_context = service_context;
                if !interrupt_obj_out.is_null() {
                    core::ptr::write_unaligned(interrupt_obj_out, proj);
                }
                0
            }
            Err(_) => 0xC000_0001u32 as i32, // STATUS_UNSUCCESSFUL
        }
    }
}

/// `IoDisconnectInterrupt(PKINTERRUPT)` (spec §9.6).
extern "win64" fn ntos_io_disconnect_interrupt(pkinterrupt: u64) {
    if pkinterrupt == 0 {
        return;
    }
    // SAFETY: `pkinterrupt` is a projection we allocated (interrupt_id@0).
    unsafe {
        let interrupt_id = core::ptr::read_unaligned(pkinterrupt as *const u64);
        let _ = rm().disconnect_interrupt(owner(), interrupt_id);
        dh().interrupt_id = 0;
    }
}

// DPC + spin-lock exports (backed by nt-kernel-exec, as in driver-host-async).

extern "win64" fn ntos_ke_initialize_dpc(dpc: u64, routine: u64, context: u64) {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().dpc().initialize(dpc, routine, context) }
}

extern "win64" fn ntos_ke_insert_queue_dpc(dpc: u64, arg1: u64, arg2: u64) -> u8 {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().dpc().insert(dpc, arg1, arg2) as u8 }
}

extern "win64" fn ntos_ke_initialize_spin_lock(spin_lock: u64) {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().initialize_spin(spin_lock) }
}

/// `KeAcquireSpinLockRaiseToDpc(SpinLock)` → old IRQL.
extern "win64" fn ntos_ke_acquire_spin_lock_raise(spin_lock: u64) -> u8 {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().acquire_spin(spin_lock) }
}

/// `KeReleaseSpinLock(SpinLock, NewIrql)`.
extern "win64" fn ntos_ke_release_spin_lock(spin_lock: u64, new_irql: u8) {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().release_spin(spin_lock, new_irql) }
}

extern "win64" fn ntos_ke_get_current_irql() -> u8 {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().irql().current() }
}

extern "win64" fn ntos_stub() -> i32 {
    0
}

#[allow(function_casts_as_integer)]
fn export_addr(name: &str) -> u64 {
    match name {
        "RtlInitUnicodeString" => ntos_rtl_init_unicode_string as usize as u64,
        "IoCreateDevice" => ntos_io_create_device as usize as u64,
        "IoCreateSymbolicLink" | "IoDeleteDevice" | "IoDeleteSymbolicLink" => {
            ntos_io_ok2 as usize as u64
        }
        "IofCompleteRequest" | "IoCompleteRequest" => ntos_iof_complete_request as usize as u64,
        "MmMapIoSpace" => ntos_mm_map_io_space as usize as u64,
        "MmUnmapIoSpace" => ntos_mm_unmap_io_space as usize as u64,
        "IoConnectInterrupt" => ntos_io_connect_interrupt as usize as u64,
        "IoDisconnectInterrupt" => ntos_io_disconnect_interrupt as usize as u64,
        "KeInitializeDpc" => ntos_ke_initialize_dpc as usize as u64,
        "KeInsertQueueDpc" => ntos_ke_insert_queue_dpc as usize as u64,
        "KeInitializeSpinLock" => ntos_ke_initialize_spin_lock as usize as u64,
        "KeAcquireSpinLockRaiseToDpc" => ntos_ke_acquire_spin_lock_raise as usize as u64,
        "KeReleaseSpinLock" | "KeReleaseSpinLockFromDpcLevel" => {
            ntos_ke_release_spin_lock as usize as u64
        }
        "KeGetCurrentIrql" => ntos_ke_get_current_irql as usize as u64,
        _ => ntos_stub as usize as u64,
    }
}

/// Run every ready DPC (the ISR's bottom half) with no runtime borrow held (spec
/// §17), recording the IRQL each ran at.
unsafe fn drain_driver(budget: usize) {
    let mut n = 0;
    while n < budget {
        let cb = match rt().take_ready() {
            Some(c) => c,
            None => break,
        };
        let irql_now = rt().irql().current();
        if let nt_kernel_exec::ReadyCallback::Dpc {
            routine,
            dpc,
            deferred_context,
            arg1,
            arg2,
        } = cb
        {
            if irql_now != nt_kernel_exec::DISPATCH_LEVEL {
                dh().bad_irql += 1;
            }
            let f: extern "win64" fn(u64, u64, u64, u64) =
                core::mem::transmute(routine as *const ());
            f(dpc, deferred_context, arg1, arg2);
        }
        rt().finish_callback();
        n += 1;
    }
}

/// Simulated interrupt injection (spec §9.4): raise the device line, resolve the
/// connected ISR through the Resource Manager, run it at the device IRQL (no borrow
/// held), then drain the DPC it queued.
unsafe fn inject_interrupt(vector: u32) -> bool {
    let tokens = match rm().inject_vector(vector) {
        Some(t) => t,
        None => return false,
    };
    sim().raise_interrupt(); // assert status bit0
    let old = rt().irql().current();
    rt().irql().raise(tokens.irql); // device IRQL
    let isr: extern "win64" fn(u64, u64) -> u8 =
        core::mem::transmute(tokens.service_routine_token as *const ());
    let _claimed = isr(dh().interrupt_projection, tokens.service_context_token);
    rt().irql().lower(old);
    drain_driver(4096); // the ISR queued a DPC → completes the pending IRP
    true
}

unsafe fn dispatch(
    driver_object: u64,
    device_object: u64,
    major: u8,
    code: u32,
    input: &[u8],
    out_cap: u32,
) -> (i32, u64, [u8; 64]) {
    let irp = alloc_blob();
    let stack = alloc_blob();
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
    rt().mark_irp_pending(irp, code as u64);

    let routine = core::ptr::read_unaligned((driver_object + 112 + major as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let status = f(device_object, irp);

    let mut out = [0u8; 64];
    for (i, o) in out.iter_mut().enumerate() {
        *o = core::ptr::read_volatile(sysbuf.add(i));
    }
    (status, dh().last_info, out)
}

fn check(name: &[u8], ok: bool) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
}

unsafe fn run() {
    RT = Some(KernelExecRuntime::new(FakeClock::new(), 0x5000_0000));
    RM = Some(ResourceManager::with_mmio_test_fixture(owner()));
    SIM = Some(SimDevice::new());

    let pe = match PeFile::parse(MMIO_SYS) {
        Ok(p) => p,
        Err(_) => {
            check(b"parse", false);
            return;
        }
    };
    check(b"parse", true);

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

    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let ImportRef::ByName {
                    name, iat_slot_rva, ..
                } = f
                {
                    let addr = export_addr(name);
                    core::ptr::write_unaligned((CODE_VADDR + *iat_slot_rva as u64) as *mut u64, addr);
                }
            }
        }
    }
    check(b"patch_iat", true);

    if let Some(rva) = pe.security_cookie_rva() {
        core::ptr::write_unaligned((CODE_VADDR + rva as u64) as *mut u64, 0x1234_5678_9abc_def0);
    }
    apply_wx(&pe, frames);
    check(b"w_xor_x", true);

    let driver_object = alloc_blob();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    // DriverEntry: creates the device, maps MMIO, reads the ID register, connects
    // the ISR on vector 5.
    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let driver_entry: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = driver_entry(driver_object, reg_path);
    check(b"driver_entry_success", status == 0);
    check(b"io_create_device", dh().device_created);
    check(b"mm_map_io_space", dh().mmio_base != 0 && rm().mapping_valid(dh().mmio_mapping_id));
    check(b"read_id_register_during_entry", dh().interrupt_id != 0); // reached connect past the ID check
    check(b"io_connect_interrupt", rm().inject_vector(INT_VECTOR).is_some());

    let dev = dh().device_object;

    // IOCTL_MMIOIT_GET_ID → the ID value 0x4d4d494f.
    let (st, _info, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2080, &[], 8);
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_get_id", st == 0 && id == 0x4d4d_494f);

    // IOCTL_MMIOIT_READ_REG32(offset 0) → also the ID register.
    let mut in_req = [0u8; 8]; // { Offset: u32, Value: u32 }
    in_req[0..4].copy_from_slice(&0u32.to_le_bytes());
    let (st, _info, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2084, &in_req, 8);
    let val = core::ptr::read_unaligned(out.as_ptr().add(4) as *const u32);
    check(b"ioctl_read_reg32", st == 0 && val == 0x4d4d_494f);

    // IOCTL_MMIOIT_WAIT_FOR_INTERRUPT → the driver pends the IRP.
    let (st, _info, _out) = dispatch(driver_object, dev, 0x0e, 0x0022_2090, &[], 8);
    check(b"wait_returns_pending", st == STATUS_PENDING && !dh().completed);

    // Inject the interrupt: ISR runs at device IRQL, acks, queues a DPC that
    // completes the pending IRP.
    let injected = inject_interrupt(INT_VECTOR);
    check(b"interrupt_injected", injected);
    check(b"isr_dpc_completed_irp", dh().completed && dh().last_status == 0);

    // IOCTL_MMIOIT_GET_INTERRUPT_COUNT → 1.
    let (st, _info, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2094, &[], 8);
    let count = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_interrupt_count", st == 0 && count == 1);

    // IOCTL_MMIOIT_DISCONNECT_INTERRUPT → the interrupt is released; injection stops.
    let (st, _info, _out) = dispatch(driver_object, dev, 0x0e, 0x0022_209C, &[], 8);
    check(
        b"ioctl_disconnect_interrupt",
        st == 0 && rm().inject_vector(INT_VECTOR).is_none(),
    );

    // No callback ran at the wrong IRQL (spec §14, §22 quality gate).
    check(b"callbacks_ran_at_correct_irql", dh().bad_irql == 0);
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);

    print_str(b"[ntos-dhm] MMIO+interrupt Driver Host: real MmioInterruptTest.sys\n");
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
