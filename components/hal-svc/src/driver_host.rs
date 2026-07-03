//! The isolated Driver Host child: loads the real `MmioInterruptTest.sys`, runs
//! `DriverEntry`, and drives the MMIO + interrupt test. Its HAL exports
//! (`MmMapIoSpace`, `IoConnectInterrupt`, `IoDisconnectInterrupt`) round-trip to the
//! HAL service over SURT; register access is inlined in the driver, so it
//! dereferences the shared MMIO frame directly. DPC / ISR / spin-lock / completion
//! run **locally** here (they are driver function pointers) via a private
//! `nt-kernel-exec` runtime. Reports the verdict on the RESULT endpoint.

use alloc::boxed::Box;
use nt_hal_abi::{
    HAL_OP_CONNECT_INTERRUPT, HAL_OP_DISCONNECT_INTERRUPT, HAL_OP_INJECT_INTERRUPT,
    HAL_OP_MAP_IO_SPACE, HAL_OP_UNMAP_IO_SPACE,
};
use nt_kernel_exec::{CompleteResult, FakeClock, KernelExecRuntime, ReadyCallback, DISPATCH_LEVEL};
use nt_pe_loader::{ImportRef, PeFile};
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

use crate::{
    ep_send_one, print_str, yield_now, CODE_FRAMES, CODE_VADDR, COMP_RING_VADDR, CT_CODE_BASE,
    CT_N_COMP, CT_N_SUB, CT_PML4, CT_RESULT, ENV, HAL_MMIO_VADDR, INT_RESOURCE_ID, INT_VECTOR,
    RING_LEN, STATE_VADDR, SUB_RING_VADDR,
};

static MMIO_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/MmioInterruptTest.sys");

/// Checks the Driver Host reports.
pub const CHECKS: u64 = 10;

const STATUS_PENDING: i32 = 0x0000_0103;

/// Everything the Driver Host needs across `extern "win64"` boundaries, on the RW
/// state page (the child's `.bss` is read-only). `Vec`s inside the runtime allocate
/// from the child's heap.
struct HostState {
    rt: KernelExecRuntime<FakeClock>,
    sq: Producer<SurtSqe>,
    cq: Consumer<SurtCqe>,
    next_id: u64,
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

fn st() -> &'static mut HostState {
    // SAFETY: single-threaded child; the state page holds an initialised HostState.
    // Every access is a fresh short borrow so a driver callback can re-enter (§17).
    unsafe { &mut *(STATE_VADDR as *mut HostState) }
}

#[repr(C, align(16))]
struct Blob([u8; 512]);

fn alloc_obj() -> u64 {
    Box::leak(Box::new(Blob([0u8; 512]))) as *mut Blob as u64
}

/// One HAL request over SURT → `(status, detail0, detail1)`.
unsafe fn hal_call(opcode: u16, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> (i32, u64, u64) {
    let id = st().next_id;
    st().next_id += 1;
    let sqe = SurtSqe {
        opcode,
        request_id: id,
        arg0,
        arg1,
        arg2,
        arg3,
        ..Default::default()
    };
    let signal = Sel4Notify::new(&ENV, CT_N_SUB);
    while st().sq.try_push(sqe).is_err() {
        yield_now();
    }
    let _ = st().sq.notify_consumer(&signal);

    let wait = Sel4Notify::new(&ENV, CT_N_COMP);
    let mut status = 0i32;
    let mut d0 = 0u64;
    let mut d1 = 0u64;
    let _ = drain_blocking(&mut st().cq, &wait, |cqe: &SurtCqe| {
        if cqe.request_id == id {
            status = cqe.status;
            d0 = cqe.detail0;
            d1 = cqe.detail1;
            false
        } else {
            true
        }
    });
    (status, d0, d1)
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
    extension_size: u32,
    _device_name: *const u8,
    _device_type: u32,
    _characteristics: u32,
    _exclusive: u8,
    device_object_out: *mut u64,
) -> i32 {
    let dev = alloc_obj();
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
        st().device_object = dev;
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
        if let CompleteResult::Completed = st().rt.complete_irp(irp as u64, status, information) {
            st().last_status = status;
            st().last_info = information;
            st().completed = true;
        }
    }
}

/// `MmMapIoSpace` — validate over SURT, return the shared MMIO frame vaddr.
extern "win64" fn ntos_mm_map_io_space(phys: u64, length: u64, cache: u32) -> u64 {
    // SAFETY: single-threaded; fresh state borrows.
    unsafe {
        let (status, mapping_id, _) = hal_call(HAL_OP_MAP_IO_SPACE, phys, length, cache as u64, 0);
        if status == 0 {
            st().mmio_mapping_id = mapping_id;
            st().mmio_base = HAL_MMIO_VADDR;
            HAL_MMIO_VADDR
        } else {
            0
        }
    }
}

extern "win64" fn ntos_mm_unmap_io_space(_base: u64, _length: u64) {
    // SAFETY: single-threaded; fresh state borrows.
    unsafe {
        let id = st().mmio_mapping_id;
        let _ = hal_call(HAL_OP_UNMAP_IO_SPACE, id, 0, 0, 0);
        st().mmio_base = 0;
    }
}

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
    // SAFETY: single-threaded; fresh state borrows.
    unsafe {
        let (status, interrupt_id, _) = hal_call(
            HAL_OP_CONNECT_INTERRUPT,
            INT_RESOURCE_ID,
            service_routine,
            service_context,
            INT_VECTOR as u64,
        );
        if status == 0 {
            let proj = alloc_obj();
            core::ptr::write_unaligned(proj as *mut u64, interrupt_id);
            st().interrupt_id = interrupt_id;
            st().interrupt_projection = proj;
            st().isr_routine = service_routine;
            st().isr_context = service_context;
            if !interrupt_obj_out.is_null() {
                core::ptr::write_unaligned(interrupt_obj_out, proj);
            }
            0
        } else {
            0xC000_0001u32 as i32
        }
    }
}

extern "win64" fn ntos_io_disconnect_interrupt(pkinterrupt: u64) {
    if pkinterrupt == 0 {
        return;
    }
    // SAFETY: `pkinterrupt` is a projection we allocated (interrupt_id@0).
    unsafe {
        let interrupt_id = core::ptr::read_unaligned(pkinterrupt as *const u64);
        let _ = hal_call(HAL_OP_DISCONNECT_INTERRUPT, interrupt_id, 0, 0, 0);
        st().interrupt_id = 0;
    }
}

extern "win64" fn ntos_ke_initialize_dpc(dpc: u64, routine: u64, context: u64) {
    st().rt.dpc().initialize(dpc, routine, context);
}
extern "win64" fn ntos_ke_insert_queue_dpc(dpc: u64, arg1: u64, arg2: u64) -> u8 {
    st().rt.dpc().insert(dpc, arg1, arg2) as u8
}
extern "win64" fn ntos_ke_initialize_spin_lock(spin_lock: u64) {
    st().rt.initialize_spin(spin_lock);
}
extern "win64" fn ntos_ke_acquire_spin_lock_raise(spin_lock: u64) -> u8 {
    st().rt.acquire_spin(spin_lock)
}
extern "win64" fn ntos_ke_release_spin_lock(spin_lock: u64, new_irql: u8) {
    st().rt.release_spin(spin_lock, new_irql);
}
extern "win64" fn ntos_ke_get_current_irql() -> u8 {
    st().rt.irql().current()
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

/// Run ready DPCs (the ISR's bottom half) with no state borrow held across the
/// driver call (§17).
unsafe fn drain_driver(budget: usize) {
    let mut n = 0;
    while n < budget {
        let cb = match st().rt.take_ready() {
            Some(c) => c,
            None => break,
        };
        let irql_now = st().rt.irql().current();
        if let ReadyCallback::Dpc {
            routine,
            dpc,
            deferred_context,
            arg1,
            arg2,
        } = cb
        {
            if irql_now != DISPATCH_LEVEL {
                st().bad_irql += 1;
            }
            let f: extern "win64" fn(u64, u64, u64, u64) =
                core::mem::transmute(routine as *const ());
            f(dpc, deferred_context, arg1, arg2);
        }
        st().rt.finish_callback();
        n += 1;
    }
}

/// Inject the interrupt (spec §9.4): ask the HAL service to assert the device line
/// + hand back the ISR tokens, run the ISR locally at the device IRQL (no borrow
/// held), then drain the DPC it queued.
unsafe fn inject_interrupt() -> bool {
    let iid = st().interrupt_id;
    let (status, routine, context) = hal_call(HAL_OP_INJECT_INTERRUPT, iid, 0, 0, 0);
    if status != 0 || routine == 0 {
        return false;
    }
    let proj = st().interrupt_projection;
    let old = st().rt.irql().current();
    st().rt.irql().raise(5); // device IRQL
    let isr: extern "win64" fn(u64, u64) -> u8 = core::mem::transmute(routine as *const ());
    let _claimed = isr(proj, context);
    st().rt.irql().lower(old);
    drain_driver(4096);
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

    st().completed = false;
    st().last_status = 0;
    st().last_info = 0;
    st().rt.mark_irp_pending(irp, code as u64);

    let routine = core::ptr::read_unaligned((driver_object + 112 + major as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let status = f(device_object, irp);

    let mut out = [0u8; 64];
    for (i, o) in out.iter_mut().enumerate() {
        *o = core::ptr::read_volatile(sysbuf.add(i));
    }
    (status, st().last_info, out)
}

unsafe fn setup() -> Option<u64> {
    let pe = PeFile::parse(MMIO_SYS).ok()?;
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
    if let Some(rva) = pe.security_cookie_rva() {
        core::ptr::write_unaligned((CODE_VADDR + rva as u64) as *mut u64, 0x1234_5678_9abc_def0);
    }
    // Re-map the image W^X + NX.
    for i in 0..CODE_FRAMES {
        let prot = pe.protection_at((i * 0x1000) as u32);
        let base = if prot.writable() { 3 } else { 2 };
        let rights = if prot.executable() {
            base
        } else {
            base | crate::PAGE_EXECUTE_NEVER
        };
        let _ = crate::page_unmap(CT_CODE_BASE + i);
        let _ = crate::page_map(CT_CODE_BASE + i, CODE_VADDR + i * 0x1000, rights, CT_PML4);
    }

    let driver_object = alloc_obj();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let driver_entry: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    if driver_entry(driver_object, reg_path) != 0 {
        return None;
    }
    Some(driver_object)
}

fn check(name: &[u8], ok: bool, passed: &mut u64) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
    if ok {
        *passed += 1;
    }
}

fn park() -> ! {
    loop {
        yield_now();
    }
}

#[no_mangle]
#[link_section = ".text.driver_host_entry"]
pub unsafe extern "C" fn driver_host_entry() -> ! {
    // Initialise the state page: runtime + SURT ring endpoints.
    let sq = match Producer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let cq = match Consumer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    core::ptr::write(
        STATE_VADDR as *mut HostState,
        HostState {
            rt: KernelExecRuntime::new(FakeClock::new(), 0x5000_0000),
            sq,
            cq,
            next_id: 1,
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
        },
    );

    let mut passed = 0u64;

    // DriverEntry: IoCreateDevice, MmMapIoSpace (SURT), READ ID, IoConnectInterrupt (SURT).
    let driver_object = match setup() {
        Some(d) => d,
        None => {
            check(b"driver_entry_success", false, &mut passed);
            let _ = ep_send_one(CT_RESULT, passed);
            park()
        }
    };
    check(b"driver_entry_success", true, &mut passed);
    check(b"mm_map_io_space", st().mmio_base == HAL_MMIO_VADDR, &mut passed);
    check(b"io_connect_interrupt", st().interrupt_id != 0, &mut passed);

    let dev = st().device_object;

    // IOCTL_MMIOIT_GET_ID → 0x4d4d494f (read from the shared MMIO frame).
    let (stt, _i, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2080, &[], 8);
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_get_id", stt == 0 && id == 0x4d4d_494f, &mut passed);

    // IOCTL_MMIOIT_READ_REG32(offset 0) → the ID register.
    let mut req = [0u8; 8];
    req[0..4].copy_from_slice(&0u32.to_le_bytes());
    let (stt, _i, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2084, &req, 8);
    let val = core::ptr::read_unaligned(out.as_ptr().add(4) as *const u32);
    check(b"ioctl_read_reg32", stt == 0 && val == 0x4d4d_494f, &mut passed);

    // IOCTL_MMIOIT_WAIT_FOR_INTERRUPT → the driver pends the IRP.
    let (stt, _i, _o) = dispatch(driver_object, dev, 0x0e, 0x0022_2090, &[], 8);
    check(
        b"wait_returns_pending",
        stt == STATUS_PENDING && !st().completed,
        &mut passed,
    );

    // Inject over SURT → ISR runs locally → DPC completes the pending IRP.
    let injected = inject_interrupt();
    check(
        b"isr_dpc_completed_irp",
        injected && st().completed && st().last_status == 0,
        &mut passed,
    );

    // IOCTL_MMIOIT_GET_INTERRUPT_COUNT → 1.
    let (stt, _i, out) = dispatch(driver_object, dev, 0x0e, 0x0022_2094, &[], 8);
    let count = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_interrupt_count", stt == 0 && count == 1, &mut passed);

    // IOCTL_MMIOIT_DISCONNECT_INTERRUPT → released; further injection fails.
    let (stt, _i, _o) = dispatch(driver_object, dev, 0x0e, 0x0022_209C, &[], 8);
    let reinject = inject_interrupt();
    check(
        b"ioctl_disconnect_interrupt",
        stt == 0 && !reinject,
        &mut passed,
    );

    check(b"callbacks_ran_at_correct_irql", st().bad_irql == 0, &mut passed);

    let _ = ep_send_one(CT_RESULT, passed);
    park()
}
