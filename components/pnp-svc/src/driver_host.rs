//! The isolated Driver Host child: loads the real `PnpMmioInterruptTest.sys`, hosts
//! the in-process HAL (Resource Manager + simulated device) + the kernel runtime,
//! and drives the PnP lifecycle — calling `AddDevice`, sending the `START_DEVICE` /
//! `REMOVE_DEVICE` IRPs locally (driver callbacks run here), while reporting each
//! state transition + querying the fixture resources from the **isolated PnP
//! Manager** over SURT. Reports the verdict on the RESULT endpoint.

use alloc::boxed::Box;
use nt_cm_resources::{InterruptDescriptor, MemoryDescriptor};
use nt_kernel_exec::{CompleteResult, EventKind, FakeClock, KernelExecRuntime};
use nt_pnp_abi::{
    IRP_MJ_PNP, IRP_MN_REMOVE_DEVICE, IRP_MN_START_DEVICE, PNP_OP_CALL_ADD_DEVICE,
    PNP_OP_CREATE_DEVNODE, PNP_OP_LOAD_DRIVER, PNP_OP_QUERY_DEVNODE, PNP_OP_REMOVE_DEVICE,
    PNP_OP_START_DEVICE,
};
use nt_pe_loader::{ImportRef, PeFile};
use nt_resource_manager::{ResourceManager, ResourceOwner};
use nt_sim_device::SimDevice;
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

use crate::{
    ep_send_one, print_str, yield_now, CODE_FRAMES, CODE_VADDR, COMP_RING_VADDR, CT_CODE_BASE,
    CT_N_COMP, CT_N_SUB, CT_PML4, CT_RESULT, DEVICE_OBJECT_ID, DRIVER_HOST_ID, ENV, INT_RESOURCE_ID,
    INT_VECTOR, MEM_RESOURCE_ID, REP_DATA_VADDR, RING_LEN, STATE_VADDR, SUB_RING_VADDR,
};

static PNP_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/PnpMmioInterruptTest.sys");

/// Checks the Driver Host reports.
pub const CHECKS: u64 = 13;

const STATUS_PENDING: i32 = 0x0000_0103;
const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;
/// `DeviceState::Removed as u32`.
const STATE_REMOVED: u64 = 12;

struct HostState {
    rt: KernelExecRuntime<FakeClock>,
    rm: ResourceManager,
    sim: SimDevice,
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
    stack_attached: bool,
    bad_irql: u32,
    res_mem_start: u64,
    res_mem_length: u32,
    res_int_vector: u32,
    res_int_level: u32,
    res_int_affinity: u64,
}

fn st() -> &'static mut HostState {
    // SAFETY: single-threaded child; the state page holds an initialised HostState.
    // Every access is a fresh short borrow so a driver callback can re-enter (§17).
    unsafe { &mut *(STATE_VADDR as *mut HostState) }
}

fn owner() -> ResourceOwner {
    ResourceOwner::new(DRIVER_HOST_ID, DEVICE_OBJECT_ID)
}

#[repr(C, align(16))]
struct Blob([u8; 512]);

fn alloc_blob() -> u64 {
    Box::leak(Box::new(Blob([0u8; 512]))) as *mut Blob as u64
}

/// One PnP request over SURT → `(status, detail0)`.
unsafe fn pnp_call(opcode: u16, arg0: u64) -> (i32, u64) {
    let id = st().next_id;
    st().next_id += 1;
    let sqe = SurtSqe {
        opcode,
        request_id: id,
        arg0,
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
    let _ = drain_blocking(&mut st().cq, &wait, |cqe: &SurtCqe| {
        if cqe.request_id == id {
            status = cqe.status;
            d0 = cqe.detail0;
            false
        } else {
            true
        }
    });
    (status, d0)
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

extern "win64" fn ntos_io_attach_device_to_device_stack(source_fdo: u64, target_pdo: u64) -> u64 {
    st().stack_attached = true;
    st().device_object = source_fdo;
    target_pdo
}

extern "win64" fn ntos_io_detach_device(_lower: u64) {
    st().stack_attached = false;
}

extern "win64" fn ntos_iof_call_driver(_device: u64, irp: u64) -> i32 {
    if irp != 0 {
        // SAFETY: `irp` is an IRP we built; IoStatus.Status@48.
        unsafe {
            core::ptr::write_unaligned((irp + 48) as *mut i32, 0);
        }
    }
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

extern "win64" fn ntos_mm_map_io_space(phys: u64, length: u64, cache: u32) -> u64 {
    match st().rm.map_io_space(owner(), phys, length, cache) {
        Ok(g) => {
            st().mmio_mapping_id = g.mapping_id;
            let base = st().sim.mmio_ptr() as u64;
            st().mmio_base = base;
            base
        }
        Err(_) => 0,
    }
}

extern "win64" fn ntos_mm_unmap_io_space(_base: u64, _length: u64) {
    let id = st().mmio_mapping_id;
    let _ = st().rm.unmap_io_space(owner(), id);
    st().mmio_base = 0;
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
        match st()
            .rm
            .connect_interrupt(owner(), INT_RESOURCE_ID, service_routine, service_context)
        {
            Ok(interrupt_id) => {
                let proj = alloc_blob();
                core::ptr::write_unaligned(proj as *mut u64, interrupt_id);
                st().interrupt_id = interrupt_id;
                st().interrupt_projection = proj;
                st().isr_routine = service_routine;
                st().isr_context = service_context;
                if !interrupt_obj_out.is_null() {
                    core::ptr::write_unaligned(interrupt_obj_out, proj);
                }
                0
            }
            Err(_) => 0xC000_0001u32 as i32,
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
        let _ = st().rm.disconnect_interrupt(owner(), interrupt_id);
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
extern "win64" fn ntos_ke_initialize_event(event: u64, kind: u32, state: u8) {
    let k = if kind == 1 {
        EventKind::Synchronization
    } else {
        EventKind::Notification
    };
    st().rt.events().initialize(event, k, state != 0);
}
extern "win64" fn ntos_ke_set_event(event: u64, _incr: i32, _wait: u8) -> i32 {
    st().rt.events().set(event) as i32
}
extern "win64" fn ntos_ke_clear_event(event: u64) {
    st().rt.events().clear(event);
}
extern "win64" fn ntos_ke_wait_for_single_object(_o: u64, _r: u32, _m: u8, _a: u8, _t: u64) -> i32 {
    0
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
        "IoAttachDeviceToDeviceStack" => ntos_io_attach_device_to_device_stack as usize as u64,
        "IoDetachDevice" => ntos_io_detach_device as usize as u64,
        "IofCallDriver" | "IoCallDriver" => ntos_iof_call_driver as usize as u64,
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
        "KeInitializeEvent" => ntos_ke_initialize_event as usize as u64,
        "KeSetEvent" => ntos_ke_set_event as usize as u64,
        "KeClearEvent" => ntos_ke_clear_event as usize as u64,
        "KeWaitForSingleObject" => ntos_ke_wait_for_single_object as usize as u64,
        _ => ntos_stub as usize as u64,
    }
}

unsafe fn drain_driver(budget: usize) {
    let mut n = 0;
    while n < budget {
        let cb = match st().rt.take_ready() {
            Some(c) => c,
            None => break,
        };
        let irql_now = st().rt.irql().current();
        if let nt_kernel_exec::ReadyCallback::Dpc {
            routine,
            dpc,
            deferred_context,
            arg1,
            arg2,
        } = cb
        {
            if irql_now != nt_kernel_exec::DISPATCH_LEVEL {
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

unsafe fn inject_interrupt(vector: u32) -> bool {
    let tokens = match st().rm.inject_vector(vector) {
        Some(t) => t,
        None => return false,
    };
    st().sim.raise_interrupt();
    let old = st().rt.irql().current();
    st().rt.irql().raise(tokens.irql);
    let isr: extern "win64" fn(u64, u64) -> u8 =
        core::mem::transmute(tokens.service_routine_token as *const ());
    let proj = st().interrupt_projection;
    let _claimed = isr(proj, tokens.service_context_token);
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
) -> (i32, [u8; 64]) {
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

    st().completed = false;
    st().last_status = 0;
    st().rt.mark_irp_pending(irp, code as u64);

    let routine = core::ptr::read_unaligned((driver_object + 112 + major as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let status = f(device_object, irp);

    let mut out = [0u8; 64];
    for (i, o) in out.iter_mut().enumerate() {
        *o = core::ptr::read_volatile(sysbuf.add(i));
    }
    (status, out)
}

unsafe fn dispatch_pnp(driver_object: u64, fdo: u64, minor: u8, raw: u64, translated: u64) -> i32 {
    let irp = alloc_blob();
    let stack_blob = alloc_blob();
    let current = stack_blob + 72;
    core::ptr::write_unaligned(irp as *mut i16, 6);
    core::ptr::write_unaligned((irp + 184) as *mut u64, current);
    core::ptr::write_unaligned(current as *mut u8, IRP_MJ_PNP);
    core::ptr::write_unaligned((current + 1) as *mut u8, minor);
    core::ptr::write_unaligned((current + 8) as *mut u64, raw);
    core::ptr::write_unaligned((current + 16) as *mut u64, translated);

    st().completed = false;
    st().last_status = 0;
    st().rt.mark_irp_pending(irp, 0x1b00 | minor as u64);

    let routine =
        core::ptr::read_unaligned((driver_object + 112 + IRP_MJ_PNP as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let _ = f(fdo, irp);
    st().last_status
}

unsafe fn build_resource_list() -> u64 {
    let buf = alloc_blob();
    let slice = core::slice::from_raw_parts_mut(buf as *mut u8, 64);
    let _ = nt_cm_resources::build_memory_interrupt_list(
        slice,
        0,
        MemoryDescriptor {
            start: st().res_mem_start,
            length: st().res_mem_length,
            flags: 0,
            share: nt_cm_resources::CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
        },
        InterruptDescriptor {
            level: st().res_int_level,
            vector: st().res_int_vector,
            affinity: st().res_int_affinity,
            flags: nt_cm_resources::CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
            share: nt_cm_resources::CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
        },
    );
    buf
}

unsafe fn setup(driver_object: u64) -> Option<(u64, u64)> {
    let pe = PeFile::parse(PNP_SYS).ok()?;
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
    // DriverExtension@48 → AddDevice@8.
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let driver_ext = alloc_blob();
    core::ptr::write_unaligned((driver_object + 48) as *mut u64, driver_ext);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let driver_entry: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    if driver_entry(driver_object, reg_path) != 0 {
        return None;
    }
    let add_device = core::ptr::read_unaligned((driver_ext + 8) as *const u64);
    Some((add_device, driver_ext))
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
            rm: ResourceManager::new(),
            sim: SimDevice::new(),
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
            stack_attached: false,
            bad_irql: 0,
            res_mem_start: 0,
            res_mem_length: 0,
            res_int_vector: 0,
            res_int_level: 0,
            res_int_affinity: 0,
        },
    );

    let mut passed = 0u64;

    let driver_object = alloc_blob();
    let (add_device, _ext) = match setup(driver_object) {
        Some(v) => v,
        None => {
            check(b"driver_entry_success", false, &mut passed);
            let _ = ep_send_one(CT_RESULT, passed);
            park()
        }
    };
    check(b"driver_entry_success", add_device != 0, &mut passed);

    // --- PnP Manager (isolated): enumerate the fixture devnode + query resources.
    let pdo = alloc_blob();
    core::ptr::write_unaligned(pdo as *mut i16, 3);
    let (cst, devnode) = pnp_call(PNP_OP_CREATE_DEVNODE, pdo);
    check(b"pnp_create_devnode", cst == 0 && devnode != 0, &mut passed);

    let (qst, _state) = pnp_call(PNP_OP_QUERY_DEVNODE, devnode);
    let p = REP_DATA_VADDR as *const u8;
    st().res_mem_start = core::ptr::read_unaligned(p as *const u64);
    st().res_mem_length = core::ptr::read_unaligned(p.add(8) as *const u32);
    st().res_int_vector = core::ptr::read_unaligned(p.add(12) as *const u32);
    st().res_int_level = core::ptr::read_unaligned(p.add(16) as *const u32);
    st().res_int_affinity = core::ptr::read_unaligned(p.add(20) as *const u64);
    check(
        b"pnp_query_resources",
        qst == 0 && st().res_mem_start == 0x1000_0000 && st().res_int_vector == INT_VECTOR,
        &mut passed,
    );

    // Negative: an out-of-order START (before AddDevice) is rejected by the isolated
    // PnP Manager (a second devnode kept clean for the real flow).
    let (_c2, dn2) = pnp_call(PNP_OP_CREATE_DEVNODE, pdo);
    let (bad, _s) = pnp_call(PNP_OP_START_DEVICE, dn2);
    check(b"pnp_invalid_transition_rejected", bad != 0, &mut passed);

    let _ = pnp_call(PNP_OP_LOAD_DRIVER, devnode);

    // AddDevice locally → FDO.
    st().device_object = 0;
    let add_fn: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(add_device as *const ());
    let add_status = add_fn(driver_object, pdo);
    let fdo = st().device_object;
    check(
        b"add_device_success",
        add_status == 0 && fdo != 0 && st().stack_attached,
        &mut passed,
    );
    let (adt, _s) = pnp_call(PNP_OP_CALL_ADD_DEVICE, devnode);
    check(b"pnp_add_device_transition", adt == 0, &mut passed);

    // Negative: IOCTL before START → STATUS_DEVICE_NOT_READY.
    let (st0, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_20C0, &[], 8);
    check(
        b"ioctl_before_start_not_ready",
        st0 == STATUS_DEVICE_NOT_READY,
        &mut passed,
    );

    // Assign resources locally (§15.2 gating) + seed the device ID register.
    st().rm.assign_memory(
        owner(),
        MEM_RESOURCE_ID,
        st().res_mem_start,
        st().res_mem_start,
        st().res_mem_length as u64,
        nt_hal_abi::MM_NON_CACHED,
        nt_hal_abi::RIGHT_READ | nt_hal_abi::RIGHT_WRITE,
    );
    st().rm
        .assign_interrupt(owner(), INT_RESOURCE_ID, INT_VECTOR, 5, 1, 0);
    core::ptr::write_volatile(st().sim.mmio_ptr() as *mut u32, 0x4d4d_494f);

    // START_DEVICE locally with the queried resources.
    let translated = build_resource_list();
    let raw = build_resource_list();
    let start_status = dispatch_pnp(driver_object, fdo, IRP_MN_START_DEVICE, raw, translated);
    check(
        b"start_device_success",
        start_status == 0 && st().mmio_base != 0 && st().interrupt_id != 0,
        &mut passed,
    );
    let (stt, sstate) = pnp_call(PNP_OP_START_DEVICE, devnode);
    check(
        b"pnp_started_state",
        stt == 0 && sstate == nt_pnp_abi::DeviceState::Started as u32 as u64,
        &mut passed,
    );

    // Device works after Started.
    let (gst, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_20C0, &[], 8);
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_get_id_after_start", gst == 0 && id == 0x4d4d_494f, &mut passed);

    let (wst, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_20D0, &[], 8);
    let pended = wst == STATUS_PENDING && !st().completed;
    let injected = inject_interrupt(INT_VECTOR);
    check(
        b"interrupt_completes_pending_ioctl",
        pended && injected && st().completed && st().last_status == 0,
        &mut passed,
    );

    // REMOVE_DEVICE locally → resources revoked.
    let mapping_id = st().mmio_mapping_id;
    let remove_status = dispatch_pnp(driver_object, fdo, IRP_MN_REMOVE_DEVICE, 0, 0);
    check(
        b"remove_device_releases_resources",
        remove_status == 0
            && !st().rm.mapping_valid(mapping_id)
            && st().rm.inject_vector(INT_VECTOR).is_none(),
        &mut passed,
    );
    let (rst, _s) = pnp_call(PNP_OP_REMOVE_DEVICE, devnode);
    // The isolated PnP Manager now reports the devnode Removed.
    let (_q, final_state) = pnp_call(PNP_OP_QUERY_DEVNODE, devnode);
    check(
        b"pnp_removed_state",
        rst == 0 && final_state == STATE_REMOVED,
        &mut passed,
    );

    check(b"callbacks_ran_at_correct_irql", st().bad_irql == 0, &mut passed);

    let _ = ep_send_one(CT_RESULT, passed);
    park()
}
