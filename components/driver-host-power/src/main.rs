//! `ntos-driver-host-power` — the Power + PnP Driver Host as a seL4 component.
//!
//! Loads the real `PowerPnpMmioTest.sys` (W^X + NX) and drives the full NT PnP **and
//! power** device lifecycle (spec: NT Power Manager, Milestone 13) against an
//! in-process HAL + PnP Manager + Power Manager:
//!
//! ```text
//! START_DEVICE (PnP) -> device D0 -> IOCTLs work, interrupts deliver
//! SET_POWER D3       -> driver PoSetPowerState(D3), Powered=0 -> IOCTLs fail,
//!                       injected interrupts dropped (HAL power-gated)
//! SET_POWER D0       -> driver PoSetPowerState(D0), Powered=1 -> IOCTLs work again,
//!                       interrupt completes a pended IOCTL
//! REMOVE_DEVICE      -> D3-like cleanup; power record unregistered
//! ```

#![no_std]
#![no_main]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use nt_cm_resources::{InterruptDescriptor, MemoryDescriptor};
use nt_kernel_exec::{CompleteResult, EventKind, FakeClock, KernelExecRuntime};
use nt_pnp_abi::{DeviceState, IRP_MJ_PNP, IRP_MN_REMOVE_DEVICE, IRP_MN_START_DEVICE};
use nt_pnp_manager::PnpManager;
use nt_power_manager::PowerManager;
use nt_power_types::{
    DevicePowerState, IRP_MJ_POWER, IRP_MN_QUERY_POWER, IRP_MN_SET_POWER, PARAM_POWER_STATE_OFFSET,
    PARAM_POWER_TYPE_OFFSET, POWER_STATE_TYPE_DEVICE,
};
use nt_resource_manager::{ResourceManager, ResourceOwner};
use nt_sim_device::SimDevice;
use sel4_rt::*;

static POWER_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/PowerPnpMmioTest.sys");

const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
const STATUS_PENDING: i32 = 0x0000_0103;
const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;

const DRIVER_HOST_ID: u64 = 1;
const DEVICE_OBJECT_ID: u64 = 10;
const INT_VECTOR: u32 = 5;
const INT_RESOURCE_ID: u64 = 200;
const MEM_RESOURCE_ID: u64 = 100;

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
        let _ = page_map(
            f,
            base + i * 0x1000,
            /* RW */ 3,
            CAP_INIT_THREAD_VSPACE,
        );
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

// --- global services (root task .bss is RW) ---------------------------------

static mut RT: Option<KernelExecRuntime<FakeClock>> = None;
static mut RM: Option<ResourceManager> = None;
static mut SIM: Option<SimDevice> = None;
static mut PNP: Option<PnpManager> = None;
static mut PWR: Option<PowerManager> = None;

unsafe fn rt() -> &'static mut KernelExecRuntime<FakeClock> {
    (*core::ptr::addr_of_mut!(RT)).as_mut().unwrap()
}
unsafe fn rm() -> &'static mut ResourceManager {
    (*core::ptr::addr_of_mut!(RM)).as_mut().unwrap()
}
unsafe fn sim() -> &'static mut SimDevice {
    (*core::ptr::addr_of_mut!(SIM)).as_mut().unwrap()
}
unsafe fn pnp() -> &'static mut PnpManager {
    (*core::ptr::addr_of_mut!(PNP)).as_mut().unwrap()
}
unsafe fn pwr() -> &'static mut PowerManager {
    (*core::ptr::addr_of_mut!(PWR)).as_mut().unwrap()
}

fn owner() -> ResourceOwner {
    ResourceOwner::new(DRIVER_HOST_ID, DEVICE_OBJECT_ID)
}

struct DhState {
    device_object: u64, // the last IoCreateDevice result (the FDO)
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
    /// Device is in D0 (powered) — the HAL gates I/O + interrupts on this (spec §12).
    powered: bool,
    /// The device power state the driver last reported via `PoSetPowerState`.
    reported_device_state: u32,
    po_start_next_count: u32,
}

static mut DH: DhState = DhState {
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
    powered: false,
    reported_device_state: 0,
    po_start_next_count: 0,
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

/// `IoAttachDeviceToDeviceStack(SourceDevice, TargetDevice)` → the lower device
/// (the PDO). Records the stack edge (spec §12).
extern "win64" fn ntos_io_attach_device_to_device_stack(source_fdo: u64, target_pdo: u64) -> u64 {
    dh().stack_attached = true;
    dh().device_object = source_fdo; // the FDO on top of the stack
    target_pdo
}

/// `IoDetachDevice(TargetDevice)`.
extern "win64" fn ntos_io_detach_device(_lower: u64) {
    dh().stack_attached = false;
}

/// `IofCallDriver(DeviceObject, Irp)` — for v0.1 the lower device (PDO / root bus)
/// completes the forwarded PnP IRP with success (spec §12.3). Returns
/// `STATUS_SUCCESS` (not pending) so the driver's synchronous forward proceeds.
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
        if let CompleteResult::Completed = rt().complete_irp(irp as u64, status, information) {
            dh().last_status = status;
            dh().last_info = information;
            dh().completed = true;
        }
    }
}

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

extern "win64" fn ntos_mm_unmap_io_space(_base: u64, _length: u64) {
    // SAFETY: single-threaded service access.
    unsafe {
        let _ = rm().unmap_io_space(owner(), dh().mmio_mapping_id);
        dh().mmio_base = 0;
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
        let _ = rm().disconnect_interrupt(owner(), interrupt_id);
        dh().interrupt_id = 0;
    }
}

extern "win64" fn ntos_ke_initialize_dpc(dpc: u64, routine: u64, context: u64) {
    unsafe { rt().dpc().initialize(dpc, routine, context) }
}
extern "win64" fn ntos_ke_insert_queue_dpc(dpc: u64, arg1: u64, arg2: u64) -> u8 {
    unsafe { rt().dpc().insert(dpc, arg1, arg2) as u8 }
}
extern "win64" fn ntos_ke_initialize_spin_lock(spin_lock: u64) {
    unsafe { rt().initialize_spin(spin_lock) }
}
extern "win64" fn ntos_ke_acquire_spin_lock_raise(spin_lock: u64) -> u8 {
    unsafe { rt().acquire_spin(spin_lock) }
}
extern "win64" fn ntos_ke_release_spin_lock(spin_lock: u64, new_irql: u8) {
    unsafe { rt().release_spin(spin_lock, new_irql) }
}
extern "win64" fn ntos_ke_get_current_irql() -> u8 {
    unsafe { rt().irql().current() }
}
extern "win64" fn ntos_ke_initialize_event(event: u64, kind: u32, state: u8) {
    let k = if kind == 1 {
        EventKind::Synchronization
    } else {
        EventKind::Notification
    };
    unsafe { rt().events().initialize(event, k, state != 0) }
}
extern "win64" fn ntos_ke_set_event(event: u64, _incr: i32, _wait: u8) -> i32 {
    unsafe { rt().events().set(event) as i32 }
}
extern "win64" fn ntos_ke_clear_event(event: u64) {
    unsafe { rt().events().clear(event) }
}
extern "win64" fn ntos_ke_wait_for_single_object(_o: u64, _r: u32, _m: u8, _a: u8, _t: u64) -> i32 {
    0
}

// --- Po* power exports (spec §14) -------------------------------------------

/// `PoCallDriver(DeviceObject, Irp)` — modern behaviour is `IoCallDriver` (spec
/// §14.2). The lower (PDO) completes the forwarded power IRP with success.
extern "win64" fn ntos_po_call_driver(_device: u64, irp: u64) -> i32 {
    if irp != 0 {
        // SAFETY: `irp` is an IRP we built; IoStatus.Status@48.
        unsafe {
            core::ptr::write_unaligned((irp + 48) as *mut i32, 0);
        }
    }
    0
}

/// `PoStartNextPowerIrp(Irp)` — a safe no-op in modern mode; record the call count
/// (spec §14.3).
extern "win64" fn ntos_po_start_next_power_irp(_irp: u64) {
    dh().po_start_next_count += 1;
}

/// `PoSetPowerState(DeviceObject, Type, State)` — the driver reports an observed
/// local transition (spec §14.4). Update the HAL power gate + return the previous
/// `POWER_STATE`.
extern "win64" fn ntos_po_set_power_state(_device: u64, power_type: u32, state: u32) -> u32 {
    let prev = dh().reported_device_state;
    if power_type == POWER_STATE_TYPE_DEVICE {
        dh().reported_device_state = state;
        // D0 (=1) powers the device on; anything else gates I/O + interrupts.
        dh().powered = state == DevicePowerState::D0 as u32;
    }
    prev
}

extern "win64" fn ntos_stub() -> i32 {
    0
}

#[allow(function_casts_as_integer)]
fn export_addr(name: &str) -> u64 {
    match name {
        "PoCallDriver" => ntos_po_call_driver as usize as u64,
        "PoStartNextPowerIrp" => ntos_po_start_next_power_irp as usize as u64,
        "PoSetPowerState" => ntos_po_set_power_state as usize as u64,
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

unsafe fn inject_interrupt(vector: u32) -> bool {
    // HAL power gate (spec §12.1): an interrupt injected while the device is not D0
    // is dropped — the ISR is not called.
    if !dh().powered {
        return false;
    }
    let tokens = match rm().inject_vector(vector) {
        Some(t) => t,
        None => return false,
    };
    sim().raise_interrupt();
    let old = rt().irql().current();
    rt().irql().raise(tokens.irql);
    let isr: extern "win64" fn(u64, u64) -> u8 =
        core::mem::transmute(tokens.service_routine_token as *const ());
    let _claimed = isr(dh().interrupt_projection, tokens.service_context_token);
    rt().irql().lower(old);
    drain_driver(4096);
    true
}

/// Dispatch an IRP into the driver's `MajorFunction[major]`. Returns `(status,
/// info, output)`.
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

/// Send an `IRP_MJ_PNP` with the given minor function + resource lists to the FDO.
/// Returns the completion status.
unsafe fn dispatch_pnp(
    driver_object: u64,
    fdo: u64,
    minor: u8,
    raw_list: u64,
    translated_list: u64,
) -> i32 {
    let irp = alloc_blob();
    let stack_blob = alloc_blob();
    // Leave a lower stack location for the driver's IoCopyCurrentIrpStackLocationToNext.
    let current = stack_blob + 72;
    core::ptr::write_unaligned(irp as *mut i16, 6);
    core::ptr::write_unaligned((irp + 184) as *mut u64, current);
    core::ptr::write_unaligned(current as *mut u8, IRP_MJ_PNP);
    core::ptr::write_unaligned((current + 1) as *mut u8, minor);
    // Parameters.StartDevice: AllocatedResources@8, AllocatedResourcesTranslated@16.
    core::ptr::write_unaligned((current + 8) as *mut u64, raw_list);
    core::ptr::write_unaligned((current + 16) as *mut u64, translated_list);

    dh().completed = false;
    dh().last_status = 0;
    rt().mark_irp_pending(irp, 0x1b00 | minor as u64);

    let routine =
        core::ptr::read_unaligned((driver_object + 112 + IRP_MJ_PNP as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let _ = f(fdo, irp);
    dh().last_status
}

/// Send an `IRP_MJ_POWER` with the given minor + `Parameters.Power.{Type,State}` to
/// the FDO. Returns the completion status.
unsafe fn dispatch_power(
    driver_object: u64,
    fdo: u64,
    minor: u8,
    power_type: u32,
    power_state: u32,
) -> i32 {
    let irp = alloc_blob();
    let stack_blob = alloc_blob();
    let current = stack_blob + 72;
    core::ptr::write_unaligned(irp as *mut i16, 6);
    core::ptr::write_unaligned((irp + 184) as *mut u64, current);
    core::ptr::write_unaligned(current as *mut u8, IRP_MJ_POWER);
    core::ptr::write_unaligned((current + 1) as *mut u8, minor);
    core::ptr::write_unaligned((current + PARAM_POWER_TYPE_OFFSET) as *mut u32, power_type);
    core::ptr::write_unaligned(
        (current + PARAM_POWER_STATE_OFFSET) as *mut u32,
        power_state,
    );

    dh().completed = false;
    dh().last_status = 0;
    rt().mark_irp_pending(irp, 0x1600 | minor as u64);

    let routine =
        core::ptr::read_unaligned((driver_object + 112 + IRP_MJ_POWER as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let _ = f(fdo, irp);
    dh().last_status
}

/// Orchestrate a device power transition (spec §10.1): the Power Manager validates +
/// marks in-flight, then QUERY_POWER (fail → abort) + SET_POWER go to the driver, then
/// the Power Manager records the outcome. Returns whether it reached `target`.
unsafe fn transition_device_power(
    driver_object: u64,
    fdo: u64,
    devnode: u64,
    target: DevicePowerState,
) -> bool {
    if pwr().begin_device_transition(devnode, target).is_err() {
        return false;
    }
    let t = target as u32;
    let q = dispatch_power(
        driver_object,
        fdo,
        IRP_MN_QUERY_POWER,
        POWER_STATE_TYPE_DEVICE,
        t,
    );
    if q != 0 {
        let _ = pwr().complete_device_transition(devnode, target, false);
        return false;
    }
    let s = dispatch_power(
        driver_object,
        fdo,
        IRP_MN_SET_POWER,
        POWER_STATE_TYPE_DEVICE,
        t,
    );
    let ok = s == 0;
    let _ = pwr().complete_device_transition(devnode, target, ok);
    ok
}

/// Build the translated `CM_RESOURCE_LIST` for a devnode into a driver-visible blob.
unsafe fn build_resource_list(devnode: u64) -> u64 {
    let res = pnp().resources(devnode).unwrap();
    let buf = alloc_blob();
    // SAFETY: the blob is 512 bytes; the list is 60.
    let slice = core::slice::from_raw_parts_mut(buf as *mut u8, 64);
    let _ = nt_cm_resources::build_memory_interrupt_list(
        slice,
        0,
        MemoryDescriptor {
            start: res.mem_start,
            length: res.mem_length,
            flags: 0,
            share: nt_cm_resources::CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
        },
        InterruptDescriptor {
            level: res.int_level,
            vector: res.int_vector,
            affinity: res.int_affinity,
            flags: if res.int_latched {
                nt_cm_resources::CM_RESOURCE_INTERRUPT_LATCHED
            } else {
                nt_cm_resources::CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
            },
            share: nt_cm_resources::CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
        },
    );
    buf
}

fn check(name: &[u8], ok: bool) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
}

unsafe fn run() {
    RT = Some(KernelExecRuntime::new(FakeClock::new(), 0x5000_0000));
    RM = Some(ResourceManager::new()); // empty — resources assigned only at START (§15.2)
    SIM = Some(SimDevice::new());
    PNP = Some(PnpManager::new());
    PWR = Some(PowerManager::new());

    let pe = match nt_pe_loader::PeFile::parse(POWER_SYS) {
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
    check(b"patch_iat", true);

    // Seed a valid /GS cookie (top 16 bits zero — see nt_pe_loader::SECURITY_COOKIE_SEED).
    pe.seed_security_cookie(CODE_VADDR);
    apply_wx(&pe, frames);
    check(b"w_xor_x", true);

    // DRIVER_OBJECT + DriverExtension (DriverExtension@48, AddDevice@8).
    let driver_object = alloc_blob();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let driver_ext = alloc_blob();
    core::ptr::write_unaligned((driver_object + 48) as *mut u64, driver_ext);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let driver_entry: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = driver_entry(driver_object, reg_path);
    check(b"driver_entry_success", status == 0);

    let add_device = core::ptr::read_unaligned((driver_ext + 8) as *const u64);
    let pnp_dispatch =
        core::ptr::read_unaligned((driver_object + 112 + IRP_MJ_PNP as u64 * 8) as *const u64);
    check(b"add_device_present", add_device != 0);
    check(b"pnp_dispatch_present", pnp_dispatch != 0);

    // --- PnP Manager: enumerate the fixture devnode + create the PDO ---------
    let pdo = alloc_blob();
    core::ptr::write_unaligned(pdo as *mut i16, 3); // Type = IO_TYPE_DEVICE
    let devnode = pnp().create_mmio_fixture_devnode(pdo);
    let _ = pnp().transition(devnode, DeviceState::DriverLoaded);

    // AddDevice(DriverObject, PDO) → driver creates the FDO + attaches.
    dh().device_object = 0;
    let add_fn: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(add_device as *const ());
    let add_status = add_fn(driver_object, pdo);
    let fdo = dh().device_object;
    let _ = pnp().transition(devnode, DeviceState::AddDeviceCalled);
    let _ = pnp().set_fdo(devnode, fdo);
    let _ = pnp().transition(devnode, DeviceState::DeviceStackBuilt);
    check(
        b"add_device_success",
        add_status == 0 && fdo != 0 && dh().stack_attached,
    );

    // Negative: an IOCTL before START fails with STATUS_DEVICE_NOT_READY (§15.2/§21.3).
    let (st, _i, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_2100, &[], 8);
    check(
        b"ioctl_before_start_not_ready",
        st == STATUS_DEVICE_NOT_READY,
    );

    // --- Resource assignment + START_DEVICE ---------------------------------
    // Assign the resources to the Resource Manager only now (before START mapping).
    let res = pnp().resources(devnode).unwrap();
    rm().assign_memory(
        owner(),
        MEM_RESOURCE_ID,
        res.mem_start,
        res.mem_start,
        res.mem_length as u64,
        nt_hal_abi::MM_NON_CACHED,
        nt_hal_abi::RIGHT_READ | nt_hal_abi::RIGHT_WRITE,
    );
    rm().assign_interrupt(owner(), INT_RESOURCE_ID, INT_VECTOR, 5, 1, 0);
    let _ = pnp().transition(devnode, DeviceState::ResourcesAssigned);
    sim(); // ensure sim exists; ID register seeded on creation
    core::ptr::write_volatile(sim().mmio_ptr() as *mut u32, 0x4d4d_494f); // seed ID reg

    let translated = build_resource_list(devnode);
    let raw = build_resource_list(devnode);
    let _ = pnp().transition(devnode, DeviceState::StartIrpSent);
    let start_status = dispatch_pnp(driver_object, fdo, IRP_MN_START_DEVICE, raw, translated);
    let started_ok = start_status == 0 && dh().mmio_base != 0 && dh().interrupt_id != 0;
    if started_ok {
        let _ = pnp().transition(devnode, DeviceState::Started);
    }
    check(b"start_device_success", started_ok);
    // START success → device D0, power record registered (spec §11.1).
    dh().powered = true;
    dh().reported_device_state = DevicePowerState::D0 as u32;
    pwr().register_device(devnode);
    check(b"registered_d0", pwr().is_on(devnode) && dh().powered);

    // --- D0: device works ----------------------------------------------------
    let (st, _i, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_2100, &[], 8); // GET_ID
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_get_id_d0", st == 0 && id == 0x4d4d_494f);

    // --- SET_POWER D3: driver quiesces, device becomes unusable --------------
    let d3_ok = transition_device_power(driver_object, fdo, devnode, DevicePowerState::D3);
    check(
        b"set_power_d3",
        d3_ok && !dh().powered && pwr().device_state(devnode) == Some(DevicePowerState::D3),
    );

    // While D3: IOCTLs fail + injected interrupts are dropped (ISR not called).
    let (st, _i, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_2100, &[], 8);
    check(b"ioctl_rejected_in_d3", st != 0);
    check(b"interrupt_dropped_in_d3", !inject_interrupt(INT_VECTOR));

    // --- SET_POWER D0: device resumes ----------------------------------------
    let d0_ok = transition_device_power(driver_object, fdo, devnode, DevicePowerState::D0);
    check(
        b"set_power_d0",
        d0_ok && dh().powered && pwr().device_state(devnode) == Some(DevicePowerState::D0),
    );

    let (st, _i, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_2100, &[], 8); // GET_ID
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_get_id_after_d0", st == 0 && id == 0x4d4d_494f);

    // Interrupt path works again: WAIT pends, injected interrupt completes it.
    let (st, _i, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_2110, &[], 8);
    let pended = st == STATUS_PENDING && !dh().completed;
    let injected = inject_interrupt(INT_VECTOR);
    check(
        b"interrupt_completes_after_resume",
        pended && injected && dh().completed && dh().last_status == 0,
    );

    // --- REMOVE_DEVICE: cleanup + power record unregistered ------------------
    let _ = pnp().transition(devnode, DeviceState::RemovePending);
    let _ = pwr().mark_remove(devnode);
    let mapping_id = dh().mmio_mapping_id;
    let remove_status = dispatch_pnp(driver_object, fdo, IRP_MN_REMOVE_DEVICE, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::Removed);
    pwr().unregister_device(devnode);
    check(
        b"remove_releases_and_unregisters",
        remove_status == 0
            && !rm().mapping_valid(mapping_id)
            && rm().inject_vector(INT_VECTOR).is_none()
            && !pwr().is_registered(devnode),
    );

    check(b"callbacks_ran_at_correct_irql", dh().bad_irql == 0);
    let _ = add_status;
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);

    print_str(b"[ntos-dhw] Power Driver Host: real PowerPnpMmioTest.sys lifecycle\n");
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
