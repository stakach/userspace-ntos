//! `ntos-driver-host-pnp` — the PnP Driver Host as a seL4 component.
//!
//! Loads the real `PnpMmioInterruptTest.sys` (W^X + NX) and drives the full NT PnP
//! device lifecycle (spec: NT PnP Manager, Milestone 12) against an in-process HAL +
//! PnP Manager:
//!
//! ```text
//! DriverEntry -> sets DriverExtension->AddDevice + MajorFunction[IRP_MJ_PNP]
//! PnP Manager -> create PDO/devnode -> AddDevice -> START_DEVICE (CM_RESOURCE_LIST)
//! driver      -> parses translated resources -> MmMapIoSpace + IoConnectInterrupt
//! client      -> IOCTLs work only after Started; injected interrupt completes a pend
//! PnP Manager -> REMOVE_DEVICE -> driver disconnects/unmaps/detaches; resources revoked
//! ```

#![no_std]
#![no_main]
#![allow(function_casts_as_integer)]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use nt_cm_resources::{InterruptDescriptor, MemoryDescriptor};
use nt_config_manager::ConfigManager;
use nt_kernel_exec::{CompleteResult, EventKind, FakeClock, KernelExecRuntime};
use nt_pnp_abi::{
    DeviceState, IRP_MJ_PNP, IRP_MN_CANCEL_REMOVE_DEVICE, IRP_MN_CANCEL_STOP_DEVICE,
    IRP_MN_QUERY_REMOVE_DEVICE, IRP_MN_QUERY_STOP_DEVICE, IRP_MN_REMOVE_DEVICE, IRP_MN_START_DEVICE,
    IRP_MN_STOP_DEVICE, IRP_MN_SURPRISE_REMOVAL,
};
use nt_pnp_manager::PnpManager;
use nt_resource_manager::{ResourceManager, ResourceOwner};
use nt_root_bus::{BusQueryId, RootBus};
use nt_sim_device::SimDevice;
use sel4_rt::*;

/// The driver images this host has in its store, indexed by service name. In a full driver database
/// this is `Services\<name>\ImagePath` -> the file; here the "boot driver set" is a static table,
/// but the driver each devnode binds is still chosen by its selected service.
static PNP_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/PnpMmioInterruptTest.sys");
static POWER_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/PowerPnpMmioTest.sys");
static KMDF_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/KmdfInterfaceRegistryTest.sys");

/// Resolve a service name to its driver image (the boot-driver "store").
fn load_service_image(service: &str) -> Option<&'static [u8]> {
    match service {
        "PnpMmioInterruptTest" => Some(PNP_SYS),
        "PowerPnpMmioTest" => Some(POWER_SYS),
        "KmdfInterfaceRegistryTest" => Some(KMDF_SYS),
        _ => None,
    }
}

const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
/// The base the second bound driver's image is mapped at (device slot 1).
const SECOND_CODE_VADDR: u64 = 0x0000_0001_6000_0000;
/// The base the KMDF driver's image is mapped at (device slot 2).
const KMDF_CODE_VADDR: u64 = 0x0000_0001_8000_0000;
/// KmdfLoaderCompatTest's Control Flow Guard dispatch/check pointer slots (its load-config dir).
const KMDF_CFG_DISPATCH_RVA: u64 = 0x3068;
const KMDF_CFG_CHECK_RVA: u64 = 0x3060;
const STATUS_PENDING: i32 = 0x0000_0103;
const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;

// --- the primary fixture devnode this host actually binds (its driver is in the store) ----
const SERVICE_NAME: &str = "PnpMmioInterruptTest";
const DEVICE_ID: &str = r"ROOT\USERSPACE_NTOS_PNP_MMIO";
const COMPATIBLE_ID: &str = r"ROOT\USERSPACE_NTOS_TEST_DEVICE";
const INSTANCE_ID: &str = "0001";
const INSTANCE_PATH: &str = r"ROOT\USERSPACE_NTOS_PNP_MMIO\0001";
const CLASS_GUID: &str = "{4d36e97d-e325-11ce-bfc1-08002be10318}";
/// The `object_id` the PnP Manager + root bus use for the primary devnode's PDO.
const PDO_OBJECT_ID: u64 = 0xFED0_0000;

/// A root-enumerated fixture devnode (a child of the synthetic ROOT bus).
struct Fixture {
    instance_path: &'static str,
    service: &'static str,
    device_id: &'static str,
    compatible_id: &'static str,
    instance_id: &'static str,
    image_path: &'static str,
    pdo_object_id: u64,
}

/// The device tree the ROOT bus enumerates. `FIXTURES[0]` (PnpMmioInterruptTest) is the one whose
/// driver image this host has in its store, so it fully binds + starts; the rest are enumerated,
/// registered, and service-resolved as children of the tree (their drivers live in other hosts).
const FIXTURES: &[Fixture] = &[
    Fixture {
        instance_path: INSTANCE_PATH,
        service: SERVICE_NAME,
        device_id: DEVICE_ID,
        compatible_id: COMPATIBLE_ID,
        instance_id: INSTANCE_ID,
        image_path: r"\SystemRoot\system32\drivers\PnpMmioInterruptTest.sys",
        pdo_object_id: PDO_OBJECT_ID,
    },
    Fixture {
        instance_path: r"ROOT\USERSPACE_NTOS_POWER\0001",
        service: "PowerPnpMmioTest",
        device_id: r"ROOT\USERSPACE_NTOS_POWER",
        compatible_id: r"ROOT\USERSPACE_NTOS_TEST_DEVICE",
        instance_id: "0001",
        image_path: r"\SystemRoot\system32\drivers\PowerPnpMmioTest.sys",
        pdo_object_id: 0xFED0_1000,
    },
    Fixture {
        instance_path: r"ROOT\KMDF_INTERFACE_REGISTRY_TEST\0001",
        service: "KmdfInterfaceRegistryTest",
        device_id: r"ROOT\KMDF_INTERFACE_REGISTRY_TEST",
        compatible_id: r"ROOT\USERSPACE_NTOS_TEST_DEVICE",
        instance_id: "0001",
        image_path: r"\SystemRoot\system32\drivers\KmdfInterfaceRegistryTest.sys",
        pdo_object_id: 0xFED0_2000,
    },
    Fixture {
        instance_path: r"ROOT\USERSPACE_NTOS_DMA\0001",
        service: "DmaPnpPowerTest",
        device_id: r"ROOT\USERSPACE_NTOS_DMA",
        compatible_id: r"ROOT\USERSPACE_NTOS_TEST_DEVICE",
        instance_id: "0001",
        image_path: r"\SystemRoot\system32\drivers\DmaPnpPowerTest.sys",
        pdo_object_id: 0xFED0_3000,
    },
    Fixture {
        instance_path: r"ROOT\KMDF_LOADER_COMPAT_TEST\0001",
        service: "KmdfLoaderCompatTest",
        device_id: r"ROOT\KMDF_LOADER_COMPAT_TEST",
        compatible_id: r"ROOT\USERSPACE_NTOS_TEST_DEVICE",
        instance_id: "0001",
        image_path: r"\SystemRoot\system32\drivers\KmdfLoaderCompatTest.sys",
        pdo_object_id: 0xFED0_4000,
    },
];

const DRIVER_HOST_ID: u64 = 1;
const DEVICE_OBJECT_ID: u64 = 10;
const INT_VECTOR: u32 = 5;
const INT_RESOURCE_ID: u64 = 200;
const MEM_RESOURCE_ID: u64 = 100;

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);

fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}

static mut CODE_FRAME_CAPS: [[u64; 16]; 3] = [[0; 16]; 3];

unsafe fn map_region(base: u64, frames: u64) {
    let cur = CURRENT.load(Ordering::Relaxed);
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
        CODE_FRAME_CAPS[cur][i as usize] = f;
    }
}

unsafe fn apply_wx(pe: &nt_pe_loader::PeFile, base: u64, frames: u64) {
    let cur = CURRENT.load(Ordering::Relaxed);
    for i in 0..frames {
        let prot = pe.protection_at((i * 0x1000) as u32);
        let bits = if prot.writable() { 3 } else { 2 };
        let rights = if prot.executable() {
            bits
        } else {
            bits | PAGE_EXECUTE_NEVER
        };
        let f = CODE_FRAME_CAPS[cur][i as usize];
        let _ = page_unmap(f);
        let _ = page_map(f, base + i * 0x1000, rights, CAP_INIT_THREAD_VSPACE);
    }
}

// --- global services (root task .bss is RW) ---------------------------------

static mut RT: Option<KernelExecRuntime<FakeClock>> = None;
static mut RM: Option<ResourceManager> = None;
static mut SIM: Option<SimDevice> = None;
static mut PNP: Option<PnpManager> = None;
static mut ROOT_BUS: Option<RootBus> = None;

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
/// The single Configuration Manager for this host — the one owned by the shared WDF runtime, so the
/// WDM device-tree enumeration + the KMDF WDF registry path share one service/devnode database.
unsafe fn cfg() -> &'static mut ConfigManager {
    nt_wdf_kmdf::config_mut()
}
unsafe fn root_bus() -> &'static mut RootBus {
    (*core::ptr::addr_of_mut!(ROOT_BUS)).as_mut().unwrap()
}

/// Emit a traced `pnp_*` lifecycle event (spec §Tracing Events).
fn trace(event: &[u8]) {
    print_str(b"  [pnp] ");
    print_str(event);
    print_str(b"\n");
}

fn owner() -> ResourceOwner {
    ResourceOwner::new(DRIVER_HOST_ID, dh().device_owner_id)
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
    pdo: u64,              // the root-bus PDO device object (bottom of the stack)
    pnp_minor: u8,         // the PnP minor of the IRP currently in flight
    pdo_object_id: u64,    // the root-bus PDO identity for this device
    device_owner_id: u64,  // the ResourceManager owner id for this device
    code_base: u64,        // the VA the driver image is mapped at
    int_resource_id: u64,  // the ResourceManager interrupt-resource id for this device
}

impl DhState {
    const fn new() -> Self {
        DhState {
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
            pdo: 0,
            pnp_minor: 0,
            pdo_object_id: 0,
            device_owner_id: 0,
            code_base: 0,
            int_resource_id: INT_RESOURCE_ID,
        }
    }
}

/// Per-device driver-host state (one slot per bound driver: 0/1 = WDM, 2 = KMDF). `CURRENT` selects
/// the device the compatibility exports read/write — set before invoking a driver's callbacks.
static mut DH: [DhState; 3] = [DhState::new(), DhState::new(), DhState::new()];
static CURRENT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn dh() -> &'static mut DhState {
    // SAFETY: single-threaded root task; .bss is writable; CURRENT in 0..2.
    unsafe { &mut (*core::ptr::addr_of_mut!(DH))[CURRENT.load(Ordering::Relaxed)] }
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

/// `IofCallDriver(DeviceObject, Irp)` — pass the IRP down the device stack. When the FDO forwards a
/// PnP IRP to the lower device (the root-bus PDO returned by `IoAttachDeviceToDeviceStack`), it is
/// dispatched to the synthetic bus, which starts/stops the PDO and completes it (spec §12.3).
extern "win64" fn ntos_iof_call_driver(device: u64, irp: u64) -> i32 {
    // SAFETY: `irp` is an IRP we built (IoStatus.Status@48); `device` is a device-object pointer.
    unsafe {
        let status = if device != 0 && device == dh().pdo {
            // Bottom of the stack: the synthetic root bus handles this PnP minor for this device.
            root_bus().dispatch_pnp(dh().pdo_object_id, dh().pnp_minor)
        } else {
            0
        };
        if irp != 0 {
            core::ptr::write_unaligned((irp + 48) as *mut i32, status);
        }
        status
    }
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
        match rm().connect_interrupt(owner(), dh().int_resource_id, service_routine, service_context)
        {
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

extern "win64" fn ntos_stub() -> i32 {
    0
}

#[allow(function_casts_as_integer)]
/// `PoCallDriver(DeviceObject, Irp)` — modern behaviour is `IoCallDriver` (forward the power IRP
/// down the stack).
extern "win64" fn ntos_po_call_driver(device: u64, irp: u64) -> i32 {
    ntos_iof_call_driver(device, irp)
}
/// `PoSetPowerState(DeviceObject, Type, State)` — the driver reports its observed power state; we
/// echo it back (the value the driver expects on return).
extern "win64" fn ntos_po_set_power_state(_device: u64, _typ: u32, state: u32) -> u32 {
    state
}
/// `PoStartNextPowerIrp(Irp)` — legacy power-queue bookkeeping; a no-op here.
extern "win64" fn ntos_po_start_next_power_irp(_irp: u64) {}

// --- KMDF (WDF) family: bound through the shared nt-wdf-kmdf crate -----------------------------
// The WDF runtime (WdfVersionBind, the 32 thunks, WdfDriverCreate, the AddDevice bridge, the full
// device/registry/interface/queue surface) lives in nt-wdf-kmdf. This component owns only the
// framework PnP dispatch (tied to its device stack) + the resource list for EvtDevicePrepareHardware.

static KMDF_PREPARE_HW: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static KMDF_D0_ENTRY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// Whether the framework ran the driver's EvtDeviceD0Exit (D3 power-down) on STOP/REMOVE.
static KMDF_D0_EXIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// The KMDF DRIVER_OBJECT (component-owned; the post-Started stop/surprise flow dispatches to it).
static KMDF_DRV_OBJECT: AtomicU64 = AtomicU64::new(0);

unsafe fn call2(fp: u64, a: u64, b: u64) -> i32 {
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(fp as *const ());
    f(a, b)
}
unsafe fn call3(fp: u64, a: u64, b: u64, c: u64) -> i32 {
    let f: extern "win64" fn(u64, u64, u64) -> i32 = core::mem::transmute(fp as *const ());
    f(a, b, c)
}

/// A WDFCMRESLIST blob (count@0, descriptors@8 = 20 bytes each) with one memory descriptor — what
/// EvtDevicePrepareHardware reads via WdfCmResourceListGetCount / GetDescriptor.
unsafe fn kmdf_build_res_list() -> u64 {
    let list = alloc_blob();
    core::ptr::write_unaligned(list as *mut u32, 1); // count
    let desc = list + 8;
    core::ptr::write_unaligned(desc as *mut u8, 3); // CmResourceTypeMemory
    core::ptr::write_unaligned((desc + 4) as *mut u64, 0xFED0_0000); // u.Memory.Start
    core::ptr::write_unaligned((desc + 12) as *mut u32, 0x1000); // u.Memory.Length
    list
}

/// The KMDF framework PnP dispatch (installed into the KMDF DRIVER_OBJECT's MajorFunction[IRP_MJ_PNP]
/// by bind_kmdf). START runs EvtDevicePrepareHardware + EvtDeviceD0Entry through the shared runtime
/// and forwards the IRP down to the root-bus PDO; other minors just forward down.
extern "win64" fn kmdf_fx_pnp_dispatch(fdo: u64, irp: u64) -> i32 {
    // SAFETY: single-threaded; dh() is device slot 2 (KMDF); the WDF runtime is initialized.
    unsafe {
        let minor = dh().pnp_minor;
        let device = nt_wdf_object::WdfHandle(fdo);
        if minor == IRP_MN_START_DEVICE {
            let _ = ntos_iof_call_driver(dh().pdo, irp); // start the lower stack (the PDO)
            let res = kmdf_build_res_list();
            let prepare = nt_wdf_kmdf::wdf().prepare_hardware(device).unwrap_or(0);
            if prepare != 0 {
                KMDF_PREPARE_HW.store(true, Ordering::Relaxed);
                call3(prepare, fdo, res, res);
            }
            let d0 = nt_wdf_kmdf::wdf()
                .set_device_power(device, true)
                .map(|(e, _)| e)
                .unwrap_or(0);
            if d0 != 0 {
                KMDF_D0_ENTRY.store(true, Ordering::Relaxed);
                call2(d0, fdo, 1);
            }
        } else if minor == IRP_MN_STOP_DEVICE || minor == IRP_MN_REMOVE_DEVICE {
            // Power the device down (EvtDeviceD0Exit / D3) then forward the IRP down to the PDO.
            let d0exit = nt_wdf_kmdf::wdf()
                .set_device_power(device, false)
                .map(|(e, _)| e)
                .unwrap_or(0);
            if d0exit != 0 {
                KMDF_D0_EXIT.store(true, Ordering::Relaxed);
                call2(d0exit, fdo, 0);
            }
            let _ = ntos_iof_call_driver(dh().pdo, irp);
        } else {
            // QUERY_STOP / CANCEL_STOP / SURPRISE_REMOVAL: forward down (pure PnP negotiation).
            let _ = ntos_iof_call_driver(dh().pdo, irp);
        }
        core::ptr::write_unaligned((irp + 48) as *mut i32, 0);
    }
    0
}

// The KMDF device's IOCTL interface (KmdfInterfaceRegistryTest).
const KMDF_PING_MAGIC: u32 = 0x4946_4B4D; // "MKFI"
const KMDF_IOCTL_PING: u32 = 0x0022_2200;
const KMDF_IOCTL_GET_CONFIG: u32 = 0x0022_2204; // Answer@0xc
const KMDF_IOCTL_GET_GREETING: u32 = 0x0022_220C; // wchar greeting @ offset 4
const KMDF_IOCTL_ECHO: u32 = 0x0022_2218;

/// A zeroed heap buffer of `size` bytes (the IOCTL system buffer).
fn alloc_bytes(size: usize) -> u64 {
    let layout = core::alloc::Layout::from_size_align(size.max(1), 16).unwrap();
    // SAFETY: nonzero size, valid 16-byte align.
    unsafe { alloc::alloc::alloc_zeroed(layout) as u64 }
}

/// Present an IOCTL to the KMDF device's default queue through the shared runtime, run the driver's
/// EvtIoDeviceControl, and read back `(status, information, output bytes)`. Mirrors direg's run_ioctl
/// but drives the *same* shared nt-wdf-kmdf runtime from this WDM host.
unsafe fn run_kmdf_ioctl(device: u64, ioctl: u32, input: &[u8], out_cap: u64) -> (i32, u64, [u8; 64]) {
    let sysbuf = alloc_bytes(out_cap.max(input.len() as u64).max(1) as usize);
    for (i, b) in input.iter().enumerate() {
        core::ptr::write_volatile((sysbuf + i as u64) as *mut u8, *b);
    }
    let irp = alloc_blob();
    let buffers = nt_wdf_request::RequestBuffers {
        input_ptr: if input.is_empty() { 0 } else { sysbuf },
        input_len: input.len() as u64,
        output_ptr: if out_cap == 0 { 0 } else { sysbuf },
        output_len: out_cap,
    };
    let (request, dispatch) = match nt_wdf_kmdf::wdf().present_ioctl(
        nt_wdf_object::WdfHandle(device),
        irp,
        ioctl,
        buffers,
    ) {
        Ok(v) => v,
        Err(_) => return (i32::MIN, 0, [0u8; 64]),
    };
    let Some(d) = dispatch else {
        return (i32::MIN, 0, [0u8; 64]);
    };
    // EvtIoDeviceControl(Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode).
    let f: extern "win64" fn(u64, u64, u64, u64, u32) =
        core::mem::transmute(d.evt_io_device_control as *const ());
    f(d.queue.0, request.0, out_cap, input.len() as u64, ioctl);
    let mut out = [0u8; 64];
    for (i, o) in out.iter_mut().enumerate().take(out_cap.min(64) as usize) {
        *o = core::ptr::read_volatile((sysbuf + i as u64) as *const u8);
    }
    let (status, info) = nt_wdf_kmdf::last_completion();
    (status, info, out)
}

fn export_addr(name: &str) -> u64 {
    match name {
        "PoCallDriver" => ntos_po_call_driver as usize as u64,
        "PoSetPowerState" => ntos_po_set_power_state as usize as u64,
        "PoStartNextPowerIrp" => ntos_po_start_next_power_irp as usize as u64,
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
    dh().pnp_minor = minor; // so IofCallDriver can dispatch the forwarded IRP to the root-bus PDO
    rt().mark_irp_pending(irp, 0x1b00 | minor as u64);

    let routine =
        core::ptr::read_unaligned((driver_object + 112 + IRP_MJ_PNP as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let _ = f(fdo, irp);
    dh().last_status
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

/// Build a translated `CM_RESOURCE_LIST` with explicit memory + interrupt resources (for a second
/// device whose resources must not collide with the first).
unsafe fn build_resource_list_explicit(mem_start: u64, mem_length: u32, vector: u32) -> u64 {
    let buf = alloc_blob();
    let slice = core::slice::from_raw_parts_mut(buf as *mut u8, 64);
    let _ = nt_cm_resources::build_memory_interrupt_list(
        slice,
        0,
        MemoryDescriptor {
            start: mem_start,
            length: mem_length,
            flags: 0,
            share: nt_cm_resources::CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
        },
        InterruptDescriptor {
            level: vector,
            vector,
            affinity: 1,
            flags: nt_cm_resources::CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
            share: nt_cm_resources::CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
        },
    );
    buf
}

/// Load + PnP-bind a second real driver in this host: map its image at `base` (device slot 1), run
/// DriverEntry, call `DriverExtension->AddDevice` with its PDO, assign distinct resources, and send
/// `IRP_MN_START_DEVICE` through the stack. Returns whether it reached Started.
unsafe fn bind_secondary(fx: &Fixture, pnp_devnode: u64, base: u64, mem_base: u64, vector: u32) -> bool {
    CURRENT.store(1, Ordering::Relaxed);
    let d = dh();
    d.pdo_object_id = fx.pdo_object_id;
    d.device_owner_id = 20;
    d.code_base = base;
    d.device_object = 0;
    d.stack_attached = false;
    d.mmio_base = 0;
    d.int_resource_id = INT_RESOURCE_ID + 1;

    let image = match load_service_image(fx.service) {
        Some(i) => i,
        None => return false,
    };
    let pe = match nt_pe_loader::PeFile::parse(image) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let frames = (pe.size_of_image() as u64).div_ceil(0x1000);
    map_region(base, frames);
    let mapped = match pe.map(base) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let dst = base as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let nt_pe_loader::ImportRef::ByName {
                    name, iat_slot_rva, ..
                } = f
                {
                    core::ptr::write_unaligned(
                        (base + *iat_slot_rva as u64) as *mut u64,
                        export_addr(name),
                    );
                }
            }
        }
    }
    pe.seed_security_cookie(base);
    apply_wx(&pe, base, frames);

    // DRIVER_OBJECT + DriverExtension, DriverEntry (sets AddDevice + MajorFunction[IRP_MJ_PNP]).
    let driver_object = alloc_blob();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let driver_ext = alloc_blob();
    core::ptr::write_unaligned((driver_object + 48) as *mut u64, driver_ext);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;
    let entry = base + pe.entry_point_rva() as u64;
    let driver_entry: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    if driver_entry(driver_object, reg_path) != 0 {
        return false;
    }
    let add_device = core::ptr::read_unaligned((driver_ext + 8) as *const u64);
    if add_device == 0 {
        return false;
    }

    // AddDevice(DriverObject, PDO) -> FDO.
    let pdo = alloc_blob();
    core::ptr::write_unaligned(pdo as *mut i16, 3);
    dh().pdo = pdo;
    let _ = pnp().transition(pnp_devnode, DeviceState::DriverLoaded);
    dh().device_object = 0;
    let add_fn: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(add_device as *const ());
    let add_status = add_fn(driver_object, pdo);
    let fdo = dh().device_object;
    if add_status != 0 || fdo == 0 {
        return false;
    }
    let _ = pnp().transition(pnp_devnode, DeviceState::AddDeviceCalled);
    let _ = pnp().set_fdo(pnp_devnode, fdo);
    let _ = pnp().transition(pnp_devnode, DeviceState::DeviceStackBuilt);

    // Assign distinct resources, then START through the stack.
    rm().assign_memory(
        owner(),
        MEM_RESOURCE_ID + 1,
        mem_base,
        mem_base,
        0x1000,
        nt_hal_abi::MM_NON_CACHED,
        nt_hal_abi::RIGHT_READ | nt_hal_abi::RIGHT_WRITE,
    );
    rm().assign_interrupt(owner(), INT_RESOURCE_ID + 1, vector, vector as u8, 1, 0);
    let _ = pnp().transition(pnp_devnode, DeviceState::ResourcesAssigned);
    let translated = build_resource_list_explicit(mem_base, 0x1000, vector);
    let raw = build_resource_list_explicit(mem_base, 0x1000, vector);
    let _ = pnp().transition(pnp_devnode, DeviceState::StartIrpSent);
    let start_status = dispatch_pnp(driver_object, fdo, IRP_MN_START_DEVICE, raw, translated);
    let started = start_status == 0
        && dh().mmio_base != 0
        && dh().interrupt_id != 0
        && root_bus().pdo_started(fx.pdo_object_id);
    if started {
        let _ = pnp().transition(pnp_devnode, DeviceState::Started);
    }
    started
}

/// Load + PnP-bind a KMDF driver (a second driver *family*) in this same host, in device slot 2,
/// through the shared nt-wdf-kmdf runtime — all the way to Started: init the runtime, seed its
/// service DB, DriverEntry -> WdfVersionBind -> WdfDriverCreate (AddDevice bridge), PnP calls the
/// bridge -> EvtDriverDeviceAdd (full: WdfDeviceCreate + registry params + device interface + I/O
/// queue) -> START through the FDO -> PDO stack (EvtDevicePrepareHardware + EvtDeviceD0Entry).
unsafe fn bind_kmdf(fx: &Fixture, pnp_devnode: u64, cfg_devnode: u64, base: u64) -> bool {
    // The service + devnode are already in the shared Configuration Manager (the tree enumeration).
    // Add the KMDF Parameters (Answer=42, Greeting="hello registry") the driver reads/writes, and
    // point the WDF runtime at this service + its devnode.
    {
        let cm = nt_wdf_kmdf::config_mut();
        cm.set_service_parameter(
            fx.service,
            "Answer",
            nt_config_manager::RegistryValueType::Dword,
            42u32.to_le_bytes().to_vec(),
        );
        cm.set_service_parameter(
            fx.service,
            "Greeting",
            nt_config_manager::RegistryValueType::Sz,
            nt_config_manager::encode_sz("hello registry"),
        );
    }
    nt_wdf_kmdf::set_devnode(cfg_devnode);
    nt_wdf_kmdf::set_driver_service(fx.service);

    CURRENT.store(2, Ordering::Relaxed);
    let d = dh();
    d.pdo_object_id = fx.pdo_object_id;
    d.device_owner_id = 30;
    d.code_base = base;
    d.device_object = 0;
    d.stack_attached = false;

    let image = match load_service_image(fx.service) {
        Some(i) => i,
        None => return false,
    };
    let pe = match nt_pe_loader::PeFile::parse(image) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let frames = (pe.size_of_image() as u64).div_ceil(0x1000);
    map_region(base, frames);
    let mapped = match pe.map(base) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let dst = base as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    // Resolve the KMDF driver's imports through the shared WDF crate (WDFLDR + core ntoskrnl).
    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let nt_pe_loader::ImportRef::ByName {
                    name, iat_slot_rva, ..
                } = f
                {
                    let addr = nt_wdf_kmdf::export_addr(name).unwrap_or_else(|| export_addr(name));
                    core::ptr::write_unaligned((base + *iat_slot_rva as u64) as *mut u64, addr);
                }
            }
        }
    }
    // CFG fixup (before W^X seals .rdata): the shared crate's `jmp rax` dispatch + a `ret` check.
    core::ptr::write_unaligned(
        (base + KMDF_CFG_DISPATCH_RVA) as *mut u64,
        nt_wdf_kmdf::cfg_dispatch_addr(),
    );
    core::ptr::write_unaligned((base + KMDF_CFG_CHECK_RVA) as *mut u64, nt_wdf_kmdf::cfg_dispatch_addr());
    pe.seed_security_cookie(base);
    apply_wx(&pe, base, frames);

    // DRIVER_OBJECT + DriverExtension, DriverEntry -> WdfVersionBind -> WdfDriverCreate.
    let driver_object = alloc_blob();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let driver_ext = alloc_blob();
    core::ptr::write_unaligned((driver_object + 48) as *mut u64, driver_ext);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;
    let entry = base + pe.entry_point_rva() as u64;
    let de: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    if de(driver_object, reg_path) != 0 {
        return false;
    }
    // Install the component's framework PnP dispatch into MajorFunction[IRP_MJ_PNP] (the crate owns
    // the AddDevice bridge; the PnP dispatch is tied to this component's device stack).
    core::ptr::write_unaligned(
        (driver_object + 112 + IRP_MJ_PNP as u64 * 8) as *mut u64,
        kmdf_fx_pnp_dispatch as usize as u64,
    );
    KMDF_DRV_OBJECT.store(driver_object, Ordering::Relaxed);
    let add_device = core::ptr::read_unaligned((driver_ext + 8) as *const u64);
    if add_device != nt_wdf_kmdf::add_device_bridge_addr() {
        return false;
    }

    // PnP calls the AddDevice bridge -> EvtDriverDeviceAdd (full device/registry/interface/queue).
    let pdo = alloc_blob();
    core::ptr::write_unaligned(pdo as *mut i16, 3);
    dh().pdo = pdo;
    let _ = pnp().transition(pnp_devnode, DeviceState::DriverLoaded);
    let add_fn: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(add_device as *const ());
    let add_status = add_fn(driver_object, pdo);
    let fdo = nt_wdf_kmdf::device();
    if add_status != 0 || fdo == 0 {
        return false;
    }
    let _ = pnp().transition(pnp_devnode, DeviceState::AddDeviceCalled);
    let _ = pnp().set_fdo(pnp_devnode, fdo);
    let _ = pnp().transition(pnp_devnode, DeviceState::DeviceStackBuilt);
    let _ = pnp().transition(pnp_devnode, DeviceState::ResourcesAssigned);
    let _ = pnp().transition(pnp_devnode, DeviceState::StartIrpSent);

    // START through the FDO -> PDO stack: the framework dispatch runs EvtDevicePrepareHardware +
    // EvtDeviceD0Entry, forwards the IRP down to the root-bus PDO, and the devnode reaches Started.
    let start_status = dispatch_pnp(driver_object, fdo, IRP_MN_START_DEVICE, 0, 0);
    let started = start_status == 0
        && KMDF_PREPARE_HW.load(Ordering::Relaxed)
        && KMDF_D0_ENTRY.load(Ordering::Relaxed)
        && root_bus().pdo_started(fx.pdo_object_id);
    if started {
        let _ = pnp().transition(pnp_devnode, DeviceState::Started);
    }
    started
}

fn check(name: &[u8], ok: bool) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
}

/// `buf` is a NUL-terminated wide string equal to `expected`.
fn wide_is(buf: &[u16], expected: &str) -> bool {
    let e: Vec<u16> = expected.encode_utf16().collect();
    buf.len() == e.len() + 1 && buf[e.len()] == 0 && buf[..e.len()] == e[..]
}

/// `buf` is a double-NUL-terminated multi-SZ whose first entry equals `expected`.
fn wide_is_multisz_first(buf: &[u16], expected: &str) -> bool {
    let e: Vec<u16> = expected.encode_utf16().collect();
    buf.len() >= e.len() + 2 && buf[e.len()] == 0 && buf[..e.len()] == e[..]
}

/// A short label for a devnode's PnP lifecycle state, for the device-tree report.
fn state_label(s: Option<DeviceState>) -> &'static [u8] {
    match s {
        Some(DeviceState::Uninitialized) => b"Uninitialized",
        Some(DeviceState::Enumerated) => b"Enumerated",
        Some(DeviceState::DriverLoaded) => b"DriverLoaded",
        Some(DeviceState::AddDeviceCalled) => b"AddDeviceCalled",
        Some(DeviceState::DeviceStackBuilt) => b"DeviceStackBuilt",
        Some(DeviceState::ResourcesAssigned) => b"ResourcesAssigned",
        Some(DeviceState::StartIrpSent) => b"StartIrpSent",
        Some(DeviceState::Started) => b"Started",
        Some(DeviceState::QueryStopPending) => b"QueryStopPending",
        Some(DeviceState::Stopped) => b"Stopped",
        Some(DeviceState::QueryRemovePending) => b"QueryRemovePending",
        Some(DeviceState::RemovePending) => b"RemovePending",
        Some(DeviceState::Removed) => b"Removed",
        Some(DeviceState::Failed) => b"Failed",
        None => b"?",
    }
}

unsafe fn run() {
    RT = Some(KernelExecRuntime::new(FakeClock::new(), 0x5000_0000));
    RM = Some(ResourceManager::new()); // empty — resources assigned only at START (§15.2)
    SIM = Some(SimDevice::new());
    PNP = Some(PnpManager::new());
    ROOT_BUS = Some(RootBus::new());
    // The shared WDF runtime owns the single Configuration Manager (see cfg()); init it once here so
    // the WDM device-tree enumeration + the KMDF WDF registry path use the same service/devnode DB.
    nt_wdf_kmdf::init();

    // --- ResolveService: seed the boot service database + the root-enumerated device tree -------
    // Register a service key + an Enum\ devnode per fixture, and have the ROOT bus create a child
    // PDO for each. The driver each devnode binds is chosen by its `Service` value — the device
    // tree drives binding, not a hardcoded image.
    let mut cfg_devnodes: Vec<u64> = Vec::new();
    for fx in FIXTURES {
        cfg().register_service(
            fx.service,
            fx.image_path,
            Some("Base"),
            Some(CLASS_GUID),
            /* start = SERVICE_BOOT_START */ 0,
            /* error_control = NORMAL */ 1,
        );
        let dn = cfg().register_devnode(
            fx.instance_path,
            Some(fx.service),
            None,
            &[fx.device_id],
            &[fx.compatible_id],
        );
        root_bus().create_pdo(
            fx.pdo_object_id,
            fx.device_id,
            &[fx.device_id],
            &[fx.compatible_id],
            fx.instance_id,
        );
        cfg_devnodes.push(dn);
    }
    trace(b"pnp_devnode_create (x N) + pnp_devnode_registry_materialize");

    // --- Enumerate the tree: IRP_MN_QUERY_DEVICE_RELATIONS(BusRelations) -------------------------
    let children = root_bus().query_device_relations();
    check(
        b"bus_relations_lists_all_children",
        children.len() == FIXTURES.len(),
    );
    trace(b"pnp_query_relations (BusRelations)");
    print_str(b"  [device-tree] \\Device\\RootBus\n");
    let mut resolved = 0usize;
    let mut bindable = 0usize;
    let mut pnp_devnodes: Vec<u64> = Vec::new();
    for (fx, &dn) in FIXTURES.iter().zip(cfg_devnodes.iter()) {
        // pnp_service_select: each child's driver is named by its devnode Service value.
        let svc_ok = cfg().devnode_service(dn) == Some(fx.service);
        if svc_ok {
            resolved += 1;
        }
        let has_driver = load_service_image(fx.service).is_some();
        if has_driver {
            bindable += 1;
        }
        // Give every child a PnP Manager state entry (starts Enumerated).
        let pdn = pnp().create_mmio_fixture_devnode(fx.pdo_object_id);
        pnp_devnodes.push(pdn);
        print_str(b"    - ");
        print_str(fx.instance_path.as_bytes());
        print_str(b"  service=");
        print_str(fx.service.as_bytes());
        print_str(b"  state=");
        print_str(state_label(pnp().state(pdn)));
        print_str(if has_driver { b"  [bind]\n" } else { b"\n" });
    }
    check(b"device_tree_services_resolved", resolved == FIXTURES.len());
    check(b"device_tree_has_bindable_driver", bindable >= 1);
    check(
        b"device_tree_all_children_enumerated",
        pnp_devnodes
            .iter()
            .all(|&d| pnp().state(d) == Some(DeviceState::Enumerated)),
    );
    trace(b"pnp_service_select");

    // --- The primary child (FIXTURES[0]) has its driver in the store: bind + start it -----------
    let selected = cfg().devnode_service(cfg_devnodes[0]).map(str::to_string);
    check(
        b"service_selected_from_devnode",
        selected.as_deref() == Some(SERVICE_NAME),
    );
    let image = match selected.as_deref().and_then(load_service_image) {
        Some(img) => img,
        None => {
            check(b"driver_loaded_by_service", false);
            return;
        }
    };
    check(b"driver_loaded_by_service", true);
    trace(b"pnp_driver_load_request");

    // The primary binds in device slot 0 (mapped at CODE_VADDR, PDO FIXTURES[0], owner 10).
    CURRENT.store(0, Ordering::Relaxed);
    dh().pdo_object_id = FIXTURES[0].pdo_object_id;
    dh().device_owner_id = DEVICE_OBJECT_ID;
    dh().code_base = CODE_VADDR;

    let pe = match nt_pe_loader::PeFile::parse(image) {
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
    apply_wx(&pe, CODE_VADDR, frames);
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

    // --- Bind the primary child: reuse its tree devnode; its PDO is the bottom of the stack -----
    let devnode = pnp_devnodes[0];
    let pdo = alloc_blob();
    core::ptr::write_unaligned(pdo as *mut i16, 3); // Type = IO_TYPE_DEVICE
    dh().pdo = pdo; // the device object the FDO forwards IRPs to (the primary child's PDO)
    trace(b"pnp_pdo_create + pnp_stack_create");

    // The PnP Manager queries the PDO's identity before binding a function driver (QUERY_ID +
    // QUERY_CAPABILITIES answered by the synthetic root bus).
    let device_id_ok = root_bus()
        .query_id(PDO_OBJECT_ID, BusQueryId::DeviceId)
        .map(|w| wide_is(&w, DEVICE_ID))
        .unwrap_or(false);
    check(b"root_bus_query_id_device", device_id_ok);
    let hwids_ok = root_bus()
        .query_id(PDO_OBJECT_ID, BusQueryId::HardwareIds)
        .map(|w| wide_is_multisz_first(&w, DEVICE_ID))
        .unwrap_or(false);
    check(b"root_bus_query_id_hardware", hwids_ok);
    trace(b"pnp_query_id");
    let caps_ok = root_bus()
        .query_capabilities(PDO_OBJECT_ID)
        .map(|c| c.version == 1 && c.device_state[0] == 1 && c.surprise_removal_ok)
        .unwrap_or(false);
    check(b"root_bus_query_capabilities", caps_ok);
    trace(b"pnp_query_capabilities");

    let _ = pnp().transition(devnode, DeviceState::DriverLoaded);
    trace(b"pnp_driver_loaded");

    // --- CallAddDevice: the PnP Manager invokes DriverExtension->AddDevice with the PDO -------
    // (the manager reads AddDevice off the DriverObject and calls it — not a hardcoded harness
    // entry) → the function driver creates its FDO and attaches it above the PDO.
    trace(b"pnp_add_device_enter");
    dh().device_object = 0;
    let add_fn: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(add_device as *const ());
    let add_status = add_fn(driver_object, pdo);
    let fdo = dh().device_object;
    let _ = pnp().transition(devnode, DeviceState::AddDeviceCalled);
    let _ = pnp().set_fdo(devnode, fdo);
    let _ = pnp().transition(devnode, DeviceState::DeviceStackBuilt);
    trace(b"pnp_add_device_exit");
    check(b"pnp_called_add_device", add_status == 0);
    // ValidateFdoAttached: the FDO must sit above the PDO in the stack.
    check(b"fdo_attached_above_pdo", fdo != 0 && dh().stack_attached);
    trace(b"pnp_fdo_detected + pnp_attach");

    // Negative: an IOCTL before START fails with STATUS_DEVICE_NOT_READY (§15.2/§21.3).
    let (st, _i, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_20C0, &[], 8);
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
    trace(b"pnp_start_enter + pnp_start_resources (raw + translated CM_RESOURCE_LIST)");
    let _ = pnp().transition(devnode, DeviceState::StartIrpSent);
    let start_status = dispatch_pnp(driver_object, fdo, IRP_MN_START_DEVICE, raw, translated);
    let started_ok = start_status == 0 && dh().mmio_base != 0 && dh().interrupt_id != 0;
    if started_ok {
        let _ = pnp().transition(devnode, DeviceState::Started);
    }
    trace(b"pnp_start_complete");
    check(b"start_device_with_resources", started_ok);
    // The START IRP travelled FDO -> PDO: the driver forwarded it down and the root-bus PDO started.
    check(
        b"start_device_irp_reached_pdo",
        root_bus().pdo_started(PDO_OBJECT_ID),
    );
    check(
        b"devnode_started",
        pnp().state(devnode) == Some(DeviceState::Started),
    );

    // --- Bind a SECOND real driver (FIXTURES[1] = PowerPnpMmioTest) in this same host -----------
    // A distinct image mapped at its own base (device slot 1), distinct resources (MMIO 0x20000000,
    // vector 6), bound through the same PnP path -> two real drivers Started in one host.
    trace(b"pnp_second_driver_bind (PowerPnpMmioTest)");
    let second_started = bind_secondary(
        &FIXTURES[1],
        pnp_devnodes[1],
        SECOND_CODE_VADDR,
        0x2000_0000,
        6,
    );
    check(b"second_driver_bound_and_started", second_started);

    // --- Bind a KMDF driver (a second driver FAMILY) in this same WDM host -----------------------
    // The WDF runtime coexists with the WDM export surface: WdfVersionBind -> WdfDriverCreate ->
    // (WDM AddDevice bridge) -> EvtDriverDeviceAdd -> WdfDeviceCreate, then START through the stack.
    trace(b"pnp_kmdf_family_bind (KmdfInterfaceRegistryTest, via nt-wdf-kmdf)");
    let kmdf_started = bind_kmdf(&FIXTURES[2], pnp_devnodes[2], cfg_devnodes[2], KMDF_CODE_VADDR);
    CURRENT.store(0, Ordering::Relaxed); // restore device 0 for the primary's IOCTLs below
    // A KMDF driver bound to Started alongside the two WDM drivers, through the shared nt-wdf-kmdf
    // runtime: WdfVersionBind (1.15) -> WdfDriverCreate -> AddDevice bridge -> full EvtDriverDeviceAdd
    // (WdfDeviceCreate + registry params + device interface + I/O queue) -> START (PrepareHardware+D0).
    check(b"kmdf_family_started_alongside_wdm", kmdf_started);

    // --- Live device-tree state snapshot: THREE children Started (2 WDM + 1 KMDF) ----------------
    print_str(b"  [device-tree live] \\Device\\RootBus\n");
    for (fx, &pdn) in FIXTURES.iter().zip(pnp_devnodes.iter()) {
        print_str(b"    - ");
        print_str(fx.instance_path.as_bytes());
        print_str(b"  state=");
        print_str(state_label(pnp().state(pdn)));
        print_str(b"\n");
    }
    check(
        b"three_children_started_two_families",
        pnp().state(pnp_devnodes[0]) == Some(DeviceState::Started)
            && pnp().state(pnp_devnodes[1]) == Some(DeviceState::Started)
            && pnp().state(pnp_devnodes[2]) == Some(DeviceState::Started)
            && pnp_devnodes[3..]
                .iter()
                .all(|&d| pnp().state(d) == Some(DeviceState::Enumerated)),
    );

    // --- device works after Started -----------------------------------------
    let (st, _i, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_20C0, &[], 8); // GET_ID
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_get_id_after_start", st == 0 && id == 0x4d4d_494f);

    // WAIT_FOR_INTERRUPT pends; injected interrupt completes it.
    let (st, _i, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_20D0, &[], 8);
    let pended = st == STATUS_PENDING && !dh().completed;
    let injected = inject_interrupt(INT_VECTOR);
    check(
        b"interrupt_completes_pending_ioctl",
        pended && injected && dh().completed && dh().last_status == 0,
    );

    let (st, _i, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_20D4, &[], 8); // GET_INTERRUPT_COUNT
    let count = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"interrupt_count", st == 0 && count == 1);

    // --- STOP negotiation: QUERY_STOP -> CANCEL_STOP keeps the device running ------------------
    // A proposed stop the PnP Manager then cancels: the device returns to Started and keeps working.
    trace(b"pnp_query_stop + pnp_cancel_stop");
    let _ = dispatch_pnp(driver_object, fdo, IRP_MN_QUERY_STOP_DEVICE, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::QueryStopPending);
    let cancel_status = dispatch_pnp(driver_object, fdo, IRP_MN_CANCEL_STOP_DEVICE, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::Started);
    let (st, _i, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_20C0, &[], 8); // GET_ID
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(
        b"cancel_stop_keeps_device_started",
        cancel_status == 0
            && pnp().state(devnode) == Some(DeviceState::Started)
            && st == 0
            && id == 0x4d4d_494f,
    );

    // --- REMOVE negotiation: QUERY_REMOVE -> CANCEL_REMOVE keeps the device running ------------
    // A proposed remove the PnP Manager then cancels (e.g. a rebalance the user vetoes): the device
    // returns to Started and keeps working, its resources untouched.
    trace(b"pnp_query_remove + pnp_cancel_remove");
    let _ = dispatch_pnp(driver_object, fdo, IRP_MN_QUERY_REMOVE_DEVICE, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::QueryRemovePending);
    let cancel_rm_status = dispatch_pnp(driver_object, fdo, IRP_MN_CANCEL_REMOVE_DEVICE, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::Started);
    let (st, _i, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_20C0, &[], 8); // GET_ID
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(
        b"cancel_remove_keeps_device_started",
        cancel_rm_status == 0
            && pnp().state(devnode) == Some(DeviceState::Started)
            && root_bus().pdo_started(PDO_OBJECT_ID)
            && st == 0
            && id == 0x4d4d_494f,
    );

    // --- STOP: QUERY_STOP -> STOP_DEVICE quiesces the device -----------------------------------
    trace(b"pnp_stop_enter");
    let _ = dispatch_pnp(driver_object, fdo, IRP_MN_QUERY_STOP_DEVICE, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::QueryStopPending);
    let stop_status = dispatch_pnp(driver_object, fdo, IRP_MN_STOP_DEVICE, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::Stopped);
    trace(b"pnp_stop_complete");
    check(
        b"stop_device_quiesces",
        stop_status == 0
            && pnp().state(devnode) == Some(DeviceState::Stopped)
            && !root_bus().pdo_started(PDO_OBJECT_ID),
    );

    // --- Restart: a fresh START IRP resumes the stopped device --------------------------------
    trace(b"pnp_restart_enter");
    let translated = build_resource_list(devnode);
    let raw = build_resource_list(devnode);
    let _ = pnp().transition(devnode, DeviceState::StartIrpSent);
    let restart_status = dispatch_pnp(driver_object, fdo, IRP_MN_START_DEVICE, raw, translated);
    if restart_status == 0 {
        let _ = pnp().transition(devnode, DeviceState::Started);
    }
    let (st, _i, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_20C0, &[], 8); // GET_ID
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(
        b"restart_after_stop_resumes",
        restart_status == 0
            && pnp().state(devnode) == Some(DeviceState::Started)
            && root_bus().pdo_started(PDO_OBJECT_ID)
            && st == 0
            && id == 0x4d4d_494f,
    );

    // --- SURPRISE_REMOVAL -> REMOVE_DEVICE releases resources ----------------------------------
    // The unexpected-removal path: SURPRISE_REMOVAL (no QUERY_REMOVE), then REMOVE tears down.
    trace(b"pnp_surprise_removal_enter");
    let surprise_status = dispatch_pnp(driver_object, fdo, IRP_MN_SURPRISE_REMOVAL, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::RemovePending);
    let mapping_id = dh().mmio_mapping_id;
    let remove_status = dispatch_pnp(driver_object, fdo, IRP_MN_REMOVE_DEVICE, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::Removed);
    trace(b"pnp_remove_complete");
    check(
        b"surprise_removal_then_remove_releases_resources",
        surprise_status == 0
            && remove_status == 0
            && !rm().mapping_valid(mapping_id)
            && rm().inject_vector(INT_VECTOR).is_none(),
    );
    // The REMOVE IRP travelled FDO -> PDO: the root-bus PDO is stopped.
    check(
        b"remove_device_irp_reached_pdo",
        !root_bus().pdo_started(PDO_OBJECT_ID),
    );
    check(
        b"devnode_removed",
        pnp().state(devnode) == Some(DeviceState::Removed),
    );

    check(b"callbacks_ran_at_correct_irql", dh().bad_irql == 0);
    let _ = add_status;

    // --- KMDF child: STOP / restart / SURPRISE_REMOVAL through the shared runtime ---------------
    // The KMDF device (slot 2, Started earlier) now runs the same stop + surprise paths, with the
    // framework driving EvtDeviceD0Exit (D3) on stop/remove + EvtDeviceD0Entry on restart via
    // nt-wdf-kmdf — the whole PnP lifecycle across two driver families.
    CURRENT.store(2, Ordering::Relaxed);
    let kdrv = KMDF_DRV_OBJECT.load(Ordering::Relaxed);
    let kfdo = nt_wdf_kmdf::device();
    let kdevnode = pnp_devnodes[2];
    let kpdo = FIXTURES[2].pdo_object_id;

    // --- KMDF IOCTL smoke: present_ioctl -> the driver's EvtIoDeviceControl via the shared runtime.
    trace(b"kmdf_ioctl_smoke (PING / GET_CONFIG / GET_GREETING / ECHO)");
    let (st, info, out) = run_kmdf_ioctl(kfdo, KMDF_IOCTL_PING, &[], 4);
    let ping = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"kmdf_ioctl_ping", st == 0 && info == 4 && ping == KMDF_PING_MAGIC);

    // GET_CONFIG: the driver reports its state; Answer@0xc is the registry Parameter it read (42).
    let (st, _i, out) = run_kmdf_ioctl(kfdo, KMDF_IOCTL_GET_CONFIG, &[], 0x2c);
    let answer = core::ptr::read_unaligned(out.as_ptr().add(0xc) as *const u32);
    check(b"kmdf_ioctl_get_config_answer_42", st == 0 && answer == 42);

    // GET_GREETING: a wide "hello registry" (the registry Parameter) at offset 4.
    let (st, _i, out) = run_kmdf_ioctl(kfdo, KMDF_IOCTL_GET_GREETING, &[], 0x20c);
    let expected: Vec<u16> = "hello registry".encode_utf16().collect();
    let mut greeting_ok = st == 0;
    for (i, w) in expected.iter().enumerate() {
        let ch = out[4 + i * 2] as u16 | ((out[4 + i * 2 + 1] as u16) << 8);
        greeting_ok &= ch == *w;
    }
    check(b"kmdf_ioctl_get_greeting", greeting_ok);

    // ECHO: the driver copies the input buffer back to the output buffer.
    let echo_in = &[0xDEu8, 0xAD, 0xBE, 0xEF];
    let (st, info, out) = run_kmdf_ioctl(kfdo, KMDF_IOCTL_ECHO, echo_in, 4);
    check(
        b"kmdf_ioctl_echo",
        st == 0 && info == 4 && &out[..4] == echo_in,
    );

    trace(b"kmdf_query_stop + kmdf_stop (EvtDeviceD0Exit / D3)");
    let _ = dispatch_pnp(kdrv, kfdo, IRP_MN_QUERY_STOP_DEVICE, 0, 0);
    let _ = pnp().transition(kdevnode, DeviceState::QueryStopPending);
    let kstop = dispatch_pnp(kdrv, kfdo, IRP_MN_STOP_DEVICE, 0, 0);
    let _ = pnp().transition(kdevnode, DeviceState::Stopped);
    check(
        b"kmdf_stop_device_quiesces",
        kstop == 0
            && pnp().state(kdevnode) == Some(DeviceState::Stopped)
            && !root_bus().pdo_started(kpdo)
            && KMDF_D0_EXIT.load(Ordering::Relaxed),
    );

    trace(b"kmdf_restart (EvtDeviceD0Entry)");
    KMDF_D0_ENTRY.store(false, Ordering::Relaxed);
    let _ = pnp().transition(kdevnode, DeviceState::StartIrpSent);
    let krestart = dispatch_pnp(kdrv, kfdo, IRP_MN_START_DEVICE, 0, 0);
    if krestart == 0 {
        let _ = pnp().transition(kdevnode, DeviceState::Started);
    }
    check(
        b"kmdf_restart_after_stop_resumes",
        krestart == 0
            && pnp().state(kdevnode) == Some(DeviceState::Started)
            && root_bus().pdo_started(kpdo)
            && KMDF_D0_ENTRY.load(Ordering::Relaxed),
    );

    trace(b"kmdf_surprise_removal + kmdf_remove");
    let ksurprise = dispatch_pnp(kdrv, kfdo, IRP_MN_SURPRISE_REMOVAL, 0, 0);
    let _ = pnp().transition(kdevnode, DeviceState::RemovePending);
    let kremove = dispatch_pnp(kdrv, kfdo, IRP_MN_REMOVE_DEVICE, 0, 0);
    let _ = pnp().transition(kdevnode, DeviceState::Removed);
    check(
        b"kmdf_surprise_removal_then_remove",
        ksurprise == 0
            && kremove == 0
            && pnp().state(kdevnode) == Some(DeviceState::Removed)
            && !root_bus().pdo_started(kpdo),
    );
    CURRENT.store(0, Ordering::Relaxed);

    // --- Report -----------------------------------------------------------------------------
    print_str(b"\n  [pnp-report] ");
    print_str(INSTANCE_PATH.as_bytes());
    print_str(b" (service=");
    print_str(SERVICE_NAME.as_bytes());
    print_str(b")\n");
    print_str(b"    bind: service-DB -> root-bus PDO (QUERY_ID/CAPABILITIES) -> PnP AddDevice -> FDO attach\n");
    print_str(b"    lifecycle: Enumerated -> DriverLoaded -> AddDeviceCalled -> Started -> Removed\n");
    print_str(b"    START_DEVICE delivered raw + translated CM_RESOURCE_LIST; interfaces: none (WDM MMIO)\n");
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);

    print_str(b"[ntos-dhp] PnP Manager: service-DB-driven bind of PnpMmioInterruptTest.sys via root-bus PDO\n");
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
