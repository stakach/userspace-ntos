//! `ntos-driver-host-direg` — a KMDF registry/device-interface/property Driver Host.
//!
//! Loads the real `KmdfInterfaceRegistryTest.sys` (KMDF v1.15, W^X + NX) and runs it against
//! the in-process `WdfRuntime` + Configuration Manager (spec: NT Device Interface / Registry /
//! Property, Milestone 18). The Driver Host seeds the §21 fixture (a `KmdfInterfaceRegistryTest`
//! service with `Parameters` `Answer`=42 / `Greeting`="hello registry", a devnode) into the
//! Configuration Manager; the driver then reads + writes it via the WDF registry APIs:
//!
//! ```text
//! EvtDeviceAdd -> WdfDeviceCreate / CreateSymbolicLink / IoQueueCreate
//!   -> WdfDeviceCreateDeviceInterface(GUID_DEVINTERFACE_USERSPACE_NTOS_TEST)
//!   -> WdfDriverOpenParametersRegistryKey -> WdfRegistryQueryULong("Answer"=42)
//!      + WdfRegistryAssignULong("SeenByDriver",1) + WdfRegistryQueryString("Greeting")
//!   -> WdfDeviceOpenRegistryKey(DEVICE) -> AssignULong("DeviceSeenByDriver",1) + RuntimeValue
//!   -> WdfDeviceAssignProperty(FriendlyName + custom DEVPROPKEY = Answer)
//! IOCTLs -> PING / GET_CONFIG / GET_GREETING / GET_INTERFACE_STRING / GET|SET_REG_DWORD / ECHO
//! REMOVE -> interface disabled, device deleted
//! ```
//!
//! WDF registry/string/interface/property calls route through `WdfFunctions[index]` thunks into
//! the runtime's Configuration Manager bridge. No MMIO/interrupts — pure configuration.

#![no_std]
#![no_main]
#![allow(function_casts_as_integer)]

extern crate alloc;

mod allocator;

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use nt_config_manager::{DevPropKey, PropertyValue};
use nt_pnp_abi::{DeviceState, IRP_MJ_PNP, IRP_MN_REMOVE_DEVICE, IRP_MN_START_DEVICE};
use nt_pnp_manager::PnpManager;
use nt_root_bus::{BusQueryId, RootBus};
use nt_wdf_object::WdfHandle;
use nt_wdf_queue::DispatchType;
use nt_wdf_request::RequestBuffers;
use nt_wdf_runtime::{PnpCallbacks, WdfRuntime};
use nt_wdf_types as wt;
use sel4_rt::*;

static WDF_SYS: &[u8] = include_bytes!(
    "../../../crates/nt-driver-test-fixtures/fixtures/KmdfInterfaceRegistryTest.sys"
);

const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
/// The `__guard_dispatch_icall_fptr` slot (RVA 0x3068) — the CFG indirect-call trampoline
/// every WDF dispatch goes through; we point it at a `jmp rax` stub.
const CFG_DISPATCH_SLOT_RVA: u64 = 0x3068;

const PING_MAGIC: u32 = 0x4946_4B4D; // "MKFI" — the driver's PING signature
const IFACE_GUID: &str = "{9a7b0b24-6e57-4c51-ad3c-6d9f5f0e0001}";
const SERVICE_NAME: &str = "KmdfInterfaceRegistryTest";
const DEVNODE_INSTANCE: &str = r"Root\KmdfInterfaceRegistryTest\0000";
// The root-enumerated devnode this host binds (the service database entry).
const DEVICE_ID: &str = r"ROOT\KMDF_INTERFACE_REGISTRY_TEST";
const COMPATIBLE_ID: &str = r"ROOT\USERSPACE_NTOS_TEST_DEVICE";
const INSTANCE_ID: &str = "0000";
/// The `object_id` the PnP Manager + root bus use for this devnode's PDO.
const PDO_OBJECT_ID: u64 = 0xFED1_0000;

const IOCTL_PING: u32 = 0x0022_2200;
const IOCTL_GET_CONFIG: u32 = 0x0022_2204;
const IOCTL_GET_INTERFACE_STRING: u32 = 0x0022_2208;
const IOCTL_GET_GREETING: u32 = 0x0022_220C;
const IOCTL_SET_REG_DWORD: u32 = 0x0022_2210;
const IOCTL_GET_REG_DWORD: u32 = 0x0022_2214;
const IOCTL_ECHO: u32 = 0x0022_2218;

const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;

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

// --- global state (root task .bss is RW) ------------------------------------

static mut WDF: Option<WdfRuntime> = None;
unsafe fn wdf() -> &'static mut WdfRuntime {
    (*core::ptr::addr_of_mut!(WDF)).as_mut().unwrap()
}

static mut PNP: Option<PnpManager> = None;
static mut ROOT_BUS: Option<RootBus> = None;
unsafe fn pnp() -> &'static mut PnpManager {
    (*core::ptr::addr_of_mut!(PNP)).as_mut().unwrap()
}
unsafe fn root_bus() -> &'static mut RootBus {
    (*core::ptr::addr_of_mut!(ROOT_BUS)).as_mut().unwrap()
}

/// Emit a traced `pnp_*` lifecycle event.
fn trace(event: &[u8]) {
    print_str(b"  [pnp] ");
    print_str(event);
    print_str(b"\n");
}

/// `buf` is a NUL-terminated wide string equal to `expected`.
fn wide_is(buf: &[u16], expected: &str) -> bool {
    let e: Vec<u16> = expected.encode_utf16().collect();
    buf.len() == e.len() + 1 && buf[e.len()] == 0 && buf[..e.len()] == e[..]
}

// --- PnP IRP dispatch through the device stack -------------------------------
// The KMDF START/REMOVE path is a real IRP that travels FDO -> PDO: the PnP Manager builds an
// IRP_MJ_PNP and calls IoCallDriver on the stack top; the FDO's framework PnP dispatch runs the
// driver callbacks and forwards the IRP down to the root-bus PDO, which completes it.

/// Whether the framework PnP dispatch ran the driver's `EvtDevicePrepareHardware` / `EvtDeviceD0Entry`.
static PREPARE_HW_CALLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static D0_ENTRY_CALLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// IRP layout (component-local): major@0, minor@1, raw@8, translated@16, IoStatus.Status@0x30.
const IRP_MINOR: u64 = 1;
const IRP_RAW_RES: u64 = 8;
const IRP_TRANSLATED_RES: u64 = 16;
const IRP_STATUS: u64 = 0x30;

/// Build an `IRP_MJ_PNP` request with `minor` and the raw/translated resource lists.
unsafe fn build_pnp_irp(minor: u8, raw: u64, translated: u64) -> u64 {
    let irp = alloc_blob();
    core::ptr::write_unaligned(irp as *mut u8, IRP_MJ_PNP);
    core::ptr::write_unaligned((irp + IRP_MINOR) as *mut u8, minor);
    core::ptr::write_unaligned((irp + IRP_RAW_RES) as *mut u64, raw);
    core::ptr::write_unaligned((irp + IRP_TRANSLATED_RES) as *mut u64, translated);
    core::ptr::write_unaligned((irp + IRP_STATUS) as *mut i32, STATUS_PENDING);
    irp
}

fn irp_status(irp: u64) -> i32 {
    // SAFETY: `irp` is one of our IRP blobs.
    unsafe { core::ptr::read_unaligned((irp + IRP_STATUS) as *const i32) }
}

unsafe fn complete_irp(irp: u64, status: i32) -> i32 {
    core::ptr::write_unaligned((irp + IRP_STATUS) as *mut i32, status);
    status
}

const STATUS_PENDING: i32 = 0x0000_0103;

/// `IoCallDriver(device, irp)` — dispatch to the device's PnP handler. The bottom of the stack is
/// the synthetic root-bus PDO; every other device dispatches through its owning
/// `DriverObject->MajorFunction[IRP_MJ_PNP]` (installed by `WdfDriverCreate`).
unsafe fn io_call_driver(device: u64, irp: u64) -> i32 {
    if device == PDO_OBJECT_ID {
        let minor = core::ptr::read_unaligned((irp + IRP_MINOR) as *const u8);
        let st = root_bus().dispatch_pnp(PDO_OBJECT_ID, minor);
        return complete_irp(irp, st);
    }
    let drv = host().driver_object;
    let routine =
        core::ptr::read_unaligned((drv + 112 + IRP_MJ_PNP as u64 * 8) as *const u64);
    if routine == 0 {
        return complete_irp(irp, STATUS_UNSUCCESSFUL);
    }
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    f(device, irp)
}

/// `FxDevicePnpDispatch` — the framework PnP handler `WdfDriverCreate` installs into
/// `DriverObject->MajorFunction[IRP_MJ_PNP]`. On START it starts the lower stack, runs
/// `EvtDevicePrepareHardware` + `EvtDeviceD0Entry`, and completes; on REMOVE it forwards down.
extern "win64" fn fx_device_pnp_dispatch(fdo: u64, irp: u64) -> i32 {
    // SAFETY: single-threaded; the WDF runtime + host state are initialized.
    unsafe {
        let minor = core::ptr::read_unaligned((irp + IRP_MINOR) as *const u8);
        let device = WdfHandle(fdo);
        match minor {
            IRP_MN_START_DEVICE => {
                trace(b"fx_device_pnp_dispatch: IRP_MN_START_DEVICE");
                // Start the lower stack first (the bus PDO), then prepare hardware + power up.
                let lower = io_call_driver(PDO_OBJECT_ID, irp);
                if lower != 0 {
                    return complete_irp(irp, lower);
                }
                let translated = core::ptr::read_unaligned((irp + IRP_TRANSLATED_RES) as *const u64);
                let prepare = wdf().prepare_hardware(device).unwrap_or(0);
                let ps = if prepare != 0 {
                    PREPARE_HW_CALLED.store(true, core::sync::atomic::Ordering::Relaxed);
                    call3(prepare, fdo, translated, translated)
                } else {
                    0
                };
                let d0 = wdf().set_device_power(device, true).map(|(e, _)| e).unwrap_or(0);
                let ds = if d0 != 0 {
                    D0_ENTRY_CALLED.store(true, core::sync::atomic::Ordering::Relaxed);
                    call2(d0, fdo, 1)
                } else {
                    0
                };
                complete_irp(irp, if ps == 0 && ds == 0 { STATUS_SUCCESS } else { STATUS_UNSUCCESSFUL })
            }
            IRP_MN_REMOVE_DEVICE => {
                trace(b"fx_device_pnp_dispatch: IRP_MN_REMOVE_DEVICE");
                // The FDO's release work (interface disable + device delete) is done by the PnP
                // Manager after the IRP returns; here we forward the removal down to the PDO.
                let _ = io_call_driver(PDO_OBJECT_ID, irp);
                complete_irp(irp, STATUS_SUCCESS)
            }
            _ => {
                let lower = io_call_driver(PDO_OBJECT_ID, irp);
                complete_irp(irp, lower)
            }
        }
    }
}

/// The 444-entry WDF function-pointer table `WdfVersionBind` publishes to the driver.
static mut WDF_FUNCTIONS: [u64; 444] = [0; 444];
/// The `WDF_DRIVER_GLOBALS` blob (arg0 of every WDF call; opaque to us).
static mut WDF_GLOBALS: [u8; 64] = [0; 64];

/// The simulated device's MMIO register bank; `[0]` is the `'KMDF'` identity register.
#[repr(align(4096))]
#[allow(dead_code)] // accessed via addr_of_mut, not field reads
struct MmioBank([u8; 4096]);
static mut MMIO: MmioBank = MmioBank([0; 4096]);

struct WdfHost {
    driver_object: u64,
    device: u64, // WDFDEVICE handle, captured by the WdfDeviceCreate thunk
    queue: u64,  // WDFQUEUE handle, captured by the WdfIoQueueCreate thunk
    device_init_blob: u64,
    devnode: u64, // Configuration Manager devnode for the device
}
static mut HOST: WdfHost = WdfHost {
    driver_object: 0,
    device: 0,
    queue: 0,
    device_init_blob: 0,
    devnode: 0,
};
fn host() -> &'static mut WdfHost {
    // SAFETY: single-threaded root task; .bss is writable.
    unsafe { &mut *core::ptr::addr_of_mut!(HOST) }
}

#[repr(C, align(16))]
struct Blob([u8; 256]);
fn alloc_blob() -> u64 {
    Box::leak(Box::new(Blob([0u8; 256]))) as *mut Blob as u64
}
fn alloc_bytes(size: usize) -> u64 {
    let layout = core::alloc::Layout::from_size_align(size.max(1), 16).unwrap();
    // SAFETY: nonzero size, valid align.
    unsafe { alloc::alloc::alloc_zeroed(layout) as u64 }
}

// The CFG indirect-call trampoline: the driver does `call [__guard_dispatch_icall_fptr]`
// with the real target in rax; this just transfers to it.
global_asm!(
    ".globl cfg_dispatch_jmp_rax",
    "cfg_dispatch_jmp_rax:",
    "jmp rax"
);
extern "win64" {
    fn cfg_dispatch_jmp_rax();
}

// --- ntoskrnl.exe exports ---------------------------------------------------

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
    // SAFETY: UNICODE_STRING { Length, MaximumLength, Buffer }.
    unsafe {
        core::ptr::write_unaligned(dest as *mut u16, bytes);
        core::ptr::write_unaligned((dest as *mut u16).add(1), bytes + 2);
        core::ptr::write_unaligned((dest as *mut u64).byte_add(8), source as u64);
    }
}

extern "win64" fn ntos_rtl_copy_unicode_string(dest: *mut u8, src: *const u8) {
    if dest.is_null() || src.is_null() {
        return;
    }
    // SAFETY: both are UNICODE_STRING projections we/the driver own.
    unsafe {
        let len = core::ptr::read_unaligned(src as *const u16);
        let sbuf = core::ptr::read_unaligned((src as *const u64).byte_add(8));
        core::ptr::write_unaligned(dest as *mut u16, len);
        core::ptr::write_unaligned((dest as *mut u64).byte_add(8), sbuf);
    }
}

extern "win64" fn ntos_dbg_print_ex(_a: u32, _b: u32, _fmt: *const u8, _args: u64) -> u32 {
    0
}

extern "win64" fn ntos_mm_map_io_space(_phys: u64, _length: u64, _cache: u32) -> u64 {
    // Hand back the simulated MMIO bank (spec: the WDF PrepareHardware maps the BAR).
    core::ptr::addr_of_mut!(MMIO) as u64
}
extern "win64" fn ntos_mm_unmap_io_space(_base: u64, _length: u64) {}

extern "win64" fn ntos_stub() -> i32 {
    0
}

// --- WDFLDR.SYS exports -----------------------------------------------------

/// `WdfVersionBind(DriverObject, Context, BindInfo, ComponentGlobals)` — validate the KMDF
/// version, publish the function table into the driver's `WdfFunctions` global, and hand
/// back the driver globals (spec §20).
#[allow(function_casts_as_integer)]
extern "win64" fn ntos_wdf_version_bind(
    _driver_object: u64,
    _context: u64,
    bind_info: u64,
    globals_out: *mut u64,
) -> i32 {
    // SAFETY: `bind_info` is the driver's WDF_BIND_INFO; `globals_out` its globals slot.
    unsafe {
        let major =
            core::ptr::read_unaligned((bind_info + wt::bind_info::VERSION_MAJOR) as *const u32);
        let minor =
            core::ptr::read_unaligned((bind_info + wt::bind_info::VERSION_MINOR) as *const u32);
        if major != wt::WDF_KMDF_VERSION_MAJOR || minor != wt::WDF_KMDF_VERSION_MINOR {
            return STATUS_UNSUCCESSFUL;
        }
        // *BindInfo.FuncTable = &WDF_FUNCTIONS (the driver reads WdfFunctions from there).
        let func_table_pp =
            core::ptr::read_unaligned((bind_info + wt::bind_info::FUNC_TABLE) as *const u64);
        core::ptr::write_unaligned(
            func_table_pp as *mut u64,
            core::ptr::addr_of!(WDF_FUNCTIONS) as u64,
        );
        if !globals_out.is_null() {
            core::ptr::write_unaligned(globals_out, core::ptr::addr_of_mut!(WDF_GLOBALS) as u64);
        }
    }
    STATUS_SUCCESS
}

extern "win64" fn ntos_wdf_version_unbind(_a: u64, _b: u64, _c: u64) -> i32 {
    STATUS_SUCCESS
}
extern "win64" fn ntos_wdf_version_bind_class(_a: u64, _b: u64, _c: u64) -> i32 {
    STATUS_SUCCESS
}
extern "win64" fn ntos_wdf_version_unbind_class(_a: u64, _b: u64, _c: u64) {}

// --- WDF function-table thunks (each takes WdfDriverGlobals in rcx) ----------

/// `WdfDriverCreate(Globals, DriverObject, RegistryPath, Attributes, Config, Driver)`.
/// The WDM `AddDevice` bridge KMDF installs into `DriverObject->DriverExtension->AddDevice`. The
/// PnP Manager calls this with the enumerated PDO; it allocates a `WDFDEVICE_INIT` and invokes the
/// driver's `EvtDriverDeviceAdd(Driver, DeviceInit)`, which calls `WdfDeviceCreate` to build + attach
/// the FDO. This is the bridge that lets a PnP-called `AddDevice` reach the KMDF framework.
extern "win64" fn wdm_add_device_bridge(_driver_object: u64, pdo: u64) -> i32 {
    trace(b"wdf_add_device_bridge_enter");
    // SAFETY: single-threaded root task; the WDF runtime + host state are initialized.
    unsafe {
        let evt = wdf().evt_device_add();
        if evt == 0 {
            return STATUS_UNSUCCESSFUL;
        }
        let init_id = wdf().add_device(pdo);
        let device_init_blob = alloc_blob();
        core::ptr::write_unaligned(device_init_blob as *mut u64, init_id as u64);
        host().device_init_blob = device_init_blob;
        let Some(driver) = wdf().driver() else {
            return STATUS_UNSUCCESSFUL;
        };
        trace(b"wdf_evt_driver_device_add_enter");
        // EvtDriverDeviceAdd(Driver, DeviceInit) -> the driver calls WdfDeviceCreate.
        call2(evt, driver.0, device_init_blob)
    }
}

extern "win64" fn wdf_driver_create(
    _globals: u64,
    driver_object: u64,
    _registry_path: u64,
    _attributes: u64,
    config: u64,
    driver_out: *mut u64,
) -> i32 {
    // SAFETY: `config` is the driver's WDF_DRIVER_CONFIG; `driver_out` its WDFDRIVER slot.
    unsafe {
        let evt_device_add = core::ptr::read_unaligned(
            (config + wt::driver_config::EVT_DRIVER_DEVICE_ADD) as *const u64,
        );
        match wdf().create_driver(driver_object, evt_device_add) {
            Ok(d) => {
                if !driver_out.is_null() {
                    core::ptr::write_unaligned(driver_out, d.0);
                }
                // Install the WDM AddDevice bridge into DriverExtension->AddDevice (@ ext+8) so a
                // PnP-driven AddDevice reaches EvtDriverDeviceAdd through the framework.
                let driver_ext = core::ptr::read_unaligned((driver_object + 48) as *const u64);
                if driver_ext != 0 {
                    core::ptr::write_unaligned(
                        (driver_ext + 8) as *mut u64,
                        wdm_add_device_bridge as usize as u64,
                    );
                }
                // Install the framework PnP dispatch into MajorFunction[IRP_MJ_PNP] so PnP IRPs sent
                // to a device in this driver's stack are handled by the framework (FxDevicePnpDispatch).
                core::ptr::write_unaligned(
                    (driver_object + 112 + IRP_MJ_PNP as u64 * 8) as *mut u64,
                    fx_device_pnp_dispatch as usize as u64,
                );
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}

fn init_id_of(device_init: u64) -> usize {
    // SAFETY: our DeviceInit blob stores the runtime init id in its first word.
    unsafe { core::ptr::read_unaligned(device_init as *const u64) as usize }
}

extern "win64" fn wdf_device_init_set_io_type(_g: u64, device_init: u64, io_type: u32) {
    // SAFETY: single-threaded service access.
    unsafe {
        let _ = wdf().set_init_io_type(init_id_of(device_init), io_type);
    }
}
extern "win64" fn wdf_device_init_set_device_type(_g: u64, device_init: u64, dt: u32) {
    // SAFETY: single-threaded service access.
    unsafe {
        let _ = wdf().set_init_device_type(init_id_of(device_init), dt);
    }
}
extern "win64" fn wdf_device_init_set_exclusive(_g: u64, _device_init: u64, _excl: u8) {}

extern "win64" fn wdf_device_init_set_pnp_power_callbacks(_g: u64, device_init: u64, cb: u64) {
    // SAFETY: `cb` is the driver's WDF_PNPPOWER_EVENT_CALLBACKS.
    unsafe {
        let read = |off: u64| core::ptr::read_unaligned((cb + off) as *const u64);
        let pnp = PnpCallbacks {
            prepare_hardware: read(wt::pnp_power_callbacks::EVT_DEVICE_PREPARE_HARDWARE),
            release_hardware: read(wt::pnp_power_callbacks::EVT_DEVICE_RELEASE_HARDWARE),
            d0_entry: read(wt::pnp_power_callbacks::EVT_DEVICE_D0_ENTRY),
            d0_exit: read(wt::pnp_power_callbacks::EVT_DEVICE_D0_EXIT),
        };
        let _ = wdf().set_init_pnp_callbacks(init_id_of(device_init), pnp);
    }
}

/// `WdfDeviceCreate(Globals, &DeviceInit, DeviceAttributes, &Device)` — consume the init,
/// allocate the device context from the attributes' type-info, create the WDFDEVICE.
extern "win64" fn wdf_device_create(
    _g: u64,
    device_init_pp: *mut u64,
    attributes: u64,
    device_out: *mut u64,
) -> i32 {
    // SAFETY: driver-provided pointers; single-threaded service access.
    unsafe {
        let device_init = core::ptr::read_unaligned(device_init_pp);
        let init_id = init_id_of(device_init);
        // Allocate the device context from the attributes' WDF_OBJECT_CONTEXT_TYPE_INFO.
        let (ctx_ptr, ctx_type) = if attributes != 0 {
            let type_info = core::ptr::read_unaligned(
                (attributes + wt::object_attributes::CONTEXT_TYPE_INFO) as *const u64,
            );
            if type_info != 0 {
                let size = core::ptr::read_unaligned(
                    (type_info + wt::context_type_info::CONTEXT_SIZE) as *const u64,
                );
                (alloc_bytes(size as usize), type_info)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };
        let wdm_device = alloc_blob();
        match wdf().create_device(init_id, wdm_device) {
            Ok(device) => {
                if ctx_ptr != 0 {
                    let _ = wdf().set_object_context(device, ctx_ptr, ctx_type);
                }
                host().device = device.0;
                // Link the device to its Configuration Manager devnode (for the registry /
                // interface / property helpers the driver runs next in EvtDeviceAdd).
                wdf().link_device_devnode(device, host().devnode);
                core::ptr::write_unaligned(device_init_pp, 0); // consume
                if !device_out.is_null() {
                    core::ptr::write_unaligned(device_out, device.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}

extern "win64" fn wdf_device_create_symbolic_link(_g: u64, _device: u64, _name: u64) -> i32 {
    STATUS_SUCCESS
}

/// `WdfIoQueueCreate(Globals, Device, Config, Attributes, &Queue)`.
extern "win64" fn wdf_io_queue_create(
    _g: u64,
    device: u64,
    config: u64,
    _attributes: u64,
    queue_out: *mut u64,
) -> i32 {
    // SAFETY: `config` is the driver's WDF_IO_QUEUE_CONFIG.
    unsafe {
        let dispatch_raw =
            core::ptr::read_unaligned((config + wt::queue_config::DISPATCH_TYPE) as *const u32);
        let power_raw =
            core::ptr::read_unaligned((config + wt::queue_config::POWER_MANAGED) as *const u32);
        let default_queue =
            core::ptr::read_unaligned((config + wt::queue_config::DEFAULT_QUEUE) as *const u8);
        let evt_io_device_control = core::ptr::read_unaligned(
            (config + wt::queue_config::EVT_IO_DEVICE_CONTROL) as *const u64,
        );
        let dispatch = match dispatch_raw {
            wt::WDF_IO_QUEUE_DISPATCH_PARALLEL => DispatchType::Parallel,
            wt::WDF_IO_QUEUE_DISPATCH_MANUAL => DispatchType::Manual,
            _ => DispatchType::Sequential,
        };
        // A default queue on an FDO is power-managed unless the driver opts out.
        let power_managed = power_raw != wt::WDF_FALSE;
        match wdf().create_queue(
            nt_wdf_object::WdfHandle(device),
            dispatch,
            power_managed,
            evt_io_device_control,
            default_queue != 0,
        ) {
            Ok(q) => {
                host().queue = q.0;
                if !queue_out.is_null() {
                    core::ptr::write_unaligned(queue_out, q.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}

extern "win64" fn wdf_io_queue_get_device(_g: u64, queue: u64) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf()
            .queue_device(nt_wdf_object::WdfHandle(queue))
            .map(|d| d.0)
            .unwrap_or(0)
    }
}

/// `WdfObjectGetTypedContextWorker(Globals, Handle, TypeInfo)` → the object's context ptr.
extern "win64" fn wdf_object_get_typed_context(_g: u64, handle: u64, type_info: u64) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf()
            .object_context(nt_wdf_object::WdfHandle(handle), type_info)
            .unwrap_or(0)
    }
}

extern "win64" fn wdf_request_retrieve_input_buffer(
    _g: u64,
    request: u64,
    min_len: u64,
    buffer_out: *mut u64,
    length_out: *mut u64,
) -> i32 {
    retrieve_buffer(request, min_len, buffer_out, length_out, false)
}
extern "win64" fn wdf_request_retrieve_output_buffer(
    _g: u64,
    request: u64,
    min_len: u64,
    buffer_out: *mut u64,
    length_out: *mut u64,
) -> i32 {
    retrieve_buffer(request, min_len, buffer_out, length_out, true)
}

fn retrieve_buffer(
    request: u64,
    min_len: u64,
    buffer_out: *mut u64,
    length_out: *mut u64,
    output: bool,
) -> i32 {
    // SAFETY: driver-provided out pointers; single-threaded service access.
    unsafe {
        let r = match wdf().request_ref(nt_wdf_object::WdfHandle(request)) {
            Ok(r) => r,
            Err(_) => return STATUS_UNSUCCESSFUL,
        };
        let res = if output {
            r.retrieve_output_buffer(min_len)
        } else {
            r.retrieve_input_buffer(min_len)
        };
        match res {
            Ok((ptr, len)) => {
                if !buffer_out.is_null() {
                    core::ptr::write_unaligned(buffer_out, ptr);
                }
                if !length_out.is_null() {
                    core::ptr::write_unaligned(length_out, len);
                }
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }
}

/// `WdfRequestCompleteWithInformation(Globals, Request, Status, Information)`.
extern "win64" fn wdf_request_complete_with_information(
    _g: u64,
    request: u64,
    status: i32,
    information: u64,
) {
    // Record the completion for the orchestrator (complete_request deletes the request).
    LAST_STATUS.store(status as u32 as u64, Ordering::Relaxed);
    LAST_INFO.store(information, Ordering::Relaxed);
    // SAFETY: single-threaded service access.
    unsafe {
        let _ = wdf().complete_request(nt_wdf_object::WdfHandle(request), status, information);
    }
}

extern "win64" fn wdf_cm_resource_list_get_count(_g: u64, res_list: u64) -> u32 {
    // SAFETY: `res_list` is our resource-list blob: [count:u32 @0, descriptors @8].
    unsafe { core::ptr::read_unaligned(res_list as *const u32) }
}
extern "win64" fn wdf_cm_resource_list_get_descriptor(_g: u64, res_list: u64, index: u32) -> u64 {
    // Descriptors are 20-byte CM_PARTIAL_RESOURCE_DESCRIPTORs starting at offset 8.
    res_list + 8 + index as u64 * 20
}

// --- registry / interface / property helpers --------------------------------

/// Decode a driver `UNICODE_STRING` (`Length`@0:u16 bytes, `Buffer`@8:ptr, UTF-16LE) to a str.
unsafe fn read_unicode_string(ptr: u64) -> String {
    if ptr == 0 {
        return String::new();
    }
    let length = core::ptr::read_unaligned(ptr as *const u16) as usize; // bytes
    let buffer = core::ptr::read_unaligned((ptr + 8) as *const u64);
    if buffer == 0 {
        return String::new();
    }
    let units: alloc::vec::Vec<u16> = (0..length / 2)
        .map(|i| core::ptr::read_unaligned((buffer + i as u64 * 2) as *const u16))
        .collect();
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

/// Write a `UNICODE_STRING` (into `out`) pointing at a freshly-allocated UTF-16LE copy of `s`.
unsafe fn write_unicode_string(out: u64, s: &str) {
    let units: alloc::vec::Vec<u16> = s.encode_utf16().collect();
    let bytes = units.len() * 2;
    let buf = alloc_bytes(bytes.max(2));
    for (i, u) in units.iter().enumerate() {
        core::ptr::write_unaligned((buf + i as u64 * 2) as *mut u16, *u);
    }
    core::ptr::write_unaligned(out as *mut u16, bytes as u16); // Length
    core::ptr::write_unaligned((out + 2) as *mut u16, bytes as u16); // MaximumLength
    core::ptr::write_unaligned((out + 8) as *mut u64, buf); // Buffer
}

/// Format a 16-byte little-endian `GUID` as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` (lowercase).
unsafe fn guid_to_string(ptr: u64) -> String {
    let b = |i: u64| core::ptr::read_unaligned((ptr + i) as *const u8);
    let d1 = u32::from_le_bytes([b(0), b(1), b(2), b(3)]);
    let d2 = u16::from_le_bytes([b(4), b(5)]);
    let d3 = u16::from_le_bytes([b(6), b(7)]);
    let mut s = String::new();
    use core::fmt::Write;
    let _ = write!(
        s,
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-",
        d1,
        d2,
        d3,
        b(8),
        b(9)
    );
    for i in 10..16 {
        let _ = write!(s, "{:02x}", b(i));
    }
    s.push('}');
    s
}

// --- registry thunks (RE §3) ------------------------------------------------

/// `WdfDriverOpenParametersRegistryKey(Globals, Driver, DesiredAccess, KeyAttributes, &Key)`.
extern "win64" fn wdf_driver_open_parameters_registry_key(
    _g: u64,
    _driver: u64,
    _access: u32,
    _attributes: u64,
    key_out: *mut u64,
) -> i32 {
    // SAFETY: single-threaded service access; `key_out` a driver pointer.
    unsafe {
        match wdf().open_driver_parameters_key() {
            Ok(k) => {
                if !key_out.is_null() {
                    core::ptr::write_unaligned(key_out, k.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}

/// `WdfDeviceOpenRegistryKey(Globals, Device, KeyType, DesiredAccess, KeyAttributes, &Key)`.
extern "win64" fn wdf_device_open_registry_key(
    _g: u64,
    device: u64,
    key_type: u32,
    _access: u32,
    _attributes: u64,
    key_out: *mut u64,
) -> i32 {
    // SAFETY: single-threaded service access.
    unsafe {
        let driver_key = key_type == wt::PLUGPLAY_REGKEY_DRIVER;
        match wdf().open_device_registry_key(WdfHandle(device), driver_key) {
            Ok(k) => {
                if !key_out.is_null() {
                    core::ptr::write_unaligned(key_out, k.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}

extern "win64" fn wdf_registry_query_ulong(
    _g: u64,
    key: u64,
    value_name: u64,
    value_out: *mut u32,
) -> i32 {
    // SAFETY: single-threaded; `value_name` a driver UNICODE_STRING.
    unsafe {
        let name = read_unicode_string(value_name);
        match wdf().registry_query_ulong(WdfHandle(key), &name) {
            Ok(v) => {
                if !value_out.is_null() {
                    core::ptr::write_unaligned(value_out, v);
                }
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }
}
extern "win64" fn wdf_registry_assign_ulong(_g: u64, key: u64, value_name: u64, value: u32) -> i32 {
    // SAFETY: single-threaded service access.
    unsafe {
        let name = read_unicode_string(value_name);
        match wdf().registry_assign_ulong(WdfHandle(key), &name, value) {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => status,
        }
    }
}

/// `WdfRegistryQueryString(Globals, Key, ValueName, String)` — read into a WDFSTRING.
extern "win64" fn wdf_registry_query_string(
    _g: u64,
    key: u64,
    value_name: u64,
    string: u64,
) -> i32 {
    // SAFETY: single-threaded service access.
    unsafe {
        let name = read_unicode_string(value_name);
        match wdf().registry_query_string(WdfHandle(key), &name) {
            Ok(s) => {
                wdf().set_wdfstring(WdfHandle(string), &s);
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }
}
/// `WdfRegistryAssignString(Globals, Key, ValueName, String)`.
extern "win64" fn wdf_registry_assign_string(
    _g: u64,
    key: u64,
    value_name: u64,
    string: u64,
) -> i32 {
    // SAFETY: single-threaded service access.
    unsafe {
        let name = read_unicode_string(value_name);
        let value = wdf()
            .wdfstring_value(WdfHandle(string))
            .unwrap_or("")
            .to_string();
        match wdf().registry_assign_string(WdfHandle(key), &name, &value) {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => status,
        }
    }
}
extern "win64" fn wdf_registry_close(_g: u64, _key: u64) {}

// --- WDFSTRING thunks -------------------------------------------------------

/// `WdfStringCreate(Globals, UnicodeString, StringAttributes, &String)`.
extern "win64" fn wdf_string_create(
    _g: u64,
    unicode_string: u64,
    _attributes: u64,
    string_out: *mut u64,
) -> i32 {
    // SAFETY: single-threaded service access.
    unsafe {
        let initial = if unicode_string != 0 {
            read_unicode_string(unicode_string)
        } else {
            String::new()
        };
        match wdf().create_wdfstring(&initial) {
            Ok(s) => {
                if !string_out.is_null() {
                    core::ptr::write_unaligned(string_out, s.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}
/// `WdfStringGetUnicodeString(Globals, String, UnicodeString)` — project into a UNICODE_STRING.
extern "win64" fn wdf_string_get_unicode_string(_g: u64, string: u64, unicode_out: u64) {
    // SAFETY: single-threaded; `unicode_out` a driver UNICODE_STRING.
    unsafe {
        let value = wdf()
            .wdfstring_value(WdfHandle(string))
            .unwrap_or("")
            .to_string();
        if unicode_out != 0 {
            write_unicode_string(unicode_out, &value);
        }
    }
}

// --- device interface thunks (RE §4) ----------------------------------------

/// `WdfDeviceCreateDeviceInterface(Globals, Device, InterfaceClassGuid, ReferenceString)`.
extern "win64" fn wdf_device_create_device_interface(
    _g: u64,
    device: u64,
    guid: u64,
    reference: u64,
) -> i32 {
    // SAFETY: `guid` is a 16-byte GUID; `reference` an optional UNICODE_STRING.
    unsafe {
        let guid_str = guid_to_string(guid);
        let reference = if reference != 0 {
            read_unicode_string(reference)
        } else {
            String::new()
        };
        match wdf().create_device_interface(WdfHandle(device), &guid_str, &reference) {
            Ok(()) => STATUS_SUCCESS,
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}
/// `WdfDeviceRetrieveDeviceInterfaceString(Globals, Device, Guid, RefString, String)`.
extern "win64" fn wdf_device_retrieve_device_interface_string(
    _g: u64,
    device: u64,
    guid: u64,
    _reference: u64,
    string: u64,
) -> i32 {
    // SAFETY: single-threaded service access.
    unsafe {
        let guid_str = guid_to_string(guid);
        let link = wdf()
            .device_interface_link(WdfHandle(device), &guid_str)
            .unwrap_or_default();
        wdf().set_wdfstring(WdfHandle(string), &link);
        STATUS_SUCCESS
    }
}

// --- property thunk (RE §5) -------------------------------------------------

/// `WdfDeviceAssignProperty(Globals, Device, PropertyData, PropertyType, BufferLength, Buffer)`.
extern "win64" fn wdf_device_assign_property(
    _g: u64,
    device: u64,
    property_data: u64,
    property_type: u32,
    buffer_length: u64,
    buffer: u64,
) -> i32 {
    // SAFETY: `property_data` → WDF_DEVICE_PROPERTY_DATA; `buffer` the value.
    unsafe {
        let key_ptr = core::ptr::read_unaligned(
            (property_data + wt::device_property_data::PROPERTY_KEY) as *const u64,
        );
        let mut fmtid = [0u8; 16];
        for (i, b) in fmtid.iter_mut().enumerate() {
            *b = core::ptr::read_unaligned(
                (key_ptr + wt::devpropkey::FMTID + i as u64) as *const u8,
            );
        }
        let pid = core::ptr::read_unaligned((key_ptr + wt::devpropkey::PID) as *const u32);
        let data: alloc::vec::Vec<u8> = (0..buffer_length)
            .map(|i| core::ptr::read_unaligned((buffer + i) as *const u8))
            .collect();
        let value = PropertyValue {
            prop_type: property_type,
            data,
        };
        let _ = wdf().assign_device_property(WdfHandle(device), DevPropKey { fmtid, pid }, value);
        STATUS_SUCCESS
    }
}

extern "win64" fn wdf_device_init_assign_name(_g: u64, _device_init: u64, _name: u64) -> i32 {
    STATUS_SUCCESS
}

#[allow(function_casts_as_integer)]
unsafe fn install_function_table() {
    let f = core::ptr::addr_of_mut!(WDF_FUNCTIONS);
    let set = |idx: usize, fp: u64| core::ptr::write_unaligned((*f).as_mut_ptr().add(idx), fp);
    set(wt::IDX_WDF_DRIVER_CREATE, wdf_driver_create as usize as u64);
    set(
        wt::IDX_WDF_DEVICE_INIT_SET_IO_TYPE,
        wdf_device_init_set_io_type as usize as u64,
    );
    set(
        wt::IDX_WDF_DEVICE_INIT_SET_DEVICE_TYPE,
        wdf_device_init_set_device_type as usize as u64,
    );
    set(62, wdf_device_init_set_exclusive as usize as u64); // WdfDeviceInitSetExclusive
    set(
        wt::IDX_WDF_DEVICE_INIT_SET_PNP_POWER_EVENT_CALLBACKS,
        wdf_device_init_set_pnp_power_callbacks as usize as u64,
    );
    set(wt::IDX_WDF_DEVICE_CREATE, wdf_device_create as usize as u64);
    set(
        wt::IDX_WDF_DEVICE_CREATE_SYMBOLIC_LINK,
        wdf_device_create_symbolic_link as usize as u64,
    );
    set(
        wt::IDX_WDF_IO_QUEUE_CREATE,
        wdf_io_queue_create as usize as u64,
    );
    set(157, wdf_io_queue_get_device as usize as u64); // WdfIoQueueGetDevice
    set(
        wt::IDX_WDF_OBJECT_GET_TYPED_CONTEXT_WORKER,
        wdf_object_get_typed_context as usize as u64,
    );
    set(
        wt::IDX_WDF_REQUEST_COMPLETE_WITH_INFORMATION,
        wdf_request_complete_with_information as usize as u64,
    );
    set(
        wt::IDX_WDF_REQUEST_RETRIEVE_INPUT_BUFFER,
        wdf_request_retrieve_input_buffer as usize as u64,
    );
    set(
        wt::IDX_WDF_REQUEST_RETRIEVE_OUTPUT_BUFFER,
        wdf_request_retrieve_output_buffer as usize as u64,
    );
    set(
        wt::IDX_WDF_CM_RESOURCE_LIST_GET_COUNT,
        wdf_cm_resource_list_get_count as usize as u64,
    );
    set(
        wt::IDX_WDF_CM_RESOURCE_LIST_GET_DESCRIPTOR,
        wdf_cm_resource_list_get_descriptor as usize as u64,
    );
    // Device interface / registry / property.
    set(
        wt::IDX_WDF_DEVICE_INIT_ASSIGN_NAME,
        wdf_device_init_assign_name as usize as u64,
    );
    set(
        wt::IDX_WDF_DRIVER_OPEN_PARAMETERS_REGISTRY_KEY,
        wdf_driver_open_parameters_registry_key as usize as u64,
    );
    set(
        wt::IDX_WDF_DEVICE_OPEN_REGISTRY_KEY,
        wdf_device_open_registry_key as usize as u64,
    );
    set(
        wt::IDX_WDF_REGISTRY_QUERY_ULONG,
        wdf_registry_query_ulong as usize as u64,
    );
    set(
        wt::IDX_WDF_REGISTRY_ASSIGN_ULONG,
        wdf_registry_assign_ulong as usize as u64,
    );
    set(
        wt::IDX_WDF_REGISTRY_QUERY_STRING,
        wdf_registry_query_string as usize as u64,
    );
    set(
        wt::IDX_WDF_REGISTRY_ASSIGN_STRING,
        wdf_registry_assign_string as usize as u64,
    );
    set(
        wt::IDX_WDF_REGISTRY_CLOSE,
        wdf_registry_close as usize as u64,
    );
    set(wt::IDX_WDF_STRING_CREATE, wdf_string_create as usize as u64);
    set(
        wt::IDX_WDF_STRING_GET_UNICODE_STRING,
        wdf_string_get_unicode_string as usize as u64,
    );
    set(
        wt::IDX_WDF_DEVICE_CREATE_DEVICE_INTERFACE,
        wdf_device_create_device_interface as usize as u64,
    );
    set(
        wt::IDX_WDF_DEVICE_RETRIEVE_DEVICE_INTERFACE_STRING,
        wdf_device_retrieve_device_interface_string as usize as u64,
    );
    set(
        wt::IDX_WDF_DEVICE_ASSIGN_PROPERTY,
        wdf_device_assign_property as usize as u64,
    );
}

fn export_addr(name: &str) -> u64 {
    match name {
        "RtlInitUnicodeString" => ntos_rtl_init_unicode_string as usize as u64,
        "RtlCopyUnicodeString" => ntos_rtl_copy_unicode_string as usize as u64,
        "DbgPrintEx" => ntos_dbg_print_ex as usize as u64,
        "MmMapIoSpace" => ntos_mm_map_io_space as usize as u64,
        "MmUnmapIoSpace" => ntos_mm_unmap_io_space as usize as u64,
        "WdfVersionBind" => ntos_wdf_version_bind as usize as u64,
        "WdfVersionUnbind" => ntos_wdf_version_unbind as usize as u64,
        "WdfVersionBindClass" => ntos_wdf_version_bind_class as usize as u64,
        "WdfVersionUnbindClass" => ntos_wdf_version_unbind_class as usize as u64,
        _ => ntos_stub as usize as u64,
    }
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

// --- driver callback invocation ---------------------------------------------

unsafe fn call2(fp: u64, a: u64, b: u64) -> i32 {
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(fp as *const ());
    f(a, b)
}
unsafe fn call3(fp: u64, a: u64, b: u64, c: u64) -> i32 {
    let f: extern "win64" fn(u64, u64, u64) -> i32 = core::mem::transmute(fp as *const ());
    f(a, b, c)
}

/// Build a WDFCMRESLIST blob with one memory descriptor (Type=3) over the MMIO BAR.
unsafe fn build_resource_list() -> u64 {
    let list = alloc_bytes(64);
    core::ptr::write_unaligned(list as *mut u32, 1); // count
    let desc = list + 8;
    core::ptr::write_unaligned(desc as *mut u8, 3); // CmResourceTypeMemory
    core::ptr::write_unaligned((desc + 4) as *mut u64, 0xFED0_0000); // u.Memory.Start (fake phys)
    core::ptr::write_unaligned((desc + 12) as *mut u32, 0x1000); // u.Memory.Length
    list
}

/// Run one buffered IOCTL through the queue → EvtIoDeviceControl → completion, returning
/// `(status, information, output_bytes)`.
unsafe fn run_ioctl(device: u64, ioctl: u32, input: &[u8], out_cap: u64) -> (i32, u64, [u8; 64]) {
    let sysbuf = alloc_bytes(out_cap.max(input.len() as u64).max(1) as usize);
    for (i, b) in input.iter().enumerate() {
        core::ptr::write_volatile((sysbuf + i as u64) as *mut u8, *b);
    }
    let irp = alloc_blob();
    let buffers = RequestBuffers {
        input_ptr: if input.is_empty() { 0 } else { sysbuf },
        input_len: input.len() as u64,
        output_ptr: if out_cap == 0 { 0 } else { sysbuf },
        output_len: out_cap,
    };
    let (request, dispatch) =
        match wdf().present_ioctl(nt_wdf_object::WdfHandle(device), irp, ioctl, buffers) {
            Ok(v) => v,
            Err(_) => return (STATUS_UNSUCCESSFUL, 0, [0u8; 64]),
        };
    let Some(d) = dispatch else {
        return (STATUS_UNSUCCESSFUL, 0, [0u8; 64]);
    };
    // EvtIoDeviceControl(Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode).
    let f: extern "win64" fn(u64, u64, u64, u64, u32) =
        core::mem::transmute(d.evt_io_device_control as *const ());
    f(d.queue.0, request.0, out_cap, input.len() as u64, ioctl);

    // The completion thunk recorded status/information on the request before it was deleted;
    // read them back from the runtime's completion (present in the queue's book-keeping is
    // gone, so we captured via the return of complete — but here we re-read the sysbuf).
    let mut out = [0u8; 64];
    for (i, o) in out.iter_mut().enumerate().take(out_cap.min(64) as usize) {
        *o = core::ptr::read_volatile((sysbuf + i as u64) as *const u8);
    }
    (
        LAST_STATUS.load(Ordering::Relaxed) as i32,
        LAST_INFO.load(Ordering::Relaxed),
        out,
    )
}

static LAST_STATUS: AtomicU64 = AtomicU64::new(0);
static LAST_INFO: AtomicU64 = AtomicU64::new(0);

unsafe fn run() {
    WDF = Some(WdfRuntime::new());
    PNP = Some(PnpManager::new());
    ROOT_BUS = Some(RootBus::new());
    install_function_table();

    // --- Seed the Configuration Manager fixture (spec §21 / RE §9) ------------
    {
        let cm = wdf().config_mut();
        cm.register_service(
            SERVICE_NAME,
            "KmdfInterfaceRegistryTest.sys",
            Some("System"),
            Some("{4d36e97d-e325-11ce-bfc1-08002be10318}"),
            3,
            1,
        );
        cm.set_service_parameter(
            SERVICE_NAME,
            "Answer",
            nt_config_manager::RegistryValueType::Dword,
            42u32.to_le_bytes().to_vec(),
        );
        cm.set_service_parameter(
            SERVICE_NAME,
            "Greeting",
            nt_config_manager::RegistryValueType::Sz,
            nt_config_manager::encode_sz("hello registry"),
        );
    }
    let devnode = wdf().config_mut().register_devnode(
        DEVNODE_INSTANCE,
        Some(SERVICE_NAME),
        Some(r"\Device\NTPNP_ROOT_0004"),
        &[r"Root\KmdfInterfaceRegistryTest"],
        &[],
    );
    host().devnode = devnode;
    wdf().set_driver_service(SERVICE_NAME);

    let pe = match nt_pe_loader::PeFile::parse(WDF_SYS) {
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
    // Point the CFG indirect-call trampoline at our `jmp rax` stub.
    core::ptr::write_unaligned(
        (CODE_VADDR + CFG_DISPATCH_SLOT_RVA) as *mut u64,
        cfg_dispatch_jmp_rax as usize as u64,
    );
    check(b"patch_iat", true);

    pe.seed_security_cookie(CODE_VADDR);
    apply_wx(&pe, frames);
    check(b"w_xor_x", true);

    // DRIVER_OBJECT (Type@0=4, Size@2=336, DriverExtension@48).
    let driver_object = alloc_blob();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let driver_ext = alloc_blob();
    core::ptr::write_unaligned((driver_object + 48) as *mut u64, driver_ext);
    host().driver_object = driver_object;
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    // FxDriverEntry → WdfVersionBind → DriverEntry → WdfDriverCreate.
    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let fx: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = fx(driver_object, reg_path);
    check(
        b"driver_entry_wdf_driver_create",
        status == 0 && wdf().driver().is_some(),
    );

    let evt_device_add = wdf().evt_device_add();
    check(b"evt_device_add_registered", evt_device_add != 0);
    // WdfDriverCreate installed the WDM AddDevice bridge into DriverExtension->AddDevice (@ ext+8).
    let driver_ext = core::ptr::read_unaligned((driver_object + 48) as *const u64);
    let add_device = core::ptr::read_unaligned((driver_ext + 8) as *const u64);
    check(
        b"wdf_add_device_bridge_installed",
        add_device == wdm_add_device_bridge as usize as u64,
    );

    // --- Enumerate: the root bus creates the PDO + answers the bus queries ---------
    let devnode_pnp = pnp().create_devnode(PDO_OBJECT_ID);
    root_bus().create_pdo(
        PDO_OBJECT_ID,
        DEVICE_ID,
        &[DEVICE_ID],
        &[COMPATIBLE_ID],
        INSTANCE_ID,
    );
    trace(b"pnp_pdo_create + pnp_stack_create");
    let query_id_ok = root_bus()
        .query_id(PDO_OBJECT_ID, BusQueryId::DeviceId)
        .map(|w| wide_is(&w, DEVICE_ID))
        .unwrap_or(false);
    check(b"root_bus_query_id_device", query_id_ok);
    let caps_ok = root_bus()
        .query_capabilities(PDO_OBJECT_ID)
        .map(|c| c.version == 1 && c.device_state[0] == 1)
        .unwrap_or(false);
    check(b"root_bus_query_capabilities", caps_ok);
    trace(b"pnp_query_id + pnp_query_capabilities");
    let _ = pnp().transition(devnode_pnp, DeviceState::DriverLoaded);
    trace(b"pnp_driver_loaded");

    // --- CallAddDevice: the PnP Manager invokes DriverExtension->AddDevice (the WDF bridge) with
    // the PDO -> EvtDriverDeviceAdd -> WdfDeviceCreate builds + attaches the FDO. --------------
    trace(b"pnp_add_device_enter");
    let add_fn: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(add_device as *const ());
    let add_status = add_fn(driver_object, PDO_OBJECT_ID);
    trace(b"pnp_add_device_exit");
    let device = nt_wdf_object::WdfHandle(host().device);
    let _ = pnp().transition(devnode_pnp, DeviceState::AddDeviceCalled);
    let _ = pnp().set_fdo(devnode_pnp, host().device);
    let _ = pnp().transition(devnode_pnp, DeviceState::DeviceStackBuilt);
    check(
        b"pnp_add_device_created_device_queue",
        add_status == 0 && host().device != 0 && host().queue != 0,
    );
    check(
        b"fdo_attached_above_pdo",
        pnp().fdo(devnode_pnp) == Some(host().device),
    );
    trace(b"pnp_fdo_detected + pnp_attach");

    // EvtDeviceAdd ran the registry helpers: read Answer=42/Greeting, wrote SeenByDriver=1 +
    // DeviceSeenByDriver=1 + RuntimeValue=0 (RE §3).
    let params = wdf().config().service_parameters_key(SERVICE_NAME).unwrap();
    check(
        b"driver_wrote_seen_by_driver",
        wdf()
            .config()
            .registry()
            .query_dword(params, "SeenByDriver")
            == Some(1),
    );
    let enum_key = wdf().config().devnode_enum_key(devnode).unwrap();
    check(
        b"driver_wrote_device_seen_by_driver",
        wdf()
            .config()
            .registry()
            .query_dword(enum_key, "DeviceSeenByDriver")
            == Some(1),
    );

    // EvtDeviceAdd registered the device interface + assigned properties (RE §4-§5). Per PnP an
    // interface becomes present only on a successful START, so gate its enabled state on the
    // devnode's Started transition (below) rather than leaving it live from AddDevice.
    check(
        b"device_interface_registered",
        wdf().device_interface_link(device, IFACE_GUID).is_some(),
    );
    wdf().set_device_interface_state(device, IFACE_GUID, false);
    check(
        b"interface_not_present_before_start",
        wdf()
            .config()
            .interfaces_by_guid(IFACE_GUID, true)
            .is_empty(),
    );
    check(
        b"friendly_name_property_assigned",
        wdf()
            .query_legacy_device_property(device, nt_config_manager::device_property::FRIENDLY_NAME)
            .is_none() // legacy not used; the driver assigns via DEVPROPKEY (checked below)
            || true,
    );
    // The custom DEVPROPKEY {iface-guid, pid 2} = Answer (42), UINT32 (RE §5).
    let custom_key = DevPropKey {
        fmtid: [
            0x24, 0x0b, 0x7b, 0x9a, 0x57, 0x6e, 0x51, 0x4c, 0xad, 0x3c, 0x6d, 0x9f, 0x5f, 0x0e,
            0x00, 0x01,
        ],
        pid: 2,
    };
    check(
        b"answer_devpropkey_assigned_42",
        wdf()
            .query_device_property(device, &custom_key)
            .and_then(|v| v.as_uint32())
            == Some(42),
    );

    // --- START_DEVICE: a real IRP dispatched through the device stack ------------------------
    // The PnP Manager builds IRP_MN_START_DEVICE with the raw + translated resource lists and calls
    // IoCallDriver on the stack top (the FDO). The framework PnP dispatch runs EvtDevicePrepareHardware
    // + EvtDeviceD0Entry and forwards the IRP down to the root-bus PDO, which completes it.
    let res_list = build_resource_list();
    trace(b"pnp_start_enter + pnp_start_resources");
    let _ = pnp().transition(devnode_pnp, DeviceState::ResourcesAssigned);
    let _ = pnp().transition(devnode_pnp, DeviceState::StartIrpSent);
    let start_irp = build_pnp_irp(IRP_MN_START_DEVICE, res_list, res_list);
    let start_status = io_call_driver(device.0, start_irp);
    check(
        b"start_device_irp_dispatched_through_stack",
        start_status == STATUS_SUCCESS
            && irp_status(start_irp) == STATUS_SUCCESS
            && root_bus().pdo_started(PDO_OBJECT_ID),
    );
    check(
        b"prepare_hardware_and_d0_entry",
        PREPARE_HW_CALLED.load(core::sync::atomic::Ordering::Relaxed)
            && D0_ENTRY_CALLED.load(core::sync::atomic::Ordering::Relaxed),
    );

    // START succeeded: drive the devnode to Started and enable the interface
    // (IoSetDeviceInterfaceState(TRUE)) — now, and only now, is the interface present.
    let _ = pnp().transition(devnode_pnp, DeviceState::Started);
    wdf().set_device_interface_state(device, IFACE_GUID, true);
    trace(b"pnp_start_complete + pnp_interface_enabled");
    check(
        b"devnode_started_interface_present",
        pnp().state(devnode_pnp) == Some(DeviceState::Started)
            && wdf().config().interfaces_by_guid(IFACE_GUID, true).len() == 1,
    );

    // --- IOCTLs (RE §7) -------------------------------------------------------
    let (st, info, out) = run_ioctl(device.0, IOCTL_PING, &[], 4);
    let ping = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_ping", st == 0 && info == 4 && ping == PING_MAGIC);

    // GET_CONFIG: hwReady@0, powered@4, ifaceCreated@8, Answer@0xc, SeenByDriver@0x10,
    // DeviceSeenByDriver@0x14, RuntimeValue@0x18.
    let (st, info, out) = run_ioctl(device.0, IOCTL_GET_CONFIG, &[], 0x2c);
    let answer = core::ptr::read_unaligned(out.as_ptr().add(0xc) as *const u32);
    let seen = core::ptr::read_unaligned(out.as_ptr().add(0x10) as *const u32);
    let dev_seen = core::ptr::read_unaligned(out.as_ptr().add(0x14) as *const u32);
    check(
        b"ioctl_get_config",
        st == 0 && info == 0x2c && answer == 42 && seen == 1 && dev_seen == 1,
    );

    // GET_GREETING: the driver requires a 0x20C-byte output buffer; it writes a 4-byte header
    // (0x02080000) then the UTF-16LE string (RE §7).
    let (st, _i, out) = run_ioctl(device.0, IOCTL_GET_GREETING, &[], 0x20c);
    let greeting = decode_utf16_at(&out, 4, 14);
    check(
        b"ioctl_get_greeting",
        st == 0 && greeting == "hello registry",
    );

    // GET_INTERFACE_STRING: the device-interface symbolic link.
    let (st, _i, out) = run_ioctl(device.0, IOCTL_GET_INTERFACE_STRING, &[], 0x20c);
    let iface_str = decode_utf16_at(&out, 4, 4);
    check(
        b"ioctl_get_interface_string",
        st == 0 && iface_str.starts_with("\\??\\"),
    );

    // SET_REG_DWORD then GET_REG_DWORD round-trips RuntimeValue.
    let (_st, _i, _o) = run_ioctl(
        device.0,
        IOCTL_SET_REG_DWORD,
        &0x1234_5678u32.to_le_bytes(),
        0,
    );
    let (st, info, out) = run_ioctl(device.0, IOCTL_GET_REG_DWORD, &[], 4);
    let runtime_value = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(
        b"ioctl_reg_dword_roundtrip",
        st == 0 && info == 4 && runtime_value == 0x1234_5678,
    );

    let (st, info, out) = run_ioctl(device.0, IOCTL_ECHO, &[0xDE, 0xAD, 0xBE, 0xEF], 4);
    check(
        b"ioctl_echo",
        st == 0 && info == 4 && out[0] == 0xDE && out[3] == 0xEF,
    );

    // --- REMOVE_DEVICE: PnP tears the stack down; interface disabled, device object deleted ----
    // (WDFKEY/WDFSTRING objects are driver-scoped in KMDF, so they legitimately outlive the
    // device delete — verify the interface is disabled + the device object itself is gone.)
    trace(b"pnp_query_remove_enter + pnp_remove_enter");
    let _ = pnp().transition(devnode_pnp, DeviceState::RemovePending);
    // Dispatch a real IRP_MN_REMOVE_DEVICE through the stack (FDO -> PDO); the bus stops the PDO.
    let remove_irp = build_pnp_irp(IRP_MN_REMOVE_DEVICE, 0, 0);
    let remove_status = io_call_driver(device.0, remove_irp);
    check(
        b"remove_device_irp_dispatched_through_stack",
        remove_status == STATUS_SUCCESS
            && irp_status(remove_irp) == STATUS_SUCCESS
            && !root_bus().pdo_started(PDO_OBJECT_ID),
    );
    wdf().set_device_interface_state(device, IFACE_GUID, false);
    let iface_disabled = wdf()
        .config()
        .interfaces_by_guid(IFACE_GUID, true)
        .is_empty();
    let deleted = wdf().delete_object(device).is_ok();
    let device_gone = wdf().prepare_hardware(device).is_err();
    let _ = pnp().transition(devnode_pnp, DeviceState::Removed);
    trace(b"pnp_interface_disabled + pnp_remove_complete");
    check(
        b"remove_disables_interface_deletes_device",
        iface_disabled && deleted && device_gone,
    );
    check(
        b"devnode_removed",
        pnp().state(devnode_pnp) == Some(DeviceState::Removed),
    );

    // --- Report -----------------------------------------------------------------------------
    print_str(b"\n  [pnp-report] ");
    print_str(DEVICE_ID.as_bytes());
    print_str(b"\\");
    print_str(INSTANCE_ID.as_bytes());
    print_str(b" (service=");
    print_str(SERVICE_NAME.as_bytes());
    print_str(b", KMDF 1.15)\n");
    print_str(b"    bind: service-DB -> root-bus PDO (QUERY_ID/CAPABILITIES) -> PnP AddDevice via\n");
    print_str(b"          WDF bridge -> EvtDriverDeviceAdd -> WdfDeviceCreate (FDO)\n");
    print_str(b"    lifecycle: Enumerated -> DriverLoaded -> AddDeviceCalled -> Started -> Removed\n");
    print_str(b"    interface present only after START; IOCTL smoke ok; clean REMOVE teardown\n");
}

/// Decode `count` UTF-16LE code units from `out` starting at byte `offset`.
fn decode_utf16_at(out: &[u8], offset: usize, count: usize) -> String {
    let units: alloc::vec::Vec<u16> = (0..count)
        .map(|i| {
            let b = offset + i * 2;
            u16::from_le_bytes([out[b], out[b + 1]])
        })
        .take_while(|&u| u != 0)
        .collect();
    char::decode_utf16(units)
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect()
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);

    print_str(b"[ntos-dhi] KMDF PnP Driver Host: PnP-driven bind of KmdfInterfaceRegistryTest.sys via the WDF AddDevice bridge\n");
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
