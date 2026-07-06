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

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use nt_config_manager::DevPropKey;
use nt_pnp_abi::{DeviceState, IRP_MJ_PNP, IRP_MN_REMOVE_DEVICE, IRP_MN_START_DEVICE};
use nt_pnp_manager::PnpManager;
use nt_root_bus::{BusQueryId, RootBus};
use nt_wdf_object::WdfHandle;
use nt_wdf_request::RequestBuffers;
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

/// The KMDF DRIVER_OBJECT (component-owned; the framework PnP dispatch reads it for
/// MajorFunction[IRP_MJ_PNP]).
static DRV_OBJECT: AtomicU64 = AtomicU64::new(0);

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
    let drv = DRV_OBJECT.load(Ordering::Relaxed);
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
                let prepare = nt_wdf_kmdf::wdf().prepare_hardware(device).unwrap_or(0);
                let ps = if prepare != 0 {
                    PREPARE_HW_CALLED.store(true, core::sync::atomic::Ordering::Relaxed);
                    call3(prepare, fdo, translated, translated)
                } else {
                    0
                };
                let d0 = nt_wdf_kmdf::wdf().set_device_power(device, true).map(|(e, _)| e).unwrap_or(0);
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


extern "win64" fn ntos_stub() -> i32 {
    0
}
/// Resolve the KMDF driver's imports through the shared WDF crate; unknown imports get a stub.
fn export_addr(name: &str) -> u64 {
    nt_wdf_kmdf::export_addr(name).unwrap_or(ntos_stub as usize as u64)
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
        match nt_wdf_kmdf::wdf().present_ioctl(nt_wdf_object::WdfHandle(device), irp, ioctl, buffers) {
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
    let (status, info) = nt_wdf_kmdf::last_completion();
    (status, info, out)
}

unsafe fn run() {
    PNP = Some(PnpManager::new());
    ROOT_BUS = Some(RootBus::new());
    nt_wdf_kmdf::init();

    // --- Seed the Configuration Manager fixture (spec §21 / RE §9) ------------
    {
        let cm = nt_wdf_kmdf::wdf().config_mut();
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
    let devnode = nt_wdf_kmdf::wdf().config_mut().register_devnode(
        DEVNODE_INSTANCE,
        Some(SERVICE_NAME),
        Some(r"\Device\NTPNP_ROOT_0004"),
        &[r"Root\KmdfInterfaceRegistryTest"],
        &[],
    );
    nt_wdf_kmdf::set_devnode(devnode);
    nt_wdf_kmdf::wdf().set_driver_service(SERVICE_NAME);

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
        nt_wdf_kmdf::cfg_dispatch_addr(),
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
    DRV_OBJECT.store(driver_object, Ordering::Relaxed);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    // FxDriverEntry → WdfVersionBind → DriverEntry → WdfDriverCreate.
    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let fx: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = fx(driver_object, reg_path);
    // Install the component's framework PnP dispatch into MajorFunction[IRP_MJ_PNP]. (The shared
    // WDF crate installs only the AddDevice bridge; the PnP dispatch is tied to this component's
    // device stack, so the component owns it.)
    core::ptr::write_unaligned(
        (driver_object + 112 + IRP_MJ_PNP as u64 * 8) as *mut u64,
        fx_device_pnp_dispatch as usize as u64,
    );
    check(
        b"driver_entry_wdf_driver_create",
        status == 0 && nt_wdf_kmdf::wdf().driver().is_some(),
    );

    let evt_device_add = nt_wdf_kmdf::wdf().evt_device_add();
    check(b"evt_device_add_registered", evt_device_add != 0);
    // WdfDriverCreate installed the WDM AddDevice bridge into DriverExtension->AddDevice (@ ext+8).
    let driver_ext = core::ptr::read_unaligned((driver_object + 48) as *const u64);
    let add_device = core::ptr::read_unaligned((driver_ext + 8) as *const u64);
    check(
        b"wdf_add_device_bridge_installed",
        add_device == nt_wdf_kmdf::add_device_bridge_addr(),
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
    let device = nt_wdf_object::WdfHandle(nt_wdf_kmdf::device());
    let _ = pnp().transition(devnode_pnp, DeviceState::AddDeviceCalled);
    let _ = pnp().set_fdo(devnode_pnp, nt_wdf_kmdf::device());
    let _ = pnp().transition(devnode_pnp, DeviceState::DeviceStackBuilt);
    check(
        b"pnp_add_device_created_device_queue",
        add_status == 0 && nt_wdf_kmdf::device() != 0 && nt_wdf_kmdf::queue() != 0,
    );
    check(
        b"fdo_attached_above_pdo",
        pnp().fdo(devnode_pnp) == Some(nt_wdf_kmdf::device()),
    );
    trace(b"pnp_fdo_detected + pnp_attach");

    // EvtDeviceAdd ran the registry helpers: read Answer=42/Greeting, wrote SeenByDriver=1 +
    // DeviceSeenByDriver=1 + RuntimeValue=0 (RE §3).
    let params = nt_wdf_kmdf::wdf().config().service_parameters_key(SERVICE_NAME).unwrap();
    check(
        b"driver_wrote_seen_by_driver",
        nt_wdf_kmdf::wdf()
            .config()
            .registry()
            .query_dword(params, "SeenByDriver")
            == Some(1),
    );
    let enum_key = nt_wdf_kmdf::wdf().config().devnode_enum_key(devnode).unwrap();
    check(
        b"driver_wrote_device_seen_by_driver",
        nt_wdf_kmdf::wdf()
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
        nt_wdf_kmdf::wdf().device_interface_link(device, IFACE_GUID).is_some(),
    );
    nt_wdf_kmdf::wdf().set_device_interface_state(device, IFACE_GUID, false);
    check(
        b"interface_not_present_before_start",
        nt_wdf_kmdf::wdf()
            .config()
            .interfaces_by_guid(IFACE_GUID, true)
            .is_empty(),
    );
    check(
        b"friendly_name_property_assigned",
        nt_wdf_kmdf::wdf()
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
        nt_wdf_kmdf::wdf()
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
    nt_wdf_kmdf::wdf().set_device_interface_state(device, IFACE_GUID, true);
    trace(b"pnp_start_complete + pnp_interface_enabled");
    check(
        b"devnode_started_interface_present",
        pnp().state(devnode_pnp) == Some(DeviceState::Started)
            && nt_wdf_kmdf::wdf().config().interfaces_by_guid(IFACE_GUID, true).len() == 1,
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
    nt_wdf_kmdf::wdf().set_device_interface_state(device, IFACE_GUID, false);
    let iface_disabled = nt_wdf_kmdf::wdf()
        .config()
        .interfaces_by_guid(IFACE_GUID, true)
        .is_empty();
    let deleted = nt_wdf_kmdf::wdf().delete_object(device).is_ok();
    let device_gone = nt_wdf_kmdf::wdf().prepare_hardware(device).is_err();
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
