//! # `nt-wdf-kmdf` — the shared KMDF (WDF framework) host surface
//!
//! The `extern "win64"` WDF function-table thunks a real KMDF driver calls (device init/create,
//! I/O queue, request buffers, registry, device interface, WDFSTRING, property, typed context),
//! `WdfVersionBind`, and the WDM `AddDevice` bridge — over a crate-global `WdfRuntime` +
//! `ConfigManager`. Extracted from `driver-host-direg` so every seL4 driver-host component can run
//! a KMDF driver's full `EvtDeviceAdd` (registry parameters + device interface + I/O queue) without
//! duplicating the runtime.
//!
//! The consuming component owns what is genuinely seL4/PE-specific: loading + mapping the `.sys`,
//! W^X, the Control-Flow-Guard slot fixup (using [`cfg_dispatch_addr`]), the `DRIVER_OBJECT` blob,
//! and the PnP-IRP dispatch / device-stack. It calls [`init`], seeds fixtures via [`config_mut`],
//! resolves the driver's imports via [`export_addr`], and drives the lifecycle via [`wdf`].

#![no_std]

extern crate alloc;

use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use nt_config_manager::{ConfigManager, DevPropKey, PropertyValue};
use nt_wdf_object::WdfHandle;
use nt_wdf_queue::DispatchType;
use nt_wdf_runtime::{PnpCallbacks, WdfRuntime};
use nt_wdf_types as wt;

const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;

/// The status + information the driver reported on the last completed WDFREQUEST (the component
/// reads these to complete the IRP after an IOCTL round-trip).
static LAST_STATUS: AtomicU64 = AtomicU64::new(0);
static LAST_INFO: AtomicU64 = AtomicU64::new(0);
/// The `(status, information)` of the last completed request.
pub fn last_completion() -> (i32, u64) {
    (
        LAST_STATUS.load(Ordering::Relaxed) as u32 as i32,
        LAST_INFO.load(Ordering::Relaxed),
    )
}

static mut WDF: Option<WdfRuntime> = None;
/// The shared WDF runtime the thunks + the consuming component both drive.
#[allow(clippy::missing_panics_doc)]
pub fn wdf() -> &'static mut WdfRuntime {
    // SAFETY: single-threaded root task; initialized by `init`.
    unsafe { (*core::ptr::addr_of_mut!(WDF)).as_mut().unwrap() }
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
                // PnP-driven AddDevice reaches EvtDriverDeviceAdd through the framework. (The
                // component installs its own MajorFunction[IRP_MJ_PNP] framework PnP dispatch, which
                // is tied to the component's device stack.)
                let driver_ext = core::ptr::read_unaligned((driver_object + 48) as *const u64);
                if driver_ext != 0 {
                    core::ptr::write_unaligned(
                        (driver_ext + 8) as *mut u64,
                        wdm_add_device_bridge as usize as u64,
                    );
                }
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

unsafe fn call2(fp: u64, a: u64, b: u64) -> i32 {
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(fp as *const ());
    f(a, b)
}
unsafe fn call3(fp: u64, a: u64, b: u64, c: u64) -> i32 {
    let f: extern "win64" fn(u64, u64, u64) -> i32 = core::mem::transmute(fp as *const ());
    f(a, b, c)
}


/// `wcslen(s)` — some KMDF stubs use it; count wide chars to the NUL.
extern "win64" fn ntos_wcslen(s: *const u16) -> u64 {
    // SAFETY: `s` is a NUL-terminated wide string.
    unsafe {
        if s.is_null() {
            return 0;
        }
        let mut n = 0u64;
        while *s.add(n as usize) != 0 {
            n += 1;
        }
        n
    }
}

// --- public API for the consuming seL4 driver-host component -----------------

/// Create the shared WDF runtime + install the 444-entry function table. Call once at startup.
pub fn init() {
    // SAFETY: single-threaded root task; called once before any driver runs.
    unsafe {
        WDF = Some(WdfRuntime::new());
        install_function_table();
    }
}

// --- UMDF v2 hosting --------------------------------------------------------
// A UMDF v2 driver runs OUT of process (or in an isolated host). Unlike KMDF (the
// driver calls WdfVersionBind itself), the host writes the WdfFunctions table + the
// WdfDriverGlobals pointer into two image globals, then calls DriverEntry directly.
// The function-table INDICES differ from KMDF — e.g. WdfDriverCreate is 57, not 116
// (reverse-engineered from a real UMDF 2.0 driver) — so we publish a SEPARATE table
// with the same shared thunks installed at the UMDF v2 positions.
static mut UMDF2_FUNCTIONS: [u64; 512] = [0; 512];
static mut UMDF2_GLOBALS: [u8; 64] = [0; 64];

/// UMDF v2 `WDFFUNCENUM` index of `WdfDriverCreate` (KMDF's is 116).
const UMDF2_IDX_WDF_DRIVER_CREATE: usize = 57;

/// Ensure the shared runtime exists and install the shared WDF thunks at their UMDF v2
/// table indices. Call once before hosting a UMDF v2 driver.
pub fn umdf2_prepare() {
    // SAFETY: single-threaded root task; called once before any UMDF driver runs.
    unsafe {
        if (*core::ptr::addr_of!(WDF)).is_none() {
            WDF = Some(WdfRuntime::new());
        }
        let t = &mut *core::ptr::addr_of_mut!(UMDF2_FUNCTIONS);
        t[UMDF2_IDX_WDF_DRIVER_CREATE] = wdf_driver_create as usize as u64;
    }
}

/// Pointer to the UMDF v2 function table — write into the driver image's `WdfFunctions`
/// global before calling its `DriverEntry`.
pub fn umdf2_functions_ptr() -> u64 {
    core::ptr::addr_of!(UMDF2_FUNCTIONS) as u64
}
/// Pointer to the UMDF v2 driver globals — write into the driver image's `WdfDriverGlobals`
/// global before calling its `DriverEntry`.
pub fn umdf2_globals_ptr() -> u64 {
    core::ptr::addr_of!(UMDF2_GLOBALS) as u64
}

/// The Configuration Manager (for seeding the service DB + devnode + parameter fixtures).
pub fn config_mut() -> &'static mut ConfigManager {
    wdf().config_mut()
}
/// The Configuration Manager (read-only).
pub fn config() -> &'static ConfigManager {
    wdf().config()
}
/// Select the service the driver binds (its registry `Parameters` key).
pub fn set_driver_service(name: &str) {
    wdf().set_driver_service(name);
}
/// Record the devnode the created WDFDEVICE belongs to (the framework links to it).
pub fn set_devnode(devnode: u64) {
    host().devnode = devnode;
}
/// The WDFDEVICE (FDO) the `WdfDeviceCreate` thunk captured.
pub fn device() -> u64 {
    host().device
}
/// The default WDFQUEUE the `WdfIoQueueCreate` thunk captured.
pub fn queue() -> u64 {
    host().queue
}
/// The created WDFDRIVER handle, if any.
pub fn driver() -> Option<u64> {
    wdf().driver().map(|d| d.0)
}

/// User-mode "open by interface": resolve the first enabled device interface of `guid` to
/// `(symbolic link, WDFDEVICE)` — what `CreateFile(symbolic_link)` would open. `None` if no enabled
/// interface of that GUID exists (device stopped/removed → interfaces disabled).
pub fn open_interface(guid: &str) -> Option<(String, u64)> {
    wdf()
        .open_device_interface(guid)
        .map(|(link, dev)| (link, dev.0))
}
/// The driver's captured `EvtDriverDeviceAdd`.
pub fn evt_device_add() -> u64 {
    wdf().evt_device_add()
}

/// Resolve a KMDF driver's import (WDFLDR + the core ntoskrnl imports this surface owns). Returns
/// `None` for imports the consuming component must resolve itself.
pub fn export_addr(name: &str) -> Option<u64> {
    let f: u64 = match name {
        "WdfVersionBind" => ntos_wdf_version_bind as usize as u64,
        "WdfVersionUnbind" => ntos_wdf_version_unbind as usize as u64,
        "WdfVersionBindClass" => ntos_wdf_version_bind_class as usize as u64,
        "WdfVersionUnbindClass" => ntos_wdf_version_unbind_class as usize as u64,
        "RtlInitUnicodeString" => ntos_rtl_init_unicode_string as usize as u64,
        "RtlCopyUnicodeString" => ntos_rtl_copy_unicode_string as usize as u64,
        "MmMapIoSpace" => ntos_mm_map_io_space as usize as u64,
        "MmUnmapIoSpace" => ntos_mm_unmap_io_space as usize as u64,
        "DbgPrintEx" => ntos_dbg_print_ex as usize as u64,
        "wcslen" => ntos_wcslen as usize as u64,
        _ => return None,
    };
    Some(f)
}

/// The `jmp rax` Control-Flow-Guard dispatch trampoline (patch it into the driver's
/// `__guard_dispatch_icall_fptr` slot before sealing `.rdata`).
pub fn cfg_dispatch_addr() -> u64 {
    cfg_dispatch_jmp_rax as usize as u64
}
/// The WDM `AddDevice` bridge (installed into `DriverExtension->AddDevice` by `WdfDriverCreate`).
pub fn add_device_bridge_addr() -> u64 {
    wdm_add_device_bridge as usize as u64
}
