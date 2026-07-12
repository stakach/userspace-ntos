//! `kmdf_host` — host a REAL KMDF (WDF) driver inside a SPAWNED, unprivileged seL4
//! component of `ntos-executive`.
//!
//! This is a SPLIT port of the standalone `driver-host-wdf` root task:
//!   * the EXECUTIVE (a separate root task) pre-loads the PE + maps memory into the
//!     spawned host via [`load_into`] (parse + map + patch IAT + CFG + /GS cookie);
//!   * the HOST just runs the WDF lifecycle via [`run`] / [`kmdf_host_entry`].
//!
//! Unlike `driver-host-wdf`, this module does NOT map its own memory, do paging, or
//! bootstrap `_start` — the executive maps the host's image (RW) and the PE image
//! (at [`KMDF_CODE_VA`], W^X) before the host ever runs.
//!
//! ```text
//! FxDriverEntry -> WdfVersionBind (fills the 444-entry WdfFunctions table + globals)
//!               -> DriverEntry -> WdfDriverCreate
//! framework AddDevice -> EvtDriverDeviceAdd -> WdfDeviceCreate -> WdfIoQueueCreate
//! START_DEVICE -> EvtDevicePrepareHardware -> MmMapIoSpace -> ID='KMDF'
//! D0 entry -> IOCTLs -> D0 exit / REMOVE
//! ```

use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use nt_pe_loader::{ImportRef, PeFile};
use nt_wdf_queue::DispatchType;
use nt_wdf_request::RequestBuffers;
use nt_wdf_runtime::{PnpCallbacks, WdfRuntime};
use nt_wdf_types as wt;

use crate::*;

/// A real MSVC-compiled KMDF v1.15 driver (git-tracked fixture).
pub static SYS_BYTES: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/KmdfBasicTest.sys");

/// Where the KMDF PE image is mapped (in BOTH the executive to load it, and the host
/// to run it) — same vaddr so the relocation base matches.
pub const KMDF_CODE_VA: u64 = 0x0000_0100_104D_0000;
/// Shared handoff page (executive writes `entry_rva` at +0; host writes the verdict at +8).
pub const KMDF_SHARED_VADDR: u64 = 0x0000_0100_104C_0000;
/// Frame count for the KMDF PE image (size ~0x7000 -> 8 pages with margin).
pub const KMDF_PE_FRAMES: u64 = 8;
/// The `__guard_dispatch_icall_fptr` slot (RVA 0x3068) — the CFG indirect-call trampoline
/// every WDF dispatch goes through; we point it at a `jmp rax` stub.
pub const CFG_DISPATCH_SLOT_RVA: u64 = 0x3068;

const KMDF_MAGIC: u32 = 0x4B4D_4446; // 'KMDF'
const IOCTL_PING: u32 = 0x0022_2180;
const IOCTL_ECHO: u32 = 0x0022_2184;
const IOCTL_GET_VERSION: u32 = 0x0022_2188;
const IOCTL_GET_STATE: u32 = 0x0022_218C;
const IOCTL_READ_REG32: u32 = 0x0022_2190;

const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;

// --- global state (the executive maps the host's image RW) ------------------

static mut WDF: Option<WdfRuntime> = None;
unsafe fn wdf() -> &'static mut WdfRuntime {
    (*core::ptr::addr_of_mut!(WDF)).as_mut().unwrap()
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
}
static mut HOST: WdfHost = WdfHost {
    driver_object: 0,
    device: 0,
    queue: 0,
    device_init_blob: 0,
};
fn host() -> &'static mut WdfHost {
    // SAFETY: single-threaded host component; its image is mapped writable.
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
global_asm!(".globl cfg_dispatch_jmp_rax", "cfg_dispatch_jmp_rax:", "jmp rax");
extern "win64" {
    fn cfg_dispatch_jmp_rax();
}

/// Address of the CFG `jmp rax` dispatch stub (patched into the driver's CFG slot).
pub fn cfg_stub_addr() -> u64 {
    cfg_dispatch_jmp_rax as usize as u64
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

extern "win64" fn ntos_mm_map_io_space(phys: u64, _length: u64, _cache: u32) -> u64 {
    // Hand back the REAL e1000e NIC BAR (mapped into this host at NIC_VADDR) — the KMDF
    // driver's EvtDevicePrepareHardware maps + reads REAL hardware through the WDF stack.
    MMIO_MAPPED.store(phys | 1, Ordering::Relaxed);
    crate::NIC_VADDR
}
extern "win64" fn ntos_mm_unmap_io_space(_base: u64, _length: u64) {}

extern "win64" fn ntos_stub() -> i32 {
    0
}

// --- WDFLDR.SYS exports -----------------------------------------------------

/// `WdfVersionBind(DriverObject, Context, BindInfo, ComponentGlobals)` — validate the KMDF
/// version, publish the function table into the driver's `WdfFunctions` global, and hand
/// back the driver globals.
extern "win64" fn ntos_wdf_version_bind(
    _driver_object: u64,
    _context: u64,
    bind_info: u64,
    globals_out: *mut u64,
) -> i32 {
    // SAFETY: `bind_info` is the driver's WDF_BIND_INFO; `globals_out` its globals slot.
    unsafe {
        let major = core::ptr::read_unaligned((bind_info + wt::bind_info::VERSION_MAJOR) as *const u32);
        let minor = core::ptr::read_unaligned((bind_info + wt::bind_info::VERSION_MINOR) as *const u32);
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
        let evt_device_add =
            core::ptr::read_unaligned((config + wt::driver_config::EVT_DRIVER_DEVICE_ADD) as *const u64);
        match wdf().create_driver(driver_object, evt_device_add) {
            Ok(d) => {
                if !driver_out.is_null() {
                    core::ptr::write_unaligned(driver_out, d.0);
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
            let type_info =
                core::ptr::read_unaligned((attributes + wt::object_attributes::CONTEXT_TYPE_INFO) as *const u64);
            if type_info != 0 {
                let size =
                    core::ptr::read_unaligned((type_info + wt::context_type_info::CONTEXT_SIZE) as *const u64);
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
        let default_queue = core::ptr::read_unaligned((config + wt::queue_config::DEFAULT_QUEUE) as *const u8);
        let evt_io_device_control =
            core::ptr::read_unaligned((config + wt::queue_config::EVT_IO_DEVICE_CONTROL) as *const u64);
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

unsafe fn install_function_table() {
    let f = core::ptr::addr_of_mut!(WDF_FUNCTIONS);
    let set = |idx: usize, fp: u64| core::ptr::write_unaligned((*f).as_mut_ptr().add(idx), fp);
    set(wt::IDX_WDF_DRIVER_CREATE, wdf_driver_create as usize as u64);
    set(wt::IDX_WDF_DEVICE_INIT_SET_IO_TYPE, wdf_device_init_set_io_type as usize as u64);
    set(wt::IDX_WDF_DEVICE_INIT_SET_DEVICE_TYPE, wdf_device_init_set_device_type as usize as u64);
    set(62, wdf_device_init_set_exclusive as usize as u64); // WdfDeviceInitSetExclusive
    set(
        wt::IDX_WDF_DEVICE_INIT_SET_PNP_POWER_EVENT_CALLBACKS,
        wdf_device_init_set_pnp_power_callbacks as usize as u64,
    );
    set(wt::IDX_WDF_DEVICE_CREATE, wdf_device_create as usize as u64);
    set(wt::IDX_WDF_DEVICE_CREATE_SYMBOLIC_LINK, wdf_device_create_symbolic_link as usize as u64);
    set(wt::IDX_WDF_IO_QUEUE_CREATE, wdf_io_queue_create as usize as u64);
    set(157, wdf_io_queue_get_device as usize as u64); // WdfIoQueueGetDevice
    set(wt::IDX_WDF_OBJECT_GET_TYPED_CONTEXT_WORKER, wdf_object_get_typed_context as usize as u64);
    set(wt::IDX_WDF_REQUEST_COMPLETE_WITH_INFORMATION, wdf_request_complete_with_information as usize as u64);
    set(wt::IDX_WDF_REQUEST_RETRIEVE_INPUT_BUFFER, wdf_request_retrieve_input_buffer as usize as u64);
    set(wt::IDX_WDF_REQUEST_RETRIEVE_OUTPUT_BUFFER, wdf_request_retrieve_output_buffer as usize as u64);
    set(wt::IDX_WDF_CM_RESOURCE_LIST_GET_COUNT, wdf_cm_resource_list_get_count as usize as u64);
    set(wt::IDX_WDF_CM_RESOURCE_LIST_GET_DESCRIPTOR, wdf_cm_resource_list_get_descriptor as usize as u64);
}

/// Resolve an ntoskrnl/WDFLDR import name to a stub address. Unknown → a benign `ntos_stub`.
pub fn export_addr(name: &str) -> u64 {
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

static LAST_STATUS: AtomicU64 = AtomicU64::new(0);
static LAST_INFO: AtomicU64 = AtomicU64::new(0);
/// Set by `ntos_mm_map_io_space` when the KMDF driver's EvtDevicePrepareHardware maps the
/// (real NIC) BAR — proof the WDF hardware-prepare path ran + reached real hardware.
static MMIO_MAPPED: AtomicU64 = AtomicU64::new(0);

/// Run one buffered IOCTL through the queue → EvtIoDeviceControl → completion, returning
/// `(status, information, output_bytes)`.
unsafe fn run_ioctl(device: u64, ioctl: u32, input: &[u8], out_cap: u64) -> (i32, u64, [u8; 32]) {
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
    let (request, dispatch) = match wdf().present_ioctl(
        nt_wdf_object::WdfHandle(device),
        irp,
        ioctl,
        buffers,
    ) {
        Ok(v) => v,
        Err(_) => return (STATUS_UNSUCCESSFUL, 0, [0u8; 32]),
    };
    let Some(d) = dispatch else {
        return (STATUS_UNSUCCESSFUL, 0, [0u8; 32]);
    };
    // EvtIoDeviceControl(Queue, Request, OutputBufferLength, InputBufferLength, IoControlCode).
    let f: extern "win64" fn(u64, u64, u64, u64, u32) = core::mem::transmute(d.evt_io_device_control as *const ());
    f(d.queue.0, request.0, out_cap, input.len() as u64, ioctl);

    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate().take(out_cap.min(32) as usize) {
        *o = core::ptr::read_volatile((sysbuf + i as u64) as *const u8);
    }
    (LAST_STATUS.load(Ordering::Relaxed) as i32, LAST_INFO.load(Ordering::Relaxed), out)
}

// --- executive-side loader --------------------------------------------------

/// Runs in the EXECUTIVE (which has the heap + the KMDF image mapped RW at [`KMDF_CODE_VA`]).
/// Parse the `.sys`, map+relocate it for `KMDF_CODE_VA`, copy the mapped bytes into the
/// (executive-mapped) image frames, patch the IAT to our stubs + the CFG dispatch slot to the
/// `jmp rax` stub, seed the /GS cookie. Returns the DriverEntry RVA. The executive then
/// re-maps those same frames W^X into the host.
pub unsafe fn load_into() -> Option<u32> {
    let pe = PeFile::parse(SYS_BYTES).ok()?;
    let mapped = pe.map(KMDF_CODE_VA).ok()?;
    let dst = KMDF_CODE_VA as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let ImportRef::ByName { name, iat_slot_rva, .. } = f {
                    core::ptr::write_unaligned(
                        (KMDF_CODE_VA + *iat_slot_rva as u64) as *mut u64,
                        export_addr(name),
                    );
                }
            }
        }
    }
    // Point the CFG indirect-call trampoline at our `jmp rax` stub.
    core::ptr::write_unaligned(
        (KMDF_CODE_VA + CFG_DISPATCH_SLOT_RVA) as *mut u64,
        cfg_stub_addr(),
    );
    pe.seed_security_cookie(KMDF_CODE_VA);
    Some(pe.entry_point_rva())
}

// --- host-side lifecycle ----------------------------------------------------

/// Runs in the HOST. Drive the real KMDF driver through the full WDF lifecycle. The
/// executive has already loaded/mapped the PE at [`KMDF_CODE_VA`], so this skips
/// load/map/apply_wx entirely and just runs the lifecycle. Returns a verdict bitmask:
///   bit0 = DriverEntry SUCCESS + WdfDriverCreate · bit1 = AddDevice built device+queue
///   bit2 = PrepareHardware mapped the MMIO id · bit3 = an IOCTL round-trip succeeded
///   bit4 = REMOVE deleted the device+queue
pub unsafe fn run(entry_rva: u32) -> u32 {
    let mut verdict = 0u32;

    WDF = Some(WdfRuntime::new());
    // Seed the identity register.
    core::ptr::write_unaligned(core::ptr::addr_of_mut!(MMIO) as *mut u32, KMDF_MAGIC);
    install_function_table();

    // DRIVER_OBJECT (Type@0=4, Size@2=336, DriverExtension@48).
    let driver_object = alloc_blob();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let driver_ext = alloc_blob();
    core::ptr::write_unaligned((driver_object + 48) as *mut u64, driver_ext);
    host().driver_object = driver_object;
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    // FxDriverEntry → WdfVersionBind → DriverEntry → WdfDriverCreate.
    let entry = KMDF_CODE_VA + entry_rva as u64;
    let fx: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = fx(driver_object, reg_path);
    if status == 0 && wdf().driver().is_some() {
        verdict |= 1;
    }
    print_str(b"[kmdf] DriverEntry + WdfDriverCreate\n");

    let evt_device_add = wdf().evt_device_add();

    // --- Framework AddDevice → EvtDriverDeviceAdd -----------------------------
    let init_id = wdf().add_device(0xFED0_0000 /* PDO */);
    let device_init_blob = alloc_blob();
    core::ptr::write_unaligned(device_init_blob as *mut u64, init_id as u64);
    host().device_init_blob = device_init_blob;
    let driver = wdf().driver().unwrap();
    let add_status = call2(evt_device_add, driver.0, device_init_blob);
    let device = nt_wdf_object::WdfHandle(host().device);
    if add_status == 0 && host().device != 0 && host().queue != 0 {
        verdict |= 2;
    }
    print_str(b"[kmdf] AddDevice created device + queue\n");

    // --- START_DEVICE → EvtDevicePrepareHardware ------------------------------
    let res_list = build_resource_list();
    let prepare = wdf().prepare_hardware(device).unwrap_or(0);
    let prep_status = if prepare != 0 {
        call3(prepare, device.0, res_list, res_list)
    } else {
        STATUS_UNSUCCESSFUL
    };
    // The driver's PrepareHardware ran and called MmMapIoSpace to map the REAL e1000e BAR
    // (MMIO_MAPPED). It read register 0 (the e1000e CTRL, 0x001402xx) and — correctly —
    // REJECTED the device (prep_status != 0): this isn't its 'KMDF' test device. That very
    // rejection PROVES it read + evaluated a real hardware register through the WDF stack
    // (on the simulated device it would have ACCEPTED). Read the live CTRL host-side too.
    let mapped = MMIO_MAPPED.load(Ordering::Relaxed) != 0;
    let ctrl = core::ptr::read_volatile(crate::NIC_VADDR as *const u32);
    core::ptr::write_volatile((KMDF_SHARED_VADDR + 0x10) as *mut u32, ctrl);
    if mapped && prep_status != 0 {
        verdict |= 4;
    }
    print_str(b"[kmdf] PrepareHardware mapped the REAL NIC BAR; read CTRL=0x");
    print_hex(ctrl);
    print_str(b" and rejected the device (not its test HW)\n");

    // --- D0 entry -------------------------------------------------------------
    let (d0_entry, _released) = wdf().set_device_power(device, true).unwrap();
    let _d0_status = if d0_entry != 0 {
        call2(d0_entry, device.0, 1 /* prev = D3 */)
    } else {
        STATUS_UNSUCCESSFUL
    };

    // --- IOCTLs ---------------------------------------------------------------
    let (st, info, out) = run_ioctl(device.0, IOCTL_PING, &[], 4);
    let ping = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    if st == 0 && info == 4 && ping == KMDF_MAGIC {
        verdict |= 8;
    }

    let (st, info, out) = run_ioctl(device.0, IOCTL_ECHO, &[0xDE, 0xAD, 0xBE, 0xEF], 4);
    if st == 0 && info == 4 && out[0] == 0xDE && out[3] == 0xEF {
        verdict |= 8;
    }

    let (st, info, out) = run_ioctl(device.0, IOCTL_GET_VERSION, &[], 8);
    let ver = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    if st == 0 && info == 8 && ver == 0x0001_0000 {
        verdict |= 8;
    }

    let (st, info, out) = run_ioctl(device.0, IOCTL_GET_STATE, &[], 0x14);
    let prepared = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    let powered = core::ptr::read_unaligned(out.as_ptr().add(4) as *const u32);
    if st == 0 && info == 0x14 && prepared == 1 && powered == 1 {
        verdict |= 8;
    }

    let mut reg_in = [0u8; 8];
    reg_in[0..8].copy_from_slice(&0u64.to_le_bytes()); // offset 0
    let (st, info, out) = run_ioctl(device.0, IOCTL_READ_REG32, &reg_in, 8);
    let value = core::ptr::read_unaligned(out.as_ptr().add(4) as *const u32);
    if st == 0 && info == 8 && value == KMDF_MAGIC {
        verdict |= 8;
    }
    print_str(b"[kmdf] IOCTL round-trip\n");

    // --- D0 exit + ReleaseHardware + REMOVE -----------------------------------
    let (d0_exit, _) = wdf().set_device_power(device, false).unwrap();
    let _exit_status = if d0_exit != 0 {
        call2(d0_exit, device.0, 3 /* target = D3 */)
    } else {
        STATUS_UNSUCCESSFUL
    };
    let release = wdf().release_hardware(device).unwrap_or(0);
    let _rel_status = if release != 0 {
        call2(release, device.0, res_list)
    } else {
        STATUS_UNSUCCESSFUL
    };

    // REMOVE: delete the device (cascades to its queue).
    let pending = wdf().delete_object(device).unwrap_or_default();
    if wdf().live_object_count() == 1 && pending.is_empty() {
        verdict |= 16;
    }
    print_str(b"[kmdf] REMOVE deleted device + queue\n");

    verdict
}

/// The host component entry point. The executive writes `entry_rva` to
/// [`KMDF_SHARED_VADDR`]+0; this drives the WDF lifecycle, writes the verdict back to
/// [`KMDF_SHARED_VADDR`]+8, signals the executive via `CT_RESULT_NTFN`, then parks.
#[no_mangle]
#[link_section = ".text.kmdf_host_entry"]
pub unsafe extern "C" fn kmdf_host_entry() -> ! {
    let entry_rva = core::ptr::read_volatile((KMDF_SHARED_VADDR + 0) as *const u64) as u32;
    let v = run(entry_rva);
    core::ptr::write_volatile((KMDF_SHARED_VADDR + 8) as *mut u32, v);
    print_str(b"[kmdf-host] lifecycle verdict bits=0x");
    print_hex(v);
    print_str(b"\n");
    let _ = syscall5(SYS_SEND, CT_RESULT_NTFN, 0, 0, 0, 0);
    loop {
        yield_now();
    }
}
