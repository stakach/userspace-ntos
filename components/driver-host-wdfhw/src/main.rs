//! `ntos-driver-host-wdfhw` — a KMDF hardware-extensions Driver Host as a seL4 component.
//!
//! Loads the real `KmdfDmaInterruptTest.sys` (KMDF v1.15, W^X + NX) and runs the whole
//! hardware-object lifecycle (spec: NT KMDF Hardware Extensions, Milestone 16) against the
//! in-process `WdfRuntime` — reusing the M15 WDF binding + adding WDFINTERRUPT, WDFDMAENABLER,
//! WDFCOMMONBUFFER, WDFTIMER, WDFWORKITEM:
//!
//! ```text
//! EvtDeviceAdd     -> WdfDeviceCreate/SymLink/IoQueueCreate + WdfInterruptCreate
//!                     + WdfTimerCreate + WdfWorkItemCreate
//! PrepareHardware  -> WDFCMRESLIST -> MmMapIoSpace (ID='KDMA') -> WdfDmaEnablerCreate
//!                     + WdfCommonBufferCreate; framework auto-connects the interrupt
//! D0 entry         -> EvtDeviceD0Entry -> WdfInterruptEnable
//! DMA roundtrip    -> IOCTL fills common buffer + programs the sim DMA; sim raises an
//!                     interrupt -> EvtInterruptIsr -> WdfInterruptQueueDpcForIsr ->
//!                     EvtInterruptDpc -> WdfRequestCompleteWithInformation
//! timer/workitem   -> IOCTL pends -> WdfTimer/WorkItem fires -> completes the request
//! D0 exit / REMOVE -> WdfInterruptDisable (drops interrupts) / WdfObjectDelete cascade
//! ```
//!
//! Every WDF call routes through `WdfFunctions[index]` via the `/guard:cf` dispatch slot;
//! each entry is a thunk into `nt_wdf_runtime::WdfRuntime`. A small simulated DMA device
//! (8 MMIO registers) drives the interrupt.

#![no_std]
#![no_main]
#![allow(function_casts_as_integer)]

extern crate alloc;

mod allocator;

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use nt_wdf_interrupt::WdfInterruptConfig;
use nt_wdf_object::WdfHandle;
use nt_wdf_queue::DispatchType;
use nt_wdf_request::RequestBuffers;
use nt_wdf_runtime::{PnpCallbacks, WdfRuntime};
use nt_wdf_types as wt;
use sel4_rt::*;

static WDF_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/KmdfDmaInterruptTest.sys");

const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
/// The `__guard_dispatch_icall_fptr` slot (RVA 0x3068) — the CFG indirect-call trampoline
/// every WDF dispatch goes through; we point it at a `jmp rax` stub.
const CFG_DISPATCH_SLOT_RVA: u64 = 0x3068;

const KMDF_MAGIC: u32 = 0x4B44_4D41; // 'KDMA' — the device ID register value
const IOCTL_GET_ID: u32 = 0x0022_21C0;
const IOCTL_GET_INFO: u32 = 0x0022_21C4;
const IOCTL_READ_REG32: u32 = 0x0022_21C8;
const IOCTL_DMA_ROUNDTRIP: u32 = 0x0022_21D0;
const IOCTL_TIMER: u32 = 0x0022_21D4;
const IOCTL_WORKITEM: u32 = 0x0022_21D8;

// Simulated DMA device MMIO register bank (RE §7).
const REG_STATUS: u64 = 0x08; // bit0 = interrupt pending, bit1 = error
const REG_INT_ACK: u64 = 0x0c;
const REG_DMA_LO: u64 = 0x10;
const REG_DMA_HI: u64 = 0x14;
const REG_DMA_LENGTH: u64 = 0x18;
const REG_DMA_COMMAND: u64 = 0x1c; // driver writes 1 = START
const REG_DMA_RESULT: u64 = 0x20;
const STATUS_INT_PENDING: u32 = 1;

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
    // Hardware object handles, captured by the create thunks.
    interrupt: u64,
    timer: u64,
    workitem: u64,
    dma_enabler: u64,
    common_buffer: u64,
}
static mut HOST: WdfHost = WdfHost {
    driver_object: 0,
    device: 0,
    queue: 0,
    device_init_blob: 0,
    interrupt: 0,
    timer: 0,
    workitem: 0,
    dma_enabler: 0,
    common_buffer: 0,
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

// --- WDFINTERRUPT thunks (RE §2, §3) ----------------------------------------

/// `WdfInterruptCreate(Globals, Device, Config, Attributes, &Interrupt)`.
extern "win64" fn wdf_interrupt_create(
    _g: u64,
    device: u64,
    config: u64,
    _attributes: u64,
    interrupt_out: *mut u64,
) -> i32 {
    // SAFETY: `config` is the driver's WDF_INTERRUPT_CONFIG.
    unsafe {
        let read = |off: u64| core::ptr::read_unaligned((config + off) as *const u64);
        let cfg = WdfInterruptConfig {
            evt_isr: read(wt::interrupt_config::EVT_INTERRUPT_ISR),
            evt_dpc: read(wt::interrupt_config::EVT_INTERRUPT_DPC),
            evt_enable: read(wt::interrupt_config::EVT_INTERRUPT_ENABLE),
            evt_disable: read(wt::interrupt_config::EVT_INTERRUPT_DISABLE),
            automatic_serialization: false,
        };
        match wdf().create_interrupt(WdfHandle(device), cfg) {
            Ok(i) => {
                host().interrupt = i.0;
                if !interrupt_out.is_null() {
                    core::ptr::write_unaligned(interrupt_out, i.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}

extern "win64" fn wdf_interrupt_queue_dpc_for_isr(_g: u64, interrupt: u64) -> u8 {
    // SAFETY: single-threaded service access.
    unsafe { wdf().interrupt_queue_dpc(WdfHandle(interrupt)) as u8 }
}

extern "win64" fn wdf_interrupt_get_device(_g: u64, interrupt: u64) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf()
            .interrupt_get_device(WdfHandle(interrupt))
            .map(|d| d.0)
            .unwrap_or(0)
    }
}

/// `WdfInterruptEnable(Globals, Interrupt)` — enable + invoke `EvtInterruptEnable(Interrupt,
/// Device)` (a nested driver callback, RE §2).
extern "win64" fn wdf_interrupt_enable(_g: u64, interrupt: u64) -> i32 {
    // SAFETY: single-threaded; invokes a driver callback.
    unsafe {
        let evt = wdf().interrupt_enable(WdfHandle(interrupt));
        if evt != 0 {
            let device = wdf()
                .interrupt_get_device(WdfHandle(interrupt))
                .map(|d| d.0)
                .unwrap_or(0);
            call2(evt, interrupt, device);
        }
        STATUS_SUCCESS
    }
}
extern "win64" fn wdf_interrupt_disable(_g: u64, interrupt: u64) -> i32 {
    // SAFETY: single-threaded; invokes a driver callback.
    unsafe {
        let evt = wdf().interrupt_disable(WdfHandle(interrupt));
        if evt != 0 {
            let device = wdf()
                .interrupt_get_device(WdfHandle(interrupt))
                .map(|d| d.0)
                .unwrap_or(0);
            call2(evt, interrupt, device);
        }
        STATUS_SUCCESS
    }
}

// --- WDFDMAENABLER + WDFCOMMONBUFFER thunks (RE §3, §5) ----------------------

/// `WdfDmaEnablerCreate(Globals, Device, Config, Attributes, &DmaEnabler)`.
extern "win64" fn wdf_dma_enabler_create(
    _g: u64,
    device: u64,
    config: u64,
    _attributes: u64,
    enabler_out: *mut u64,
) -> i32 {
    // SAFETY: `config` is the driver's WDF_DMA_ENABLER_CONFIG.
    unsafe {
        let profile =
            core::ptr::read_unaligned((config + wt::dma_enabler_config::PROFILE) as *const u32);
        let max_length = core::ptr::read_unaligned(
            (config + wt::dma_enabler_config::MAXIMUM_LENGTH) as *const u64,
        );
        match wdf().create_dma_enabler(WdfHandle(device), profile, max_length) {
            Ok(e) => {
                host().dma_enabler = e.0;
                if !enabler_out.is_null() {
                    core::ptr::write_unaligned(enabler_out, e.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}

extern "win64" fn wdf_dma_enabler_get_maximum_length(_g: u64, enabler: u64) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf()
            .dma_enabler_maximum_length(WdfHandle(enabler))
            .unwrap_or(0)
    }
}

/// `WdfCommonBufferCreate(Globals, DmaEnabler, Length, Attributes, &CommonBuffer)` — allocate
/// a page-aligned backing buffer + a fake logical address.
extern "win64" fn wdf_common_buffer_create(
    _g: u64,
    enabler: u64,
    length: u64,
    _attributes: u64,
    common_buffer_out: *mut u64,
) -> i32 {
    // SAFETY: single-threaded service access.
    unsafe {
        let va = alloc_bytes(length as usize);
        match wdf().create_common_buffer(WdfHandle(enabler), length, va) {
            Ok((cb, _logical)) => {
                host().common_buffer = cb.0;
                if !common_buffer_out.is_null() {
                    core::ptr::write_unaligned(common_buffer_out, cb.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}

extern "win64" fn wdf_common_buffer_get_virtual_address(_g: u64, cb: u64) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf()
            .common_buffer_virtual_address(WdfHandle(cb))
            .unwrap_or(0)
    }
}
extern "win64" fn wdf_common_buffer_get_logical_address(_g: u64, cb: u64) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf()
            .common_buffer_logical_address(WdfHandle(cb))
            .unwrap_or(0)
    }
}
extern "win64" fn wdf_common_buffer_get_length(_g: u64, cb: u64) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe { wdf().common_buffer_length(WdfHandle(cb)).unwrap_or(0) }
}

// --- WDFTIMER + WDFWORKITEM thunks (RE §3) ----------------------------------

fn parent_of(attributes: u64) -> u64 {
    // WDF_OBJECT_ATTRIBUTES.ParentObject@0x20; fall back to the device.
    if attributes != 0 {
        // SAFETY: `attributes` is the driver's WDF_OBJECT_ATTRIBUTES.
        let p = unsafe {
            core::ptr::read_unaligned(
                (attributes + wt::object_attributes::PARENT_OBJECT) as *const u64,
            )
        };
        if p != 0 {
            return p;
        }
    }
    host().device
}

extern "win64" fn wdf_timer_create(
    _g: u64,
    config: u64,
    attributes: u64,
    timer_out: *mut u64,
) -> i32 {
    // SAFETY: `config` is the driver's WDF_TIMER_CONFIG.
    unsafe {
        let evt =
            core::ptr::read_unaligned((config + wt::timer_config::EVT_TIMER_FUNC) as *const u64);
        match wdf().create_timer(WdfHandle(parent_of(attributes)), evt) {
            Ok(t) => {
                host().timer = t.0;
                if !timer_out.is_null() {
                    core::ptr::write_unaligned(timer_out, t.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}
extern "win64" fn wdf_timer_start(_g: u64, timer: u64, _due_time: i64) -> u8 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf().timer_start(WdfHandle(timer));
    }
    0
}
extern "win64" fn wdf_timer_stop(_g: u64, timer: u64, _wait: u8) -> u8 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf().timer_stop(WdfHandle(timer));
    }
    0
}
extern "win64" fn wdf_timer_get_parent_object(_g: u64, timer: u64) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf()
            .timer_get_parent(WdfHandle(timer))
            .map(|p| p.0)
            .unwrap_or(0)
    }
}

extern "win64" fn wdf_work_item_create(
    _g: u64,
    config: u64,
    attributes: u64,
    workitem_out: *mut u64,
) -> i32 {
    // SAFETY: `config` is the driver's WDF_WORKITEM_CONFIG.
    unsafe {
        let evt = core::ptr::read_unaligned(
            (config + wt::workitem_config::EVT_WORK_ITEM_FUNC) as *const u64,
        );
        match wdf().create_workitem(WdfHandle(parent_of(attributes)), evt) {
            Ok(w) => {
                host().workitem = w.0;
                if !workitem_out.is_null() {
                    core::ptr::write_unaligned(workitem_out, w.0);
                }
                STATUS_SUCCESS
            }
            Err(_) => STATUS_UNSUCCESSFUL,
        }
    }
}
extern "win64" fn wdf_work_item_enqueue(_g: u64, workitem: u64) {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf().workitem_enqueue(WdfHandle(workitem));
    }
}
extern "win64" fn wdf_work_item_get_parent_object(_g: u64, workitem: u64) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        wdf()
            .workitem_get_parent(WdfHandle(workitem))
            .map(|p| p.0)
            .unwrap_or(0)
    }
}
extern "win64" fn wdf_work_item_flush(_g: u64, _workitem: u64) {}

extern "win64" fn wdf_object_delete(_g: u64, object: u64) {
    // SAFETY: single-threaded service access.
    unsafe {
        let _ = wdf().delete_object(WdfHandle(object));
    }
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
    // KMDF hardware extensions.
    set(
        wt::IDX_WDF_INTERRUPT_CREATE,
        wdf_interrupt_create as usize as u64,
    );
    set(
        wt::IDX_WDF_INTERRUPT_QUEUE_DPC_FOR_ISR,
        wdf_interrupt_queue_dpc_for_isr as usize as u64,
    );
    set(
        wt::IDX_WDF_INTERRUPT_ENABLE,
        wdf_interrupt_enable as usize as u64,
    );
    set(
        wt::IDX_WDF_INTERRUPT_DISABLE,
        wdf_interrupt_disable as usize as u64,
    );
    set(
        wt::IDX_WDF_INTERRUPT_GET_DEVICE,
        wdf_interrupt_get_device as usize as u64,
    );
    set(
        wt::IDX_WDF_DMA_ENABLER_CREATE,
        wdf_dma_enabler_create as usize as u64,
    );
    set(
        wt::IDX_WDF_DMA_ENABLER_GET_MAXIMUM_LENGTH,
        wdf_dma_enabler_get_maximum_length as usize as u64,
    );
    set(
        wt::IDX_WDF_COMMON_BUFFER_CREATE,
        wdf_common_buffer_create as usize as u64,
    );
    set(
        wt::IDX_WDF_COMMON_BUFFER_GET_ALIGNED_VIRTUAL_ADDRESS,
        wdf_common_buffer_get_virtual_address as usize as u64,
    );
    set(
        wt::IDX_WDF_COMMON_BUFFER_GET_ALIGNED_LOGICAL_ADDRESS,
        wdf_common_buffer_get_logical_address as usize as u64,
    );
    set(
        wt::IDX_WDF_COMMON_BUFFER_GET_LENGTH,
        wdf_common_buffer_get_length as usize as u64,
    );
    set(wt::IDX_WDF_TIMER_CREATE, wdf_timer_create as usize as u64);
    set(wt::IDX_WDF_TIMER_START, wdf_timer_start as usize as u64);
    set(wt::IDX_WDF_TIMER_STOP, wdf_timer_stop as usize as u64);
    set(
        wt::IDX_WDF_TIMER_GET_PARENT_OBJECT,
        wdf_timer_get_parent_object as usize as u64,
    );
    set(
        wt::IDX_WDF_WORK_ITEM_CREATE,
        wdf_work_item_create as usize as u64,
    );
    set(
        wt::IDX_WDF_WORK_ITEM_ENQUEUE,
        wdf_work_item_enqueue as usize as u64,
    );
    set(
        wt::IDX_WDF_WORK_ITEM_GET_PARENT_OBJECT,
        wdf_work_item_get_parent_object as usize as u64,
    );
    set(
        wt::IDX_WDF_WORK_ITEM_FLUSH,
        wdf_work_item_flush as usize as u64,
    );
    set(wt::IDX_WDF_OBJECT_DELETE, wdf_object_delete as usize as u64);
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

static LAST_STATUS: AtomicU64 = AtomicU64::new(0);
static LAST_INFO: AtomicU64 = AtomicU64::new(0);

/// Present a buffered IOCTL + invoke `EvtIoDeviceControl`; returns the shared system buffer
/// (0 on failure). For a pending IOCTL the driver returns without completing — the caller
/// then drives the hardware event before reading `LAST_STATUS`/`LAST_INFO` + the buffer.
unsafe fn dispatch_ioctl(device: u64, ioctl: u32, input: &[u8], out_cap: u64) -> u64 {
    LAST_STATUS.store(0x0000_0103, Ordering::Relaxed); // STATUS_PENDING default
    LAST_INFO.store(0, Ordering::Relaxed);
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
    let (request, dispatch) = match wdf().present_ioctl(WdfHandle(device), irp, ioctl, buffers) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let Some(d) = dispatch else { return 0 };
    let f: extern "win64" fn(u64, u64, u64, u64, u32) =
        core::mem::transmute(d.evt_io_device_control as *const ());
    f(d.queue.0, request.0, out_cap, input.len() as u64, ioctl);
    sysbuf
}

unsafe fn read_out(sysbuf: u64, out_cap: u64) -> [u8; 64] {
    let mut out = [0u8; 64];
    if sysbuf != 0 {
        for (i, o) in out.iter_mut().enumerate().take(out_cap.min(64) as usize) {
            *o = core::ptr::read_volatile((sysbuf + i as u64) as *const u8);
        }
    }
    out
}

fn last_status() -> i32 {
    LAST_STATUS.load(Ordering::Relaxed) as i32
}
fn last_info() -> u64 {
    LAST_INFO.load(Ordering::Relaxed)
}

/// The simulated DMA engine: on a START command, decode the common-buffer logical address the
/// driver programmed, checksum it into the RESULT register, raise the interrupt (RE §7).
unsafe fn run_sim_dma() {
    let bank = core::ptr::addr_of_mut!(MMIO) as u64;
    let command = core::ptr::read_volatile((bank + REG_DMA_COMMAND) as *const u32);
    if command != 1 {
        return;
    }
    let lo = core::ptr::read_volatile((bank + REG_DMA_LO) as *const u32);
    let hi = core::ptr::read_volatile((bank + REG_DMA_HI) as *const u32);
    let logical = ((hi as u64) << 32) | lo as u64;
    let length = core::ptr::read_volatile((bank + REG_DMA_LENGTH) as *const u32);
    let mut result: u32 = 0;
    if let Ok(va) = wdf().dma_decode_logical(logical, length as u64) {
        for i in 0..length as u64 {
            result = result.wrapping_add(core::ptr::read_volatile((va + i) as *const u8) as u32);
        }
    }
    core::ptr::write_volatile((bank + REG_DMA_RESULT) as *mut u32, result);
    core::ptr::write_volatile((bank + REG_STATUS) as *mut u32, STATUS_INT_PENDING);
    core::ptr::write_volatile((bank + REG_DMA_COMMAND) as *mut u32, 0);
}

/// Deliver the device interrupt to the driver: EvtInterruptIsr → (if it queues) EvtInterruptDpc
/// (RE §2). Returns whether the ISR claimed it.
unsafe fn deliver_interrupt() -> bool {
    let interrupt = host().interrupt;
    let Some(isr) = wdf().fire_interrupt(WdfHandle(interrupt)) else {
        return false;
    };
    let isr_fn: extern "win64" fn(u64, u32) -> u8 = core::mem::transmute(isr as *const ());
    let claimed = isr_fn(interrupt, 0);
    if claimed == 0 {
        return false;
    }
    if let Some(dpc) = wdf().interrupt_take_dpc(WdfHandle(interrupt)) {
        let dpc_fn: extern "win64" fn(u64, u64) = core::mem::transmute(dpc as *const ());
        dpc_fn(interrupt, host().device);
    }
    true
}

/// Fire the WDF timer → EvtTimerFunc (RE §2).
unsafe fn fire_timer() {
    if let Some(evt) = wdf().timer_fire(WdfHandle(host().timer)) {
        let f: extern "win64" fn(u64) = core::mem::transmute(evt as *const ());
        f(host().timer);
    }
}
/// Run the WDF work item → EvtWorkItem (RE §2).
unsafe fn run_workitem() {
    if let Some(evt) = wdf().workitem_run(WdfHandle(host().workitem)) {
        let f: extern "win64" fn(u64) = core::mem::transmute(evt as *const ());
        f(host().workitem);
    }
}

unsafe fn run() {
    WDF = Some(WdfRuntime::new());
    // Seed the identity register.
    core::ptr::write_unaligned(core::ptr::addr_of_mut!(MMIO) as *mut u32, KMDF_MAGIC);
    install_function_table();

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

    // --- Framework AddDevice → EvtDriverDeviceAdd -----------------------------
    let init_id = wdf().add_device(0xFED0_0000 /* PDO */);
    let device_init_blob = alloc_blob();
    core::ptr::write_unaligned(device_init_blob as *mut u64, init_id as u64);
    host().device_init_blob = device_init_blob;
    let driver = wdf().driver().unwrap();
    let add_status = call2(evt_device_add, driver.0, device_init_blob);
    let device = nt_wdf_object::WdfHandle(host().device);
    check(
        b"evt_device_add_created_device_queue",
        add_status == 0 && host().device != 0 && host().queue != 0,
    );

    // EvtDeviceAdd also created the interrupt, timer, and work item.
    check(
        b"add_device_created_hw_objects",
        add_status == 0 && host().interrupt != 0 && host().timer != 0 && host().workitem != 0,
    );

    // --- START_DEVICE → EvtDevicePrepareHardware ------------------------------
    let res_list = build_resource_list();
    let prepare = wdf().prepare_hardware(device).unwrap_or(0);
    let prep_status = if prepare != 0 {
        call3(prepare, device.0, res_list, res_list)
    } else {
        STATUS_UNSUCCESSFUL
    };
    // The framework connects the interrupt after PrepareHardware succeeds (§7.4).
    if prep_status == 0 {
        wdf().connect_device_interrupts(device);
    }
    check(
        b"prepare_hardware_dma_enabler_common_buffer",
        prep_status == 0 && host().dma_enabler != 0 && host().common_buffer != 0,
    );

    // --- D0 entry (the driver calls WdfInterruptEnable) -----------------------
    let (d0_entry, _released) = wdf().set_device_power(device, true).unwrap();
    let d0_status = if d0_entry != 0 {
        call2(d0_entry, device.0, 1 /* prev = D3 */)
    } else {
        STATUS_UNSUCCESSFUL
    };
    check(b"d0_entry_enables_interrupt", d0_status == 0);

    // --- GET_ID / GET_INFO ----------------------------------------------------
    let sysbuf = dispatch_ioctl(device.0, IOCTL_GET_ID, &[], 4);
    let id = core::ptr::read_unaligned(read_out(sysbuf, 4).as_ptr() as *const u32);
    check(
        b"ioctl_get_id",
        last_status() == 0 && last_info() == 4 && id == KMDF_MAGIC,
    );

    let sysbuf = dispatch_ioctl(device.0, IOCTL_GET_INFO, &[], 0x3c);
    let info = read_out(sysbuf, 0x3c);
    let prepared = core::ptr::read_unaligned(info.as_ptr() as *const u32);
    let powered = core::ptr::read_unaligned(info.as_ptr().add(4) as *const u32);
    let mapped = core::ptr::read_unaligned(info.as_ptr().add(8) as *const u32);
    check(
        b"ioctl_get_info",
        last_status() == 0 && last_info() == 0x3c && prepared == 1 && powered == 1 && mapped == 1,
    );

    // READ_REG32 offset 0 → the ID register (via the driver's WdfCommonBuffer-independent path).
    let sysbuf = dispatch_ioctl(device.0, IOCTL_READ_REG32, &0u64.to_le_bytes(), 8);
    let reg_val = core::ptr::read_unaligned(read_out(sysbuf, 8).as_ptr().add(4) as *const u32);
    check(
        b"ioctl_read_reg32_id",
        last_status() == 0 && reg_val == KMDF_MAGIC,
    );

    // --- COMMON-BUFFER DMA ROUNDTRIP: IOCTL → sim DMA → interrupt → DPC → complete
    let mut rt_in = [0u8; 24];
    rt_in[0..4].copy_from_slice(&16u32.to_le_bytes()); // length
    rt_in[4..8].copy_from_slice(&0x10u32.to_le_bytes()); // seed
    let sysbuf = dispatch_ioctl(device.0, IOCTL_DMA_ROUNDTRIP, &rt_in, 0x18);
    let pended = last_status() == 0x0000_0103;
    run_sim_dma();
    let claimed = deliver_interrupt();
    // The driver's ISR acknowledged the interrupt (wrote the INT_ACK register).
    let acked =
        core::ptr::read_volatile((core::ptr::addr_of!(MMIO) as u64 + REG_INT_ACK) as *const u32)
            == 1;
    let out = read_out(sysbuf, 0x18);
    let result = core::ptr::read_unaligned(out.as_ptr().add(8) as *const u32);
    let isr_count = core::ptr::read_unaligned(out.as_ptr().add(0xc) as *const u32);
    // The sim checksums (i+seed) for i in 0..16 = sum(0x10..=0x1f) = 376.
    let expected: u32 = (0..16u32).map(|i| (i + 0x10) & 0xff).sum();
    check(
        b"dma_roundtrip_isr_dpc_complete",
        pended
            && claimed
            && acked
            && last_status() == 0
            && last_info() == 0x18
            && result == expected
            && isr_count == 1,
    );
    let (ic, dc) = wdf().interrupt_counts(WdfHandle(host().interrupt)).unwrap();
    check(b"interrupt_and_dpc_counted", ic == 1 && dc == 1);

    // --- TIMER IOCTL: pends, timer fires → completes --------------------------
    let sysbuf = dispatch_ioctl(device.0, IOCTL_TIMER, &[], 4);
    let pended = last_status() == 0x0000_0103;
    fire_timer();
    let _ = read_out(sysbuf, 4);
    check(
        b"timer_ioctl_completes",
        pended
            && last_status() == 0
            && last_info() == 4
            && wdf().timer_fired_count(WdfHandle(host().timer)) == Some(1),
    );

    // --- WORKITEM IOCTL: pends, work item runs → completes --------------------
    let sysbuf = dispatch_ioctl(device.0, IOCTL_WORKITEM, &[], 4);
    let pended = last_status() == 0x0000_0103;
    run_workitem();
    let _ = read_out(sysbuf, 4);
    check(
        b"workitem_ioctl_completes",
        pended
            && last_status() == 0
            && last_info() == 4
            && wdf().workitem_ran_count(WdfHandle(host().workitem)) == Some(1),
    );

    // --- D0 exit + ReleaseHardware + REMOVE -----------------------------------
    let (d0_exit, _) = wdf().set_device_power(device, false).unwrap();
    let exit_status = if d0_exit != 0 {
        call2(d0_exit, device.0, 3 /* target = D3 */)
    } else {
        STATUS_UNSUCCESSFUL
    };
    // In D3 the interrupt is disabled → an injected interrupt is dropped (§14.3).
    let dropped = !deliver_interrupt();
    let release = wdf().release_hardware(device).unwrap_or(0);
    let rel_status = if release != 0 {
        call2(release, device.0, res_list)
    } else {
        STATUS_UNSUCCESSFUL
    };
    check(
        b"d0_exit_release_hardware",
        exit_status == 0 && dropped && rel_status == 0,
    );

    // REMOVE: delete the device (cascades to queue + hardware objects).
    let pending = wdf().delete_object(device).unwrap_or_default();
    check(
        b"remove_deletes_device_tree",
        wdf().live_object_count() == 1 && pending.is_empty(),
    );
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);

    print_str(b"[ntos-dhw] WDF Driver Host: real KmdfDmaInterruptTest.sys (KMDF 1.15 HW)\n");
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
