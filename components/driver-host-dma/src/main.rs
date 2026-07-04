//! `ntos-driver-host-dma` — the DMA + Power + PnP Driver Host as a seL4 component.
//!
//! Loads the real `DmaPnpPowerTest.sys` (W^X + NX) and drives the full NT DMA device
//! lifecycle (spec: NT DMA/MDL/IOMMU, Milestone 14) against in-process PnP + Power + DMA
//! + MDL managers:
//!
//! ```text
//! START_DEVICE (PnP) -> device D0; driver IoGetDmaAdapter + AllocateCommonBuffer
//! GET_DMA_INFO       -> 64 map registers, 4096-byte common buffer allocated
//! MDL_SELF_TEST      -> IoAllocateMdl + MmBuildMdlForNonPagedPool + Get System Address
//! COMMON_ROUNDTRIP   -> driver programs DMA; sim device decodes the logical address
//!                       (IOMMU facade), inverts the common buffer; interrupt -> DPC
//! DIRECT_BUFFER_FILL -> METHOD_OUT_DIRECT: driver fills IRP->MdlAddress
//! SET_POWER D3/D0    -> DMA rejected in D3, resumes in D0
//! REMOVE_DEVICE      -> common buffer freed, adapter put, DMA resources revoked
//! ```

#![no_std]
#![no_main]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use nt_cm_resources::{InterruptDescriptor, MemoryDescriptor};
use nt_dma_manager::{DmaManager, DmaOwner};
use nt_kernel_exec::{CompleteResult, EventKind, FakeClock, KernelExecRuntime};
use nt_mdl::MdlRegistry;
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

static DMA_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/DmaPnpPowerTest.sys");

const CODE_VADDR: u64 = 0x0000_0001_4000_0000;
const STATUS_PENDING: i32 = 0x0000_0103;
const STATUS_DEVICE_NOT_READY: i32 = 0xC000_00A3u32 as i32;

const DRIVER_HOST_ID: u64 = 1;
const DEVICE_OBJECT_ID: u64 = 10;
const INT_VECTOR: u32 = 5;
const INT_RESOURCE_ID: u64 = 200;
const MEM_RESOURCE_ID: u64 = 100;

// DmaPnpPowerTest.sys register bank + commands (§14.2/§14.3).
const DMA_REG_STATUS: u64 = 0x08;
const DMA_REG_DMA_LO: u64 = 0x10;
const DMA_REG_DMA_HI: u64 = 0x14;
const DMA_REG_LENGTH: u64 = 0x18;
const DMA_REG_COMMAND: u64 = 0x1c;
const DMA_REG_RESULT: u64 = 0x20;
const DMA_STATUS_DONE: u32 = 0x0000_0001;
const DMA_CMD_COMMON_INVERT: u32 = 1;
const DMA_ID_VALUE: u32 = 0x444d_4131; // "DMA1"
const COMMON_BUFFER_LEN: u32 = 4096;

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
static mut DMA: Option<DmaManager> = None;
static mut MDL: Option<MdlRegistry> = None;

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
unsafe fn dma() -> &'static mut DmaManager {
    (*core::ptr::addr_of_mut!(DMA)).as_mut().unwrap()
}
unsafe fn mdl() -> &'static mut MdlRegistry {
    (*core::ptr::addr_of_mut!(MDL)).as_mut().unwrap()
}

fn owner() -> ResourceOwner {
    ResourceOwner::new(DRIVER_HOST_ID, DEVICE_OBJECT_ID)
}
fn dma_owner() -> DmaOwner {
    DmaOwner::new(DRIVER_HOST_ID, DEVICE_OBJECT_ID)
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
    // DMA state.
    dma_adapter_id: u64,
    dma_adapter_blob: u64,
    common_buffer_va: u64,
    common_buffer_logical: u64,
    common_buffer_len: u32,
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
    dma_adapter_id: 0,
    dma_adapter_blob: 0,
    common_buffer_va: 0,
    common_buffer_logical: 0,
    common_buffer_len: 0,
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

// --- DMA + MDL exports (spec §8, §9, §11) -----------------------------------

fn alloc_bytes(size: usize) -> u64 {
    let layout = core::alloc::Layout::from_size_align(size.max(1), 16).unwrap();
    // SAFETY: nonzero size, valid align.
    unsafe { alloc::alloc::alloc_zeroed(layout) as u64 }
}

/// The common buffer — a dedicated page-aligned static (real `AllocateCommonBuffer`
/// returns page-aligned memory; the driver + simulated device both access it).
#[repr(align(4096))]
struct CommonBuf([u8; 4096]);
static mut COMMON_BUF: CommonBuf = CommonBuf([0; 4096]);

/// `IoGetDmaAdapter(Pdo, DeviceDescription, NumberOfMapRegisters)` — build a
/// `DMA_ADAPTER` + `DMA_OPERATIONS` table and register the adapter (spec §9).
#[allow(function_casts_as_integer)]
extern "win64" fn ntos_io_get_dma_adapter(
    _pdo: u64,
    _desc: u64,
    num_map_registers_out: *mut u32,
) -> u64 {
    // SAFETY: single-threaded service access; `num_map_registers_out` a driver ptr.
    unsafe {
        let adapter_id = dma().register_adapter(dma_owner(), true, COMMON_BUFFER_LEN as u64, true);
        dh().dma_adapter_id = adapter_id;
        // DMA_OPERATIONS: Size@0, PutDmaAdapter@8, AllocateCommonBuffer@16,
        // FreeCommonBuffer@24 (the rest left null — the driver null-checks).
        let ops = alloc_bytes(256);
        core::ptr::write_unaligned(ops as *mut u32, 256);
        core::ptr::write_unaligned((ops + 8) as *mut u64, ntos_dma_put_adapter as usize as u64);
        core::ptr::write_unaligned(
            (ops + 16) as *mut u64,
            ntos_dma_alloc_common_buffer as usize as u64,
        );
        core::ptr::write_unaligned(
            (ops + 24) as *mut u64,
            ntos_dma_free_common_buffer as usize as u64,
        );
        // DMA_ADAPTER: Version@0, Size@2, DmaOperations@8.
        let adapter = alloc_bytes(64);
        core::ptr::write_unaligned(adapter as *mut u16, 1);
        core::ptr::write_unaligned((adapter + 2) as *mut u16, 64);
        core::ptr::write_unaligned((adapter + 8) as *mut u64, ops);
        dh().dma_adapter_blob = adapter;
        if !num_map_registers_out.is_null() {
            core::ptr::write_unaligned(
                num_map_registers_out,
                dma().num_map_registers(adapter_id).unwrap_or(64),
            );
        }
        adapter
    }
}

/// `AllocateCommonBuffer(Adapter, Length, LogicalAddress, CacheEnabled)` → a CPU
/// virtual address; writes the fake logical address (spec §11.1).
extern "win64" fn ntos_dma_alloc_common_buffer(
    _adapter: u64,
    length: u32,
    logical_out: *mut i64,
    _cache: u8,
) -> u64 {
    // SAFETY: single-threaded; `logical_out` a driver pointer.
    unsafe {
        // Page-aligned common buffer backing (§11.1).
        let buf = core::ptr::addr_of_mut!(COMMON_BUF) as u64;
        core::ptr::write_bytes(buf as *mut u8, 0, (length as usize).min(4096));
        match dma().alloc_common_buffer(dma_owner(), dh().dma_adapter_id, length as u64, buf) {
            Ok(g) => {
                dh().common_buffer_va = buf;
                dh().common_buffer_logical = g.logical_base;
                dh().common_buffer_len = length;
                if !logical_out.is_null() {
                    core::ptr::write_unaligned(logical_out, g.logical_base as i64);
                }
                buf
            }
            Err(_) => 0,
        }
    }
}

/// `FreeCommonBuffer(Adapter, Length, LogicalAddress, VirtualAddress, CacheEnabled)`.
extern "win64" fn ntos_dma_free_common_buffer(
    _adapter: u64,
    length: u32,
    logical: i64,
    _virtual: u64,
    _cache: u8,
) {
    // SAFETY: single-threaded service access.
    unsafe {
        let _ = dma().free_common_buffer(dma_owner(), logical as u64, length as u64);
        dh().common_buffer_va = 0;
    }
}

/// `PutDmaAdapter(Adapter)`.
extern "win64" fn ntos_dma_put_adapter(_adapter: u64) {
    // SAFETY: single-threaded service access.
    unsafe {
        dma().put_adapter(dh().dma_adapter_id);
        dh().dma_adapter_id = 0;
    }
}

/// `IoAllocateMdl(VirtualAddress, Length, ...)` → a driver-visible MDL projection.
/// Stashes the canonical MDL id in the (unused) `Next` field.
extern "win64" fn ntos_io_allocate_mdl(
    va: u64,
    length: u32,
    _secondary: u8,
    _charge: u8,
    _irp: u64,
) -> u64 {
    // SAFETY: single-threaded service access.
    unsafe {
        let m = alloc_bytes(nt_mdl::MDL_SIZE);
        let id = mdl().allocate(va, length);
        core::ptr::write_unaligned((m + nt_mdl::MDL_OFF_NEXT) as *mut u64, id);
        core::ptr::write_unaligned((m + nt_mdl::MDL_OFF_START_VA) as *mut u64, va & !0xFFF);
        core::ptr::write_unaligned((m + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32, length);
        core::ptr::write_unaligned(
            (m + nt_mdl::MDL_OFF_BYTE_OFFSET) as *mut u32,
            (va & 0xFFF) as u32,
        );
        m
    }
}

/// `MmBuildMdlForNonPagedPool(Mdl)` — mark the MDL nonpaged + set `MappedSystemVa`.
extern "win64" fn ntos_mm_build_mdl_for_nonpaged_pool(m: u64) {
    // SAFETY: `m` is an MDL projection we allocated.
    unsafe {
        let id = core::ptr::read_unaligned((m + nt_mdl::MDL_OFF_NEXT) as *const u64);
        let _ = mdl().build_for_nonpaged(id);
        let flags = core::ptr::read_unaligned((m + nt_mdl::MDL_OFF_FLAGS) as *const i16);
        core::ptr::write_unaligned(
            (m + nt_mdl::MDL_OFF_FLAGS) as *mut i16,
            flags | nt_mdl::MDL_SOURCE_IS_NONPAGED_POOL,
        );
        let start = core::ptr::read_unaligned((m + nt_mdl::MDL_OFF_START_VA) as *const u64);
        let off = core::ptr::read_unaligned((m + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32);
        core::ptr::write_unaligned(
            (m + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *mut u64,
            start + off as u64,
        );
    }
}

/// `MmMapLockedPagesSpecifyCache(...)` — the fallback path for
/// `MmGetSystemAddressForMdlSafe`; returns the mapped VA.
extern "win64" fn ntos_mm_map_locked_pages(
    m: u64,
    _mode: u8,
    _cache: u32,
    _va: u64,
    _b: u32,
    _p: u32,
) -> u64 {
    // SAFETY: `m` is an MDL projection we allocated.
    unsafe {
        let mapped =
            core::ptr::read_unaligned((m + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *const u64);
        if mapped != 0 {
            return mapped;
        }
        let start = core::ptr::read_unaligned((m + nt_mdl::MDL_OFF_START_VA) as *const u64);
        let off = core::ptr::read_unaligned((m + nt_mdl::MDL_OFF_BYTE_OFFSET) as *const u32);
        start + off as u64
    }
}

/// `IoFreeMdl(Mdl)`.
extern "win64" fn ntos_io_free_mdl(m: u64) {
    // SAFETY: `m` is an MDL projection we allocated.
    unsafe {
        let id = core::ptr::read_unaligned((m + nt_mdl::MDL_OFF_NEXT) as *const u64);
        let _ = mdl().free(id);
    }
}

/// `ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag)`.
extern "win64" fn ntos_ex_allocate_pool(_pool: u32, size: u64, _tag: u32) -> u64 {
    alloc_bytes(size as usize)
}

/// `ExFreePoolWithTag(P, Tag)` — leak (short-lived component).
extern "win64" fn ntos_ex_free_pool(_p: u64, _tag: u32) {}

extern "win64" fn ntos_stub() -> i32 {
    0
}

#[allow(function_casts_as_integer)]
fn export_addr(name: &str) -> u64 {
    match name {
        "PoCallDriver" => ntos_po_call_driver as usize as u64,
        "PoStartNextPowerIrp" => ntos_po_start_next_power_irp as usize as u64,
        "PoSetPowerState" => ntos_po_set_power_state as usize as u64,
        "IoGetDmaAdapter" => ntos_io_get_dma_adapter as usize as u64,
        "IoAllocateMdl" => ntos_io_allocate_mdl as usize as u64,
        "IoFreeMdl" => ntos_io_free_mdl as usize as u64,
        "MmBuildMdlForNonPagedPool" => ntos_mm_build_mdl_for_nonpaged_pool as usize as u64,
        "MmMapLockedPagesSpecifyCache" => ntos_mm_map_locked_pages as usize as u64,
        "ExAllocatePoolWithTag" => ntos_ex_allocate_pool as usize as u64,
        "ExFreePoolWithTag" => ntos_ex_free_pool as usize as u64,
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

/// Run the simulated DMA device: read the command the driver programmed into the
/// register bank, decode the logical address to the common buffer via the DMA Manager
/// (the IOMMU-facade lookup), perform the transfer, then mark done (spec §14).
unsafe fn run_dma_command() {
    let bank = sim().mmio_ptr() as u64;
    let command = core::ptr::read_volatile((bank + DMA_REG_COMMAND) as *const u32);
    if command == DMA_CMD_COMMON_INVERT {
        let lo = core::ptr::read_volatile((bank + DMA_REG_DMA_LO) as *const u32);
        let hi = core::ptr::read_volatile((bank + DMA_REG_DMA_HI) as *const u32);
        let logical = ((hi as u64) << 32) | lo as u64;
        let length = core::ptr::read_volatile((bank + DMA_REG_LENGTH) as *const u32);
        if let Ok(va) = dma().decode_logical(logical, length as u64) {
            for i in 0..length as u64 {
                let p = (va + i) as *mut u8;
                core::ptr::write_volatile(p, !core::ptr::read_volatile(p));
            }
            core::ptr::write_volatile((bank + DMA_REG_RESULT) as *mut u32, length);
        }
        core::ptr::write_volatile((bank + DMA_REG_STATUS) as *mut u32, DMA_STATUS_DONE);
        core::ptr::write_volatile((bank + DMA_REG_COMMAND) as *mut u32, 0);
    }
}

/// Build a driver-visible MDL projection over `[va, va+len)`, nonpaged + mapped.
unsafe fn build_output_mdl(va: u64, len: u32) -> u64 {
    let m = alloc_bytes(nt_mdl::MDL_SIZE);
    let id = mdl().allocate(va, len);
    let _ = mdl().build_for_nonpaged(id);
    core::ptr::write_unaligned((m + nt_mdl::MDL_OFF_NEXT) as *mut u64, id);
    core::ptr::write_unaligned(
        (m + nt_mdl::MDL_OFF_FLAGS) as *mut i16,
        nt_mdl::MDL_SOURCE_IS_NONPAGED_POOL,
    );
    core::ptr::write_unaligned((m + nt_mdl::MDL_OFF_MAPPED_SYSTEM_VA) as *mut u64, va);
    core::ptr::write_unaligned((m + nt_mdl::MDL_OFF_START_VA) as *mut u64, va & !0xFFF);
    core::ptr::write_unaligned((m + nt_mdl::MDL_OFF_BYTE_COUNT) as *mut u32, len);
    core::ptr::write_unaligned(
        (m + nt_mdl::MDL_OFF_BYTE_OFFSET) as *mut u32,
        (va & 0xFFF) as u32,
    );
    m
}

/// Dispatch a `METHOD_OUT_DIRECT` IOCTL: the I/O Manager exposes the output buffer as
/// `IRP->MdlAddress` (spec §16.1). Returns `(status, output[128])`.
unsafe fn dispatch_direct(
    driver_object: u64,
    device_object: u64,
    code: u32,
    out_len: u32,
) -> (i32, [u8; 128]) {
    let irp = alloc_blob();
    let stack = alloc_blob();
    let sysbuf = Box::leak(Box::new([0u8; 64])) as *mut u8;
    let out_buf = alloc_bytes(out_len.max(1) as usize);
    let mdl_blob = build_output_mdl(out_buf, out_len);

    core::ptr::write_unaligned(irp as *mut i16, 6);
    core::ptr::write_unaligned((irp + 8) as *mut u64, mdl_blob); // IRP->MdlAddress
    core::ptr::write_unaligned((irp + 24) as *mut u64, sysbuf as u64);
    core::ptr::write_unaligned((irp + 184) as *mut u64, stack);
    core::ptr::write_unaligned(stack as *mut u8, 0x0e); // IRP_MJ_DEVICE_CONTROL
    core::ptr::write_unaligned((stack + 8) as *mut u32, out_len);
    core::ptr::write_unaligned((stack + 16) as *mut u32, 0);
    core::ptr::write_unaligned((stack + 24) as *mut u32, code);

    dh().completed = false;
    dh().last_status = 0;
    rt().mark_irp_pending(irp, code as u64);

    let routine = core::ptr::read_unaligned((driver_object + 112 + 0x0e * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let status = f(device_object, irp);

    let mut out = [0u8; 128];
    for (i, o) in out.iter_mut().enumerate().take(out_len as usize) {
        *o = core::ptr::read_volatile((out_buf + i as u64) as *const u8);
    }
    (status, out)
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
    DMA = Some(DmaManager::new());
    MDL = Some(MdlRegistry::new());

    let pe = match nt_pe_loader::PeFile::parse(DMA_SYS) {
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
    core::ptr::write_volatile(sim().mmio_ptr() as *mut u32, DMA_ID_VALUE); // seed ID reg "DMA1"

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
    // The driver acquired a DMA adapter + common buffer during START (spec §20.1).
    check(
        b"dma_adapter_and_common_buffer",
        dh().dma_adapter_id != 0 && dh().common_buffer_va != 0 && dh().common_buffer_len == 4096,
    );

    // GET_ID → "DMA1".
    let (st, _i, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_2140, &[], 8);
    let id = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_get_id", st == 0 && id == DMA_ID_VALUE);

    // GET_DMA_INFO → NumberOfMapRegisters=64, CommonBufferLength=4096, allocated.
    let (st, _i, out) = dispatch(driver_object, fdo, 0x0e, 0x0022_2144, &[], 24);
    let n_map = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    let cb_len = core::ptr::read_unaligned(out.as_ptr().add(4) as *const u32);
    let cb_alloc = core::ptr::read_unaligned(out.as_ptr().add(16) as *const u32);
    check(
        b"dma_info",
        st == 0 && n_map == 64 && cb_len == 4096 && cb_alloc == 1,
    );

    // MDL self-test: IoAllocateMdl + MmBuildMdlForNonPagedPool + MmGetSystemAddressForMdlSafe.
    let (st, _i, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_2168, &[], 4);
    check(b"mdl_self_test", st == 0);

    // COMMON_BUFFER_ROUNDTRIP: driver fills the common buffer, programs the DMA regs;
    // the sim device inverts it via the logical address; interrupt → DPC completes.
    let mut rt_in = [0u8; 24];
    rt_in[0..4].copy_from_slice(&64u32.to_le_bytes()); // Length
    rt_in[4..8].copy_from_slice(&0x10u32.to_le_bytes()); // Pattern
    let (st, _i, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_2164, &rt_in, 24);
    let pended = st == STATUS_PENDING;
    run_dma_command();
    let injected = inject_interrupt(INT_VECTOR);
    check(
        b"common_buffer_roundtrip",
        pended && injected && dh().completed && dh().last_status == 0,
    );

    // DIRECT_BUFFER_FILL (METHOD_OUT_DIRECT): the driver fills the IRP->MdlAddress buffer.
    let (st, out) = dispatch_direct(driver_object, fdo, 0x0022_216E, 64);
    let filled = out.iter().take(64).any(|&b| b != 0);
    check(b"direct_buffer_fill_via_mdl", st == 0 && filled);

    // --- D3: DMA command is rejected -----------------------------------------
    let d3_ok = transition_device_power(driver_object, fdo, devnode, DevicePowerState::D3);
    let (st, _i, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_2164, &rt_in, 24);
    check(
        b"dma_rejected_in_d3",
        d3_ok && !dh().powered && st != STATUS_PENDING,
    );

    // --- D0: DMA resumes -----------------------------------------------------
    let d0_ok = transition_device_power(driver_object, fdo, devnode, DevicePowerState::D0);
    let (st, _i, _o) = dispatch(driver_object, fdo, 0x0e, 0x0022_2164, &rt_in, 24);
    let pended = st == STATUS_PENDING;
    run_dma_command();
    let injected = inject_interrupt(INT_VECTOR);
    check(
        b"dma_resumes_in_d0",
        d0_ok && dh().powered && pended && injected && dh().completed,
    );

    // --- REMOVE_DEVICE: driver frees common buffer + puts adapter ------------
    let cb_logical = dh().common_buffer_logical;
    let _ = pnp().transition(devnode, DeviceState::RemovePending);
    let _ = pwr().mark_remove(devnode);
    let mapping_id = dh().mmio_mapping_id;
    let remove_status = dispatch_pnp(driver_object, fdo, IRP_MN_REMOVE_DEVICE, 0, 0);
    let _ = pnp().transition(devnode, DeviceState::Removed);
    pwr().unregister_device(devnode);
    // The driver freed the common buffer (its logical address no longer decodes);
    // the DMA Manager revokes anything left for a defensive cleanup (§15.3).
    dma().revoke_owner(dma_owner());
    check(
        b"remove_revokes_dma",
        remove_status == 0
            && !rm().mapping_valid(mapping_id)
            && dma().decode_logical(cb_logical, 4).is_err(),
    );

    check(b"callbacks_ran_at_correct_irql", dh().bad_irql == 0);
    let _ = add_status;
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);

    print_str(b"[ntos-dhd] DMA Driver Host: real DmaPnpPowerTest.sys lifecycle\n");
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
