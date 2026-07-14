//! Hosting a REAL Windows `.sys` driver binary in the isolated seL4 driver host.
//!
//! The executive (which owns the heap + untyped) parses/maps/relocates the PE and patches
//! its import table to the `extern "win64"` ntoskrnl stubs below (wired to the real
//! seL4-granted resources); the isolated host then calls DriverEntry → AddDevice →
//! IRP_MN_START_DEVICE with our real CM_RESOURCE_LIST. The driver is crash-contained in
//! its own CSpace/VSpace and reaches real hardware only through `MmMapIoSpace` returning
//! the real NIC BAR.

use crate::*;
use nt_pe_loader::{ImportRef, PeFile};

/// Where the PE image is mapped (R+W+X) in BOTH the executive (to load it) and the host
/// (to run it) — same vaddr so the relocation base matches. Lives in the relocated shared
/// "cluster" region (WORK_CLUSTER_BASE, 0x1040_0000), well clear of the 64 MiB ELF reserve.
pub const CODE_VA: u64 = 0x0000_0100_104A_0000;
/// A RW "guest arena" mapped in both — holds all mutable host state (`.bss` is RO in the
/// host) + the blobs the stubs allocate (DRIVER_OBJECT, device objects, IRP, ...).
pub const ARENA_VADDR: u64 = 0x0000_0100_105F_E000;
/// Frame counts: the PE image is 7 pages (size 0x7000) — map 8 with margin; the arena 2.
pub const PE_FRAMES: u64 = 8;
pub const ARENA_FRAMES: u64 = 2;

const IRP_MJ_PNP: u64 = 0x1b;
const IRP_MN_START_DEVICE: u8 = 0x00;

// Arena header offsets (state the stubs read/write; the executive reads it back after).
const A_BUMP: u64 = 0; // u64 bump pointer
const A_MMIO_PHYS: u64 = 8; // u64 phys MmMapIoSpace was called with
const A_MMIO_RET: u64 = 16; // u64 vaddr it returned
const A_ISR: u64 = 24; // u64 ISR routine IoConnectInterrupt recorded
const A_ISR_CTX: u64 = 32; // u64 ISR context
const A_DEVICE: u64 = 40; // u64 last IoCreateDevice object (the FDO)
const A_HDR_END: u64 = 0x40; // blob allocations start here

unsafe fn arena_init() {
    core::ptr::write_volatile((ARENA_VADDR + A_BUMP) as *mut u64, ARENA_VADDR + A_HDR_END);
    for off in [A_MMIO_PHYS, A_MMIO_RET, A_ISR, A_ISR_CTX, A_DEVICE] {
        core::ptr::write_volatile((ARENA_VADDR + off) as *mut u64, 0);
    }
}

unsafe fn arena_alloc(size: u64) -> u64 {
    let bump = ARENA_VADDR + A_BUMP;
    let mut p = core::ptr::read_volatile(bump as *const u64);
    p = (p + 15) & !15;
    core::ptr::write_volatile(bump as *mut u64, p + size);
    let mut i = 0;
    while i < size {
        core::ptr::write_volatile((p + i) as *mut u8, 0);
        i += 1;
    }
    p
}

// --- ntoskrnl.exe compatibility stubs (extern "win64"), wired to real resources --------

extern "win64" fn s_rtl_init_unicode_string(dest: *mut u8, source: *const u16) {
    if dest.is_null() {
        return;
    }
    let mut n = 0usize;
    if !source.is_null() {
        unsafe {
            while *source.add(n) != 0 && n < 4096 {
                n += 1;
            }
        }
    }
    let bytes = (n * 2) as u16;
    unsafe {
        core::ptr::write_unaligned(dest as *mut u16, bytes);
        core::ptr::write_unaligned((dest as *mut u16).add(1), bytes.wrapping_add(2));
        core::ptr::write_unaligned(dest.add(8) as *mut u64, source as u64);
    }
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn s_io_create_device(
    _driver_object: u64,
    extension_size: u32,
    _device_name: u64,
    _device_type: u32,
    _characteristics: u32,
    _exclusive: u8,
    device_object_out: *mut u64,
) -> i32 {
    unsafe {
        let dev = arena_alloc(0x100);
        let ext = if extension_size > 0 {
            arena_alloc(extension_size as u64)
        } else {
            0
        };
        core::ptr::write_unaligned((dev + 64) as *mut u64, ext); // DeviceExtension@64
        core::ptr::write_volatile((ARENA_VADDR + A_DEVICE) as *mut u64, dev);
        if !device_object_out.is_null() {
            core::ptr::write_unaligned(device_object_out, dev);
        }
    }
    0
}

/// `MmMapIoSpace(phys, len, cache)` → the REAL NIC BAR mapped in this host. Records the
/// phys the driver asked for so the executive can verify it was the NIC's.
extern "win64" fn s_mm_map_io_space(phys: u64, _length: u64, _cache: u32) -> u64 {
    unsafe {
        core::ptr::write_volatile((ARENA_VADDR + A_MMIO_PHYS) as *mut u64, phys);
        core::ptr::write_volatile((ARENA_VADDR + A_MMIO_RET) as *mut u64, NIC_VADDR);
    }
    NIC_VADDR
}

extern "win64" fn s_io_attach(_source_fdo: u64, target_pdo: u64) -> u64 {
    target_pdo
}

extern "win64" fn s_iof_call_driver(_device: u64, irp: u64) -> i32 {
    unsafe {
        if irp != 0 {
            core::ptr::write_unaligned((irp + 48) as *mut i32, 0); // IoStatus.Status = SUCCESS
        }
    }
    0
}

extern "win64" fn s_iof_complete_request(_irp: u64, _priority: i8) {}

#[allow(clippy::too_many_arguments)]
extern "win64" fn s_io_connect_interrupt(
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
    unsafe {
        core::ptr::write_volatile((ARENA_VADDR + A_ISR) as *mut u64, service_routine);
        core::ptr::write_volatile((ARENA_VADDR + A_ISR_CTX) as *mut u64, service_context);
        let proj = arena_alloc(16);
        if !interrupt_obj_out.is_null() {
            core::ptr::write_unaligned(interrupt_obj_out, proj);
        }
    }
    0
}

extern "win64" fn s_void() {}
extern "win64" fn s_ok() -> i32 {
    0
}
extern "win64" fn s_u8() -> u8 {
    0
}

/// Resolve an ntoskrnl import name to a stub address. Unknown → a benign `s_ok` (0).
fn export_addr(name: &str) -> u64 {
    let f: u64 = match name {
        "RtlInitUnicodeString" => s_rtl_init_unicode_string as usize as u64,
        "IoCreateDevice" => s_io_create_device as usize as u64,
        "MmMapIoSpace" => s_mm_map_io_space as usize as u64,
        "IoAttachDeviceToDeviceStack" => s_io_attach as usize as u64,
        "IofCallDriver" => s_iof_call_driver as usize as u64,
        "IofCompleteRequest" => s_iof_complete_request as usize as u64,
        "IoConnectInterrupt" => s_io_connect_interrupt as usize as u64,
        // void-returning no-ops:
        "MmUnmapIoSpace" | "IoDeleteDevice" | "IoDetachDevice" | "IoDisconnectInterrupt"
        | "KeInitializeDpc" | "KeInitializeEvent" | "KeInitializeSpinLock"
        | "KeReleaseSpinLock" => s_void as usize as u64,
        // BOOLEAN / KIRQL (u8):
        "KeInsertQueueDpc" | "KeAcquireSpinLockRaiseToDpc" => s_u8 as usize as u64,
        // NTSTATUS / LONG (i32) → success:
        "KeSetEvent" | "KeWaitForSingleObject" | "IoCreateSymbolicLink"
        | "IoDeleteSymbolicLink" => s_ok as usize as u64,
        _ => s_ok as usize as u64,
    };
    f
}

/// Runs in the EXECUTIVE (which has the heap). Parse the `.sys` (raw bytes loaded BY-PATH from
/// the FS — no baked `include_bytes!`), map+relocate it for `CODE_VA`, copy the mapped bytes into
/// the (executive-mapped) image frames, patch the IAT to our stubs, seed the /GS cookie. Returns
/// the DriverEntry RVA. The executive then re-maps those same frames R+X into the host.
pub unsafe fn load_into(sys_bytes: &[u8]) -> Option<u32> {
    let pe = PeFile::parse(sys_bytes).ok()?;
    let mapped = pe.map(CODE_VA).ok()?;
    let dst = CODE_VA as *mut u8;
    for (i, b) in mapped.bytes.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    if let Ok(imports) = pe.imports() {
        for dll in &imports {
            for f in &dll.functions {
                if let ImportRef::ByName { name, iat_slot_rva, .. } = f {
                    core::ptr::write_unaligned(
                        (CODE_VA + *iat_slot_rva as u64) as *mut u64,
                        export_addr(name),
                    );
                }
            }
        }
    }
    pe.seed_security_cookie(CODE_VA);
    Some(pe.entry_point_rva())
}

/// Runs in the HOST. Drive the real driver through its lifecycle:
/// DriverEntry → AddDevice → IRP_MN_START_DEVICE (with a real CM_RESOURCE_LIST whose
/// Memory.Start is `bar_paddr`). Returns a verdict bitmask:
///   1 = DriverEntry STATUS_SUCCESS · 2 = AddDevice built an FDO · 4 = START SUCCESS
///   8 = MmMapIoSpace returned the real BAR · 16 = IoConnectInterrupt recorded an ISR
pub unsafe fn sys_start(entry_rva: u32, bar_paddr: u64) -> u8 {
    arena_init();
    // DRIVER_OBJECT (Type@0=4, Size@2=336, DriverExtension@48 → AddDevice@+8).
    let drv = arena_alloc(0x200);
    core::ptr::write_unaligned(drv as *mut i16, 4);
    core::ptr::write_unaligned((drv + 2) as *mut i16, 336);
    let ext = arena_alloc(0x40);
    core::ptr::write_unaligned((drv + 48) as *mut u64, ext);
    let reg_path = arena_alloc(16);

    // DriverEntry(DriverObject, RegistryPath).
    let entry = CODE_VA + entry_rva as u64;
    let de: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let de_status = de(drv, reg_path);
    let mut verdict = 0u8;
    if de_status != 0 {
        return verdict;
    }
    verdict |= 1;

    let add_device = core::ptr::read_unaligned((ext + 8) as *const u64);
    if add_device == 0 {
        return verdict;
    }
    // AddDevice(DriverObject, PDO) → FDO (recorded via IoCreateDevice into A_DEVICE).
    let pdo = arena_alloc(0x100);
    core::ptr::write_unaligned(pdo as *mut i16, 3);
    core::ptr::write_volatile((ARENA_VADDR + A_DEVICE) as *mut u64, 0);
    let add: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(add_device as *const ());
    let add_status = add(drv, pdo);
    let fdo = core::ptr::read_volatile((ARENA_VADDR + A_DEVICE) as *const u64);
    if add_status != 0 || fdo == 0 {
        return verdict;
    }
    verdict |= 2;

    // Build the translated CM_RESOURCE_LIST the driver reads at START (Memory.Start =
    // the real NIC BAR paddr; the driver passes it to MmMapIoSpace, which returns the BAR).
    let reslist = arena_alloc(0x80);
    {
        use nt_cm_resources::*;
        let slice = core::slice::from_raw_parts_mut(reslist as *mut u8, MEMORY_INTERRUPT_LIST_SIZE);
        let _ = build_memory_interrupt_list(
            slice,
            0,
            MemoryDescriptor {
                start: bar_paddr,
                length: 0x4000,
                flags: CM_RESOURCE_MEMORY_READ_WRITE,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
            InterruptDescriptor {
                level: NIC_MSI_VECTOR as u32,
                vector: NIC_MSI_VECTOR as u32,
                affinity: 1,
                flags: CM_RESOURCE_INTERRUPT_LATCHED,
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            },
        );
    }
    // Build the IRP + IO_STACK_LOCATION (IRP Type@0=6, CurrentStackLocation@184; stack
    // Major@0/Minor@1, Parameters.StartDevice.AllocatedResources@8 / Translated@16).
    let irp = arena_alloc(0x100);
    let stack = arena_alloc(0x100);
    let current = stack + 72; // leave one lower slot for IoCopyCurrentIrpStackLocationToNext
    core::ptr::write_unaligned(irp as *mut i16, 6);
    core::ptr::write_unaligned((irp + 184) as *mut u64, current);
    core::ptr::write_unaligned(current as *mut u8, IRP_MJ_PNP as u8);
    core::ptr::write_unaligned((current + 1) as *mut u8, IRP_MN_START_DEVICE);
    core::ptr::write_unaligned((current + 8) as *mut u64, reslist);
    core::ptr::write_unaligned((current + 16) as *mut u64, reslist);

    let routine = core::ptr::read_unaligned((drv + 112 + IRP_MJ_PNP * 8) as *const u64);
    let start_status = if routine != 0 {
        let pnp: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
        pnp(fdo, irp)
    } else {
        -1
    };
    if start_status == 0 {
        verdict |= 4;
    }
    let mmio_ret = core::ptr::read_volatile((ARENA_VADDR + A_MMIO_RET) as *const u64);
    if mmio_ret == NIC_VADDR {
        verdict |= 8;
    }
    let isr = core::ptr::read_volatile((ARENA_VADDR + A_ISR) as *const u64);
    if isr != 0 {
        verdict |= 16;
    }
    verdict
}
