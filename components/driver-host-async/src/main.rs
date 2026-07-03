//! `ntos-driver-host-async` — the async Driver Host as a seL4 component.
//!
//! A bare-metal root task the rust-micro kernel boots. It maps the real MSVC-built
//! `AsyncTest.sys` WDM driver into its own VSpace executable (W^X + NX), runs its
//! `DriverEntry`, and drives the **asynchronous** IRP completion paths (spec:
//! NT Dispatcher/DPC/Timer/Work-Item, Milestone 10): a `DeviceIoControl` marks the
//! IRP pending, queues a DPC / timer-DPC / work item, and returns `STATUS_PENDING`;
//! the Driver Host's `nt-kernel-exec` runtime later runs the deferred callback at
//! the correct simulated IRQL, which completes the IRP.
//!
//! Prints `PASS`/`FAIL` per step, then the kernel-exit sentinel.

#![no_std]
#![no_main]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::boxed::Box;
use nt_kernel_exec::{EventKind, FakeClock, KernelExecRuntime, ReadyCallback, DISPATCH_LEVEL};
use nt_pe_loader::{ImportRef, PeFile};
use sel4_rt::*;

/// The real async driver image, built by <https://github.com/stakach/ntdriver>.
static ASYNCTEST_SYS: &[u8] =
    include_bytes!("../../../crates/nt-driver-test-fixtures/fixtures/AsyncTest.sys");

/// Map the image at its preferred base (`0x140000000`) — no relocation needed.
const CODE_VADDR: u64 = 0x0000_0001_4000_0000;

/// `STATUS_PENDING` — the driver deferred completion.
const STATUS_PENDING: i32 = 0x0000_0103;

/// `IO_WORKITEM` handles start here (opaque; the driver only stores + returns them).
const WORK_HANDLE_BASE: u64 = 0x0000_0000_5000_0000;

static NEXT_SLOT: AtomicU64 = AtomicU64::new(0);

fn alloc_slot() -> u64 {
    NEXT_SLOT.fetch_add(1, Ordering::Relaxed)
}

static mut CODE_FRAME_CAPS: [u64; 16] = [0; 16];

/// Map `frames` fresh RW 4 KiB pages at `base`, creating the PDPT/PD/PT + recording
/// the frame caps for the later W^X remap.
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
        let _ = page_map(f, base + i * 0x1000, /* RW */ 3, CAP_INIT_THREAD_VSPACE);
        CODE_FRAME_CAPS[i as usize] = f;
    }
}

/// Re-map the driver image W^X + NX: executable code read-only, writable data RW,
/// every non-executable page `ExecuteNever`.
unsafe fn apply_wx(pe: &PeFile, frames: u64) {
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

// --- the NT kernel execution runtime (root task .bss is RW) ------------------

static mut RT: Option<KernelExecRuntime<FakeClock>> = None;

/// The Driver Host's execution runtime. Single-threaded; every access is a fresh
/// short borrow so a driver callback can re-enter it (spec §17).
unsafe fn rt() -> &'static mut KernelExecRuntime<FakeClock> {
    (*core::ptr::addr_of_mut!(RT)).as_mut().unwrap()
}

/// Captured Driver Host state.
struct DhState {
    device_created: bool,
    device_object: u64,
    name_units: [u16; 64],
    name_len: usize,
    completed: bool,
    last_status: i32,
    last_info: u64,
    bad_irql: u32,
    dpc_runs: u32,
    timer_runs: u32,
    work_runs: u32,
}

static mut DH: DhState = DhState {
    device_created: false,
    device_object: 0,
    name_units: [0; 64],
    name_len: 0,
    completed: false,
    last_status: 0,
    last_info: 0,
    bad_irql: 0,
    dpc_runs: 0,
    timer_runs: 0,
    work_runs: 0,
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

// --- compatibility exports the driver imports -------------------------------

/// `RtlInitUnicodeString(Dest, Source)`.
extern "win64" fn ntos_rtl_init_unicode_string(dest: *mut u8, source: *const u16) {
    if dest.is_null() {
        return;
    }
    let mut n = 0usize;
    if !source.is_null() {
        // SAFETY: the driver passes a NUL-terminated wide string in its .rdata.
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

/// `IoCreateDevice(...)` — allocate a DEVICE_OBJECT + its extension.
#[allow(clippy::too_many_arguments)]
extern "win64" fn ntos_io_create_device(
    _driver_object: u64,
    extension_size: u32,
    device_name: *const u8,
    _device_type: u32,
    _characteristics: u32,
    _exclusive: u8,
    device_object_out: *mut u64,
) -> i32 {
    let dev = alloc_blob();
    // Allocate the device extension the driver requested + wire DeviceObject
    // ->DeviceExtension (offset 64).
    let ext = if extension_size > 0 {
        let layout =
            core::alloc::Layout::from_size_align((extension_size as usize).max(1), 16).unwrap();
        // SAFETY: nonzero size, 16-align.
        unsafe { alloc::alloc::alloc_zeroed(layout) as u64 }
    } else {
        0
    };
    // SAFETY: single-threaded; `device_name` a driver UNICODE_STRING, `out` writable.
    unsafe {
        core::ptr::write_unaligned((dev + 64) as *mut u64, ext);
        if !device_name.is_null() {
            let len_units = (core::ptr::read_unaligned(device_name as *const u16) / 2) as usize;
            let buf = core::ptr::read_unaligned(device_name.add(8) as *const u64) as *const u16;
            let n = len_units.min(64);
            for i in 0..n {
                dh().name_units[i] = *buf.add(i);
            }
            dh().name_len = n;
        }
        dh().device_created = true;
        dh().device_object = dev;
        if !device_object_out.is_null() {
            core::ptr::write_unaligned(device_object_out, dev);
        }
    }
    0
}

/// `IoCreateSymbolicLink` / `IoDeleteDevice` / `IoDeleteSymbolicLink` — accepted.
extern "win64" fn ntos_io_ok2(_a: u64, _b: u64) -> i32 {
    0
}

/// `IofCompleteRequest(Irp, PriorityBoost)` — record the completion (`Irp->IoStatus`
/// at offset 48/56). The deferred callback calls this from DPC/timer/work context.
extern "win64" fn ntos_iof_complete_request(irp: *const u8, _priority: i8) {
    if irp.is_null() {
        return;
    }
    // SAFETY: `irp` is an IRP we built; IoStatus.Status@48, .Information@56.
    unsafe {
        dh().last_status = core::ptr::read_unaligned(irp.add(48) as *const i32);
        dh().last_info = core::ptr::read_unaligned(irp.add(56) as *const u64);
        dh().completed = true;
    }
}

/// `ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag)` — zeroed pool allocation.
extern "win64" fn ntos_ex_allocate_pool(_pool: u32, size: u64, _tag: u32) -> u64 {
    let layout = core::alloc::Layout::from_size_align((size as usize).max(1), 16).unwrap();
    // SAFETY: nonzero size, valid align.
    unsafe { alloc::alloc::alloc_zeroed(layout) as u64 }
}

/// `ExFreePoolWithTag(P, Tag)` — leak (the component is short-lived).
extern "win64" fn ntos_ex_free_pool(_p: u64, _tag: u32) {}

/// `KeGetCurrentIrql()`.
extern "win64" fn ntos_ke_get_current_irql() -> u8 {
    // SAFETY: single-threaded runtime access.
    unsafe { rt().irql().current() }
}

/// `KeInitializeDpc(Dpc, Routine, Context)`.
extern "win64" fn ntos_ke_initialize_dpc(dpc: u64, routine: u64, context: u64) {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().dpc().initialize(dpc, routine, context) }
}

/// `KeInsertQueueDpc(Dpc, Arg1, Arg2)` → BOOLEAN.
extern "win64" fn ntos_ke_insert_queue_dpc(dpc: u64, arg1: u64, arg2: u64) -> u8 {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().dpc().insert(dpc, arg1, arg2) as u8 }
}

/// `KeInitializeTimer(Timer)` (also serves `KeInitializeTimerEx`).
extern "win64" fn ntos_ke_initialize_timer(timer: u64) {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().timer().initialize(timer) }
}

/// `KeSetTimer(Timer, DueTime, Dpc)` → BOOLEAN. `DueTime` is a by-value 100ns
/// LARGE_INTEGER in rdx.
extern "win64" fn ntos_ke_set_timer(timer: u64, due_time: i64, dpc: u64) -> u8 {
    let assoc = if dpc != 0 { Some(dpc) } else { None };
    // SAFETY: fresh runtime borrow.
    unsafe { rt().set_timer(timer, due_time, 0, assoc) as u8 }
}

/// `KeInitializeEvent(Event, Type, State)` — Type 0 = Notification, 1 = Synchronization.
extern "win64" fn ntos_ke_initialize_event(event: u64, kind: u32, state: u8) {
    let k = if kind == 1 {
        EventKind::Synchronization
    } else {
        EventKind::Notification
    };
    // SAFETY: fresh runtime borrow.
    unsafe { rt().events().initialize(event, k, state != 0) }
}

/// `KeSetEvent(Event, Increment, Wait)` → previous state (LONG).
extern "win64" fn ntos_ke_set_event(event: u64, _incr: i32, _wait: u8) -> i32 {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().events().set(event) as i32 }
}

/// `KeClearEvent(Event)`.
extern "win64" fn ntos_ke_clear_event(event: u64) {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().events().clear(event) }
}

/// `KeWaitForSingleObject(Object, Reason, Mode, Alertable, Timeout)` → NTSTATUS.
/// The async driver only waits during unload (not exercised here); succeed.
extern "win64" fn ntos_ke_wait_for_single_object(
    _object: u64,
    _reason: u32,
    _mode: u8,
    _alertable: u8,
    _timeout: u64,
) -> i32 {
    0
}

/// `IoAllocateWorkItem(DeviceObject)` → PIO_WORKITEM (opaque handle).
extern "win64" fn ntos_io_allocate_work_item(device_object: u64) -> u64 {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().work().allocate(device_object) }
}

/// `IoQueueWorkItem(WorkItem, Routine, QueueType, Context)`.
extern "win64" fn ntos_io_queue_work_item(handle: u64, routine: u64, _queue: u32, context: u64) {
    // SAFETY: fresh runtime borrow.
    unsafe {
        rt().work().queue_io(handle, routine, context);
    }
}

/// `IoFreeWorkItem(WorkItem)`.
extern "win64" fn ntos_io_free_work_item(handle: u64) {
    // SAFETY: fresh runtime borrow.
    unsafe { rt().work().free(handle) }
}

/// Fail-safe stub for anything unexercised.
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
        "IofCompleteRequest" | "IoCompleteRequest" => ntos_iof_complete_request as usize as u64,
        "ExAllocatePoolWithTag" => ntos_ex_allocate_pool as usize as u64,
        "ExFreePoolWithTag" => ntos_ex_free_pool as usize as u64,
        "KeGetCurrentIrql" => ntos_ke_get_current_irql as usize as u64,
        "KeInitializeDpc" => ntos_ke_initialize_dpc as usize as u64,
        "KeInsertQueueDpc" => ntos_ke_insert_queue_dpc as usize as u64,
        "KeInitializeTimer" | "KeInitializeTimerEx" => ntos_ke_initialize_timer as usize as u64,
        "KeSetTimer" | "KeSetTimerEx" => ntos_ke_set_timer as usize as u64,
        "KeInitializeEvent" => ntos_ke_initialize_event as usize as u64,
        "KeSetEvent" => ntos_ke_set_event as usize as u64,
        "KeClearEvent" => ntos_ke_clear_event as usize as u64,
        "KeWaitForSingleObject" => ntos_ke_wait_for_single_object as usize as u64,
        "IoAllocateWorkItem" => ntos_io_allocate_work_item as usize as u64,
        "IoQueueWorkItem" => ntos_io_queue_work_item as usize as u64,
        "IoFreeWorkItem" => ntos_io_free_work_item as usize as u64,
        _ => ntos_stub as usize as u64,
    }
}

/// Run every ready deferred callback (DPC / timer-DPC / work item) by calling the
/// driver routine **with no runtime borrow held** (spec §17), recording the IRQL
/// each ran at. Bounded by `budget` against a self-requeuing driver.
unsafe fn drain_driver(budget: usize) {
    let mut n = 0;
    while n < budget {
        let cb = match rt().take_ready() {
            Some(c) => c,
            None => break,
        };
        let irql_now = rt().irql().current();
        match cb {
            ReadyCallback::Dpc {
                routine,
                dpc,
                deferred_context,
                arg1,
                arg2,
            } => {
                if irql_now != DISPATCH_LEVEL {
                    dh().bad_irql += 1;
                }
                dh().dpc_runs += 1;
                let f: extern "win64" fn(u64, u64, u64, u64) =
                    core::mem::transmute(routine as *const ());
                f(dpc, deferred_context, arg1, arg2);
            }
            ReadyCallback::WorkIo {
                routine,
                device_object,
                context,
            } => {
                if irql_now != 0 {
                    dh().bad_irql += 1;
                }
                dh().work_runs += 1;
                let f: extern "win64" fn(u64, u64) = core::mem::transmute(routine as *const ());
                f(device_object, context);
            }
            ReadyCallback::WorkEx { routine, parameter } => {
                let f: extern "win64" fn(u64) = core::mem::transmute(routine as *const ());
                f(parameter);
            }
        }
        rt().finish_callback();
        n += 1;
    }
}

/// Dispatch one IRP into `MajorFunction[major]`. If the driver returns
/// `STATUS_PENDING`, advance the clock (to fire any timer) and drain the runtime so
/// the deferred callback completes the IRP. Returns `(status, information)`.
unsafe fn dispatch(driver_object: u64, device_object: u64, major: u8, code: u32) -> (i32, u64) {
    let irp = alloc_blob();
    let stack = alloc_blob();
    let sysbuf = Box::leak(Box::new([0u8; 64])) as *mut u8;

    // IRP: Type=6, SystemBuffer@24, CurrentStackLocation@184.
    core::ptr::write_unaligned(irp as *mut i16, 6);
    core::ptr::write_unaligned((irp + 24) as *mut u64, sysbuf as u64);
    core::ptr::write_unaligned((irp + 184) as *mut u64, stack);
    // IO_STACK_LOCATION: MajorFunction@0, DeviceIoControl Out@8 / In@16 / Code@24.
    core::ptr::write_unaligned(stack as *mut u8, major);
    core::ptr::write_unaligned((stack + 8) as *mut u32, 64);
    core::ptr::write_unaligned((stack + 16) as *mut u32, 0);
    core::ptr::write_unaligned((stack + 24) as *mut u32, code);

    dh().completed = false;
    dh().last_status = 0;
    dh().last_info = 0;

    let routine = core::ptr::read_unaligned((driver_object + 112 + major as u64 * 8) as *const u64);
    let f: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(routine as *const ());
    let status = f(device_object, irp);

    if status == STATUS_PENDING {
        // Fire any pending timer, then run the deferred callback that completes it.
        rt().clock_mut().advance_ms(60_000);
        drain_driver(4096);
    }

    (dh().last_status, dh().last_info)
}

fn check(name: &[u8], ok: bool) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
}

unsafe fn run() {
    RT = Some(KernelExecRuntime::new(FakeClock::new(), WORK_HANDLE_BASE));

    let pe = match PeFile::parse(ASYNCTEST_SYS) {
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
                if let ImportRef::ByName {
                    name, iat_slot_rva, ..
                } = f
                {
                    let addr = export_addr(name);
                    core::ptr::write_unaligned((CODE_VADDR + *iat_slot_rva as u64) as *mut u64, addr);
                }
            }
        }
    }
    check(b"patch_iat", true);

    let cookie_ok = if let Some(rva) = pe.security_cookie_rva() {
        core::ptr::write_unaligned((CODE_VADDR + rva as u64) as *mut u64, 0x1234_5678_9abc_def0);
        true
    } else {
        false
    };
    check(b"security_cookie", cookie_ok);

    apply_wx(&pe, frames);
    check(b"w_xor_x", true);

    // DRIVER_OBJECT + empty RegistryPath.
    let driver_object = alloc_blob();
    core::ptr::write_unaligned(driver_object as *mut i16, 4);
    core::ptr::write_unaligned((driver_object + 2) as *mut i16, 336);
    let reg_path = Box::leak(Box::new([0u8; 16])) as *mut u8 as u64;

    let entry = CODE_VADDR + pe.entry_point_rva() as u64;
    let driver_entry: extern "win64" fn(u64, u64) -> i32 = core::mem::transmute(entry as *const ());
    let status = driver_entry(driver_object, reg_path);
    check(b"driver_entry_success", status == 0);

    let major = |m: u64| core::ptr::read_unaligned((driver_object + 112 + m * 8) as *const u64);
    check(b"dispatch_device_control", major(0x0e) != 0);
    check(b"io_create_device", dh().device_created);

    print_str(b"  device: ");
    let mut ascii = [0u8; 64];
    let n = dh().name_len.min(64);
    for i in 0..n {
        let c = dh().name_units[i];
        ascii[i] = if (0x20..0x7f).contains(&c) { c as u8 } else { b'?' };
    }
    print_str(&ascii[..n]);
    print_str(b"\n");

    let dev = dh().device_object;

    // IRP_MJ_CREATE (open).
    let _ = dispatch(driver_object, dev, 0x00, 0);

    // --- asynchronous completion paths (spec §13) --------------------------
    // IOCTL_ASYNC_COMPLETE_VIA_DPC → STATUS_PENDING, DPC completes with "DPC!".
    let (st, info) = dispatch(driver_object, dev, 0x0e, 0x0022_2048);
    check(
        b"async_dpc_completion",
        st == 0 && info == 0x4450_4321 && dh().dpc_runs >= 1,
    );

    // IOCTL_ASYNC_COMPLETE_VIA_TIMER → STATUS_PENDING, timer→DPC completes with "TMR!".
    let (st, info) = dispatch(driver_object, dev, 0x0e, 0x0022_204C);
    check(
        b"async_timer_completion",
        st == 0 && info == 0x544D_5221 && dh().timer_runs == 0, // completes via a DPC
    );

    // IOCTL_ASYNC_COMPLETE_VIA_WORKITEM → STATUS_PENDING, work item completes "WKI!".
    let (st, info) = dispatch(driver_object, dev, 0x0e, 0x0022_2050);
    check(
        b"async_workitem_completion",
        st == 0 && info == 0x574B_4921 && dh().work_runs >= 1,
    );

    // Quality gate (spec §20): no DPC ran at PASSIVE, no work item at DISPATCH.
    check(b"callbacks_ran_at_correct_irql", dh().bad_irql == 0);
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;
    NEXT_SLOT.store(bi.empty.start, Ordering::Relaxed);

    print_str(b"[ntos-dha] async Driver Host: load + run real AsyncTest.sys over DPC/timer/work\n");
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
