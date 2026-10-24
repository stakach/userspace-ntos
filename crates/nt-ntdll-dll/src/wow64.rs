//! Native WOW64 queries and the cross-process emulator work-list ABI.
//!
//! The executable is AMD64. A 32-bit CPU area or thread context requires a
//! registered WOW64 emulator; exporting a symbol does not create that state.
//! The list operations are independent of the emulator and follow the native
//! 64-bit header protocol in Wine's `winternl.h` and `ntdll/process.c`.

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const PROCESS_WOW64_INFORMATION: u64 = 26;
const FLUSH: u32 = 0x8000_0000;

#[repr(C)]
pub struct CrossProcessWorkHeader {
    // Low ULONG: first relative entry offset plus FLUSH; high ULONG: generation.
    value: AtomicU64,
}

#[repr(C)]
pub struct CrossProcessWorkEntry {
    next: AtomicU32,
    id: u32,
    address: u64,
    size: u64,
    arguments: [u32; 4],
}

const _: () = assert!(core::mem::size_of::<CrossProcessWorkHeader>() == 8);
const _: () = assert!(core::mem::size_of::<CrossProcessWorkEntry>() == 40);

fn first(value: u64) -> u32 {
    value as u32
}

fn advance(value: u64, new_first: u32) -> u64 {
    (((value >> 32) as u32).wrapping_add(1) as u64) << 32 | u64::from(new_first)
}

fn entry_offset(
    list: *mut CrossProcessWorkHeader,
    entry: *mut CrossProcessWorkEntry,
) -> Option<u32> {
    if list.is_null() || entry.is_null() {
        return None;
    }
    let displacement = (entry as usize).checked_sub(list as usize)?;
    if displacement == 0 || displacement > u32::MAX as usize >> 1 {
        return None;
    }
    Some(displacement as u32)
}

fn query_process_machine(
    handle: usize,
    query: impl FnOnce(usize, &mut usize) -> u32,
) -> Result<(u16, u16), u32> {
    // NtCurrentProcess needs no syscall to identify its own architecture.
    if handle == usize::MAX {
        return Ok((IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_AMD64));
    }
    let mut wow64_peb = 0usize;
    let status = query(handle, &mut wow64_peb);
    if status & 0x8000_0000 != 0 {
        return Err(status);
    }
    Ok((
        if wow64_peb == 0 {
            IMAGE_FILE_MACHINE_AMD64
        } else {
            IMAGE_FILE_MACHINE_I386
        },
        IMAGE_FILE_MACHINE_AMD64,
    ))
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fn native_wow64_peb(handle: usize, output: &mut usize) -> u32 {
    // SAFETY: the trap copies one pointer-sized result into our local output.
    unsafe {
        nt_ntdll::trap_stubs::nt_query_information_process(
            handle as u64,
            PROCESS_WOW64_INFORMATION,
            output as *mut usize as u64,
            core::mem::size_of::<usize>() as u64,
            0,
        ) as u32
    }
}

#[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
fn native_wow64_peb(_handle: usize, _output: &mut usize) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// `RtlWow64GetCurrentMachine() -> USHORT`.
#[export_name = "RtlWow64GetCurrentMachine"]
pub extern "system" fn rtl_wow64_get_current_machine() -> u16 {
    IMAGE_FILE_MACHINE_AMD64
}

/// `RtlWow64GetProcessMachines(HANDLE, PUSHORT, PUSHORT) -> NTSTATUS`.
///
/// # Safety
/// Output pointers, when non-null, must be writable.
#[export_name = "RtlWow64GetProcessMachines"]
pub unsafe extern "system" fn rtl_wow64_get_process_machines(
    process: *mut c_void,
    process_machine: *mut u16,
    native_machine: *mut u16,
) -> u32 {
    if process_machine.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let (current, native) = match query_process_machine(process as usize, native_wow64_peb) {
        Ok(value) => value,
        Err(status) => return status,
    };
    // SAFETY: caller owns these output pointers.
    unsafe {
        ptr::write(process_machine, current);
        if !native_machine.is_null() {
            ptr::write(native_machine, native);
        }
    }
    STATUS_SUCCESS
}

/// `RtlWow64GetSharedInfoProcess(HANDLE, BOOLEAN*, WOW64INFO*) -> NTSTATUS`.
/// A native process has no WOW64 shared info. A guest needs an emulator-backed
/// cross-process read, so leave both outputs untouched when it is unsupported.
///
/// # Safety
/// `is_wow64` must be writable.
#[export_name = "RtlWow64GetSharedInfoProcess"]
pub unsafe extern "system" fn rtl_wow64_get_shared_info_process(
    process: *mut c_void,
    is_wow64: *mut u8,
    _info: *mut c_void,
) -> u32 {
    if is_wow64.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    match query_process_machine(process as usize, native_wow64_peb) {
        Ok((IMAGE_FILE_MACHINE_AMD64, _)) => (),
        Ok(_) => return STATUS_NOT_SUPPORTED,
        Err(status) => return status,
    }
    // SAFETY: the caller provided a writable one-byte BOOLEAN.
    unsafe { ptr::write(is_wow64, 0) };
    STATUS_SUCCESS
}

/// `RtlWow64IsWowGuestMachineSupported(USHORT, BOOLEAN*) -> NTSTATUS`.
/// No guest-machine support has been registered with this kernel personality.
///
/// # Safety
/// `supported` must be writable.
#[export_name = "RtlWow64IsWowGuestMachineSupported"]
pub unsafe extern "system" fn rtl_wow64_is_wow_guest_machine_supported(
    _machine: u16,
    supported: *mut u8,
) -> u32 {
    if supported.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller provided a writable one-byte BOOLEAN.
    unsafe { ptr::write(supported, 0) };
    STATUS_SUCCESS
}

/// `RtlWow64GetCpuAreaInfo(WOW64_CPURESERVED*, ULONG, WOW64_CPU_AREA_INFO*)`.
#[export_name = "RtlWow64GetCpuAreaInfo"]
pub extern "system" fn rtl_wow64_get_cpu_area_info(
    _cpu: *mut c_void,
    _reserved: u32,
    _info: *mut c_void,
) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// `RtlWow64GetCurrentCpuArea(USHORT*, void**, void**)`.
#[export_name = "RtlWow64GetCurrentCpuArea"]
pub extern "system" fn rtl_wow64_get_current_cpu_area(
    _machine: *mut u16,
    _context: *mut *mut c_void,
    _context_ex: *mut *mut c_void,
) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// `RtlWow64GetThreadContext(HANDLE, WOW64_CONTEXT*)`.
#[export_name = "RtlWow64GetThreadContext"]
pub extern "system" fn rtl_wow64_get_thread_context(
    _thread: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// `RtlWow64SetThreadContext(HANDLE, const WOW64_CONTEXT*)`.
#[export_name = "RtlWow64SetThreadContext"]
pub extern "system" fn rtl_wow64_set_thread_context(
    _thread: *mut c_void,
    _context: *const c_void,
) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// `RtlWow64GetThreadSelectorEntry(HANDLE, THREAD_DESCRIPTOR_INFORMATION*, ULONG, ULONG*)`.
#[export_name = "RtlWow64GetThreadSelectorEntry"]
pub extern "system" fn rtl_wow64_get_thread_selector_entry(
    _thread: *mut c_void,
    _info: *mut c_void,
    _size: u32,
    _return_length: *mut u32,
) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// `RtlWow64SuspendThread(HANDLE, PULONG) -> NTSTATUS`.
/// Suspend is a native thread operation even for a guest thread handle.
///
/// # Safety
/// `previous_count`, when non-null, must be writable.
#[export_name = "RtlWow64SuspendThread"]
pub unsafe extern "system" fn rtl_wow64_suspend_thread(
    thread: *mut c_void,
    previous_count: *mut u32,
) -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    {
        // SAFETY: kernel validates the handle and optional count pointer.
        unsafe {
            nt_ntdll::trap_stubs::nt_suspend_thread(thread as u64, previous_count as u64) as u32
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
    {
        let _ = (thread, previous_count);
        STATUS_NOT_SUPPORTED
    }
}

/// `RtlWow64PopCrossProcessWorkFromFreeList(CROSS_PROCESS_WORK_HDR*)`.
///
/// # Safety
/// `list` and each linked entry must remain mapped during the operation.
#[export_name = "RtlWow64PopCrossProcessWorkFromFreeList"]
pub unsafe extern "system" fn rtl_wow64_pop_cross_process_work_from_free_list(
    list: *mut CrossProcessWorkHeader,
) -> *mut CrossProcessWorkEntry {
    let Some(header) = (unsafe { list.as_ref() }) else {
        return ptr::null_mut();
    };
    loop {
        let old = header.value.load(Ordering::Acquire);
        let offset = first(old);
        if offset == 0 {
            return ptr::null_mut();
        }
        // SAFETY: caller maintains the relative-offset list and keeps entries mapped.
        let entry = unsafe {
            list.cast::<u8>()
                .add(offset as usize)
                .cast::<CrossProcessWorkEntry>()
        };
        let next = unsafe { (*entry).next.load(Ordering::Acquire) };
        if header
            .value
            .compare_exchange(old, advance(old, next), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            unsafe { (*entry).next.store(0, Ordering::Release) };
            return entry;
        }
    }
}

/// `RtlWow64PushCrossProcessWorkOntoFreeList(CROSS_PROCESS_WORK_HDR*, ENTRY*)`.
///
/// # Safety
/// Caller owns an unlinked entry in the list's shared allocation.
#[export_name = "RtlWow64PushCrossProcessWorkOntoFreeList"]
pub unsafe extern "system" fn rtl_wow64_push_cross_process_work_onto_free_list(
    list: *mut CrossProcessWorkHeader,
    entry: *mut CrossProcessWorkEntry,
) -> u8 {
    let Some(offset) = entry_offset(list, entry) else {
        return 0;
    };
    let header = unsafe { &*list };
    loop {
        let old = header.value.load(Ordering::Acquire);
        unsafe { (*entry).next.store(first(old), Ordering::Release) };
        if header
            .value
            .compare_exchange(
                old,
                advance(old, offset),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return 1;
        }
    }
}

/// `RtlWow64PushCrossProcessWorkOntoWorkList(CROSS_PROCESS_WORK_HDR*, ENTRY*, void**)`.
///
/// # Safety
/// Caller owns an unlinked entry; `unknown` must be writable.
#[export_name = "RtlWow64PushCrossProcessWorkOntoWorkList"]
pub unsafe extern "system" fn rtl_wow64_push_cross_process_work_onto_work_list(
    list: *mut CrossProcessWorkHeader,
    entry: *mut CrossProcessWorkEntry,
    unknown: *mut *mut c_void,
) -> u8 {
    let Some(offset) = entry_offset(list, entry) else {
        return 0;
    };
    if unknown.is_null() {
        return 0;
    }
    unsafe { ptr::write(unknown, ptr::null_mut()) };
    let header = unsafe { &*list };
    loop {
        let old = header.value.load(Ordering::Acquire);
        unsafe { (*entry).next.store(first(old) & !FLUSH, Ordering::Release) };
        let new_first = offset | (first(old) & FLUSH);
        if header
            .value
            .compare_exchange(
                old,
                advance(old, new_first),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return 1;
        }
    }
}

/// `RtlWow64RequestCrossProcessHeavyFlush(CROSS_PROCESS_WORK_HDR*)`.
///
/// # Safety
/// `list` must remain mapped and aligned.
#[export_name = "RtlWow64RequestCrossProcessHeavyFlush"]
pub unsafe extern "system" fn rtl_wow64_request_cross_process_heavy_flush(
    list: *mut CrossProcessWorkHeader,
) -> u8 {
    let Some(header) = (unsafe { list.as_ref() }) else {
        return 0;
    };
    loop {
        let old = header.value.load(Ordering::Acquire);
        if header
            .value
            .compare_exchange(
                old,
                advance(old, first(old) | FLUSH),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return 1;
        }
    }
}

/// `RtlWow64PopAllCrossProcessWorkFromWorkList(CROSS_PROCESS_WORK_HDR*, BOOLEAN*)`.
///
/// # Safety
/// `list` and linked entries must stay mapped; `flush` must be writable.
#[export_name = "RtlWow64PopAllCrossProcessWorkFromWorkList"]
pub unsafe extern "system" fn rtl_wow64_pop_all_cross_process_work_from_work_list(
    list: *mut CrossProcessWorkHeader,
    flush: *mut u8,
) -> *mut CrossProcessWorkEntry {
    let Some(header) = (unsafe { list.as_ref() }) else {
        return ptr::null_mut();
    };
    if flush.is_null() {
        return ptr::null_mut();
    }
    let old = loop {
        let old = header.value.load(Ordering::Acquire);
        if first(old) == 0 {
            break old;
        }
        if header
            .value
            .compare_exchange(old, advance(old, 0), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break old;
        }
    };
    unsafe { ptr::write(flush, u8::from(first(old) & FLUSH != 0)) };
    let mut offset = first(old) & !FLUSH;
    let mut previous = 0;
    while offset != 0 {
        let entry = unsafe {
            list.cast::<u8>()
                .add(offset as usize)
                .cast::<CrossProcessWorkEntry>()
        };
        let next = unsafe { (*entry).next.load(Ordering::Acquire) };
        unsafe { (*entry).next.store(previous, Ordering::Release) };
        if next == 0 {
            return entry;
        }
        previous = offset;
        offset = next;
    }
    ptr::null_mut()
}

#[used]
pub static WOW64_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = wow64_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn wow64_export_anchor() {
    core::hint::black_box(rtl_wow64_get_current_machine as *const () as usize);
    core::hint::black_box(rtl_wow64_get_process_machines as *const () as usize);
    core::hint::black_box(rtl_wow64_get_shared_info_process as *const () as usize);
    core::hint::black_box(rtl_wow64_is_wow_guest_machine_supported as *const () as usize);
    core::hint::black_box(rtl_wow64_get_cpu_area_info as *const () as usize);
    core::hint::black_box(rtl_wow64_get_current_cpu_area as *const () as usize);
    core::hint::black_box(rtl_wow64_get_thread_context as *const () as usize);
    core::hint::black_box(rtl_wow64_set_thread_context as *const () as usize);
    core::hint::black_box(rtl_wow64_get_thread_selector_entry as *const () as usize);
    core::hint::black_box(rtl_wow64_suspend_thread as *const () as usize);
    core::hint::black_box(rtl_wow64_pop_cross_process_work_from_free_list as *const () as usize);
    core::hint::black_box(rtl_wow64_push_cross_process_work_onto_free_list as *const () as usize);
    core::hint::black_box(rtl_wow64_push_cross_process_work_onto_work_list as *const () as usize);
    core::hint::black_box(rtl_wow64_request_cross_process_heavy_flush as *const () as usize);
    core::hint::black_box(
        rtl_wow64_pop_all_cross_process_work_from_work_list as *const () as usize,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_machine_does_not_write_success_on_query_failure() {
        assert_eq!(
            query_process_machine(usize::MAX, |_, _| panic!("pseudo queried")),
            Ok((IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_AMD64))
        );
        assert_eq!(
            query_process_machine(123, |_, output| {
                *output = 0x1000;
                0
            }),
            Ok((IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64))
        );
        assert_eq!(
            query_process_machine(123, |_, _| 0xC000_0008),
            Err(0xC000_0008)
        );
    }

    #[repr(C)]
    struct List {
        header: CrossProcessWorkHeader,
        entries: [CrossProcessWorkEntry; 2],
    }

    #[test]
    fn cross_process_lists_preserve_generation_order_and_flush() {
        let blank = || CrossProcessWorkEntry {
            next: AtomicU32::new(0),
            id: 0,
            address: 0,
            size: 0,
            arguments: [0; 4],
        };
        let mut list = List {
            header: CrossProcessWorkHeader {
                value: AtomicU64::new(0),
            },
            entries: [blank(), blank()],
        };
        let head = &mut list.header;
        let one = list.entries.as_mut_ptr();
        // SAFETY: `entries` has exactly two elements.
        let two = unsafe { one.add(1) };
        let mut unused = 1usize as *mut c_void;
        let mut flush = 0u8;
        unsafe {
            assert_eq!(
                rtl_wow64_push_cross_process_work_onto_work_list(head, one, &mut unused),
                1
            );
            assert!(unused.is_null());
            assert_eq!(rtl_wow64_request_cross_process_heavy_flush(head), 1);
            assert_eq!(
                rtl_wow64_push_cross_process_work_onto_work_list(head, two, &mut unused),
                1
            );
            let first = rtl_wow64_pop_all_cross_process_work_from_work_list(head, &mut flush);
            assert_eq!(first, one);
            assert_eq!(
                (*first).next.load(Ordering::Acquire) as usize,
                (two as usize) - (head as *mut _ as usize)
            );
            assert_eq!(flush, 1);
            assert!(
                rtl_wow64_pop_all_cross_process_work_from_work_list(head, &mut flush).is_null()
            );
            assert_eq!(flush, 0);
            assert_eq!(
                rtl_wow64_push_cross_process_work_onto_free_list(head, one),
                1
            );
            assert_eq!(
                rtl_wow64_push_cross_process_work_onto_free_list(head, two),
                1
            );
            assert_eq!(rtl_wow64_pop_cross_process_work_from_free_list(head), two);
            assert_eq!(rtl_wow64_pop_cross_process_work_from_free_list(head), one);
            assert!(rtl_wow64_pop_cross_process_work_from_free_list(head).is_null());
        }
        assert_eq!(list.header.value.load(Ordering::Relaxed) >> 32, 8);
    }
}
