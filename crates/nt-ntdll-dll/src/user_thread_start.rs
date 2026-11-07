//! x64 user-thread startup gateway.

use core::ffi::c_void;

type ThreadStart = unsafe extern "system" fn(*mut c_void) -> u32;
type ThreadInitThunk = unsafe extern "system" fn(u32, *mut c_void, *mut c_void);

const STATUS_SUCCESS: u32 = 0;
const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;

#[repr(C)]
struct CountedString<T> {
    length: u16,
    maximum_length: u16,
    buffer: *const T,
}

/// Invoke the kernel32 thread thunk when the loader resolved it; otherwise call the start routine.
/// The thunk normally exits the thread itself. If it returns, LiberNT exits with STATUS_SUCCESS.
///
/// # Safety
/// `start_address` is a valid one-argument Windows-ABI thread routine, and `thunk`, when present,
/// is the released kernel32's three-argument `BaseThreadInitThunk`.
unsafe fn invoke_start(
    start_address: *mut c_void,
    parameter: *mut c_void,
    thunk: Option<ThreadInitThunk>,
) -> u32 {
    if let Some(thunk) = thunk {
        // SAFETY: caller established the resolved thunk and the start routine's lifetime.
        unsafe { thunk(0, start_address, parameter) };
        STATUS_SUCCESS
    } else {
        // SAFETY: start_address names a one-argument Windows-ABI routine per the thread context.
        let start: ThreadStart = unsafe { core::mem::transmute(start_address) };
        unsafe { start(parameter) }
    }
}

/// Resolve the optional kernel32 thread thunk from the source-built loader's mapped module table.
/// A loaded kernel32 without its expected export is a loader/ABI failure, not permission to bypass
/// kernel32's thread registration and call the start routine directly.
///
/// # Safety
/// Called after the process loader has initialized its mapped-module table.
#[cfg(target_arch = "x86_64")]
unsafe fn resolve_kernel32_thunk() -> Result<Option<ThreadInitThunk>, u32> {
    const KERNEL32: [u16; 13] = [
        b'k' as u16,
        b'e' as u16,
        b'r' as u16,
        b'n' as u16,
        b'e' as u16,
        b'l' as u16,
        b'3' as u16,
        b'2' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    const THUNK: &[u8] = b"BaseThreadInitThunk";
    let dll_name = CountedString {
        length: ((KERNEL32.len() - 1) * 2) as u16,
        maximum_length: (KERNEL32.len() * 2) as u16,
        buffer: KERNEL32.as_ptr(),
    };
    let mut dll_base = core::ptr::null_mut();
    // SAFETY: the counted string and output are valid; loader owns the mapped module table.
    let status = unsafe {
        crate::exports::ldr_get_dll_handle(
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &dll_name as *const CountedString<u16> as *const nt_ntdll_layout::UnicodeString,
            &mut dll_base,
        )
    };
    if status == STATUS_DLL_NOT_FOUND {
        return Ok(None);
    }
    if status != STATUS_SUCCESS {
        return Err(status);
    }

    let thunk_name = CountedString {
        length: THUNK.len() as u16,
        maximum_length: THUNK.len() as u16,
        buffer: THUNK.as_ptr(),
    };
    let mut address = core::ptr::null_mut();
    // SAFETY: dll_base was returned by the loader, and the ANSI_STRING layout is its C ABI.
    let status = unsafe {
        crate::exports::ldr_get_procedure_address(
            dll_base,
            &thunk_name as *const CountedString<u8> as *const c_void,
            0,
            &mut address,
        )
    };
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    if address.is_null() {
        return Err(0xC000_0139); // STATUS_ENTRYPOINT_NOT_FOUND
    }
    // SAFETY: successful export resolution supplied kernel32's BaseThreadInitThunk address.
    Ok(Some(unsafe { core::mem::transmute(address) }))
}

/// NT5/ReactOS `BaseInitializeContext` starts a fresh x64 thread at `StackBase`, which is
/// 16-byte aligned and has no return address. Rust's Windows ABI expects an entry RSP of 8 mod
/// 16. Supply that initial return slot without changing the caller's captured CONTEXT or its
/// RCX/RDX startup arguments. An ordinary call already has the correct entry alignment.
///
/// # Safety
/// Entered with a writable user stack and valid thread startup arguments.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[export_name = "RtlUserThreadStart"]
pub unsafe extern "system" fn rtl_user_thread_start(
    _start_address: *mut c_void,
    _parameter: *mut c_void,
) {
    core::arch::naked_asm!(
        "test rsp, 8",
        "jnz 2f",
        "sub rsp, 8",
        "mov qword ptr [rsp], 0",
        "2:",
        "jmp {body}",
        body = sym rtl_user_thread_start_body,
    );
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe extern "system" fn rtl_user_thread_start_body(
    start_address: *mut c_void,
    parameter: *mut c_void,
) {
    // SAFETY: the loader established its module table before entering a user thread.
    let status = match unsafe { resolve_kernel32_thunk() } {
        Ok(thunk) => unsafe { invoke_start(start_address, parameter, thunk) },
        Err(status) => status,
    };
    // SAFETY: the released thread gateway always exits through RtlExitUserThread.
    unsafe { crate::exports::rtl_exit_user_thread(status) };
}

#[cfg(not(target_arch = "x86_64"))]
#[export_name = "RtlUserThreadStart"]
pub unsafe extern "system" fn rtl_user_thread_start(
    _start_address: *mut c_void,
    _parameter: *mut c_void,
) {
}

#[used]
pub static USER_THREAD_START_EXPORT_ANCHOR_FN: unsafe extern "C" fn() =
    user_thread_start_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// This routine is only stored in a `#[used]` static.
pub unsafe extern "C" fn user_thread_start_export_anchor() {
    core::hint::black_box(rtl_user_thread_start as *const () as usize);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static THUNK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static START_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn thunk(
        unknown: u32,
        start_address: *mut c_void,
        parameter: *mut c_void,
    ) {
        assert_eq!(unknown, 0);
        assert!(!start_address.is_null());
        assert_eq!(parameter as usize, 7);
        THUNK_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "system" fn start(parameter: *mut c_void) -> u32 {
        assert_eq!(parameter as usize, 7);
        START_CALLS.fetch_add(1, Ordering::SeqCst);
        0x1234
    }

    #[test]
    fn dispatches_through_kernel32_when_present_and_exits_with_start_result_when_absent() {
        THUNK_CALLS.store(0, Ordering::SeqCst);
        START_CALLS.store(0, Ordering::SeqCst);
        let start_address = start as *const () as *mut c_void;
        let status = unsafe { invoke_start(start_address, 7usize as *mut c_void, Some(thunk)) };
        assert_eq!(status, 0);
        assert_eq!(THUNK_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(START_CALLS.load(Ordering::SeqCst), 0);
        let status = unsafe { invoke_start(start_address, 7usize as *mut c_void, None) };
        assert_eq!(status, 0x1234);
        assert_eq!(THUNK_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(START_CALLS.load(Ordering::SeqCst), 1);
    }

}
