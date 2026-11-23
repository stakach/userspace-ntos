//! Additional exports carried by the released LiberNT loader ABI.

use core::ffi::c_void;
use nt_ntdll_layout::UnicodeString;

const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Return the process loader's recorded full pathname for a mapped module.
///
/// # Safety
/// `name` must point to a writable x64 UNICODE_STRING and its advertised buffer must be writable.
#[export_name = "LdrGetDllFullName"]
pub unsafe extern "system" fn ldr_get_dll_full_name(module: *mut c_void, name: *mut c_void) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        let _lock = match unsafe { crate::exports::acquire_loader_lock() } {
            Ok(lock) => lock,
            Err(status) => return status,
        };
        unsafe { crate::on_target::ldr_get_dll_full_name(module, name) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (module, name);
        STATUS_NOT_IMPLEMENTED
    }
}

#[cfg(target_arch = "x86_64")]
include!(concat!(env!("OUT_DIR"), "/release_api_sets.rs"));

/// The running process's advertised OS version selects the release's active contracts.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn current_api_set_version() -> u8 {
    let peb: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags, readonly));
        nt_ntdll::loader::api_set::api_set_version(
            core::ptr::read_unaligned((peb + 0x118) as *const u32),
            core::ptr::read_unaligned((peb + 0x11c) as *const u32),
        )
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn query_counted_api_set_presence(
    name: *const UnicodeString,
    match_family: bool,
) -> Result<(bool, bool), u32> {
    // Read the fields independently: native UNICODE_STRING padding need not be initialized.
    let (length, maximum_length, buffer) = unsafe {
        (
            core::ptr::addr_of!((*name).length).read_unaligned(),
            core::ptr::addr_of!((*name).maximum_length).read_unaligned(),
            core::ptr::addr_of!((*name).buffer).read_unaligned(),
        )
    };
    if length & 1 != 0
        || maximum_length & 1 != 0
        || length > maximum_length
        || (length != 0
            && (buffer == 0
                || buffer & 1 != 0
                || buffer.checked_add(u64::from(length)).is_none()))
    {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let units = if length == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(buffer as *const u16, length as usize / 2) }
    };
    nt_ntdll::loader::api_set::query_api_set_presence(
        RELEASE_API_SETS,
        units,
        unsafe { current_api_set_version() },
        match_family,
    )
}

/// Query whether the contract family has a host in the process's active API-set schema.
///
/// # Safety
/// `name` points to a readable counted UNICODE_STRING and `present` to a writable BOOLEAN.
#[export_name = "ApiSetQueryApiSetPresence"]
pub unsafe extern "system" fn api_set_query_api_set_presence(
    name: *const UnicodeString,
    present: *mut u8,
) -> u32 {
    if name.is_null() || present.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let (_, has_host) = match unsafe { query_counted_api_set_presence(name, true) } {
            Ok(result) => result,
            Err(status) => return status,
        };
        unsafe { present.write(u8::from(has_host)) };
        0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        STATUS_NOT_IMPLEMENTED
    }
}

/// Query exact schema membership and host presence for an extension-free contract name.
///
/// # Safety
/// `name` points to a readable counted UNICODE_STRING. Both outputs are writable BOOLEANs.
#[cfg(target_arch = "x86_64")]
#[export_name = "ApiSetQueryApiSetPresenceEx"]
pub unsafe extern "system" fn api_set_query_api_set_presence_ex(
    name: *const UnicodeString,
    in_schema: *mut u8,
    present: *mut u8,
) -> u32 {
    if name.is_null() || in_schema.is_null() || present.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let (member, has_host) = match unsafe { query_counted_api_set_presence(name, false) } {
        Ok(result) => result,
        Err(status) => return status,
    };
    unsafe {
        in_schema.write(u8::from(member));
        present.write(u8::from(has_host));
    }
    0
}

/// Resolve one PE delay import. Failure is represented by a null function pointer; the current
/// loader has no delay-load failure callback/exception ownership, so it cannot safely perform a
/// partial IAT update before those hooks are installed.
///
/// # Safety
/// The pointer arguments follow the Windows delay-load ABI.
#[export_name = "LdrResolveDelayLoadedAPI"]
pub unsafe extern "system" fn ldr_resolve_delay_loaded_api(
    _base: *mut c_void,
    _descriptor: *const c_void,
    _dll_hook: *const c_void,
    _system_hook: *const c_void,
    _thunk: *mut c_void,
    _flags: u32,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// Eagerly resolve one DLL's delay imports. Do not report success without updating its IAT.
///
/// # Safety
/// `image` and `dll_name` follow the Windows loader ABI.
#[export_name = "LdrResolveDelayLoadsFromDll"]
pub unsafe extern "system" fn ldr_resolve_delay_loads_from_dll(
    _image: *mut c_void,
    _dll_name: *const u8,
    _flags: u32,
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

#[used]
pub static LOADER_EXTRA_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = loader_extra_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn loader_extra_anchor() {
    core::hint::black_box(ldr_get_dll_full_name as *const () as usize);
    core::hint::black_box(api_set_query_api_set_presence as *const () as usize);
    #[cfg(target_arch = "x86_64")]
    core::hint::black_box(api_set_query_api_set_presence_ex as *const () as usize);
    core::hint::black_box(ldr_resolve_delay_loaded_api as *const () as usize);
    core::hint::black_box(ldr_resolve_delay_loads_from_dll as *const () as usize);
}
