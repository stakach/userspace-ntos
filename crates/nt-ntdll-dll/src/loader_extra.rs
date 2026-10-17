//! Additional exports carried by the released LiberNT loader ABI.

use core::ffi::c_void;

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

/// Query the process API-set namespace. No namespace is installed by this loader yet; return a
/// real failure instead of claiming that a contract is absent from a schema we have not read.
///
/// # Safety
/// The caller owns the optional writable `present` byte.
#[export_name = "ApiSetQueryApiSetPresence"]
pub unsafe extern "system" fn api_set_query_api_set_presence(
    name: *const c_void,
    present: *mut u8,
) -> u32 {
    if name.is_null() || present.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_NOT_IMPLEMENTED
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
    core::hint::black_box(ldr_resolve_delay_loaded_api as *const () as usize);
    core::hint::black_box(ldr_resolve_delay_loads_from_dll as *const () as usize);
}
