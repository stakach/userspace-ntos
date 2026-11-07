//! Miscellaneous released ntdll entry points with verified source ABIs.
//!
//! These functions are kept separate from the loader and native syscall paths.

use core::ffi::c_void;

use nt_ntdll_layout::UnicodeString;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

type HeapEnumerationRoutine = unsafe extern "system" fn(*mut c_void, *mut c_void) -> u32;

/// The Ex entry has exactly the same five-argument contract as the regular
/// registry query in the Wine export specification.
///
/// # Safety
/// The arguments meet the `RtlQueryRegistryValues` contract.
#[export_name = "RtlQueryRegistryValuesEx"]
pub unsafe extern "system" fn rtl_query_registry_values_ex(
    relative_to: u32,
    path: *const u16,
    query_table: *mut c_void,
    context: *mut c_void,
    environment: *mut c_void,
) -> u32 {
    unsafe {
        crate::exports::rtl_query_registry_values(
            relative_to,
            path,
            query_table,
            context,
            environment,
        )
    }
}

/// Enumerate the process heaps through the existing process-heap authority.
/// The callback's first failure is returned without invoking later callbacks.
///
/// # Safety
/// `callback` is callable and `parameter` meets its contract.
#[export_name = "RtlEnumProcessHeaps"]
pub unsafe extern "system" fn rtl_enum_process_heaps(
    callback: Option<HeapEnumerationRoutine>,
    parameter: *mut c_void,
) -> u32 {
    let Some(callback) = callback else {
        return STATUS_INVALID_PARAMETER;
    };
    let count = unsafe { crate::exports::rtl_get_process_heaps(0, core::ptr::null_mut()) };
    // The current heap implementation registers one process heap. Fail closed
    // if the registry grows; enumerating only a prefix would report success
    // for an incomplete enumeration.
    if count > 1 {
        return STATUS_NOT_IMPLEMENTED;
    }
    if count == 0 {
        return STATUS_SUCCESS;
    }
    let mut heap = core::ptr::null_mut();
    let observed = unsafe { crate::exports::rtl_get_process_heaps(1, &mut heap) };
    if observed != count || heap.is_null() {
        return STATUS_NOT_IMPLEMENTED;
    }
    unsafe { callback(heap, parameter) }
}

/// Locale-name validity follows the same NLS mapping and neutral-locale flag
/// policy as the existing `RtlLocaleNameToLcid` entry.
///
/// # Safety
/// `name` is a NUL-terminated UTF-16 locale name.
#[export_name = "RtlIsValidLocaleName"]
pub unsafe extern "system" fn rtl_is_valid_locale_name(name: *const u16, flags: u32) -> u8 {
    if name.is_null() {
        return 0;
    }
    let mut lcid = 0u32;
    u8::from(
        unsafe { crate::exports::rtl_locale_name_to_lcid(name, &mut lcid, flags) }
            == STATUS_SUCCESS,
    )
}

/// No device-family provider is registered yet. Report unknown family and form
/// rather than inventing a desktop identity for the host.
///
/// # Safety
/// Non-null outputs are writable for their scalar type.
#[export_name = "RtlGetDeviceFamilyInfoEnum"]
pub unsafe extern "system" fn rtl_get_device_family_info_enum(
    version: *mut u64,
    family: *mut u32,
    form: *mut u32,
) {
    if !version.is_null() {
        unsafe { *version = 0 };
    }
    if !family.is_null() {
        unsafe { *family = 0 };
    }
    if !form.is_null() {
        unsafe { *form = 0 };
    }
}

/// The ReactOS implementation does not support WOW64 APC queueing yet.
#[export_name = "RtlQueueApcWow64Thread"]
pub extern "system" fn rtl_queue_apc_wow64_thread(
    _thread: *mut c_void,
    _routine: *const c_void,
    _context: *mut c_void,
    _argument1: *mut c_void,
    _argument2: *mut c_void,
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// ReactOS reports this facility as unimplemented; no callback is retained.
#[export_name = "RtlRegisterSecureMemoryCacheCallback"]
pub extern "system" fn rtl_register_secure_memory_cache_callback(_callback: *const c_void) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// Remote thread context modification requires a native process/thread owner.
#[export_name = "RtlRemoteCall"]
pub extern "system" fn rtl_remote_call(
    _process: *mut c_void,
    _thread: *mut c_void,
    _site: *const c_void,
    _argument_count: u32,
    _arguments: *const u32,
    _pass_context: u8,
    _already_suspended: u8,
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// The volume folder's ACL and filesystem mutation must be one native effect.
#[export_name = "RtlCreateSystemVolumeInformationFolder"]
pub extern "system" fn rtl_create_system_volume_information_folder(
    _root: *const UnicodeString,
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// The source implementation performs name canonicalization and allocates a
/// process-heap buffer. An unsupported conversion must not return an empty
/// successful list, which would drop caller-supplied computer names.
#[export_name = "RtlConvertUiListToApiList"]
pub extern "system" fn rtl_convert_ui_list_to_api_list(
    _input: *const UnicodeString,
    _output: *mut UnicodeString,
    _blank_delimiter: u8,
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// This ReactOS ABI returns a pointer and reports unsupported operation by NULL.
#[export_name = "RtlProtectHeap"]
pub extern "system" fn rtl_protect_heap(_heap: *mut c_void, _read_only: u8) -> *mut c_void {
    core::ptr::null_mut()
}

/// Cross-process emulator work sharing is absent. Always clear the two output
/// slots, matching Wine's no-mapping result without manufacturing a section.
///
/// # Safety
/// Non-null outputs are writable pointer slots.
#[export_name = "RtlOpenCrossProcessEmulatorWorkConnection"]
pub unsafe extern "system" fn rtl_open_cross_process_emulator_work_connection(
    _process: *mut c_void,
    section: *mut *mut c_void,
    address: *mut *mut c_void,
) {
    if !section.is_null() {
        unsafe { *section = core::ptr::null_mut() };
    }
    if !address.is_null() {
        unsafe { *address = core::ptr::null_mut() };
    }
}

/// Windows SQM's three-DWORD counter hook is telemetry-only in Wine and has
/// no observable state in this NT personality.
#[export_name = "WinSqmIncrementDWORD"]
pub extern "system" fn win_sqm_increment_dword(_session: u32, _counter: u32, _amount: u32) {}

#[used]
pub static REMAINING_MISC_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = remaining_misc_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn remaining_misc_export_anchor() {
    core::hint::black_box([
        rtl_query_registry_values_ex as *const () as usize,
        rtl_enum_process_heaps as *const () as usize,
        rtl_is_valid_locale_name as *const () as usize,
        rtl_get_device_family_info_enum as *const () as usize,
        rtl_queue_apc_wow64_thread as *const () as usize,
        rtl_register_secure_memory_cache_callback as *const () as usize,
        rtl_remote_call as *const () as usize,
        rtl_create_system_volume_information_folder as *const () as usize,
        rtl_convert_ui_list_to_api_list as *const () as usize,
        rtl_protect_heap as *const () as usize,
        rtl_open_cross_process_emulator_work_connection as *const () as usize,
        win_sqm_increment_dword as *const () as usize,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_effects_fail_closed() {
        assert_eq!(
            rtl_queue_apc_wow64_thread(
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut()
            ),
            STATUS_NOT_IMPLEMENTED
        );
        assert_eq!(
            rtl_register_secure_memory_cache_callback(core::ptr::null()),
            STATUS_NOT_IMPLEMENTED
        );
        assert_eq!(
            rtl_remote_call(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                0
            ),
            STATUS_NOT_IMPLEMENTED
        );
        assert_eq!(
            rtl_protect_heap(core::ptr::null_mut(), 1),
            core::ptr::null_mut()
        );
        assert_eq!(
            rtl_enum_process_heaps(None, core::ptr::null_mut()),
            STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn absent_emulator_mapping_clears_both_outputs() {
        let mut section = 1usize as *mut c_void;
        let mut address = 2usize as *mut c_void;
        unsafe {
            rtl_open_cross_process_emulator_work_connection(
                core::ptr::null_mut(),
                &mut section,
                &mut address,
            )
        };
        assert!(section.is_null());
        assert!(address.is_null());
    }

    #[test]
    fn desktop_family_matches_wine_contract() {
        let mut version = u64::MAX;
        let mut family = u32::MAX;
        let mut form = u32::MAX;
        unsafe { rtl_get_device_family_info_enum(&mut version, &mut family, &mut form) };
        assert_eq!((version, family, form), (0, 3, 0));
    }
}
