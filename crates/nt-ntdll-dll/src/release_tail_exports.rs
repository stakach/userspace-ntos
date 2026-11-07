//! The remaining pinned LiberNT ntdll entry points with source-checked AMD64 contracts.

use core::ffi::c_void;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const ALPC_COMPLETION_LIST_RUNDOWN_INFORMATION: u64 = 10;

/// Native completion-list teardown carries the port handle through the existing ALPC service.
#[export_name = "AlpcRundownCompletionList"]
pub unsafe extern "system" fn alpc_rundown_completion_list(port: *mut c_void) -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    {
        // SAFETY: no user buffer is passed; the native provider owns rundown of `port`.
        unsafe {
            nt_ntdll::trap_stubs::nt_alpc_set_information(
                port as u64,
                ALPC_COMPLETION_LIST_RUNDOWN_INFORMATION,
                0,
                0,
            ) as u32
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
    {
        let _ = port;
        STATUS_NOT_IMPLEMENTED
    }
}

// These three exported PCs are fault-recovery labels inside Windows' assembly SList pop
// implementation. This personality has no kernel-side PC patching contract for them. Trapping
// on an unexpected call is safer than pretending to complete a partial lock-free operation.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
macro_rules! fault_label {
    ($name:ident, $export:literal) => {
        #[unsafe(naked)]
        #[export_name = $export]
        pub unsafe extern "C" fn $name() -> ! {
            core::arch::naked_asm!("ud2");
        }
    };
}

#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fault_label!(
    exp_interlocked_pop_entry_slist_end,
    "ExpInterlockedPopEntrySListEnd"
);
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fault_label!(
    exp_interlocked_pop_entry_slist_fault,
    "ExpInterlockedPopEntrySListFault"
);
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
fault_label!(
    exp_interlocked_pop_entry_slist_resume,
    "ExpInterlockedPopEntrySListResume"
);

/// Compact every currently registered process heap, including private heaps.
#[export_name = "RtlFlushHeaps"]
pub unsafe extern "system" fn rtl_flush_heaps() -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    {
        let mut stack = [core::ptr::null_mut(); 64];
        let mut ptr = stack.as_mut_ptr();
        let mut capacity = stack.len();
        loop {
            // SAFETY: `ptr` owns `capacity` writable handle slots for this query.
            let count =
                unsafe { crate::exports::rtl_get_process_heaps(capacity as u32, ptr) } as usize;
            if count <= capacity {
                for index in 0..count {
                    // SAFETY: every returned handle names a process heap at query time.
                    unsafe { crate::exports::rtl_compact_heap(*ptr.add(index), 0) };
                }
                if ptr != stack.as_mut_ptr() {
                    unsafe { crate::process_heap_free(ptr.cast()) };
                }
                return STATUS_SUCCESS;
            }
            let Some(bytes) = count.checked_mul(core::mem::size_of::<*mut c_void>()) else {
                if ptr != stack.as_mut_ptr() {
                    unsafe { crate::process_heap_free(ptr.cast()) };
                }
                return STATUS_NO_MEMORY;
            };
            let next = unsafe { crate::process_heap_alloc(bytes) } as *mut *mut c_void;
            if next.is_null() {
                if ptr != stack.as_mut_ptr() {
                    unsafe { crate::process_heap_free(ptr.cast()) };
                }
                return STATUS_NO_MEMORY;
            }
            if ptr != stack.as_mut_ptr() {
                unsafe { crate::process_heap_free(ptr.cast()) };
            }
            ptr = next;
            capacity = count;
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "windows")))]
    {
        STATUS_NOT_IMPLEMENTED
    }
}

/// The released AMD64 build has no CFG range provider and reports unsupported registration.
#[export_name = "RtlRegisterCfgTargetRange"]
pub extern "system" fn rtl_register_cfg_target_range(_base: *mut c_void, _size: usize) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// Released AMD64 has no dynamic CFG range to remove.
#[export_name = "RtlUnregisterCfgTargetRange"]
pub extern "system" fn rtl_unregister_cfg_target_range(_base: *mut c_void) {}

/// Released AMD64 has no CFG range provider and reports unsupported target updates.
#[export_name = "RtlSetCfgTargetValidity"]
pub extern "system" fn rtl_set_cfg_target_validity(
    _base: *mut c_void,
    _size: usize,
    _count: u32,
    _targets: *mut c_void,
) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// No WNF provider is registered. Release source clears the change stamp on failure.
#[export_name = "RtlQueryWnfStateData"]
pub unsafe extern "system" fn rtl_query_wnf_state_data(
    change_stamp: *mut u32,
    _state_name: u64,
    _callback: *mut c_void,
    _callback_context: *mut c_void,
    _type_id: *mut c_void,
    _flags: u32,
) -> u32 {
    if !change_stamp.is_null() {
        unsafe { *change_stamp = 0 };
    }
    STATUS_NOT_IMPLEMENTED
}

/// No WNF provider is registered. No callback or subscription is retained.
#[export_name = "RtlSubscribeWnfStateChangeNotification"]
pub unsafe extern "system" fn rtl_subscribe_wnf_state_change_notification(
    subscription: *mut *mut c_void,
    _state_name: u64,
    _change_stamp: u32,
    _callback: *mut c_void,
    _callback_context: *mut c_void,
    _type_id: *mut c_void,
    _serialization_group: u32,
    _unknown: u32,
    _flags: u32,
) -> u32 {
    if !subscription.is_null() {
        unsafe { *subscription = core::ptr::null_mut() };
    }
    STATUS_NOT_IMPLEMENTED
}

#[export_name = "RtlUnsubscribeWnfNotificationWaitForCompletion"]
pub extern "system" fn rtl_unsubscribe_wnf_notification_wait_for_completion(
    _subscription: *mut c_void,
) -> u32 {
    STATUS_NOT_IMPLEMENTED
}

/// The released implementation consumes a three-word descriptor without a telemetry provider.
///
/// # Safety
/// `codepath` points to three readable DWORDs.
#[export_name = "RtlLogUnexpectedCodepath"]
pub unsafe extern "system" fn rtl_log_unexpected_codepath(codepath: *const u32) -> u32 {
    if codepath.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let value = unsafe {
        core::ptr::read_volatile(codepath)
            ^ core::ptr::read_volatile(codepath.add(1))
            ^ core::ptr::read_volatile(codepath.add(2))
    };
    core::hint::black_box(value);
    STATUS_SUCCESS
}

#[used]
pub static RELEASE_TAIL_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = release_tail_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn release_tail_export_anchor() {
    #[cfg(all(target_arch = "x86_64", target_os = "windows"))]
    core::hint::black_box([
        exp_interlocked_pop_entry_slist_end as *const () as usize,
        exp_interlocked_pop_entry_slist_fault as *const () as usize,
        exp_interlocked_pop_entry_slist_resume as *const () as usize,
    ]);
    core::hint::black_box([
        alpc_rundown_completion_list as *const () as usize,
        rtl_flush_heaps as *const () as usize,
        rtl_register_cfg_target_range as *const () as usize,
        rtl_unregister_cfg_target_range as *const () as usize,
        rtl_set_cfg_target_validity as *const () as usize,
        rtl_query_wnf_state_data as *const () as usize,
        rtl_subscribe_wnf_state_change_notification as *const () as usize,
        rtl_unsubscribe_wnf_notification_wait_for_completion as *const () as usize,
        rtl_log_unexpected_codepath as *const () as usize,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_wnf_provider_clears_outputs_and_fails() {
        let mut stamp = 9;
        assert_eq!(
            unsafe {
                rtl_query_wnf_state_data(
                    &mut stamp,
                    1,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    0,
                )
            },
            STATUS_NOT_IMPLEMENTED
        );
        assert_eq!(stamp, 0);
        let mut subscription = 1usize as *mut c_void;
        assert_eq!(
            unsafe {
                rtl_subscribe_wnf_state_change_notification(
                    &mut subscription,
                    1,
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    0,
                    0,
                    0,
                )
            },
            STATUS_NOT_IMPLEMENTED
        );
        assert!(subscription.is_null());
    }

    #[test]
    fn amd64_cfg_contract_and_descriptor_validation() {
        assert_eq!(
            rtl_register_cfg_target_range(core::ptr::null_mut(), 0),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(
            rtl_set_cfg_target_validity(core::ptr::null_mut(), 0, 0, core::ptr::null_mut()),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(
            unsafe { rtl_log_unexpected_codepath(core::ptr::null()) },
            STATUS_INVALID_PARAMETER
        );
        let words = [1, 2, 3];
        assert_eq!(
            unsafe { rtl_log_unexpected_codepath(words.as_ptr()) },
            STATUS_SUCCESS
        );
    }
}
