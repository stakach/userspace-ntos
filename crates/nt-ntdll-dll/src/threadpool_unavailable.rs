//! Exact Tp ABI entries whose native callback and completion ownership is not integrated yet.
//!
//! A caller can resolve every released Tp name, but unsupported object creation fails before it
//! publishes a handle. Void operations raise an NT status instead of silently dropping work.

use core::ffi::c_void;

use crate::threadpool_state::{reject_object_allocation, STATUS_NOT_SUPPORTED};

macro_rules! unsupported_alloc {
    ($name:ident, $export:literal, $out:ident $(, $arg:ident: $ty:ty)*) => {
        #[export_name = $export]
        pub unsafe extern "system" fn $name($out: *mut *mut c_void $(, $arg: $ty)*) -> u32 {
            let _ = ($($arg,)*);
            unsafe { reject_object_allocation($out) }
        }
    };
}

macro_rules! unsupported_status {
    ($name:ident, $export:literal $(, $arg:ident: $ty:ty)*) => {
        #[export_name = $export]
        pub unsafe extern "system" fn $name($($arg: $ty),*) -> u32 {
            let _ = ($($arg,)*);
            STATUS_NOT_SUPPORTED
        }
    };
}

macro_rules! unsupported_bool {
    ($name:ident, $export:literal $(, $arg:ident: $ty:ty)*) => {
        #[export_name = $export]
        pub unsafe extern "system" fn $name($($arg: $ty),*) -> u32 {
            let _ = ($($arg,)*);
            0
        }
    };
}

macro_rules! unsupported_void {
    ($name:ident, $export:literal $(, $arg:ident: $ty:ty)*) => {
        #[export_name = $export]
        pub unsafe extern "system" fn $name($($arg: $ty),*) {
            let _ = ($($arg,)*);
            unsafe { crate::exports::rtl_raise_status(STATUS_NOT_SUPPORTED) };
            loop { core::hint::spin_loop(); }
        }
    };
}

// Allocators return a failure and clear their output. Exact arities follow the pinned LiberNT
// ntdll.spec and winternl.h; these object families need independent native effect ownership.
unsupported_alloc!(tp_alloc_alpc_completion, "TpAllocAlpcCompletion", out,
    port: *mut c_void, callback: *mut c_void, context: *mut c_void, environment: *mut c_void);
unsupported_alloc!(tp_alloc_alpc_completion_ex, "TpAllocAlpcCompletionEx", out,
    port: *mut c_void, callback: *mut c_void, context: *mut c_void, environment: *mut c_void);
unsupported_alloc!(tp_alloc_cleanup_group, "TpAllocCleanupGroup", out);
unsupported_alloc!(tp_alloc_io_completion, "TpAllocIoCompletion", out,
    file: *mut c_void, callback: *mut c_void, context: *mut c_void, environment: *mut c_void);
unsupported_alloc!(tp_alloc_pool, "TpAllocPool", out, reserved: *mut c_void);
unsupported_alloc!(tp_alloc_timer, "TpAllocTimer", out,
    callback: *mut c_void, context: *mut c_void, environment: *mut c_void);
unsupported_alloc!(tp_alloc_wait, "TpAllocWait", out,
    callback: *mut c_void, context: *mut c_void, environment: *mut c_void);

unsupported_void!(tp_alpc_register_completion_list, "TpAlpcRegisterCompletionList", alpc: *mut c_void);
unsupported_void!(tp_alpc_unregister_completion_list, "TpAlpcUnregisterCompletionList", alpc: *mut c_void);
unsupported_void!(tp_callback_leave_critical_section_on_completion,
    "TpCallbackLeaveCriticalSectionOnCompletion", instance: *mut c_void, section: *mut c_void);
unsupported_status!(tp_callback_may_run_long, "TpCallbackMayRunLong", instance: *mut c_void);
unsupported_void!(tp_callback_release_mutex_on_completion,
    "TpCallbackReleaseMutexOnCompletion", instance: *mut c_void, mutex: *mut c_void);
unsupported_void!(tp_callback_release_semaphore_on_completion,
    "TpCallbackReleaseSemaphoreOnCompletion", instance: *mut c_void, semaphore: *mut c_void, count: u32);
unsupported_status!(tp_callback_send_alpc_message_on_completion,
    "TpCallbackSendAlpcMessageOnCompletion", instance: *mut c_void, port: *mut c_void,
    flags: u32, message: *mut c_void);
unsupported_status!(tp_callback_send_pending_alpc_message,
    "TpCallbackSendPendingAlpcMessage", instance: *mut c_void);
unsupported_void!(tp_callback_set_event_on_completion,
    "TpCallbackSetEventOnCompletion", instance: *mut c_void, event: *mut c_void);
unsupported_void!(tp_callback_unload_dll_on_completion,
    "TpCallbackUnloadDllOnCompletion", instance: *mut c_void, module: *mut c_void);
unsupported_void!(tp_cancel_async_io_operation, "TpCancelAsyncIoOperation", io: *mut c_void);
unsupported_void!(tp_disassociate_callback, "TpDisassociateCallback", instance: *mut c_void);
unsupported_bool!(tp_is_timer_set, "TpIsTimerSet", timer: *mut c_void);
unsupported_status!(tp_query_pool_stack_information,
    "TpQueryPoolStackInformation", pool: *mut c_void, information: *mut c_void);

unsupported_void!(tp_release_alpc_completion, "TpReleaseAlpcCompletion", alpc: *mut c_void);
unsupported_void!(tp_release_cleanup_group, "TpReleaseCleanupGroup", group: *mut c_void);
unsupported_void!(tp_release_cleanup_group_members, "TpReleaseCleanupGroupMembers",
    group: *mut c_void, cancel_pending: u32, context: *mut c_void);
unsupported_void!(tp_release_io_completion, "TpReleaseIoCompletion", io: *mut c_void);
unsupported_void!(tp_release_pool, "TpReleasePool", pool: *mut c_void);
unsupported_void!(tp_release_timer, "TpReleaseTimer", timer: *mut c_void);
unsupported_void!(tp_release_wait, "TpReleaseWait", wait: *mut c_void);
unsupported_void!(tp_set_pool_max_threads, "TpSetPoolMaxThreads", pool: *mut c_void, maximum: u32);
unsupported_bool!(tp_set_pool_min_threads, "TpSetPoolMinThreads", pool: *mut c_void, minimum: u32);
unsupported_status!(tp_set_pool_stack_information,
    "TpSetPoolStackInformation", pool: *mut c_void, information: *mut c_void);
unsupported_void!(tp_set_timer, "TpSetTimer",
    timer: *mut c_void, due_time: *const i64, period: i32, window: i32);
unsupported_bool!(tp_set_timer_ex, "TpSetTimerEx",
    timer: *mut c_void, due_time: *const i64, period: i32, window: i32);
unsupported_void!(tp_set_wait, "TpSetWait",
    wait: *mut c_void, handle: *mut c_void, timeout: *const i64);
unsupported_bool!(tp_set_wait_ex, "TpSetWaitEx",
    wait: *mut c_void, handle: *mut c_void, timeout: *const i64, reserved: *mut c_void);
unsupported_void!(tp_start_async_io_operation, "TpStartAsyncIoOperation", io: *mut c_void);
unsupported_void!(tp_wait_for_alpc_completion, "TpWaitForAlpcCompletion", alpc: *mut c_void);
unsupported_void!(tp_wait_for_io_completion, "TpWaitForIoCompletion", io: *mut c_void, cancel: u32);
unsupported_void!(tp_wait_for_timer, "TpWaitForTimer", timer: *mut c_void, cancel: u32);
unsupported_void!(tp_wait_for_wait, "TpWaitForWait", wait: *mut c_void, cancel: u32);

#[used]
pub static THREADPOOL_UNAVAILABLE_EXPORT_ANCHOR_FN: unsafe extern "C" fn() =
    threadpool_unavailable_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Stored only in a `#[used]` static.
pub unsafe extern "C" fn threadpool_unavailable_export_anchor() {
    core::hint::black_box([
        tp_alloc_alpc_completion as *const () as usize,
        tp_alloc_alpc_completion_ex as *const () as usize,
        tp_alloc_cleanup_group as *const () as usize,
        tp_alloc_io_completion as *const () as usize,
        tp_alloc_pool as *const () as usize,
        tp_alloc_timer as *const () as usize,
        tp_alloc_wait as *const () as usize,
        tp_alpc_register_completion_list as *const () as usize,
        tp_alpc_unregister_completion_list as *const () as usize,
        tp_callback_leave_critical_section_on_completion as *const () as usize,
        tp_callback_may_run_long as *const () as usize,
        tp_callback_release_mutex_on_completion as *const () as usize,
        tp_callback_release_semaphore_on_completion as *const () as usize,
        tp_callback_send_alpc_message_on_completion as *const () as usize,
        tp_callback_send_pending_alpc_message as *const () as usize,
        tp_callback_set_event_on_completion as *const () as usize,
        tp_callback_unload_dll_on_completion as *const () as usize,
        tp_cancel_async_io_operation as *const () as usize,
        tp_disassociate_callback as *const () as usize,
        tp_is_timer_set as *const () as usize,
        tp_query_pool_stack_information as *const () as usize,
        tp_release_alpc_completion as *const () as usize,
        tp_release_cleanup_group as *const () as usize,
        tp_release_cleanup_group_members as *const () as usize,
        tp_release_io_completion as *const () as usize,
        tp_release_pool as *const () as usize,
        tp_release_timer as *const () as usize,
        tp_release_wait as *const () as usize,
        tp_set_pool_max_threads as *const () as usize,
        tp_set_pool_min_threads as *const () as usize,
        tp_set_pool_stack_information as *const () as usize,
        tp_set_timer as *const () as usize,
        tp_set_timer_ex as *const () as usize,
        tp_set_wait as *const () as usize,
        tp_set_wait_ex as *const () as usize,
        tp_start_async_io_operation as *const () as usize,
        tp_wait_for_alpc_completion as *const () as usize,
        tp_wait_for_io_completion as *const () as usize,
        tp_wait_for_timer as *const () as usize,
        tp_wait_for_wait as *const () as usize,
    ]);
}
