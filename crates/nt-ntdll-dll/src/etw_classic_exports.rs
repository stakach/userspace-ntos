//! Classic ETW exports (`advapi32` forwards `RegisterTraceGuids`, `TraceMessage` and the
//! others here). The decisions are `nt_ntdll::etw_classic`: providers register for real; no
//! trace session exists, so nothing can be traced, controlled or started.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

use nt_ntdll::etw::{Guid, ProviderRegistry};
use nt_ntdll::etw_classic::{
    self as classic, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
    ERROR_SUCCESS, INVALID_TRACE_HANDLE,
};

const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;

fn set_last_error(error: u32) {
    unsafe { crate::exports::rtl_set_last_win32_error(error) };
}

// ---- Providers ---------------------------------------------------------------------------------

/// `TRACE_GUID_REGISTRATION { LPCGUID Guid; HANDLE RegHandle; }`.
#[repr(C)]
struct TraceGuidRegistration {
    guid: *const Guid,
    reg_handle: u64,
}

unsafe fn register_trace_guids(
    request_address: *const c_void,
    context: *mut c_void,
    control_guid: *const Guid,
    guid_count: u32,
    trace_guid_reg: *mut TraceGuidRegistration,
    registration_handle: *mut u64,
) -> u32 {
    let status = classic::register_trace_guids_arguments(
        !request_address.is_null(),
        !control_guid.is_null(),
        guid_count,
        !trace_guid_reg.is_null(),
        !registration_handle.is_null(),
    );
    if status != ERROR_SUCCESS {
        return status;
    }
    let provider = unsafe { core::ptr::read_unaligned(control_guid) };
    let handle = match crate::exports::etw_register_provider(
        provider,
        request_address as usize,
        context as usize,
    ) {
        Ok(handle) => handle,
        Err(status) => return status,
    };
    unsafe {
        for index in 0..guid_count as usize {
            let entry = trace_guid_reg.add(index);
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*entry).reg_handle), handle);
        }
        core::ptr::write_unaligned(registration_handle, handle);
    }
    ERROR_SUCCESS
}

/// `RegisterTraceGuidsW(...)`: a real registration; with no session its control callback is
/// never called.
#[export_name = "EtwRegisterTraceGuidsW"]
pub unsafe extern "system" fn etw_register_trace_guids_w(
    request_address: *const c_void,
    context: *mut c_void,
    control_guid: *const Guid,
    guid_count: u32,
    trace_guid_reg: *mut c_void,
    _mof_image_path: *const u16,
    _mof_resource_name: *const u16,
    registration_handle: *mut u64,
) -> u32 {
    unsafe {
        register_trace_guids(
            request_address,
            context,
            control_guid,
            guid_count,
            trace_guid_reg.cast(),
            registration_handle,
        )
    }
}

/// `RegisterTraceGuidsA(...)`: as `RegisterTraceGuidsW`.
#[export_name = "EtwRegisterTraceGuidsA"]
pub unsafe extern "system" fn etw_register_trace_guids_a(
    request_address: *const c_void,
    context: *mut c_void,
    control_guid: *const Guid,
    guid_count: u32,
    trace_guid_reg: *mut c_void,
    _mof_image_path: *const u8,
    _mof_resource_name: *const u8,
    registration_handle: *mut u64,
) -> u32 {
    unsafe {
        register_trace_guids(
            request_address,
            context,
            control_guid,
            guid_count,
            trace_guid_reg.cast(),
            registration_handle,
        )
    }
}

/// `UnregisterTraceGuids(TRACEHANDLE)`.
#[export_name = "EtwUnregisterTraceGuids"]
pub extern "system" fn etw_unregister_trace_guids(registration_handle: u64) -> u32 {
    match crate::exports::etw_unregister_provider(registration_handle) {
        ERROR_SUCCESS => ERROR_SUCCESS,
        _ => ERROR_INVALID_PARAMETER,
    }
}

static TRACE_INSTANCE_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// `CreateTraceInstanceId(HANDLE RegHandle, PEVENT_INSTANCE_INFO InstInfo)`: a fresh instance
/// id for a registered provider.
#[export_name = "EtwCreateTraceInstanceId"]
pub unsafe extern "system" fn etw_create_trace_instance_id(
    registration_handle: u64,
    instance_info: *mut u64,
) -> u32 {
    if instance_info.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    if !crate::exports::etw_provider_registered(registration_handle) {
        return ERROR_INVALID_HANDLE;
    }
    let id = TRACE_INSTANCE_SEQUENCE.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    unsafe {
        // EVENT_INSTANCE_INFO { HANDLE RegHandle; ULONG InstanceId; }.
        core::ptr::write_unaligned(instance_info, registration_handle);
        core::ptr::write_unaligned(instance_info.add(1) as *mut u32, id);
    }
    ERROR_SUCCESS
}

/// `GetTraceLoggerHandle(PVOID Buffer)`: no session ever enabled the provider.
#[export_name = "EtwGetTraceLoggerHandle"]
pub extern "system" fn etw_get_trace_logger_handle(_buffer: *mut c_void) -> u64 {
    set_last_error(ERROR_INVALID_HANDLE);
    INVALID_TRACE_HANDLE
}

/// `GetTraceEnableFlags(TRACEHANDLE)`: no logger handle is valid.
#[export_name = "EtwGetTraceEnableFlags"]
pub extern "system" fn etw_get_trace_enable_flags(_logger: u64) -> u32 {
    set_last_error(ERROR_INVALID_HANDLE);
    0
}

/// `GetTraceEnableLevel(TRACEHANDLE)`: no logger handle is valid.
#[export_name = "EtwGetTraceEnableLevel"]
pub extern "system" fn etw_get_trace_enable_level(_logger: u64) -> u8 {
    set_last_error(ERROR_INVALID_HANDLE);
    0
}

/// `TraceEvent(TRACEHANDLE, PEVENT_TRACE_HEADER)`.
#[export_name = "EtwTraceEvent"]
pub extern "system" fn etw_trace_event(_session: u64, event: *const c_void) -> u32 {
    classic::trace_to_session(!event.is_null())
}

/// `TraceEventInstance(TRACEHANDLE, PEVENT_INSTANCE_HEADER, PEVENT_INSTANCE_INFO, PEVENT_INSTANCE_INFO)`.
#[export_name = "EtwTraceEventInstance"]
pub extern "system" fn etw_trace_event_instance(
    _session: u64,
    event: *const c_void,
    _instance: *const c_void,
    _parent: *const c_void,
) -> u32 {
    classic::trace_to_session(!event.is_null())
}

/// `LogTraceEvent(TRACEHANDLE, PEVENT_TRACE_HEADER)`.
#[export_name = "EtwLogTraceEvent"]
pub extern "system" fn etw_log_trace_event(_session: u64, event: *const c_void) -> u32 {
    classic::trace_to_session(!event.is_null())
}

/// `TraceMessage(TRACEHANDLE, ULONG, LPCGUID, USHORT, ...)`.
#[export_name = "EtwTraceMessage"]
pub extern "C" fn etw_trace_message(_session: u64, _flags: u32, _guid: *const Guid, _number: u16) -> u32 {
    classic::trace_to_session(true)
}

/// `TraceMessageVa(TRACEHANDLE, ULONG, LPCGUID, USHORT, va_list)`.
#[export_name = "EtwTraceMessageVa"]
pub extern "system" fn etw_trace_message_va(
    _session: u64,
    _flags: u32,
    _guid: *const Guid,
    _number: u16,
    _arguments: *mut c_void,
) -> u32 {
    classic::trace_to_session(true)
}

/// `EtwSetMark(TRACEHANDLE, PETW_SET_MARK_INFORMATION, ULONG)`: marks go to a session.
#[export_name = "EtwSetMark"]
pub extern "system" fn etw_set_mark(_session: u64, mark: *const c_void, _size: u32) -> u32 {
    classic::trace_to_session(!mark.is_null())
}

// ---- Sessions ----------------------------------------------------------------------------------

unsafe fn start_trace(session: *mut u64, properties: *const c_void) -> u32 {
    if session.is_null() || properties.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    unsafe { core::ptr::write_unaligned(session, 0) };
    ERROR_NOT_SUPPORTED
}

/// `StartTraceW(PTRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES)`: there is no session service.
#[export_name = "EtwStartTraceW"]
pub unsafe extern "system" fn etw_start_trace_w(
    session: *mut u64,
    _name: *const u16,
    properties: *const c_void,
) -> u32 {
    unsafe { start_trace(session, properties) }
}

/// `StartTraceA(...)`: as `StartTraceW`.
#[export_name = "EtwStartTraceA"]
pub unsafe extern "system" fn etw_start_trace_a(
    session: *mut u64,
    _name: *const u8,
    properties: *const c_void,
) -> u32 {
    unsafe { start_trace(session, properties) }
}

macro_rules! session_control {
    ($export:literal, $function:ident, $name:ty) => {
        /// The named or handled session is not running.
        #[export_name = $export]
        pub extern "system" fn $function(
            _session: u64,
            _name: $name,
            properties: *mut c_void,
        ) -> u32 {
            classic::control_session(!properties.is_null())
        }
    };
}
session_control!("EtwStopTraceW", etw_stop_trace_w, *const u16);
session_control!("EtwStopTraceA", etw_stop_trace_a, *const u8);
session_control!("EtwQueryTraceW", etw_query_trace_w, *const u16);
session_control!("EtwQueryTraceA", etw_query_trace_a, *const u8);
session_control!("EtwFlushTraceW", etw_flush_trace_w, *const u16);
session_control!("EtwFlushTraceA", etw_flush_trace_a, *const u8);
session_control!("EtwUpdateTraceW", etw_update_trace_w, *const u16);
session_control!("EtwUpdateTraceA", etw_update_trace_a, *const u8);

/// `ControlTraceW(TRACEHANDLE, LPCWSTR, PEVENT_TRACE_PROPERTIES, ULONG)`.
#[export_name = "EtwControlTraceW"]
pub extern "system" fn etw_control_trace_w(
    _session: u64,
    _name: *const u16,
    properties: *mut c_void,
    _control_code: u32,
) -> u32 {
    classic::control_session(!properties.is_null())
}

/// `ControlTraceA(...)`: as `ControlTraceW`.
#[export_name = "EtwControlTraceA"]
pub extern "system" fn etw_control_trace_a(
    _session: u64,
    _name: *const u8,
    properties: *mut c_void,
    _control_code: u32,
) -> u32 {
    classic::control_session(!properties.is_null())
}

unsafe fn query_all_traces(array: *mut c_void, count: u32, logger_count: *mut u32) -> u32 {
    match classic::query_all_traces(!array.is_null(), count, !logger_count.is_null()) {
        Ok(sessions) => {
            unsafe { core::ptr::write_unaligned(logger_count, sessions) };
            ERROR_SUCCESS
        }
        Err(status) => status,
    }
}

/// `QueryAllTracesW(PEVENT_TRACE_PROPERTIES*, ULONG, PULONG)`: no session is running.
#[export_name = "EtwQueryAllTracesW"]
pub unsafe extern "system" fn etw_query_all_traces_w(
    array: *mut c_void,
    count: u32,
    logger_count: *mut u32,
) -> u32 {
    unsafe { query_all_traces(array, count, logger_count) }
}

/// `QueryAllTracesA(...)`: as `QueryAllTracesW`.
#[export_name = "EtwQueryAllTracesA"]
pub unsafe extern "system" fn etw_query_all_traces_a(
    array: *mut c_void,
    count: u32,
    logger_count: *mut u32,
) -> u32 {
    unsafe { query_all_traces(array, count, logger_count) }
}

/// `EnableTrace(ULONG, ULONG, ULONG, LPCGUID, TRACEHANDLE)`: no session handle is valid.
#[export_name = "EtwEnableTrace"]
pub extern "system" fn etw_enable_trace(
    _enable: u32,
    _flags: u32,
    _level: u32,
    control_guid: *const Guid,
    _session: u64,
) -> u32 {
    if control_guid.is_null() { ERROR_INVALID_PARAMETER } else { ERROR_INVALID_HANDLE }
}

// ---- Notifications -----------------------------------------------------------------------------

static mut NOTIFICATION_REGISTRY: ProviderRegistry<16> = ProviderRegistry::new();
static NOTIFICATION_LOCK: AtomicU32 = AtomicU32::new(0);

fn with_notifications<T>(body: impl FnOnce(&mut ProviderRegistry<16>) -> T) -> T {
    while NOTIFICATION_LOCK
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let result = body(unsafe { &mut *core::ptr::addr_of_mut!(NOTIFICATION_REGISTRY) });
    NOTIFICATION_LOCK.store(0, Ordering::Release);
    result
}

/// `EtwNotificationRegister(LPCGUID, ULONG Type, PETW_NOTIFICATION_CALLBACK, PVOID, PREGHANDLE)`:
/// a real registration; no notification is ever delivered because nothing sends one.
#[export_name = "EtwNotificationRegister"]
pub unsafe extern "system" fn etw_notification_register(
    guid: *const Guid,
    _notification_type: u32,
    callback: *const c_void,
    context: *mut c_void,
    registration: *mut u64,
) -> u32 {
    if guid.is_null() || callback.is_null() || registration.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let guid = unsafe { core::ptr::read_unaligned(guid) };
    match with_notifications(|registry| registry.register(guid, callback as usize, context as usize)) {
        Ok(handle) => {
            unsafe { core::ptr::write_unaligned(registration, handle) };
            ERROR_SUCCESS
        }
        Err(status) => status,
    }
}

/// `EtwNotificationUnregister(REGHANDLE, PVOID* Context)`.
#[export_name = "EtwNotificationUnregister"]
pub unsafe extern "system" fn etw_notification_unregister(
    registration: u64,
    context: *mut *mut c_void,
) -> u32 {
    let status = with_notifications(|registry| registry.unregister(registration));
    if status == ERROR_SUCCESS && !context.is_null() {
        unsafe { core::ptr::write_unaligned(context, core::ptr::null_mut()) };
    }
    status
}

// ---- Session-service plumbing with no service behind it ------------------------------------------

macro_rules! no_session_service {
    ($export:literal, $function:ident, $status:expr) => {
        /// Session-service plumbing; this personality has no ETW session service.
        #[export_name = $export]
        pub extern "system" fn $function() -> u32 {
            $status
        }
    };
}
no_session_service!("EtwEnumerateTraceGuids", etw_enumerate_trace_guids, ERROR_NOT_SUPPORTED);
no_session_service!(
    "EtwEnumerateProcessRegGuids",
    etw_enumerate_process_reg_guids,
    ERROR_NOT_SUPPORTED
);
no_session_service!("EtwNotificationRegistrationA", etw_notification_registration_a, ERROR_NOT_SUPPORTED);
no_session_service!("EtwNotificationRegistrationW", etw_notification_registration_w, ERROR_NOT_SUPPORTED);
no_session_service!("EtwReceiveNotificationsA", etw_receive_notifications_a, ERROR_NOT_SUPPORTED);
no_session_service!("EtwReceiveNotificationsW", etw_receive_notifications_w, ERROR_NOT_SUPPORTED);
no_session_service!("EtwReplyNotification", etw_reply_notification, ERROR_NOT_SUPPORTED);
no_session_service!("EtwSendNotification", etw_send_notification, ERROR_NOT_SUPPORTED);
no_session_service!(
    "EtwProcessPrivateLoggerRequest",
    etw_process_private_logger_request,
    ERROR_NOT_SUPPORTED
);
no_session_service!("EtwRegisterSecurityProvider", etw_register_security_provider, ERROR_NOT_SUPPORTED);
no_session_service!("EtwDeliverDataBlock", etw_deliver_data_block, ERROR_NOT_SUPPORTED);
no_session_service!("EtwpCreateEtwThread", etwp_create_etw_thread, STATUS_NOT_SUPPORTED);
no_session_service!("EtwpGetCpuSpeed", etwp_get_cpu_speed, STATUS_NOT_SUPPORTED);
no_session_service!("EtwpGetTraceBuffer", etwp_get_trace_buffer, STATUS_NOT_SUPPORTED);
no_session_service!("EtwpNotificationThread", etwp_notification_thread, STATUS_NOT_SUPPORTED);
no_session_service!("EtwpSetHWConfigFunction", etwp_set_hw_config_function, STATUS_NOT_SUPPORTED);
