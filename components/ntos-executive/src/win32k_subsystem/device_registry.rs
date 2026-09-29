//! Win32k's PDO-scoped IoOpenDeviceRegistryKey import.

use super::*;

const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BBu32 as i32;
const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033u32 as i32;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

pub(super) extern "win64" fn open_device_registry_key(
    device_object: u64,
    key_type: u32,
    desired_access: u32,
    handle_out: *mut u64,
) -> i32 {
    unsafe {
        if handle_out.is_null() {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let (words, raw, handle, out2, out3) = crate::driver_launch::call_on4_raw(
            (W32_REGISTRY_LABEL << 12) | 4,
            WIN32K_REGISTRY_OP_OPEN_DEVICE_KEY,
            device_object,
            key_type as u64,
            desired_access as u64,
        );
        if words != 4
            || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64)
            || out2 != 0
            || out3 != 0
        {
            crate::provider_bugcheck::report(
                0xc4,
                [W32_REGISTRY_LABEL, key_type as u64, words, raw],
            );
        }
        let status = raw as u32 as i32;
        if status != 0 {
            if handle != 0 {
                crate::provider_bugcheck::report(0xc4, [W32_REGISTRY_LABEL, handle, words, raw]);
            }
            return status;
        }
        if handle == 0 {
            crate::provider_bugcheck::report(0xc4, [W32_REGISTRY_LABEL, device_object, words, raw]);
        }
        write_unaligned(handle_out, handle);
        acknowledge_win32k_registry_output(handle, false)
    }
}

pub(super) unsafe fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    mi: u64,
    device_object: u64,
    key_type: u64,
    desired_access: u64,
) -> (i32, u64, u64) {
    if mi != ((W32_REGISTRY_LABEL << 12) | 4) || reply_cap != channel.reply_cap {
        return (STATUS_INVALID_PARAMETER_I32, 0, 0);
    }
    let (Ok(key_type), Ok(desired_access)) =
        (u32::try_from(key_type), u32::try_from(desired_access))
    else {
        return (STATUS_INVALID_PARAMETER_I32, 0, 0);
    };
    let kind = match nt_io_manager::device_registry::DeviceRegistryKeyType::from_flags(key_type) {
        Ok(nt_io_manager::device_registry::DeviceRegistryKeyType::Driver) => {
            nt_io_manager::device_registry::DeviceRegistryKeyType::Driver
        }
        Ok(_) => return (STATUS_NOT_SUPPORTED, 0, 0),
        Err(status) => return (status as i32, 0, 0),
    };
    let access =
        match crate::win32k_device_consumer::authenticate(channel, reply_cap, device_object) {
            Ok(access) => access,
            Err(status) => return (status, 0, 0),
        };
    let identity = match access.require_pdo() {
        Ok(identity) => identity,
        Err(status) => return (status, 0, 0),
    };
    let caller = match crate::provider_registry_caller::resolve(channel) {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0, 0),
    };
    let dispatch =
        match crate::driver_launch::driver_registry_handles::RegistryPublicationDispatch::capture(
            channel,
        ) {
            Ok(dispatch) => dispatch,
            Err(status) => return (status as i32, 0, 0),
        };
    let property = match crate::driver_launch::win32k_pdo_driver_key_property_snapshot(
        access.device(),
        identity,
    ) {
        Ok(property) => property,
        Err(status) => return (status, 0, 0),
    };
    let driver_key = match nt_io_manager::device_registry::decode_driver_key_property(&property) {
        Ok(driver_key) => driver_key,
        Err(status) => return (status as i32, 0, 0),
    };
    let plan = match kind.plan(&[], Some(&driver_key), desired_access) {
        Ok(plan) => plan,
        Err(status) => return (status as i32, 0, 0),
    };
    let path = match plan
        .absolute_path()
        .map_err(|status| status as i32)
        .and_then(|path| {
            alloc::string::String::from_utf16(&path).map_err(|_| STATUS_OBJECT_NAME_INVALID)
        }) {
        Ok(path) => path,
        Err(status) => return (status, 0, 0),
    };
    if access.require_pdo() != Ok(identity) {
        return (STATUS_INVALID_DEVICE_REQUEST, 0, 0);
    }
    let subject = match crate::with_provider_security_managers(|pm, tokens| {
        nt_user_host::registry_subject::RegistrySubject::capture(pm, tokens, caller)
    }) {
        Ok(subject) => Win32kRegistrySubject(Some(subject)),
        Err(status) => return (status as i32, 0, 0),
    };
    let metadata = crate::driver_launch::DriverRegistryOpenMetadata {
        dispatch,
        root_handle: None,
        desired_access: plan.requested_access(),
        attributes: nt_process::native_handle::OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        security_descriptor: None,
    };
    let (status, handle, extra) = crate::driver_launch::service_hosted_driver_open_registry_path(
        caller,
        &path,
        &metadata,
        subject.0.as_ref().expect("captured registry subject"),
    );
    if status != 0 {
        return (status, 0, 0);
    }
    if extra != 0 || handle == 0 || access.require_pdo() != Ok(identity) {
        if let Err(status) =
            crate::driver_launch::driver_registry_handles::abort_driver_registry_publication(
                dispatch, caller, handle,
            )
        {
            return (status, 0, 0);
        }
        return (STATUS_INVALID_DEVICE_REQUEST, 0, 0);
    }
    (0, handle, 0)
}
