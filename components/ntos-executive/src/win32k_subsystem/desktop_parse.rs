//! `ObOpenObjectByName` for Desktop objects through the registered WindowStation parse
//! procedure, as ReactOS `ObpLookupObjectName` -> `ExpWinStaObjectParse` does.
//!
//! win32k's own `IntDesktopObjectParse` finds an existing desktop on the WindowStation's
//! `DesktopListHead`, or (for a create) calls `ObCreateObject`,
//! `IntAssignDesktopSecurityOnParse` (`ObGetObjectSecurity` + `ObAssignSecurity` through the
//! retained subject lease) and `UserInitializeDesktop`. The adapter owns only the Object
//! Manager side: the captured name, the ACCESS_STATE, the callout and the handle.

use super::*;
use nt_kernel_abi::security_create_x64::AccessState;
type UnicodeString = nt_kernel_abi::UnicodeString;
use nt_kernel_abi::win32k_parse_x64::Win32ParseMethodParameters;
use nt_kernel_abi::GuestAddr;
use nt_status::NtStatus;

/// `WIN32_CALLOUTS_FPNS.WindowStationParseProcedure`.
const WINDOW_STATION_PARSE_OFF: u64 = 14 * 8;
const OBJECT_ATTRIBUTES_SIZE: u32 = 0x30;
const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033u32 as i32;
const MAX_NAME_UNITS: usize = (u16::MAX as usize) / 2;

/// `RtlMapGenericMask` with the Desktop type's registered mapping, as `SeCreateAccessState`.
unsafe fn map_generic(object_type: u64, access: u32) -> u32 {
    let object_type = object_type as *const nt_object_manager::object_type::ObjectType;
    let native = &(*object_type).type_info.generic_mapping;
    let mut mapped = access & !0xF000_0000;
    for (bit, field) in [
        (0x8000_0000u32, core::ptr::addr_of!(native.generic_read)),
        (0x4000_0000, core::ptr::addr_of!(native.generic_write)),
        (0x2000_0000, core::ptr::addr_of!(native.generic_execute)),
        (0x1000_0000, core::ptr::addr_of!(native.generic_all)),
    ] {
        if access & bit != 0 {
            mapped |= read_volatile(field);
        }
    }
    mapped
}

#[allow(clippy::too_many_arguments)]
pub(super) unsafe fn open(
    object_attributes: u64,
    object_type: u64,
    access_mode: u64,
    access_state: u64,
    desired_access: u64,
    parse_context: u64,
    handle: *mut u64,
) -> i32 {
    // KPROCESSOR_MODE and ACCESS_MASK arrive in full registers; only their ABI width is defined.
    let access_mode = access_mode as u8;
    let desired_access = desired_access as u32;
    if object_attributes == 0 || access_mode > 1 {
        return STATUS_INVALID_PARAMETER_I32;
    }
    if handle.is_null() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    write_unaligned(handle, 0);
    if read_unaligned(object_attributes as *const u32) != OBJECT_ATTRIBUTES_SIZE {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let requested_root = read_unaligned((object_attributes + 0x08) as *const u64);
    let name = read_unaligned((object_attributes + 0x10) as *const u64);
    let attributes = read_unaligned((object_attributes + 0x18) as *const u32);
    let security_descriptor = read_unaligned((object_attributes + 0x20) as *const u64);
    let security_qos = read_unaligned((object_attributes + 0x28) as *const u64);
    let Some((_, window_station)) =
        effective_desktop_root(&*core::ptr::addr_of!(OBJ_TABLE), requested_root)
    else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    if name == 0 {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let length = read_unaligned(name as *const u16) as usize;
    let buffer = read_unaligned((name + 8) as *const u64);
    if length & 1 != 0 || (length != 0 && buffer == 0) {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let units = length / 2;
    if units > MAX_NAME_UNITS - 1 {
        return STATUS_OBJECT_NAME_INVALID;
    }
    // The parse routine scans RemainingName with wcschr, so it receives an owned,
    // NUL-terminated copy rather than the caller's counted buffer.
    let mut text: Vec<u16> = Vec::new();
    if text.try_reserve_exact(units + 1).is_err() {
        return STATUS_INSUFFICIENT_RESOURCES_I32;
    }
    for index in 0..units {
        text.push(read_unaligned((buffer + (index * 2) as u64) as *const u16));
    }
    text.push(0);
    let remaining =
        match nt_object_manager::win32k_desktop_parse::desktop_remaining_name(
            &text[..units],
            requested_root != 0,
        ) {
            Ok(range) => range,
            Err(status) => return status.0,
        };
    let base = text.as_ptr() as u64;
    let complete_name = UnicodeString {
        length: (units * 2) as u16,
        maximum_length: ((units + 1) * 2) as u16,
        _reserved: 0,
        buffer: GuestAddr(base),
    };
    let mut remaining_name = UnicodeString {
        length: (remaining.len() * 2) as u16,
        maximum_length: ((remaining.len() + 1) * 2) as u16,
        _reserved: 0,
        buffer: GuestAddr(base + (remaining.start * 2) as u64),
    };
    // ObOpenObjectByName without an ACCESS_STATE builds one (SeCreateAccessState) carrying the
    // captured creator descriptor; the subject itself is the lease the root retains.
    let mut local_access_state = if access_state == 0 {
        let mut state = nt_kernel_abi::security_create_x64::initial_create_access_state(
            map_generic(object_type, desired_access),
        );
        state.security_descriptor = GuestAddr(security_descriptor);
        Some(state)
    } else {
        None
    };
    let access_state = match local_access_state.as_mut() {
        Some(state) => state as *mut AccessState as u64,
        None => access_state,
    };
    let mut object = 0u64;
    let parameters = Win32ParseMethodParameters::new(
        GuestAddr(window_station),
        GuestAddr(object_type),
        GuestAddr(access_state),
        access_mode,
        attributes,
        GuestAddr(&complete_name as *const UnicodeString as u64),
        GuestAddr(&mut remaining_name as *mut UnicodeString as u64),
        GuestAddr(parse_context),
        GuestAddr(security_qos),
        GuestAddr(&mut object as *mut u64 as u64),
    );
    let routine = read_volatile((WIN32_CALLOUTS + WINDOW_STATION_PARSE_OFF) as *const u64);
    if routine == 0 {
        return STATUS_NOT_IMPLEMENTED_I32;
    }
    let status = NtStatus(
        call_win32k_pe(routine, &[&parameters as *const Win32ParseMethodParameters as u64])
            as u32 as i32,
    );
    let object = read_volatile(&object);
    let created = parse_context != 0 && read_volatile(parse_context as *const u8) != 0;
    match (&mut *core::ptr::addr_of_mut!(OBJ_TABLE))
        .admit_desktop_parse_result(status, object, created)
    {
        Ok(admission) => {
            write_unaligned(handle, admission.handle);
            admission.status.0
        }
        Err(rejected) => {
            // A successful parse returned one reference the handle did not consume.
            if !status.is_error() && object != 0 {
                s_ob_dereference_object(object);
            }
            rejected.0
        }
    }
}
