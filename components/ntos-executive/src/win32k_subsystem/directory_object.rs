//! Pointer-free directory-object requests from the win32k component.

use super::*;

const LABEL: u64 = W32_DIRECTORY_LABEL;
const BEGIN_CREATE: u64 = 1;
const BEGIN_OPEN: u64 = 2;
const APPEND: u64 = 3;
const COMMIT: u64 = 4;
const PUBLISH: u64 = 5;
const ABORT: u64 = 6;
const CLOSE: u64 = 7;
const ACK: u64 = 8;
const QUERY_MULTI_CONTINUE: u64 = 9;
const QUERY_MULTI_RESTART: u64 = 10;
const QUERY_SINGLE_CONTINUE: u64 = 11;
const QUERY_SINGLE_RESTART: u64 = 12;
const QUERY_READ: u64 = 13;
const QUERY_ACK: u64 = 14;
const MAX_NAME_UNITS: usize = 1024;
const MAX_COMPONENT_UNITS: usize = 128;
const STATUS_OBJECT_NAME_INVALID: i32 = 0xC000_0033u32 as i32;
const STATUS_DATATYPE_MISALIGNMENT: i32 = 0x8000_0002u32 as i32;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001au32 as i32;
const STATUS_MORE_ENTRIES: i32 = 0x0000_0105;
const QUERY_CHUNK_BYTES: usize = 24;

struct DirectoryName {
    root: u64,
    attributes: u32,
    units: usize,
    text: [u16; MAX_NAME_UNITS],
}

unsafe fn capture_name(object_attributes: u64) -> Result<DirectoryName, i32> {
    if object_attributes == 0 {
        return Err(STATUS_INVALID_PARAMETER_I32);
    }
    if read_unaligned(object_attributes as *const u32) < 0x30 {
        return Err(STATUS_INVALID_PARAMETER_I32);
    }
    let root = read_unaligned((object_attributes + 8) as *const u64);
    let name_ptr = read_unaligned((object_attributes + 16) as *const u64);
    let attributes = read_unaligned((object_attributes + 24) as *const u32);
    let security_descriptor = read_unaligned((object_attributes + 32) as *const u64);
    let security_qos = read_unaligned((object_attributes + 40) as *const u64);
    if security_descriptor != 0 || security_qos != 0 {
        return Err(STATUS_NOT_SUPPORTED_I32);
    }
    if name_ptr == 0 {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let length = read_unaligned(name_ptr as *const u16) as usize;
    let maximum = read_unaligned((name_ptr + 2) as *const u16) as usize;
    let buffer = read_unaligned((name_ptr + 8) as *const u64);
    if length == 0
        || length & 1 != 0
        || length > maximum
        || length > MAX_NAME_UNITS * 2
        || buffer == 0
    {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }

    let units = length / 2;
    let mut text = [0u16; MAX_NAME_UNITS];
    let mut component_len = 0usize;
    for (index, slot) in text[..units].iter_mut().enumerate() {
        let unit = read_unaligned((buffer + (index * 2) as u64) as *const u16);
        if unit == 0 || unit > 0x7f {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if unit == b'\\' as u16 {
            if index != 0 && component_len == 0 {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            component_len = 0;
        } else {
            component_len += 1;
            if component_len > MAX_COMPONENT_UNITS {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
        }
        *slot = unit;
    }
    if component_len == 0 {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(DirectoryName {
        root,
        attributes,
        units,
        text,
    })
}

/// The broker replies with exactly four words; unused words must be zero. A malformed reply may
/// represent an uncertain native effect, so it cannot be converted to a retryable NTSTATUS.
unsafe fn call(op: u64, first: u64, second: u64, third: u64, output: bool) -> (i32, u64) {
    let (info, raw, value, spare, reserved) =
        crate::driver_launch::call_on4_raw((LABEL << 12) | 4, op, first, second, third);
    let canonical_status = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if info != 4
        || !canonical_status
        || spare != 0
        || reserved != 0
        || (!output && value != 0)
        || ((raw as u32 as i32) < 0 && value != 0)
    {
        crate::provider_bugcheck::report(0xc4, [LABEL, op, info, raw]);
    }
    (raw as u32 as i32, value)
}

unsafe fn abort(token: u64, handle: u64) {
    let (status, _) = call(ABORT, token, handle, 0, false);
    if status != 0 {
        crate::provider_bugcheck::report(0xc4, [LABEL, ABORT, token, status as u32 as u64]);
    }
}

unsafe fn open_impl(
    handle_out: *mut u64,
    desired_access: u32,
    object_attributes: u64,
    create: bool,
) -> i32 {
    if handle_out.is_null() {
        return STATUS_ACCESS_VIOLATION_I32;
    }
    let name = match capture_name(object_attributes) {
        Ok(name) => name,
        Err(status) => return status,
    };
    let operation = if create { BEGIN_CREATE } else { BEGIN_OPEN };
    let packed = (u64::from(name.attributes) << 32) | u64::from(desired_access);
    let (status, token) = call(operation, name.root, packed, name.units as u64, true);
    if status < 0 {
        return status;
    }
    if status != 0 || token == 0 {
        crate::provider_bugcheck::report(0xc4, [LABEL, operation, token, status as u32 as u64]);
    }

    for offset in (0..name.units).step_by(4) {
        let count = (name.units - offset).min(4);
        let mut packed_units = 0u64;
        for index in 0..count {
            packed_units |= u64::from(name.text[offset + index]) << (index * 16);
        }
        let position = ((offset as u64) << 32) | count as u64;
        let (status, _) = call(APPEND, token, position, packed_units, false);
        if status != 0 {
            abort(token, 0);
            return status;
        }
    }

    let (commit_status, handle) = call(COMMIT, token, 0, 0, true);
    if commit_status < 0 {
        abort(token, 0);
        return commit_status;
    }
    if commit_status != 0 || handle == 0 {
        abort(token, 0);
        crate::provider_bugcheck::report(0xc4, [LABEL, COMMIT, token, commit_status as u32 as u64]);
    }
    write_unaligned(handle_out, handle);
    let (publish_status, _) = call(PUBLISH, token, handle, 0, false);
    if publish_status < 0 {
        write_unaligned(handle_out, 0);
        abort(token, handle);
        return publish_status;
    }
    let (ack_status, _) = call(ACK, token, handle, 0, false);
    if ack_status != 0 {
        crate::provider_bugcheck::report(0xc4, [LABEL, ACK, token, ack_status as u32 as u64]);
    }
    publish_status
}

pub(super) extern "win64" fn create(
    handle_out: *mut u64,
    desired_access: u32,
    object_attributes: u64,
) -> i32 {
    unsafe { open_impl(handle_out, desired_access, object_attributes, true) }
}

pub(super) extern "win64" fn open(
    handle_out: *mut u64,
    desired_access: u32,
    object_attributes: u64,
) -> i32 {
    unsafe { open_impl(handle_out, desired_access, object_attributes, false) }
}

pub(super) unsafe fn close(handle: u64) -> i32 {
    call(CLOSE, handle, 0, 0, false).0
}

unsafe fn query_call(op: u64, first: u64, second: u64, third: u64) -> (i32, u64, u64, u64) {
    let (info, raw, out1, out2, out3) =
        crate::driver_launch::call_on4_raw((LABEL << 12) | 4, op, first, second, third);
    let canonical_status = raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64;
    if info != 4 || !canonical_status {
        crate::provider_bugcheck::report(0xc4, [LABEL, op, info, raw]);
    }
    (raw as u32 as i32, out1, out2, out3)
}

pub(super) extern "win64" fn query(
    handle: u64,
    buffer: *mut u8,
    length: u32,
    single: u8,
    restart: u8,
    context: *mut u32,
    return_length: *mut u32,
) -> i32 {
    unsafe {
        if context.is_null() || (length != 0 && buffer.is_null()) {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        if (context as usize) & 3 != 0
            || (!return_length.is_null() && (return_length as usize) & 3 != 0)
            || (length != 0 && (buffer as usize) & 1 != 0)
        {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        let operation = match (single != 0, restart != 0) {
            (false, false) => QUERY_MULTI_CONTINUE,
            (false, true) => QUERY_MULTI_RESTART,
            (true, false) => QUERY_SINGLE_CONTINUE,
            (true, true) => QUERY_SINGLE_RESTART,
        };
        let current = if restart != 0 { 0 } else { read_unaligned(context) };
        let request = (u64::from(current) << 32) | u64::from(length);
        let (status, token, lengths, next_context) =
            query_call(operation, handle, buffer as u64, request);
        if !matches!(
            status,
            0 | STATUS_MORE_ENTRIES | STATUS_NO_MORE_ENTRIES | STATUS_BUFFER_TOO_SMALL_I32
        ) {
            if token != 0 || lengths != 0 || next_context != 0 {
                crate::provider_bugcheck::report(0xc4, [LABEL, operation, token, lengths]);
            }
            return status;
        }
        let written = lengths as u32 as usize;
        let required = (lengths >> 32) as u32;
        let valid_result = match status {
            0 => written >= 32 && required as usize == written,
            STATUS_MORE_ENTRIES => written == 0 && required >= 32,
            STATUS_NO_MORE_ENTRIES => {
                required == 32 && written == if length >= 32 { 32 } else { 0 }
            }
            STATUS_BUFFER_TOO_SMALL_I32 => written == 0 && required > length,
            _ => false,
        };
        if next_context > u32::MAX as u64
            || written > length as usize
            || (written == 0) != (token == 0)
            || !valid_result
        {
            crate::provider_bugcheck::report(0xc4, [LABEL, operation, token, lengths]);
        }
        for offset in (0..written).step_by(QUERY_CHUNK_BYTES) {
            let count = (written - offset).min(QUERY_CHUNK_BYTES);
            let (read_status, a, b, c) =
                query_call(QUERY_READ, token, offset as u64, count as u64);
            if read_status != 0 {
                crate::provider_bugcheck::report(
                    0xc4,
                    [LABEL, QUERY_READ, token, read_status as u32 as u64],
                );
            }
            let mut bytes = [0u8; QUERY_CHUNK_BYTES];
            bytes[..8].copy_from_slice(&a.to_le_bytes());
            bytes[8..16].copy_from_slice(&b.to_le_bytes());
            bytes[16..24].copy_from_slice(&c.to_le_bytes());
            if bytes[count..].iter().any(|&byte| byte != 0) {
                crate::provider_bugcheck::report(0xc4, [LABEL, QUERY_READ, token, count as u64]);
            }
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.add(offset), count);
        }
        if status >= 0 {
            write_unaligned(context, next_context as u32);
        }
        if !return_length.is_null() {
            write_unaligned(return_length, required);
        }
        if token != 0 {
            let (ack_status, a, b, c) = query_call(QUERY_ACK, token, 0, 0);
            if ack_status != 0 || a != 0 || b != 0 || c != 0 {
                crate::provider_bugcheck::report(
                    0xc4,
                    [LABEL, QUERY_ACK, token, ack_status as u32 as u64],
                );
            }
        }
        status
    }
}
