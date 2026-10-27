//! Checked `ObReferenceObjectByPointer` for a hosted DEVICE_OBJECT projection.
//!
//! The service owns the canonical reference and exact registration generation. A malformed
//! transport reply is an uncertain effect: the caller must not retry the increment.

use super::*;

pub(super) const OP_REFERENCE_BY_POINTER: u64 = 39;
pub(super) const DEVICE_OBJECT_TYPE_CELL_OFFSET: u64 = 0x230;
pub(super) const DEVICE_OBJECT_TYPE_BODY_OFFSET: u64 = 0x380;
pub(super) const DEVICE_OBJECT_TYPE_MARKER: u64 = u64::from_le_bytes(*b"DEVCTYPE");

const STATUS_OBJECT_TYPE_MISMATCH: i32 = 0xC000_0024u32 as i32;

/// `NTSTATUS ObReferenceObjectByPointer(PVOID, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE)`.
///
/// A hosted KernelMode device reference is supported. UserMode access checks and nonzero desired
/// access are refused until the object security policy can authorize them. The optional type must
/// be the exact descriptor published in this driver's DATA mapping; no caller pointer is probed.
pub(super) extern "win64" fn ob_reference_object_by_pointer(
    object: u64,
    desired_access: u32,
    object_type: u64,
    access_mode: u8,
) -> i32 {
    if access_mode > 1 || object == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if access_mode != 0 || desired_access != 0 {
        return STATUS_ACCESS_DENIED;
    }
    if !unsafe { consumer_device_object_in_local_pool(object) } {
        return STATUS_INVALID_PARAMETER;
    }
    let expected_type = FSD_DATA_VADDR + DEVICE_OBJECT_TYPE_BODY_OFFSET;
    let published_type = unsafe {
        read_volatile((FSD_DATA_VADDR + DEVICE_OBJECT_TYPE_CELL_OFFSET) as *const u64)
    };
    let marker = unsafe { read_volatile(expected_type as *const u64) };
    if published_type != expected_type || marker != DEVICE_OBJECT_TYPE_MARKER {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if object_type != 0 && object_type != expected_type {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    // No shared argument buffer is involved. The synchronous call retains this lane's Reply
    // until the service has either admitted or rejected the exact canonical increment.
    let (words, status, count, reserved0, reserved1) = unsafe {
        call_on4_raw(
            (FSD_SERVICE_DEVICE_LABEL << 12) | 4,
            OP_REFERENCE_BY_POINTER,
            object,
            object_type,
            0,
        )
    };
    if words != 4 || reserved0 != 0 || reserved1 != 0 {
        unsafe {
            crate::provider_bugcheck::report(
                0xc4,
                [FSD_SERVICE_DEVICE_LABEL, OP_REFERENCE_BY_POINTER, words, status],
            )
        }
    }
    let reply = nt_io_abi::device_pointer::DevicePointerReply::decode(status, count)
        .unwrap_or_else(|_| unsafe {
            crate::provider_bugcheck::report(
                0xc4,
                [FSD_SERVICE_DEVICE_LABEL, OP_REFERENCE_BY_POINTER, status, count],
            )
        });
    match reply.into_result() {
        Ok(_) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind(
        "ObReferenceObjectByPointer",
        ob_reference_object_by_pointer as *const () as usize as u64,
    );
}
