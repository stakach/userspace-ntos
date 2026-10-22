//! KeQueryActiveProcessors projects the processor topology captured from boot information.

use super::*;

pub(super) const fn active_processor_mask(count: u64) -> u64 {
    nt_kernel_exec::processor_topology::active_processor_mask(count)
}

/// KAFFINITY KeQueryActiveProcessors(void).
pub(super) extern "win64" fn query_active_processors() -> u64 {
    active_processor_mask(crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire))
}

/// `ULONG KeQueryActiveProcessorCountEx(USHORT GroupNumber)`.
pub(super) extern "win64" fn query_active_processor_count_ex(group: u16) -> u32 {
    nt_kernel_exec::processor_topology::active_processor_count_for_group(
        crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire), group,
    )
}

/// No hot-add capacity is advertised by the current boot topology.
pub(super) extern "win64" fn query_maximum_processor_count_ex(group: u16) -> u32 {
    query_active_processor_count_ex(group)
}

pub(super) extern "win64" fn query_active_group_count() -> u16 {
    1
}

pub(super) extern "win64" fn query_group_affinity(group: u16) -> u64 {
    if group == 0 {
        active_processor_mask(crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire))
    } else {
        0
    }
}

/// `VOID KeQueryNodeActiveAffinity(USHORT, PGROUP_AFFINITY, PUSHORT)`.
pub(super) extern "win64" fn query_node_active_affinity(
    node: u16,
    affinity: u64,
    count: u64,
) {
    let mask = if node == 0 { query_group_affinity(0) } else { 0 };
    unsafe {
        if affinity != 0 && affinity.checked_add(16).is_some() {
            write_unaligned(affinity as *mut u64, mask);
            write_unaligned((affinity + 8) as *mut u64, 0);
        }
        if count != 0 && count.checked_add(2).is_some() {
            write_unaligned(count as *mut u16, (mask != 0) as u16);
        }
    }
}

/// `NTSTATUS KeSetTargetProcessorDpcEx(PKDPC, PPROCESSOR_NUMBER)`.
/// The only boot processor is group zero, number zero. Preserve the explicit
/// target marker in KDPC.Number even though root's one-CPU queue needs no route.
pub(super) extern "win64" fn set_target_processor_dpc_ex(dpc: u64, number: u64) -> i32 {
    if dpc == 0 || number == 0 || dpc.checked_add(KDPC_SIZE).is_none()
        || number.checked_add(4).is_none()
        || crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire) != 1
    {
        return STATUS_INVALID_PARAMETER;
    }
    let encoded = unsafe { read_unaligned(number as *const u32) };
    if encoded != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let object_type = unsafe { read_unaligned((dpc + KDPC_TYPE_OFFSET) as *const u8) };
    if object_type != KDPC_OBJECT_TYPE && object_type != KDPC_THREADED_OBJECT_TYPE {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe { write_unaligned((dpc + 2) as *mut u16, 64); }
    STATUS_SUCCESS
}

/// `ULONG KeGetCurrentProcessorNumberEx(PPROCESSOR_NUMBER)`.
pub(super) extern "win64" fn current_processor_number_ex(number: u64) -> u32 {
    let count = crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire);
    let Some(index) = nt_kernel_exec::processor_topology::single_processor_index(count) else {
        unsafe { crate::provider_bugcheck::report(0xc4, [count, number, 0x50524f43, 0]); }
    };
    if number != 0 {
        if number.checked_add(4).is_none() {
            unsafe { crate::provider_bugcheck::report(0xc4, [count, number, 0x50524f43, 1]); }
        }
        // PROCESSOR_NUMBER: USHORT Group, UCHAR Number, UCHAR Reserved.
        unsafe { write_unaligned(number as *mut u32, index); }
    }
    index
}

/// `NTSTATUS KeGetProcessorNumberFromIndex(ULONG, PPROCESSOR_NUMBER)`.
pub(super) extern "win64" fn processor_number_from_index(index: u32, number: u64) -> i32 {
    let count = crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire);
    let Some(encoded) = nt_kernel_exec::processor_topology::processor_number_for_index(count, index)
        else { return STATUS_INVALID_PARAMETER; };
    if number == 0 || number.checked_add(4).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe { write_unaligned(number as *mut u32, encoded); }
    0
}

/// `NTSTATUS KeQueryLogicalProcessorRelationship(PPROCESSOR_NUMBER,
/// LOGICAL_PROCESSOR_RELATIONSHIP, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, PULONG)`.
/// The current boot publishes one group record for group queries, including
/// the group information sought by the released NDIS RelationAll probe. The
/// size probe writes Length even when Information is null.
pub(super) extern "win64" fn query_logical_processor_relationship(
    processor_number: u64,
    relationship: u32,
    information: u64,
    length: u64,
) -> i32 {
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
    if length == 0 || length.checked_add(4).is_none() || !matches!(relationship, 4 | 0xffff) {
        return STATUS_INVALID_PARAMETER;
    }
    let count = crate::SYSTEM_PROCESSOR_COUNT.load(Ordering::Acquire);
    if !(1..=64).contains(&count) {
        return STATUS_INVALID_PARAMETER;
    }
    if processor_number != 0 {
        if processor_number.checked_add(4).is_none() {
            return STATUS_INVALID_PARAMETER;
        }
        let encoded = unsafe { read_unaligned(processor_number as *const u32) };
        let group = encoded as u16;
        let number = (encoded >> 16) as u8;
        let reserved = (encoded >> 24) as u8;
        if group != 0 || number as u64 >= count || reserved != 0 {
            return STATUS_INVALID_PARAMETER;
        }
    }
    let available = unsafe { read_unaligned(length as *const u32) as usize };
    let required = nt_kernel_exec::processor_topology::RELATION_GROUP_RECORD_BYTES;
    unsafe { write_unaligned(length as *mut u32, required as u32); }
    if information == 0 || available < required {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if information.checked_add(required as u64).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    let output = unsafe { core::slice::from_raw_parts_mut(information as *mut u8, required) };
    match nt_kernel_exec::processor_topology::write_relation_group(count, Some(output)) {
        Ok(_) => 0,
        Err(nt_kernel_exec::processor_topology::RelationGroupError::BufferTooSmall { .. }) =>
            STATUS_INFO_LENGTH_MISMATCH,
        Err(nt_kernel_exec::processor_topology::RelationGroupError::InvalidTopology) =>
            STATUS_INVALID_PARAMETER,
    }
}
