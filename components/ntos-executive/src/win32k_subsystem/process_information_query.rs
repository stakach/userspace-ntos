//! Native win32k ZwQueryInformationProcess entry and component-owned copyout.

use super::*;
use crate::process_information_bridge::{
    decode_response, encode_request, packet_len_for, ProcessQueryRequest,
};

const ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;
const INSUFFICIENT_RESOURCES: i32 = 0xC000_009Au32 as i32;

unsafe fn current_stack_span(address: u64, length: usize) -> bool {
    if length == 0 {
        return true;
    }
    let Some(end) = address.checked_add(length as u64) else { return false; };
    let marker = 0u8;
    let stack = nt_compat_exports::memory::component_stack_limits(
        core::ptr::addr_of!(marker) as u64,
        WIN32K_STACK_VADDR,
        WIN32K_STACK_BYTES,
        WIN32K_LANE_ARENA_VADDR,
        WIN32K_LANE_STRIDE,
        WIN32K_LANE_STACK_FRAMES * 0x1000,
        WIN32K_LANE_CAPACITY,
    );
    stack.is_some_and(|(low, high)| address >= low && end <= high)
}

unsafe fn writable_component_span(address: u64, length: usize) -> bool {
    if length == 0 { return true; }
    if current_stack_span(address, length) { return true; }
    if !provider_pool_contains(address) { return false; }
    let Some(_pool) = provider_pool_lock() else { return false; };
    shared_pool::containing_allocation(
        &ProviderPoolMemory,
        address - WIN32K_POOL_VADDR,
        length as u64,
    ).is_ok()
}

unsafe fn copy_to_component_span(address: u64, bytes: &[u8]) -> bool {
    if bytes.is_empty() { return true; }
    if current_stack_span(address, bytes.len()) {
        core::ptr::copy(bytes.as_ptr(), address as *mut u8, bytes.len());
        return true;
    }
    if !provider_pool_contains(address) { return false; }
    let Some(_pool) = provider_pool_lock() else { return false; };
    if shared_pool::containing_allocation(
        &ProviderPoolMemory,
        address - WIN32K_POOL_VADDR,
        bytes.len() as u64,
    ).is_err() { return false; }
    core::ptr::copy(bytes.as_ptr(), address as *mut u8, bytes.len());
    true
}

fn overlaps_packet(address: u64, length: usize, packet: u64, packet_length: usize) -> bool {
    if length == 0 { return false; }
    let Some(end) = address.checked_add(length as u64) else { return true; };
    let Some(packet_end) = packet.checked_add(packet_length as u64) else { return true; };
    address < packet_end && packet < end
}

/// The fifth native argument is passed on the Win64 stack; the broker carries no raw output
/// pointer authority. Only this component writes its own admitted stack or pool memory.
pub(super) extern "win64" fn query_information_process(
    handle: u64,
    class: u32,
    information: *mut u8,
    information_length: u32,
    return_length: *mut u32,
) -> i32 {
    unsafe {
        if !return_length.is_null() && !writable_component_span(return_length as u64, 4) {
            return ACCESS_VIOLATION;
        }
        let request = ProcessQueryRequest {
            handle,
            class,
            output_address: information as u64,
            output_length: information_length,
            return_length_requested: !return_length.is_null(),
        };
        let Some(packet_length) = packet_len_for(information_length) else {
            return INSUFFICIENT_RESOURCES;
        };
        let packet = pool_alloc(packet_length as u64);
        if packet == 0 {
            return INSUFFICIENT_RESOURCES;
        }
        let bytes = core::slice::from_raw_parts_mut(packet as *mut u8, packet_length);
        if encode_request(bytes, request).is_err() {
            assert!(provider_pool_free(packet), "process-query packet rollback failed");
            return nt_process::STATUS_INVALID_PARAMETER as i32;
        }
        let Some(identity) = provider_pool_allocation_identity(packet) else {
            crate::provider_bugcheck::report(
                0xc4, [W32_PROCESS_QUERY_LABEL, packet, packet_length as u64, 4],
            );
        };
        let (words, broker_status, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_PROCESS_QUERY_LABEL << 12) | 4,
            packet,
            packet_length as u64,
            identity.allocation_generation,
            0,
        );
        if words != 1 {
            // Unknown reply ownership cannot authorize reuse of this shared allocation.
            crate::provider_bugcheck::report(
                0xc4,
                [W32_PROCESS_QUERY_LABEL, packet, words, broker_status],
            );
        }
        let Some(pin) = pin_component_provider_pool_packet_exact(
            packet, packet_length, identity.allocation_generation,
        ) else {
            crate::provider_bugcheck::report(
                0xc4, [W32_PROCESS_QUERY_LABEL, packet, packet_length as u64, 5],
            );
        };
        let status = if broker_status != 0 {
            broker_status as u32 as i32
        } else {
            let bytes = core::slice::from_raw_parts(packet as *const u8, packet_length);
            let reply = decode_response(bytes, request).unwrap_or_else(|_| {
                crate::provider_bugcheck::report(
                    0xc4,
                    [W32_PROCESS_QUERY_LABEL, packet, packet_length as u64, 1],
                )
            });
            let output_written = reply.status != 0
                || (!overlaps_packet(information as u64, reply.bytes.len(), packet, packet_length)
                    && copy_to_component_span(information as u64, reply.bytes));
            let return_written = return_length.is_null()
                || (output_written
                    && !overlaps_packet(return_length as u64, 4, packet, packet_length)
                    && copy_to_component_span(
                    return_length as u64,
                    &reply.return_length.to_le_bytes(),
                ));
            if output_written && return_written {
                reply.status as i32
            } else {
                ACCESS_VIOLATION
            }
        };
        if !release_component_provider_pool_packet_exact(pin) {
            crate::provider_bugcheck::report(
                0xc4, [W32_PROCESS_QUERY_LABEL, packet, packet_length as u64, 6],
            );
        }
        assert!(provider_pool_free(packet), "process-query packet retirement failed");
        status
    }
}
