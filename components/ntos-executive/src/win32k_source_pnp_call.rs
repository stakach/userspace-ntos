//! Component call adapter for win32k's file-less TargetDeviceRelation IRP.

use super::*;
use core::sync::atomic::AtomicU64;
use nt_io_manager::win32k_source_pnp_wire::{
    self as wire, SourcePnpRequest, SourcePnpResponse,
};
use source_irp_call::SourceRequestKind;

static NEXT_PNP_NONCE: AtomicU64 = AtomicU64::new(1);

/// Dormant until the exact-device root PnP service has passed native validation.
pub(super) extern "win64" fn iof_call_driver(device: u64, irp: u64) -> i32 {
    unsafe {
        let Some(activation) = active_provider_stack_event_activation() else {
            return STATUS_NOT_SUPPORTED_I32;
        };
        let stack_pointer = current_stack_pointer();
        let mut source = match source_irp::admit_pnp_target_relation(irp, device, stack_pointer) {
            Ok(source) => source,
            Err(status) => return status,
        };
        let packet = pool_alloc(wire::PACKET_BYTES as u64);
        if packet == 0 {
            if !source_irp::release_pnp_dispatch(&mut source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, 0, 1]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let Some(packet_pin) = source_irp::pin_system_buffer(packet, wire::PACKET_BYTES as u64) else {
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, packet, 0, 2]);
            }
            if !source_irp::release_pnp_dispatch(&mut source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, 0, 3]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        };
        let nonce = match NEXT_PNP_NONCE.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |n| n.checked_add(1),
        ) {
            Ok(value) if value != 0 => value,
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, 0, 4]),
        };
        let source_ticket = source.source_ticket_serial();
        let source_generation = source.source_native_generation();
        let request = SourcePnpRequest {
            nonce,
            source_irp_va: source.source_address(),
            source_ticket_serial: source_ticket,
            native_allocation_generation: source_generation,
            device_object_va: device,
            relation_type: nt_pnp_abi::TARGET_DEVICE_RELATION,
            event: source.event,
        };
        let packet_bytes = core::slice::from_raw_parts_mut(packet as *mut u8, wire::PACKET_BYTES);
        if wire::encode_request(request, packet_bytes).is_err() {
            if !source_irp::release_system_buffer(packet_pin) || !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, packet, 0, 5]);
            }
            if !source_irp::release_pnp_dispatch(&mut source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, 0, 6]);
            }
            return STATUS_INVALID_PARAMETER_I32;
        }
        let index = match source_irp_call::reserve_packet(
            SourceRequestKind::Pnp,
            activation,
            irp,
            packet,
            wire::PACKET_BYTES,
            packet_pin,
        ) {
            Ok(index) => index,
            Err(packet_pin) => {
                if !source_irp::release_system_buffer(packet_pin) || !provider_pool_free(packet) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, packet, 0, 7]);
                }
                if !source_irp::release_pnp_dispatch(&mut source) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, 0, 8]);
                }
                return STATUS_INSUFFICIENT_RESOURCES_I32;
            }
        };
        if !source_irp::abort_pnp_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, 0, 9]);
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_SOURCE_PNP_LABEL << 12) | 4,
            packet,
            wire::PACKET_BYTES as u64,
            stack_pointer,
            0,
        );
        if !source_irp_call::valid_status_word(words, raw)
            || !source_irp_call::packet_live(index, packet, wire::PACKET_BYTES)
        {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, packet, words, raw]);
        }
        let packet_bytes = core::slice::from_raw_parts(packet as *const u8, wire::PACKET_BYTES);
        match wire::decode_response(packet_bytes) {
            Ok(SourcePnpResponse::Pending { token }) if raw as u32 == wire::STATUS_PENDING => {
                source_irp_call::retain_token(index, token);
                wire::STATUS_PENDING as i32
            }
            Ok(SourcePnpResponse::Inline { token, status, .. }) if raw as u32 == status => {
                source_irp_call::retain_token(index, token);
                source_irp_call::complete_and_release(index, token, irp);
                status as i32
            }
            Err(_)
                if raw as u32 & 0xc000_0000 == 0xc000_0000
                    && wire::decode_request(packet_bytes).is_ok() =>
            {
                source_irp_call::retire_packet(index);
                let mut source = source_irp::admit_pnp_target_relation(irp, device, stack_pointer)
                    .unwrap_or_else(|_| {
                        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, raw, 10])
                    });
                if source.source_ticket_serial() != source_ticket
                    || source.source_native_generation() != source_generation
                    || !source_irp::release_pnp_dispatch(&mut source)
                {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, raw, 11]);
                }
                raw as u32 as i32
            }
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, packet, raw, 12]),
        }
    }
}
