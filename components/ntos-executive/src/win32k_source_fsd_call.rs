//! Retained component call for exact-device file-less READ/WRITE source IRPs.

use super::*;
use core::sync::atomic::AtomicU64;
use nt_io_manager::win32k_source_fsd_wire::{
    self as wire, SourceFsdRequest, SourceFsdResponse,
};
use source_irp_call::SourceRequestKind;

static NEXT_FSD_NONCE: AtomicU64 = AtomicU64::new(1);

/// Dormant until the canonical exact-device READ/WRITE root service is verified.
pub(super) extern "win64" fn iof_call_driver(device: u64, irp: u64) -> i32 {
    unsafe {
        let Some(activation) = active_provider_stack_event_activation() else {
            return STATUS_NOT_SUPPORTED_I32;
        };
        let stack_pointer = current_stack_pointer();
        let mut source = match source_fsd::admit(irp, device, stack_pointer, None) {
            Ok(source) => source,
            Err(status) => return status,
        };
        let nonce = match NEXT_FSD_NONCE.fetch_update(
            Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1),
        ) {
            Ok(nonce) if nonce != 0 => nonce,
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 1]),
        };
        let ticket = source.source_ticket_serial();
        let generation = source.source_native_generation();
        let request = SourceFsdRequest {
            nonce,
            source_irp_va: source.source_address(),
            source_ticket_serial: ticket,
            native_allocation_generation: generation,
            device_object_va: device,
            major: source.major,
            transfer_mode: source.transfer_mode,
            byte_offset: source.byte_offset,
            input: &source.input,
            output_initial: &source.output_initial,
            output_capacity: source.output_capacity,
            event: source.event,
        };
        let total = match wire::packet_len(request) {
            Ok(total) if total <= wire::MAX_PACKET_BYTES => total,
            _ => {
                if !source_fsd::release(&mut source) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 2]);
                }
                return STATUS_INVALID_PARAMETER_I32;
            }
        };
        let packet = pool_alloc(total as u64);
        if packet == 0 {
            if !source_fsd::release(&mut source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 3]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let Some(packet_pin) = source_irp::pin_system_buffer(packet, total as u64) else {
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, packet, 0, 4]);
            }
            if !source_fsd::release(&mut source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 5]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        };
        if wire::encode_request(
            request,
            core::slice::from_raw_parts_mut(packet as *mut u8, total),
        ).is_err() {
            if !source_irp::release_system_buffer(packet_pin) || !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, packet, 0, 6]);
            }
            if !source_fsd::release(&mut source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 7]);
            }
            return STATUS_INVALID_PARAMETER_I32;
        }
        let index = match source_irp_call::reserve_packet(
            SourceRequestKind::Fsd, activation, irp, packet, total, packet_pin,
        ) {
            Ok(index) => index,
            Err(packet_pin) => {
                if !source_irp::release_system_buffer(packet_pin) || !provider_pool_free(packet) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, packet, 0, 8]);
                }
                if !source_fsd::release(&mut source) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 9]);
                }
                return STATUS_INSUFFICIENT_RESOURCES_I32;
            }
        };
        if !source_fsd::abort(&mut source) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 10]);
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_SOURCE_FSD_LABEL << 12) | 4,
            packet,
            total as u64,
            stack_pointer,
            0,
        );
        if !source_irp_call::valid_status_word(words, raw)
            || !source_irp_call::packet_live(index, packet, total)
        {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, packet, words, raw]);
        }
        let bytes = core::slice::from_raw_parts(packet as *const u8, total);
        match wire::decode_response(bytes) {
            Ok(SourceFsdResponse::Pending { token }) if raw as u32 == wire::STATUS_PENDING => {
                source_irp_call::retain_token(index, token);
                wire::STATUS_PENDING as i32
            }
            Ok(SourceFsdResponse::Inline { token, status, .. }) if raw as u32 == status => {
                source_irp_call::retain_token(index, token);
                source_irp_call::complete_and_release(index, token, irp);
                status as i32
            }
            Err(_)
                if raw as u32 & 0xc000_0000 == 0xc000_0000
                    && wire::decode_request(bytes).is_ok() =>
            {
                source_irp_call::retire_packet(index);
                let mut source = source_fsd::admit(irp, device, stack_pointer, None)
                    .unwrap_or_else(|_| {
                        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, raw, 11])
                    });
                if source.source_ticket_serial() != ticket
                    || source.source_native_generation() != generation
                    || !source_fsd::release(&mut source)
                {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, raw, 12]);
                }
                raw as u32 as i32
            }
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, packet, raw, 13]),
        }
    }
}
