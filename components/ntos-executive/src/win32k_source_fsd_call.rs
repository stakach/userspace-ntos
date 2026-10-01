//! Origin-owned lifetime for file-less win32k READ/WRITE source IRPs.

use super::*;
use core::sync::atomic::AtomicU64;
use nt_io_manager::source_terminal::{PreparedTerminal, TerminalPacketIdentity};
use nt_io_manager::win32k_source_fsd_wire::{
    self as wire, SourceFsdRequest, SourceFsdResponse, TerminalPublication,
};

const STATUS_UNSUCCESSFUL_I32: i32 = 0xc000_0001u32 as i32;
static NEXT_FSD_NONCE: AtomicU64 = AtomicU64::new(1);
static mut ORIGINS: Vec<OriginSlot> = Vec::new();

struct Origin {
    nonce: u64,
    source: Option<source_fsd::SourceFsdDispatchLease>,
    phase: OriginPhase,
    prepared: Option<PreparedTerminal>,
    prepared_packet: Vec<u8>,
    request_packet: Option<(u64, source_irp::PinnedSystemBuffer)>,
}

use nt_io_manager::source_terminal::{OriginCallPhase as OriginPhase, TerminalAdmission, TerminalDelivery, TERMINAL_NOT_READY};

enum OriginSlot {
    Empty,
    Live(Origin),
    Busy(u64),
    Completed {
        request_packet: Option<(u64, source_irp::PinnedSystemBuffer)>,
        nonce: u64,
        token: u64,
        status: u32,
        information: u64,
        output: Vec<u8>,
    },
}

unsafe fn insert_origin(origin: Origin) -> Result<(), Origin> {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    if rows.iter().any(|row| match row {
        OriginSlot::Live(existing) => existing.nonce == origin.nonce,
        OriginSlot::Busy(nonce) | OriginSlot::Completed { nonce, .. } => *nonce == origin.nonce,
        OriginSlot::Empty => false,
    }) {
        return Err(origin);
    }
    if let Some(row) = rows.iter_mut().find(|row| matches!(row, OriginSlot::Empty)) {
        *row = OriginSlot::Live(origin);
        return Ok(());
    }
    if rows.try_reserve(1).is_err() {
        return Err(origin);
    }
    rows.push(OriginSlot::Live(origin));
    Ok(())
}

unsafe fn take_origin(nonce: u64) -> Option<(usize, Origin)> {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    let index = rows.iter().position(|row| {
        matches!(row, OriginSlot::Live(origin) if origin.nonce == nonce)
    })?;
    let origin = match core::mem::replace(&mut rows[index], OriginSlot::Busy(nonce)) {
        OriginSlot::Live(origin) => origin,
        _ => unreachable!(),
    };
    Some((index, origin))
}

unsafe fn take_request_packet(nonce: u64) -> Option<(u64, source_irp::PinnedSystemBuffer)> {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    for row in rows {
        match row {
            OriginSlot::Live(origin) if origin.nonce == nonce => return origin.request_packet.take(),
            OriginSlot::Completed { nonce: found_nonce, request_packet, .. } if *found_nonce == nonce => return request_packet.take(),
            _ => {}
        }
    }
    None
}

unsafe fn replace_busy(index: usize, nonce: u64, replacement: OriginSlot) {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    if !matches!(rows.get(index), Some(OriginSlot::Busy(found)) if *found == nonce) {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, nonce, index as u64, 1]);
    }
    rows[index] = replacement;
}

unsafe fn release_unentered(origin: &mut Origin) {
    if let Some(mut source) = origin.source.take() {
        if !source_fsd::release(&mut source) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, origin.nonce, 0, 2]);
        }
    }
}

unsafe fn accept_pending(nonce: u64, token: u64) -> bool {
    let Some((index, mut origin)) = take_origin(nonce) else { return false };
    let accepted = matches!(origin.phase, OriginPhase::Calling) && token != 0;
    if accepted { origin.phase = OriginPhase::Armed(token); }
    replace_busy(index, nonce, OriginSlot::Live(origin));
    accepted
}

unsafe fn accept_inline(
    nonce: u64, token: u64, status: u32, information: u64, output: &[u8],
) -> bool {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    let Some(row) = rows.iter_mut().find(|row| {
        matches!(row, OriginSlot::Completed { nonce: found, .. } if *found == nonce)
    }) else { return false };
    match row {
        OriginSlot::Completed {
            token: found_token, status: found_status,
            information: found_information, output: found_output, ..
        } if *found_token == token && *found_status == status
            && *found_information == information && found_output.as_slice() == output =>
        {
            *row = OriginSlot::Empty;
            true
        }
        _ => false,
    }
}

unsafe fn reject_unentered(nonce: u64) -> bool {
    let Some((index, mut origin)) = take_origin(nonce) else { return false };
    if !matches!(origin.phase, OriginPhase::Calling) {
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return false;
    }
    release_unentered(&mut origin);
    replace_busy(index, nonce, OriginSlot::Empty);
    true
}

// Reject pending terminal extraction until its original Call continuation has accepted Pending.
unsafe fn terminal_admission(nonce: u64, delivery: TerminalDelivery, token: u64) -> TerminalAdmission {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &*core::ptr::addr_of!(ORIGINS);
    let Some(row) = rows.iter().find(|row| match row {
        OriginSlot::Live(origin) => origin.nonce == nonce,
        OriginSlot::Busy(found) => *found == nonce,
        _ => false,
    }) else { return TerminalAdmission::Rejected };
    match row {
        OriginSlot::Live(origin) => delivery.admit(origin.phase, token),
        OriginSlot::Busy(_) if delivery == TerminalDelivery::Pending => TerminalAdmission::NotReady,
        _ => TerminalAdmission::Rejected,
    }
}

unsafe fn terminal_packet_identity(
    packet: u64, bytes: u64,
) -> Option<shared_pool::AllocationIdentity> {
    let _pool = provider_pool_lock()?;
    let memory = ProviderPoolMemory;
    let offset = packet.checked_sub(WIN32K_POOL_VADDR)?;
    let native = shared_pool::allocation_identity(&memory, offset).ok()?;
    (shared_pool::allocation_capacity(&memory, offset).ok()? >= bytes).then_some(native)
}

/// Consume a root-authenticated terminal handoff on a different win32k lane.
/// The original Call may still be parked while an inline completion is published.
unsafe fn finish_terminal_commit(
    packet: u64, length: u64, native: shared_pool::AllocationIdentity,
    command: TerminalPublication,
) -> i32 {
    let packet_bytes = core::slice::from_raw_parts_mut(packet as *mut u8, length as usize);
    let Ok(ack) = wire::decode_terminal_ack(packet_bytes) else { return STATUS_INVALID_PARAMETER_I32 };
    let handoff = ack.handoff;
    let nonce = handoff.nonce;
    let token = handoff.token;
    let status = handoff.status;
    let information = handoff.information;
    let Some((index, mut origin)) = take_origin(nonce) else { return STATUS_INVALID_PARAMETER_I32 };
    let discard = command == TerminalPublication::DiscardRequested;
    let sequence = match wire::terminal_signal_sequence(packet_bytes) {
        Ok(sequence) => sequence,
        Err(_) => { replace_busy(index, nonce, OriginSlot::Live(origin)); return STATUS_INVALID_PARAMETER_I32; }
    };
    let packet_identity = TerminalPacketIdentity { address: packet, length,
        allocation_id: native.allocation_id, allocation_generation: native.allocation_generation };
    let prepared_matches = origin.prepared.is_some_and(|prepared| {
        prepared.matches(packet_identity, handoff.token, handoff.status, handoff.information)
            && nt_io_manager::source_terminal::same_terminal_packet(
                &origin.prepared_packet, packet_bytes, 64)
    });
    let source = origin.source.as_ref().expect("retained FSD source");
    let source_matches = source.source_address() == handoff.source_irp_va
        && source.source_ticket_serial() == handoff.source_ticket_serial
        && source.source_native_generation() == handoff.native_allocation_generation;
    let source_live = source.validate();
    let phase_matches = if discard {
        match origin.phase {
            OriginPhase::Calling => true,
            OriginPhase::Armed(token) => token == handoff.token,
            OriginPhase::Indeterminate => false,
        }
    } else { handoff.delivery.admit(origin.phase, handoff.token) == TerminalAdmission::Ready };
    if !source_matches || !source_live || !phase_matches
        || (!discard && !prepared_matches) || (discard && origin.prepared.is_some() && !prepared_matches)
    {
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return STATUS_INVALID_PARAMETER_I32;
    }
    let inline = !discard && origin.prepared.is_some_and(|prepared| prepared.inline);
    let mut inline_output = Vec::new();
    if inline {
        if inline_output.try_reserve_exact(handoff.output.len()).is_err() {
            replace_busy(index, nonce, OriginSlot::Live(origin));
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        inline_output.extend_from_slice(handoff.output);
    }
    origin.phase = OriginPhase::Indeterminate;
    if discard {
        if let Some((address, pin)) = origin.request_packet.take() {
            source_irp_call::retire_packet(address, pin);
        }
    }
    let mut source = origin.source.take().unwrap();
    if !(if discard { source_fsd::release(&mut source) } else { source_fsd::commit(&mut source, sequence) }) {
        origin.source = Some(source);
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return STATUS_UNSUCCESSFUL_I32;
    }
    if terminal_packet_identity(packet, length) != Some(native)
        || wire::publish_terminal_ack(packet_bytes, if discard {
            TerminalPublication::Discarded
        } else { TerminalPublication::Committed }).is_err()
    {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, nonce, packet, 90]);
    }
    let replacement = if inline {
        OriginSlot::Completed { nonce, token,
            request_packet: origin.request_packet.take(), status,
            information, output: inline_output }
    } else { OriginSlot::Empty };
    replace_busy(index, nonce, replacement);
    0
}

pub(crate) unsafe fn complete_terminal(packet: u64, bytes: u64) -> i32 {
    if bytes < wire::TERMINAL_HEADER_BYTES as u64
        || bytes > wire::TERMINAL_HEADER_BYTES as u64 + wire::MAX_BUFFER_BYTES as u64
        || !provider_pool_contains(packet)
        || packet.checked_add(bytes - 1).is_none_or(|end| !provider_pool_contains(end))
    {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let Some(packet_identity) = terminal_packet_identity(packet, bytes) else {
        return STATUS_INVALID_PARAMETER_I32;
    };
    let packet_bytes = core::slice::from_raw_parts_mut(packet as *mut u8, bytes as usize);
    if let Ok(ack) = wire::decode_terminal_ack(packet_bytes) {
        if matches!(ack.publication, TerminalPublication::CommitRequested | TerminalPublication::DiscardRequested) {
            return finish_terminal_commit(packet, bytes, packet_identity, ack.publication);
        }
        return STATUS_INVALID_PARAMETER_I32;
    }
    let Ok(handoff) = wire::decode_terminal_handoff(packet_bytes) else {
        return STATUS_INVALID_PARAMETER_I32;
    };
    match terminal_admission(handoff.nonce, handoff.delivery, handoff.token) {
        TerminalAdmission::NotReady => return TERMINAL_NOT_READY,
        TerminalAdmission::Rejected => return STATUS_INVALID_PARAMETER_I32,
        TerminalAdmission::Ready => {}
    }
    let Some((index, mut origin)) = take_origin(handoff.nonce) else {
        return STATUS_INVALID_PARAMETER_I32;
    };
    if origin.prepared.is_some() {
        replace_busy(index, handoff.nonce, OriginSlot::Live(origin));
        return STATUS_INVALID_PARAMETER_I32;
    }
    let Some(source) = origin.source.as_ref() else {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, handoff.nonce, 0, 3]);
    };
    let request = SourceFsdRequest {
        nonce: origin.nonce,
        source_irp_va: source.source_address(),
        source_ticket_serial: source.source_ticket_serial(),
        native_allocation_generation: source.source_native_generation(),
        device_object_va: source.device,
        major: source.major,
        transfer_mode: source.transfer_mode,
        byte_offset: source.byte_offset,
        input: &source.input,
        output_initial: &source.output_initial,
        output_capacity: source.output_capacity,
        event: source.event,
    };
    let matched = wire::terminal_matches_request(request, handoff)
        && match origin.phase {
            OriginPhase::Calling => true,
            OriginPhase::Armed(token) => token == handoff.token,
            OriginPhase::Indeterminate => false,
        };
    if !matched || !source.validate() {
        replace_busy(index, handoff.nonce, OriginSlot::Live(origin));
        let _ = wire::publish_terminal_ack(
            packet_bytes,
            TerminalPublication::Failed(STATUS_INVALID_PARAMETER_I32 as u32),
        );
        return STATUS_INVALID_PARAMETER_I32;
    }
    if origin.prepared_packet.try_reserve_exact(packet_bytes.len()).is_err() {
        replace_busy(index, handoff.nonce, OriginSlot::Live(origin));
        return STATUS_INSUFFICIENT_RESOURCES_I32;
    }
    origin.prepared_packet.extend_from_slice(packet_bytes);
    let prior_phase = origin.phase;
    origin.phase = OriginPhase::Indeterminate;
    let source = origin.source.as_ref().unwrap();
    if !source.publish_terminal(
        handoff.status, handoff.information, handoff.output,
        source.output_va, source.iosb_va,
    ) {
        replace_busy(index, handoff.nonce, OriginSlot::Live(origin));
        return STATUS_UNSUCCESSFUL_I32;
    }
    let nonce = handoff.nonce;
    let token = handoff.token;
    let status = handoff.status;
    let information = handoff.information;
    let inline = handoff.delivery == TerminalDelivery::Inline;
    if terminal_packet_identity(packet, bytes) != Some(packet_identity)
        || wire::publish_terminal_ack(packet_bytes, TerminalPublication::Published).is_err()
    {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, nonce, packet, 4]);
    }
    origin.phase = prior_phase;
    origin.prepared = Some(PreparedTerminal {
        packet: TerminalPacketIdentity { address: packet, length: bytes,
            allocation_id: packet_identity.allocation_id, allocation_generation: packet_identity.allocation_generation },
        token: token, status: status,
        information: information,
        inline,
    });
    replace_busy(index, nonce, OriginSlot::Live(origin));
    0
}

pub(super) extern "win64" fn iof_call_driver(device: u64, irp: u64) -> i32 {
    unsafe {
        let Some(_) = active_provider_stack_event_activation() else {
            return STATUS_NOT_SUPPORTED_I32;
        };
        let stack_pointer = current_stack_pointer();
        let source = match source_fsd::admit(irp, device, stack_pointer, None) {
            Ok(source) => source,
            Err(status) => return status,
        };
        let nonce = match NEXT_FSD_NONCE.fetch_update(
            Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1),
        ) {
            Ok(nonce) if nonce != 0 => nonce,
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 5]),
        };
        let request = SourceFsdRequest {
            nonce,
            source_irp_va: source.source_address(),
            source_ticket_serial: source.source_ticket_serial(),
            native_allocation_generation: source.source_native_generation(),
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
                let mut source = source;
                if !source_fsd::release(&mut source) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 6]);
                }
                return STATUS_INVALID_PARAMETER_I32;
            }
        };
        let packet = pool_alloc(total as u64);
        if packet == 0 {
            let mut source = source;
            if !source_fsd::release(&mut source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 7]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let Some(packet_pin) = source_irp::pin_system_buffer(packet, total as u64) else {
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, packet, 0, 8]);
            }
            let mut source = source;
            if !source_fsd::release(&mut source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 9]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        };
        if wire::encode_request(
            request, core::slice::from_raw_parts_mut(packet as *mut u8, total),
        ).is_err() {
            source_irp_call::retire_packet(packet, packet_pin);
            let mut source = source;
            if !source_fsd::release(&mut source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, 0, 10]);
            }
            return STATUS_INVALID_PARAMETER_I32;
        }
        let pending_source_va = request.source_irp_va;
        let pending_source_ticket = request.source_ticket_serial;
        let pending_source_generation = request.native_allocation_generation;
        if let Err(mut origin) = insert_origin(Origin {
            nonce, source: Some(source), phase: OriginPhase::Calling, prepared: None, prepared_packet: Vec::new(), request_packet: Some((packet, packet_pin)),
        }) {
            let (packet, packet_pin) = origin.request_packet.take().expect("unentered request packet");
            source_irp_call::retire_packet(packet, packet_pin);
            release_unentered(&mut origin);
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_SOURCE_FSD_LABEL << 12) | 4,
            packet,
            total as u64,
            stack_pointer,
            0,
        );
        let (request_address, mut packet_pin) = take_request_packet(nonce).unwrap_or_else(|| {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, nonce, packet, 91])
        });
        if request_address != packet {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, nonce, request_address, 92]);
        }
        if !source_irp_call::valid_status_word(words, raw)
            || !source_irp::system_buffer_live(&packet_pin)
        {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, packet, words, raw]);
        }
        let bytes = core::slice::from_raw_parts(packet as *const u8, total);
        let result = match wire::decode_response(bytes) {
            Ok(SourceFsdResponse::Pending { token }) if raw as u32 == wire::STATUS_PENDING => {
                if !accept_pending(nonce, token) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, token, 11]);
                }
                packet_pin = source_irp_call::announce_pending(nt_io_manager::source_pending_armed::PendingArmedIdentity {
                    kind: nt_io_manager::source_pending_armed::PendingSourceKind::Fsd,
                    nonce, token, source_irp_va: pending_source_va,
                    source_ticket_serial: pending_source_ticket,
                    native_allocation_generation: pending_source_generation,
                }, packet, packet_pin);
                wire::STATUS_PENDING as i32
            }
            Ok(SourceFsdResponse::Inline { token, status, information, output })
                if raw as u32 == status =>
            {
                if !accept_inline(nonce, token, status, information, output) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, token, 12]);
                }
                status as i32
            }
            Err(_)
                if raw as u32 & 0xc000_0000 == 0xc000_0000
                    && wire::decode_request(bytes).is_ok() =>
            {
                if !reject_unentered(nonce) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, irp, raw, 13]);
                }
                raw as u32 as i32
            }
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_FSD_LABEL, packet, raw, 14]),
        };
        source_irp_call::retire_packet(packet, packet_pin);
        result
    }
}
