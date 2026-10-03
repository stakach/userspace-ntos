//! Origin-owned lifetime for a file-less win32k TargetDeviceRelation IRP.

use super::*;
use core::sync::atomic::AtomicU64;
use nt_io_manager::source_terminal::{PreparedTerminal, TerminalPacketIdentity};
use nt_io_manager::win32k_source_pnp_wire::{
    self as wire, SourcePnpRequest, SourcePnpResponse, TerminalPublication,
};

const STATUS_UNSUCCESSFUL_I32: i32 = 0xc000_0001u32 as i32;
static NEXT_PNP_NONCE: AtomicU64 = AtomicU64::new(1);
static PNP_TRACE_CALLS: AtomicU64 = AtomicU64::new(0);
static mut ORIGINS: Vec<OriginSlot> = Vec::new();

struct Origin {
    request: SourcePnpRequest,
    source: Option<source_irp::SourcePnpDispatchLease>,
    relation: Option<source_irp::SourceRelationAllocationLease>,
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
        request: SourcePnpRequest,
        token: u64,
        status: u32,
        information: u64,
    },
}

unsafe fn insert_origin(origin: Origin) -> Result<(), Origin> {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    if rows.iter().any(|row| match row {
        OriginSlot::Live(existing) => existing.request.nonce == origin.request.nonce,
        OriginSlot::Busy(nonce) => *nonce == origin.request.nonce,
        OriginSlot::Completed { request, .. } => request.nonce == origin.request.nonce,
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
        matches!(row, OriginSlot::Live(origin) if origin.request.nonce == nonce)
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
            OriginSlot::Live(origin) if origin.request.nonce == nonce => return origin.request_packet.take(),
            OriginSlot::Completed { request, request_packet, .. } if request.nonce == nonce => return request_packet.take(),
            _ => {}
        }
    }
    None
}

unsafe fn replace_busy(index: usize, nonce: u64, replacement: OriginSlot) {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    if !matches!(rows.get(index), Some(OriginSlot::Busy(found)) if *found == nonce) {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, nonce, index as u64, 13]);
    }
    rows[index] = replacement;
}

unsafe fn release_unentered(origin: &mut Origin) {
    if let Some(mut relation) = origin.relation.take() {
        if !relation.abort() {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, origin.request.nonce, 0, 14]);
        }
    }
    if let Some(mut source) = origin.source.take() {
        if !source_irp::release_pnp_dispatch(&mut source) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, origin.request.source_irp_va, 0, 15]);
        }
    }
}

unsafe fn accept_pending(nonce: u64, token: u64) -> bool {
    let Some((index, mut origin)) = take_origin(nonce) else { return false };
    let accepted = matches!(origin.phase, OriginPhase::Calling) && token != 0;
    if accepted {
        origin.phase = OriginPhase::Armed(token);
    }
    replace_busy(index, nonce, OriginSlot::Live(origin));
    accepted
}

unsafe fn accept_inline(nonce: u64, token: u64, status: u32, information: u64) -> bool {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    let Some(row) = rows.iter_mut().find(|row| {
        matches!(row, OriginSlot::Completed { request, .. } if request.nonce == nonce)
    }) else { return false };
    match row {
        OriginSlot::Completed {
            token: found_token,
            status: found_status,
            information: found_information,
            ..
        } if *found_token == token && *found_status == status && *found_information == information => {
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
        OriginSlot::Live(origin) => origin.request.nonce == nonce,
        OriginSlot::Busy(found) => *found == nonce,
        _ => false,
    }) else { return TerminalAdmission::Rejected };
    match row {
        OriginSlot::Live(origin) => delivery.admit(origin.phase, token),
        OriginSlot::Busy(_) if delivery == TerminalDelivery::Pending => TerminalAdmission::NotReady,
        _ => TerminalAdmission::Rejected,
    }
}

unsafe fn terminal_packet_identity(packet: u64) -> Option<shared_pool::AllocationIdentity> {
    let _pool = provider_pool_lock()?;
    let memory = ProviderPoolMemory;
    let offset = packet.checked_sub(WIN32K_POOL_VADDR)?;
    let native = shared_pool::allocation_identity(&memory, offset).ok()?;
    (shared_pool::allocation_capacity(&memory, offset).ok()?
        >= wire::TERMINAL_PACKET_BYTES as u64)
        .then_some(native)
}

/// A root-authenticated terminal request is delivered on another win32k lane.
/// The root may write the projected relation bytes, but only this origin may
/// publish the IOSB, mirror its Event, and release its allocation pins.
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
                &origin.prepared_packet, packet_bytes, 96)
    });
    let source_matches = wire::terminal_matches_request(origin.request, handoff);
    let source_live = origin.source.as_ref().is_some_and(|source| source.validate())
        && origin.relation.as_ref().is_some_and(|relation| relation.validate());
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
    origin.phase = OriginPhase::Indeterminate;
    if discard {
        if let Some((address, pin)) = origin.request_packet.take() {
            source_irp_call::retire_packet(address, pin);
        }
    }
    let mut relation = origin.relation.take().unwrap();
    let relation_ok = if !discard && handoff.status & 0x8000_0000 == 0 {
        relation.transfer_to_caller()
    } else { relation.abort() };
    if !relation_ok {
        origin.relation = Some(relation);
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return STATUS_UNSUCCESSFUL_I32;
    }
    let mut source = origin.source.take().unwrap();
    if !(if discard { source_irp::release_pnp_dispatch(&mut source) }
        else { source_irp::commit_pnp_dispatch(&mut source, sequence) }) {
        origin.source = Some(source);
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return STATUS_UNSUCCESSFUL_I32;
    }
    if terminal_packet_identity(packet) != Some(native)
        || wire::publish_terminal_ack(packet_bytes, if discard {
            TerminalPublication::Discarded
        } else { TerminalPublication::Committed }).is_err()
    {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, nonce, packet, 90]);
    }
    let replacement = if inline {
        OriginSlot::Completed { request: origin.request, token,
            request_packet: origin.request_packet.take(),
            status, information }
    } else { OriginSlot::Empty };
    replace_busy(index, nonce, replacement);
    0
}

pub(crate) unsafe fn complete_terminal(packet: u64, bytes: u64) -> i32 {
    if bytes != wire::TERMINAL_PACKET_BYTES as u64
        || !provider_pool_contains(packet)
        || packet.checked_add(bytes - 1).is_none_or(|end| !provider_pool_contains(end))
    {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let Some(packet_identity) = terminal_packet_identity(packet) else {
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
    let matched = wire::terminal_matches_request(origin.request, handoff)
        && match origin.phase {
            OriginPhase::Calling => true,
            OriginPhase::Armed(token) => token == handoff.token,
            OriginPhase::Indeterminate => false,
        };
    if !matched {
        replace_busy(index, handoff.nonce, OriginSlot::Live(origin));
        let _ = wire::publish_terminal_ack(
            packet_bytes,
            TerminalPublication::Failed(STATUS_INVALID_PARAMETER_I32 as u32),
        );
        return STATUS_INVALID_PARAMETER_I32;
    }
    let Some(source) = origin.source.as_ref() else {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, handoff.nonce, 0, 16]);
    };
    let Some(relation) = origin.relation.as_ref() else {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, handoff.nonce, 0, 17]);
    };
    let relation_bytes_match = if handoff.status & 0x8000_0000 == 0 {
        relation.with_bytes(|bytes| {
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()) == 1
                && bytes[4..8] == [0; 4]
                && u64::from_le_bytes(bytes[8..16].try_into().unwrap()) == handoff.pdo_va
        }) == Some(true)
    } else {
        true
    };
    if !source.validate()
        || !relation.validate()
        || relation.native_identity().allocation_generation != handoff.relation_allocation_generation
        || !relation_bytes_match
    {
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
    if !source.publish_terminal(handoff.status, handoff.information, handoff.iosb_va) {
        replace_busy(index, handoff.nonce, OriginSlot::Live(origin));
        return STATUS_UNSUCCESSFUL_I32;
    }
    if terminal_packet_identity(packet) != Some(packet_identity)
        || wire::publish_terminal_ack(packet_bytes, TerminalPublication::Published).is_err()
    {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, handoff.nonce, packet, 18]);
    }
    origin.phase = prior_phase;
    origin.prepared = Some(PreparedTerminal {
        packet: TerminalPacketIdentity { address: packet, length: bytes,
            allocation_id: packet_identity.allocation_id, allocation_generation: packet_identity.allocation_generation },
        token: handoff.token, status: handoff.status,
        information: handoff.information,
        inline: handoff.delivery == TerminalDelivery::Inline,
    });
    replace_busy(index, handoff.nonce, OriginSlot::Live(origin));
    0
}

pub(super) extern "win64" fn iof_call_driver(device: u64, irp: u64) -> i32 {
    unsafe {
        let trace = PNP_TRACE_CALLS.fetch_add(1, Ordering::Relaxed) < 8;
        if trace {
            print_str(b"[source-pnp-origin] entry device=0x");
            print_hex_u64(device);
            print_str(b" irp=0x");
            print_hex_u64(irp);
            print_str(b"\n");
        }
        let Some(_) = active_provider_stack_event_activation() else {
            if trace { print_str(b"[source-pnp-origin] no stack activation\n"); }
            return STATUS_NOT_SUPPORTED_I32;
        };
        let stack_pointer = current_stack_pointer();
        let source = match source_irp::admit_pnp_target_relation(irp, device, stack_pointer) {
            Ok(source) => source,
            Err(status) => {
                if trace {
                    print_str(b"[source-pnp-origin] source admission status=0x");
                    print_hex(status as u32);
                    print_str(b"\n");
                }
                return status;
            }
        };
        let relation = match source_irp::allocate_target_relation() {
            Some(relation) => relation,
            None => {
                if trace { print_str(b"[source-pnp-origin] relation allocation failed\n"); }
                let mut source = source;
                if !source_irp::release_pnp_dispatch(&mut source) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, 0, 1]);
                }
                return STATUS_INSUFFICIENT_RESOURCES_I32;
            }
        };
        let nonce = match NEXT_PNP_NONCE.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |n| n.checked_add(1),
        ) {
            Ok(value) if value != 0 => value,
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, 0, 4]),
        };
        let request = SourcePnpRequest {
            nonce,
            source_irp_va: source.source_address(),
            source_ticket_serial: source.source_ticket_serial(),
            native_allocation_generation: source.source_native_generation(),
            device_object_va: device,
            relation_type: nt_pnp_abi::TARGET_DEVICE_RELATION,
            event: source.event,
            iosb_va: source.iosb_va,
            relation_allocation_va: relation.address(),
            relation_allocation_generation: relation.native_identity().allocation_generation,
        };
        let mut origin = Origin {
            request,
            source: Some(source),
            relation: Some(relation),
            phase: OriginPhase::Calling,
            prepared: None, prepared_packet: Vec::new(), request_packet: None,
        };
        let packet = pool_alloc(wire::PACKET_BYTES as u64);
        if packet == 0 {
            if trace { print_str(b"[source-pnp-origin] packet allocation failed\n"); }
            release_unentered(&mut origin);
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let Some(packet_pin) = source_irp::pin_system_buffer(packet, wire::PACKET_BYTES as u64) else {
            if trace { print_str(b"[source-pnp-origin] packet pin failed\n"); }
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, packet, 0, 2]);
            }
            release_unentered(&mut origin);
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        };
        let packet_bytes = core::slice::from_raw_parts_mut(packet as *mut u8, wire::PACKET_BYTES);
        if wire::encode_request(request, packet_bytes).is_err() {
            if trace { print_str(b"[source-pnp-origin] request encoding failed\n"); }
            source_irp_call::retire_packet(packet, packet_pin);
            release_unentered(&mut origin);
            return STATUS_INVALID_PARAMETER_I32;
        }
        origin.request_packet = Some((packet, packet_pin));
        if let Err(mut origin) = insert_origin(origin) {
            if trace { print_str(b"[source-pnp-origin] origin registration failed\n"); }
            let (packet, packet_pin) = origin.request_packet.take().expect("unentered request packet");
            source_irp_call::retire_packet(packet, packet_pin);
            release_unentered(&mut origin);
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        if trace {
            print_str(b"[source-pnp-origin] call nonce=0x");
            print_hex_u64(nonce);
            print_str(b" source=0x");
            print_hex_u64(request.source_irp_va);
            print_str(b" relation=0x");
            print_hex_u64(request.relation_allocation_va);
            print_str(b" packet=0x");
            print_hex_u64(packet);
            print_str(b"\n");
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_SOURCE_PNP_LABEL << 12) | 4,
            packet,
            wire::PACKET_BYTES as u64,
            stack_pointer,
            0,
        );
        if trace {
            print_str(b"[source-pnp-origin] reply words=0x");
            print_hex_u64(words);
            print_str(b" status=0x");
            print_hex(raw as u32);
            print_str(b"\n");
        }
        let (request_address, mut packet_pin) = take_request_packet(nonce).unwrap_or_else(|| {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, nonce, packet, 91])
        });
        if request_address != packet {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, nonce, request_address, 92]);
        }
        if !source_irp_call::valid_status_word(words, raw)
            || !source_irp::system_buffer_live(&packet_pin)
        {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, packet, words, raw]);
        }
        let packet_bytes = core::slice::from_raw_parts(packet as *const u8, wire::PACKET_BYTES);
        let result = match wire::decode_response(packet_bytes) {
            Ok(SourcePnpResponse::Pending { token }) if raw as u32 == wire::STATUS_PENDING => {
                if !accept_pending(nonce, token) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, token, 20]);
                }
                packet_pin = source_irp_call::announce_pending(nt_io_manager::source_pending_armed::PendingArmedIdentity {
                    kind: nt_io_manager::source_pending_armed::PendingSourceKind::Pnp,
                    nonce, token, source_irp_va: request.source_irp_va,
                    source_ticket_serial: request.source_ticket_serial,
                    native_allocation_generation: request.native_allocation_generation,
                }, packet, packet_pin);
                wire::STATUS_PENDING as i32
            }
            Ok(SourcePnpResponse::Inline { token, status, information }) if raw as u32 == status => {
                if !accept_inline(nonce, token, status, information) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, token, 21]);
                }
                status as i32
            }
            Err(_)
                if raw as u32 & 0xc000_0000 == 0xc000_0000
                    && wire::decode_request(packet_bytes).is_ok() =>
            {
                if !reject_unentered(nonce) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, irp, raw, 22]);
                }
                raw as u32 as i32
            }
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_PNP_LABEL, packet, raw, 12]),
        };
        source_irp_call::retire_packet(packet, packet_pin);
        if trace {
            print_str(b"[source-pnp-origin] return status=0x");
            print_hex(result as u32);
            print_str(b"\n");
        }
        result
    }
}
