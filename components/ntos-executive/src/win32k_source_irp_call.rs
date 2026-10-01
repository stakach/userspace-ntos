//! Component-side call and request packet lifecycle for file-less source IOCTLs.

use super::*;
use core::sync::atomic::AtomicU64;
use nt_io_manager::source_terminal::{PreparedTerminal, TerminalPacketIdentity};
use nt_io_manager::win32k_source_irp_ioctl_wire::{
    self as wire, SourceIrpIoctlRequest, SourceIrpIoctlResponse, TerminalPublication,
};

static NEXT_SOURCE_IOCTL_NONCE: AtomicU64 = AtomicU64::new(1);
const STATUS_UNSUCCESSFUL_I32: i32 = 0xc000_0001u32 as i32;
static mut ORIGINS: Vec<OriginSlot> = Vec::new();

#[derive(Clone, Copy)]
struct OriginIdentity {
    nonce: u64,
    source_irp_va: u64,
    source_ticket_serial: u64,
    native_allocation_generation: u64,
    code: u32,
    output_va: u64,
    output_capacity: u32,
    iosb_va: u64,
}

struct Origin {
    identity: OriginIdentity,
    source: source_irp::SourceBufferedDispatchLease,
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
    Completed { identity: OriginIdentity, token: u64, status: u32, information: u64, request_packet: Option<(u64, source_irp::PinnedSystemBuffer)> },
}

unsafe fn insert_origin(origin: Origin) -> Result<(), Origin> {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    if rows.iter().any(|row| match row {
        OriginSlot::Live(existing) => existing.identity.nonce == origin.identity.nonce,
        OriginSlot::Busy(nonce) => *nonce == origin.identity.nonce,
        OriginSlot::Completed { identity, .. } => identity.nonce == origin.identity.nonce,
        OriginSlot::Empty => false,
    }) { return Err(origin); }
    if let Some(row) = rows.iter_mut().find(|row| matches!(row, OriginSlot::Empty)) {
        *row = OriginSlot::Live(origin);
        return Ok(());
    }
    if rows.try_reserve(1).is_err() { return Err(origin); }
    rows.push(OriginSlot::Live(origin));
    Ok(())
}

unsafe fn take_origin(nonce: u64) -> Option<(usize, Origin)> {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    let index = rows.iter().position(|row| {
        matches!(row, OriginSlot::Live(origin) if origin.identity.nonce == nonce)
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
            OriginSlot::Live(origin) if origin.identity.nonce == nonce => return origin.request_packet.take(),
            OriginSlot::Completed { identity, request_packet, .. } if identity.nonce == nonce => return request_packet.take(),
            _ => {}
        }
    }
    None
}

unsafe fn replace_busy(index: usize, nonce: u64, replacement: OriginSlot) {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    if !matches!(rows.get(index), Some(OriginSlot::Busy(found)) if *found == nonce) {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, nonce, index as u64, 50]);
    }
    rows[index] = replacement;
}

unsafe fn reject_unentered(nonce: u64) -> bool {
    let Some((index, mut origin)) = take_origin(nonce) else { return false };
    if !matches!(origin.phase, OriginPhase::Calling) {
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return false;
    }
    if !source_irp::release_buffered_dispatch(&mut origin.source) {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, nonce, 0, 51]);
    }
    replace_busy(index, nonce, OriginSlot::Empty);
    true
}

unsafe fn accept_pending(nonce: u64, token: u64) -> bool {
    let Some((index, mut origin)) = take_origin(nonce) else { return false };
    if !matches!(origin.phase, OriginPhase::Calling) || token == 0 {
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return false;
    }
    origin.phase = OriginPhase::Armed(token);
    replace_busy(index, nonce, OriginSlot::Live(origin));
    true
}

unsafe fn accept_inline(nonce: u64, token: u64, status: u32, information: u64) -> bool {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(ORIGINS);
    let Some(row) = rows.iter_mut().find(|row| {
        matches!(row, OriginSlot::Completed { identity, .. } if identity.nonce == nonce)
    }) else { return false };
    if matches!(row, OriginSlot::Completed {
        token: found_token, status: found_status, information: found_info, ..
    } if *found_token == token && *found_status == status && *found_info == information) {
        *row = OriginSlot::Empty;
        true
    } else { false }
}

// Pending Reply acknowledgement does not prove the original Call continuation armed its origin.
// Check under metadata ownership before extraction, so accept_pending cannot encounter Busy.
unsafe fn terminal_admission(nonce: u64, delivery: TerminalDelivery, token: u64) -> TerminalAdmission {
    let _metadata = ProviderMetadataGuard::acquire();
    let rows = &*core::ptr::addr_of!(ORIGINS);
    let Some(row) = rows.iter().find(|row| match row {
        OriginSlot::Live(origin) => origin.identity.nonce == nonce,
        OriginSlot::Busy(found) => *found == nonce,
        _ => false,
    }) else { return TerminalAdmission::Rejected };
    match row {
        OriginSlot::Live(origin) => delivery.admit(origin.phase, token),
        OriginSlot::Busy(_) if delivery == TerminalDelivery::Pending => TerminalAdmission::NotReady,
        _ => TerminalAdmission::Rejected,
    }
}

unsafe fn terminal_packet_identity(packet: u64, length: usize)
    -> Option<shared_pool::AllocationIdentity>
{
    let _pool = provider_pool_lock()?;
    let memory = ProviderPoolMemory;
    let offset = packet.checked_sub(WIN32K_POOL_VADDR)?;
    let native = shared_pool::allocation_identity(&memory, offset).ok()?;
    (shared_pool::allocation_capacity(&memory, offset).ok()? >= length as u64)
        .then_some(native)
}

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
                &origin.prepared_packet, packet_bytes, 88)
    });
    let identity = origin.identity;
    let source_matches = identity.source_irp_va == handoff.source_irp_va
        && identity.source_ticket_serial == handoff.source_ticket_serial
        && identity.native_allocation_generation == handoff.native_allocation_generation
        && identity.code == handoff.code && identity.iosb_va == handoff.iosb_va
        && identity.output_va == handoff.output_va && identity.output_capacity == handoff.output_capacity;
    let source_live = origin.source.validate();
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
            retire_packet(address, pin);
        }
    }
    if !(if discard { source_irp::release_buffered_dispatch(&mut origin.source) }
        else { source_irp::commit_buffered_dispatch(&mut origin.source, sequence) })
    { replace_busy(index, nonce, OriginSlot::Live(origin)); return STATUS_UNSUCCESSFUL_I32; }
    if terminal_packet_identity(packet, length as usize) != Some(native)
        || wire::publish_terminal_ack(packet_bytes, if discard {
            TerminalPublication::Discarded
        } else { TerminalPublication::Committed }).is_err()
    {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, nonce, packet, 90]);
    }
    let replacement = if inline {
        OriginSlot::Completed { identity: origin.identity, token,
            request_packet: origin.request_packet.take(),
            status, information }
    } else { OriginSlot::Empty };
    replace_busy(index, nonce, replacement);
    0
}

pub(crate) unsafe fn complete_terminal(packet: u64, length: u64) -> i32 {
    let Ok(length) = usize::try_from(length) else { return STATUS_INVALID_PARAMETER_I32 };
    if length < wire::TERMINAL_HEADER_BYTES
        || length > wire::MAX_TERMINAL_PACKET_BYTES
        || !provider_pool_contains(packet)
        || packet.checked_add(length as u64 - 1).is_none_or(|end| !provider_pool_contains(end))
    { return STATUS_INVALID_PARAMETER_I32; }
    let Some(native) = terminal_packet_identity(packet, length) else {
        return STATUS_INVALID_PARAMETER_I32;
    };
    let packet_bytes = core::slice::from_raw_parts_mut(packet as *mut u8, length);
    if let Ok(ack) = wire::decode_terminal_ack(packet_bytes) {
        if matches!(ack.publication, TerminalPublication::CommitRequested | TerminalPublication::DiscardRequested) {
            return finish_terminal_commit(packet, length as u64, native, ack.publication);
        }
        return STATUS_INVALID_PARAMETER_I32;
    }
    let Ok(handoff) = wire::decode_terminal_handoff(packet_bytes) else {
        return STATUS_INVALID_PARAMETER_I32;
    };
    let nonce = handoff.nonce;
    let token = handoff.token;
    let status = handoff.status;
    let information = handoff.information;
    let inline = handoff.delivery == TerminalDelivery::Inline;
    match terminal_admission(nonce, handoff.delivery, token) {
        TerminalAdmission::NotReady => return TERMINAL_NOT_READY,
        TerminalAdmission::Rejected => return STATUS_INVALID_PARAMETER_I32,
        TerminalAdmission::Ready => {}
    }
    let Some((index, mut origin)) = take_origin(nonce) else {
        return STATUS_INVALID_PARAMETER_I32;
    };
    if origin.prepared.is_some() {
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return STATUS_INVALID_PARAMETER_I32;
    }
    let identity = origin.identity;
    let matched = identity.source_irp_va == handoff.source_irp_va
        && identity.source_ticket_serial == handoff.source_ticket_serial
        && identity.native_allocation_generation == handoff.native_allocation_generation
        && identity.code == handoff.code
        && identity.iosb_va == handoff.iosb_va
        && identity.output_va == handoff.output_va
        && identity.output_capacity == handoff.output_capacity
        && match origin.phase {
            OriginPhase::Calling => true,
            OriginPhase::Armed(token) => token == handoff.token,
            OriginPhase::Indeterminate => false,
        };
    if !matched || !origin.source.validate() {
        replace_busy(index, nonce, OriginSlot::Live(origin));
        let _ = wire::publish_terminal_ack(
            packet_bytes, TerminalPublication::Failed(STATUS_INVALID_PARAMETER_I32 as u32),
        );
        return STATUS_INVALID_PARAMETER_I32;
    }
    if origin.prepared_packet.try_reserve_exact(packet_bytes.len()).is_err() {
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return STATUS_INSUFFICIENT_RESOURCES_I32;
    }
    origin.prepared_packet.extend_from_slice(packet_bytes);
    let prior_phase = origin.phase;
    origin.phase = OriginPhase::Indeterminate;
    if !origin.source.publish_terminal(
        handoff.status, handoff.information, handoff.output,
        origin.source.output_va, origin.source.iosb_va,
    ) {
        replace_busy(index, nonce, OriginSlot::Live(origin));
        return STATUS_UNSUCCESSFUL_I32;
    }
    if terminal_packet_identity(packet, length) != Some(native)
        || wire::publish_terminal_ack(packet_bytes, TerminalPublication::Published).is_err()
    {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, nonce, packet, 52]);
    }
    origin.phase = prior_phase;
    origin.prepared = Some(PreparedTerminal {
        packet: TerminalPacketIdentity { address: packet, length: length as u64,
            allocation_id: native.allocation_id, allocation_generation: native.allocation_generation },
        token: token, status: status,
        information: information,
        inline,
    });
    replace_busy(index, nonce, OriginSlot::Live(origin));
    0
}
pub(super) unsafe fn retire_packet(packet: u64, packet_pin: source_irp::PinnedSystemBuffer) {
    if !source_irp::release_system_buffer(packet_pin) || !provider_pool_free(packet) {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, 0, 2]);
    }
}

struct ArmedPacket {
    identity: nt_io_manager::source_pending_armed::PendingArmedIdentity,
    address: u64,
    pin: source_irp::PinnedSystemBuffer,
}

static mut ARMED_PACKETS: Vec<ArmedPacket> = Vec::new();

/// Source completion may retire its origin after this broker ACK, before this Call returns.
/// Keep the acknowledgement packet in independent durable ownership across that interval.
pub(super) unsafe fn announce_pending(
    identity: nt_io_manager::source_pending_armed::PendingArmedIdentity,
    packet: u64,
    pin: source_irp::PinnedSystemBuffer,
) -> source_irp::PinnedSystemBuffer {
    use nt_io_manager::source_pending_armed::{encode, PACKET_BYTES};
    if !source_irp::system_buffer_live(&pin) || pin.address() != packet {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_ARMED_LABEL, packet, identity.nonce, 97]);
    }
    {
        let _metadata = ProviderMetadataGuard::acquire();
        let rows = &mut *core::ptr::addr_of_mut!(ARMED_PACKETS);
        if rows.iter().any(|row| row.identity == identity || row.address == packet)
            || rows.try_reserve(1).is_err()
        {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_ARMED_LABEL, packet, identity.nonce, 98]);
        }
        rows.push(ArmedPacket { identity, address: packet, pin });
    }
    if encode(identity, core::slice::from_raw_parts_mut(packet as *mut u8, PACKET_BYTES)).is_err() {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_ARMED_LABEL, packet, identity.nonce, 99]);
    }
    let (words, status, _, _, _) = crate::driver_launch::call_on4_raw(
        (W32_SOURCE_ARMED_LABEL << 12) | 4, packet, PACKET_BYTES as u64, 0, 0,
    );
    if !valid_status_word(words, status) || status != 0 {
        // An uncertain acknowledgement retains both source ownership and its packet.
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_ARMED_LABEL, packet, words, status]);
    }
    let row = {
        let _metadata = ProviderMetadataGuard::acquire();
        let rows = &mut *core::ptr::addr_of_mut!(ARMED_PACKETS);
        let Some(index) = rows.iter().position(|row| row.identity == identity && row.address == packet)
        else { crate::provider_bugcheck::report(0xc4, [W32_SOURCE_ARMED_LABEL, packet, identity.nonce, 100]); };
        rows.remove(index)
    };
    if !source_irp::system_buffer_live(&row.pin) {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_ARMED_LABEL, packet, identity.nonce, 101]);
    }
    row.pin
}

pub(super) fn valid_status_word(words: u64, raw: u64) -> bool {
    words == 1 && (raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64)
}

pub(super) extern "win64" fn iof_call_driver(device: u64, irp: u64) -> i32 {
    unsafe {
        let Some(_) = active_provider_stack_event_activation() else {
            return STATUS_NOT_SUPPORTED_I32;
        };
        let stack_pointer = current_stack_pointer();
        let mut admission = match source_irp::admit_buffered_dispatch(irp, device, stack_pointer, None) {
            Ok(lease) => lease,
            Err(status) => return status,
        };
        let input_length = admission.input.len() as u32;
        let total = match wire::packet_len(admission.code, input_length, admission.output_capacity) {
            Ok(total) if (total as u64) < WIN32K_POOL_FRAMES * 0x1000 => total,
            _ => {
                if !source_irp::release_buffered_dispatch(&mut admission) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 5]);
                }
                return STATUS_INVALID_PARAMETER_I32;
            }
        };
        let packet = pool_alloc(total as u64);
        if packet == 0 {
            if !source_irp::release_buffered_dispatch(&mut admission) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 6]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let Some(packet_pin) = source_irp::pin_system_buffer(packet, total as u64) else {
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, 0, 7]);
            }
            if !source_irp::release_buffered_dispatch(&mut admission) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 8]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        };
        let nonce = match NEXT_SOURCE_IOCTL_NONCE.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |n| n.checked_add(1),
        ) {
            Ok(value) if value != 0 => value,
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 9]),
        };
        let source_ticket = admission.source_ticket_serial();
        let source_generation = admission.source_native_generation();
        let system_identity = admission.system_buffer_native_identity();
        let mdl_identity = admission.mdl_native_identity();
        let identity = OriginIdentity {
            nonce,
            source_irp_va: admission.source_address(),
            source_ticket_serial: source_ticket,
            native_allocation_generation: source_generation,
            code: admission.code,
            output_va: admission.output_va,
            output_capacity: admission.output_capacity,
            iosb_va: admission.iosb_va,
        };
        let encoded = wire::encode_request(
            SourceIrpIoctlRequest {
                nonce,
                source_irp_va: admission.source_address(),
                source_ticket_serial: source_ticket,
                native_allocation_generation: source_generation,
                device_object_va: device,
                code: admission.code,
                input: &admission.input,
                output_initial: &admission.output_initial,
                output_capacity: admission.output_capacity,
                event: admission.event,
                output_va: admission.output_va,
                iosb_va: admission.iosb_va,
                system_buffer_va: admission.system_buffer_address().unwrap_or(0),
                system_buffer_generation: system_identity
                    .map_or(0, |identity| identity.allocation_generation),
                mdl_va: admission.mdl_address().unwrap_or(0),
                mdl_generation: mdl_identity
                    .map_or(0, |identity| identity.allocation_generation),
                input_va: admission.type3_input_buffer_address().unwrap_or(0),
                event_body_va: admission.event_body().unwrap_or(0),
            },
            core::slice::from_raw_parts_mut(packet as *mut u8, total),
        );
        if encoded.is_err() {
            if !source_irp::release_system_buffer(packet_pin) || !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, 0, 10]);
            }
            if !source_irp::release_buffered_dispatch(&mut admission) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 11]);
            }
            return STATUS_INVALID_PARAMETER_I32;
        }
        if let Err(mut origin) = insert_origin(Origin {
            identity,
            source: admission,
            phase: OriginPhase::Calling,
            prepared: None, prepared_packet: Vec::new(), request_packet: Some((packet, packet_pin)),
        }) {
            let (packet, packet_pin) = origin.request_packet.take().expect("unentered request packet");
            retire_packet(packet, packet_pin);
            if !source_irp::release_buffered_dispatch(&mut origin.source) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 14]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_SOURCE_IOCTL_LABEL << 12) | 4,
            packet,
            total as u64,
            stack_pointer,
            0,
        );
        let (request_address, packet_pin) = take_request_packet(nonce).unwrap_or_else(|| {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, nonce, packet, 91])
        });
        if request_address != packet {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, nonce, request_address, 92]);
        }
        if !valid_status_word(words, raw) || !source_irp::system_buffer_live(&packet_pin) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, words, raw]);
        }
        let response = wire::decode_response(core::slice::from_raw_parts(packet as *const u8, total));
        match response {
            Ok(SourceIrpIoctlResponse::Pending { token }) if raw as u32 == wire::STATUS_PENDING => {
                if !accept_pending(nonce, token) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, token, 53]);
                }
                let packet_pin = announce_pending(nt_io_manager::source_pending_armed::PendingArmedIdentity {
                    kind: nt_io_manager::source_pending_armed::PendingSourceKind::Ioctl,
                    nonce, token, source_irp_va: identity.source_irp_va,
                    source_ticket_serial: source_ticket,
                    native_allocation_generation: source_generation,
                }, packet, packet_pin);
                retire_packet(packet, packet_pin);
                wire::STATUS_PENDING as i32
            }
            Ok(SourceIrpIoctlResponse::Inline { token, status, information, .. })
                if raw as u32 == status => {
                if !accept_inline(nonce, token, status, information) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, token, 54]);
                }
                retire_packet(packet, packet_pin);
                status as i32
            }
            Err(_)
                if raw as u32 & 0xc000_0000 == 0xc000_0000
                    && wire::decode_request(core::slice::from_raw_parts(packet as *const u8, total))
                        .is_ok() =>
            {
                retire_packet(packet, packet_pin);
                if !reject_unentered(nonce) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, raw, 55]);
                }
                raw as u32 as i32
            }
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, raw, 15]),
        }
    }
}
