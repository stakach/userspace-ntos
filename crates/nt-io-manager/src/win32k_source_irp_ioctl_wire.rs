//! Bounded round-trip wire for win32k file-less, kernel-built device controls.
//!
//! Every identity here is correlation data. The receiver must derive authority
//! from its physical provider lane and revalidate the live source IRP, device,
//! and optional Event before dispatch.

use nt_io_abi::ioctl;

pub const HEADER_BYTES: usize = 192;
pub const MAX_BUFFER_BYTES: u32 = 64 * 1024;
pub const MAX_PACKET_BYTES: usize = HEADER_BYTES + 2 * MAX_BUFFER_BYTES as usize;
pub const TERMINAL_HEADER_BYTES: usize = 128;
pub const MAX_TERMINAL_PACKET_BYTES: usize = TERMINAL_HEADER_BYTES + MAX_BUFFER_BYTES as usize;
pub const STATUS_PENDING: u32 = 0x103;
const KIND: u32 = 1;
const VERSION: u32 = 4;
const TERMINAL_KIND: u32 = 4;
const TERMINAL_VERSION: u32 = 1;
const TOKEN_OFF: usize = 88;
const INFORMATION_OFF: usize = 96;
const STATUS_OFF: usize = 104;
const COMPLETED_OFF: usize = 108;
const OUTPUT_LENGTH_OFF: usize = 112;
const OUTPUT_VA_OFF: usize = 120;
const IOSB_VA_OFF: usize = 128;
const SYSTEM_BUFFER_VA_OFF: usize = 136;
const SYSTEM_BUFFER_GENERATION_OFF: usize = 144;
const MDL_VA_OFF: usize = 152;
const MDL_GENERATION_OFF: usize = 160;
const INPUT_VA_OFF: usize = 168;
const EVENT_BODY_VA_OFF: usize = 176;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventIdentity {
    pub local_id: u64,
    pub object_slot_plus_one: u64,
    pub object_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIrpIoctlRequest<'a> {
    pub nonce: u64,
    pub source_irp_va: u64,
    pub source_ticket_serial: u64,
    pub native_allocation_generation: u64,
    pub device_object_va: u64,
    pub code: u32,
    pub input: &'a [u8],
    /// Original second/user buffer bytes for direct and neither methods.
    pub output_initial: &'a [u8],
    pub output_capacity: u32,
    pub event: Option<EventIdentity>,
    pub output_va: u64,
    pub iosb_va: u64,
    pub system_buffer_va: u64,
    pub system_buffer_generation: u64,
    pub mdl_va: u64,
    pub mdl_generation: u64,
    pub input_va: u64,
    pub event_body_va: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIoctlTerminalHandoff<'a> {
    pub nonce: u64,
    pub token: u64,
    pub source_irp_va: u64,
    pub source_ticket_serial: u64,
    pub native_allocation_generation: u64,
    pub code: u32,
    pub iosb_va: u64,
    pub output_va: u64,
    pub output_capacity: u32,
    pub status: u32,
    pub information: u64,
    pub output: &'a [u8],
}

pub use crate::source_terminal::TerminalPublication;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIoctlTerminalAck<'a> {
    pub handoff: SourceIoctlTerminalHandoff<'a>,
    pub publication: TerminalPublication,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceIrpIoctlResponse<'a> {
    Pending {
        token: u64,
    },
    Inline {
        token: u64,
        status: u32,
        information: u64,
        output: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    BufferTooSmall,
    LengthMismatch,
    Malformed,
}

fn u32_at(packet: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(packet[offset..offset + 4].try_into().unwrap())
}

fn u64_at(packet: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(packet[offset..offset + 8].try_into().unwrap())
}

fn put_u32(packet: &mut [u8], offset: usize, value: u32) {
    packet[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(packet: &mut [u8], offset: usize, value: u64) {
    packet[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn packet_len(code: u32, input_len: u32, output_capacity: u32) -> Result<usize, WireError> {
    if input_len > MAX_BUFFER_BYTES || output_capacity > MAX_BUFFER_BYTES {
        return Err(WireError::LengthMismatch);
    }
    let payload = if ioctl::method(code) == ioctl::METHOD_BUFFERED {
        input_len.max(output_capacity)
    } else {
        input_len
            .checked_add(output_capacity)
            .ok_or(WireError::LengthMismatch)?
    };
    Ok(HEADER_BYTES + payload as usize)
}

pub fn completion_output_len(code: u32, status: u32, information: u64, capacity: u32) -> usize {
    if ioctl::method(code) != ioctl::METHOD_BUFFERED {
        capacity as usize
    } else if status >> 30 == 3 || status == 0x8000_0016 {
        0
    } else {
        information.min(capacity as u64) as usize
    }
}

fn validate(request: &SourceIrpIoctlRequest<'_>) -> Result<(), WireError> {
    if request.nonce == 0
        || request.source_irp_va == 0
        || request.source_ticket_serial == 0
        || request.native_allocation_generation == 0
        || request.device_object_va == 0
        || request.iosb_va == 0
        || (request.output_capacity != 0 && request.output_va == 0)
        || request.event.is_some() != (request.event_body_va != 0)
        || (request.system_buffer_va == 0) != (request.system_buffer_generation == 0)
        || (request.mdl_va == 0) != (request.mdl_generation == 0)
        || (ioctl::method(request.code) == ioctl::METHOD_BUFFERED
            && !request.output_initial.is_empty())
        || (ioctl::method(request.code) != ioctl::METHOD_BUFFERED
            && request.output_initial.len() != request.output_capacity as usize)
        || request.event.is_some_and(|event| {
            event.local_id == 0 || event.object_slot_plus_one == 0 || event.object_generation == 0
        })
    {
        return Err(WireError::Malformed);
    }
    let expected = match ioctl::method(request.code) {
        ioctl::METHOD_BUFFERED => {
            (request.system_buffer_va != 0)
                == (!request.input.is_empty() || request.output_capacity != 0)
                && request.mdl_va == 0
                && request.input_va == 0
        }
        ioctl::METHOD_IN_DIRECT | ioctl::METHOD_OUT_DIRECT => {
            (request.system_buffer_va != 0) == !request.input.is_empty()
                && (request.mdl_va != 0) == (request.output_capacity != 0)
                && request.input_va == 0
        }
        ioctl::METHOD_NEITHER => {
            request.system_buffer_va == 0
                && request.mdl_va == 0
                && (!request.input.is_empty() || request.input_va == 0)
        }
        _ => false,
    };
    if !expected {
        return Err(WireError::Malformed);
    }
    Ok(())
}

pub fn encode_request(
    request: SourceIrpIoctlRequest<'_>,
    packet: &mut [u8],
) -> Result<(), WireError> {
    let input_len = u32::try_from(request.input.len()).map_err(|_| WireError::LengthMismatch)?;
    if packet.len() != packet_len(request.code, input_len, request.output_capacity)? {
        return Err(WireError::LengthMismatch);
    }
    validate(&request)?;
    packet.fill(0);
    put_u32(packet, 0, KIND);
    put_u32(packet, 4, VERSION);
    put_u64(packet, 8, request.nonce);
    put_u64(packet, 16, request.source_irp_va);
    put_u64(packet, 24, request.source_ticket_serial);
    put_u64(packet, 32, request.native_allocation_generation);
    put_u64(packet, 40, request.device_object_va);
    put_u32(packet, 48, request.code);
    put_u32(packet, 52, input_len);
    put_u32(packet, 56, request.output_capacity);
    if let Some(event) = request.event {
        put_u64(packet, 64, event.local_id);
        put_u64(packet, 72, event.object_slot_plus_one);
        put_u64(packet, 80, event.object_generation);
    }
    put_u64(packet, OUTPUT_VA_OFF, request.output_va);
    put_u64(packet, IOSB_VA_OFF, request.iosb_va);
    put_u64(packet, SYSTEM_BUFFER_VA_OFF, request.system_buffer_va);
    put_u64(
        packet,
        SYSTEM_BUFFER_GENERATION_OFF,
        request.system_buffer_generation,
    );
    put_u64(packet, MDL_VA_OFF, request.mdl_va);
    put_u64(packet, MDL_GENERATION_OFF, request.mdl_generation);
    put_u64(packet, INPUT_VA_OFF, request.input_va);
    put_u64(packet, EVENT_BODY_VA_OFF, request.event_body_va);
    packet[HEADER_BYTES..HEADER_BYTES + request.input.len()].copy_from_slice(request.input);
    if !request.output_initial.is_empty() {
        let start = HEADER_BYTES + request.input.len();
        packet[start..start + request.output_initial.len()].copy_from_slice(request.output_initial);
    }
    Ok(())
}

fn validate_header(packet: &[u8]) -> Result<(u32, usize, u32, Option<EventIdentity>), WireError> {
    if packet.len() < HEADER_BYTES {
        return Err(WireError::BufferTooSmall);
    }
    let input_len = u32_at(packet, 52);
    let output_capacity = u32_at(packet, 56);
    let code = u32_at(packet, 48);
    if packet.len() != packet_len(code, input_len, output_capacity)? {
        return Err(WireError::LengthMismatch);
    }
    if u32_at(packet, 0) != KIND
        || u32_at(packet, 4) != VERSION
        || u32_at(packet, 60) != 0
        || packet[116..120].iter().any(|byte| *byte != 0)
        || packet[184..HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(WireError::Malformed);
    }
    let event = match (u64_at(packet, 64), u64_at(packet, 72), u64_at(packet, 80)) {
        (0, 0, 0) => None,
        (local_id, object_slot_plus_one, object_generation) => Some(EventIdentity {
            local_id,
            object_slot_plus_one,
            object_generation,
        }),
    };
    validate(&SourceIrpIoctlRequest {
        nonce: u64_at(packet, 8),
        source_irp_va: u64_at(packet, 16),
        source_ticket_serial: u64_at(packet, 24),
        native_allocation_generation: u64_at(packet, 32),
        device_object_va: u64_at(packet, 40),
        code,
        input: &packet[HEADER_BYTES..HEADER_BYTES + input_len as usize],
        output_initial: if ioctl::method(code) == ioctl::METHOD_BUFFERED {
            &[]
        } else {
            &packet[HEADER_BYTES + input_len as usize
                ..HEADER_BYTES + input_len as usize + output_capacity as usize]
        },
        output_capacity,
        event,
        output_va: u64_at(packet, OUTPUT_VA_OFF),
        iosb_va: u64_at(packet, IOSB_VA_OFF),
        system_buffer_va: u64_at(packet, SYSTEM_BUFFER_VA_OFF),
        system_buffer_generation: u64_at(packet, SYSTEM_BUFFER_GENERATION_OFF),
        mdl_va: u64_at(packet, MDL_VA_OFF),
        mdl_generation: u64_at(packet, MDL_GENERATION_OFF),
        input_va: u64_at(packet, INPUT_VA_OFF),
        event_body_va: u64_at(packet, EVENT_BODY_VA_OFF),
    })?;
    Ok((code, input_len as usize, output_capacity, event))
}

pub fn decode_request(packet: &[u8]) -> Result<SourceIrpIoctlRequest<'_>, WireError> {
    let (code, input_len, output_capacity, event) = validate_header(packet)?;
    let initial_len = if ioctl::method(code) == ioctl::METHOD_BUFFERED {
        0
    } else {
        output_capacity as usize
    };
    if u64_at(packet, TOKEN_OFF) != 0
        || u64_at(packet, INFORMATION_OFF) != 0
        || u32_at(packet, STATUS_OFF) != 0
        || u32_at(packet, COMPLETED_OFF) != 0
        || u32_at(packet, OUTPUT_LENGTH_OFF) != 0
        || packet[HEADER_BYTES + input_len + initial_len..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(WireError::Malformed);
    }
    let request = SourceIrpIoctlRequest {
        nonce: u64_at(packet, 8),
        source_irp_va: u64_at(packet, 16),
        source_ticket_serial: u64_at(packet, 24),
        native_allocation_generation: u64_at(packet, 32),
        device_object_va: u64_at(packet, 40),
        code,
        input: &packet[HEADER_BYTES..HEADER_BYTES + input_len],
        output_initial: &packet[HEADER_BYTES + input_len..HEADER_BYTES + input_len + initial_len],
        output_capacity,
        event,
        output_va: u64_at(packet, OUTPUT_VA_OFF),
        iosb_va: u64_at(packet, IOSB_VA_OFF),
        system_buffer_va: u64_at(packet, SYSTEM_BUFFER_VA_OFF),
        system_buffer_generation: u64_at(packet, SYSTEM_BUFFER_GENERATION_OFF),
        mdl_va: u64_at(packet, MDL_VA_OFF),
        mdl_generation: u64_at(packet, MDL_GENERATION_OFF),
        input_va: u64_at(packet, INPUT_VA_OFF),
        event_body_va: u64_at(packet, EVENT_BODY_VA_OFF),
    };
    validate(&request)?;
    Ok(request)
}

pub fn publish_pending(packet: &mut [u8], token: u64) -> Result<(), WireError> {
    decode_request(packet)?;
    if token == 0 {
        return Err(WireError::Malformed);
    }
    packet[HEADER_BYTES..].fill(0);
    put_u64(packet, TOKEN_OFF, token);
    put_u32(packet, STATUS_OFF, STATUS_PENDING);
    Ok(())
}

pub fn publish_inline_terminal(
    packet: &mut [u8],
    token: u64,
    status: u32,
    information: u64,
    output: &[u8],
) -> Result<(), WireError> {
    let request = decode_request(packet)?;
    if token == 0
        || status == STATUS_PENDING
        || output.len()
            != completion_output_len(request.code, status, information, request.output_capacity)
    {
        return Err(WireError::Malformed);
    }
    packet[HEADER_BYTES..].fill(0);
    packet[HEADER_BYTES..HEADER_BYTES + output.len()].copy_from_slice(output);
    put_u64(packet, TOKEN_OFF, token);
    put_u64(packet, INFORMATION_OFF, information);
    put_u32(packet, STATUS_OFF, status);
    put_u32(packet, COMPLETED_OFF, 1);
    put_u32(packet, OUTPUT_LENGTH_OFF, output.len() as u32);
    Ok(())
}

pub fn decode_response(packet: &[u8]) -> Result<SourceIrpIoctlResponse<'_>, WireError> {
    let (code, _, output_capacity, _) = validate_header(packet)?;
    let token = u64_at(packet, TOKEN_OFF);
    if token == 0 {
        return Err(WireError::Malformed);
    }
    let status = u32_at(packet, STATUS_OFF);
    let information = u64_at(packet, INFORMATION_OFF);
    let output_len = u32_at(packet, OUTPUT_LENGTH_OFF) as usize;
    match u32_at(packet, COMPLETED_OFF) {
        0 if status == STATUS_PENDING && information == 0 && output_len == 0 => {
            if packet[HEADER_BYTES..].iter().any(|byte| *byte != 0) {
                return Err(WireError::Malformed);
            }
            Ok(SourceIrpIoctlResponse::Pending { token })
        }
        1 if status != STATUS_PENDING
            && output_len == completion_output_len(code, status, information, output_capacity) =>
        {
            if packet[HEADER_BYTES + output_len..]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(WireError::Malformed);
            }
            Ok(SourceIrpIoctlResponse::Inline {
                token,
                status,
                information,
                output: &packet[HEADER_BYTES..HEADER_BYTES + output_len],
            })
        }
        _ => Err(WireError::Malformed),
    }
}

pub fn terminal_packet_len(output_len: usize) -> Result<usize, WireError> {
    if output_len > MAX_BUFFER_BYTES as usize {
        return Err(WireError::LengthMismatch);
    }
    Ok(TERMINAL_HEADER_BYTES + output_len)
}

pub fn terminal_matches_request(
    request: SourceIrpIoctlRequest<'_>,
    handoff: SourceIoctlTerminalHandoff<'_>,
) -> bool {
    request.nonce == handoff.nonce
        && request.source_irp_va == handoff.source_irp_va
        && request.source_ticket_serial == handoff.source_ticket_serial
        && request.native_allocation_generation == handoff.native_allocation_generation
        && request.code == handoff.code
        && request.iosb_va == handoff.iosb_va
        && request.output_va == handoff.output_va
        && request.output_capacity == handoff.output_capacity
}

pub fn encode_terminal_handoff(
    handoff: SourceIoctlTerminalHandoff<'_>,
    packet: &mut [u8],
) -> Result<(), WireError> {
    if packet.len() != terminal_packet_len(handoff.output.len())?
        || handoff.nonce == 0
        || handoff.token == 0
        || handoff.source_irp_va == 0
        || handoff.source_ticket_serial == 0
        || handoff.native_allocation_generation == 0
        || handoff.iosb_va == 0
        || (handoff.output_capacity != 0 && handoff.output_va == 0)
        || handoff.status == STATUS_PENDING
        || handoff.output.len()
            != completion_output_len(
                handoff.code,
                handoff.status,
                handoff.information,
                handoff.output_capacity,
            )
    {
        return Err(WireError::Malformed);
    }
    packet.fill(0);
    put_u32(packet, 0, TERMINAL_KIND);
    put_u32(packet, 4, TERMINAL_VERSION);
    put_u64(packet, 8, handoff.nonce);
    put_u64(packet, 16, handoff.token);
    put_u64(packet, 24, handoff.source_irp_va);
    put_u64(packet, 32, handoff.source_ticket_serial);
    put_u64(packet, 40, handoff.native_allocation_generation);
    put_u32(packet, 48, handoff.code);
    put_u32(packet, 52, handoff.output_capacity);
    put_u64(packet, 56, handoff.iosb_va);
    put_u64(packet, 64, handoff.output_va);
    put_u32(packet, 72, handoff.status);
    put_u32(packet, 76, handoff.output.len() as u32);
    put_u64(packet, 80, handoff.information);
    packet[TERMINAL_HEADER_BYTES..].copy_from_slice(handoff.output);
    Ok(())
}

fn terminal_header(packet: &[u8]) -> Result<SourceIoctlTerminalHandoff<'_>, WireError> {
    if packet.len() < TERMINAL_HEADER_BYTES
        || (u64_at(packet, 96) != 0 && !matches!(u32_at(packet, 88), 3 | 4))
        || u32_at(packet, 0) != TERMINAL_KIND
        || u32_at(packet, 4) != TERMINAL_VERSION
        || u32_at(packet, 76) as usize != packet.len() - TERMINAL_HEADER_BYTES
        || packet[104..TERMINAL_HEADER_BYTES]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(WireError::Malformed);
    }
    let handoff = SourceIoctlTerminalHandoff {
        nonce: u64_at(packet, 8),
        token: u64_at(packet, 16),
        source_irp_va: u64_at(packet, 24),
        source_ticket_serial: u64_at(packet, 32),
        native_allocation_generation: u64_at(packet, 40),
        code: u32_at(packet, 48),
        output_capacity: u32_at(packet, 52),
        iosb_va: u64_at(packet, 56),
        output_va: u64_at(packet, 64),
        status: u32_at(packet, 72),
        information: u64_at(packet, 80),
        output: &packet[TERMINAL_HEADER_BYTES..],
    };
    if packet.len() != terminal_packet_len(handoff.output.len())?
        || handoff.nonce == 0
        || handoff.token == 0
        || handoff.source_irp_va == 0
        || handoff.source_ticket_serial == 0
        || handoff.native_allocation_generation == 0
        || handoff.iosb_va == 0
        || (handoff.output_capacity != 0 && handoff.output_va == 0)
        || handoff.status == STATUS_PENDING
        || handoff.output.len()
            != completion_output_len(
                handoff.code,
                handoff.status,
                handoff.information,
                handoff.output_capacity,
            )
    {
        return Err(WireError::Malformed);
    }
    Ok(handoff)
}

pub fn decode_terminal_handoff(packet: &[u8]) -> Result<SourceIoctlTerminalHandoff<'_>, WireError> {
    let handoff = terminal_header(packet)?;
    if u32_at(packet, 88) != 0 || u32_at(packet, 92) != 0 {
        return Err(WireError::Malformed);
    }
    Ok(handoff)
}

/// A canonical deferred Set reserves this sequence before the origin retires its IRP.
pub fn request_terminal_commit(packet: &mut [u8], signal_sequence: u64) -> Result<(), WireError> {
    publish_terminal_ack(packet, TerminalPublication::CommitRequested)?;
    put_u64(packet, 96, signal_sequence);
    Ok(())
}

pub fn terminal_signal_sequence(packet: &[u8]) -> Result<u64, WireError> {
    terminal_header(packet)?;
    Ok(u64_at(packet, 96))
}

pub fn publish_terminal_ack(
    packet: &mut [u8],
    publication: TerminalPublication,
) -> Result<(), WireError> {
    terminal_header(packet)?;
    let previous = match (u32_at(packet, 88), u32_at(packet, 92)) {
        (0, 0) => None,
        (stage, status) => {
            Some(TerminalPublication::decode(stage, status).ok_or(WireError::Malformed)?)
        }
    };
    if !publication.can_follow(previous) {
        return Err(WireError::Malformed);
    }
    let (stage, status) = publication.words();
    put_u32(packet, 88, stage);
    put_u32(packet, 92, status);
    Ok(())
}

pub fn decode_terminal_ack(packet: &[u8]) -> Result<SourceIoctlTerminalAck<'_>, WireError> {
    let handoff = terminal_header(packet)?;
    let publication = TerminalPublication::decode(u32_at(packet, 88), u32_at(packet, 92))
        .ok_or(WireError::Malformed)?;
    Ok(SourceIoctlTerminalAck {
        handoff,
        publication,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn request<'a>(input: &'a [u8]) -> SourceIrpIoctlRequest<'a> {
        SourceIrpIoctlRequest {
            nonce: 1,
            source_irp_va: 0x1000,
            source_ticket_serial: 2,
            native_allocation_generation: 3,
            device_object_va: 0x2000,
            code: ioctl::ctl_code(0x22, 0x800, ioctl::METHOD_BUFFERED, ioctl::FILE_ANY_ACCESS),
            input,
            output_initial: &[],
            output_capacity: 16,
            event: None,
            output_va: 0x3000,
            iosb_va: 0x4000,
            system_buffer_va: 0x5000,
            system_buffer_generation: 6,
            mdl_va: 0,
            mdl_generation: 0,
            input_va: 0,
            event_body_va: 0,
        }
    }

    #[test]
    fn prepare_commit_and_stopped_discard_do_not_skip_or_replay_phases() {
        let handoff = SourceIoctlTerminalHandoff {
            nonce: 1,
            token: 2,
            source_irp_va: 3,
            source_ticket_serial: 4,
            native_allocation_generation: 5,
            code: 0,
            iosb_va: 6,
            output_va: 0,
            output_capacity: 0,
            status: 0,
            information: 0,
            output: &[],
        };
        let mut packet = [0; TERMINAL_HEADER_BYTES];
        encode_terminal_handoff(handoff, &mut packet).unwrap();
        assert!(publish_terminal_ack(&mut packet, TerminalPublication::Committed).is_err());
        publish_terminal_ack(&mut packet, TerminalPublication::Published).unwrap();
        assert!(publish_terminal_ack(&mut packet, TerminalPublication::Published).is_err());
        request_terminal_commit(&mut packet, 41).unwrap();
        assert_eq!(terminal_signal_sequence(&packet), Ok(41));
        assert_eq!(decode_terminal_ack(&packet).unwrap().handoff, handoff);
        publish_terminal_ack(&mut packet, TerminalPublication::Committed).unwrap();
        assert_eq!(terminal_signal_sequence(&packet), Ok(41));
        assert_eq!(
            decode_terminal_ack(&packet).unwrap().publication,
            TerminalPublication::Committed
        );
        assert!(publish_terminal_ack(&mut packet, TerminalPublication::Committed).is_err());
        encode_terminal_handoff(handoff, &mut packet).unwrap();
        publish_terminal_ack(&mut packet, TerminalPublication::DiscardRequested).unwrap();
        publish_terminal_ack(&mut packet, TerminalPublication::Discarded).unwrap();
        assert_eq!(
            decode_terminal_ack(&packet).unwrap().publication,
            TerminalPublication::Discarded
        );
    }

    #[test]
    fn round_trip_with_and_without_event() {
        for event in [
            None,
            Some(EventIdentity {
                local_id: 4,
                object_slot_plus_one: 5,
                object_generation: 6,
            }),
        ] {
            let mut expected = request(b"abc");
            expected.event = event;
            expected.event_body_va = event.map_or(0, |_| 0x6000);
            let mut packet = [0xff; HEADER_BYTES + 16];
            encode_request(expected, &mut packet).unwrap();
            assert_eq!(decode_request(&packet), Ok(expected));
            assert_eq!(u32_at(&packet, 60), 0);
            assert_eq!(u64_at(&packet, 88), 0);
            assert!(packet[HEADER_BYTES + 3..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn refuses_malformed_identity_or_header() {
        let mut packet = [0; HEADER_BYTES + 16];
        encode_request(request(b""), &mut packet).unwrap();
        for offset in [8, 16, 24, 32, 40] {
            let mut bad = packet;
            bad[offset..offset + 8].fill(0);
            assert_eq!(
                decode_request(&bad),
                Err(WireError::Malformed),
                "offset {offset}"
            );
        }
        for offset in [0, 4, 60, 64, 72, 80, 88, 96, 104, 108, 112, 116, 184] {
            let mut bad = packet;
            bad[offset] ^= 1;
            assert_eq!(
                decode_request(&bad),
                Err(WireError::Malformed),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn bounds_and_exact_length() {
        assert_eq!(
            packet_len(request(b"").code, MAX_BUFFER_BYTES + 1, 0),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(
            packet_len(request(b"").code, 0, MAX_BUFFER_BYTES + 1),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(
            decode_request(&[0; HEADER_BYTES - 1]),
            Err(WireError::BufferTooSmall)
        );
        let mut packet = [0; HEADER_BYTES + 16];
        encode_request(request(b"x"), &mut packet).unwrap();
        assert_eq!(
            decode_request(&packet[..HEADER_BYTES]),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(
            decode_request(&[&packet[..], &[0]].concat()),
            Err(WireError::LengthMismatch)
        );
        packet[HEADER_BYTES + 1] = 1;
        assert_eq!(decode_request(&packet), Err(WireError::Malformed));
    }

    #[test]
    fn pending_clears_input_and_requires_exact_token_state() {
        let mut packet = [0xa5; HEADER_BYTES + 16];
        encode_request(request(b"abc"), &mut packet).unwrap();
        assert_eq!(publish_pending(&mut packet, 0), Err(WireError::Malformed));
        publish_pending(&mut packet, 7).unwrap();
        assert_eq!(
            decode_response(&packet),
            Ok(SourceIrpIoctlResponse::Pending { token: 7 })
        );
        assert_eq!(decode_request(&packet), Err(WireError::Malformed));
        assert!(packet[HEADER_BYTES..].iter().all(|byte| *byte == 0));
        packet[HEADER_BYTES] = 1;
        assert_eq!(decode_response(&packet), Err(WireError::Malformed));
        packet[HEADER_BYTES] = 0;
        put_u64(&mut packet, TOKEN_OFF, 0);
        assert_eq!(decode_response(&packet), Err(WireError::Malformed));
    }

    #[test]
    fn inline_terminal_preserves_information_and_bounds_output() {
        let mut packet = [0xa5; HEADER_BYTES + 16];
        encode_request(request(b"abc"), &mut packet).unwrap();
        assert_eq!(
            publish_inline_terminal(&mut packet, 9, STATUS_PENDING, 0, &[]),
            Err(WireError::Malformed)
        );
        assert_eq!(
            publish_inline_terminal(&mut packet, 9, 0, 2, &[1]),
            Err(WireError::Malformed)
        );
        publish_inline_terminal(&mut packet, 9, 0x8000_0005, 2, &[1, 2]).unwrap();
        assert_eq!(
            decode_response(&packet),
            Ok(SourceIrpIoctlResponse::Inline {
                token: 9,
                status: 0x8000_0005,
                information: 2,
                output: &[1, 2],
            })
        );
        assert!(packet[HEADER_BYTES + 2..].iter().all(|byte| *byte == 0));
        packet[HEADER_BYTES + 2] = 1;
        assert_eq!(decode_response(&packet), Err(WireError::Malformed));
        packet[HEADER_BYTES + 2] = 0;
        put_u32(&mut packet, OUTPUT_LENGTH_OFF, 17);
        assert_eq!(decode_response(&packet), Err(WireError::Malformed));
    }

    #[test]
    fn terminal_errors_and_verify_required_do_not_publish_output() {
        for status in [0xc000_000d, 0x8000_0016] {
            let mut packet = [0; HEADER_BYTES + 16];
            encode_request(request(b"abc"), &mut packet).unwrap();
            assert_eq!(
                publish_inline_terminal(&mut packet, 10, status, 5, &[1]),
                Err(WireError::Malformed)
            );
            publish_inline_terminal(&mut packet, 10, status, 5, &[]).unwrap();
            assert_eq!(
                decode_response(&packet),
                Ok(SourceIrpIoctlResponse::Inline {
                    token: 10,
                    status,
                    information: 5,
                    output: &[],
                })
            );
        }
    }

    #[test]
    fn direct_and_neither_preserve_the_second_buffer_independently_of_information() {
        for method in [
            ioctl::METHOD_IN_DIRECT,
            ioctl::METHOD_OUT_DIRECT,
            ioctl::METHOD_NEITHER,
        ] {
            let seed = [9u8, 8, 7, 6];
            let mut expected = request(b"in");
            expected.code = ioctl::ctl_code(0x22, 0x801, method, ioctl::FILE_ANY_ACCESS);
            expected.output_capacity = seed.len() as u32;
            expected.output_initial = &seed;
            if method == ioctl::METHOD_NEITHER {
                expected.system_buffer_va = 0;
                expected.system_buffer_generation = 0;
                expected.input_va = 0x7000;
            } else {
                expected.mdl_va = 0x8000;
                expected.mdl_generation = 9;
            }
            let mut packet = vec![0; packet_len(expected.code, 2, 4).unwrap()];
            encode_request(expected, &mut packet).unwrap();
            assert_eq!(decode_request(&packet), Ok(expected));
            assert_eq!(
                &packet[HEADER_BYTES..HEADER_BYTES + 6],
                b"in\x09\x08\x07\x06"
            );
            publish_inline_terminal(&mut packet, 17, 0xc000_000d, 0, &seed).unwrap();
            assert_eq!(
                decode_response(&packet),
                Ok(SourceIrpIoctlResponse::Inline {
                    token: 17,
                    status: 0xc000_000d,
                    information: 0,
                    output: &seed,
                })
            );
        }
    }

    #[test]
    fn terminal_ack_binds_origin_and_bounded_output_for_all_methods() {
        for method in [
            ioctl::METHOD_BUFFERED,
            ioctl::METHOD_IN_DIRECT,
            ioctl::METHOD_OUT_DIRECT,
            ioctl::METHOD_NEITHER,
        ] {
            let mut request = request(b"in");
            request.code = ioctl::ctl_code(0x22, 0x801, method, ioctl::FILE_ANY_ACCESS);
            let output = [1u8, 2];
            let handoff = SourceIoctlTerminalHandoff {
                nonce: request.nonce,
                token: 10,
                source_irp_va: request.source_irp_va,
                source_ticket_serial: request.source_ticket_serial,
                native_allocation_generation: request.native_allocation_generation,
                code: request.code,
                iosb_va: request.iosb_va,
                output_va: request.output_va,
                output_capacity: request.output_capacity,
                status: 0,
                information: 2,
                output: if method == ioctl::METHOD_BUFFERED {
                    &output
                } else {
                    &[0; 16]
                },
            };
            let mut packet = vec![0; terminal_packet_len(handoff.output.len()).unwrap()];
            encode_terminal_handoff(handoff, &mut packet).unwrap();
            assert!(terminal_matches_request(request, handoff));
            assert_eq!(decode_terminal_handoff(&packet), Ok(handoff));
            publish_terminal_ack(&mut packet, TerminalPublication::Published).unwrap();
            assert_eq!(
                decode_terminal_ack(&packet),
                Ok(SourceIoctlTerminalAck {
                    handoff,
                    publication: TerminalPublication::Published,
                })
            );
            packet[24] ^= 1;
            assert_ne!(decode_terminal_ack(&packet).unwrap().handoff, handoff);
        }
    }
}
