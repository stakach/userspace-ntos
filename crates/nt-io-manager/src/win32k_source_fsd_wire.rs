//! Bounded correlation wire for file-less win32k READ/WRITE source IRPs.

use crate::win32k_source_irp_ioctl_wire::EventIdentity;
use nt_io_abi::major;

pub const HEADER_BYTES: usize = 128;
pub const MAX_BUFFER_BYTES: u32 = 64 * 1024;
pub const MAX_PACKET_BYTES: usize = HEADER_BYTES + MAX_BUFFER_BYTES as usize;
pub const STATUS_PENDING: u32 = 0x103;
pub const BUFFERED: u32 = 0;
pub const DIRECT: u32 = 1;
pub const NEITHER: u32 = 2;
const KIND: u32 = 3;
const VERSION: u32 = 1;
const TOKEN_OFF: usize = 96;
const INFORMATION_OFF: usize = 104;
const STATUS_OFF: usize = 112;
const COMPLETED_OFF: usize = 116;
const OUTPUT_LENGTH_OFF: usize = 120;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceFsdRequest<'a> {
    pub nonce: u64,
    pub source_irp_va: u64,
    pub source_ticket_serial: u64,
    pub native_allocation_generation: u64,
    pub device_object_va: u64,
    pub major: u8,
    pub transfer_mode: u32,
    pub byte_offset: u64,
    pub input: &'a [u8],
    pub output_initial: &'a [u8],
    pub output_capacity: u32,
    pub event: Option<EventIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceFsdResponse<'a> {
    Pending { token: u64 },
    Inline { token: u64, status: u32, information: u64, output: &'a [u8] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
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

fn payload_len(request: SourceFsdRequest<'_>) -> Result<usize, WireError> {
    if request.input.len() > MAX_BUFFER_BYTES as usize
        || request.output_capacity > MAX_BUFFER_BYTES
        || request.output_initial.len() > MAX_BUFFER_BYTES as usize
    {
        return Err(WireError::LengthMismatch);
    }
    let read = request.major == major::IRP_MJ_READ;
    let write = request.major == major::IRP_MJ_WRITE;
    if request.nonce == 0
        || request.source_irp_va == 0
        || request.source_ticket_serial == 0
        || request.native_allocation_generation == 0
        || request.device_object_va == 0
        || !matches!(request.transfer_mode, BUFFERED | DIRECT | NEITHER)
        || (!read && !write)
        || (read && (!request.input.is_empty()
            || request.output_initial.len() != if request.transfer_mode == BUFFERED { 0 } else { request.output_capacity as usize }))
        || (write && (request.output_capacity != 0 || !request.output_initial.is_empty()))
        || request.event.is_some_and(|event| {
            event.local_id == 0 || event.object_slot_plus_one == 0 || event.object_generation == 0
        })
    {
        return Err(WireError::Malformed);
    }
    request.input.len().checked_add(request.output_initial.len())
        .map(|length| length.max(request.output_capacity as usize))
        .filter(|length| *length <= MAX_BUFFER_BYTES as usize)
        .ok_or(WireError::LengthMismatch)
}

pub fn packet_len(request: SourceFsdRequest<'_>) -> Result<usize, WireError> {
    Ok(HEADER_BYTES + payload_len(request)?)
}

pub fn completion_output_len(request: SourceFsdRequest<'_>, information: u64) -> usize {
    if request.major == major::IRP_MJ_READ {
        information.min(request.output_capacity as u64) as usize
    } else {
        0
    }
}

pub fn valid_information(request: SourceFsdRequest<'_>, information: u64) -> bool {
    if request.major == major::IRP_MJ_READ {
        information <= u64::from(request.output_capacity)
    } else {
        information <= request.input.len() as u64
    }
}

pub fn encode_request(request: SourceFsdRequest<'_>, packet: &mut [u8]) -> Result<(), WireError> {
    if packet.len() != packet_len(request)? {
        return Err(WireError::LengthMismatch);
    }
    packet.fill(0);
    put_u32(packet, 0, KIND);
    put_u32(packet, 4, VERSION);
    put_u64(packet, 8, request.nonce);
    put_u64(packet, 16, request.source_irp_va);
    put_u64(packet, 24, request.source_ticket_serial);
    put_u64(packet, 32, request.native_allocation_generation);
    put_u64(packet, 40, request.device_object_va);
    put_u32(packet, 48, request.major as u32);
    put_u32(packet, 52, request.transfer_mode);
    put_u64(packet, 56, request.byte_offset);
    put_u32(packet, 64, request.input.len() as u32);
    put_u32(packet, 68, request.output_capacity);
    if let Some(event) = request.event {
        put_u64(packet, 72, event.local_id);
        put_u64(packet, 80, event.object_slot_plus_one);
        put_u64(packet, 88, event.object_generation);
    }
    packet[HEADER_BYTES..HEADER_BYTES + request.input.len()].copy_from_slice(request.input);
    let start = HEADER_BYTES + request.input.len();
    packet[start..start + request.output_initial.len()].copy_from_slice(request.output_initial);
    Ok(())
}

fn header(packet: &[u8]) -> Result<SourceFsdRequest<'_>, WireError> {
    if packet.len() < HEADER_BYTES {
        return Err(WireError::LengthMismatch);
    }
    let major = u32_at(packet, 48);
    let mode = u32_at(packet, 52);
    let input_len = u32_at(packet, 64) as usize;
    let capacity = u32_at(packet, 68);
    let initial_len = if major == nt_io_abi::major::IRP_MJ_READ as u32 && mode != BUFFERED {
        capacity as usize
    } else { 0 };
    let request_bytes = input_len.checked_add(initial_len).ok_or(WireError::LengthMismatch)?;
    let expected = HEADER_BYTES.checked_add(request_bytes.max(capacity as usize))
        .ok_or(WireError::LengthMismatch)?;
    if packet.len() != expected || major > u8::MAX as u32 {
        return Err(WireError::LengthMismatch);
    }
    if u32_at(packet, 0) != KIND || u32_at(packet, 4) != VERSION
        || u32_at(packet, 124) != 0
    {
        return Err(WireError::Malformed);
    }
    let event = match (u64_at(packet, 72), u64_at(packet, 80), u64_at(packet, 88)) {
        (0, 0, 0) => None,
        (local_id, object_slot_plus_one, object_generation) => Some(EventIdentity {
            local_id, object_slot_plus_one, object_generation,
        }),
    };
    let request = SourceFsdRequest {
        nonce: u64_at(packet, 8),
        source_irp_va: u64_at(packet, 16),
        source_ticket_serial: u64_at(packet, 24),
        native_allocation_generation: u64_at(packet, 32),
        device_object_va: u64_at(packet, 40),
        major: major as u8,
        transfer_mode: mode,
        byte_offset: u64_at(packet, 56),
        input: &packet[HEADER_BYTES..HEADER_BYTES + input_len],
        output_initial: &packet[HEADER_BYTES + input_len..HEADER_BYTES + request_bytes],
        output_capacity: capacity,
        event,
    };
    payload_len(request)?;
    Ok(request)
}

pub fn decode_request(packet: &[u8]) -> Result<SourceFsdRequest<'_>, WireError> {
    let request = header(packet)?;
    if u64_at(packet, TOKEN_OFF) != 0 || u64_at(packet, INFORMATION_OFF) != 0
        || u32_at(packet, STATUS_OFF) != 0 || u32_at(packet, COMPLETED_OFF) != 0
        || u32_at(packet, OUTPUT_LENGTH_OFF) != 0
        || packet[HEADER_BYTES + request.input.len() + request.output_initial.len()..]
            .iter().any(|byte| *byte != 0)
    {
        return Err(WireError::Malformed);
    }
    Ok(request)
}

pub fn publish_pending(packet: &mut [u8], token: u64) -> Result<(), WireError> {
    decode_request(packet)?;
    if token == 0 { return Err(WireError::Malformed); }
    packet[HEADER_BYTES..].fill(0);
    put_u64(packet, TOKEN_OFF, token);
    put_u32(packet, STATUS_OFF, STATUS_PENDING);
    Ok(())
}

pub fn publish_inline_terminal(
    packet: &mut [u8], token: u64, status: u32, information: u64, output: &[u8],
) -> Result<(), WireError> {
    let request = decode_request(packet)?;
    if token == 0 || status == STATUS_PENDING
        || !valid_information(request, information)
        || output.len() != completion_output_len(request, information)
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

pub fn decode_response(packet: &[u8]) -> Result<SourceFsdResponse<'_>, WireError> {
    let request = header(packet)?;
    let token = u64_at(packet, TOKEN_OFF);
    let status = u32_at(packet, STATUS_OFF);
    let information = u64_at(packet, INFORMATION_OFF);
    let length = u32_at(packet, OUTPUT_LENGTH_OFF) as usize;
    if token == 0 { return Err(WireError::Malformed); }
    match u32_at(packet, COMPLETED_OFF) {
        0 if status == STATUS_PENDING && information == 0 && length == 0
            && packet[HEADER_BYTES..].iter().all(|byte| *byte == 0) =>
        {
            Ok(SourceFsdResponse::Pending { token })
        }
        1 if status != STATUS_PENDING && valid_information(request, information)
            && length == completion_output_len(request, information)
            && packet[HEADER_BYTES + length..].iter().all(|byte| *byte == 0) =>
        {
            Ok(SourceFsdResponse::Inline {
                token, status, information,
                output: &packet[HEADER_BYTES..HEADER_BYTES + length],
            })
        }
        _ => Err(WireError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn request<'a>(major: u8, mode: u32, input: &'a [u8], initial: &'a [u8], capacity: u32)
        -> SourceFsdRequest<'a>
    {
        SourceFsdRequest {
            nonce: 1, source_irp_va: 0x1000, source_ticket_serial: 2,
            native_allocation_generation: 3, device_object_va: 0x2000,
            major, transfer_mode: mode, byte_offset: 44,
            input, output_initial: initial, output_capacity: capacity, event: None,
        }
    }

    #[test]
    fn read_modes_preserve_initial_only_when_driver_can_see_it() {
        for mode in [BUFFERED, DIRECT, NEITHER] {
            let initial: &[u8] = if mode == BUFFERED { &[] } else { &[9, 8, 7, 6] };
            let expected = request(major::IRP_MJ_READ, mode, &[], initial, 4);
            let mut packet = vec![0; packet_len(expected).unwrap()];
            assert_eq!(packet.len(), HEADER_BYTES + 4);
            encode_request(expected, &mut packet).unwrap();
            assert_eq!(decode_request(&packet), Ok(expected));
            publish_inline_terminal(&mut packet, 5, 0, 2, &[1, 2]).unwrap();
            assert_eq!(decode_response(&packet), Ok(SourceFsdResponse::Inline {
                token: 5, status: 0, information: 2, output: &[1, 2],
            }));
        }
    }

    #[test]
    fn write_has_input_and_no_output() {
        let expected = request(major::IRP_MJ_WRITE, DIRECT, &[4, 3], &[], 0);
        let mut packet = vec![0; packet_len(expected).unwrap()];
        encode_request(expected, &mut packet).unwrap();
        assert_eq!(decode_request(&packet), Ok(expected));
        publish_pending(&mut packet, 6).unwrap();
        assert_eq!(decode_response(&packet), Ok(SourceFsdResponse::Pending { token: 6 }));
    }

    #[test]
    fn rejects_information_beyond_requested_transfer() {
        let read = request(major::IRP_MJ_READ, BUFFERED, &[], &[], 4);
        let mut packet = vec![0; packet_len(read).unwrap()];
        encode_request(read, &mut packet).unwrap();
        assert_eq!(publish_inline_terminal(&mut packet, 7, 0, 5, &[0; 4]), Err(WireError::Malformed));
        let write = request(major::IRP_MJ_WRITE, BUFFERED, &[1, 2], &[], 0);
        let mut packet = vec![0; packet_len(write).unwrap()];
        encode_request(write, &mut packet).unwrap();
        assert_eq!(publish_inline_terminal(&mut packet, 8, 0, 3, &[]), Err(WireError::Malformed));
    }
}
