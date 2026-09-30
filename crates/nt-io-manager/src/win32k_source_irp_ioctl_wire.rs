//! Bounded round-trip wire for win32k file-less, kernel-built METHOD_BUFFERED IRPs.
//!
//! Every identity here is correlation data. The receiver must derive authority
//! from its physical provider lane and revalidate the live source IRP, device,
//! and optional Event before dispatch.

use nt_io_abi::ioctl;

pub const HEADER_BYTES: usize = 128;
pub const MAX_BUFFER_BYTES: u32 = 64 * 1024;
pub const MAX_PACKET_BYTES: usize = HEADER_BYTES + MAX_BUFFER_BYTES as usize;
pub const STATUS_PENDING: u32 = 0x103;
const KIND: u32 = 1;
const VERSION: u32 = 2;
const TOKEN_OFF: usize = 88;
const INFORMATION_OFF: usize = 96;
const STATUS_OFF: usize = 104;
const COMPLETED_OFF: usize = 108;
const OUTPUT_LENGTH_OFF: usize = 112;

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
    pub output_capacity: u32,
    pub event: Option<EventIdentity>,
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

pub fn packet_len(input_len: u32, output_capacity: u32) -> Result<usize, WireError> {
    if input_len > MAX_BUFFER_BYTES || output_capacity > MAX_BUFFER_BYTES {
        return Err(WireError::LengthMismatch);
    }
    Ok(HEADER_BYTES + input_len.max(output_capacity) as usize)
}

fn copied_output_len(status: u32, information: u64, capacity: u32) -> usize {
    if status >> 30 == 3 || status == 0x8000_0016 {
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
        || ioctl::method(request.code) != ioctl::METHOD_BUFFERED
        || request.event.is_some_and(|event| {
            event.local_id == 0 || event.object_slot_plus_one == 0 || event.object_generation == 0
        })
    {
        return Err(WireError::Malformed);
    }
    Ok(())
}

pub fn encode_request(
    request: SourceIrpIoctlRequest<'_>,
    packet: &mut [u8],
) -> Result<(), WireError> {
    let input_len = u32::try_from(request.input.len()).map_err(|_| WireError::LengthMismatch)?;
    if packet.len() != packet_len(input_len, request.output_capacity)? {
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
    packet[HEADER_BYTES..HEADER_BYTES + request.input.len()].copy_from_slice(request.input);
    Ok(())
}

fn validate_header(packet: &[u8]) -> Result<(usize, u32, Option<EventIdentity>), WireError> {
    if packet.len() < HEADER_BYTES {
        return Err(WireError::BufferTooSmall);
    }
    let input_len = u32_at(packet, 52);
    let output_capacity = u32_at(packet, 56);
    if packet.len() != packet_len(input_len, output_capacity)? {
        return Err(WireError::LengthMismatch);
    }
    if u32_at(packet, 0) != KIND
        || u32_at(packet, 4) != VERSION
        || u32_at(packet, 60) != 0
        || packet[116..128].iter().any(|byte| *byte != 0)
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
        code: u32_at(packet, 48),
        input: &[],
        output_capacity,
        event,
    })?;
    Ok((input_len as usize, output_capacity, event))
}

pub fn decode_request(packet: &[u8]) -> Result<SourceIrpIoctlRequest<'_>, WireError> {
    let (input_len, output_capacity, event) = validate_header(packet)?;
    if u64_at(packet, TOKEN_OFF) != 0
        || u64_at(packet, INFORMATION_OFF) != 0
        || u32_at(packet, STATUS_OFF) != 0
        || u32_at(packet, COMPLETED_OFF) != 0
        || u32_at(packet, OUTPUT_LENGTH_OFF) != 0
        || packet[HEADER_BYTES + input_len..]
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
        code: u32_at(packet, 48),
        input: &packet[HEADER_BYTES..HEADER_BYTES + input_len],
        output_capacity,
        event,
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
        || output.len() != copied_output_len(status, information, request.output_capacity)
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
    let (_, output_capacity, _) = validate_header(packet)?;
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
            && output_len == copied_output_len(status, information, output_capacity) =>
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>(input: &'a [u8]) -> SourceIrpIoctlRequest<'a> {
        SourceIrpIoctlRequest {
            nonce: 1,
            source_irp_va: 0x1000,
            source_ticket_serial: 2,
            native_allocation_generation: 3,
            device_object_va: 0x2000,
            code: ioctl::ctl_code(0x22, 0x800, ioctl::METHOD_BUFFERED, ioctl::FILE_ANY_ACCESS),
            input,
            output_capacity: 16,
            event: None,
        }
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
        for offset in [0, 4, 60, 64, 72, 80, 88, 96, 104, 108, 112, 116, 120] {
            let mut bad = packet;
            bad[offset] ^= 1;
            assert_eq!(
                decode_request(&bad),
                Err(WireError::Malformed),
                "offset {offset}"
            );
        }
        let mut bad = packet;
        bad[48] |= 1;
        assert_eq!(decode_request(&bad), Err(WireError::Malformed));
    }

    #[test]
    fn bounds_and_exact_length() {
        assert_eq!(
            packet_len(MAX_BUFFER_BYTES + 1, 0),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(
            packet_len(0, MAX_BUFFER_BYTES + 1),
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
}
