//! Bounded, pointer-free wire for a win32k `ZwReadFile` request.
//!
//! The virtual addresses are untrusted scalar values. The executive must authenticate the
//! provider's physical lane and validate/pin both target ranges before using either address.

use crate::ReadWriteParameters;

pub const HEADER_BYTES: usize = 64;
pub const MAX_READ_BYTES: u32 = 64 * 1024;
pub const STATUS_PENDING: u32 = 0x103;
const KIND_READ: u32 = 1;
const KIND_OFF: usize = 0;
const RESERVED_OFF: usize = 4;
const OFFSET_OFF: usize = 8;
const KEY_OFF: usize = 16;
const LENGTH_OFF: usize = 20;
const OUTPUT_VA_OFF: usize = 24;
const IOSB_VA_OFF: usize = 32;
const TOKEN_OFF: usize = 40;
const COMPLETED_OFF: usize = 48;
const STATUS_OFF: usize = 52;
const INFORMATION_OFF: usize = 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsyncReadRequest {
    pub parameters: ReadWriteParameters,
    pub output_va: u64,
    pub iosb_va: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncReadResponse<'a> {
    Pending { token: u64 },
    Inline {
        token: u64,
        status: u32,
        information: u64,
        bytes: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncReadWireError {
    BufferTooSmall,
    LengthMismatch,
    Malformed,
}

fn read_u32(packet: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(packet[offset..offset + 4].try_into().unwrap())
}

fn read_u64(packet: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(packet[offset..offset + 8].try_into().unwrap())
}

fn write_u32(packet: &mut [u8], offset: usize, value: u32) {
    packet[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(packet: &mut [u8], offset: usize, value: u64) {
    packet[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn packet_len(length: u32) -> Result<usize, AsyncReadWireError> {
    if length > MAX_READ_BYTES {
        return Err(AsyncReadWireError::LengthMismatch);
    }
    HEADER_BYTES
        .checked_add(length as usize)
        .ok_or(AsyncReadWireError::LengthMismatch)
}

fn validate_header(packet: &[u8]) -> Result<u32, AsyncReadWireError> {
    if packet.len() < HEADER_BYTES {
        return Err(AsyncReadWireError::BufferTooSmall);
    }
    let length = read_u32(packet, LENGTH_OFF);
    if packet.len() != packet_len(length)? {
        return Err(AsyncReadWireError::LengthMismatch);
    }
    if read_u32(packet, KIND_OFF) != KIND_READ
        || read_u32(packet, RESERVED_OFF) != 0
        || (read_u64(packet, OFFSET_OFF) as i64) < 0
        || read_u64(packet, IOSB_VA_OFF) == 0
        || (length != 0 && read_u64(packet, OUTPUT_VA_OFF) == 0)
    {
        return Err(AsyncReadWireError::Malformed);
    }
    Ok(length)
}

pub fn encode_request(
    request: AsyncReadRequest,
    packet: &mut [u8],
) -> Result<(), AsyncReadWireError> {
    if packet.len() != packet_len(request.parameters.length)? {
        return Err(AsyncReadWireError::LengthMismatch);
    }
    packet.fill(0);
    write_u32(packet, KIND_OFF, KIND_READ);
    write_u64(packet, OFFSET_OFF, request.parameters.offset);
    write_u32(packet, KEY_OFF, request.parameters.key);
    write_u32(packet, LENGTH_OFF, request.parameters.length);
    write_u64(packet, OUTPUT_VA_OFF, request.output_va);
    write_u64(packet, IOSB_VA_OFF, request.iosb_va);
    validate_header(packet)?;
    Ok(())
}

pub fn decode_request(packet: &[u8]) -> Result<AsyncReadRequest, AsyncReadWireError> {
    let length = validate_header(packet)?;
    if read_u64(packet, TOKEN_OFF) != 0
        || read_u32(packet, COMPLETED_OFF) != 0
        || read_u32(packet, STATUS_OFF) != 0
        || read_u64(packet, INFORMATION_OFF) != 0
        || packet[HEADER_BYTES..].iter().any(|byte| *byte != 0)
    {
        return Err(AsyncReadWireError::Malformed);
    }
    Ok(AsyncReadRequest {
        parameters: ReadWriteParameters {
            length,
            key: read_u32(packet, KEY_OFF),
            offset: read_u64(packet, OFFSET_OFF),
        },
        output_va: read_u64(packet, OUTPUT_VA_OFF),
        iosb_va: read_u64(packet, IOSB_VA_OFF),
    })
}

pub fn publish_pending(packet: &mut [u8], token: u64) -> Result<(), AsyncReadWireError> {
    decode_request(packet)?;
    if token == 0 {
        return Err(AsyncReadWireError::Malformed);
    }
    write_u64(packet, TOKEN_OFF, token);
    write_u32(packet, STATUS_OFF, STATUS_PENDING);
    Ok(())
}

pub fn publish_inline_terminal(
    packet: &mut [u8],
    token: u64,
    status: u32,
    output: &[u8],
) -> Result<(), AsyncReadWireError> {
    let request = decode_request(packet)?;
    if token == 0 || status == STATUS_PENDING || output.len() > request.parameters.length as usize {
        return Err(AsyncReadWireError::Malformed);
    }
    packet[HEADER_BYTES..HEADER_BYTES + output.len()].copy_from_slice(output);
    write_u64(packet, TOKEN_OFF, token);
    write_u32(packet, STATUS_OFF, status);
    write_u64(packet, INFORMATION_OFF, output.len() as u64);
    write_u32(packet, COMPLETED_OFF, 1);
    Ok(())
}

pub fn decode_response(packet: &[u8]) -> Result<AsyncReadResponse<'_>, AsyncReadWireError> {
    let length = validate_header(packet)? as usize;
    let token = read_u64(packet, TOKEN_OFF);
    if token == 0 {
        return Err(AsyncReadWireError::Malformed);
    }
    let status = read_u32(packet, STATUS_OFF);
    let information = read_u64(packet, INFORMATION_OFF);
    match read_u32(packet, COMPLETED_OFF) {
        0 if status == STATUS_PENDING && information == 0 => {
            if packet[HEADER_BYTES..].iter().any(|byte| *byte != 0) {
                return Err(AsyncReadWireError::Malformed);
            }
            Ok(AsyncReadResponse::Pending { token })
        }
        1 if status != STATUS_PENDING && information <= length as u64 => {
            let valid = information as usize;
            if packet[HEADER_BYTES + valid..].iter().any(|byte| *byte != 0) {
                return Err(AsyncReadWireError::Malformed);
            }
            Ok(AsyncReadResponse::Inline {
                token,
                status,
                information,
                bytes: &packet[HEADER_BYTES..HEADER_BYTES + valid],
            })
        }
        _ => Err(AsyncReadWireError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AsyncReadRequest {
        AsyncReadRequest {
            parameters: ReadWriteParameters { length: 4, key: 7, offset: 12 },
            output_va: 0x1000,
            iosb_va: 0x2000,
        }
    }

    #[test]
    fn pending_and_inline_responses_are_distinct() {
        let mut pending = [0xa5; HEADER_BYTES + 4];
        encode_request(request(), &mut pending).unwrap();
        assert_eq!(decode_request(&pending), Ok(request()));
        publish_pending(&mut pending, 17).unwrap();
        assert_eq!(decode_response(&pending), Ok(AsyncReadResponse::Pending { token: 17 }));
        assert_eq!(decode_request(&pending), Err(AsyncReadWireError::Malformed));

        let mut inline = [0xa5; HEADER_BYTES + 4];
        encode_request(request(), &mut inline).unwrap();
        publish_inline_terminal(&mut inline, 18, 0, &[1, 2]).unwrap();
        assert_eq!(decode_response(&inline), Ok(AsyncReadResponse::Inline {
            token: 18, status: 0, information: 2, bytes: &[1, 2],
        }));
    }

    #[test]
    fn request_refuses_bad_length_offset_addresses_and_dirty_payload() {
        assert_eq!(packet_len(MAX_READ_BYTES + 1), Err(AsyncReadWireError::LengthMismatch));
        let mut packet = [0; HEADER_BYTES + 4];
        let mut input = request();
        input.parameters.offset = u64::MAX;
        assert_eq!(encode_request(input, &mut packet), Err(AsyncReadWireError::Malformed));
        input = request();
        input.iosb_va = 0;
        assert_eq!(encode_request(input, &mut packet), Err(AsyncReadWireError::Malformed));
        encode_request(request(), &mut packet).unwrap();
        packet[HEADER_BYTES] = 1;
        assert_eq!(decode_request(&packet), Err(AsyncReadWireError::Malformed));
        packet[HEADER_BYTES] = 0;
        packet[RESERVED_OFF] = 1;
        assert_eq!(decode_request(&packet), Err(AsyncReadWireError::Malformed));
    }

    #[test]
    fn response_refuses_zero_token_and_corrupt_shape() {
        let mut packet = [0; HEADER_BYTES + 4];
        encode_request(request(), &mut packet).unwrap();
        assert_eq!(publish_pending(&mut packet, 0), Err(AsyncReadWireError::Malformed));
        assert_eq!(publish_inline_terminal(&mut packet, 1, STATUS_PENDING, &[]), Err(AsyncReadWireError::Malformed));
        publish_pending(&mut packet, 1).unwrap();
        packet[HEADER_BYTES] = 1;
        assert_eq!(decode_response(&packet), Err(AsyncReadWireError::Malformed));

        encode_request(request(), &mut packet).unwrap();
        publish_inline_terminal(&mut packet, 2, 0, &[1]).unwrap();
        packet[HEADER_BYTES + 1] = 9;
        assert_eq!(decode_response(&packet), Err(AsyncReadWireError::Malformed));
        packet[HEADER_BYTES + 1] = 0;
        write_u64(&mut packet, INFORMATION_OFF, 5);
        assert_eq!(decode_response(&packet), Err(AsyncReadWireError::Malformed));
    }
}
