//! Bounded, pointer-free wire for win32k `ZwDeviceIoControlFile` METHOD_BUFFERED requests.
//!
//! The virtual addresses are untrusted scalar values. The executive must authenticate the
//! provider lane and validate the target ranges before writing output or the IOSB.

use nt_io_abi::ioctl;

pub const HEADER_BYTES: usize = 64;
pub const MAX_BUFFER_BYTES: u32 = 64 * 1024;
pub const MAX_PACKET_BYTES: usize = HEADER_BYTES + MAX_BUFFER_BYTES as usize;
pub const STATUS_PENDING: u32 = 0x103;
const KIND_BUFFERED_IOCTL: u32 = 1;
const KIND_OFF: usize = 0;
const CODE_OFF: usize = 4;
const INPUT_LENGTH_OFF: usize = 8;
const OUTPUT_CAPACITY_OFF: usize = 12;
const OUTPUT_VA_OFF: usize = 16;
const IOSB_VA_OFF: usize = 24;
const TOKEN_OFF: usize = 32;
const INFORMATION_OFF: usize = 40;
const STATUS_OFF: usize = 48;
const COMPLETED_OFF: usize = 52;
const OUTPUT_LENGTH_OFF: usize = 56;
const RESERVED_OFF: usize = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferedIoctlRequest<'a> {
    pub code: u32,
    pub input: &'a [u8],
    pub output_capacity: u32,
    pub output_va: u64,
    pub iosb_va: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferedIoctlResponse<'a> {
    Pending { token: u64 },
    Inline {
        token: u64,
        status: u32,
        information: u64,
        output: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferedIoctlWireError {
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

pub fn packet_len(input_len: u32, output_capacity: u32) -> Result<usize, BufferedIoctlWireError> {
    if input_len > MAX_BUFFER_BYTES || output_capacity > MAX_BUFFER_BYTES {
        return Err(BufferedIoctlWireError::LengthMismatch);
    }
    HEADER_BYTES
        .checked_add(input_len.max(output_capacity) as usize)
        .ok_or(BufferedIoctlWireError::LengthMismatch)
}

fn validate_header(packet: &[u8]) -> Result<(usize, usize), BufferedIoctlWireError> {
    if packet.len() < HEADER_BYTES {
        return Err(BufferedIoctlWireError::BufferTooSmall);
    }
    let input_len = read_u32(packet, INPUT_LENGTH_OFF);
    let output_capacity = read_u32(packet, OUTPUT_CAPACITY_OFF);
    if packet.len() != packet_len(input_len, output_capacity)? {
        return Err(BufferedIoctlWireError::LengthMismatch);
    }
    if read_u32(packet, KIND_OFF) != KIND_BUFFERED_IOCTL
        || ioctl::method(read_u32(packet, CODE_OFF)) != ioctl::METHOD_BUFFERED
        || read_u32(packet, RESERVED_OFF) != 0
        || read_u64(packet, IOSB_VA_OFF) == 0
        || (output_capacity != 0 && read_u64(packet, OUTPUT_VA_OFF) == 0)
    {
        return Err(BufferedIoctlWireError::Malformed);
    }
    Ok((input_len as usize, output_capacity as usize))
}

fn copied_output_len(status: u32, information: u64, capacity: u32) -> usize {
    if status >> 30 == 3 || status == 0x8000_0016 {
        0
    } else {
        information.min(capacity as u64) as usize
    }
}

pub fn encode_request(
    request: BufferedIoctlRequest<'_>,
    packet: &mut [u8],
) -> Result<(), BufferedIoctlWireError> {
    let input_len = u32::try_from(request.input.len())
        .map_err(|_| BufferedIoctlWireError::LengthMismatch)?;
    if packet.len() != packet_len(input_len, request.output_capacity)? {
        return Err(BufferedIoctlWireError::LengthMismatch);
    }
    if ioctl::method(request.code) != ioctl::METHOD_BUFFERED
        || request.iosb_va == 0
        || (request.output_capacity != 0 && request.output_va == 0)
    {
        return Err(BufferedIoctlWireError::Malformed);
    }
    packet.fill(0);
    write_u32(packet, KIND_OFF, KIND_BUFFERED_IOCTL);
    write_u32(packet, CODE_OFF, request.code);
    write_u32(packet, INPUT_LENGTH_OFF, input_len);
    write_u32(packet, OUTPUT_CAPACITY_OFF, request.output_capacity);
    write_u64(packet, OUTPUT_VA_OFF, request.output_va);
    write_u64(packet, IOSB_VA_OFF, request.iosb_va);
    packet[HEADER_BYTES..HEADER_BYTES + request.input.len()].copy_from_slice(request.input);
    Ok(())
}

pub fn decode_request(packet: &[u8]) -> Result<BufferedIoctlRequest<'_>, BufferedIoctlWireError> {
    let (input_len, output_capacity) = validate_header(packet)?;
    if read_u64(packet, TOKEN_OFF) != 0
        || read_u64(packet, INFORMATION_OFF) != 0
        || read_u32(packet, STATUS_OFF) != 0
        || read_u32(packet, COMPLETED_OFF) != 0
        || read_u32(packet, OUTPUT_LENGTH_OFF) != 0
        || packet[HEADER_BYTES + input_len..].iter().any(|byte| *byte != 0)
    {
        return Err(BufferedIoctlWireError::Malformed);
    }
    Ok(BufferedIoctlRequest {
        code: read_u32(packet, CODE_OFF),
        input: &packet[HEADER_BYTES..HEADER_BYTES + input_len],
        output_capacity: output_capacity as u32,
        output_va: read_u64(packet, OUTPUT_VA_OFF),
        iosb_va: read_u64(packet, IOSB_VA_OFF),
    })
}

pub fn publish_pending(packet: &mut [u8], token: u64) -> Result<(), BufferedIoctlWireError> {
    decode_request(packet)?;
    if token == 0 {
        return Err(BufferedIoctlWireError::Malformed);
    }
    packet[HEADER_BYTES..].fill(0);
    write_u64(packet, TOKEN_OFF, token);
    write_u32(packet, STATUS_OFF, STATUS_PENDING);
    Ok(())
}

pub fn publish_inline_terminal(
    packet: &mut [u8],
    token: u64,
    status: u32,
    information: u64,
    output: &[u8],
) -> Result<(), BufferedIoctlWireError> {
    let request = decode_request(packet)?;
    let expected = copied_output_len(status, information, request.output_capacity);
    if token == 0 || status == STATUS_PENDING || output.len() != expected {
        return Err(BufferedIoctlWireError::Malformed);
    }
    packet[HEADER_BYTES..].fill(0);
    packet[HEADER_BYTES..HEADER_BYTES + output.len()].copy_from_slice(output);
    write_u64(packet, TOKEN_OFF, token);
    write_u64(packet, INFORMATION_OFF, information);
    write_u32(packet, STATUS_OFF, status);
    write_u32(packet, COMPLETED_OFF, 1);
    write_u32(packet, OUTPUT_LENGTH_OFF, output.len() as u32);
    Ok(())
}

pub fn decode_response(packet: &[u8]) -> Result<BufferedIoctlResponse<'_>, BufferedIoctlWireError> {
    let (_, output_capacity) = validate_header(packet)?;
    let token = read_u64(packet, TOKEN_OFF);
    if token == 0 {
        return Err(BufferedIoctlWireError::Malformed);
    }
    let status = read_u32(packet, STATUS_OFF);
    let information = read_u64(packet, INFORMATION_OFF);
    let output_len = read_u32(packet, OUTPUT_LENGTH_OFF) as usize;
    match read_u32(packet, COMPLETED_OFF) {
        0 if status == STATUS_PENDING && information == 0 && output_len == 0 => {
            if packet[HEADER_BYTES..].iter().any(|byte| *byte != 0) {
                return Err(BufferedIoctlWireError::Malformed);
            }
            Ok(BufferedIoctlResponse::Pending { token })
        }
        1 if status != STATUS_PENDING
            && output_len == copied_output_len(status, information, output_capacity as u32) => {
            if packet[HEADER_BYTES + output_len..].iter().any(|byte| *byte != 0) {
                return Err(BufferedIoctlWireError::Malformed);
            }
            Ok(BufferedIoctlResponse::Inline {
                token,
                status,
                information,
                output: &packet[HEADER_BYTES..HEADER_BYTES + output_len],
            })
        }
        _ => Err(BufferedIoctlWireError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: u32 = 0x0022_2000;

    fn request<'a>(input: &'a [u8]) -> BufferedIoctlRequest<'a> {
        BufferedIoctlRequest {
            code: CODE,
            input,
            output_capacity: 8,
            output_va: 0x1000,
            iosb_va: 0x2000,
        }
    }

    #[test]
    fn request_and_pending_clear_input_before_publication() {
        let mut packet = [0xa5; HEADER_BYTES + 8];
        let request = request(&[1, 2, 3]);
        encode_request(request, &mut packet).unwrap();
        assert_eq!(decode_request(&packet), Ok(request));
        publish_pending(&mut packet, 7).unwrap();
        assert_eq!(decode_response(&packet), Ok(BufferedIoctlResponse::Pending { token: 7 }));
        assert_eq!(decode_request(&packet), Err(BufferedIoctlWireError::Malformed));
        assert!(packet[HEADER_BYTES..].iter().all(|byte| *byte == 0));
        packet[HEADER_BYTES] = 1;
        assert_eq!(decode_response(&packet), Err(BufferedIoctlWireError::Malformed));
    }

    #[test]
    fn inline_completion_keeps_raw_information_separate_from_output_count() {
        let mut packet = [0xa5; HEADER_BYTES + 8];
        encode_request(request(&[1, 2, 3]), &mut packet).unwrap();
        publish_inline_terminal(&mut packet, 8, 0x8000_0005, 2, &[4, 5]).unwrap();
        assert_eq!(decode_response(&packet), Ok(BufferedIoctlResponse::Inline {
            token: 8,
            status: 0x8000_0005,
            information: 2,
            output: &[4, 5],
        }));
        packet[HEADER_BYTES + 2] = 9;
        assert_eq!(decode_response(&packet), Err(BufferedIoctlWireError::Malformed));
    }

    #[test]
    fn rejects_unbounded_and_non_buffered_requests() {
        assert_eq!(packet_len(MAX_BUFFER_BYTES + 1, 0), Err(BufferedIoctlWireError::LengthMismatch));
        assert_eq!(packet_len(0, MAX_BUFFER_BYTES + 1), Err(BufferedIoctlWireError::LengthMismatch));
        let mut packet = [0; HEADER_BYTES + 8];
        let mut bad = request(&[1, 2, 3]);
        bad.code |= 3;
        assert_eq!(encode_request(bad, &mut packet), Err(BufferedIoctlWireError::Malformed));
        bad = request(&[1, 2, 3]);
        bad.iosb_va = 0;
        assert_eq!(encode_request(bad, &mut packet), Err(BufferedIoctlWireError::Malformed));
        encode_request(request(&[1, 2, 3]), &mut packet).unwrap();
        packet[RESERVED_OFF] = 1;
        assert_eq!(decode_request(&packet), Err(BufferedIoctlWireError::Malformed));
        packet[RESERVED_OFF] = 0;
        packet[HEADER_BYTES + 3] = 1;
        assert_eq!(decode_request(&packet), Err(BufferedIoctlWireError::Malformed));
    }

    #[test]
    fn rejects_bad_response_token_state_and_output_bounds() {
        let mut packet = [0; HEADER_BYTES + 8];
        encode_request(request(&[1]), &mut packet).unwrap();
        assert_eq!(publish_pending(&mut packet, 0), Err(BufferedIoctlWireError::Malformed));
        assert_eq!(publish_inline_terminal(&mut packet, 1, STATUS_PENDING, 0, &[]), Err(BufferedIoctlWireError::Malformed));
        assert_eq!(publish_inline_terminal(&mut packet, 1, 0, 9, &[0; 9]), Err(BufferedIoctlWireError::Malformed));
        assert_eq!(publish_inline_terminal(&mut packet, 1, 0, 0, &[1]), Err(BufferedIoctlWireError::Malformed));
        publish_inline_terminal(&mut packet, 1, 0, 1, &[1]).unwrap();
        write_u32(&mut packet, OUTPUT_LENGTH_OFF, 9);
        assert_eq!(decode_response(&packet), Err(BufferedIoctlWireError::Malformed));
        write_u32(&mut packet, OUTPUT_LENGTH_OFF, 1);
        write_u64(&mut packet, TOKEN_OFF, 0);
        assert_eq!(decode_response(&packet), Err(BufferedIoctlWireError::Malformed));
    }
}
