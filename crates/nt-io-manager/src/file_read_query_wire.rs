//! Pointer-free packet shared by hosted kernel File read and information-query callers.

use crate::{query_information_contract, ReadWriteParameters};

pub const HEADER_BYTES: usize = 40;
pub const KIND_READ: u32 = 1;
pub const KIND_QUERY: u32 = 2;

const KIND_OFF: usize = 0;
const CODE_OFF: usize = 4;
const OFFSET_OFF: usize = 8;
const KEY_OFF: usize = 16;
const LENGTH_OFF: usize = 20;
const COMPLETED_OFF: usize = 24;
const STATUS_OFF: usize = 28;
const INFORMATION_OFF: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileReadQueryRequest {
    Read(ReadWriteParameters),
    Query { class: u32, length: u32 },
}

impl FileReadQueryRequest {
    pub const fn output_len(self) -> u32 {
        match self {
            Self::Read(parameters) => parameters.length,
            Self::Query { length, .. } => length,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileReadQueryWireError {
    Malformed,
    InvalidClass,
    LengthMismatch,
    BufferTooSmall,
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

pub fn packet_len(length: u32) -> Result<usize, FileReadQueryWireError> {
    HEADER_BYTES
        .checked_add(length as usize)
        .ok_or(FileReadQueryWireError::LengthMismatch)
}

fn validate_request(request: FileReadQueryRequest) -> Result<(), FileReadQueryWireError> {
    match request {
        FileReadQueryRequest::Read(parameters) if (parameters.offset as i64) >= 0 => Ok(()),
        FileReadQueryRequest::Read(_) => Err(FileReadQueryWireError::Malformed),
        FileReadQueryRequest::Query { class, length } => {
            let contract = query_information_contract(class)
                .ok_or(FileReadQueryWireError::InvalidClass)?;
            if (length as usize) < contract.minimum_length() {
                return Err(FileReadQueryWireError::LengthMismatch);
            }
            Ok(())
        }
    }
}

/// Initialize the complete header before a component publishes the packet through IPC.
pub fn encode_request(
    request: FileReadQueryRequest,
    packet: &mut [u8],
) -> Result<(), FileReadQueryWireError> {
    validate_request(request)?;
    if packet.len() != packet_len(request.output_len())? {
        return Err(FileReadQueryWireError::BufferTooSmall);
    }
    packet[..HEADER_BYTES].fill(0);
    match request {
        FileReadQueryRequest::Read(parameters) => {
            write_u32(packet, KIND_OFF, KIND_READ);
            write_u32(packet, CODE_OFF, parameters.length);
            write_u64(packet, OFFSET_OFF, parameters.offset);
            write_u32(packet, KEY_OFF, parameters.key);
        }
        FileReadQueryRequest::Query { class, .. } => {
            write_u32(packet, KIND_OFF, KIND_QUERY);
            write_u32(packet, CODE_OFF, class);
        }
    }
    write_u32(packet, LENGTH_OFF, request.output_len());
    Ok(())
}

pub fn decode_request(packet: &[u8]) -> Result<FileReadQueryRequest, FileReadQueryWireError> {
    if packet.len() < HEADER_BYTES {
        return Err(FileReadQueryWireError::BufferTooSmall);
    }
    let length = read_u32(packet, LENGTH_OFF);
    if packet.len() != packet_len(length)?
        || read_u32(packet, COMPLETED_OFF) != 0
        || read_u32(packet, STATUS_OFF) != 0
        || read_u64(packet, INFORMATION_OFF) != 0
    {
        return Err(FileReadQueryWireError::Malformed);
    }
    let code = read_u32(packet, CODE_OFF);
    let offset = read_u64(packet, OFFSET_OFF);
    let key = read_u32(packet, KEY_OFF);
    let request = match read_u32(packet, KIND_OFF) {
        KIND_READ if code == length => FileReadQueryRequest::Read(ReadWriteParameters {
            length,
            key,
            offset,
        }),
        KIND_QUERY if offset == 0 && key == 0 => FileReadQueryRequest::Query {
            class: code,
            length,
        },
        _ => return Err(FileReadQueryWireError::Malformed),
    };
    validate_request(request)?;
    Ok(request)
}

/// The provider may complete with a failure or STATUS_PENDING. The caller interprets the status;
/// this function only publishes exact bytes and the matching IOSB payload.
pub fn publish_completion(
    packet: &mut [u8],
    output: &[u8],
    status: u32,
    information: u64,
) -> Result<(), FileReadQueryWireError> {
    let request = decode_request(packet)?;
    if output.len() != request.output_len() as usize {
        return Err(FileReadQueryWireError::LengthMismatch);
    }
    packet[HEADER_BYTES..].copy_from_slice(output);
    write_u32(packet, STATUS_OFF, status);
    write_u64(packet, INFORMATION_OFF, information);
    write_u32(packet, COMPLETED_OFF, 1);
    Ok(())
}

pub fn decode_completion(packet: &[u8]) -> Result<(u32, u64, &[u8]), FileReadQueryWireError> {
    if packet.len() < HEADER_BYTES {
        return Err(FileReadQueryWireError::BufferTooSmall);
    }
    if packet.len() != packet_len(read_u32(packet, LENGTH_OFF))?
        || read_u32(packet, COMPLETED_OFF) != 1
    {
        return Err(FileReadQueryWireError::Malformed);
    }
    Ok((
        read_u32(packet, STATUS_OFF),
        read_u64(packet, INFORMATION_OFF),
        &packet[HEADER_BYTES..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_roundtrip_and_pending_completion_preserve_exact_shape() {
        let request = FileReadQueryRequest::Read(ReadWriteParameters {
            length: 3,
            key: 7,
            offset: 12,
        });
        let mut packet = [0xa5; HEADER_BYTES + 3];
        encode_request(request, &mut packet).unwrap();
        assert_eq!(decode_request(&packet), Ok(request));
        publish_completion(&mut packet, &[1, 2, 3], 0x103, 0).unwrap();
        assert_eq!(decode_completion(&packet), Ok((0x103, 0, &[1, 2, 3][..])));
        assert_eq!(decode_request(&packet), Err(FileReadQueryWireError::Malformed));
    }

    #[test]
    fn query_uses_real_information_class_contract() {
        let request = FileReadQueryRequest::Query {
            class: 4,
            length: 40,
        };
        let mut packet = [0; HEADER_BYTES + 40];
        encode_request(request, &mut packet).unwrap();
        assert_eq!(decode_request(&packet), Ok(request));
        assert_eq!(
            encode_request(
                FileReadQueryRequest::Query {
                    class: 4,
                    length: 39,
                },
                &mut packet,
            ),
            Err(FileReadQueryWireError::LengthMismatch)
        );
        assert_eq!(
            encode_request(
                FileReadQueryRequest::Query {
                    class: 3,
                    length: 40,
                },
                &mut packet,
            ),
            Err(FileReadQueryWireError::InvalidClass)
        );
    }

    #[test]
    fn malformed_lengths_and_absolute_offsets_never_admit_a_request() {
        let request = FileReadQueryRequest::Read(ReadWriteParameters {
            length: 1,
            key: 0,
            offset: 0,
        });
        let mut packet = [0; HEADER_BYTES + 1];
        encode_request(request, &mut packet).unwrap();
        packet[LENGTH_OFF] = 2;
        assert_eq!(decode_request(&packet), Err(FileReadQueryWireError::Malformed));
        packet[LENGTH_OFF] = 1;
        packet[OFFSET_OFF + 7] = 0x80;
        assert_eq!(decode_request(&packet), Err(FileReadQueryWireError::Malformed));
        assert_eq!(
            publish_completion(&mut packet, &[1], 0, 1),
            Err(FileReadQueryWireError::Malformed)
        );
    }
}
