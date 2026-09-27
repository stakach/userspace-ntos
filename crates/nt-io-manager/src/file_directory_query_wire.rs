//! Pointer-free request and completion packet for a hosted kernel directory query.

pub const HEADER_BYTES: usize = 40;
pub const KIND_DIRECTORY: u32 = 3;
const KIND_OFF: usize = 0;
const CLASS_OFF: usize = 4;
const PATTERN_UNITS_OFF: usize = 8;
const RESERVED_OFF: usize = 12;
const FLAGS_OFF: usize = 16;
const OUTPUT_LEN_OFF: usize = 20;
const COMPLETED_OFF: usize = 24;
const STATUS_OFF: usize = 28;
const INFORMATION_OFF: usize = 32;
const FLAG_RESTART_SCAN: u32 = 1;
const FLAG_RETURN_SINGLE_ENTRY: u32 = 2;
const FLAG_PATTERN_PRESENT: u32 = 4;
const VALID_FLAGS: u32 = FLAG_RESTART_SCAN | FLAG_RETURN_SINGLE_ENTRY | FLAG_PATTERN_PRESENT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryQueryRequest<'a> {
    pub output_len: u32,
    pub restart_scan: bool,
    pub return_single_entry: bool,
    pub pattern: Option<&'a [u16]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedPattern<'a>(&'a [u8]);

impl EncodedPattern<'_> {
    pub fn len(self) -> usize {
        self.0.len() / 2
    }

    pub fn is_empty(self) -> bool {
        self.0.is_empty()
    }

    pub fn unit(self, index: usize) -> Option<u16> {
        let offset = index.checked_mul(2)?;
        let bytes = self.0.get(offset..offset.checked_add(2)?)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedDirectoryQueryRequest<'a> {
    pub output_len: u32,
    pub restart_scan: bool,
    pub return_single_entry: bool,
    pub pattern: Option<EncodedPattern<'a>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryQueryWireError {
    BufferTooSmall,
    InvalidClass,
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

pub fn packet_len(output_len: u32, pattern_units: usize) -> Result<usize, DirectoryQueryWireError> {
    if pattern_units > nt_fs::MAX_DIRECTORY_NAME {
        return Err(DirectoryQueryWireError::LengthMismatch);
    }
    HEADER_BYTES
        .checked_add(
            pattern_units
                .checked_mul(2)
                .ok_or(DirectoryQueryWireError::LengthMismatch)?,
        )
        .and_then(|length| length.checked_add(output_len as usize))
        .ok_or(DirectoryQueryWireError::LengthMismatch)
}

fn validate_output_len(output_len: u32) -> Result<(), DirectoryQueryWireError> {
    let minimum = nt_fs::directory_query_minimum_length(nt_fs::FILE_DIRECTORY_INFORMATION)
        .ok_or(DirectoryQueryWireError::InvalidClass)?;
    if (output_len as usize) < minimum {
        return Err(DirectoryQueryWireError::LengthMismatch);
    }
    Ok(())
}

/// The sole admitted class is FileDirectoryInformation; the packet has no raw pointers.
pub fn encode_request(
    request: DirectoryQueryRequest<'_>,
    packet: &mut [u8],
) -> Result<(), DirectoryQueryWireError> {
    validate_output_len(request.output_len)?;
    let pattern_units = request.pattern.map_or(0, |pattern| pattern.len());
    if packet.len() != packet_len(request.output_len, pattern_units)? {
        return Err(DirectoryQueryWireError::LengthMismatch);
    }
    let mut flags = 0;
    if request.restart_scan {
        flags |= FLAG_RESTART_SCAN;
    }
    if request.return_single_entry {
        flags |= FLAG_RETURN_SINGLE_ENTRY;
    }
    if request.pattern.is_some() {
        flags |= FLAG_PATTERN_PRESENT;
    }
    packet.fill(0);
    write_u32(packet, KIND_OFF, KIND_DIRECTORY);
    write_u32(packet, CLASS_OFF, nt_fs::FILE_DIRECTORY_INFORMATION);
    write_u32(packet, OUTPUT_LEN_OFF, request.output_len);
    write_u32(packet, FLAGS_OFF, flags);
    write_u32(packet, PATTERN_UNITS_OFF, pattern_units as u32);
    if let Some(pattern) = request.pattern {
        for (index, unit) in pattern.iter().enumerate() {
            let offset = HEADER_BYTES + index * 2;
            packet[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    Ok(())
}

pub fn decode_request(
    packet: &[u8],
) -> Result<DecodedDirectoryQueryRequest<'_>, DirectoryQueryWireError> {
    if packet.len() < HEADER_BYTES {
        return Err(DirectoryQueryWireError::BufferTooSmall);
    }
    if read_u32(packet, KIND_OFF) != KIND_DIRECTORY {
        return Err(DirectoryQueryWireError::Malformed);
    }
    if read_u32(packet, CLASS_OFF) != nt_fs::FILE_DIRECTORY_INFORMATION {
        return Err(DirectoryQueryWireError::InvalidClass);
    }
    let output_len = read_u32(packet, OUTPUT_LEN_OFF);
    validate_output_len(output_len)?;
    let flags = read_u32(packet, FLAGS_OFF);
    let pattern_units = read_u32(packet, PATTERN_UNITS_OFF) as usize;
    if read_u32(packet, RESERVED_OFF) != 0
        || flags & !VALID_FLAGS != 0
        || (flags & FLAG_PATTERN_PRESENT == 0 && pattern_units != 0)
        || packet.len() != packet_len(output_len, pattern_units)?
        || read_u32(packet, COMPLETED_OFF) != 0
        || read_u32(packet, STATUS_OFF) != 0
        || read_u64(packet, INFORMATION_OFF) != 0
    {
        return Err(DirectoryQueryWireError::Malformed);
    }
    let pattern = (flags & FLAG_PATTERN_PRESENT != 0)
        .then(|| EncodedPattern(&packet[HEADER_BYTES..HEADER_BYTES + pattern_units * 2]));
    Ok(DecodedDirectoryQueryRequest {
        output_len,
        restart_scan: flags & FLAG_RESTART_SCAN != 0,
        return_single_entry: flags & FLAG_RETURN_SINGLE_ENTRY != 0,
        pattern,
    })
}

pub fn publish_completion(
    packet: &mut [u8],
    output: &[u8],
    status: u32,
    information: u64,
) -> Result<(), DirectoryQueryWireError> {
    let request = decode_request(packet)?;
    if output.len() != request.output_len as usize || information > request.output_len as u64 {
        return Err(DirectoryQueryWireError::LengthMismatch);
    }
    let output_start = HEADER_BYTES + request.pattern.map_or(0, |pattern| pattern.0.len());
    packet[output_start..].copy_from_slice(output);
    write_u32(packet, STATUS_OFF, status);
    write_u64(packet, INFORMATION_OFF, information);
    write_u32(packet, COMPLETED_OFF, 1);
    Ok(())
}

pub fn decode_completion(packet: &[u8]) -> Result<(u32, u64, &[u8]), DirectoryQueryWireError> {
    if packet.len() < HEADER_BYTES {
        return Err(DirectoryQueryWireError::BufferTooSmall);
    }
    if read_u32(packet, KIND_OFF) != KIND_DIRECTORY {
        return Err(DirectoryQueryWireError::Malformed);
    }
    if read_u32(packet, CLASS_OFF) != nt_fs::FILE_DIRECTORY_INFORMATION {
        return Err(DirectoryQueryWireError::InvalidClass);
    }
    let output_len = read_u32(packet, OUTPUT_LEN_OFF);
    validate_output_len(output_len)?;
    let flags = read_u32(packet, FLAGS_OFF);
    let pattern_units = read_u32(packet, PATTERN_UNITS_OFF) as usize;
    if read_u32(packet, RESERVED_OFF) != 0
        || flags & !VALID_FLAGS != 0
        || (flags & FLAG_PATTERN_PRESENT == 0 && pattern_units != 0)
        || packet.len() != packet_len(output_len, pattern_units)?
        || read_u32(packet, COMPLETED_OFF) != 1
        || read_u64(packet, INFORMATION_OFF) > output_len as u64
    {
        return Err(DirectoryQueryWireError::Malformed);
    }
    let output_start = HEADER_BYTES + pattern_units * 2;
    Ok((
        read_u32(packet, STATUS_OFF),
        read_u64(packet, INFORMATION_OFF),
        &packet[output_start..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_scan_and_wildcard_roundtrip_through_completion() {
        let pattern = [
            b'*' as u16,
            b'.' as u16,
            b't' as u16,
            b't' as u16,
            b'f' as u16,
        ];
        let request = DirectoryQueryRequest {
            output_len: 72,
            restart_scan: true,
            return_single_entry: false,
            pattern: Some(&pattern),
        };
        let mut packet = [0xa5; HEADER_BYTES + 10 + 72];
        encode_request(request, &mut packet).unwrap();
        let decoded = decode_request(&packet).unwrap();
        assert!(decoded.restart_scan);
        assert!(!decoded.return_single_entry);
        let encoded_pattern = decoded.pattern.unwrap();
        assert_eq!(encoded_pattern.len(), pattern.len());
        for (index, unit) in pattern.iter().enumerate() {
            assert_eq!(encoded_pattern.unit(index), Some(*unit));
        }
        assert_eq!(encoded_pattern.unit(pattern.len()), None);
        publish_completion(&mut packet, &[3; 72], 0, 72).unwrap();
        assert_eq!(decode_completion(&packet), Ok((0, 72, &[3; 72][..])));
        assert_eq!(
            decode_request(&packet),
            Err(DirectoryQueryWireError::Malformed)
        );
    }

    #[test]
    fn absent_and_empty_patterns_remain_distinct() {
        let mut packet = [0; HEADER_BYTES + 72];
        encode_request(
            DirectoryQueryRequest {
                output_len: 72,
                restart_scan: false,
                return_single_entry: true,
                pattern: None,
            },
            &mut packet,
        )
        .unwrap();
        let decoded = decode_request(&packet).unwrap();
        assert!(decoded.return_single_entry);
        assert_eq!(decoded.pattern, None);
        encode_request(
            DirectoryQueryRequest {
                output_len: 72,
                restart_scan: true,
                return_single_entry: false,
                pattern: Some(&[]),
            },
            &mut packet,
        )
        .unwrap();
        assert!(decode_request(&packet).unwrap().pattern.unwrap().is_empty());
    }

    #[test]
    fn rejects_invalid_class_lengths_flags_and_completion() {
        let mut packet = [0; HEADER_BYTES + 72];
        encode_request(
            DirectoryQueryRequest {
                output_len: 72,
                restart_scan: false,
                return_single_entry: false,
                pattern: None,
            },
            &mut packet,
        )
        .unwrap();
        write_u32(
            &mut packet,
            CLASS_OFF,
            nt_fs::FILE_BOTH_DIRECTORY_INFORMATION,
        );
        assert_eq!(
            decode_request(&packet),
            Err(DirectoryQueryWireError::InvalidClass)
        );
        write_u32(&mut packet, CLASS_OFF, nt_fs::FILE_DIRECTORY_INFORMATION);
        write_u32(&mut packet, FLAGS_OFF, 0x80);
        assert_eq!(
            decode_request(&packet),
            Err(DirectoryQueryWireError::Malformed)
        );
        write_u32(&mut packet, FLAGS_OFF, 0);
        write_u32(&mut packet, PATTERN_UNITS_OFF, 1);
        assert_eq!(
            decode_request(&packet),
            Err(DirectoryQueryWireError::Malformed)
        );
        write_u32(&mut packet, PATTERN_UNITS_OFF, 0);
        write_u32(&mut packet, OUTPUT_LEN_OFF, 71);
        assert_eq!(
            decode_request(&packet),
            Err(DirectoryQueryWireError::LengthMismatch)
        );
        write_u32(&mut packet, OUTPUT_LEN_OFF, 72);
        assert_eq!(
            publish_completion(&mut packet, &[0; 72], 0, 73),
            Err(DirectoryQueryWireError::LengthMismatch)
        );
        write_u32(&mut packet, COMPLETED_OFF, 1);
        write_u64(&mut packet, INFORMATION_OFF, 73);
        assert_eq!(
            decode_completion(&packet),
            Err(DirectoryQueryWireError::Malformed)
        );
    }

    #[test]
    fn rejects_oversized_pattern_and_truncated_packet() {
        assert_eq!(
            packet_len(72, nt_fs::MAX_DIRECTORY_NAME + 1),
            Err(DirectoryQueryWireError::LengthMismatch)
        );
        assert_eq!(
            decode_request(&[0; HEADER_BYTES - 1]),
            Err(DirectoryQueryWireError::BufferTooSmall)
        );
        let mut packet = [0; HEADER_BYTES + 72];
        encode_request(
            DirectoryQueryRequest {
                output_len: 72,
                restart_scan: false,
                return_single_entry: false,
                pattern: None,
            },
            &mut packet,
        )
        .unwrap();
        write_u32(
            &mut packet,
            PATTERN_UNITS_OFF,
            (nt_fs::MAX_DIRECTORY_NAME + 1) as u32,
        );
        write_u32(&mut packet, FLAGS_OFF, FLAG_PATTERN_PRESENT);
        assert_eq!(
            decode_request(&packet),
            Err(DirectoryQueryWireError::LengthMismatch)
        );
    }
}
