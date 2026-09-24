//! Bounded, pointer-free transport for a captured kernel IoCreateFile request.

use alloc::vec::Vec;
use nt_types::AccessMode;

use crate::io_create_file::{
    self, IoCreateFilePolicy, IoCreateFileScalars, IoCreateFileType, OwnedIoCreateFileRequest,
};

pub const IO_CREATE_FILE_WIRE_VERSION: u16 = 1;
pub const IO_CREATE_FILE_WIRE_HEADER_BYTES: usize = 88;

const MAGIC: u32 = u32::from_le_bytes(*b"ICFW");
const HAS_ALLOCATION_SIZE: u32 = 1;
const HAS_SECURITY_DESCRIPTOR: u32 = 2;
const HAS_SECURITY_QOS: u32 = 4;
const HAS_EXTRA_PARAMETERS: u32 = 8;
const KNOWN_FLAGS: u32 =
    HAS_ALLOCATION_SIZE | HAS_SECURITY_DESCRIPTOR | HAS_SECURITY_QOS | HAS_EXTRA_PARAMETERS;
const CHECK_PARAMETERS: u8 = 1;
const FORCE_ACCESS_CHECK: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoCreateFileWireError {
    Malformed,
    UnsupportedVersion,
    TooLarge,
    BufferTooSmall,
    InsufficientResources,
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn u16_at(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().unwrap())
}

fn u32_at(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn u64_at(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}

pub fn encoded_len(request: &OwnedIoCreateFileRequest) -> Result<usize, IoCreateFileWireError> {
    let name_bytes = request
        .name
        .len()
        .checked_mul(2)
        .ok_or(IoCreateFileWireError::TooLarge)?;
    if name_bytes > u16::MAX as usize || request.name.len() > u32::MAX as usize {
        return Err(IoCreateFileWireError::TooLarge);
    }
    let mut total = IO_CREATE_FILE_WIRE_HEADER_BYTES;
    for length in [
        name_bytes,
        request.ea.len(),
        request.security_descriptor.as_ref().map_or(0, Vec::len),
        request.security_qos.as_ref().map_or(0, Vec::len),
        request.extra_create_parameters.as_ref().map_or(0, Vec::len),
    ] {
        if length > u32::MAX as usize {
            return Err(IoCreateFileWireError::TooLarge);
        }
        total = total
            .checked_add(length)
            .ok_or(IoCreateFileWireError::TooLarge)?;
    }
    if total > u32::MAX as usize {
        return Err(IoCreateFileWireError::TooLarge);
    }
    Ok(total)
}

/// Serialize only captured values. Caller output addresses and capabilities never enter the wire.
pub fn encode(request: &OwnedIoCreateFileRequest) -> Result<Vec<u8>, IoCreateFileWireError> {
    let total = encoded_len(request)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| IoCreateFileWireError::InsufficientResources)?;
    output.resize(total, 0);
    encode_into(request, &mut output)?;
    Ok(output)
}

/// Write an exact frame into caller-owned memory, without allocating another transfer buffer.
/// Returns the used prefix length; a larger destination is allowed.
pub fn encode_into(
    request: &OwnedIoCreateFileRequest,
    output: &mut [u8],
) -> Result<usize, IoCreateFileWireError> {
    let total = encoded_len(request)?;
    if output.len() < total {
        return Err(IoCreateFileWireError::BufferTooSmall);
    }
    let output = &mut output[..total];
    let mut flags = 0;
    if request.allocation_size.is_some() {
        flags |= HAS_ALLOCATION_SIZE;
    }
    if request.security_descriptor.is_some() {
        flags |= HAS_SECURITY_DESCRIPTOR;
    }
    if request.security_qos.is_some() {
        flags |= HAS_SECURITY_QOS;
    }
    if request.extra_create_parameters.is_some() {
        flags |= HAS_EXTRA_PARAMETERS;
    }
    put_u32(output, 0, MAGIC);
    put_u16(output, 4, IO_CREATE_FILE_WIRE_VERSION);
    put_u16(output, 6, IO_CREATE_FILE_WIRE_HEADER_BYTES as u16);
    put_u32(output, 8, total as u32);
    put_u32(output, 12, flags);
    output[16] = match request.policy.file_type {
        IoCreateFileType::Ordinary => 0,
        IoCreateFileType::NamedPipe => 1,
        IoCreateFileType::Mailslot => 2,
    };
    output[17] = request.policy.major;
    output[18] = match request.policy.access_mode {
        AccessMode::KernelMode => 0,
        AccessMode::UserMode => 1,
    };
    output[19] = (request.policy.check_parameters as u8) * CHECK_PARAMETERS
        | (request.policy.force_access_check as u8) * FORCE_ACCESS_CHECK;
    output[20] = request.policy.create_stack_flags;
    output[21..24].fill(0);
    put_u32(output, 24, request.policy.create_options);
    put_u32(output, 28, request.policy.io_options);
    put_u32(output, 32, request.desired_access);
    put_u32(output, 36, request.file_attributes);
    put_u32(output, 40, request.share_access);
    put_u32(output, 44, request.disposition);
    put_u32(output, 48, request.object_attributes);
    put_u64(output, 52, request.root_directory);
    put_u64(
        output,
        60,
        request.allocation_size.unwrap_or_default() as u64,
    );
    put_u32(output, 68, request.name.len() as u32);
    put_u32(output, 72, request.ea.len() as u32);
    put_u32(
        output,
        76,
        request.security_descriptor.as_ref().map_or(0, Vec::len) as u32,
    );
    put_u32(
        output,
        80,
        request.security_qos.as_ref().map_or(0, Vec::len) as u32,
    );
    put_u32(
        output,
        84,
        request.extra_create_parameters.as_ref().map_or(0, Vec::len) as u32,
    );
    let mut position = IO_CREATE_FILE_WIRE_HEADER_BYTES;
    for unit in &request.name {
        put_u16(output, position, *unit);
        position += 2;
    }
    for bytes in [
        Some(&request.ea),
        request.security_descriptor.as_ref(),
        request.security_qos.as_ref(),
        request.extra_create_parameters.as_ref(),
    ] {
        if let Some(bytes) = bytes {
            output[position..position + bytes.len()].copy_from_slice(bytes);
            position += bytes.len();
        }
    }
    debug_assert_eq!(position, total);
    Ok(total)
}

fn copy_bytes(input: &[u8]) -> Result<Vec<u8>, IoCreateFileWireError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(input.len())
        .map_err(|_| IoCreateFileWireError::InsufficientResources)?;
    owned.extend_from_slice(input);
    Ok(owned)
}

/// Decode an exact frame; lengths and presence are checked before any payload allocation.
pub fn decode(input: &[u8]) -> Result<OwnedIoCreateFileRequest, IoCreateFileWireError> {
    if input.len() > u32::MAX as usize {
        return Err(IoCreateFileWireError::TooLarge);
    }
    if input.len() < IO_CREATE_FILE_WIRE_HEADER_BYTES || u32_at(input, 0) != MAGIC {
        return Err(IoCreateFileWireError::Malformed);
    }
    if u16_at(input, 4) != IO_CREATE_FILE_WIRE_VERSION {
        return Err(IoCreateFileWireError::UnsupportedVersion);
    }
    if u16_at(input, 6) as usize != IO_CREATE_FILE_WIRE_HEADER_BYTES
        || u32_at(input, 8) as usize != input.len()
    {
        return Err(IoCreateFileWireError::Malformed);
    }
    let flags = u32_at(input, 12);
    if flags & !KNOWN_FLAGS != 0
        || input[19] & !(CHECK_PARAMETERS | FORCE_ACCESS_CHECK) != 0
        || input[21..24] != [0; 3]
    {
        return Err(IoCreateFileWireError::Malformed);
    }
    let file_type = match input[16] {
        0 => IoCreateFileType::Ordinary,
        1 => IoCreateFileType::NamedPipe,
        2 => IoCreateFileType::Mailslot,
        _ => return Err(IoCreateFileWireError::Malformed),
    };
    let access_mode = match input[18] {
        0 => AccessMode::KernelMode,
        1 => AccessMode::UserMode,
        _ => return Err(IoCreateFileWireError::Malformed),
    };
    let name_units = u32_at(input, 68) as usize;
    let name_bytes = name_units
        .checked_mul(2)
        .ok_or(IoCreateFileWireError::TooLarge)?;
    if name_bytes > u16::MAX as usize {
        return Err(IoCreateFileWireError::TooLarge);
    }
    let lengths = [
        name_bytes,
        u32_at(input, 72) as usize,
        u32_at(input, 76) as usize,
        u32_at(input, 80) as usize,
        u32_at(input, 84) as usize,
    ];
    for (length, bit) in [
        (lengths[2], HAS_SECURITY_DESCRIPTOR),
        (lengths[3], HAS_SECURITY_QOS),
        (lengths[4], HAS_EXTRA_PARAMETERS),
    ] {
        if flags & bit == 0 && length != 0 {
            return Err(IoCreateFileWireError::Malformed);
        }
    }
    let mut end = IO_CREATE_FILE_WIRE_HEADER_BYTES;
    for length in lengths {
        end = end
            .checked_add(length)
            .ok_or(IoCreateFileWireError::TooLarge)?;
    }
    if end != input.len() {
        return Err(IoCreateFileWireError::Malformed);
    }
    if flags & HAS_ALLOCATION_SIZE == 0 && u64_at(input, 60) != 0 {
        return Err(IoCreateFileWireError::Malformed);
    }
    let mut position = IO_CREATE_FILE_WIRE_HEADER_BYTES;
    let mut name = Vec::new();
    name.try_reserve_exact(name_units)
        .map_err(|_| IoCreateFileWireError::InsufficientResources)?;
    for _ in 0..name_units {
        name.push(u16_at(input, position));
        position += 2;
    }
    let ea_bytes = &input[position..position + lengths[1]];
    if !ea_bytes.is_empty() && crate::validate_ea_buffer(ea_bytes).is_err() {
        return Err(IoCreateFileWireError::Malformed);
    }
    let ea = copy_bytes(ea_bytes)?;
    position += lengths[1];
    let mut optional = [None, None, None];
    for (slot, (length, bit)) in optional.iter_mut().zip([
        (lengths[2], HAS_SECURITY_DESCRIPTOR),
        (lengths[3], HAS_SECURITY_QOS),
        (lengths[4], HAS_EXTRA_PARAMETERS),
    ]) {
        if flags & bit != 0 {
            *slot = Some(copy_bytes(&input[position..position + length])?);
        }
        position += length;
    }
    let policy = IoCreateFilePolicy {
        file_type,
        major: input[17],
        access_mode,
        check_parameters: input[19] & CHECK_PARAMETERS != 0,
        force_access_check: input[19] & FORCE_ACCESS_CHECK != 0,
        create_stack_flags: input[20],
        create_options: u32_at(input, 24),
        io_options: u32_at(input, 28),
    };
    let expected = io_create_file::classify(
        IoCreateFileScalars {
            desired_access: u32_at(input, 32),
            file_attributes: u32_at(input, 36),
            share_access: u32_at(input, 40),
            disposition: u32_at(input, 44),
            create_options: policy.create_options,
            create_file_type: input[16] as u32,
            extra_create_parameters_present: flags & HAS_EXTRA_PARAMETERS != 0,
            io_options: policy.io_options,
        },
        policy.access_mode,
    )
    .map_err(|_| IoCreateFileWireError::Malformed)?;
    if policy != expected {
        return Err(IoCreateFileWireError::Malformed);
    }
    Ok(OwnedIoCreateFileRequest {
        policy,
        desired_access: u32_at(input, 32),
        file_attributes: u32_at(input, 36),
        share_access: u32_at(input, 40),
        disposition: u32_at(input, 44),
        object_attributes: u32_at(input, 48),
        root_directory: u64_at(input, 52),
        allocation_size: (flags & HAS_ALLOCATION_SIZE != 0)
            .then(|| i64::from_le_bytes(u64_at(input, 60).to_le_bytes())),
        name,
        ea,
        security_descriptor: optional[0].take(),
        security_qos: optional[1].take(),
        extra_create_parameters: optional[2].take(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn request() -> OwnedIoCreateFileRequest {
        OwnedIoCreateFileRequest {
            policy: IoCreateFilePolicy {
                file_type: IoCreateFileType::Ordinary,
                major: 0,
                access_mode: AccessMode::KernelMode,
                check_parameters: false,
                force_access_check: true,
                create_options: 0x100,
                io_options: 0x101,
                create_stack_flags: 1,
            },
            desired_access: 0x123,
            file_attributes: 0x456,
            share_access: 3,
            disposition: 1,
            object_attributes: 0x240,
            root_directory: 0x84,
            name: vec![b'\\' as u16, b'D' as u16],
            allocation_size: Some(64),
            ea: vec![0, 0, 0, 0, 0, 1, 1, 0, b'x', 0, b'y'],
            security_descriptor: Some(vec![]),
            security_qos: None,
            extra_create_parameters: Some(vec![4, 5]),
        }
    }

    #[test]
    fn roundtrip_preserves_values_and_optional_presence() {
        let value = request();
        let bytes = encode(&value).unwrap();
        assert_eq!(bytes.len(), IO_CREATE_FILE_WIRE_HEADER_BYTES + 4 + 11 + 2);
        assert_eq!(decode(&bytes).unwrap(), value);
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_bad_lengths() {
        let bytes = encode(&request()).unwrap();
        assert_eq!(
            decode(&bytes[..bytes.len() - 1]),
            Err(IoCreateFileWireError::Malformed)
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(IoCreateFileWireError::Malformed));
        let mut wrong = bytes.clone();
        wrong[72..76].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&wrong), Err(IoCreateFileWireError::Malformed));
        wrong[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(decode(&wrong), Err(IoCreateFileWireError::TooLarge));
    }

    #[test]
    fn rejects_unknown_version_flags_and_absent_payload() {
        let bytes = encode(&request()).unwrap();
        let mut wrong = bytes.clone();
        wrong[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            decode(&wrong),
            Err(IoCreateFileWireError::UnsupportedVersion)
        );
        wrong = bytes.clone();
        let flags = u32_at(&wrong, 12) | 0x10;
        wrong[12..16].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(decode(&wrong), Err(IoCreateFileWireError::Malformed));
        wrong = bytes;
        let flags = u32_at(&wrong, 12) & !HAS_EXTRA_PARAMETERS;
        wrong[12..16].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(decode(&wrong), Err(IoCreateFileWireError::Malformed));
    }

    #[test]
    fn rejects_forged_derived_create_policy() {
        let bytes = encode(&request()).unwrap();
        let mut wrong = bytes.clone();
        wrong[17] = 2;
        assert_eq!(decode(&wrong), Err(IoCreateFileWireError::Malformed));
        let mut wrong = bytes.clone();
        wrong[19] = 0;
        assert_eq!(decode(&wrong), Err(IoCreateFileWireError::Malformed));
        let mut wrong = bytes;
        wrong[20] = 0;
        assert_eq!(decode(&wrong), Err(IoCreateFileWireError::Malformed));
    }

    #[test]
    fn rejects_modified_ea_after_caller_capture() {
        let mut bytes = encode(&request()).unwrap();
        let ea_start = IO_CREATE_FILE_WIRE_HEADER_BYTES + 4;
        bytes[ea_start..ea_start + 4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(decode(&bytes), Err(IoCreateFileWireError::Malformed));
    }

    #[test]
    fn refuses_name_that_cannot_fit_nt_unicode_string() {
        let mut value = request();
        value.name.resize(u16::MAX as usize / 2 + 1, 0);
        assert_eq!(encode(&value), Err(IoCreateFileWireError::TooLarge));
    }

    #[test]
    fn encodes_into_a_larger_caller_buffer() {
        let value = request();
        let exact = encode(&value).unwrap();
        let mut buffer = vec![0xa5; exact.len() + 8];
        assert_eq!(encode_into(&value, &mut buffer), Ok(exact.len()));
        assert_eq!(&buffer[..exact.len()], exact.as_slice());
        assert_eq!(&buffer[exact.len()..], &[0xa5; 8]);
        assert_eq!(
            encode_into(&value, &mut buffer[..exact.len() - 1]),
            Err(IoCreateFileWireError::BufferTooSmall)
        );
    }
}
