//! Pointer-free transport for a retained Mup `IOCTL_REDIR_QUERY_PATH` forward.
//!
//! Frame identities are correlation data, not authority. The native adapter must obtain the
//! expected identity from its retained source IRP, target registration, and security graph,
//! then validate those owners again before dispatch or source-local completion.

use alloc::vec::Vec;
use core::num::NonZeroU64;

use crate::{
    redir_query_path::{
        capture_completion, CapturedQueryPath, QueryPathCompletion, QueryPathError,
        RetainedSecurityContextTicket, IOCTL_REDIR_QUERY_PATH, IRP_MJ_DEVICE_CONTROL,
        QUERY_PATH_REQUEST_X64_SIZE, QUERY_PATH_RESPONSE_SIZE,
    },
    retained_query_path_forward::{QueryPathForwardIdentity, SourceIrpTicket},
    DeviceId, HostedDomainId,
};

pub const QUERY_PATH_WIRE_VERSION: u16 = 1;
pub const QUERY_PATH_WIRE_HEADER_BYTES: usize = 104;

const REQUEST_MAGIC: u32 = u32::from_le_bytes(*b"QPRQ");
const COMPLETION_MAGIC: u32 = u32::from_le_bytes(*b"QPCP");
const MAX_PATH_BYTES: usize = 65_532;
const MAX_BUFFER_BYTES: usize = QUERY_PATH_REQUEST_X64_SIZE + MAX_PATH_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryPathWireError {
    Malformed,
    UnsupportedVersion,
    WrongIdentity,
    InvalidRequest,
    InvalidCompletion(QueryPathError),
    BufferTooSmall,
    InsufficientResources,
}

/// No address from `HostedDevicePointerRegistration` enters this identity. The receiving
/// adapter resolves `target_device` through the I/O Manager's live provider registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryPathWireIdentity {
    pub source: SourceIrpTicket,
    pub target_device: DeviceId,
    pub security: RetainedSecurityContextTicket,
}

impl From<QueryPathForwardIdentity> for QueryPathWireIdentity {
    fn from(identity: QueryPathForwardIdentity) -> Self {
        Self {
            source: identity.source,
            target_device: identity.target.device_id(),
            security: identity.security,
        }
    }
}

fn valid_identity(identity: QueryPathWireIdentity) -> bool {
    identity.source.domain.domain_id != HostedDomainId::NULL
        && identity.source.domain.domain_id.generation() != 0
        && identity.source.domain.cookie != 0
        && identity.source.id.get() != 0
        && identity.source.generation.get() != 0
        && !identity.target_device.is_null()
        && identity.target_device.generation() != 0
        && identity.security.id() != 0
        && identity.security.generation() != 0
}

fn request_lengths(request: &CapturedQueryPath) -> Result<(usize, usize), QueryPathWireError> {
    let path_bytes = request
        .path
        .len()
        .checked_mul(2)
        .ok_or(QueryPathWireError::InvalidRequest)?;
    let minimum = QUERY_PATH_REQUEST_X64_SIZE
        .checked_add(path_bytes)
        .ok_or(QueryPathWireError::InvalidRequest)?;
    if path_bytes == 0
        || path_bytes > MAX_PATH_BYTES
        || (request.input_buffer_length as usize) < minimum
        || request.input_buffer_length as usize > MAX_BUFFER_BYTES
        || request.output_buffer_length < QUERY_PATH_RESPONSE_SIZE as u32
        || request.output_buffer_length as usize > MAX_BUFFER_BYTES
    {
        return Err(QueryPathWireError::InvalidRequest);
    }
    Ok((path_bytes, QUERY_PATH_WIRE_HEADER_BYTES + path_bytes))
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

fn write_common(output: &mut [u8], magic: u32, identity: QueryPathWireIdentity, total: usize) {
    output.fill(0);
    put_u32(output, 0, magic);
    put_u16(output, 4, QUERY_PATH_WIRE_VERSION);
    put_u16(output, 6, QUERY_PATH_WIRE_HEADER_BYTES as u16);
    put_u32(output, 8, total as u32);
    put_u32(output, 12, IOCTL_REDIR_QUERY_PATH);
    output[16] = IRP_MJ_DEVICE_CONTROL;
    output[18] = 1; // KernelMode requestor.
    put_u64(output, 32, identity.source.domain.domain_id.raw());
    put_u64(output, 40, identity.source.domain.cookie);
    put_u64(output, 48, identity.source.id.get());
    put_u64(output, 56, identity.source.generation.get());
    put_u64(output, 64, identity.target_device.raw());
    put_u64(output, 72, identity.security.id());
    put_u64(output, 80, identity.security.generation());
}

fn validate_common(
    input: &[u8],
    magic: u32,
    expected: QueryPathWireIdentity,
) -> Result<(), QueryPathWireError> {
    if input.len() < QUERY_PATH_WIRE_HEADER_BYTES
        || u32_at(input, 0) != magic
        || u16_at(input, 6) as usize != QUERY_PATH_WIRE_HEADER_BYTES
        || u32_at(input, 8) as usize != input.len()
        || u32_at(input, 12) != IOCTL_REDIR_QUERY_PATH
        || input[16] != IRP_MJ_DEVICE_CONTROL
        || input[17] != 0
        || input[18] != 1
        || input[19] != 0
        || !valid_identity(expected)
    {
        return Err(QueryPathWireError::Malformed);
    }
    if u16_at(input, 4) != QUERY_PATH_WIRE_VERSION {
        return Err(QueryPathWireError::UnsupportedVersion);
    }
    if u64_at(input, 32) != expected.source.domain.domain_id.raw()
        || u64_at(input, 40) != expected.source.domain.cookie
        || u64_at(input, 48) != expected.source.id.get()
        || u64_at(input, 56) != expected.source.generation.get()
        || u64_at(input, 64) != expected.target_device.raw()
        || u64_at(input, 72) != expected.security.id()
        || u64_at(input, 80) != expected.security.generation()
    {
        return Err(QueryPathWireError::WrongIdentity);
    }
    Ok(())
}

/// Serialize a source-owned capture. The original security-context address is absent.
pub fn encode_request(
    identity: QueryPathWireIdentity,
    request: &CapturedQueryPath,
) -> Result<Vec<u8>, QueryPathWireError> {
    if !valid_identity(identity) || identity.security != request.security {
        return Err(QueryPathWireError::WrongIdentity);
    }
    let (_, total) = request_lengths(request)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(total)
        .map_err(|_| QueryPathWireError::InsufficientResources)?;
    output.resize(total, 0);
    encode_request_into(identity, request, &mut output)?;
    Ok(output)
}

/// Write an exact request frame into caller-owned transport storage.
pub fn encode_request_into(
    identity: QueryPathWireIdentity,
    request: &CapturedQueryPath,
    output: &mut [u8],
) -> Result<usize, QueryPathWireError> {
    if !valid_identity(identity) || identity.security != request.security {
        return Err(QueryPathWireError::WrongIdentity);
    }
    let (path_bytes, total) = request_lengths(request)?;
    if output.len() < total {
        return Err(QueryPathWireError::BufferTooSmall);
    }
    let output = &mut output[..total];
    write_common(output, REQUEST_MAGIC, identity, total);
    put_u32(output, 20, request.input_buffer_length);
    put_u32(output, 24, request.output_buffer_length);
    put_u32(output, 28, path_bytes as u32);
    for (index, unit) in request.path.iter().enumerate() {
        put_u16(output, QUERY_PATH_WIRE_HEADER_BYTES + index * 2, *unit);
    }
    Ok(total)
}

/// Decode only after the transport's authenticated owner supplies the expected identity.
pub fn decode_request(
    input: &[u8],
    expected: QueryPathWireIdentity,
) -> Result<CapturedQueryPath, QueryPathWireError> {
    validate_common(input, REQUEST_MAGIC, expected)?;
    if input[88..QUERY_PATH_WIRE_HEADER_BYTES] != [0; 16] {
        return Err(QueryPathWireError::Malformed);
    }
    let path_bytes = u32_at(input, 28) as usize;
    if path_bytes == 0
        || path_bytes & 1 != 0
        || path_bytes > MAX_PATH_BYTES
        || QUERY_PATH_WIRE_HEADER_BYTES + path_bytes != input.len()
    {
        return Err(QueryPathWireError::InvalidRequest);
    }
    let mut path = Vec::new();
    path.try_reserve_exact(path_bytes / 2)
        .map_err(|_| QueryPathWireError::InsufficientResources)?;
    for unit in input[QUERY_PATH_WIRE_HEADER_BYTES..].chunks_exact(2) {
        path.push(u16::from_le_bytes([unit[0], unit[1]]));
    }
    let request = CapturedQueryPath {
        security: expected.security,
        path,
        input_buffer_length: u32_at(input, 20),
        output_buffer_length: u32_at(input, 24),
    };
    request_lengths(&request)?;
    Ok(request)
}

/// Build the provider's x64 METHOD_NEITHER input in provider-owned memory. The caller must
/// validate `provider_security_context` against its live provider-local security projection;
/// this value is never serialized. The unowned tail advertised by the source is zero-filled.
pub fn materialize_provider_input(
    request: &CapturedQueryPath,
    provider_security_context: NonZeroU64,
) -> Result<Vec<u8>, QueryPathWireError> {
    let (path_bytes, _) = request_lengths(request)?;
    let mut input = Vec::new();
    input
        .try_reserve_exact(request.input_buffer_length as usize)
        .map_err(|_| QueryPathWireError::InsufficientResources)?;
    input.resize(request.input_buffer_length as usize, 0);
    put_u32(&mut input, 0, path_bytes as u32);
    put_u64(&mut input, 8, provider_security_context.get());
    for (index, unit) in request.path.iter().enumerate() {
        put_u16(&mut input, 16 + index * 2, *unit);
    }
    Ok(input)
}

/// Capture a terminal provider result before sending it back to the source domain.
pub fn encode_completion(
    identity: QueryPathWireIdentity,
    request: &CapturedQueryPath,
    status: u32,
    information: u64,
    response: &[u8],
) -> Result<[u8; QUERY_PATH_WIRE_HEADER_BYTES], QueryPathWireError> {
    if !valid_identity(identity) || identity.security != request.security {
        return Err(QueryPathWireError::WrongIdentity);
    }
    request_lengths(request)?;
    let completion = capture_completion(request, status, information, response)
        .map_err(QueryPathWireError::InvalidCompletion)?;
    let mut output = [0; QUERY_PATH_WIRE_HEADER_BYTES];
    write_common(
        &mut output,
        COMPLETION_MAGIC,
        identity,
        QUERY_PATH_WIRE_HEADER_BYTES,
    );
    put_u32(&mut output, 20, completion.status);
    put_u32(&mut output, 24, completion.length_accepted);
    put_u64(&mut output, 88, completion.information);
    Ok(output)
}

/// Revalidate the exact owner and captured request before source-local completion unwind.
pub fn decode_completion(
    input: &[u8],
    expected: QueryPathWireIdentity,
    request: &CapturedQueryPath,
) -> Result<QueryPathCompletion, QueryPathWireError> {
    validate_common(input, COMPLETION_MAGIC, expected)?;
    if input.len() != QUERY_PATH_WIRE_HEADER_BYTES
        || u32_at(input, 28) != 0
        || input[96..QUERY_PATH_WIRE_HEADER_BYTES] != [0; 8]
        || expected.security != request.security
    {
        return Err(QueryPathWireError::Malformed);
    }
    request_lengths(request)?;
    let status = u32_at(input, 20);
    let length_accepted = u32_at(input, 24);
    let response = length_accepted.to_le_bytes();
    let response = if status as i32 >= 0 {
        &response[..]
    } else {
        &[][..]
    };
    let completion = capture_completion(request, status, u64_at(input, 88), response)
        .map_err(QueryPathWireError::InvalidCompletion)?;
    if completion.length_accepted != length_accepted {
        return Err(QueryPathWireError::Malformed);
    }
    Ok(completion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostedDomainIdentity;

    fn fixture() -> (QueryPathWireIdentity, CapturedQueryPath) {
        let identity = QueryPathWireIdentity {
            source: SourceIrpTicket::new(
                HostedDomainIdentity {
                    domain_id: HostedDomainId::new(1, 2),
                    cookie: 0x2233_4455,
                },
                27,
                9,
            )
            .unwrap(),
            target_device: DeviceId::new(3, 4),
            security: RetainedSecurityContextTicket::new(18, 6).unwrap(),
        };
        let request = CapturedQueryPath {
            security: identity.security,
            path: alloc::vec![b'\\' as u16, b's' as u16, b'r' as u16, b'v' as u16],
            input_buffer_length: 32,
            output_buffer_length: 4,
        };
        (identity, request)
    }

    #[test]
    fn request_roundtrip_owns_path_and_has_no_source_pointer() {
        let (identity, request) = fixture();
        let frame = encode_request(identity, &request).unwrap();
        assert_eq!(frame.len(), QUERY_PATH_WIRE_HEADER_BYTES + 8);
        assert!(!frame
            .windows(8)
            .any(|bytes| bytes == 0xfeed_cafe_dead_beefu64.to_le_bytes()));
        assert_eq!(decode_request(&frame, identity), Ok(request));
    }

    #[test]
    fn request_requires_exact_source_target_and_security_identities() {
        let (identity, request) = fixture();
        let frame = encode_request(identity, &request).unwrap();
        for changed in [48usize, 56, 64, 72, 80] {
            let mut corrupt = frame.clone();
            corrupt[changed] ^= 1;
            assert_eq!(
                decode_request(&corrupt, identity),
                Err(QueryPathWireError::WrongIdentity)
            );
        }
        let mut wrong = identity;
        wrong.source.domain.cookie += 1;
        assert_eq!(
            decode_request(&frame, wrong),
            Err(QueryPathWireError::WrongIdentity)
        );
    }

    #[test]
    fn rejects_truncation_trailing_bytes_invalid_lengths_and_reserved_fields() {
        let (identity, request) = fixture();
        let frame = encode_request(identity, &request).unwrap();
        assert!(decode_request(&frame[..frame.len() - 1], identity).is_err());
        let mut corrupt = frame.clone();
        corrupt.push(0);
        assert!(decode_request(&corrupt, identity).is_err());
        let mut corrupt = frame.clone();
        put_u32(&mut corrupt, 20, 31);
        assert_eq!(
            decode_request(&corrupt, identity),
            Err(QueryPathWireError::InvalidRequest)
        );
        let mut corrupt = frame.clone();
        put_u32(&mut corrupt, 28, 7);
        assert_eq!(
            decode_request(&corrupt, identity),
            Err(QueryPathWireError::InvalidRequest)
        );
        let mut corrupt = frame.clone();
        corrupt[88] = 1;
        assert_eq!(
            decode_request(&corrupt, identity),
            Err(QueryPathWireError::Malformed)
        );
        let mut corrupt = frame;
        put_u16(&mut corrupt, 4, 2);
        assert_eq!(
            decode_request(&corrupt, identity),
            Err(QueryPathWireError::UnsupportedVersion)
        );
    }

    #[test]
    fn completion_roundtrip_rechecks_request_and_rejects_pending() {
        let (identity, request) = fixture();
        assert_eq!(
            encode_completion(identity, &request, 0x103, 0, &[]),
            Err(QueryPathWireError::InvalidCompletion(
                QueryPathError::Pending
            ))
        );
        let frame = encode_completion(identity, &request, 0, 4, &4u32.to_le_bytes()).unwrap();
        assert_eq!(
            decode_completion(&frame, identity, &request),
            Ok(QueryPathCompletion {
                status: 0,
                information: 4,
                length_accepted: 4,
            })
        );
        let mut wrong = identity;
        wrong.security = RetainedSecurityContextTicket::new(18, 7).unwrap();
        assert_eq!(
            decode_completion(&frame, wrong, &request),
            Err(QueryPathWireError::WrongIdentity)
        );
        let mut corrupt = frame;
        put_u32(&mut corrupt, 24, 9);
        assert_eq!(
            decode_completion(&corrupt, identity, &request),
            Err(QueryPathWireError::InvalidCompletion(
                QueryPathError::InvalidPath
            ))
        );
    }

    #[test]
    fn failed_completion_has_no_accepted_path() {
        let (identity, request) = fixture();
        let frame = encode_completion(identity, &request, 0xc000_0034, 0, &[]).unwrap();
        assert_eq!(
            decode_completion(&frame, identity, &request)
                .unwrap()
                .length_accepted,
            0
        );
        let mut corrupt = frame;
        put_u32(&mut corrupt, 24, 2);
        assert_eq!(
            decode_completion(&corrupt, identity, &request),
            Err(QueryPathWireError::Malformed)
        );
    }

    #[test]
    fn caller_buffer_must_hold_exact_frame() {
        let (identity, request) = fixture();
        let mut small = [0; QUERY_PATH_WIRE_HEADER_BYTES];
        assert_eq!(
            encode_request_into(identity, &request, &mut small),
            Err(QueryPathWireError::BufferTooSmall)
        );
        let mut request = request;
        request.security = RetainedSecurityContextTicket::new(18, 7).unwrap();
        assert_eq!(
            encode_request(identity, &request),
            Err(QueryPathWireError::WrongIdentity)
        );
    }

    #[test]
    fn provider_input_uses_only_local_security_pointer_and_zero_fills_tail() {
        let (identity, mut request) = fixture();
        request.input_buffer_length = 40;
        let frame = encode_request(identity, &request).unwrap();
        assert!(!frame
            .windows(8)
            .any(|bytes| bytes == 0x1234_5000u64.to_le_bytes()));
        let decoded = decode_request(&frame, identity).unwrap();
        let input =
            materialize_provider_input(&decoded, NonZeroU64::new(0x1234_5000).unwrap()).unwrap();
        assert_eq!(input.len(), 40);
        assert_eq!(u32_at(&input, 0), 8);
        assert_eq!(u64_at(&input, 8), 0x1234_5000);
        assert_eq!(&input[16..24], &[b'\\', 0, b's', 0, b'r', 0, b'v', 0]);
        assert!(input[24..].iter().all(|byte| *byte == 0));
    }
}
