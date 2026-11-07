//! Exact, bounded shared-pool wire format for native process-information queries.
//!
//! The component owns the allocation. The executive authenticates its physical allocation
//! identity and caller before decoding these bytes; packet contents alone grant no authority.

pub const HEADER_SIZE: usize = 48;
pub const MAX_OUTPUT_BYTES: usize = 0x10 + u16::MAX as usize;
const MAGIC: u32 = 0x5150_3257; // W2PQ
const VERSION: u16 = 1;
const RETURN_LENGTH_FLAG: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessQueryRequest {
    pub handle: u64,
    pub class: u32,
    pub output_address: u64,
    pub output_length: u32,
    pub return_length_requested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessQueryResponse<'a> {
    pub status: u32,
    pub return_length: u32,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    InvalidLength,
    InvalidHeader,
    WrongRequest,
    InvalidResponse,
}

pub fn packet_len_for(output_length: u32) -> Option<usize> {
    HEADER_SIZE.checked_add((output_length as usize).min(MAX_OUTPUT_BYTES))
}

/// Select the retained attach owner only when its original owner and the active mapped window
/// agree. The caller also validates both owners' live process generations before using handles.
pub fn selected_effective_owner<T: Copy + Eq>(
    original: T,
    record: Option<(T, T, bool)>,
    active: Option<T>,
) -> Option<T> {
    let current = match record {
        Some((saved_original, current, inflight)) if !inflight && saved_original == original => current,
        Some(_) => return None,
        None => original,
    };
    (active == Some(current)).then_some(current)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub fn encode_request(packet: &mut [u8], request: ProcessQueryRequest) -> Result<(), PacketError> {
    if packet_len_for(request.output_length) != Some(packet.len()) {
        return Err(PacketError::InvalidLength);
    }
    packet.fill(0);
    packet[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    packet[4..6].copy_from_slice(&VERSION.to_le_bytes());
    packet[6..8].copy_from_slice(&(u16::from(request.return_length_requested)).to_le_bytes());
    packet[8..16].copy_from_slice(&request.handle.to_le_bytes());
    packet[16..20].copy_from_slice(&request.class.to_le_bytes());
    packet[20..24].copy_from_slice(&request.output_length.to_le_bytes());
    packet[24..32].copy_from_slice(&request.output_address.to_le_bytes());
    Ok(())
}

pub fn decode_request(packet: &[u8]) -> Result<ProcessQueryRequest, PacketError> {
    if packet.len() < HEADER_SIZE {
        return Err(PacketError::InvalidLength);
    }
    if read_u32(packet, 0) != MAGIC
        || read_u16(packet, 4) != VERSION
        || read_u16(packet, 6) & !RETURN_LENGTH_FLAG != 0
        || read_u32(packet, 44) != 0
    {
        return Err(PacketError::InvalidHeader);
    }
    let output_length = read_u32(packet, 20);
    if packet_len_for(output_length) != Some(packet.len()) {
        return Err(PacketError::InvalidLength);
    }
    Ok(ProcessQueryRequest {
        handle: read_u64(packet, 8),
        class: read_u32(packet, 16),
        output_address: read_u64(packet, 24),
        output_length,
        return_length_requested: read_u16(packet, 6) & RETURN_LENGTH_FLAG != 0,
    })
}

pub fn encode_response(
    packet: &mut [u8],
    request: ProcessQueryRequest,
    status: u32,
    return_length: u32,
    bytes: &[u8],
) -> Result<(), PacketError> {
    if decode_request(packet)? != request {
        return Err(PacketError::WrongRequest);
    }
    validate_response(request, packet.len(), status, return_length, bytes.len())?;
    packet[32..36].copy_from_slice(&status.to_le_bytes());
    packet[36..40].copy_from_slice(&return_length.to_le_bytes());
    packet[40..44].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
    packet[HEADER_SIZE..HEADER_SIZE + bytes.len()].copy_from_slice(bytes);
    Ok(())
}

pub fn decode_response<'a>(
    packet: &'a [u8],
    request: ProcessQueryRequest,
) -> Result<ProcessQueryResponse<'a>, PacketError> {
    if decode_request(packet)? != request {
        return Err(PacketError::WrongRequest);
    }
    let status = read_u32(packet, 32);
    let return_length = read_u32(packet, 36);
    let bytes_len = read_u32(packet, 40) as usize;
    validate_response(request, packet.len(), status, return_length, bytes_len)?;
    Ok(ProcessQueryResponse {
        status,
        return_length,
        bytes: &packet[HEADER_SIZE..HEADER_SIZE + bytes_len],
    })
}

fn validate_response(
    request: ProcessQueryRequest,
    packet_len: usize,
    status: u32,
    return_length: u32,
    bytes_len: usize,
) -> Result<(), PacketError> {
    if bytes_len > packet_len - HEADER_SIZE
        || bytes_len > request.output_length as usize
        || bytes_len > MAX_OUTPUT_BYTES
        || (status == 0 && (bytes_len == 0 || bytes_len != return_length as usize))
        || (status != 0 && bytes_len != 0)
    {
        return Err(PacketError::InvalidResponse);
    }
    Ok(())
}
