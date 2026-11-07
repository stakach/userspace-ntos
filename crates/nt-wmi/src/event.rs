//! Bounded WNODE event header admission. Native code must first capture an
//! exact source allocation, then parse a copied 48-byte header and payload.

use crate::WmiGuid;

pub const WNODE_FLAG_EVENT_ITEM: u32 = 0x0000_0008;
const HEADER_BYTES: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WnodeError {
    Bounds,
    Provider,
    Flags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WnodeEventHeader {
    pub buffer_size: u32,
    pub provider_id: u32,
    pub guid: WmiGuid,
    pub flags: u32,
}

pub fn parse_event_header(
    header: &[u8],
    allocation_capacity: usize,
) -> Result<WnodeEventHeader, WnodeError> {
    let bytes = header.get(..HEADER_BYTES).ok_or(WnodeError::Bounds)?;
    let size = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| WnodeError::Bounds)?);
    let size_usize = usize::try_from(size).map_err(|_| WnodeError::Bounds)?;
    if size_usize < HEADER_BYTES || size_usize > allocation_capacity {
        return Err(WnodeError::Bounds);
    }
    let provider_id = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| WnodeError::Bounds)?);
    if provider_id == 0 {
        return Err(WnodeError::Provider);
    }
    let flags = u32::from_le_bytes(bytes[44..48].try_into().map_err(|_| WnodeError::Bounds)?);
    if flags & WNODE_FLAG_EVENT_ITEM == 0 {
        return Err(WnodeError::Flags);
    }
    Ok(WnodeEventHeader {
        buffer_size: size,
        provider_id,
        guid: WmiGuid(bytes[24..40].try_into().map_err(|_| WnodeError::Bounds)?),
        flags,
    })
}
