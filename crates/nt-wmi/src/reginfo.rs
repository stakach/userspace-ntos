//! Bounded parser for the x64 `WMIREGINFO` result of `IRP_MN_REGINFO`.
//! It returns owned GUID facts only after the complete header and array pass.

use alloc::vec::Vec;

use crate::WmiGuid;

const HEADER_BYTES: usize = 24;
const GUID_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegInfoError {
    Bounds,
    Chained,
    Allocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredGuid {
    pub guid: WmiGuid,
    pub flags: u32,
    pub instance_count: u32,
    pub instance_info: u64,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let word = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(word.try_into().ok()?))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let word = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(word.try_into().ok()?))
}

pub fn parse_reginfo(bytes: &[u8]) -> Result<Vec<RegisteredGuid>, RegInfoError> {
    if bytes.len() < HEADER_BYTES {
        return Err(RegInfoError::Bounds);
    }
    let total = usize::try_from(u32_at(bytes, 0).ok_or(RegInfoError::Bounds)?)
        .map_err(|_| RegInfoError::Bounds)?;
    if total < HEADER_BYTES || total > bytes.len() {
        return Err(RegInfoError::Bounds);
    }
    if u32_at(bytes, 4).ok_or(RegInfoError::Bounds)? != 0 {
        return Err(RegInfoError::Chained);
    }
    let count = usize::try_from(u32_at(bytes, 16).ok_or(RegInfoError::Bounds)?)
        .map_err(|_| RegInfoError::Bounds)?;
    let end = count
        .checked_mul(GUID_BYTES)
        .and_then(|length| HEADER_BYTES.checked_add(length))
        .ok_or(RegInfoError::Bounds)?;
    if end > total {
        return Err(RegInfoError::Bounds);
    }
    let mut registrations = Vec::new();
    registrations
        .try_reserve(count)
        .map_err(|_| RegInfoError::Allocation)?;
    for index in 0..count {
        let start = HEADER_BYTES + index * GUID_BYTES;
        let guid = bytes
            .get(start..start + 16)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .ok_or(RegInfoError::Bounds)?;
        registrations.push(RegisteredGuid {
            guid: WmiGuid(guid),
            flags: u32_at(bytes, start + 16).ok_or(RegInfoError::Bounds)?,
            instance_count: u32_at(bytes, start + 20).ok_or(RegInfoError::Bounds)?,
            instance_info: u64_at(bytes, start + 24).ok_or(RegInfoError::Bounds)?,
        });
    }
    Ok(registrations)
}
