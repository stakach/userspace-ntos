//! Policy for publishing text returned by an actual PDO QueryDeviceText IRP.
//!
//! The native caller must copy bytes from the retained, generation-checked allocation while its
//! physical pool lock is held. A catalog ticket is required here, but a byte slice by itself is
//! never proof that the bytes came from that allocation. This module grants no pool-free, registry,
//! or PnP-arrival authority. It only prepares a REG_SZ value for a separate durable CM write.

use alloc::vec::Vec;

use crate::returned_pnp_buffer::{
    BufferPhase, ReturnedAllocation, ReturnedPnpBufferCatalog, ReturnedPnpBufferTicket,
    ReturnedPnpQuery, ReturnedPnpRequest,
};

pub const DEVICE_TEXT_DESCRIPTION: u32 = 0;
pub const DEVICE_TEXT_LOCATION_INFORMATION: u32 = 1;
pub const REG_SZ: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceTextPublicationError {
    ForeignOrRetiredTicket,
    WrongRequest,
    WrongQuery,
    WrongPhase,
    ProviderFailure(u32),
    WrongAllocation,
    MissingRead,
    OutOfBounds,
    MalformedUtf16,
    InsufficientResources,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoDeviceText {
    Unsupported(u32),
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceTextRegistryValue {
    pub name: &'static str,
    pub value_type: u32,
    /// Complete little-endian UTF-16 REG_SZ payload, including exactly one terminator.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceTextPublication {
    KeepExistingDescription,
    NoText(NoDeviceText),
    Write(DeviceTextRegistryValue),
}

/// Decide whether one exact PDO result permits a registry write before arrival publication.
///
/// `read` is a copy of the returned allocation starting at Information. Native code must obtain
/// it under the pool lock after checking the exact physical arena and allocation generation.
/// Extra allocation bytes after the first UTF-16 NUL are ignored, as for a C string. The
/// returned value must still be committed by CM before any arrival notification is published.
pub fn plan_device_text_publication(
    catalog: &ReturnedPnpBufferCatalog,
    ticket: ReturnedPnpBufferTicket,
    request: ReturnedPnpRequest,
    allocation: Option<ReturnedAllocation>,
    read: Option<&[u8]>,
    description_exists: bool,
) -> Result<DeviceTextPublication, DeviceTextPublicationError> {
    let snapshot = catalog
        .snapshot(ticket)
        .map_err(|_| DeviceTextPublicationError::ForeignOrRetiredTicket)?;
    if snapshot.request != request {
        return Err(DeviceTextPublicationError::WrongRequest);
    }
    let name = match request.query {
        ReturnedPnpQuery::DeviceText {
            text_type: DEVICE_TEXT_DESCRIPTION,
            ..
        } => "DeviceDesc",
        ReturnedPnpQuery::DeviceText {
            text_type: DEVICE_TEXT_LOCATION_INFORMATION,
            ..
        } => "LocationInformation",
        _ => return Err(DeviceTextPublicationError::WrongQuery),
    };
    match snapshot.phase {
        BufferPhase::TerminalNoBuffer { status } => {
            if allocation.is_some() || read.is_some() {
                return Err(DeviceTextPublicationError::WrongAllocation);
            }
            return match status {
                0xc000_00bb => Ok(DeviceTextPublication::NoText(NoDeviceText::Unsupported(
                    status,
                ))),
                0 => Ok(DeviceTextPublication::NoText(NoDeviceText::Empty)),
                _ => Err(DeviceTextPublicationError::ProviderFailure(status)),
            };
        }
        BufferPhase::Published => {}
        _ => return Err(DeviceTextPublicationError::WrongPhase),
    }
    let owned = snapshot
        .allocation
        .ok_or(DeviceTextPublicationError::WrongAllocation)?;
    if allocation != Some(owned) {
        return Err(DeviceTextPublicationError::WrongAllocation);
    }
    if name == "DeviceDesc" && description_exists {
        return Ok(DeviceTextPublication::KeepExistingDescription);
    }
    let read = read.ok_or(DeviceTextPublicationError::MissingRead)?;
    if read.len() as u64 > owned.pool.capacity || read.len() & 1 != 0 {
        return Err(DeviceTextPublicationError::OutOfBounds);
    }
    let mut units = read
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    let end = units
        .position(|unit| unit == 0)
        .ok_or(DeviceTextPublicationError::MalformedUtf16)?;
    if end == 0 {
        return Ok(DeviceTextPublication::NoText(NoDeviceText::Empty));
    }
    let value_bytes = (end + 1) * 2;
    let mut data = Vec::new();
    data.try_reserve_exact(value_bytes)
        .map_err(|_| DeviceTextPublicationError::InsufficientResources)?;
    data.extend_from_slice(&read[..value_bytes]);
    Ok(DeviceTextPublication::Write(DeviceTextRegistryValue {
        name,
        value_type: REG_SZ,
        data,
    }))
}
