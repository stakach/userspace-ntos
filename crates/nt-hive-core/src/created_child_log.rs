//! All-or-nothing decoding and application of a created child and its assigned metadata.

use super::{Hive, HiveLogReplayError, Reader};
use alloc::{string::String, vec::Vec};

pub(super) struct CreatedChild {
    parent: String,
    name: String,
    class_name: Option<String>,
    descriptor: Vec<u8>,
}

fn blob<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], HiveLogReplayError> {
    let size = reader.u32().ok_or(HiveLogReplayError::InvalidPayload)? as usize;
    reader
        .take_slice(size)
        .ok_or(HiveLogReplayError::InvalidPayload)
}

fn string(reader: &mut Reader<'_>) -> Result<String, HiveLogReplayError> {
    let bytes = blob(reader)?;
    if bytes.len() % 2 != 0 {
        return Err(HiveLogReplayError::InvalidPayload);
    }
    let mut result = String::new();
    let capacity = (bytes.len() / 2)
        .checked_mul(3)
        .ok_or(HiveLogReplayError::InvalidPayload)?;
    result
        .try_reserve_exact(capacity)
        .map_err(|_| HiveLogReplayError::OutOfMemory)?;
    for unit in char::decode_utf16(
        bytes
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]])),
    ) {
        result.push(unit.map_err(|_| HiveLogReplayError::InvalidPayload)?);
    }
    Ok(result)
}

pub(super) fn decode(payload: &[u8]) -> Result<CreatedChild, HiveLogReplayError> {
    let mut reader = Reader::new(payload);
    let parent = string(&mut reader)?;
    let name = string(&mut reader)?;
    if parent.contains('\0')
        || (!parent.is_empty() && parent.split('\\').any(str::is_empty))
        || name.is_empty()
        || name.contains(['\\', '\0'])
    {
        return Err(HiveLogReplayError::InvalidPayload);
    }
    let class_name = match reader.u8() {
        Some(0) => None,
        Some(1) => Some(string(&mut reader)?),
        _ => return Err(HiveLogReplayError::InvalidPayload),
    };
    let bytes = blob(&mut reader)?;
    if bytes.is_empty() || !reader.is_empty() {
        return Err(HiveLogReplayError::InvalidPayload);
    }
    let mut descriptor = Vec::new();
    descriptor
        .try_reserve_exact(bytes.len())
        .map_err(|_| HiveLogReplayError::OutOfMemory)?;
    descriptor.extend_from_slice(bytes);
    Ok(CreatedChild {
        parent,
        name,
        class_name,
        descriptor,
    })
}

pub(super) fn apply(hive: &mut Hive, payload: &[u8]) -> Result<(), HiveLogReplayError> {
    let child = decode(payload)?;
    let mut tx = hive.begin_transaction();
    let parent = tx
        .open_key(&child.parent)
        .ok_or(HiveLogReplayError::CreateChild(
            crate::CreateChildError::ParentNotFound,
        ))?;
    tx.try_create_child(parent, child.name, child.class_name, child.descriptor)
        .map_err(HiveLogReplayError::CreateChild)?;
    tx.commit();
    Ok(())
}

#[cfg(test)]
#[path = "created_child_log_tests.rs"]
mod tests;
