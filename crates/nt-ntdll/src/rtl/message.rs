//! Message-table resource helpers for `RtlFindMessage`.
//!
//! ReactOS stores message strings in an `RT_MESSAGETABLE` resource whose payload starts with a
//! `MESSAGE_RESOURCE_DATA`: a block count, an array of `(LowId, HighId, OffsetToEntries)` records,
//! then a run of variable-length `MESSAGE_RESOURCE_ENTRY` records. The DLL export locates the
//! resource with `LdrFindResource_U`/`LdrAccessResource`; this module performs the pure table walk.

/// `STATUS_SUCCESS`.
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
/// `STATUS_MESSAGE_NOT_FOUND`.
pub const STATUS_MESSAGE_NOT_FOUND: u32 = 0xC000_0109;
/// `STATUS_RESOURCE_DATA_NOT_FOUND`.
pub const STATUS_RESOURCE_DATA_NOT_FOUND: u32 = 0xC000_0089;

const MESSAGE_RESOURCE_DATA_HEADER: usize = 4;
const MESSAGE_RESOURCE_BLOCK_SIZE: usize = 12;
const MESSAGE_RESOURCE_ENTRY_HEADER: usize = 4;

#[inline]
fn rd_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Locate `message_id` in a `MESSAGE_RESOURCE_DATA` buffer.
///
/// Returns the byte offset of the matched `MESSAGE_RESOURCE_ENTRY` within `table`.
pub fn find_message_entry(table: &[u8], message_id: u32) -> Result<usize, u32> {
    let block_count = rd_u32(table, 0).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)? as usize;
    let blocks_end = MESSAGE_RESOURCE_DATA_HEADER
        .checked_add(
            block_count
                .checked_mul(MESSAGE_RESOURCE_BLOCK_SIZE)
                .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?,
        )
        .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
    if blocks_end > table.len() {
        return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
    }

    for i in 0..block_count {
        let block = MESSAGE_RESOURCE_DATA_HEADER + i * MESSAGE_RESOURCE_BLOCK_SIZE;
        let low = rd_u32(table, block).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
        let high = rd_u32(table, block + 4).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
        let entries = rd_u32(table, block + 8).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)? as usize;

        if message_id < low {
            return Err(STATUS_MESSAGE_NOT_FOUND);
        }
        if message_id > high {
            continue;
        }
        if entries < blocks_end || entries >= table.len() {
            return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
        }

        let mut entry = entries;
        for _ in 0..(message_id - low) {
            let length = rd_u16(table, entry).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)? as usize;
            if length < MESSAGE_RESOURCE_ENTRY_HEADER {
                return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
            }
            entry = entry
                .checked_add(length)
                .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
            if entry >= table.len() {
                return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
            }
        }

        let length = rd_u16(table, entry).ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)? as usize;
        if length < MESSAGE_RESOURCE_ENTRY_HEADER {
            return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
        }
        let end = entry
            .checked_add(length)
            .ok_or(STATUS_RESOURCE_DATA_NOT_FOUND)?;
        if end > table.len() {
            return Err(STATUS_RESOURCE_DATA_NOT_FOUND);
        }
        return Ok(entry);
    }

    Err(STATUS_MESSAGE_NOT_FOUND)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec::Vec;

    fn push_u16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn push_entry(buf: &mut Vec<u8>, flags: u16, text: &[u8]) -> usize {
        let off = buf.len();
        push_u16(buf, (MESSAGE_RESOURCE_ENTRY_HEADER + text.len()) as u16);
        push_u16(buf, flags);
        buf.extend_from_slice(text);
        off
    }

    #[test]
    fn finds_entry_by_message_id() {
        let mut table = Vec::new();
        push_u32(&mut table, 1); // NumberOfBlocks
        push_u32(&mut table, 100); // LowId
        push_u32(&mut table, 102); // HighId
        push_u32(&mut table, 16); // OffsetToEntries
        let first = push_entry(&mut table, 0, b"one");
        let second = push_entry(&mut table, 0, b"two");
        let third = push_entry(&mut table, 0, b"three");

        assert_eq!(first, 16);
        assert_eq!(find_message_entry(&table, 100), Ok(first));
        assert_eq!(find_message_entry(&table, 101), Ok(second));
        assert_eq!(find_message_entry(&table, 102), Ok(third));
    }

    #[test]
    fn missing_ids_return_message_not_found() {
        let mut table = Vec::new();
        push_u32(&mut table, 1);
        push_u32(&mut table, 10);
        push_u32(&mut table, 10);
        push_u32(&mut table, 16);
        push_entry(&mut table, 0, b"x");

        assert_eq!(find_message_entry(&table, 9), Err(STATUS_MESSAGE_NOT_FOUND));
        assert_eq!(
            find_message_entry(&table, 11),
            Err(STATUS_MESSAGE_NOT_FOUND)
        );
    }

    #[test]
    fn malformed_tables_return_resource_data_not_found() {
        assert_eq!(
            find_message_entry(&[], 1),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND)
        );

        let mut table = Vec::new();
        push_u32(&mut table, 1);
        push_u32(&mut table, 1);
        push_u32(&mut table, 1);
        push_u32(&mut table, 2); // Offset points into the header.
        assert_eq!(
            find_message_entry(&table, 1),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND)
        );

        let mut table = Vec::new();
        push_u32(&mut table, 1);
        push_u32(&mut table, 1);
        push_u32(&mut table, 1);
        push_u32(&mut table, 16);
        push_u16(&mut table, 3); // Entry length smaller than header.
        push_u16(&mut table, 0);
        assert_eq!(
            find_message_entry(&table, 1),
            Err(STATUS_RESOURCE_DATA_NOT_FOUND)
        );
    }
}
