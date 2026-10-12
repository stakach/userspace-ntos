//! Dormant framing for compact SYSTEM mutation journals.
//!
//! This codec does not establish durability. A storage owner must append the exact bytes,
//! complete its barrier, and retain uncertain effects before acknowledging a mutation. Boot
//! replay and checkpoint integration are required before native use.

use alloc::vec::Vec;
use nt_config_store::codec::crc32c;

const MAGIC: [u8; 8] = *b"CMWAL001";
const HEADER_LEN: usize = 44;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalError {
    WrongMount,
    GenerationGap,
    GenerationOverflow,
    EmptyPayload,
    LengthOverflow,
    OutOfMemory,
    BadMagic,
    BadChecksum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalRecord<'a> {
    pub expected_generation: u64,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalScan<'a> {
    /// Complete, checksum-verified records only.
    pub records: Vec<WalRecord<'a>>,
    pub next_generation: u64,
    pub complete_bytes: usize,
    pub torn_tail: bool,
}

/// Frame one already encoded hive mutation journal for a persisted storage incarnation.
/// `mount` must survive reboot; an ephemeral CM mount token is not suitable.
pub fn encode_record(
    mount: u64,
    expected_generation: u64,
    payload: &[u8],
) -> Result<Vec<u8>, WalError> {
    if mount == 0 {
        return Err(WalError::WrongMount);
    }
    if payload.is_empty() {
        return Err(WalError::EmptyPayload);
    }
    let next = expected_generation
        .checked_add(1)
        .ok_or(WalError::GenerationOverflow)?;
    let length = u32::try_from(payload.len()).map_err(|_| WalError::LengthOverflow)?;
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(WalError::LengthOverflow)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| WalError::OutOfMemory)?;
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&mount.to_le_bytes());
    bytes.extend_from_slice(&expected_generation.to_le_bytes());
    bytes.extend_from_slice(&next.to_le_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&crc32c(payload).to_le_bytes());
    let header_crc = crc32c(&bytes);
    bytes.extend_from_slice(&header_crc.to_le_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// Scan the durable prefix. An incomplete trailing record is ignored; a complete invalid
/// record is corruption. The caller must validate each payload's hive-log semantics before
/// publishing any replayed state.
pub fn scan_records<'a>(
    bytes: &'a [u8],
    mount: u64,
    initial_generation: u64,
) -> Result<WalScan<'a>, WalError> {
    if mount == 0 {
        return Err(WalError::WrongMount);
    }
    let mut scan = WalScan {
        records: Vec::new(),
        next_generation: initial_generation,
        complete_bytes: 0,
        torn_tail: false,
    };
    while scan.complete_bytes < bytes.len() {
        let tail = &bytes[scan.complete_bytes..];
        if tail.len() < HEADER_LEN {
            scan.torn_tail = true;
            break;
        }
        let header = &tail[..HEADER_LEN];
        if header[..8] != MAGIC {
            return Err(WalError::BadMagic);
        }
        if u32::from_le_bytes(header[40..44].try_into().unwrap()) != crc32c(&header[..40]) {
            return Err(WalError::BadChecksum);
        }
        let record_mount = u64::from_le_bytes(header[8..16].try_into().unwrap());
        if record_mount != mount {
            return Err(WalError::WrongMount);
        }
        let expected = u64::from_le_bytes(header[16..24].try_into().unwrap());
        let next = u64::from_le_bytes(header[24..32].try_into().unwrap());
        if expected != scan.next_generation || expected.checked_add(1) != Some(next) {
            return Err(WalError::GenerationGap);
        }
        let length = u32::from_le_bytes(header[32..36].try_into().unwrap()) as usize;
        if length == 0 {
            return Err(WalError::EmptyPayload);
        }
        let end = HEADER_LEN
            .checked_add(length)
            .ok_or(WalError::LengthOverflow)?;
        if end > tail.len() {
            scan.torn_tail = true;
            break;
        }
        let payload = &tail[HEADER_LEN..end];
        if u32::from_le_bytes(header[36..40].try_into().unwrap()) != crc32c(payload) {
            return Err(WalError::BadChecksum);
        }
        scan.records.try_reserve(1).map_err(|_| WalError::OutOfMemory)?;
        scan.records.push(WalRecord {
            expected_generation: expected,
            payload,
        });
        scan.complete_bytes += end;
        scan.next_generation = next;
    }
    Ok(scan)
}
