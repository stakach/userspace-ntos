//! File-delta payloads for the physical volume WAL: the changed extents of one existing file and
//! its resulting length. The sector WAL supplies checksums, torn-frame rejection and durability;
//! this codec states only what the file must contain after the record.
//!
//! Records are absolute. Replaying a whole ordered suffix over a snapshot that already holds
//! some of its records converges on the same bytes, so no "previous length" is recorded.
//! Dormant: no native producer or boot replay routes this kind yet.

use alloc::vec::Vec;

const FILE_DELTA_MAGIC: &[u8; 8] = b"NTFDLT01";
const HEADER_BYTES: usize = 48;
const RUN_ENTRY_BYTES: usize = 12;

/// Granularity at which [`changed_file_delta_extents`] compares old and new contents.
pub const FILE_DELTA_BLOCK_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileDeltaWalPayloadError {
    UnknownKind,
    InvalidSequence,
    InvalidIdentity,
    InvalidPath,
    InvalidLength,
    InvalidExtent,
    OutOfMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileDeltaWalReplayError {
    /// The record does not directly follow the previous file delta of this WAL incarnation.
    OutOfOrder,
    MissingFile,
    ForeignIdentity,
    /// Hive logs under an anchored WAL suffix change only through their own append records.
    ProtectedTarget,
    /// The unpublished volume may be partly updated and must be discarded.
    OutOfMemory,
}

/// Bytes the file holds at `offset` once the record is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileDeltaExtent<'a> {
    pub offset: u64,
    pub bytes: &'a [u8],
}

/// Producer view of one delta, before encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileDeltaRecord<'a> {
    /// 1-based position among the file deltas of the current WAL incarnation.
    pub sequence: u64,
    pub file_id: u64,
    pub path: &'a str,
    /// Exact file length after the record; shorter truncates, longer zero-extends.
    pub end_of_file: u64,
    /// Ascending, non-empty, non-overlapping, and inside `end_of_file`.
    pub extents: &'a [FileDeltaExtent<'a>],
}

/// A decoded, validated delta borrowed from its WAL frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileDeltaWalPayload<'a> {
    sequence: u64,
    file_id: u64,
    end_of_file: u64,
    path: &'a str,
    run_table: &'a [u8],
    data: &'a [u8],
}

impl<'a> FileDeltaWalPayload<'a> {
    pub fn sequence(&self) -> u64 { self.sequence }
    pub fn file_id(&self) -> u64 { self.file_id }
    pub fn end_of_file(&self) -> u64 { self.end_of_file }
    pub fn path(&self) -> &'a str { self.path }

    /// The validated extents in ascending offset order.
    pub fn extents(&self) -> impl Iterator<Item = FileDeltaExtent<'a>> {
        let (run_table, data) = (self.run_table, self.data);
        let mut consumed = 0usize;
        run_table.chunks_exact(RUN_ENTRY_BYTES).map(move |entry| {
            let offset = u64::from_le_bytes(entry[..8].try_into().unwrap());
            let len = u32::from_le_bytes(entry[8..].try_into().unwrap()) as usize;
            let bytes = &data[consumed..consumed + len];
            consumed += len;
            FileDeltaExtent { offset, bytes }
        })
    }
}

/// Admits file deltas only in their recorded order. The first record of a replayed suffix
/// sets the position, because an earlier prefix may already be folded into the snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileDeltaReplayCursor {
    last: Option<u64>,
}

impl FileDeltaReplayCursor {
    pub fn new() -> Self { Self::default() }

    pub fn last_applied(&self) -> Option<u64> { self.last }

    pub(crate) fn admits(&self, sequence: u64) -> bool {
        match self.last {
            None => sequence != 0,
            Some(last) => last.checked_add(1) == Some(sequence),
        }
    }

    pub(crate) fn advance(&mut self, sequence: u64) {
        self.last = Some(sequence);
    }
}

fn validate_identity(
    sequence: u64,
    file_id: u64,
    path: &str,
    end_of_file: u64,
) -> Result<(), FileDeltaWalPayloadError> {
    if sequence == 0 {
        return Err(FileDeltaWalPayloadError::InvalidSequence);
    }
    if file_id == 0 {
        return Err(FileDeltaWalPayloadError::InvalidIdentity);
    }
    if !path.starts_with('\\') || path.contains('\0') {
        return Err(FileDeltaWalPayloadError::InvalidPath);
    }
    if end_of_file > i64::MAX as u64 {
        return Err(FileDeltaWalPayloadError::InvalidLength);
    }
    Ok(())
}

/// Runs must be non-empty, ascending, disjoint and inside the final length. Returns their
/// total byte count.
fn validate_runs(
    runs: impl Iterator<Item = (u64, usize)>,
    end_of_file: u64,
) -> Result<usize, FileDeltaWalPayloadError> {
    let mut previous_end = 0u64;
    let mut total = 0usize;
    for (offset, len) in runs {
        let end = u64::try_from(len).ok().and_then(|len| offset.checked_add(len));
        match end {
            Some(end) if len != 0 && offset >= previous_end && end <= end_of_file => {
                previous_end = end;
            }
            _ => return Err(FileDeltaWalPayloadError::InvalidExtent),
        }
        total = total.checked_add(len).ok_or(FileDeltaWalPayloadError::InvalidExtent)?;
    }
    Ok(total)
}

pub fn encode_file_delta_wal_payload(
    record: FileDeltaRecord<'_>,
) -> Result<Vec<u8>, FileDeltaWalPayloadError> {
    validate_identity(record.sequence, record.file_id, record.path, record.end_of_file)?;
    let data_len = validate_runs(
        record.extents.iter().map(|extent| (extent.offset, extent.bytes.len())),
        record.end_of_file,
    )?;
    let too_long = |_| FileDeltaWalPayloadError::InvalidLength;
    let path_len = u32::try_from(record.path.len()).map_err(too_long)?;
    let run_count = u32::try_from(record.extents.len()).map_err(too_long)?;
    let data_len_field = u32::try_from(data_len).map_err(too_long)?;
    let total = record.extents.len().checked_mul(RUN_ENTRY_BYTES)
        .and_then(|runs| runs.checked_add(HEADER_BYTES))
        .and_then(|len| len.checked_add(record.path.len()))
        .and_then(|len| len.checked_add(data_len))
        .filter(|len| u32::try_from(*len).is_ok())
        .ok_or(FileDeltaWalPayloadError::InvalidLength)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| FileDeltaWalPayloadError::OutOfMemory)?;
    bytes.extend_from_slice(FILE_DELTA_MAGIC);
    bytes.extend_from_slice(&record.sequence.to_le_bytes());
    bytes.extend_from_slice(&record.file_id.to_le_bytes());
    bytes.extend_from_slice(&record.end_of_file.to_le_bytes());
    bytes.extend_from_slice(&path_len.to_le_bytes());
    bytes.extend_from_slice(&run_count.to_le_bytes());
    bytes.extend_from_slice(&data_len_field.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(record.path.as_bytes());
    for extent in record.extents {
        bytes.extend_from_slice(&extent.offset.to_le_bytes());
        bytes.extend_from_slice(&(extent.bytes.len() as u32).to_le_bytes());
    }
    for extent in record.extents {
        bytes.extend_from_slice(extent.bytes);
    }
    Ok(bytes)
}

pub fn decode_file_delta_wal_payload(
    bytes: &[u8],
) -> Result<FileDeltaWalPayload<'_>, FileDeltaWalPayloadError> {
    if !bytes.starts_with(FILE_DELTA_MAGIC) {
        return Err(FileDeltaWalPayloadError::UnknownKind);
    }
    if bytes.len() < HEADER_BYTES {
        return Err(FileDeltaWalPayloadError::InvalidLength);
    }
    let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let (sequence, file_id, end_of_file) = (u64_at(8), u64_at(16), u64_at(24));
    let (path_len, run_count, data_len) =
        (u32_at(32) as usize, u32_at(36) as usize, u32_at(40) as usize);
    if u32_at(44) != 0 {
        // A later revision of this kind; this decoder cannot know what the field means.
        return Err(FileDeltaWalPayloadError::UnknownKind);
    }
    let path_end = HEADER_BYTES.checked_add(path_len);
    let runs_end = run_count.checked_mul(RUN_ENTRY_BYTES)
        .and_then(|runs| path_end?.checked_add(runs));
    let (Some(path_end), Some(runs_end)) = (path_end, runs_end) else {
        return Err(FileDeltaWalPayloadError::InvalidLength);
    };
    if runs_end.checked_add(data_len) != Some(bytes.len()) {
        return Err(FileDeltaWalPayloadError::InvalidLength);
    }
    let path = core::str::from_utf8(&bytes[HEADER_BYTES..path_end])
        .map_err(|_| FileDeltaWalPayloadError::InvalidPath)?;
    validate_identity(sequence, file_id, path, end_of_file)?;
    let run_table = &bytes[path_end..runs_end];
    let total = validate_runs(
        run_table.chunks_exact(RUN_ENTRY_BYTES).map(|entry| (
            u64::from_le_bytes(entry[..8].try_into().unwrap()),
            u32::from_le_bytes(entry[8..].try_into().unwrap()) as usize,
        )),
        end_of_file,
    )?;
    if total != data_len {
        return Err(FileDeltaWalPayloadError::InvalidExtent);
    }
    Ok(FileDeltaWalPayload {
        sequence,
        file_id,
        end_of_file,
        path,
        run_table,
        data: &bytes[runs_end..],
    })
}

/// The blocks of `new` that a file currently holding `old` does not already contain once its
/// length is set to `new.len()`. Adjacent changed blocks are joined.
///
/// Setting the length zero-fills everything past the old end, so zero bytes there are not
/// reported. A producer logs the result with `end_of_file = new.len()`.
pub fn changed_file_delta_extents<'a>(
    old: &[u8],
    new: &'a [u8],
) -> Result<Vec<FileDeltaExtent<'a>>, FileDeltaWalPayloadError> {
    let mut extents: Vec<FileDeltaExtent<'a>> = Vec::new();
    let mut run_start = None;
    for (index, block) in new.chunks(FILE_DELTA_BLOCK_BYTES).enumerate() {
        let start = index * FILE_DELTA_BLOCK_BYTES;
        // Bytes of this block the old file also has; the rest lies past its end.
        let old_block = old.get(start..).unwrap_or(&[]);
        let shared = old_block.len().min(block.len());
        let changed = block[..shared] != old_block[..shared]
            || block[shared..].iter().any(|byte| *byte != 0);
        if changed {
            run_start.get_or_insert(start);
            continue;
        }
        if let Some(run) = run_start.take() {
            extents.try_reserve(1).map_err(|_| FileDeltaWalPayloadError::OutOfMemory)?;
            extents.push(FileDeltaExtent { offset: run as u64, bytes: &new[run..start] });
        }
    }
    if let Some(run) = run_start {
        extents.try_reserve(1).map_err(|_| FileDeltaWalPayloadError::OutOfMemory)?;
        extents.push(FileDeltaExtent { offset: run as u64, bytes: &new[run..] });
    }
    Ok(extents)
}

#[cfg(test)]
#[path = "file_delta_wal_payload_tests.rs"]
mod tests;
