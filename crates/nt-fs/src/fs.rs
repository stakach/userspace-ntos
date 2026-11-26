//! MemFs (spec §12) + the `FileSystem` facade exposing the Zw* native file APIs (spec §8-§9).
//!
//! MemFs is an in-memory `NtFileSystemRuntime`: a node tree with create-disposition semantics.
//! `FileSystem` owns the volume + [`MountManager`], resolves NT paths, and manages file objects
//! and handles behind the `ZwCreateFile` / `ZwReadFile` / `ZwWriteFile` / `ZwFlushBuffersFile` /
//! `ZwQueryInformationFile` / `ZwClose` surface.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
#[cfg(test)]
use core::sync::atomic::{AtomicUsize, Ordering};
use nt_config_store::codec::{crc32c, crc32c_combine, Crc32c};

use crate::directory::{
    query_directory_by_index, DirectoryEntry, DirectoryQueryResult, DirectoryQueryState,
    MAX_SHORT_NAME,
};
use crate::fat_directory::FileShortName;
use crate::path::{normalize_separators, MountManager, MEMFS_VOLUME};
use crate::snapshot_store::{
    SnapshotBlockDevice, SnapshotBlockStore, SnapshotBlockStoreError, SnapshotPayloadReader,
    SnapshotPayloadSink, StoredSnapshotMetadata, WalSnapshotManifest,
};
use crate::status::*;
use crate::volume_wal_payload::{
    validate_hive_log, HiveLogWalPayload, HiveLogWalReplay, HiveLogWalReplayError,
};

#[cfg(test)]
#[path = "snapshot_crc_compatibility_tests.rs"]
mod snapshot_crc_compatibility_tests;

#[cfg(test)]
#[path = "wal_log_protection_tests.rs"]
mod wal_log_protection_tests;

#[path = "file_delta_replay.rs"]
mod file_delta_replay;

#[path = "file_basic_replay.rs"]
mod file_basic_replay;

#[path = "file_create_replay.rs"]
mod file_create_replay;

#[path = "file_rename_replay.rs"]
mod file_rename_replay;

#[path = "optional_file.rs"]
mod optional_file;

#[path = "file_create.rs"]
mod file_create;

#[path = "delete_disposition.rs"]
mod delete_disposition;

#[path = "basic_information.rs"]
mod basic_information;
pub(crate) use basic_information::BasicInformationChange;
pub use basic_information::PreparedBasicInformation;

#[path = "set_information_effect.rs"]
mod set_information_effect;
pub use set_information_effect::SetInformationEffect;

#[path = "file_object_information.rs"]
mod file_object_information;
pub use file_object_information::FileObjectInformation;

#[path = "file_io_lifetime.rs"]
mod file_io_lifetime;

#[path = "file_io_serialization.rs"]
mod file_io_serialization;
pub use file_io_serialization::{FileCleanupEffects, FileIoState};

#[path = "snapshot_journal.rs"]
mod snapshot_journal;
pub use snapshot_journal::*;

#[path = "snapshot_capacity.rs"]
mod snapshot_capacity;
use snapshot_capacity::{SnapshotBudget, SnapshotReservationKind};
pub use snapshot_capacity::SnapshotCapacityReservation;

/// A MemFs node (spec §12.3). File data and attributes belong to this shared identity; directory
/// entries own names. Directories retain their single parent for `..`, while regular files may have
/// any number of entries and a corresponding link count.
const ZERO_EXTENT_BLOB: usize = usize::MAX;
const MEMFS_SNAPSHOT_MAGIC: [u8; 8] = *b"USNTFS\0\x01";
const MEMFS_SNAPSHOT_VERSION_V1: u16 = 1;
const MEMFS_SNAPSHOT_VERSION_V2: u16 = 2;
const MEMFS_SNAPSHOT_VERSION_V3: u16 = 3;
const MEMFS_SNAPSHOT_VERSION_V4: u16 = 4;
const MEMFS_SNAPSHOT_VERSION_V5: u16 = 5;
const MEMFS_SNAPSHOT_VERSION_V6: u16 = 6;
// V7 stores the allocator high-water in the root record's otherwise unused node key.
const MEMFS_SNAPSHOT_VERSION: u16 = 7;
const MEMFS_SNAPSHOT_HEADER_LEN: usize = 32;
const SNAP_SHORT_NAME_STORAGE_LEN: usize = 1 + MAX_SHORT_NAME * 2;
const SNAP_RECORD_FIXED_LEN: usize = 77 + SNAP_SHORT_NAME_STORAGE_LEN;
const SNAP_EXTENT_HEADER_LEN: usize = 1 + 8;
const MEMFS_ALLOCATION_UNIT: u64 = 0x1000;
const SNAP_REC_DIR: u8 = 1;
const SNAP_REC_FILE: u8 = 2;
const SNAP_REC_LINK: u8 = 3;
const SNAP_EXTENT_ZERO: u8 = 0;
const SNAP_EXTENT_DATA: u8 = 1;

const fn allocation_size_for_eof(end_of_file: u64) -> u64 {
    if end_of_file == 0 {
        0
    } else {
        end_of_file.saturating_add(MEMFS_ALLOCATION_UNIT - 1) & !(MEMFS_ALLOCATION_UNIT - 1)
    }
}

/// A validated MemFs snapshot header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MemFsSnapshotInfo {
    pub version: u16,
    pub record_count: u32,
    pub payload_len: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct MemFsSnapshotHeader {
    info: MemFsSnapshotInfo,
    payload_crc: u32,
}

/// Snapshot decode/validation failures. Snapshots are durable storage input, so malformed bytes are
/// rejected before any partial tree is returned.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MemFsSnapshotError {
    BadMagic,
    BadChecksum,
    Truncated,
    UnsupportedVersion,
    InvalidRecord,
    InvalidPath,
    NameCollision,
    OutOfSpace,
    OutOfMemory,
}

/// Failures while reclaiming immutable file-data blobs that are no longer referenced by a file.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MemFsBlobCompactError {
    CorruptExtent,
    OutOfMemory,
}

/// Immutable blob storage before and after a successful compaction.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MemFsBlobCompaction {
    pub blobs_before: usize,
    pub blobs_after: usize,
    pub bytes_before: usize,
    pub bytes_after: usize,
}

impl MemFsBlobCompaction {
    pub fn reclaimed_blobs(self) -> usize {
        self.blobs_before.saturating_sub(self.blobs_after)
    }

    pub fn reclaimed_bytes(self) -> usize {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

#[derive(Clone, Copy)]
struct FileExtent {
    blob: usize,
    offset: usize,
    len: usize,
}

enum FileData {
    Bytes(Vec<u8>),
    Extents(Vec<FileExtent>),
}

impl FileData {
    fn empty() -> Self {
        Self::Bytes(Vec::new())
    }

    fn len(&self, blobs: &[Vec<u8>]) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Extents(extents) => extents
                .iter()
                .filter(|extent| {
                    extent.blob == ZERO_EXTENT_BLOB
                        || blobs
                            .get(extent.blob)
                            .is_some_and(|blob| extent.offset + extent.len <= blob.len())
                })
                .map(|extent| extent.len)
                .sum(),
        }
    }

    fn read_into(&self, blobs: &[Vec<u8>], offset: u64, out: &mut [u8]) -> usize {
        match self {
            Self::Bytes(bytes) => {
                let start = (offset as usize).min(bytes.len());
                let end = (start + out.len()).min(bytes.len());
                let len = end.saturating_sub(start);
                out[..len].copy_from_slice(&bytes[start..end]);
                len
            }
            Self::Extents(extents) => {
                let mut file_cursor = 0usize;
                let mut requested = offset as usize;
                let mut written = 0usize;
                for extent in extents {
                    if written == out.len() {
                        break;
                    }
                    let extent_end = file_cursor + extent.len;
                    if requested >= extent_end {
                        file_cursor = extent_end;
                        continue;
                    }
                    let within = requested.saturating_sub(file_cursor);
                    let available = extent.len - within;
                    let copy = available.min(out.len() - written);
                    if extent.blob == ZERO_EXTENT_BLOB {
                        out[written..written + copy].fill(0);
                    } else {
                        let Some(blob) = blobs.get(extent.blob) else {
                            return written;
                        };
                        if extent.offset + extent.len > blob.len() {
                            return written;
                        }
                        let blob_start = extent.offset + within;
                        out[written..written + copy]
                            .copy_from_slice(&blob[blob_start..blob_start + copy]);
                    }
                    written += copy;
                    requested += copy;
                    file_cursor = extent_end;
                }
                written
            }
        }
    }

    fn truncate(&mut self, len: usize) {
        match self {
            Self::Bytes(bytes) => bytes.resize(len, 0),
            Self::Extents(extents) => {
                let mut remaining = len;
                let mut keep = 0usize;
                for extent in extents.iter_mut() {
                    if remaining >= extent.len {
                        remaining -= extent.len;
                        keep += 1;
                    } else {
                        extent.len = remaining;
                        if remaining != 0 {
                            keep += 1;
                        }
                        break;
                    }
                }
                extents.truncate(keep);
            }
        }
    }

    fn contiguous_slice<'a>(&'a self, blobs: &'a [Vec<u8>]) -> Option<&'a [u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes.as_slice()),
            Self::Extents(extents) => {
                let Some(first) = extents.first() else {
                    return Some(&[]);
                };
                if first.blob == ZERO_EXTENT_BLOB {
                    return None;
                }
                let blob = blobs.get(first.blob)?;
                let start = first.offset;
                let mut cursor = start;
                for extent in extents {
                    if extent.blob == ZERO_EXTENT_BLOB {
                        return None;
                    }
                    if extent.blob != first.blob || extent.offset != cursor {
                        return None;
                    }
                    cursor += extent.len;
                }
                blob.get(start..cursor)
            }
        }
    }

    fn to_vec(&self, blobs: &[Vec<u8>]) -> Option<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Some(bytes.clone()),
            Self::Extents(_) => {
                let len = self.len(blobs);
                let mut out = Vec::new();
                out.try_reserve_exact(len).ok()?;
                out.resize(len, 0);
                let read = self.read_into(blobs, 0, &mut out);
                if read == len {
                    Some(out)
                } else {
                    None
                }
            }
        }
    }
}

struct SnapshotCrcSink {
    crc: Crc32c,
    len: usize,
}

impl SnapshotCrcSink {
    fn new() -> Self {
        Self {
            crc: Crc32c::new(),
            len: 0,
        }
    }

    fn finish(self) -> (u32, usize) {
        (self.crc.finish(), self.len)
    }
}

impl SnapshotPayloadSink for SnapshotCrcSink {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.crc.update(bytes);
        self.len = self
            .len
            .checked_add(bytes.len())
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        Ok(())
    }
}

struct SnapshotStreamReader<'a, S: SnapshotPayloadReader> {
    source: &'a mut S,
    crc: Crc32c,
    len: usize,
}

impl<'a, S: SnapshotPayloadReader> SnapshotStreamReader<'a, S> {
    fn new(source: &'a mut S) -> Self {
        Self {
            source,
            crc: Crc32c::new(),
            len: 0,
        }
    }

    fn remaining(&self) -> usize {
        self.source.remaining()
    }

    fn read_exact(&mut self, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        self.source.read_exact(out)?;
        self.crc.update(out);
        self.len = self
            .len
            .checked_add(out.len())
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, SnapshotBlockStoreError> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn u32(&mut self) -> Result<u32, SnapshotBlockStoreError> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn u64(&mut self) -> Result<u64, SnapshotBlockStoreError> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn vec(&mut self, len: usize) -> Result<Vec<u8>, SnapshotBlockStoreError> {
        let mut out = Vec::new();
        out.try_reserve_exact(len)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        out.resize(len, 0);
        self.read_exact(&mut out)?;
        Ok(out)
    }

    fn finish(self) -> (u32, usize) {
        (self.crc.finish(), self.len)
    }
}

fn snapshot_error_to_store_error(err: MemFsSnapshotError) -> SnapshotBlockStoreError {
    match err {
        MemFsSnapshotError::OutOfMemory => SnapshotBlockStoreError::OutOfMemory,
        MemFsSnapshotError::OutOfSpace => SnapshotBlockStoreError::OutOfSpace,
        MemFsSnapshotError::BadMagic
        | MemFsSnapshotError::BadChecksum
        | MemFsSnapshotError::Truncated
        | MemFsSnapshotError::UnsupportedVersion
        | MemFsSnapshotError::InvalidRecord
        | MemFsSnapshotError::InvalidPath
        | MemFsSnapshotError::NameCollision => SnapshotBlockStoreError::Corrupt,
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u16_at(out: &mut [u8], value: u16) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn put_u32_at(out: &mut [u8], value: u32) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn put_u64_at(out: &mut [u8], value: u64) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn write_snapshot_short_name(name: FileShortName, out: &mut Vec<u8>) {
    let mut encoded = [0u8; SNAP_SHORT_NAME_STORAGE_LEN];
    write_snapshot_short_name_at(name, &mut encoded);
    out.extend_from_slice(&encoded);
}

fn write_snapshot_short_name_at(name: FileShortName, out: &mut [u8]) {
    debug_assert_eq!(out.len(), SNAP_SHORT_NAME_STORAGE_LEN);
    out.fill(0);
    out[0] = name.units().len() as u8;
    for (index, unit) in name.units().iter().copied().enumerate() {
        put_u16_at(&mut out[1 + index * 2..3 + index * 2], unit);
    }
}

fn decode_snapshot_short_name(bytes: &[u8]) -> Option<FileShortName> {
    if bytes.len() != SNAP_SHORT_NAME_STORAGE_LEN || bytes[0] as usize > MAX_SHORT_NAME {
        return None;
    }
    let len = bytes[0] as usize;
    let mut units = [0u16; MAX_SHORT_NAME];
    for (index, encoded) in bytes[1..].chunks_exact(2).enumerate() {
        units[index] = u16::from_le_bytes([encoded[0], encoded[1]]);
    }
    if units[len..].iter().any(|unit| *unit != 0) || !valid_short_name(&units[..len]) {
        return None;
    }
    FileShortName::from_units(&units[..len])
}

struct SnapshotReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> SnapshotReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], MemFsSnapshotError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(MemFsSnapshotError::Truncated)?;
        let Some(bytes) = self.bytes.get(self.pos..end) else {
            return Err(MemFsSnapshotError::Truncated);
        };
        self.pos = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, MemFsSnapshotError> {
        Ok(*self.take(1)?.first().ok_or(MemFsSnapshotError::Truncated)?)
    }

    fn u16(&mut self) -> Result<u16, MemFsSnapshotError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| MemFsSnapshotError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, MemFsSnapshotError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| MemFsSnapshotError::Truncated)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, MemFsSnapshotError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| MemFsSnapshotError::Truncated)?,
        ))
    }
}

struct MemFsNode {
    file_id: u64,
    is_dir: bool,
    attributes: u32,
    creation_time: u64,
    last_access_time: u64,
    last_write_time: u64,
    change_time: u64,
    link_count: u32,
    parent: u64,
    allocation_size: u64,
    valid_data_length: u64,
    data: FileData,
    children: Vec<MemFsDirEntry>,
}

/// A stable directory-entry identity. Multiple entries may name the same non-directory node; open
/// File objects retain `id` so rename and delete-on-close act on the entry that was actually opened.
struct MemFsDirEntry {
    id: u64,
    folded_name: String,
    created_name: String,
    folded_short_name: String,
    short_name: FileShortName,
    node_id: u64,
}

/// All namespace checks and allocations for one rename, while the volume is unchanged.
struct PreparedRename {
    source: u64,
    source_entry: u64,
    source_parent: u64,
    source_index: usize,
    target_parent: u64,
    replacement_entry: Option<u64>,
    source_is_dir: bool,
    same_entry: bool,
    folded_name: String,
    created_name: String,
    moved_short_name: Option<(FileShortName, String)>,
}

/// A fully allocated directory entry, ready to attach without a fallible operation.
struct PreparedInsertEntry {
    parent: u64,
    node_id: u64,
    next_link_count: u32,
    entry: MemFsDirEntry,
}

enum PreparedLink {
    Unchanged,
    Add { insertion: PreparedInsertEntry, replacement_entry: Option<u64> },
}

/// An in-memory file system (spec §12) — the v0.1 `NtFileSystemRuntime`.
pub struct MemFs {
    nodes: Vec<Option<MemFsNode>>,
    blobs: Vec<Vec<u8>>,
    #[cfg(test)]
    blob_slice_candidates_inspected: AtomicUsize,
    next_file_id: u64,
    next_entry_id: u64,
    current_time_100ns: u64,
}

fn fold(s: &str) -> String {
    s.to_ascii_lowercase()
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFs {
    /// An empty volume with just a root directory.
    pub fn new() -> Self {
        let mut fs = MemFs {
            nodes: Vec::new(),
            blobs: Vec::new(),
            #[cfg(test)]
            blob_slice_candidates_inspected: AtomicUsize::new(0),
            next_file_id: 1,
            next_entry_id: 1,
            current_time_100ns: 0,
        };
        fs.nodes.push(Some(MemFsNode {
            file_id: 0,
            is_dir: true,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            link_count: 1,
            parent: 0,
            allocation_size: 0,
            valid_data_length: 0,
            data: FileData::empty(),
            children: Vec::new(),
        }));
        fs
    }

    fn set_current_time_100ns(&mut self, now: u64) {
        self.current_time_100ns = now;
    }

    fn initialize_timestamps(&mut self, now: u64) -> bool {
        self.current_time_100ns = now;
        let mut changed = false;
        for node in self.nodes.iter_mut().flatten() {
            if node.creation_time == 0 {
                node.creation_time = now;
                changed = true;
            }
            if node.last_access_time == 0 {
                node.last_access_time = now;
                changed = true;
            }
            if node.last_write_time == 0 {
                node.last_write_time = now;
                changed = true;
            }
            if node.change_time == 0 {
                node.change_time = now;
                changed = true;
            }
        }
        changed
    }

    fn touch_write(&mut self, id: u64) {
        let now = self.current_time_100ns;
        if let Some(node) = self.node_mut(id) {
            node.last_write_time = now;
            node.change_time = now;
        }
    }

    fn touch_change(&mut self, id: u64) {
        let now = self.current_time_100ns;
        if let Some(node) = self.node_mut(id) {
            node.change_time = now;
        }
    }

    fn touch_access(&mut self, id: u64) {
        let now = self.current_time_100ns;
        if let Some(node) = self.node_mut(id) {
            node.last_access_time = now;
        }
    }

    /// Remove immutable data blobs that no live file extent references.
    ///
    /// All allocation and extent validation happens before publication. An allocation failure or
    /// corrupt extent therefore leaves both the blob arena and every file unchanged.
    pub fn compact_blobs(&mut self) -> Result<MemFsBlobCompaction, MemFsBlobCompactError> {
        const UNUSED: usize = usize::MAX;
        const REFERENCED: usize = usize::MAX - 1;

        let blobs_before = self.blobs.len();
        let bytes_before = self.blobs.iter().map(Vec::len).sum();
        let mut remap = Vec::new();
        remap
            .try_reserve_exact(blobs_before)
            .map_err(|_| MemFsBlobCompactError::OutOfMemory)?;
        remap.resize(blobs_before, UNUSED);

        for node in self.nodes.iter().flatten() {
            let FileData::Extents(extents) = &node.data else {
                continue;
            };
            for extent in extents {
                if extent.blob == ZERO_EXTENT_BLOB || extent.len == 0 {
                    continue;
                }
                let blob = self
                    .blobs
                    .get(extent.blob)
                    .ok_or(MemFsBlobCompactError::CorruptExtent)?;
                let end = extent
                    .offset
                    .checked_add(extent.len)
                    .ok_or(MemFsBlobCompactError::CorruptExtent)?;
                if end > blob.len() {
                    return Err(MemFsBlobCompactError::CorruptExtent);
                }
                remap[extent.blob] = REFERENCED;
            }
        }

        let mut blobs_after = 0usize;
        for mapped in &mut remap {
            if *mapped == REFERENCED {
                *mapped = blobs_after;
                blobs_after += 1;
            }
        }
        if blobs_after == blobs_before {
            return Ok(MemFsBlobCompaction {
                blobs_before,
                blobs_after,
                bytes_before,
                bytes_after: bytes_before,
            });
        }
        let mut compacted = Vec::new();
        compacted
            .try_reserve_exact(blobs_after)
            .map_err(|_| MemFsBlobCompactError::OutOfMemory)?;

        let old_blobs = core::mem::take(&mut self.blobs);
        for (old_index, blob) in old_blobs.into_iter().enumerate() {
            if remap[old_index] != UNUSED {
                compacted.push(blob);
            }
        }
        let bytes_after = compacted.iter().map(Vec::len).sum();
        self.blobs = compacted;
        for node in self.nodes.iter_mut().flatten() {
            let FileData::Extents(extents) = &mut node.data else {
                continue;
            };
            for extent in extents {
                if extent.blob != ZERO_EXTENT_BLOB && extent.len != 0 {
                    extent.blob = remap[extent.blob];
                }
            }
        }

        Ok(MemFsBlobCompaction {
            blobs_before,
            blobs_after,
            bytes_before,
            bytes_after,
        })
    }

    /// The default fixture tree (spec §12.2): `\Windows\System32\Config\{SYSTEM,SOFTWARE,…}` +
    /// `\Temp\`, with empty hive files.
    pub fn with_fixture() -> Self {
        let mut fs = MemFs::new();
        let config = fs.ensure_dir(r"\Windows\System32\Config");
        for hive in ["SYSTEM", "SOFTWARE", "SECURITY", "SAM", "DEFAULT"] {
            fs.create_child(config, hive, false);
        }
        fs.ensure_dir(r"\Temp");
        fs
    }

    fn snapshot_header(bytes: &[u8]) -> Result<MemFsSnapshotHeader, MemFsSnapshotError> {
        if bytes.len() != MEMFS_SNAPSHOT_HEADER_LEN {
            return Err(MemFsSnapshotError::Truncated);
        }
        let mut r = SnapshotReader::new(bytes);
        if r.take(MEMFS_SNAPSHOT_MAGIC.len())? != MEMFS_SNAPSHOT_MAGIC {
            return Err(MemFsSnapshotError::BadMagic);
        }
        let header_len = r.u16()? as usize;
        if header_len != MEMFS_SNAPSHOT_HEADER_LEN {
            return Err(MemFsSnapshotError::UnsupportedVersion);
        }
        let version = r.u16()?;
        if !matches!(
            version,
            MEMFS_SNAPSHOT_VERSION_V1
                | MEMFS_SNAPSHOT_VERSION_V2
                | MEMFS_SNAPSHOT_VERSION_V3
                | MEMFS_SNAPSHOT_VERSION_V4
                | MEMFS_SNAPSHOT_VERSION_V5
                | MEMFS_SNAPSHOT_VERSION_V6
                | MEMFS_SNAPSHOT_VERSION
        ) {
            return Err(MemFsSnapshotError::UnsupportedVersion);
        }
        let record_count = r.u32()?;
        let payload_len = r.u64()?;
        let payload_crc = r.u32()?;
        let header_crc = r.u32()?;
        if crc32c(&bytes[..MEMFS_SNAPSHOT_HEADER_LEN - 4]) != header_crc {
            return Err(MemFsSnapshotError::BadChecksum);
        }
        Ok(MemFsSnapshotHeader {
            info: MemFsSnapshotInfo {
                version,
                record_count,
                payload_len,
            },
            payload_crc,
        })
    }

    /// Parse and validate a snapshot header without restoring the tree.
    pub fn snapshot_info(bytes: &[u8]) -> Result<MemFsSnapshotInfo, MemFsSnapshotError> {
        if bytes.len() < MEMFS_SNAPSHOT_HEADER_LEN {
            return Err(MemFsSnapshotError::Truncated);
        }
        let header = Self::snapshot_header(&bytes[..MEMFS_SNAPSHOT_HEADER_LEN])?;
        let payload_len_usize = usize::try_from(header.info.payload_len)
            .map_err(|_| MemFsSnapshotError::InvalidRecord)?;
        let end = MEMFS_SNAPSHOT_HEADER_LEN
            .checked_add(payload_len_usize)
            .ok_or(MemFsSnapshotError::InvalidRecord)?;
        if bytes.len() < end {
            return Err(MemFsSnapshotError::Truncated);
        }
        if bytes.len() != end {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        if crc32c(&bytes[MEMFS_SNAPSHOT_HEADER_LEN..end]) != header.payload_crc {
            return Err(MemFsSnapshotError::BadChecksum);
        }
        Ok(header.info)
    }

    fn snapshot_header_payload_len(
        header: MemFsSnapshotHeader,
    ) -> Result<usize, MemFsSnapshotError> {
        let payload_len_usize = usize::try_from(header.info.payload_len)
            .map_err(|_| MemFsSnapshotError::InvalidRecord)?;
        MEMFS_SNAPSHOT_HEADER_LEN
            .checked_add(payload_len_usize)
            .ok_or(MemFsSnapshotError::InvalidRecord)?;
        Ok(payload_len_usize)
    }

    /// Serialize the volume tree to a versioned, checksummed snapshot. Open FILE_OBJECT handles are
    /// intentionally not part of the image; a restored boot reopens files through normal Zw paths.
    pub fn to_snapshot(&self) -> Result<Vec<u8>, MemFsSnapshotError> {
        let mut out = Vec::new();
        self.write_snapshot_into(&mut out)?;
        Ok(out)
    }

    /// Exact byte length of the current serialized snapshot, including its format header.
    pub fn snapshot_encoded_len(&self) -> Result<usize, MemFsSnapshotError> {
        self.measure_snapshot(&mut String::new()).map(|(_, total_len)| total_len)
    }

    fn measure_snapshot(&self, path: &mut String) -> Result<(u32, usize), MemFsSnapshotError> {
        let root = self.node(0).ok_or(MemFsSnapshotError::InvalidRecord)?;
        let mut record_count = 1u32;
        let mut measured_files = Vec::new();
        let payload_len = self
            .snapshot_record_len("", root, false, FileShortName::EMPTY)?
            .checked_add(self.measure_snapshot_children(
                0,
                path,
                &mut measured_files,
                &mut record_count,
            )?)
            .ok_or(MemFsSnapshotError::InvalidRecord)?;

        let total_len = MEMFS_SNAPSHOT_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(MemFsSnapshotError::InvalidRecord)?;
        Ok((record_count, total_len))
    }

    /// Replace a caller-owned capture with the exact current snapshot, retaining its allocation
    /// for later captures. The caller must keep these bytes immutable through physical commit.
    pub fn write_snapshot_into(&self, out: &mut Vec<u8>) -> Result<(), MemFsSnapshotError> {
        let mut path = String::new();
        let (record_count, total_len) = self.measure_snapshot(&mut path)?;
        let root = self.node(0).ok_or(MemFsSnapshotError::InvalidRecord)?;
        let payload_len = total_len - MEMFS_SNAPSHOT_HEADER_LEN;
        out.clear();
        if out.capacity() < total_len {
            // The capture is empty, so release it before reserving: the old block can then
            // serve the request, and the two never coexist. An amortized reservation would
            // double an allocation the size of the whole volume. An eighth of slack lets the
            // volume grow for a while before the capture has to move again.
            *out = Vec::new();
            let with_slack = total_len.saturating_add(total_len / 8);
            if out.try_reserve_exact(with_slack).is_err() {
                out.try_reserve_exact(total_len)
                    .map_err(|_| MemFsSnapshotError::OutOfMemory)?;
            }
        }
        out.resize(MEMFS_SNAPSHOT_HEADER_LEN, 0);
        self.write_snapshot_record("", root, false, FileShortName::EMPTY, out)?;
        let mut written_records = 1u32;
        let mut written_files = Vec::new();
        self.write_snapshot_children(
            0,
            &mut path,
            &mut written_files,
            out,
            &mut written_records,
        )?;
        if written_records != record_count || out.len() != total_len {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        let payload_crc = crc32c(&out[MEMFS_SNAPSHOT_HEADER_LEN..]);
        Self::write_snapshot_header(
            &mut out[..MEMFS_SNAPSHOT_HEADER_LEN],
            record_count,
            payload_len as u64,
            payload_crc,
        );
        Ok(())
    }

    /// Restore a volume from [`Self::to_snapshot`] bytes.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, MemFsSnapshotError> {
        let info = Self::snapshot_info(bytes)?;
        let mut fs = MemFs::new();
        let payload = &bytes[MEMFS_SNAPSHOT_HEADER_LEN..];
        let mut r = SnapshotReader::new(payload);
        let mut seen = 0u32;
        let mut hardlink_nodes = Vec::new();
        let mut next_file_id = None;
        let mut max_node_file_id = 0;
        while !r.is_empty() {
            let kind = r.u8()?;
            let attributes = r.u32()?;
            let path_len =
                usize::try_from(r.u32()?).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
            let node_key = if info.version >= MEMFS_SNAPSHOT_VERSION_V2 {
                r.u64()?
            } else {
                0
            };
            let times = if info.version >= MEMFS_SNAPSHOT_VERSION_V3 {
                [r.u64()?, r.u64()?, r.u64()?, r.u64()?]
            } else {
                [0; 4]
            };
            let logical_len_u64 = r.u64()?;
            let logical_len =
                usize::try_from(logical_len_u64).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
            let allocation_size = if info.version >= MEMFS_SNAPSHOT_VERSION_V4 {
                r.u64()?
            } else {
                allocation_size_for_eof(logical_len_u64)
            };
            let valid_data_length = if info.version >= MEMFS_SNAPSHOT_VERSION_V5 {
                r.u64()?
            } else {
                logical_len_u64
            };
            let extent_count =
                usize::try_from(r.u32()?).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
            let short_name = if info.version >= MEMFS_SNAPSHOT_VERSION_V6 {
                decode_snapshot_short_name(r.take(SNAP_SHORT_NAME_STORAGE_LEN)?)
                    .ok_or(MemFsSnapshotError::InvalidRecord)?
            } else {
                FileShortName::EMPTY
            };
            let path_bytes = r.take(path_len)?;
            let path =
                core::str::from_utf8(path_bytes).map_err(|_| MemFsSnapshotError::InvalidPath)?;
            if path.is_empty() {
                if info.version < MEMFS_SNAPSHOT_VERSION_V3
                    || seen != 0
                    || kind != SNAP_REC_DIR
                    || (info.version >= MEMFS_SNAPSHOT_VERSION && node_key == 0)
                    || (info.version < MEMFS_SNAPSHOT_VERSION && node_key != 0)
                    || logical_len != 0
                    || allocation_size != 0
                    || valid_data_length != 0
                    || extent_count != 0
                    || !short_name.units().is_empty()
                {
                    return Err(MemFsSnapshotError::InvalidRecord);
                }
                let root = fs.node_mut(0).ok_or(MemFsSnapshotError::InvalidRecord)?;
                root.attributes = attributes | FILE_ATTRIBUTE_DIRECTORY;
                root.creation_time = times[0];
                root.last_access_time = times[1];
                root.last_write_time = times[2];
                root.change_time = times[3];
                if info.version >= MEMFS_SNAPSHOT_VERSION {
                    next_file_id = Some(node_key);
                }
                seen = 1;
                continue;
            }
            if kind == SNAP_REC_LINK {
                if info.version < MEMFS_SNAPSHOT_VERSION_V2
                    || node_key == 0
                    || logical_len != 0
                    || allocation_size != 0
                    || valid_data_length != 0
                    || extent_count != 0
                {
                    return Err(MemFsSnapshotError::InvalidRecord);
                }
                let target = hardlink_nodes
                    .iter()
                    .find(|(key, _)| *key == node_key)
                    .map(|(_, id)| *id)
                    .ok_or(MemFsSnapshotError::InvalidRecord)?;
                let entry_id = fs.restore_snapshot_link(path, target, attributes, times)?;
                fs.restore_entry_short_name(entry_id, short_name)?;
                seen = seen
                    .checked_add(1)
                    .ok_or(MemFsSnapshotError::InvalidRecord)?;
                continue;
            }
            let is_dir = match kind {
                SNAP_REC_DIR => true,
                SNAP_REC_FILE => false,
                _ => return Err(MemFsSnapshotError::InvalidRecord),
            };
            let file_id = if info.version >= MEMFS_SNAPSHOT_VERSION_V2 {
                max_node_file_id = max_node_file_id.max(node_key);
                Some(node_key)
            } else {
                None
            };
            let (id, entry_id) =
                fs.restore_snapshot_node(path, is_dir, attributes, times, file_id)?;
            fs.restore_entry_short_name(entry_id, short_name)?;
            if is_dir {
                if logical_len != 0
                    || allocation_size != 0
                    || valid_data_length != 0
                    || extent_count != 0
                {
                    return Err(MemFsSnapshotError::InvalidRecord);
                }
            } else {
                if allocation_size & (MEMFS_ALLOCATION_UNIT - 1) != 0
                    || allocation_size < allocation_size_for_eof(logical_len_u64)
                    || valid_data_length > logical_len_u64
                {
                    return Err(MemFsSnapshotError::InvalidRecord);
                }
                let data = fs.read_snapshot_file_data(&mut r, logical_len, extent_count)?;
                let Some(node) = fs.node_mut(id) else {
                    return Err(MemFsSnapshotError::InvalidRecord);
                };
                node.allocation_size = allocation_size;
                node.valid_data_length = valid_data_length;
                node.data = data;
                if info.version >= MEMFS_SNAPSHOT_VERSION_V2 {
                    if node_key == 0
                        || hardlink_nodes.iter().any(|(key, _)| *key == node_key)
                        || hardlink_nodes.try_reserve_exact(1).is_err()
                    {
                        return Err(MemFsSnapshotError::InvalidRecord);
                    }
                    hardlink_nodes.push((node_key, id));
                }
            }
            seen = seen
                .checked_add(1)
                .ok_or(MemFsSnapshotError::InvalidRecord)?;
        }
        if seen != info.record_count {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        if let Some(next_file_id) = next_file_id {
            if max_node_file_id >= next_file_id {
                return Err(MemFsSnapshotError::InvalidRecord);
            }
            fs.next_file_id = next_file_id;
        }
        Ok(fs)
    }

    fn from_snapshot_reader<S: SnapshotPayloadReader>(
        source: &mut S,
    ) -> Result<Self, SnapshotBlockStoreError> {
        let total_len = source.remaining();
        if total_len < MEMFS_SNAPSHOT_HEADER_LEN {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let mut header_bytes = [0u8; MEMFS_SNAPSHOT_HEADER_LEN];
        source.read_exact(&mut header_bytes)?;
        let header = Self::snapshot_header(&header_bytes).map_err(snapshot_error_to_store_error)?;
        let payload_len =
            Self::snapshot_header_payload_len(header).map_err(snapshot_error_to_store_error)?;
        if source.remaining() != payload_len {
            return Err(SnapshotBlockStoreError::Corrupt);
        }

        let mut fs = MemFs::new();
        let mut r = SnapshotStreamReader::new(source);
        let mut seen = 0u32;
        let mut hardlink_nodes = Vec::new();
        let mut next_file_id = None;
        let mut max_node_file_id = 0;
        while r.remaining() != 0 {
            let kind = r.u8()?;
            let attributes = r.u32()?;
            let path_len =
                usize::try_from(r.u32()?).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
            let node_key = if header.info.version >= MEMFS_SNAPSHOT_VERSION_V2 {
                r.u64()?
            } else {
                0
            };
            let times = if header.info.version >= MEMFS_SNAPSHOT_VERSION_V3 {
                [r.u64()?, r.u64()?, r.u64()?, r.u64()?]
            } else {
                [0; 4]
            };
            let logical_len_u64 = r.u64()?;
            let logical_len =
                usize::try_from(logical_len_u64).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
            let allocation_size = if header.info.version >= MEMFS_SNAPSHOT_VERSION_V4 {
                r.u64()?
            } else {
                allocation_size_for_eof(logical_len_u64)
            };
            let valid_data_length = if header.info.version >= MEMFS_SNAPSHOT_VERSION_V5 {
                r.u64()?
            } else {
                logical_len_u64
            };
            let extent_count =
                usize::try_from(r.u32()?).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
            let short_name = if header.info.version >= MEMFS_SNAPSHOT_VERSION_V6 {
                let encoded = r.vec(SNAP_SHORT_NAME_STORAGE_LEN)?;
                decode_snapshot_short_name(&encoded).ok_or(SnapshotBlockStoreError::Corrupt)?
            } else {
                FileShortName::EMPTY
            };
            let path_bytes = r.vec(path_len)?;
            let path =
                core::str::from_utf8(&path_bytes).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
            if path.is_empty() {
                if header.info.version < MEMFS_SNAPSHOT_VERSION_V3
                    || seen != 0
                    || kind != SNAP_REC_DIR
                    || (header.info.version >= MEMFS_SNAPSHOT_VERSION && node_key == 0)
                    || (header.info.version < MEMFS_SNAPSHOT_VERSION && node_key != 0)
                    || logical_len != 0
                    || allocation_size != 0
                    || valid_data_length != 0
                    || extent_count != 0
                    || !short_name.units().is_empty()
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                let root = fs.node_mut(0).ok_or(SnapshotBlockStoreError::Corrupt)?;
                root.attributes = attributes | FILE_ATTRIBUTE_DIRECTORY;
                root.creation_time = times[0];
                root.last_access_time = times[1];
                root.last_write_time = times[2];
                root.change_time = times[3];
                if header.info.version >= MEMFS_SNAPSHOT_VERSION {
                    next_file_id = Some(node_key);
                }
                seen = 1;
                continue;
            }
            if kind == SNAP_REC_LINK {
                if header.info.version < MEMFS_SNAPSHOT_VERSION_V2
                    || node_key == 0
                    || logical_len != 0
                    || allocation_size != 0
                    || valid_data_length != 0
                    || extent_count != 0
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                let target = hardlink_nodes
                    .iter()
                    .find(|(key, _)| *key == node_key)
                    .map(|(_, id)| *id)
                    .ok_or(SnapshotBlockStoreError::Corrupt)?;
                let entry_id = fs
                    .restore_snapshot_link(path, target, attributes, times)
                    .map_err(snapshot_error_to_store_error)?;
                fs.restore_entry_short_name(entry_id, short_name)
                    .map_err(snapshot_error_to_store_error)?;
                seen = seen
                    .checked_add(1)
                    .ok_or(SnapshotBlockStoreError::Corrupt)?;
                continue;
            }
            let is_dir = match kind {
                SNAP_REC_DIR => true,
                SNAP_REC_FILE => false,
                _ => return Err(SnapshotBlockStoreError::Corrupt),
            };
            if header.info.version >= MEMFS_SNAPSHOT_VERSION_V2 {
                max_node_file_id = max_node_file_id.max(node_key);
            }
            let (id, entry_id) = fs
                .restore_snapshot_node(
                    path,
                    is_dir,
                    attributes,
                    times,
                    (header.info.version >= MEMFS_SNAPSHOT_VERSION_V2).then_some(node_key),
                )
                .map_err(snapshot_error_to_store_error)?;
            fs.restore_entry_short_name(entry_id, short_name)
                .map_err(snapshot_error_to_store_error)?;
            if is_dir {
                if logical_len != 0
                    || allocation_size != 0
                    || valid_data_length != 0
                    || extent_count != 0
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
            } else {
                if allocation_size & (MEMFS_ALLOCATION_UNIT - 1) != 0
                    || allocation_size < allocation_size_for_eof(logical_len_u64)
                    || valid_data_length > logical_len_u64
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                let data =
                    fs.read_snapshot_file_data_streaming(&mut r, logical_len, extent_count)?;
                let Some(node) = fs.node_mut(id) else {
                    return Err(SnapshotBlockStoreError::Corrupt);
                };
                node.allocation_size = allocation_size;
                node.valid_data_length = valid_data_length;
                node.data = data;
                if header.info.version >= MEMFS_SNAPSHOT_VERSION_V2 {
                    if node_key == 0
                        || hardlink_nodes.iter().any(|(key, _)| *key == node_key)
                        || hardlink_nodes.try_reserve_exact(1).is_err()
                    {
                        return Err(SnapshotBlockStoreError::Corrupt);
                    }
                    hardlink_nodes.push((node_key, id));
                }
            }
            seen = seen
                .checked_add(1)
                .ok_or(SnapshotBlockStoreError::Corrupt)?;
        }
        if seen != header.info.record_count {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        if let Some(next_file_id) = next_file_id {
            if max_node_file_id >= next_file_id {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            fs.next_file_id = next_file_id;
        }
        let (payload_crc, payload_read) = r.finish();
        if payload_read != payload_len || payload_crc != header.payload_crc {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(fs)
    }

    fn commit_snapshot_to_store<D: SnapshotBlockDevice>(
        &self,
        store: &SnapshotBlockStore,
        dev: &mut D,
        wal: Option<WalSnapshotManifest>,
        empty_wal_migration: bool,
    ) -> Result<(u64, usize), SnapshotBlockStoreError> {
        let mut payload_crc_sink = SnapshotCrcSink::new();
        let record_count = self.write_snapshot_payload_to_sink(&mut payload_crc_sink)?;
        let (payload_crc, payload_written) = payload_crc_sink.finish();
        let payload_len = payload_written;
        let total_len = MEMFS_SNAPSHOT_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(SnapshotBlockStoreError::Corrupt)?;

        let payload_len_u64 =
            u64::try_from(payload_len).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
        let mut header = [0u8; MEMFS_SNAPSHOT_HEADER_LEN];
        Self::write_snapshot_header(&mut header, record_count, payload_len_u64, payload_crc);

        let store_payload_crc = crc32c_combine(crc32c(&header), payload_crc, payload_len_u64);

        let write_payload = |writer: &mut crate::snapshot_store::PayloadSectorWriter<'_, D>| {
            writer.write_all(&header)?;
            let written_records = self.write_snapshot_payload_to_sink(writer)?;
            if written_records != record_count {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            Ok(())
        };
        let generation = match wal {
            Some(manifest) if empty_wal_migration => store.commit_next_streaming_for_empty_wal_migration(
                dev,
                total_len,
                store_payload_crc,
                manifest,
                write_payload,
            )?,
            Some(manifest) => store.commit_next_streaming_with_wal_manifest(
                dev,
                total_len,
                store_payload_crc,
                manifest,
                write_payload,
            )?,
            None => store.commit_next_streaming(dev, total_len, store_payload_crc, write_payload)?,
        };
        Ok((generation, total_len))
    }

    fn node(&self, id: u64) -> Option<&MemFsNode> {
        self.nodes.get(id as usize)?.as_ref()
    }
    fn node_mut(&mut self, id: u64) -> Option<&mut MemFsNode> {
        self.nodes.get_mut(id as usize)?.as_mut()
    }

    fn write_snapshot_children(
        &self,
        parent: u64,
        path: &mut String,
        seen_files: &mut Vec<u64>,
        out: &mut Vec<u8>,
        record_count: &mut u32,
    ) -> Result<(), MemFsSnapshotError> {
        let Some(node) = self.node(parent) else {
            return Err(MemFsSnapshotError::InvalidRecord);
        };
        if !node.is_dir {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        for entry in &node.children {
            let name = &entry.created_name;
            let child_id = entry.node_id;
            let Some(child) = self.node(child_id) else {
                return Err(MemFsSnapshotError::InvalidRecord);
            };
            let prefix_len = path.len();
            let extra_sep = usize::from(prefix_len != 0);
            path.try_reserve_exact(extra_sep + name.len())
                .map_err(|_| MemFsSnapshotError::OutOfMemory)?;
            if prefix_len != 0 {
                path.push('\\');
            }
            path.push_str(name);
            let link_only = if child.is_dir {
                false
            } else if seen_files.contains(&child_id) {
                true
            } else {
                seen_files
                    .try_reserve_exact(1)
                    .map_err(|_| MemFsSnapshotError::OutOfMemory)?;
                seen_files.push(child_id);
                false
            };
            self.write_snapshot_record(path, child, link_only, entry.short_name, out)?;
            *record_count = record_count
                .checked_add(1)
                .ok_or(MemFsSnapshotError::InvalidRecord)?;
            if child.is_dir {
                self.write_snapshot_children(child_id, path, seen_files, out, record_count)?;
            }
            path.truncate(prefix_len);
        }
        Ok(())
    }

    fn write_snapshot_payload_to_sink<S: SnapshotPayloadSink>(
        &self,
        sink: &mut S,
    ) -> Result<u32, SnapshotBlockStoreError> {
        let root = self.node(0).ok_or(SnapshotBlockStoreError::Corrupt)?;
        self.write_snapshot_record_to_sink("", root, false, FileShortName::EMPTY, sink)?;
        let mut record_count = 1u32;
        let mut path = String::new();
        let mut seen_files = Vec::new();
        self.write_snapshot_children_to_sink(
            0,
            &mut path,
            &mut seen_files,
            sink,
            &mut record_count,
        )?;
        Ok(record_count)
    }

    fn write_snapshot_children_to_sink<S: SnapshotPayloadSink>(
        &self,
        parent: u64,
        path: &mut String,
        seen_files: &mut Vec<u64>,
        sink: &mut S,
        record_count: &mut u32,
    ) -> Result<(), SnapshotBlockStoreError> {
        let Some(node) = self.node(parent) else {
            return Err(SnapshotBlockStoreError::Corrupt);
        };
        if !node.is_dir {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        for entry in &node.children {
            let name = &entry.created_name;
            let child_id = entry.node_id;
            let Some(child) = self.node(child_id) else {
                return Err(SnapshotBlockStoreError::Corrupt);
            };
            let prefix_len = path.len();
            let extra_sep = usize::from(prefix_len != 0);
            path.try_reserve_exact(extra_sep + name.len())
                .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
            if prefix_len != 0 {
                path.push('\\');
            }
            path.push_str(name);
            let link_only = if child.is_dir {
                false
            } else if seen_files.contains(&child_id) {
                true
            } else {
                seen_files
                    .try_reserve_exact(1)
                    .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
                seen_files.push(child_id);
                false
            };
            self.write_snapshot_record_to_sink(path, child, link_only, entry.short_name, sink)?;
            *record_count = record_count
                .checked_add(1)
                .ok_or(SnapshotBlockStoreError::Corrupt)?;
            if child.is_dir {
                self.write_snapshot_children_to_sink(
                    child_id,
                    path,
                    seen_files,
                    sink,
                    record_count,
                )?;
            }
            path.truncate(prefix_len);
        }
        Ok(())
    }

    fn measure_snapshot_children(
        &self,
        parent: u64,
        path: &mut String,
        seen_files: &mut Vec<u64>,
        record_count: &mut u32,
    ) -> Result<usize, MemFsSnapshotError> {
        let Some(node) = self.node(parent) else {
            return Err(MemFsSnapshotError::InvalidRecord);
        };
        if !node.is_dir {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        let mut total = 0usize;
        for entry in &node.children {
            let name = &entry.created_name;
            let child_id = entry.node_id;
            let Some(child) = self.node(child_id) else {
                return Err(MemFsSnapshotError::InvalidRecord);
            };
            let prefix_len = path.len();
            let extra_sep = usize::from(prefix_len != 0);
            path.try_reserve_exact(extra_sep + name.len())
                .map_err(|_| MemFsSnapshotError::OutOfMemory)?;
            if prefix_len != 0 {
                path.push('\\');
            }
            path.push_str(name);
            let link_only = if child.is_dir {
                false
            } else if seen_files.contains(&child_id) {
                true
            } else {
                seen_files
                    .try_reserve_exact(1)
                    .map_err(|_| MemFsSnapshotError::OutOfMemory)?;
                seen_files.push(child_id);
                false
            };
            total = total
                .checked_add(self.snapshot_record_len(path, child, link_only, entry.short_name)?)
                .ok_or(MemFsSnapshotError::InvalidRecord)?;
            *record_count = record_count
                .checked_add(1)
                .ok_or(MemFsSnapshotError::InvalidRecord)?;
            if child.is_dir {
                total = total
                    .checked_add(self.measure_snapshot_children(
                        child_id,
                        path,
                        seen_files,
                        record_count,
                    )?)
                    .ok_or(MemFsSnapshotError::InvalidRecord)?;
            }
            path.truncate(prefix_len);
        }
        Ok(total)
    }

    fn snapshot_record_len(
        &self,
        path: &str,
        node: &MemFsNode,
        link_only: bool,
        short_name: FileShortName,
    ) -> Result<usize, MemFsSnapshotError> {
        let path_len = u32::try_from(path.len()).map_err(|_| MemFsSnapshotError::InvalidPath)?;
        let end_of_file = node.data.len(&self.blobs) as u64;
        if (node.is_dir && (node.allocation_size != 0 || node.valid_data_length != 0))
            || (!node.is_dir
                && (node.allocation_size & (MEMFS_ALLOCATION_UNIT - 1) != 0
                    || node.allocation_size < allocation_size_for_eof(end_of_file)
                    || node.valid_data_length > end_of_file))
        {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        let data_len = if node.is_dir || link_only {
            0
        } else {
            Self::snapshot_file_data_encoded_len(&self.blobs, &node.data)?
        };
        if !valid_short_name(short_name.units()) {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        SNAP_RECORD_FIXED_LEN
            .checked_add(path_len as usize)
            .and_then(|n| n.checked_add(data_len))
            .ok_or(MemFsSnapshotError::InvalidRecord)
    }

    fn write_snapshot_record(
        &self,
        path: &str,
        node: &MemFsNode,
        link_only: bool,
        short_name: FileShortName,
        out: &mut Vec<u8>,
    ) -> Result<(), MemFsSnapshotError> {
        let path_len = u32::try_from(path.len()).map_err(|_| MemFsSnapshotError::InvalidPath)?;
        let logical_len = if node.is_dir || link_only {
            0
        } else {
            node.data.len(&self.blobs) as u64
        };
        let allocation_size = if node.is_dir || link_only {
            0
        } else {
            node.allocation_size
        };
        let valid_data_length = if node.is_dir || link_only {
            0
        } else {
            node.valid_data_length
        };
        let extent_count = if node.is_dir || link_only {
            0
        } else {
            u32::try_from(Self::snapshot_extent_count(&node.data))
                .map_err(|_| MemFsSnapshotError::InvalidRecord)?
        };
        out.push(if link_only {
            SNAP_REC_LINK
        } else if node.is_dir {
            SNAP_REC_DIR
        } else {
            SNAP_REC_FILE
        });
        put_u32(out, node.attributes);
        put_u32(out, path_len);
        put_u64(
            out,
            if path.is_empty() {
                self.next_file_id
            } else {
                node.file_id
            },
        );
        put_u64(out, node.creation_time);
        put_u64(out, node.last_access_time);
        put_u64(out, node.last_write_time);
        put_u64(out, node.change_time);
        put_u64(out, logical_len);
        put_u64(out, allocation_size);
        put_u64(out, valid_data_length);
        put_u32(out, extent_count);
        write_snapshot_short_name(short_name, out);
        out.extend_from_slice(path.as_bytes());
        if !node.is_dir && !link_only {
            self.write_snapshot_file_data(&node.data, out)?;
        }
        Ok(())
    }

    fn write_snapshot_record_to_sink<S: SnapshotPayloadSink>(
        &self,
        path: &str,
        node: &MemFsNode,
        link_only: bool,
        short_name: FileShortName,
        sink: &mut S,
    ) -> Result<(), SnapshotBlockStoreError> {
        let path_len = u32::try_from(path.len()).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
        let logical_len = if node.is_dir || link_only {
            0
        } else {
            u64::try_from(node.data.len(&self.blobs))
                .map_err(|_| SnapshotBlockStoreError::Corrupt)?
        };
        let allocation_size = if node.is_dir || link_only {
            0
        } else {
            node.allocation_size
        };
        let valid_data_length = if node.is_dir || link_only {
            0
        } else {
            node.valid_data_length
        };
        let extent_count = if node.is_dir || link_only {
            0
        } else {
            u32::try_from(Self::snapshot_extent_count(&node.data))
                .map_err(|_| SnapshotBlockStoreError::Corrupt)?
        };
        let mut header = [0u8; 77 + SNAP_SHORT_NAME_STORAGE_LEN];
        header[0] = if link_only {
            SNAP_REC_LINK
        } else if node.is_dir {
            SNAP_REC_DIR
        } else {
            SNAP_REC_FILE
        };
        put_u32_at(&mut header[1..5], node.attributes);
        put_u32_at(&mut header[5..9], path_len);
        put_u64_at(
            &mut header[9..17],
            if path.is_empty() {
                self.next_file_id
            } else {
                node.file_id
            },
        );
        put_u64_at(&mut header[17..25], node.creation_time);
        put_u64_at(&mut header[25..33], node.last_access_time);
        put_u64_at(&mut header[33..41], node.last_write_time);
        put_u64_at(&mut header[41..49], node.change_time);
        put_u64_at(&mut header[49..57], logical_len);
        put_u64_at(&mut header[57..65], allocation_size);
        put_u64_at(&mut header[65..73], valid_data_length);
        put_u32_at(&mut header[73..77], extent_count);
        write_snapshot_short_name_at(short_name, &mut header[77..]);
        sink.write_all(&header)?;
        sink.write_all(path.as_bytes())?;
        if !node.is_dir && !link_only {
            self.write_snapshot_file_data_to_sink(&node.data, sink)?;
        }
        Ok(())
    }

    fn write_snapshot_header(
        out: &mut [u8],
        record_count: u32,
        payload_len: u64,
        payload_crc: u32,
    ) {
        out.fill(0);
        out[0..8].copy_from_slice(&MEMFS_SNAPSHOT_MAGIC);
        put_u16_at(&mut out[8..10], MEMFS_SNAPSHOT_HEADER_LEN as u16);
        put_u16_at(&mut out[10..12], MEMFS_SNAPSHOT_VERSION);
        put_u32_at(&mut out[12..16], record_count);
        put_u64_at(&mut out[16..24], payload_len);
        put_u32_at(&mut out[24..28], payload_crc);
        let header_crc = crc32c(&out[..MEMFS_SNAPSHOT_HEADER_LEN - 4]);
        put_u32_at(&mut out[28..32], header_crc);
    }

    fn snapshot_extent_count(data: &FileData) -> usize {
        match data {
            FileData::Bytes(bytes) => usize::from(!bytes.is_empty()),
            FileData::Extents(extents) => extents.iter().filter(|extent| extent.len != 0).count(),
        }
    }

    fn snapshot_file_data_encoded_len(
        blobs: &[Vec<u8>],
        data: &FileData,
    ) -> Result<usize, MemFsSnapshotError> {
        let mut total = 0usize;
        match data {
            FileData::Bytes(bytes) => {
                if !bytes.is_empty() {
                    total = total
                        .checked_add(SNAP_EXTENT_HEADER_LEN)
                        .and_then(|n| n.checked_add(bytes.len()))
                        .ok_or(MemFsSnapshotError::InvalidRecord)?;
                }
            }
            FileData::Extents(extents) => {
                for extent in extents.iter().filter(|extent| extent.len != 0) {
                    let data_len = if extent.blob == ZERO_EXTENT_BLOB {
                        0
                    } else {
                        let Some(blob) = blobs.get(extent.blob) else {
                            return Err(MemFsSnapshotError::InvalidRecord);
                        };
                        let end = extent
                            .offset
                            .checked_add(extent.len)
                            .ok_or(MemFsSnapshotError::InvalidRecord)?;
                        if blob.get(extent.offset..end).is_none() {
                            return Err(MemFsSnapshotError::InvalidRecord);
                        }
                        extent.len
                    };
                    total = total
                        .checked_add(SNAP_EXTENT_HEADER_LEN)
                        .and_then(|n| n.checked_add(data_len))
                        .ok_or(MemFsSnapshotError::InvalidRecord)?;
                }
            }
        }
        Ok(total)
    }

    fn projected_extents_encoded_len(extents: &[FileExtent])
        -> Result<usize, MemFsSnapshotError>
    {
        extents.iter().filter(|extent| extent.len != 0).try_fold(0usize, |total, extent| {
            total.checked_add(SNAP_EXTENT_HEADER_LEN)
                .and_then(|len| len.checked_add(
                    if extent.blob == ZERO_EXTENT_BLOB { 0 } else { extent.len }
                ))
                .ok_or(MemFsSnapshotError::InvalidRecord)
        })
    }

    fn live_file_data_encoded_len(&self, id: u64) -> Result<usize, MemFsSnapshotError> {
        let node = self.node(id).ok_or(MemFsSnapshotError::InvalidRecord)?;
        if node.is_dir || node.link_count == 0 {
            return Ok(0);
        }
        Self::snapshot_file_data_encoded_len(&self.blobs, &node.data)
    }

    fn data_encoded_len_after_truncate(data: &FileData, length: usize)
        -> Result<usize, MemFsSnapshotError>
    {
        match data {
            FileData::Bytes(_) => {
                if length == 0 { Ok(0) } else {
                    length.checked_add(9).ok_or(MemFsSnapshotError::InvalidRecord)
                }
            }
            FileData::Extents(extents) => {
                let mut remaining = length;
                let mut cost = 0usize;
                for extent in extents {
                    let kept = remaining.min(extent.len);
                    if kept == 0 { break; }
                    cost = cost.checked_add(9)
                        .and_then(|len| len.checked_add(
                            if extent.blob == ZERO_EXTENT_BLOB { 0 } else { kept }
                        ))
                        .ok_or(MemFsSnapshotError::InvalidRecord)?;
                    remaining -= kept;
                }
                if remaining != 0 { return Err(MemFsSnapshotError::InvalidRecord); }
                Ok(cost)
            }
        }
    }

    fn projected_end_of_file_data_cost(&self, id: u64, requested: u64)
        -> Result<usize, u32>
    {
        let node = self.node(id).ok_or(STATUS_INVALID_HANDLE)?;
        if node.is_dir { return Err(STATUS_INVALID_DEVICE_REQUEST); }
        if requested > i64::MAX as u64 { return Err(STATUS_INVALID_PARAMETER); }
        let length = usize::try_from(requested).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let current = node.data.len(&self.blobs);
        if length <= current {
            return Self::data_encoded_len_after_truncate(&node.data, length)
                .map_err(|_| STATUS_DATA_ERROR);
        }
        let old = Self::snapshot_file_data_encoded_len(&self.blobs, &node.data)
            .map_err(|_| STATUS_DATA_ERROR)?;
        let adds_zero_record = match &node.data {
            FileData::Bytes(_) => true,
            FileData::Extents(extents) => extents.last()
                .is_none_or(|extent| extent.blob != ZERO_EXTENT_BLOB),
        };
        old.checked_add(if adds_zero_record { 9 } else { 0 })
            .ok_or(STATUS_DATA_ERROR)
    }

    fn projected_allocation_data_cost(&self, id: u64, requested: u64)
        -> Result<usize, u32>
    {
        let node = self.node(id).ok_or(STATUS_INVALID_HANDLE)?;
        if node.is_dir { return Err(STATUS_INVALID_DEVICE_REQUEST); }
        if requested > i64::MAX as u64 { return Err(STATUS_INVALID_PARAMETER); }
        if allocation_size_for_eof(requested) < requested {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let length = usize::try_from(requested).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let current = node.data.len(&self.blobs);
        if length < current {
            Self::data_encoded_len_after_truncate(&node.data, length)
                .map_err(|_| STATUS_DATA_ERROR)
        } else {
            Self::snapshot_file_data_encoded_len(&self.blobs, &node.data)
                .map_err(|_| STATUS_DATA_ERROR)
        }
    }

    fn write_snapshot_file_data(
        &self,
        data: &FileData,
        out: &mut Vec<u8>,
    ) -> Result<(), MemFsSnapshotError> {
        match data {
            FileData::Bytes(bytes) => {
                if !bytes.is_empty() {
                    out.push(SNAP_EXTENT_DATA);
                    put_u64(out, bytes.len() as u64);
                    out.extend_from_slice(bytes);
                }
            }
            FileData::Extents(extents) => {
                for extent in extents.iter().filter(|extent| extent.len != 0) {
                    if extent.blob == ZERO_EXTENT_BLOB {
                        out.push(SNAP_EXTENT_ZERO);
                        put_u64(out, extent.len as u64);
                        continue;
                    }
                    let Some(blob) = self.blobs.get(extent.blob) else {
                        return Err(MemFsSnapshotError::InvalidRecord);
                    };
                    let end = extent
                        .offset
                        .checked_add(extent.len)
                        .ok_or(MemFsSnapshotError::InvalidRecord)?;
                    let Some(bytes) = blob.get(extent.offset..end) else {
                        return Err(MemFsSnapshotError::InvalidRecord);
                    };
                    out.push(SNAP_EXTENT_DATA);
                    put_u64(out, bytes.len() as u64);
                    out.extend_from_slice(bytes);
                }
            }
        }
        Ok(())
    }

    fn write_snapshot_file_data_to_sink<S: SnapshotPayloadSink>(
        &self,
        data: &FileData,
        sink: &mut S,
    ) -> Result<(), SnapshotBlockStoreError> {
        match data {
            FileData::Bytes(bytes) => {
                if !bytes.is_empty() {
                    let len =
                        u64::try_from(bytes.len()).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
                    let mut header = [0u8; 9];
                    header[0] = SNAP_EXTENT_DATA;
                    put_u64_at(&mut header[1..9], len);
                    sink.write_all(&header)?;
                    sink.write_all(bytes)?;
                }
            }
            FileData::Extents(extents) => {
                for extent in extents.iter().filter(|extent| extent.len != 0) {
                    let len =
                        u64::try_from(extent.len).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
                    let mut header = [0u8; 9];
                    if extent.blob == ZERO_EXTENT_BLOB {
                        header[0] = SNAP_EXTENT_ZERO;
                        put_u64_at(&mut header[1..9], len);
                        sink.write_all(&header)?;
                        continue;
                    }
                    let Some(blob) = self.blobs.get(extent.blob) else {
                        return Err(SnapshotBlockStoreError::Corrupt);
                    };
                    let end = extent
                        .offset
                        .checked_add(extent.len)
                        .ok_or(SnapshotBlockStoreError::Corrupt)?;
                    let Some(bytes) = blob.get(extent.offset..end) else {
                        return Err(SnapshotBlockStoreError::Corrupt);
                    };
                    header[0] = SNAP_EXTENT_DATA;
                    put_u64_at(&mut header[1..9], len);
                    sink.write_all(&header)?;
                    sink.write_all(bytes)?;
                }
            }
        }
        Ok(())
    }

    fn restore_snapshot_node(
        &mut self,
        path: &str,
        is_dir: bool,
        attributes: u32,
        times: [u64; 4],
        file_id: Option<u64>,
    ) -> Result<(u64, u64), MemFsSnapshotError> {
        if !Self::valid_snapshot_path(path) {
            return Err(MemFsSnapshotError::InvalidPath);
        }
        if self.lookup(path).is_some() {
            return Err(MemFsSnapshotError::NameCollision);
        }
        let Some((parent_path, leaf)) = Self::parent_and_leaf_relative(path) else {
            return Err(MemFsSnapshotError::InvalidPath);
        };
        let Some(parent) = self.lookup(parent_path) else {
            return Err(MemFsSnapshotError::InvalidPath);
        };
        if !self.node(parent).is_some_and(|node| node.is_dir) {
            return Err(MemFsSnapshotError::InvalidPath);
        }
        if !is_dir && attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        if let Some(file_id) = file_id {
            if file_id == 0
                || self
                    .nodes
                    .iter()
                    .flatten()
                    .any(|node| node.file_id == file_id)
            {
                return Err(MemFsSnapshotError::InvalidRecord);
            }
        }
        let (id, entry_id) = self.create_child_with_entry(parent, leaf, is_dir);
        if let Some(file_id) = file_id {
            self.node_mut(id).unwrap().file_id = file_id;
            self.next_file_id = self.next_file_id.max(
                file_id
                    .checked_add(1)
                    .ok_or(MemFsSnapshotError::InvalidRecord)?,
            );
        }
        let Some(node) = self.node_mut(id) else {
            return Err(MemFsSnapshotError::InvalidRecord);
        };
        node.attributes = if is_dir {
            attributes | FILE_ATTRIBUTE_DIRECTORY
        } else {
            attributes
        };
        node.creation_time = times[0];
        node.last_access_time = times[1];
        node.last_write_time = times[2];
        node.change_time = times[3];
        Ok((id, entry_id))
    }

    fn restore_snapshot_link(
        &mut self,
        path: &str,
        target: u64,
        attributes: u32,
        times: [u64; 4],
    ) -> Result<u64, MemFsSnapshotError> {
        if !Self::valid_snapshot_path(path) || self.lookup(path).is_some() {
            return Err(MemFsSnapshotError::InvalidPath);
        }
        let Some(target_node) = self.node(target) else {
            return Err(MemFsSnapshotError::InvalidRecord);
        };
        if target_node.is_dir
            || target_node.attributes != attributes
            || times
                != [
                    target_node.creation_time,
                    target_node.last_access_time,
                    target_node.last_write_time,
                    target_node.change_time,
                ]
        {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        let Some((parent_path, leaf)) = Self::parent_and_leaf_relative(path) else {
            return Err(MemFsSnapshotError::InvalidPath);
        };
        let Some(parent) = self.lookup(parent_path) else {
            return Err(MemFsSnapshotError::InvalidPath);
        };
        self.insert_entry(parent, leaf, target).map_err(|status| {
            if status == STATUS_INSUFFICIENT_RESOURCES {
                MemFsSnapshotError::OutOfMemory
            } else {
                MemFsSnapshotError::InvalidRecord
            }
        })
    }

    fn valid_snapshot_path(path: &str) -> bool {
        !path.is_empty()
            && !path.starts_with('\\')
            && !path.ends_with('\\')
            && path
                .split('\\')
                .all(|component| !component.is_empty() && component != "." && component != "..")
    }

    fn read_snapshot_file_data(
        &mut self,
        r: &mut SnapshotReader<'_>,
        logical_len: usize,
        extent_count: usize,
    ) -> Result<FileData, MemFsSnapshotError> {
        if logical_len == 0 && extent_count == 0 {
            return Ok(FileData::empty());
        }
        let mut extents = Vec::new();
        extents
            .try_reserve_exact(extent_count)
            .map_err(|_| MemFsSnapshotError::OutOfMemory)?;
        let mut total = 0usize;
        for _ in 0..extent_count {
            let kind = r.u8()?;
            let len = usize::try_from(r.u64()?).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
            if len == 0 {
                return Err(MemFsSnapshotError::InvalidRecord);
            }
            total = total
                .checked_add(len)
                .ok_or(MemFsSnapshotError::InvalidRecord)?;
            match kind {
                SNAP_EXTENT_ZERO => Self::push_extent_merged(
                    &mut extents,
                    FileExtent {
                        blob: ZERO_EXTENT_BLOB,
                        offset: 0,
                        len,
                    },
                ),
                SNAP_EXTENT_DATA => {
                    let bytes = r.take(len)?;
                    let blob = self
                        .intern_blob(bytes)
                        .ok_or(MemFsSnapshotError::OutOfMemory)?;
                    Self::push_extent_merged(
                        &mut extents,
                        FileExtent {
                            blob,
                            offset: 0,
                            len,
                        },
                    );
                }
                _ => return Err(MemFsSnapshotError::InvalidRecord),
            }
        }
        if total != logical_len {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        Ok(FileData::Extents(extents))
    }

    fn read_snapshot_file_data_streaming<S: SnapshotPayloadReader>(
        &mut self,
        r: &mut SnapshotStreamReader<'_, S>,
        logical_len: usize,
        extent_count: usize,
    ) -> Result<FileData, SnapshotBlockStoreError> {
        if logical_len == 0 && extent_count == 0 {
            return Ok(FileData::empty());
        }
        let mut extents = Vec::new();
        extents
            .try_reserve_exact(extent_count)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        let mut total = 0usize;
        for _ in 0..extent_count {
            let kind = r.u8()?;
            let len = usize::try_from(r.u64()?).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
            if len == 0 {
                return Err(SnapshotBlockStoreError::Corrupt);
            }
            total = total
                .checked_add(len)
                .ok_or(SnapshotBlockStoreError::Corrupt)?;
            match kind {
                SNAP_EXTENT_ZERO => Self::push_extent_merged(
                    &mut extents,
                    FileExtent {
                        blob: ZERO_EXTENT_BLOB,
                        offset: 0,
                        len,
                    },
                ),
                SNAP_EXTENT_DATA => {
                    let bytes = r.vec(len)?;
                    let blob = self
                        .intern_blob_owned(bytes)
                        .ok_or(SnapshotBlockStoreError::OutOfMemory)?;
                    Self::push_extent_merged(
                        &mut extents,
                        FileExtent {
                            blob,
                            offset: 0,
                            len,
                        },
                    );
                }
                _ => return Err(SnapshotBlockStoreError::Corrupt),
            }
        }
        if total != logical_len {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(FileData::Extents(extents))
    }

    fn child(&self, dir: u64, name: &str) -> Option<u64> {
        self.child_entry(dir, name).map(|entry| entry.node_id)
    }

    fn child_entry(&self, dir: u64, name: &str) -> Option<&MemFsDirEntry> {
        let folded = fold(name);
        self.node(dir)?.children.iter().find(|entry| {
            entry.folded_name == folded
                || (!entry.folded_short_name.is_empty() && entry.folded_short_name == folded)
        })
    }

    fn child_long_entry(&self, dir: u64, name: &str) -> Option<&MemFsDirEntry> {
        let folded = fold(name);
        self.node(dir)?
            .children
            .iter()
            .find(|entry| entry.folded_name == folded)
    }

    fn child_folded_bytes(&self, dir: u64, name: &[u8]) -> Option<u64> {
        self.node(dir)?
            .children
            .iter()
            .find(|entry| {
                entry.folded_name.as_bytes().eq_ignore_ascii_case(name)
                    || (!entry.folded_short_name.is_empty()
                        && entry
                            .folded_short_name
                            .as_bytes()
                            .eq_ignore_ascii_case(name))
            })
            .map(|entry| entry.node_id)
    }

    fn insert_entry(&mut self, parent: u64, name: &str, node_id: u64) -> Result<u64, u32> {
        let plan = self.prepare_insert_entry(parent, name, node_id, None)?;
        Ok(self.apply_insert_entry(plan))
    }

    fn prepare_insert_entry(
        &mut self,
        parent: u64,
        name: &str,
        node_id: u64,
        allowed_replacement: Option<u64>,
    ) -> Result<PreparedInsertEntry, u32> {
        if name.is_empty() || name == "." || name == ".." || name.contains('\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(link_count) = self.node(node_id).map(|node| node.link_count) else {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        if self.child_entry(parent, name)
            .is_some_and(|entry| Some(entry.id) != allowed_replacement)
        {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let next_link_count = link_count
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        self.next_entry_id.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let mut folded_name = String::new();
        folded_name.try_reserve_exact(name.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        folded_name.push_str(name);
        folded_name.make_ascii_lowercase();
        let mut created_name = String::new();
        created_name.try_reserve_exact(name.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        created_name.push_str(name);
        let Some(parent_node) = self.node_mut(parent) else {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        if !parent_node.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if parent_node.children.try_reserve_exact(1).is_err() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(PreparedInsertEntry { parent, node_id, next_link_count,
            entry: MemFsDirEntry {
            id: self.next_entry_id,
            folded_name,
            created_name,
            folded_short_name: String::new(),
            short_name: FileShortName::EMPTY,
            node_id,
        } })
    }

    fn apply_insert_entry(&mut self, plan: PreparedInsertEntry) -> u64 {
        let entry_id = plan.entry.id;
        self.next_entry_id += 1;
        self.node_mut(plan.parent).expect("prepared entry parent").children.push(plan.entry);
        self.node_mut(plan.node_id).expect("prepared entry node").link_count =
            plan.next_link_count;
        entry_id
    }

    fn create_child_with_entry(&mut self, parent: u64, name: &str, is_dir: bool) -> (u64, u64) {
        let options = if is_dir {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
        let plan = self
            .prepare_create_child(
                parent,
                name,
                options,
                0,
                &mut file_create::CreateAllocator::default(),
            )
            .expect("provisioned child must have valid identity and capacity");
        let (node_id, entry_id, _) = self.apply_create(plan);
        (node_id, entry_id)
    }

    fn create_child(&mut self, parent: u64, name: &str, is_dir: bool) -> u64 {
        self.create_child_with_entry(parent, name, is_dir).0
    }

    fn entry_location(&self, entry_id: u64) -> Option<(u64, usize, u64)> {
        if entry_id == 0 {
            return None;
        }
        for (parent, node) in self.nodes.iter().enumerate() {
            let Some(node) = node else {
                continue;
            };
            let Some(index) = node.children.iter().position(|entry| entry.id == entry_id) else {
                continue;
            };
            return Some((parent as u64, index, node.children[index].node_id));
        }
        None
    }

    fn entry_short_name(&self, entry_id: u64) -> Option<FileShortName> {
        if entry_id == 0 {
            return Some(FileShortName::EMPTY);
        }
        let (parent, index, _) = self.entry_location(entry_id)?;
        Some(self.node(parent)?.children.get(index)?.short_name)
    }

    fn namespace_conflicts(
        &self,
        parent: u64,
        folded: &str,
        ignored_entry: u64,
        second_ignored_entry: u64,
    ) -> bool {
        self.node(parent).is_none_or(|node| {
            node.children.iter().any(|entry| {
                entry.id != ignored_entry
                    && entry.id != second_ignored_entry
                    && (entry.folded_name == folded
                        || (!entry.folded_short_name.is_empty()
                            && entry.folded_short_name == folded))
            })
        })
    }

    fn set_entry_short_name(&mut self, entry_id: u64, name: FileShortName) -> u32 {
        let Some((parent, index, node_id)) = self.entry_location(entry_id) else {
            return STATUS_ACCESS_DENIED;
        };
        let folded = match String::from_utf16(name.units()) {
            Ok(name) => fold(&name),
            Err(_) => return STATUS_INVALID_PARAMETER,
        };
        if !folded.is_empty() && self.namespace_conflicts(parent, &folded, entry_id, 0) {
            return STATUS_OBJECT_NAME_COLLISION;
        }
        let Some(entry) = self
            .node_mut(parent)
            .and_then(|node| node.children.get_mut(index))
        else {
            return STATUS_ACCESS_DENIED;
        };
        entry.folded_short_name = folded;
        entry.short_name = name;
        self.touch_change(node_id);
        STATUS_SUCCESS
    }

    fn restore_entry_short_name(
        &mut self,
        entry_id: u64,
        name: FileShortName,
    ) -> Result<(), MemFsSnapshotError> {
        let Some((parent, index, _)) = self.entry_location(entry_id) else {
            return Err(MemFsSnapshotError::InvalidRecord);
        };
        let created =
            String::from_utf16(name.units()).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
        let folded = fold(&created);
        if !folded.is_empty() && self.namespace_conflicts(parent, &folded, entry_id, 0) {
            return Err(MemFsSnapshotError::NameCollision);
        }
        let entry = self
            .node_mut(parent)
            .and_then(|node| node.children.get_mut(index))
            .ok_or(MemFsSnapshotError::InvalidRecord)?;
        entry.folded_short_name = folded;
        entry.short_name = name;
        Ok(())
    }

    fn opened_name(&self, entry_id: u64) -> Option<String> {
        self.try_opened_name(entry_id).ok()
    }

    /// Remove one exact directory entry. The node remains resident at link count zero until the
    /// FileSystem proves that no open File object still references it.
    fn unlink_entry(&mut self, entry_id: u64) -> Result<u64, u32> {
        let (parent, index, node_id) = self
            .entry_location(entry_id)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let node = self.node(node_id).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if node.is_dir && !node.children.is_empty() {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        let parent_node = self.node_mut(parent).ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        parent_node.children.remove(index);
        let node = self.node_mut(node_id).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        node.link_count = node.link_count.saturating_sub(1);
        Ok(node_id)
    }

    fn reap_unlinked(&mut self, node_id: u64) {
        if node_id != 0
            && self
                .node(node_id)
                .is_some_and(|node| node.link_count == 0 && node.children.is_empty())
        {
            self.nodes[node_id as usize] = None;
        }
    }

    fn prepare_rename_into_parent(
        &mut self,
        source: u64,
        source_entry: u64,
        target_parent: u64,
        leaf: &str,
        replace_if_exists: bool,
    ) -> Result<PreparedRename, u32> {
        self.prepare_rename_into_parent_with_short_name(
            source, source_entry, target_parent, leaf, replace_if_exists, None,
        )
    }

    fn prepare_rename_into_parent_with_short_name(
        &mut self,
        source: u64,
        source_entry: u64,
        target_parent: u64,
        leaf: &str,
        replace_if_exists: bool,
        moved_short_name: Option<FileShortName>,
    ) -> Result<PreparedRename, u32> {
        if source == 0 || leaf.is_empty() || leaf == "." || leaf == ".." || leaf.contains('\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some((source_parent, source_index, entry_node)) = self.entry_location(source_entry)
        else {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        if entry_node != source {
            return Err(STATUS_INVALID_HANDLE);
        }
        let Some(source_node) = self.node(source) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let source_is_dir = source_node.is_dir;
        let Some(target_parent_node) = self.node(target_parent) else {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        if !target_parent_node.is_dir {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        if source_is_dir {
            let mut cur = target_parent;
            loop {
                if cur == source {
                    return Err(STATUS_ACCESS_DENIED);
                }
                if cur == 0 {
                    break;
                }
                let Some(node) = self.node(cur) else {
                    return Err(STATUS_OBJECT_PATH_NOT_FOUND);
                };
                cur = node.parent;
            }
        }

        let namespace_entry = self.child_entry(target_parent, leaf).map(|entry| entry.id);
        let existing = self
            .child_long_entry(target_parent, leaf)
            .map(|entry| (entry.id, entry.node_id));
        if existing.is_none() && namespace_entry.is_some_and(|entry| entry != source_entry) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let source_short_name = self
            .node(source_parent)
            .and_then(|node| node.children.get(source_index))
            .map(|entry| entry.folded_short_name.as_str())
            .unwrap_or_default();
        let moved_short_name = moved_short_name.map(|name| {
            let mut folded = String::new();
            folded.try_reserve_exact(MAX_SHORT_NAME * 4)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            for unit in core::char::decode_utf16(name.units().iter().copied()) {
                folded.push(unit.map_err(|_| STATUS_INVALID_PARAMETER)?);
            }
            folded.make_ascii_lowercase();
            Ok::<_, u32>((name, folded))
        }).transpose()?;
        let effective_short_name = moved_short_name.as_ref()
            .map_or(source_short_name, |(_, folded)| folded.as_str());
        if (source_parent != target_parent || moved_short_name.is_some())
            && !effective_short_name.is_empty()
            && self.namespace_conflicts(
                target_parent,
                effective_short_name,
                source_entry,
                existing.map_or(0, |(entry, _)| entry),
            )
        {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let same_entry = existing.is_some_and(|(entry, _)| entry == source_entry);
        if let Some((existing_entry, existing_node_id)) = existing {
            if existing_entry != source_entry {
                if !replace_if_exists {
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
                let Some(existing_node) = self.node(existing_node_id) else {
                    return Err(STATUS_OBJECT_NAME_NOT_FOUND);
                };
                if source_is_dir || existing_node.is_dir {
                    return Err(STATUS_ACCESS_DENIED);
                }
            }
        }
        let mut folded_name = String::new();
        folded_name.try_reserve_exact(leaf.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        folded_name.push_str(leaf);
        folded_name.make_ascii_lowercase();
        let mut created_name = String::new();
        created_name.try_reserve_exact(leaf.len())
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        created_name.push_str(leaf);
        if !same_entry && source_parent != target_parent {
            let Some(parent_node) = self.node_mut(target_parent) else {
                return Err(STATUS_OBJECT_PATH_NOT_FOUND);
            };
            if parent_node.children.try_reserve_exact(1).is_err() {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
        }
        Ok(PreparedRename {
            source, source_entry, source_parent, source_index, target_parent,
            replacement_entry: existing.filter(|(entry, _)| *entry != source_entry)
                .map(|(entry, _)| entry),
            source_is_dir, same_entry, folded_name, created_name, moved_short_name,
        })
    }

    fn apply_rename_into_parent(&mut self, plan: PreparedRename) -> u32 {
        let PreparedRename {
            source, source_entry, source_parent, source_index, target_parent,
            replacement_entry, source_is_dir, same_entry, folded_name, created_name,
            moved_short_name,
        } = plan;
        if same_entry {
            let Some(entry) = self.node_mut(target_parent)
                .and_then(|node| node.children.get_mut(source_index))
            else {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            };
            entry.folded_name = folded_name;
            entry.created_name = created_name;
            if let Some((short, folded)) = moved_short_name {
                entry.short_name = short;
                entry.folded_short_name = folded;
            }
            return STATUS_SUCCESS;
        }
        if let Some(existing_entry) = replacement_entry {
            if let Err(status) = self.unlink_entry(existing_entry) {
                return status;
            }
        }
        let Some(old_parent) = self.node_mut(source_parent) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        let Some(old_index) = old_parent
            .children
            .iter()
            .position(|entry| entry.id == source_entry)
        else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let mut entry = old_parent.children.remove(old_index);

        let Some(source_node) = self.node_mut(source) else {
            return STATUS_INVALID_HANDLE;
        };
        if source_is_dir {
            source_node.parent = target_parent;
        }

        let Some(parent_node) = self.node_mut(target_parent) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        entry.folded_name = folded_name;
        entry.created_name = created_name;
        if let Some((short, folded)) = moved_short_name {
            entry.short_name = short;
            entry.folded_short_name = folded;
        }
        parent_node.children.push(entry);
        STATUS_SUCCESS
    }

    /// The node a rename to `target_path` would replace: a distinct entry already holding the
    /// final name. `start` is the directory the path is parsed from, or the volume root.
    fn rename_replace_target(
        &self,
        source_entry: u64,
        start: Option<u64>,
        target_path: &str,
    ) -> Option<u64> {
        let (parent_path, leaf) = Self::parent_and_leaf_relative(target_path)?;
        let parent = match start {
            Some(directory) => self.lookup_from(directory, parent_path)?,
            None => self.lookup(parent_path)?,
        };
        self.child_long_entry(parent, leaf)
            .filter(|entry| entry.id != source_entry)
            .map(|entry| entry.node_id)
    }

    fn prepare_rename_relative(
        &mut self,
        source: u64,
        source_entry: u64,
        start: Option<u64>,
        target_path: &str,
        replace_if_exists: bool,
    ) -> Result<PreparedRename, u32> {
        let Some((parent_path, leaf)) = Self::parent_and_leaf_relative(target_path) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let parent = match start {
            Some(root) => self.lookup_from(root, parent_path),
            None => self.lookup(parent_path),
        };
        let parent = parent.ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        self.prepare_rename_into_parent(source, source_entry, parent, leaf, replace_if_exists)
    }

    fn subtree_snapshot_entry_count(&self, root: u64) -> Result<usize, u32> {
        let node = self.node(root).ok_or(STATUS_DATA_ERROR)?;
        if !node.is_dir { return Ok(1); }
        let mut stack = Vec::new();
        stack.try_reserve_exact(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        stack.push(root);
        let mut count = 1usize;
        while let Some(directory) = stack.pop() {
            let node = self.node(directory).ok_or(STATUS_DATA_ERROR)?;
            for entry in &node.children {
                count = count.checked_add(1).ok_or(STATUS_DATA_ERROR)?;
                if self.node(entry.node_id).ok_or(STATUS_DATA_ERROR)?.is_dir {
                    stack.try_reserve_exact(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                    stack.push(entry.node_id);
                }
            }
        }
        Ok(count)
    }

    fn prepare_link_into_parent(
        &mut self,
        source: u64,
        target_parent: u64,
        leaf: &str,
        replace_if_exists: bool,
    ) -> Result<PreparedLink, u32> {
        if source == 0 || leaf.is_empty() || leaf == "." || leaf == ".." || leaf.contains('\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(source_node) = self.node(source) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        if source_node.is_dir {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(parent) = self.node(target_parent) else {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        if !parent.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let namespace_entry = self.child_entry(target_parent, leaf).map(|entry| entry.id);
        let existing = self
            .child_long_entry(target_parent, leaf)
            .map(|entry| (entry.id, entry.node_id));
        if existing.is_none() && namespace_entry.is_some() {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let replacement_entry = if let Some((existing_entry, existing_node)) = existing {
            if existing_node == source {
                return Ok(PreparedLink::Unchanged);
            }
            if !replace_if_exists {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
            if self.next_entry_id.checked_add(1).is_none() || source_node.link_count == u32::MAX {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            if self.node(existing_node).is_some_and(|node| node.is_dir) {
                return Err(STATUS_ACCESS_DENIED);
            }
            Some(existing_entry)
        } else if self.next_entry_id.checked_add(1).is_none() || source_node.link_count == u32::MAX
        {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        } else { None };
        let insertion = self.prepare_insert_entry(
            target_parent, leaf, source, replacement_entry,
        )?;
        Ok(PreparedLink::Add { insertion, replacement_entry })
    }

    fn prepare_link_relative(
        &mut self,
        source: u64,
        start: Option<u64>,
        target_path: &str,
        replace_if_exists: bool,
    ) -> Result<PreparedLink, u32> {
        let Some((parent_path, leaf)) = Self::parent_and_leaf_relative(target_path) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let parent = match start {
            Some(root) => self.lookup_from(root, parent_path),
            None => self.lookup(parent_path),
        };
        let parent = parent.ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        self.prepare_link_into_parent(source, parent, leaf, replace_if_exists)
    }

    fn apply_link(
        &mut self,
        plan: PreparedLink,
    ) -> u32 {
        let PreparedLink::Add { insertion, replacement_entry } = plan else {
            return STATUS_SUCCESS;
        };
        if let Some(entry) = replacement_entry {
            if let Err(status) = self.unlink_entry(entry) {
                return status;
            }
        }
        self.apply_insert_entry(insertion);
        STATUS_SUCCESS
    }

    fn can_mark_delete_pending(&self, id: u64, ignore_readonly: bool) -> u32 {
        let Some(node) = self.node(id) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if id == 0 {
            return STATUS_ACCESS_DENIED;
        }
        if !ignore_readonly && node.attributes & FILE_ATTRIBUTE_READONLY != 0 {
            return STATUS_CANNOT_DELETE;
        }
        if node.is_dir && !node.children.is_empty() {
            return STATUS_DIRECTORY_NOT_EMPTY;
        }
        STATUS_SUCCESS
    }

    /// Create every missing directory along `path`, returning the leaf directory's id.
    fn ensure_dir(&mut self, path: &str) -> u64 {
        let mut cur = 0;
        for comp in path.split('\\').filter(|c| !c.is_empty()) {
            cur = match self.child(cur, comp) {
                Some(id) => id,
                None => self.create_child(cur, comp, true),
            };
        }
        cur
    }

    /// Create every missing directory along a folded volume-relative path, returning the leaf id.
    fn ensure_dir_folded_relative(&mut self, path: &[u8]) -> Option<u64> {
        self.materialize_parent_folded_relative(path).ok()
    }

    /// Fallible directory materialization used by a prepared CREATE transaction. Each component
    /// is admitted before its local namespace effect; the outer transaction rolls back earlier
    /// components if a later admission fails.
    fn materialize_parent_folded_relative(&mut self, path: &[u8]) -> Result<u64, u32> {
        let mut cur = 0;
        for comp in path.split(|byte| *byte == b'\\').filter(|c| !c.is_empty()) {
            if !self.is_dir(cur) {
                return Err(STATUS_OBJECT_PATH_NOT_FOUND);
            }
            cur = match self.child_folded_bytes(cur, comp) {
                Some(id) => id,
                None => {
                    let name = core::str::from_utf8(comp)
                        .map_err(|_| STATUS_INVALID_PARAMETER)?;
                    let plan = self.prepare_create_child(
                        cur, name, FILE_DIRECTORY_FILE, 0,
                        &mut file_create::CreateAllocator::default(),
                    )?;
                    self.apply_create(plan).0
                }
            };
        }
        if self.is_dir(cur) { Ok(cur) } else { Err(STATUS_OBJECT_PATH_NOT_FOUND) }
    }

    /// Resolve a volume-relative path to a node id.
    fn lookup(&self, path: &str) -> Option<u64> {
        self.lookup_entry_from(0, path).map(|(node, _)| node)
    }

    /// Include every hard-link entry to the protected file, not just its opened name. Directory
    /// parents have one entry each, so their parent chain identifies a moved subtree.
    fn subtree_contains_file_id(&self, ancestor: u64, file_id: u64) -> bool {
        let Some(ancestor_node) = self.node(ancestor) else {
            return false;
        };
        if ancestor_node.file_id == file_id {
            return true;
        }
        if !ancestor_node.is_dir {
            return false;
        }
        for (parent, node) in self.nodes.iter().enumerate() {
            let Some(node) = node.as_ref().filter(|node| node.is_dir) else {
                continue;
            };
            if !node.children.iter().any(|entry| {
                self.node(entry.node_id).is_some_and(|child| child.file_id == file_id)
            }) {
                continue;
            }
            let mut current = parent as u64;
            for _ in 0..self.nodes.len() {
                if current == ancestor {
                    return true;
                }
                if current == 0 {
                    break;
                }
                let Some(directory) = self.node(current) else {
                    break;
                };
                current = directory.parent;
            }
        }
        false
    }

    fn lookup_entry_from(&self, start: u64, path: &str) -> Option<(u64, u64)> {
        let mut cur = start;
        let mut entry_id = 0;
        for comp in path.split('\\').filter(|c| !c.is_empty()) {
            let entry = self.child_entry(cur, comp)?;
            cur = entry.node_id;
            entry_id = entry.id;
        }
        Some((cur, entry_id))
    }

    fn lookup_from(&self, start: u64, path: &str) -> Option<u64> {
        let mut cur = start;
        for comp in path.split('\\').filter(|c| !c.is_empty()) {
            cur = self.child(cur, comp)?;
        }
        Some(cur)
    }

    fn lookup_folded_from(&self, start: u64, path: &[u8]) -> Option<u64> {
        self.lookup_folded_entry_from(start, path)
            .map(|(node, _)| node)
    }

    fn lookup_folded_entry_from(&self, start: u64, path: &[u8]) -> Option<(u64, u64)> {
        let mut cur = start;
        let mut entry_id = 0;
        for comp in path.split(|byte| *byte == b'\\').filter(|c| !c.is_empty()) {
            let entry = self.node(cur)?.children.iter().find(|entry| {
                entry.folded_name.as_bytes().eq_ignore_ascii_case(comp)
                    || (!entry.folded_short_name.is_empty()
                        && entry
                            .folded_short_name
                            .as_bytes()
                            .eq_ignore_ascii_case(comp))
            })?;
            cur = entry.node_id;
            entry_id = entry.id;
        }
        Some((cur, entry_id))
    }

    fn lookup_folded_relative(&self, path: &[u8]) -> Option<u64> {
        self.lookup_folded_from(0, path)
    }

    /// Split a path into (parent components, leaf name).
    fn parent_and_leaf(path: &str) -> Option<(&str, &str)> {
        let trimmed = path.trim_end_matches('\\');
        let idx = trimmed.rfind('\\')?;
        Some((&trimmed[..idx], &trimmed[idx + 1..]))
    }

    fn parent_and_leaf_relative(path: &str) -> Option<(&str, &str)> {
        let trimmed = path.trim_end_matches('\\');
        if trimmed.is_empty() {
            return None;
        }
        match trimmed.rfind('\\') {
            Some(index) => Some((&trimmed[..index], &trimmed[index + 1..])),
            None => Some(("", trimmed)),
        }
    }

    fn parent_and_leaf_bytes(path: &[u8]) -> Option<(&[u8], &[u8])> {
        let trimmed = path.strip_suffix(b"\\").unwrap_or(path);
        if trimmed.is_empty() {
            return None;
        }
        match trimmed.iter().rposition(|byte| *byte == b'\\') {
            Some(index) => Some((&trimmed[..index], &trimmed[index + 1..])),
            None => Some((&[], trimmed)),
        }
    }

    /// Query a volume-relative path's attributes WITHOUT opening a handle — the
    /// `NtQueryAttributesFile` / `NtQueryFullAttributesFile` path (attributes are read straight off
    /// the node, no `FILE_OBJECT` allocated). `None` if the path does not resolve.
    fn query(&self, rel_path: &str) -> Option<StandardInformation> {
        let id = self.lookup(rel_path)?;
        Some(StandardInformation {
            end_of_file: self.size(id),
            is_directory: self.is_dir(id),
            attributes: self.attributes(id),
            number_of_links: self.node(id)?.link_count,
            delete_pending: false,
        })
    }

    fn query_folded_relative(&self, rel_path: &[u8]) -> Option<StandardInformation> {
        self.query_folded_from(0, rel_path)
    }

    fn query_folded_from(&self, start: u64, rel_path: &[u8]) -> Option<StandardInformation> {
        let id = self.lookup_folded_from(start, rel_path)?;
        Some(StandardInformation {
            end_of_file: self.size(id),
            is_directory: self.is_dir(id),
            attributes: self.attributes(id),
            number_of_links: self.node(id)?.link_count,
            delete_pending: false,
        })
    }

    fn metadata(&self, id: u64, delete_pending: bool) -> Option<FileMetadata> {
        let node = self.node(id)?;
        let end_of_file = if node.is_dir { 0 } else { self.size(id) };
        let allocation_size = if node.is_dir { 0 } else { node.allocation_size };
        Some(FileMetadata {
            creation_time: node.creation_time,
            last_access_time: node.last_access_time,
            last_write_time: node.last_write_time,
            change_time: node.change_time,
            allocation_size,
            end_of_file,
            valid_data_length: if node.is_dir {
                0
            } else {
                node.valid_data_length
            },
            file_id: node.file_id,
            attributes: node.attributes,
            reparse_tag: 0,
            number_of_links: node.link_count,
            delete_pending,
            is_directory: node.is_dir,
        })
    }

    fn query_metadata(&self, rel_path: &str) -> Option<FileMetadata> {
        self.metadata(self.lookup(rel_path)?, false)
    }

    fn query_metadata_folded_relative(&self, rel_path: &[u8]) -> Option<FileMetadata> {
        self.metadata(self.lookup_folded_relative(rel_path)?, false)
    }

    fn query_metadata_folded_from(&self, start: u64, rel_path: &[u8]) -> Option<FileMetadata> {
        self.metadata(self.lookup_folded_from(start, rel_path)?, false)
    }

    fn is_dir(&self, id: u64) -> bool {
        self.node(id).map(|n| n.is_dir).unwrap_or(false)
    }
    fn attributes(&self, id: u64) -> u32 {
        self.node(id).map(|n| n.attributes).unwrap_or(0)
    }
    fn set_end_of_file(&mut self, id: u64, length: u64) -> u32 {
        let Some(n) = self.node(id) else {
            return STATUS_INVALID_HANDLE;
        };
        if n.is_dir {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        if length > i64::MAX as u64 {
            return STATUS_INVALID_PARAMETER;
        }
        let Ok(length) = usize::try_from(length) else {
            return STATUS_INVALID_PARAMETER;
        };
        let current = self.size(id) as usize;
        if length <= current {
            let node = self.node_mut(id).unwrap();
            node.data.truncate(length);
            node.valid_data_length = node.valid_data_length.min(length as u64);
            return STATUS_SUCCESS;
        }
        if !self.extend_with_zeroes(id, length - current) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let allocation_size = allocation_size_for_eof(length as u64);
        let node = self.node_mut(id).unwrap();
        node.allocation_size = node.allocation_size.max(allocation_size);
        STATUS_SUCCESS
    }

    fn set_allocation_size(&mut self, id: u64, requested: u64) -> u32 {
        let Some(node) = self.node(id) else {
            return STATUS_INVALID_HANDLE;
        };
        if node.is_dir {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        if requested > i64::MAX as u64 {
            return STATUS_INVALID_PARAMETER;
        }
        let allocation_size = allocation_size_for_eof(requested);
        if allocation_size < requested {
            return STATUS_INVALID_PARAMETER;
        }
        let Ok(new_eof) = usize::try_from(requested) else {
            return STATUS_INVALID_PARAMETER;
        };
        if self.size(id) as usize > new_eof {
            let node = self.node_mut(id).unwrap();
            node.data.truncate(new_eof);
            node.valid_data_length = node.valid_data_length.min(requested);
        }
        self.node_mut(id).unwrap().allocation_size = allocation_size;
        STATUS_SUCCESS
    }

    fn set_valid_data_length(&mut self, id: u64, requested: u64) -> u32 {
        let Some(node) = self.node(id) else {
            return STATUS_INVALID_HANDLE;
        };
        if node.is_dir {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        if requested > i64::MAX as u64
            || requested < node.valid_data_length
            || requested > node.data.len(&self.blobs) as u64
        {
            return STATUS_INVALID_PARAMETER;
        }
        self.node_mut(id).unwrap().valid_data_length = requested;
        STATUS_SUCCESS
    }

    fn ensure_allocation_covers_eof(&mut self, id: u64) {
        let required = allocation_size_for_eof(self.size(id));
        if let Some(node) = self.node_mut(id) {
            node.allocation_size = node.allocation_size.max(required);
        }
    }

    fn mark_data_initialized_through(&mut self, id: u64, end: u64) {
        let end = end.min(self.size(id));
        if let Some(node) = self.node_mut(id) {
            node.valid_data_length = node.valid_data_length.max(end);
        }
    }

    fn push_extent_merged(extents: &mut Vec<FileExtent>, extent: FileExtent) {
        if extent.len == 0 {
            return;
        }
        if let Some(last) = extents.last_mut() {
            if last.blob == ZERO_EXTENT_BLOB && extent.blob == ZERO_EXTENT_BLOB {
                last.len += extent.len;
                return;
            }
            if last.blob == extent.blob
                && last.blob != ZERO_EXTENT_BLOB
                && last.offset + last.len == extent.offset
            {
                last.len += extent.len;
                return;
            }
        }
        extents.push(extent);
    }

    fn slice_extent(extent: FileExtent, skip: usize, len: usize) -> FileExtent {
        FileExtent {
            blob: extent.blob,
            offset: if extent.blob == ZERO_EXTENT_BLOB {
                0
            } else {
                extent.offset + skip
            },
            len,
        }
    }

    fn extend_with_zeroes(&mut self, id: u64, additional: usize) -> bool {
        if additional == 0 {
            return true;
        }
        let Some(node) = self.node(id) else {
            return false;
        };
        if node.is_dir {
            return false;
        }
        if matches!(node.data, FileData::Extents(_)) {
            let Some(node) = self.node_mut(id) else {
                return false;
            };
            let FileData::Extents(extents) = &mut node.data else {
                return false;
            };
            if extents.try_reserve_exact(1).is_err() {
                return false;
            }
            Self::push_extent_merged(
                extents,
                FileExtent {
                    blob: ZERO_EXTENT_BLOB,
                    offset: 0,
                    len: additional,
                },
            );
            return true;
        }

        let existing_len = match &node.data {
            FileData::Bytes(bytes) => bytes.len(),
            FileData::Extents(_) => unreachable!(),
        };
        if existing_len != 0 && self.blobs.try_reserve_exact(1).is_err() {
            return false;
        }
        let mut extents = Vec::new();
        if extents
            .try_reserve_exact(if existing_len == 0 { 1 } else { 2 })
            .is_err()
        {
            return false;
        }
        let data = {
            let Some(node) = self.node_mut(id) else {
                return false;
            };
            core::mem::replace(&mut node.data, FileData::Extents(Vec::new()))
        };
        if let FileData::Bytes(bytes) = data {
            if !bytes.is_empty() {
                let blob = self.blobs.len();
                self.blobs.push(bytes);
                extents.push(FileExtent {
                    blob,
                    offset: 0,
                    len: existing_len,
                });
            }
        }
        Self::push_extent_merged(
            &mut extents,
            FileExtent {
                blob: ZERO_EXTENT_BLOB,
                offset: 0,
                len: additional,
            },
        );
        let Some(node) = self.node_mut(id) else {
            return false;
        };
        node.data = FileData::Extents(extents);
        true
    }

    fn directory_entry_count(&self, id: u64) -> Option<usize> {
        let node = self.node(id)?;
        if !node.is_dir {
            return None;
        }
        Some(node.children.len() + 2)
    }

    fn directory_entry(&self, id: u64, index: usize) -> Option<DirectoryEntry> {
        let node = self.node(id)?;
        if !node.is_dir {
            return None;
        }
        match index {
            0 => self.make_directory_entry(0, ".", FileShortName::EMPTY, node),
            1 => {
                let parent = self.node(node.parent).unwrap_or(node);
                self.make_directory_entry(1, "..", FileShortName::EMPTY, parent)
            }
            _ => {
                let child = node.children.get(index - 2)?;
                let target = self.node(child.node_id)?;
                self.make_directory_entry(index, &child.created_name, child.short_name, target)
            }
        }
    }

    fn make_directory_entry(
        &self,
        index: usize,
        name: &str,
        short_name: FileShortName,
        target: &MemFsNode,
    ) -> Option<DirectoryEntry> {
        let size = target.data.len(&self.blobs) as u64;
        let mut entry = DirectoryEntry {
            file_index: index as u32,
            attributes: target.attributes,
            end_of_file: size,
            allocation_size: if target.is_dir {
                0
            } else {
                target.allocation_size
            },
            ..DirectoryEntry::default()
        };
        let mut name_len = 0usize;
        for unit in name.encode_utf16() {
            if name_len == entry.name.len() {
                return None;
            }
            entry.name[name_len] = unit;
            name_len += 1;
        }
        entry.name_len = name_len as u16;
        if !entry.set_short_name(short_name.units()) {
            return None;
        }
        Some(entry)
    }
    fn size(&self, id: u64) -> u64 {
        self.node(id)
            .map(|n| n.data.len(&self.blobs) as u64)
            .unwrap_or(0)
    }
    fn read_at(&self, id: u64, offset: u64, len: usize) -> Vec<u8> {
        let Some(n) = self.node(id) else {
            return Vec::new();
        };
        let file_len = n.data.len(&self.blobs);
        let start = (offset as usize).min(file_len);
        let read_len = len.min(file_len.saturating_sub(start));
        let mut out = Vec::new();
        if out.try_reserve_exact(read_len).is_err() {
            return Vec::new();
        }
        out.resize(read_len, 0);
        let read = n.data.read_into(&self.blobs, offset, &mut out);
        out.truncate(read);
        out
    }

    fn read_at_into(&self, id: u64, offset: u64, out: &mut [u8]) -> usize {
        let Some(n) = self.node(id) else { return 0 };
        n.data.read_into(&self.blobs, offset, out)
    }

    /// Preserve only a read wholly backed by one immutable blob. The writer still compares its
    /// bytes with that exact range before sharing it; this is a hint, never authority for content.
    fn immutable_read_extent(&self, id: u64, offset: u64, len: usize) -> Option<FileExtent> {
        if len == 0 {
            return None;
        }
        let FileData::Extents(extents) = &self.node(id)?.data else {
            return None;
        };
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(len)?;
        let mut file_offset = 0usize;
        for extent in extents {
            let extent_end = file_offset.checked_add(extent.len)?;
            if start >= file_offset && end <= extent_end && extent.blob != ZERO_EXTENT_BLOB {
                let blob_offset = extent.offset.checked_add(start - file_offset)?;
                let blob_end = blob_offset.checked_add(len)?;
                self.blobs.get(extent.blob)?.get(blob_offset..blob_end)?;
                return Some(FileExtent {
                    blob: extent.blob,
                    offset: blob_offset,
                    len,
                });
            }
            file_offset = extent_end;
        }
        None
    }

    fn matching_immutable_read(
        &self,
        bytes: &[u8],
        recent: Option<FileExtent>,
    ) -> Option<FileExtent> {
        let extent = recent?;
        if extent.len != bytes.len() || extent.blob == ZERO_EXTENT_BLOB {
            return None;
        }
        let end = extent.offset.checked_add(extent.len)?;
        #[cfg(test)]
        self.blob_slice_candidates_inspected
            .fetch_add(1, Ordering::Relaxed);
        (self.blobs.get(extent.blob)?.get(extent.offset..end)? == bytes).then_some(extent)
    }

    /// Replace a file node's contents with `bytes`, allocating EXACTLY once (the volume lives on a
    /// bump heap in the executive, so a growth-by-doubling `resize` would strand the intermediate
    /// buffers). `false` if the node is missing or is a directory.
    fn set_file_data(&mut self, id: u64, bytes: &[u8]) -> bool {
        let Some(node) = self.node(id) else {
            return false;
        };
        if node.is_dir {
            return false;
        }
        let mut extents = Vec::new();
        if extents.try_reserve_exact(1).is_err() {
            return false;
        }
        let Some(blob) = self.intern_blob(bytes) else {
            return false;
        };
        extents.push(FileExtent {
            blob,
            offset: 0,
            len: bytes.len(),
        });
        let Some(node) = self.node_mut(id) else {
            return false;
        };
        node.data = FileData::Extents(extents);
        node.allocation_size = allocation_size_for_eof(bytes.len() as u64);
        node.valid_data_length = bytes.len() as u64;
        true
    }

    /// Replace a file node's contents by taking ownership of the already-built byte buffer.
    /// This avoids a second full-size allocation for internal kernel checkpoint writers that
    /// already hold an owned image.
    fn set_file_data_owned(&mut self, id: u64, bytes: Vec<u8>) -> bool {
        let Some(node) = self.node(id) else {
            return false;
        };
        if node.is_dir {
            return false;
        }
        let Some(node) = self.node_mut(id) else {
            return false;
        };
        node.allocation_size = allocation_size_for_eof(bytes.len() as u64);
        node.valid_data_length = bytes.len() as u64;
        node.data = FileData::Bytes(bytes);
        true
    }

    /// A file node's bytes, borrowed in place. `None` for a directory or a missing node.
    fn file_data(&self, rel_path: &str) -> Option<&[u8]> {
        let id = self.lookup(rel_path)?;
        let node = self.node(id)?;
        if node.is_dir {
            None
        } else {
            node.data.contiguous_slice(&self.blobs)
        }
    }

    fn file_data_owned(&self, rel_path: &str) -> Option<Vec<u8>> {
        let id = self.lookup(rel_path)?;
        let node = self.node(id)?;
        if node.is_dir {
            None
        } else {
            node.data.to_vec(&self.blobs)
        }
    }

    fn file_data_folded_relative(&self, rel_path: &[u8]) -> Option<&[u8]> {
        let id = self.lookup_folded_relative(rel_path)?;
        let node = self.node(id)?;
        if node.is_dir {
            None
        } else {
            node.data.contiguous_slice(&self.blobs)
        }
    }

    fn file_len(&self, rel_path: &str) -> Option<u64> {
        let id = self.lookup(rel_path)?;
        let node = self.node(id)?;
        if node.is_dir {
            None
        } else {
            Some(node.data.len(&self.blobs) as u64)
        }
    }

    fn projected_write_data_cost(
        &self, id: u64, offset: u64, bytes: &[u8], recent_read: Option<FileExtent>,
    ) -> Result<usize, u32> {
        let node = self.node(id).ok_or(STATUS_INVALID_HANDLE)?;
        if node.is_dir { return Err(STATUS_INVALID_DEVICE_REQUEST); }
        let start = usize::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?;
        let end = start.checked_add(bytes.len()).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let current_len = node.data.len(&self.blobs);
        let old_cost = Self::snapshot_file_data_encoded_len(&self.blobs, &node.data)
            .map_err(|_| STATUS_DATA_ERROR)?;
        if bytes.is_empty() { return Ok(old_cost); }

        if let FileData::Extents(extents) = &node.data {
            if extents.iter().any(|extent| extent.blob == ZERO_EXTENT_BLOB) {
                let reused = self.matching_immutable_read(bytes, recent_read)
                    .or_else(|| self.blobs.iter().position(|blob| blob.as_slice() == bytes)
                        .map(|blob| FileExtent { blob, offset: 0, len: bytes.len() }));
                let blob = match reused {
                    Some(extent) => extent,
                    None => FileExtent { blob: self.blobs.len(), offset: 0, len: bytes.len() },
                };
                let next = Self::plan_spliced_extents(extents, start, blob)
                    .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
                return Self::projected_extents_encoded_len(&next)
                    .map_err(|_| STATUS_DATA_ERROR);
            }
            if start == current_len {
                if let Some(copied) = self.matching_immutable_read(bytes, recent_read) {
                    let merged = extents.last().is_some_and(|last| {
                        last.blob == copied.blob
                            && last.blob != ZERO_EXTENT_BLOB
                            && last.offset.checked_add(last.len) == Some(copied.offset)
                    });
                    return old_cost.checked_add(if merged { 0 } else { SNAP_EXTENT_HEADER_LEN })
                        .and_then(|len| len.checked_add(bytes.len()))
                        .ok_or(STATUS_DATA_ERROR);
                }
            }
        } else if matches!(&node.data, FileData::Bytes(data) if data.is_empty())
            && start == current_len
            && self.matching_immutable_read(bytes, recent_read).is_some()
        {
            return SNAP_EXTENT_HEADER_LEN.checked_add(bytes.len())
                .ok_or(STATUS_DATA_ERROR);
        }

        SNAP_EXTENT_HEADER_LEN.checked_add(current_len.max(end))
            .ok_or(STATUS_DATA_ERROR)
    }

    fn write_at(
        &mut self,
        id: u64,
        offset: u64,
        bytes: &[u8],
        recent_read: Option<FileExtent>,
    ) -> usize {
        let Some(node) = self.node(id) else {
            return 0;
        };
        if node.is_dir {
            return 0;
        }
        let start = offset as usize;
        if bytes.is_empty() {
            return 0;
        }
        let current_len = self.size(id) as usize;
        if start.checked_add(bytes.len()).is_none() {
            return 0;
        }
        let sparse_extent_backed = matches!(
            &node.data,
            FileData::Extents(extents)
                if extents.iter().any(|extent| extent.blob == ZERO_EXTENT_BLOB)
        );
        if sparse_extent_backed {
            let reused = self.matching_immutable_read(bytes, recent_read)
                .or_else(|| self.blobs.iter().position(|blob| blob.as_slice() == bytes)
                    .map(|blob| FileExtent { blob, offset: 0, len: bytes.len() }));
            let pending_blob = reused.is_none();
            let extent = reused.unwrap_or(FileExtent {
                blob: self.blobs.len(), offset: 0, len: bytes.len(),
            });
            let Some(node) = self.node(id) else { return 0; };
            let FileData::Extents(old) = &node.data else { return 0; };
            let Some(next) = Self::plan_spliced_extents(old, start, extent) else { return 0; };
            if pending_blob && self.intern_blob(bytes) != Some(extent.blob) {
                return 0;
            }
            self.node_mut(id).expect("prepared sparse write node").data = FileData::Extents(next);
            return bytes.len();
        }
        let can_append_extent = matches!(&node.data, FileData::Extents(_))
            || matches!(&node.data, FileData::Bytes(data) if data.is_empty());
        let copied_extent = (start == current_len && can_append_extent)
            .then(|| self.matching_immutable_read(bytes, recent_read))
            .flatten();
        if let Some(extent) = copied_extent {
            let Some(node) = self.node_mut(id) else {
                return 0;
            };
            match &mut node.data {
                FileData::Extents(extents) => {
                    if extents.try_reserve_exact(1).is_err() {
                        return 0;
                    }
                    extents.push(extent);
                    return bytes.len();
                }
                FileData::Bytes(data) if data.is_empty() => {
                    let mut extents = Vec::new();
                    if extents.try_reserve_exact(1).is_err() {
                        return 0;
                    }
                    extents.push(extent);
                    node.data = FileData::Extents(extents);
                    return bytes.len();
                }
                _ => {}
            }
        }
        if !self.materialize_node_data(id) {
            return 0;
        }
        let Some(n) = self.node_mut(id) else { return 0 };
        let FileData::Bytes(data) = &mut n.data else {
            return 0;
        };
        if start + bytes.len() > data.len() {
            // Reserve EXACTLY what the write needs before growing: the executive backs this volume
            // with a no-free bump heap, so `resize`'s amortised doubling would strand a buffer up
            // to twice the useful size on every extend.
            if data
                .try_reserve_exact(start + bytes.len() - data.len())
                .is_err()
            {
                return 0;
            }
            data.resize(start + bytes.len(), 0);
        }
        data[start..start + bytes.len()].copy_from_slice(bytes);
        bytes.len()
    }

    fn append_at_end(&mut self, id: u64, bytes: &[u8]) -> usize {
        let Some(node) = self.node(id) else {
            return 0;
        };
        if node.is_dir {
            return 0;
        }
        if bytes.is_empty() {
            return 0;
        }
        let mut appended = Vec::new();
        if appended.try_reserve_exact(bytes.len()).is_err() {
            return 0;
        }
        appended.extend_from_slice(bytes);

        // Prepare every allocation before moving the old bytes or publishing the new blob.
        // In particular, a failed blob reserve must leave a Bytes-backed file intact.
        let mut converted = match &node.data {
            FileData::Bytes(existing) => {
                let mut extents = Vec::new();
                if extents.try_reserve_exact(usize::from(!existing.is_empty()) + 1).is_err() {
                    return 0;
                }
                Some(extents)
            }
            FileData::Extents(_) => None,
        };
        if converted.is_none() {
            let Some(node) = self.node_mut(id) else { return 0; };
            let FileData::Extents(extents) = &mut node.data else { return 0; };
            if extents.try_reserve_exact(1).is_err() {
                return 0;
            }
        }
        let old_bytes_need_blob = self.node(id).is_some_and(|node| {
            matches!(&node.data, FileData::Bytes(existing) if !existing.is_empty())
        });
        if self.blobs.try_reserve_exact(usize::from(old_bytes_need_blob) + 1).is_err() {
            return 0;
        }

        if let Some(mut extents) = converted.take() {
            let old = core::mem::replace(
                &mut self.node_mut(id).expect("prepared append node").data,
                FileData::Extents(Vec::new()),
            );
            let FileData::Bytes(existing) = old else { unreachable!("prepared Bytes append") };
            if !existing.is_empty() {
                let len = existing.len();
                let blob = self.blobs.len();
                self.blobs.push(existing);
                extents.push(FileExtent { blob, offset: 0, len });
            }
            self.node_mut(id).expect("prepared append node").data = FileData::Extents(extents);
        }
        let blob = self.blobs.len();
        self.blobs.push(appended);
        let FileData::Extents(extents) =
            &mut self.node_mut(id).expect("prepared append node").data
        else { unreachable!("prepared append extents") };
        Self::push_extent_merged(extents, FileExtent { blob, offset: 0, len: bytes.len() });
        bytes.len()
    }

    fn plan_spliced_extents(
        old_extents: &[FileExtent], start: usize, write: FileExtent,
    ) -> Option<Vec<FileExtent>> {
        let Some(write_end) = start.checked_add(write.len) else {
            return None;
        };
        let old_len = old_extents.iter().map(|extent| extent.len).sum::<usize>();
        let mut next = Vec::new();
        if next.try_reserve_exact(old_extents.len() + 3).is_err() {
            return None;
        }

        let mut cursor = 0usize;
        let mut inserted = false;
        for extent in old_extents.iter().copied() {
            let extent_start = cursor;
            let Some(extent_end) = cursor.checked_add(extent.len) else {
                return None;
            };
            cursor = extent_end;

            if extent_end <= start {
                Self::push_extent_merged(&mut next, extent);
                continue;
            }
            if extent_start >= write_end {
                if !inserted {
                    Self::push_extent_merged(&mut next, write);
                    inserted = true;
                }
                Self::push_extent_merged(&mut next, extent);
                continue;
            }
            if extent_start < start {
                Self::push_extent_merged(
                    &mut next,
                    Self::slice_extent(extent, 0, start - extent_start),
                );
            }
            if !inserted {
                Self::push_extent_merged(&mut next, write);
                inserted = true;
            }
            if extent_end > write_end {
                Self::push_extent_merged(
                    &mut next,
                    Self::slice_extent(extent, write_end - extent_start, extent_end - write_end),
                );
            }
        }
        if !inserted {
            if start > old_len {
                Self::push_extent_merged(
                    &mut next,
                    FileExtent {
                        blob: ZERO_EXTENT_BLOB,
                        offset: 0,
                        len: start - old_len,
                    },
                );
            }
            Self::push_extent_merged(&mut next, write);
        }

        Some(next)
    }

    fn intern_blob(&mut self, bytes: &[u8]) -> Option<usize> {
        if let Some(index) = self
            .blobs
            .iter()
            .position(|existing| existing.as_slice() == bytes)
        {
            return Some(index);
        }
        let mut blob = Vec::new();
        blob.try_reserve_exact(bytes.len()).ok()?;
        blob.extend_from_slice(bytes);
        self.blobs.try_reserve_exact(1).ok()?;
        self.blobs.push(blob);
        Some(self.blobs.len() - 1)
    }

    fn intern_blob_owned(&mut self, bytes: Vec<u8>) -> Option<usize> {
        self.blobs.try_reserve_exact(1).ok()?;
        self.blobs.push(bytes);
        Some(self.blobs.len() - 1)
    }

    fn materialize_node_data(&mut self, id: u64) -> bool {
        let Some(node) = self.node(id) else {
            return false;
        };
        let FileData::Extents(extents) = &node.data else {
            return true;
        };
        let len = node.data.len(&self.blobs);
        let mut data = Vec::new();
        if data.try_reserve_exact(len).is_err() {
            return false;
        }
        for extent in extents {
            if extent.blob == ZERO_EXTENT_BLOB {
                let next_len = data.len() + extent.len;
                data.resize(next_len, 0);
                continue;
            }
            let Some(blob) = self.blobs.get(extent.blob) else {
                return false;
            };
            if extent.offset + extent.len > blob.len() {
                return false;
            }
            data.extend_from_slice(&blob[extent.offset..extent.offset + extent.len]);
        }
        self.node_mut(id).unwrap().data = FileData::Bytes(data);
        true
    }
}

/// Read/write/delete access and sharing carried by one NT File open description.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FileShareAccess {
    read: bool,
    write: bool,
    delete: bool,
    shared_read: bool,
    shared_write: bool,
    shared_delete: bool,
}

/// Privileges captured from the create request's effective subject and retained by one File open
/// description. Filesystems consume these CCB-like flags; they do not re-evaluate a possibly
/// different thread token when a later information request arrives.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FileOpenPrivileges {
    pub manage_volume: bool,
}

impl FileShareAccess {
    pub(crate) const fn none() -> Self {
        Self {
            read: false,
            write: false,
            delete: false,
            shared_read: false,
            shared_write: false,
            shared_delete: false,
        }
    }

    pub fn new(desired_access: u32, share_access: u32) -> Self {
        const GENERIC_ALL: u32 = 0x1000_0000;
        const GENERIC_EXECUTE: u32 = 0x2000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_READ: u32 = 0x8000_0000;
        const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

        let all = desired_access & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0;
        Self {
            read: all
                || desired_access
                    & (FILE_READ_DATA | FILE_EXECUTE | GENERIC_READ | GENERIC_EXECUTE)
                    != 0,
            write: all
                || desired_access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE) != 0,
            delete: all || desired_access & DELETE != 0,
            shared_read: share_access & FILE_SHARE_READ != 0,
            shared_write: share_access & FILE_SHARE_WRITE != 0,
            shared_delete: share_access & FILE_SHARE_DELETE != 0,
        }
    }

    fn participates(self) -> bool {
        self.read || self.write || self.delete
    }

    pub fn compatible_with(self, existing: Self) -> bool {
        !self.participates()
            || !existing.participates()
            || ((!self.read || existing.shared_read)
                && (!self.write || existing.shared_write)
                && (!self.delete || existing.shared_delete)
                && (!existing.read || self.shared_read)
                && (!existing.write || self.shared_write)
                && (!existing.delete || self.shared_delete))
    }
}

/// An open file instance (a simplified `FILE_OBJECT` + MemFs open handle, spec §6.1, §12.4).
struct FileObject {
    node_id: u64,
    entry_id: u64,
    /// Last live path for this exact opened entry. Live entries are resolved from the tree so a
    /// rename is immediately visible; the retained value remains authoritative after unlink.
    opened_name: String,
    current_offset: u64,
    /// `FILE_OBJECT::Event` state shared by every duplicated process handle.
    signaled: bool,
    /// Immutable CREATE admission options.
    create_options: u32,
    mode_state: crate::FileModeState,
    /// One share claim belongs to this open description, until final-handle cleanup completes.
    share: FileShareAccess,
    open_privileges: FileOpenPrivileges,
    /// Handles referring to this file object. `NtDuplicateObject` adds one, `ZwClose` removes one;
    /// the object (and any pending delete) is actioned when the last one goes.
    handle_references: u32,
    /// Handles, in-flight I/O and any transferred cleanup reference. The object survives cleanup
    /// until every filesystem-owned completion has been published.
    references: u32,
    serialization: nt_io_completion::FileIoSerialization,
    /// The final handle transfers its reference here until cleanup effects have committed.
    cleanup_reference_held: bool,
    cleanup_error: Option<u32>,
    /// DeletePending of the opened entry, mirrored on every File open on it.
    delete_pending: bool,
    /// `FILE_DELETE_ON_CLOSE`: this File marks its entry DeletePending when its last handle closes.
    delete_on_close: bool,
    /// Per-`FILE_OBJECT` directory-enumeration cursor (spec §17): `NtQueryDirectoryFile` resumes
    /// from it, `RestartScan` rewinds it. Shared by handles duplicated from this file object.
    query: DirectoryQueryState,
}

/// File information classes (spec §18) supported in v0.1.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StandardInformation {
    pub end_of_file: u64,
    pub is_directory: bool,
    pub attributes: u32,
    pub number_of_links: u32,
    pub delete_pending: bool,
}

/// Filesystem-owned metadata shared by handle and by-name query paths. `file_id` identifies the
/// underlying node, so every hard link to a MemFs file reports the same identity.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FileMetadata {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub valid_data_length: u64,
    pub file_id: u64,
    pub attributes: u32,
    pub reparse_tag: u32,
    pub number_of_links: u32,
    pub delete_pending: bool,
    pub is_directory: bool,
}

/// Ownership transition for an installed read-only file at create/open time. The union namespace
/// resolves source existence; this policy decides whether the caller can retain that source or must
/// first publish a writable-volume node.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InstalledFileOpenAction {
    ReadOnly,
    CopyContents,
    CopyMetadata,
    NameCollision,
}

/// Select the owner for a regular-file open in the overlay plus installed-volume namespace.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LayeredFileOpenDecision {
    UseOverlay,
    Installed(InstalledFileOpenAction),
    CreateOverlay,
}

/// Validate the common `NtCreateFile`/`NtOpenFile` contract before namespace lookup or mutation.
/// This is the NT5 I/O Manager parameter policy; filesystem entry points call it defensively as
/// well so kernel-mode users cannot bypass destructive-disposition ordering.
pub fn validate_file_create_parameters(
    desired_access: u32,
    file_attributes: u32,
    share_access: u32,
    disposition: u32,
    options: u32,
) -> Result<(), u32> {
    if file_attributes & !FILE_ATTRIBUTE_VALID_FLAGS != 0
        || share_access & !FILE_SHARE_VALID_FLAGS != 0
        || disposition > FILE_MAXIMUM_DISPOSITION
        || options & !FILE_VALID_OPTION_FLAGS != 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }

    let synchronous = options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT);
    if (synchronous != 0 && desired_access & SYNCHRONIZE == 0)
        || synchronous == (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)
        || (options & FILE_DELETE_ON_CLOSE != 0 && desired_access & DELETE == 0)
        || (options & FILE_DIRECTORY_FILE != 0 && options & FILE_NON_DIRECTORY_FILE != 0)
        || (options & FILE_COMPLETE_IF_OPLOCKED != 0 && options & FILE_RESERVE_OPFILTER != 0)
        || (options & FILE_NO_INTERMEDIATE_BUFFERING != 0 && desired_access & FILE_APPEND_DATA != 0)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }

    if options & FILE_DIRECTORY_FILE != 0 {
        const DIRECTORY_OPTIONS: u32 = FILE_DIRECTORY_FILE
            | FILE_SYNCHRONOUS_IO_ALERT
            | FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_WRITE_THROUGH
            | FILE_COMPLETE_IF_OPLOCKED
            | FILE_OPEN_FOR_BACKUP_INTENT
            | FILE_DELETE_ON_CLOSE
            | FILE_OPEN_FOR_FREE_SPACE_QUERY
            | FILE_OPEN_BY_FILE_ID
            | FILE_NO_COMPRESSION
            | FILE_OPEN_REPARSE_POINT;
        if options & !DIRECTORY_OPTIONS != 0
            || !matches!(disposition, FILE_CREATE | FILE_OPEN | FILE_OPEN_IF)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
    }
    Ok(())
}

/// Classify one open of a file known to exist on the installed read-only volume. This is kept in
/// the host-testable filesystem crate so the executive does not grow a second disposition policy.
pub fn installed_file_open_action(
    desired_access: u32,
    disposition: u32,
    options: u32,
) -> Result<InstalledFileOpenAction, u32> {
    const FILE_WRITE_EA: u32 = 0x0000_0010;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MUTATING_ACCESS: u32 = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | MAXIMUM_ALLOWED
        | GENERIC_WRITE
        | GENERIC_ALL;

    if options & FILE_DIRECTORY_FILE != 0 {
        return Err(STATUS_NOT_A_DIRECTORY);
    }
    match disposition {
        FILE_CREATE => Ok(InstalledFileOpenAction::NameCollision),
        FILE_OPEN | FILE_OPEN_IF => {
            if desired_access & MUTATING_ACCESS != 0 || options & FILE_DELETE_ON_CLOSE != 0 {
                Ok(InstalledFileOpenAction::CopyContents)
            } else {
                Ok(InstalledFileOpenAction::ReadOnly)
            }
        }
        FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE => {
            Ok(InstalledFileOpenAction::CopyMetadata)
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    }
}

/// Decide only the source layer. The selected filesystem still enforces sharing, access, and
/// create parameters; an overlay lookup error is never treated as an absent entry.
pub fn layered_file_open_decision(
    overlay_lookup: Result<bool, u32>,
    installed_regular_file: bool,
    desired_access: u32,
    disposition: u32,
    options: u32,
) -> Result<LayeredFileOpenDecision, u32> {
    let overlay_exists = overlay_lookup?;
    if disposition > FILE_MAXIMUM_DISPOSITION {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if overlay_exists {
        return Ok(LayeredFileOpenDecision::UseOverlay);
    }
    if installed_regular_file {
        return installed_file_open_action(desired_access, disposition, options)
            .map(LayeredFileOpenDecision::Installed);
    }
    if disposition == FILE_OPEN {
        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    Ok(LayeredFileOpenDecision::CreateOverlay)
}

impl FileMetadata {
    pub fn query_metadata(self) -> crate::QueryMetadata {
        crate::QueryMetadata {
            creation_time: self.creation_time,
            last_access_time: self.last_access_time,
            last_write_time: self.last_write_time,
            change_time: self.change_time,
            allocation_size: self.allocation_size,
            end_of_file: self.end_of_file,
            file_id: self.file_id,
            file_attributes: self.attributes,
            reparse_tag: self.reparse_tag,
            number_of_links: self.number_of_links,
            delete_pending: self.delete_pending,
            directory: self.is_directory,
            ..crate::QueryMetadata::default()
        }
    }
}

/// Whether a rename may replace a target that still has open handles. FASTFAT and NTFS deny a
/// caller that replacement; the filesystem's own image installation is not a caller rename.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OpenReplaceTarget {
    Deny,
    Allow,
}

/// Canonical parse root for a file rename. This keeps process handles out of
/// the filesystem API while preserving the three NT rename name forms.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileRenameRoot {
    /// A relative name is parsed from the source File's current parent.
    SourceParent,
    /// A volume-relative path is parsed from the mounted volume root.
    VolumeRoot,
    /// A relative name is parsed from this live directory File.
    Directory(u64),
}

/// Validated common header used by `FILE_RENAME_INFORMATION` and
/// `FILE_LINK_INFORMATION` on x64.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SetFileNameInformation<'a> {
    pub replace_if_exists: bool,
    pub root_directory: u64,
    pub file_name: &'a [u8],
}

/// Validated x64 `FILE_MOVE_CLUSTER_INFORMATION` payload. The target fields
/// deliberately share the rename/link layout, while the first union member is
/// a cluster count rather than a Boolean.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MoveClusterInformation<'a> {
    pub cluster_count: u32,
    pub root_directory: u64,
    pub file_name: &'a [u8],
}

/// Parse and validate the variable-length `FILE_NAME_INFORMATION` payload used by
/// `FileShortNameInformation`. An empty name removes the entry's existing alias.
pub fn parse_short_name_information(data: &[u8]) -> Result<FileShortName, u32> {
    if data.len() < 4 {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let byte_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if byte_len & 1 != 0 || byte_len > MAX_SHORT_NAME * 2 || data.len() - 4 < byte_len {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let mut units = [0u16; MAX_SHORT_NAME];
    for (index, bytes) in data[4..4 + byte_len].chunks_exact(2).enumerate() {
        units[index] = u16::from_le_bytes([bytes[0], bytes[1]]);
    }
    let units = &units[..byte_len / 2];
    if !valid_short_name(units) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    FileShortName::from_units(units).ok_or(STATUS_INVALID_PARAMETER)
}

fn valid_short_name(name: &[u16]) -> bool {
    if name.is_empty() {
        return true;
    }
    if String::from_utf16(name).is_err() || name == [b'.' as u16] || name == [b'.' as u16; 2] {
        return false;
    }
    let mut dot = None;
    for (index, unit) in name.iter().copied().enumerate() {
        if unit == b'.' as u16 {
            if dot.replace(index).is_some() {
                return false;
            }
            continue;
        }
        if unit <= b' ' as u16
            || (unit <= 0x7f
                && matches!(
                    unit as u8,
                    b'"' | b'*'
                        | b'+'
                        | b','
                        | b'/'
                        | b':'
                        | b';'
                        | b'<'
                        | b'='
                        | b'>'
                        | b'?'
                        | b'['
                        | b'\\'
                        | b']'
                        | b'|'
                ))
        {
            return false;
        }
    }
    match dot {
        Some(index) => (1..=8).contains(&index) && (1..=3).contains(&(name.len() - index - 1)),
        None => name.len() <= 8,
    }
}

/// Parse the x64 set-file-name structure without interpreting its caller-owned
/// `RootDirectory` handle.
pub fn parse_set_file_name_information(data: &[u8]) -> Result<SetFileNameInformation<'_>, u32> {
    if data.len() < 20 {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let name_len = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    if name_len == 0 || name_len & 1 != 0 || data.len().saturating_sub(20) < name_len {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(SetFileNameInformation {
        replace_if_exists: data[0] != 0,
        root_directory: u64::from_le_bytes(data[8..16].try_into().unwrap()),
        file_name: &data[20..20 + name_len],
    })
}

/// Parse the x64 move-cluster structure without interpreting its caller-owned
/// `RootDirectory` handle.
pub fn parse_move_cluster_information(data: &[u8]) -> Result<MoveClusterInformation<'_>, u32> {
    if data.len() < 20 {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    let name_len = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    if name_len == 0 || name_len & 1 != 0 || data.len().saturating_sub(20) < name_len {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(MoveClusterInformation {
        cluster_count: u32::from_le_bytes(data[0..4].try_into().unwrap()),
        root_directory: u64::from_le_bytes(data[8..16].try_into().unwrap()),
        file_name: &data[20..20 + name_len],
    })
}

/// Parse the provider-owned attribute field from a complete x64 `FILE_BASIC_INFORMATION` result.
/// The four timestamps remain opaque to the I/O Manager; only the filesystem-owned attributes
/// determine rename/link target-directory access.
pub fn parse_file_basic_information_attributes(data: &[u8]) -> Result<u32, u32> {
    if data.len() < 40 {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    Ok(u32::from_le_bytes(data[32..36].try_into().unwrap()))
}

/// The I/O-Manager-facing file system: the volume + mount manager + file-object/handle table,
/// exposing the Zw* native file APIs (spec §8-§9).
pub struct FileSystem {
    volume: MemFs,
    snapshot_budget: Option<SnapshotBudget>,
    /// Last exact immutable range returned to a caller. Consumed by the next write after an
    /// exact byte comparison, so unrelated writes never search provisioned file contents.
    recent_immutable_read: Option<FileExtent>,
    mounts: MountManager,
    handles: Vec<Option<FileObject>>,
    /// Live log nodes still covered by an unfurled volume WAL suffix.
    wal_protected_logs: Vec<u64>,
    notifications: crate::DirectoryNotifyTable<u64>,
    pending_file_cleanup_count: usize,
    file_cleanup_effects: FileCleanupEffects,
    #[cfg(test)]
    create_fail_at: Option<usize>,
}

/// The result of `ZwCreateFile`: `(status, handle, information)` (spec §8.1).
pub struct CreateResult {
    pub status: u32,
    pub handle: u64,
    pub information: u32,
}

pub const INVALID_HANDLE: u64 = u64::MAX;

impl FileSystem {
    /// A file system over `volume`, mounted with the required v0.1 mounts (spec §13.2).
    pub fn new(volume: MemFs) -> Self {
        FileSystem {
            volume,
            snapshot_budget: None,
            recent_immutable_read: None,
            mounts: MountManager::new(),
            handles: Vec::new(),
            wal_protected_logs: Vec::new(),
            notifications: crate::DirectoryNotifyTable::new(),
            pending_file_cleanup_count: 0,
            file_cleanup_effects: FileCleanupEffects::default(),
            #[cfg(test)]
            create_fail_at: None,
        }
    }

    /// Configure the mounted snapshot slot's maximum encoded volume image length.
    pub fn set_snapshot_payload_capacity(&mut self, capacity: usize) -> Result<(), u32> {
        if let Some(existing) = &self.snapshot_budget {
            return if existing.capacity() == capacity {
                Ok(())
            } else {
                Err(STATUS_INVALID_DEVICE_REQUEST)
            };
        }
        let encoded_len = self.volume.snapshot_encoded_len()
            .map_err(|_| STATUS_DATA_ERROR)?;
        self.snapshot_budget = Some(SnapshotBudget::new(encoded_len, capacity)?);
        Ok(())
    }

    pub fn snapshot_payload_capacity(&self) -> Option<usize> {
        self.snapshot_budget.as_ref().map(SnapshotBudget::capacity)
    }

    /// Current exact encoded volume length. A configured mounted volume maintains this as a
    /// mutation ledger, so callers need not traverse the tree on each admission.
    pub fn snapshot_payload_encoded_len(&self) -> Result<usize, u32> {
        match &self.snapshot_budget {
            Some(budget) => Ok(budget.encoded_len()),
            None => self.volume.snapshot_encoded_len().map_err(|_| STATUS_DATA_ERROR),
        }
    }

    /// After all anchored boot WAL records have replayed into a private volume, measure the
    /// resulting tree once and authenticate its capacity before publishing it as the live mount.
    /// The caller must reserve future folds only after this reconciliation.
    pub fn reconcile_unpublished_replay_snapshot(&mut self) -> Result<usize, u32> {
        let actual = self.volume.snapshot_encoded_len().map_err(|_| STATUS_DATA_ERROR)?;
        let budget = self.snapshot_budget.as_mut().ok_or(STATUS_DEVICE_NOT_READY)?;
        budget.reconcile_unpublished_replay(actual)?;
        Ok(actual)
    }

    fn reserved_replacement_node(&self, node_id: u64) -> bool {
        self.volume.node(node_id).is_some_and(|node| {
            self.snapshot_budget.as_ref().is_some_and(|budget| {
                budget.replacement_targets(node.file_id)
            })
        })
    }

    /// Project a provisioning transaction before creating any parent or replacing file bytes.
    /// Existing components use their serialized names, including long names reached by aliases.
    fn project_provision_relative(&self, relative: &[u8], file: Option<&[u8]>)
        -> Result<Option<usize>, u32>
    {
        let Some(budget) = &self.snapshot_budget else { return Ok(None); };
        let (parents, leaf) = if file.is_some() {
            let (parent, leaf) = MemFs::parent_and_leaf_bytes(relative)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            (parent, Some(leaf))
        } else { (relative, None) };
        let mut parent = 0;
        let mut path_len = 0usize;
        let mut growth = 0usize;
        for component in parents.split(|byte| *byte == b'\\').filter(|part| !part.is_empty()) {
            let name = core::str::from_utf8(component).map_err(|_| STATUS_INVALID_PARAMETER)?;
            if name == "." || name == ".." { return Err(STATUS_INVALID_PARAMETER); }
            if let Some((node, entry)) = self.volume.lookup_folded_entry_from(parent, component) {
                if !self.volume.is_dir(node) { return Err(STATUS_OBJECT_PATH_NOT_FOUND); }
                path_len = self.volume.opened_name(entry)
                    .ok_or(STATUS_INSUFFICIENT_RESOURCES)?
                    .trim_start_matches('\\').len();
                parent = node;
            } else {
                path_len = path_len.checked_add(usize::from(path_len != 0))
                    .and_then(|len| len.checked_add(name.len())).ok_or(STATUS_DATA_ERROR)?;
                growth = growth.checked_add(SNAP_RECORD_FIXED_LEN)
                    .and_then(|len| len.checked_add(path_len)).ok_or(STATUS_DATA_ERROR)?;
                // An absent parent has no node ID; all remaining components are necessarily new.
                parent = u64::MAX;
            }
        }
        let mut old_data = 0usize;
        if let (Some(bytes), Some(leaf)) = (file, leaf) {
            let name = core::str::from_utf8(leaf).map_err(|_| STATUS_INVALID_PARAMETER)?;
            if name.is_empty() || name == "." || name == ".." { return Err(STATUS_INVALID_PARAMETER); }
            if parent != u64::MAX {
                if let Some(id) = self.volume.child_folded_bytes(parent, leaf) {
                    if self.volume.is_dir(id) { return Err(STATUS_FILE_IS_A_DIRECTORY); }
                    if self.reserved_replacement_node(id) { return Err(STATUS_ACCESS_DENIED); }
                    old_data = self.volume.live_file_data_encoded_len(id)
                        .map_err(|_| STATUS_DATA_ERROR)?;
                } else {
                    let leaf_len = path_len.checked_add(usize::from(path_len != 0))
                        .and_then(|len| len.checked_add(name.len()))
                        .ok_or(STATUS_DATA_ERROR)?;
                    growth = growth.checked_add(SNAP_RECORD_FIXED_LEN)
                        .and_then(|len| len.checked_add(leaf_len))
                        .ok_or(STATUS_DATA_ERROR)?;
                }
            } else {
                let leaf_len = path_len.checked_add(1)
                    .and_then(|len| len.checked_add(name.len())).ok_or(STATUS_DATA_ERROR)?;
                growth = growth.checked_add(SNAP_RECORD_FIXED_LEN)
                    .and_then(|len| len.checked_add(leaf_len))
                    .ok_or(STATUS_DATA_ERROR)?;
            }
            if !bytes.is_empty() {
                growth = growth.checked_add(SNAP_EXTENT_HEADER_LEN)
                    .and_then(|len| len.checked_add(bytes.len())).ok_or(STATUS_DATA_ERROR)?;
            }
        }
        budget.project(old_data, growth).map(Some)
    }

    fn project_snapshot_data_cost(&self, id: u64, next_data_cost: usize)
        -> Result<Option<usize>, u32>
    {
        let Some(budget) = &self.snapshot_budget else { return Ok(None); };
        if self.reserved_replacement_node(id) { return Err(STATUS_ACCESS_DENIED); }
        let old_data_cost = self.volume.live_file_data_encoded_len(id)
            .map_err(|_| STATUS_DATA_ERROR)?;
        let node = self.volume.node(id).ok_or(STATUS_DATA_ERROR)?;
        let next_data_cost = if node.link_count == 0 { 0 } else { next_data_cost };
        budget.project(old_data_cost, next_data_cost).map(Some)
    }

    fn project_snapshot_append(&self, id: u64, bytes: usize) -> Result<Option<usize>, u32> {
        if self.snapshot_budget.is_none() || bytes == 0 { return Ok(None); }
        let old = self.volume.live_file_data_encoded_len(id)
            .map_err(|_| STATUS_DATA_ERROR)?;
        let next = old.checked_add(9).and_then(|n| n.checked_add(bytes))
            .ok_or(STATUS_DATA_ERROR)?;
        self.project_snapshot_data_cost(id, next)
    }

    fn publish_snapshot_size(&mut self, next: Option<usize>) {
        if let Some(next) = next {
            self.snapshot_budget.as_mut().expect("projected snapshot budget").publish(next);
        }
    }

    /// Reserve an entire future append, including an absent file's directory entry. The
    /// reservation remains charged inside this FileSystem if its move-only token is lost.
    pub fn reserve_snapshot_append_by_path(
        &mut self, path: &str, bytes_len: usize,
    ) -> Result<SnapshotCapacityReservation, u32> {
        let rel = self.to_relative(&normalize_separators(path))
            .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        let mut allocator = file_create::CreateAllocator::default();
        let plan = self.volume.prepare_create(
            &rel, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, 0, &mut allocator,
        )?;
        let (file_id, create_charge) = match &plan {
            file_create::PreparedCreate::Existing { node, .. } => {
                let node = self.volume.node(*node).ok_or(STATUS_DATA_ERROR)?;
                if node.is_dir { return Err(STATUS_FILE_IS_A_DIRECTORY); }
                (Some(node.file_id), 0)
            }
            file_create::PreparedCreate::New { .. } => {
                let name = self.volume.create_opened_name(&plan, &mut allocator)?;
                let record = SNAP_RECORD_FIXED_LEN
                    .checked_add(name.trim_start_matches('\\').len())
                    .ok_or(STATUS_DATA_ERROR)?;
                (None, record)
            }
        };
        let append_charge = if bytes_len == 0 { 0 } else {
            SNAP_EXTENT_HEADER_LEN.checked_add(bytes_len).ok_or(STATUS_DATA_ERROR)?
        };
        let budget = self.snapshot_budget.as_mut().ok_or(STATUS_DEVICE_NOT_READY)?;
        budget.reserve_append(rel, file_id, bytes_len, create_charge, append_charge)
    }

    /// Retain the peak growth for an owned replacement of an existing file. Other files,
    /// including a companion journal, remain present in the projected intermediate snapshot.
    pub fn reserve_snapshot_replacement_by_path(
        &mut self, path: &str, new_bytes_len: usize,
    ) -> Result<SnapshotCapacityReservation, u32> {
        let rel = self.to_relative(&normalize_separators(path))
            .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        let node_id = self.volume.lookup(&rel).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let node = self.volume.node(node_id).ok_or(STATUS_DATA_ERROR)?;
        if node.is_dir { return Err(STATUS_FILE_IS_A_DIRECTORY); }
        if self.handles.iter().flatten().any(|object| {
            object.node_id == node_id && object.requests_delete()
        }) {
            return Err(STATUS_DELETE_PENDING);
        }
        let file_id = node.file_id;
        let old = self.volume.live_file_data_encoded_len(node_id)
            .map_err(|_| STATUS_DATA_ERROR)?;
        let new = if new_bytes_len == 0 { 0 } else {
            SNAP_EXTENT_HEADER_LEN.checked_add(new_bytes_len).ok_or(STATUS_DATA_ERROR)?
        };
        let charge = new.saturating_sub(old);
        let budget = self.snapshot_budget.as_mut().ok_or(STATUS_DEVICE_NOT_READY)?;
        budget.reserve_replacement(rel, file_id, new_bytes_len, old, charge)
    }

    /// Atomically replace a future projection while preserving the same reservation identity.
    /// Failure returns the original token and keeps its earlier capacity charge intact.
    pub fn update_snapshot_replacement_projection(
        &mut self, mut token: SnapshotCapacityReservation, new_bytes_len: usize,
    ) -> Result<SnapshotCapacityReservation, (u32, SnapshotCapacityReservation)> {
        if token.kind != SnapshotReservationKind::Replacement {
            return Err((STATUS_INVALID_PARAMETER, token));
        }
        let Some(node_id) = self.volume.lookup(&token.relative_path) else {
            return Err((STATUS_OBJECT_NAME_NOT_FOUND, token));
        };
        let Some(node) = self.volume.node(node_id) else {
            return Err((STATUS_DATA_ERROR, token));
        };
        if Some(node.file_id) != token.file_id || node.is_dir {
            return Err((STATUS_DATA_ERROR, token));
        }
        let old = match self.volume.live_file_data_encoded_len(node_id) {
            Ok(old) => old,
            Err(_) => return Err((STATUS_DATA_ERROR, token)),
        };
        if old != token.replacement_base_cost {
            return Err((STATUS_DATA_ERROR, token));
        }
        let new = if new_bytes_len == 0 { 0 } else {
            match SNAP_EXTENT_HEADER_LEN.checked_add(new_bytes_len) {
                Some(new) => new,
                None => return Err((STATUS_DATA_ERROR, token)),
            }
        };
        let charge = new.saturating_sub(old);
        let Some(budget) = self.snapshot_budget.as_mut() else {
            return Err((STATUS_DEVICE_NOT_READY, token));
        };
        if let Err(status) = budget.update_replacement(&token, charge) {
            return Err((status, token));
        }
        token.bytes_len = new_bytes_len;
        token.append_charge = charge;
        Ok(token)
    }

    /// Release only the unconsumed charge after an exact, proven no-effect abort.
    pub fn cancel_snapshot_reservation(
        &mut self, token: SnapshotCapacityReservation,
    ) -> Result<(), (u32, SnapshotCapacityReservation)> {
        let Some(budget) = self.snapshot_budget.as_mut() else {
            return Err((STATUS_DEVICE_NOT_READY, token));
        };
        if !budget.owns(&token) { return Err((STATUS_DATA_ERROR, token)); }
        budget.cancel(&token).map_err(|status| (status, token))
    }

    /// Register one filesystem-owned directory notification request. `context` is the I/O
    /// Manager's opaque completion correlation; it is never interpreted by the filesystem.
    pub fn zw_notify_change_directory_file(
        &mut self,
        handle: u64,
        completion_filter: u32,
        watch_tree: bool,
        buffer_length: u32,
        context: u64,
    ) -> Result<crate::DirectoryNotifyId, u32> {
        let Some(object) = self.obj(handle) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        if !self.volume.is_dir(object.node_id) {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        let directory = self
            .zw_query_opened_name(handle)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        self.notifications.register(
            handle,
            &directory,
            completion_filter,
            watch_tree,
            buffer_length,
            context,
        )
    }

    pub fn zw_cancel_directory_notify(&mut self, id: crate::DirectoryNotifyId) -> bool {
        self.notifications.cancel(id)
    }

    pub fn pop_directory_notify_completion(
        &mut self,
    ) -> Option<crate::DirectoryNotifyCompletion<u64>> {
        self.notifications.pop_completion()
    }

    pub fn directory_notify_completion(
        &self,
        id: crate::DirectoryNotifyId,
    ) -> Option<&crate::DirectoryNotifyCompletion<u64>> {
        self.notifications.completion(id)
    }

    pub fn directory_notify_completion_exact(
        &self,
        id: crate::DirectoryNotifyId,
        context: u64,
    ) -> Result<Option<&crate::DirectoryNotifyCompletion<u64>>, u32> {
        self.notifications.completion_exact(id, &context)
    }

    pub fn copy_directory_notify_completion(
        &self,
        id: crate::DirectoryNotifyId,
        context: u64,
        offset: usize,
        output: &mut [u8],
    ) -> Result<usize, u32> {
        self.notifications.copy_completion_bytes(id, &context, offset, output)
    }

    pub fn acknowledge_directory_notify_completion(
        &mut self,
        id: crate::DirectoryNotifyId,
        context: u64,
    ) -> Result<(), u32> {
        self.notifications.acknowledge_completion(id, &context)
    }

    fn report_handle_change(&mut self, handle: u64, filter: u32) {
        if let Some(path) = self.zw_query_opened_name(handle) {
            self.notifications.report_change(crate::DirectoryChange {
                full_path: &path,
                filter,
                action: crate::FILE_ACTION_MODIFIED,
            });
        }
    }

    fn rename_target_name(
        &self,
        handle: u64,
        root: FileRenameRoot,
        target: &str,
    ) -> Option<String> {
        let root_name = match root {
            FileRenameRoot::SourceParent => {
                let source = self.zw_query_opened_name(handle)?;
                source
                    .rsplit_once('\\')
                    .map_or(
                        "\\",
                        |(parent, _)| {
                            if parent.is_empty() {
                                "\\"
                            } else {
                                parent
                            }
                        },
                    )
                    .to_string()
            }
            FileRenameRoot::VolumeRoot => "\\".to_string(),
            FileRenameRoot::Directory(directory) => self.zw_query_opened_name(directory)?,
        };
        let target = target.trim_start_matches('\\');
        let mut path = String::new();
        path.try_reserve_exact(root_name.len().checked_add(target.len())?.checked_add(1)?)
            .ok()?;
        path.push_str(&root_name);
        if path != "\\" {
            path.push('\\');
        }
        path.push_str(target);
        Some(path)
    }

    /// Publish the kernel's current NT system time to the filesystem for subsequent mutations.
    pub fn set_current_time_100ns(&mut self, now: u64) {
        self.volume.set_current_time_100ns(now);
    }

    /// Complete the create path's security-context capture before the File object is published to
    /// user mode. Duplicated handles retain these flags through their shared open description.
    pub fn capture_open_privileges(&mut self, handle: u64, privileges: FileOpenPrivileges) -> u32 {
        let Some(object) = self.obj_mut(handle) else {
            return STATUS_INVALID_HANDLE;
        };
        object.open_privileges = privileges;
        STATUS_SUCCESS
    }

    /// Initialize a new volume and migrate pre-v3 snapshots whose format did not carry timestamps.
    /// Returns whether durable node metadata changed and therefore needs a checkpoint.
    pub fn initialize_timestamps(&mut self, now: u64) -> bool {
        self.volume.initialize_timestamps(now)
    }

    /// Export just the durable volume tree. Open handles are per-boot FILE_OBJECT state and are not
    /// included.
    pub fn export_volume_snapshot(&self) -> Result<Vec<u8>, MemFsSnapshotError> {
        let mut image = Vec::new();
        self.export_volume_snapshot_into(&mut image)?;
        Ok(image)
    }

    /// Exact size of the current encoded volume image, without allocating the image.
    pub fn snapshot_encoded_len(&self) -> Result<usize, MemFsSnapshotError> {
        self.volume.snapshot_encoded_len()
    }

    /// Capture into retained storage for checkpoints that must keep one immutable image across
    /// native I/O reentry and reuse the allocation on later commits.
    pub fn export_volume_snapshot_into(
        &self,
        out: &mut Vec<u8>,
    ) -> Result<(), MemFsSnapshotError> {
        self.volume.write_snapshot_into(out)?;
        self.check_snapshot_capture_len(out.len())
    }

    /// Reconcile the exact serialized result before a checkpoint may start physical I/O.
    fn check_snapshot_capture_len(&self, actual: usize) -> Result<(), MemFsSnapshotError> {
        if let Some(budget) = &self.snapshot_budget {
            if actual > budget.capacity() {
                return Err(MemFsSnapshotError::OutOfSpace);
            }
            if actual != budget.encoded_len() {
                return Err(MemFsSnapshotError::InvalidRecord);
            }
        }
        Ok(())
    }

    fn check_streaming_snapshot_before_io(&self, store_capacity: usize)
        -> Result<(), SnapshotBlockStoreError>
    {
        let actual = self.volume.snapshot_encoded_len().map_err(|error| match error {
            MemFsSnapshotError::OutOfMemory => SnapshotBlockStoreError::OutOfMemory,
            _ => SnapshotBlockStoreError::Corrupt,
        })?;
        if let Some(budget) = &self.snapshot_budget {
            if actual > budget.capacity() { return Err(SnapshotBlockStoreError::OutOfSpace); }
            if actual != budget.encoded_len() { return Err(SnapshotBlockStoreError::Corrupt); }
        }
        if actual > store_capacity { return Err(SnapshotBlockStoreError::OutOfSpace); }
        Ok(())
    }

    /// Reclaim immutable file-data blobs made unreachable by truncate, replace, or unlink.
    pub fn compact_volume_blobs(&mut self) -> Result<MemFsBlobCompaction, MemFsBlobCompactError> {
        self.recent_immutable_read = None;
        self.volume.compact_blobs()
    }

    /// Commit the durable volume tree to a block-backed snapshot store without allocating the full
    /// snapshot image. The stored payload is byte-for-byte identical to [`Self::export_volume_snapshot`].
    pub fn commit_volume_snapshot<D: SnapshotBlockDevice>(
        &self,
        store: &SnapshotBlockStore,
        dev: &mut D,
    ) -> Result<(u64, usize), SnapshotBlockStoreError> {
        self.check_streaming_snapshot_before_io(store.payload_capacity(dev)?)?;
        self.volume.commit_snapshot_to_store(store, dev, None, false)
    }

    /// Commit the same streaming volume image with an explicit WAL manifest. Every
    /// mounted-volume checkpoint can use this contract once native WAL recovery and
    /// mutation ordering are active; the caller must supply the exact folded serial.
    pub fn commit_volume_snapshot_with_wal_manifest<D: SnapshotBlockDevice>(
        &self,
        store: &SnapshotBlockStore,
        dev: &mut D,
        manifest: WalSnapshotManifest,
    ) -> Result<(u64, usize), SnapshotBlockStoreError> {
        self.check_streaming_snapshot_before_io(store.payload_capacity(dev)?)?;
        self.volume.commit_snapshot_to_store(store, dev, Some(manifest), false)
    }

    pub(crate) fn commit_volume_snapshot_for_empty_wal_migration<D: SnapshotBlockDevice>(
        &self,
        store: &SnapshotBlockStore,
        dev: &mut D,
        manifest: WalSnapshotManifest,
    ) -> Result<(u64, usize), SnapshotBlockStoreError> {
        self.check_streaming_snapshot_before_io(store.payload_capacity(dev)?)?;
        self.volume.commit_snapshot_to_store(store, dev, Some(manifest), true)
    }

    /// Restore the durable volume tree from a block-backed snapshot store without allocating the
    /// entire stored payload as a temporary buffer.
    pub fn restore_volume_snapshot_from_store<D: SnapshotBlockDevice>(
        store: &SnapshotBlockStore,
        dev: &mut D,
    ) -> Result<Option<(Self, u64, usize)>, SnapshotBlockStoreError> {
        match store.read_latest_streaming(dev, |reader| {
            Ok(Self::new(MemFs::from_snapshot_reader(reader)?))
        })? {
            Some((generation, bytes, fs)) => Ok(Some((fs, generation, bytes))),
            None => Ok(None),
        }
    }

    /// Decode the selected snapshot and return its paired format metadata under one read lease.
    /// A WAL-bearing image remains private until its anchored suffix is recovered and replayed.
    pub fn restore_volume_snapshot_with_metadata_from_store<D: SnapshotBlockDevice>(
        store: &SnapshotBlockStore,
        dev: &mut D,
    ) -> Result<Option<(Self, StoredSnapshotMetadata)>, SnapshotBlockStoreError> {
        store
            .read_latest_streaming_with_metadata(dev, |reader| {
                Ok(Self::new(MemFs::from_snapshot_reader(reader)?))
            })
            .map(|restored| restored.map(|(metadata, fs)| (fs, metadata)))
    }

    /// Decode a snapshot before the native caller can replay WAL records. A v2 image is
    /// returned only after both slots prove the same empty WAL baseline; later v2 states
    /// require the WAL-aware boot path and may not be published from snapshot bytes alone.
    pub fn restore_volume_snapshot_before_wal_replay_from_store<D: SnapshotBlockDevice>(
        store: &SnapshotBlockStore,
        dev: &mut D,
    ) -> Result<Option<(Self, StoredSnapshotMetadata)>, SnapshotBlockStoreError> {
        store.read_latest_streaming_before_wal_replay(dev, |reader| {
            Ok(Self::new(MemFs::from_snapshot_reader(reader)?))
        }).map(|restored| restored.map(|(metadata, fs)| (fs, metadata)))
    }

    /// Restore a file system from a durable volume snapshot, with a fresh handle table and the
    /// standard v0.1 mount manager.
    pub fn from_volume_snapshot(bytes: &[u8]) -> Result<Self, MemFsSnapshotError> {
        Ok(Self::new(MemFs::from_snapshot(bytes)?))
    }

    pub fn mounts_mut(&mut self) -> &mut MountManager {
        &mut self.mounts
    }

    /// Resolve an NT path to a MemFs volume-relative path (rejecting a non-MemFs volume).
    fn to_relative(&self, path: &str) -> Option<String> {
        let (volume, rel) = self.mounts.resolve(path)?;
        volume.eq_ignore_ascii_case(MEMFS_VOLUME).then_some(rel)
    }

    fn obj(&self, handle: u64) -> Option<&FileObject> {
        self.handles.get(handle as usize)?.as_ref()
    }
    fn obj_mut(&mut self, handle: u64) -> Option<&mut FileObject> {
        self.handles.get_mut(handle as usize)?.as_mut()
    }

    fn check_share_access(&self, node_id: u64, requested: FileShareAccess) -> Result<(), u32> {
        if self
            .handles
            .iter()
            .flatten()
            .filter(|object| {
                (object.handle_references != 0 || object.cleanup_reference_held)
                    && object.node_id == node_id
            })
            .all(|object| requested.compatible_with(object.share))
        {
            Ok(())
        } else {
            Err(STATUS_SHARING_VIOLATION)
        }
    }

    fn reap_unlinked_nodes(&mut self) {
        for node_id in 1..self.volume.nodes.len() as u64 {
            if self
                .volume
                .node(node_id)
                .is_none_or(|node| node.link_count != 0)
                || self
                    .handles
                    .iter()
                    .flatten()
                    .any(|object| object.node_id == node_id)
            {
                continue;
            }
            self.volume.reap_unlinked(node_id);
        }
    }

    fn decode_utf16_name(bytes: &[u8]) -> Result<String, u32> {
        if bytes.is_empty() || bytes.len() % 2 != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut out = String::new();
        if out.try_reserve_exact(bytes.len()).is_err() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let units = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));
        for ch in core::char::decode_utf16(units) {
            match ch {
                Ok(ch) => out.push(ch),
                Err(_) => return Err(STATUS_INVALID_PARAMETER),
            }
        }
        Ok(out)
    }

    fn decode_rename_information(data: &[u8]) -> Result<(bool, u64, String), u32> {
        let information = parse_set_file_name_information(data)?;
        let name = Self::decode_utf16_name(information.file_name)?;
        Ok((
            information.replace_if_exists,
            information.root_directory,
            normalize_separators(&name),
        ))
    }

    fn decode_disposition_ex_flags(data: &[u8]) -> Result<u32, u32> {
        if data.len() < 4 {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let flags = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if flags & !FILE_DISPOSITION_VALID_FLAGS != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(flags)
    }

    fn rename_file_decoded(
        &mut self,
        handle: u64,
        root: FileRenameRoot,
        target: &str,
        replace_if_exists: bool,
        open_target: OpenReplaceTarget,
    ) -> u32 {
        let Some((source, source_entry)) = self
            .obj(handle)
            .map(|object| (object.node_id, object.entry_id))
        else {
            return STATUS_INVALID_HANDLE;
        };
        if self.wal_protected_subtree(source) || self.reserved_replacement_node(source) {
            return STATUS_ACCESS_DENIED;
        }
        if target.is_empty() || self.to_relative(target).is_some() {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(old_name) = self.zw_query_opened_name(handle) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        let Some(new_name) = self.rename_target_name(handle, root, target) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        if self.wal_protected_target_name(&new_name) {
            return STATUS_ACCESS_DENIED;
        }
        if replace_if_exists
            && open_target == OpenReplaceTarget::Deny
            && self.rename_replace_target_is_open(source_entry, root, target)
        {
            return STATUS_ACCESS_DENIED;
        }
        let (start, target) = match root {
            FileRenameRoot::SourceParent => {
                if target.starts_with('\\') {
                    return STATUS_INVALID_PARAMETER;
                }
                let Some((parent, _, entry_node)) = self.volume.entry_location(source_entry) else {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                };
                if entry_node != source { return STATUS_INVALID_HANDLE; }
                (Some(parent), target)
            }
            FileRenameRoot::VolumeRoot => {
                let target = target.trim_start_matches('\\');
                if target.is_empty() {
                    return STATUS_INVALID_PARAMETER;
                }
                (None, target)
            }
            FileRenameRoot::Directory(directory) => {
                if target.starts_with('\\') {
                    return STATUS_INVALID_PARAMETER;
                }
                let Some(root_id) = self.obj(directory).map(|object| object.node_id) else {
                    return STATUS_INVALID_HANDLE;
                };
                if !self.volume.is_dir(root_id) {
                    return STATUS_NOT_A_DIRECTORY;
                }
                (Some(root_id), target)
            }
        };
        let plan = match self.volume.prepare_rename_relative(
            source, source_entry, start, target, replace_if_exists,
        ) {
            Ok(plan) => plan,
            Err(status) => return status,
        };
        if plan.replacement_entry.is_some_and(|entry| {
            self.volume.entry_location(entry).is_some_and(|(_, _, node)|
                self.reserved_replacement_node(node))
        }) {
            return STATUS_ACCESS_DENIED;
        }
        let next_snapshot_size = if let Some(budget) = &self.snapshot_budget {
            let entries = match self.volume.subtree_snapshot_entry_count(plan.source) {
                Ok(entries) => entries,
                Err(status) => return status,
            };
            let old_paths = old_name.len().checked_mul(entries);
            let new_paths = new_name.len().checked_mul(entries);
            let (Some(old_paths), Some(new_paths)) = (old_paths, new_paths) else {
                return STATUS_DATA_ERROR;
            };
            let replacement = if let Some(entry) = plan.replacement_entry {
                let Some((_, _, node_id)) = self.volume.entry_location(entry) else {
                    return STATUS_DATA_ERROR;
                };
                let Some(node) = self.volume.node(node_id) else { return STATUS_DATA_ERROR; };
                let data = if node.link_count == 1 {
                    match self.volume.live_file_data_encoded_len(node_id) {
                        Ok(len) => len,
                        Err(_) => return STATUS_DATA_ERROR,
                    }
                } else { 0 };
                let Some(cost) = SNAP_RECORD_FIXED_LEN
                    .checked_add(new_name.trim_start_matches('\\').len())
                    .and_then(|len| len.checked_add(data))
                else { return STATUS_DATA_ERROR; };
                cost
            } else { 0 };
            let Some(old) = old_paths.checked_add(replacement) else {
                return STATUS_DATA_ERROR;
            };
            match budget.project(old, new_paths) {
                Ok(next) => Some(next),
                Err(status) => return status,
            }
        } else { None };
        let status = self.volume.apply_rename_into_parent(plan);
        if status == STATUS_SUCCESS {
            self.publish_snapshot_size(next_snapshot_size);
            let filter = if self.volume.is_dir(source) {
                crate::FILE_NOTIFY_CHANGE_DIR_NAME
            } else {
                crate::FILE_NOTIFY_CHANGE_FILE_NAME
            };
            self.notifications.report_changes(&[
                crate::DirectoryChange {
                    full_path: &old_name,
                    filter,
                    action: crate::FILE_ACTION_RENAMED_OLD_NAME,
                },
                crate::DirectoryChange {
                    full_path: &new_name,
                    filter,
                    action: crate::FILE_ACTION_RENAMED_NEW_NAME,
                },
            ]);
            self.volume.touch_change(source);
            if let Some(name) = self.volume.opened_name(source_entry) {
                for object in self.handles.iter_mut().flatten() {
                    if object.entry_id == source_entry {
                        object.opened_name.clone_from(&name);
                    }
                }
            }
            self.reap_unlinked_nodes();
        }
        status
    }

    /// A replace target counts as open while any handle to its node remains; a File that has
    /// only its cleanup or in-flight I/O references left no longer holds the name.
    fn rename_replace_target_is_open(
        &self,
        source_entry: u64,
        root: FileRenameRoot,
        target: &str,
    ) -> bool {
        let start = match root {
            FileRenameRoot::SourceParent => {
                match self.volume.entry_location(source_entry) {
                    Some((parent, _, _)) => Some(parent),
                    None => return false,
                }
            }
            FileRenameRoot::VolumeRoot => None,
            FileRenameRoot::Directory(directory) => match self.obj(directory) {
                Some(object) => Some(object.node_id),
                None => return false,
            },
        };
        let target = match root {
            FileRenameRoot::VolumeRoot => target.trim_start_matches('\\'),
            _ => target,
        };
        self.volume
            .rename_replace_target(source_entry, start, target)
            .is_some_and(|node| {
                self.handles
                    .iter()
                    .flatten()
                    .any(|object| object.node_id == node && object.handle_references != 0)
            })
    }

    /// Rename a live File for a caller, using a canonical filesystem root and a UTF-16LE name.
    /// Caller handles never enter this API; `Directory` is this filesystem's
    /// retained File identity. A replace target that is still open is denied.
    pub fn zw_rename_file(
        &mut self,
        handle: u64,
        root: FileRenameRoot,
        target_name: &[u8],
        replace_if_exists: bool,
    ) -> u32 {
        let target = match Self::decode_utf16_name(target_name) {
            Ok(target) => normalize_separators(&target),
            Err(status) => return status,
        };
        self.rename_file_decoded(handle, root, &target, replace_if_exists, OpenReplaceTarget::Deny)
    }

    fn link_file_decoded(
        &mut self,
        handle: u64,
        root: FileRenameRoot,
        target: &str,
        replace_if_exists: bool,
    ) -> u32 {
        let Some((source, source_entry)) = self
            .obj(handle)
            .map(|object| (object.node_id, object.entry_id))
        else {
            return STATUS_INVALID_HANDLE;
        };
        if self.wal_protected_subtree(source) || self.reserved_replacement_node(source) {
            return STATUS_ACCESS_DENIED;
        }
        if target.is_empty() || self.to_relative(target).is_some() {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(new_name) = self.rename_target_name(handle, root, target) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        if self.wal_protected_target_name(&new_name) {
            return STATUS_ACCESS_DENIED;
        }
        let (start, target) = match root {
            FileRenameRoot::SourceParent => {
                if target.starts_with('\\') {
                    return STATUS_INVALID_PARAMETER;
                }
                let Some((parent, _, entry_node)) = self.volume.entry_location(source_entry) else {
                    return STATUS_OBJECT_NAME_NOT_FOUND;
                };
                if entry_node != source { return STATUS_INVALID_HANDLE; }
                (Some(parent), target)
            }
            FileRenameRoot::VolumeRoot => {
                let target = target.trim_start_matches('\\');
                if target.is_empty() {
                    return STATUS_INVALID_PARAMETER;
                }
                (None, target)
            }
            FileRenameRoot::Directory(directory) => {
                if target.starts_with('\\') {
                    return STATUS_INVALID_PARAMETER;
                }
                let Some(root_id) = self.obj(directory).map(|object| object.node_id) else {
                    return STATUS_INVALID_HANDLE;
                };
                if !self.volume.is_dir(root_id) {
                    return STATUS_NOT_A_DIRECTORY;
                }
                (Some(root_id), target)
            }
        };
        let plan = match self.volume.prepare_link_relative(
            source, start, target, replace_if_exists,
        ) {
            Ok(plan) => plan,
            Err(status) => return status,
        };
        if matches!(&plan, PreparedLink::Add { replacement_entry: Some(entry), .. }
            if self.volume.entry_location(*entry).is_some_and(|(_, _, node)|
                self.reserved_replacement_node(node))) {
            return STATUS_ACCESS_DENIED;
        }
        let next_snapshot_size = if let (Some(budget), PreparedLink::Add {
            replacement_entry, ..
        }) = (&self.snapshot_budget, &plan) {
            let Some(record) = SNAP_RECORD_FIXED_LEN
                .checked_add(new_name.trim_start_matches('\\').len()) else {
                return STATUS_DATA_ERROR;
            };
            let source_data = match self.volume.node(source) {
                Some(node) if node.link_count == 0 => {
                    match MemFs::snapshot_file_data_encoded_len(&self.volume.blobs, &node.data) {
                        Ok(len) => len,
                        Err(_) => return STATUS_DATA_ERROR,
                    }
                }
                Some(_) => 0,
                None => return STATUS_DATA_ERROR,
            };
            let old_data = if let Some(entry) = replacement_entry {
                let Some((_, _, node_id)) = self.volume.entry_location(*entry) else {
                    return STATUS_DATA_ERROR;
                };
                if self.volume.node(node_id).is_some_and(|node| node.link_count == 1) {
                    match self.volume.live_file_data_encoded_len(node_id) {
                        Ok(len) => len,
                        Err(_) => return STATUS_DATA_ERROR,
                    }
                } else { 0 }
            } else { 0 };
            let old = if replacement_entry.is_some() {
                record.checked_add(old_data)
            } else { Some(0) };
            let Some(old) = old else { return STATUS_DATA_ERROR; };
            let Some(new) = record.checked_add(source_data) else { return STATUS_DATA_ERROR; };
            match budget.project(old, new) {
                Ok(next) => Some(next),
                Err(status) => return status,
            }
        } else { None };
        let status = self.volume.apply_link(plan);
        if status == STATUS_SUCCESS {
            self.publish_snapshot_size(next_snapshot_size);
            self.notifications.report_change(crate::DirectoryChange {
                full_path: &new_name,
                filter: crate::FILE_NOTIFY_CHANGE_FILE_NAME,
                action: crate::FILE_ACTION_ADDED,
            });
            self.volume.touch_change(source);
            self.reap_unlinked_nodes();
        }
        status
    }

    /// Create a hard link to a live non-directory File through a canonical filesystem parse root.
    pub fn zw_link_file(
        &mut self,
        handle: u64,
        root: FileRenameRoot,
        target_name: &[u8],
        replace_if_exists: bool,
    ) -> u32 {
        let target = match Self::decode_utf16_name(target_name) {
            Ok(target) => normalize_separators(&target),
            Err(status) => return status,
        };
        self.link_file_decoded(handle, root, &target, replace_if_exists)
    }

    /// `ZwCreateFile` (spec §8.1): resolve the path, apply the create disposition, and return a
    /// file handle.
    pub fn zw_create_file(
        &mut self,
        path: &str,
        desired_access: u32,
        file_attributes: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
    ) -> CreateResult {
        self.zw_create_file_with_reservation(
            path, desired_access, file_attributes, share_access, disposition, options, None,
        )
    }

    /// Open the exact file named by a retained capacity reservation, consuming only its
    /// precharged CREATE record if this operation actually publishes a new file.
    pub fn zw_create_file_reserved(
        &mut self,
        token: &mut SnapshotCapacityReservation,
        path: &str,
        desired_access: u32,
        file_attributes: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
    ) -> CreateResult {
        let fail = |status| CreateResult {
            status, handle: INVALID_HANDLE, information: 0,
        };
        let Some(budget) = &self.snapshot_budget else { return fail(STATUS_DEVICE_NOT_READY); };
        if !budget.owns(token) || token.kind != SnapshotReservationKind::Append
            || !matches!(disposition, FILE_OPEN | FILE_OPEN_IF | FILE_CREATE) {
            return fail(STATUS_INVALID_DEVICE_REQUEST);
        }
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return fail(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        if !rel.eq_ignore_ascii_case(&token.relative_path) {
            return fail(STATUS_INVALID_PARAMETER);
        }
        let result = self.zw_create_file_with_reservation(
            path, desired_access, file_attributes, share_access, disposition, options,
            Some(token),
        );
        if result.status == STATUS_SUCCESS {
            let node_id = self.obj(result.handle).expect("reserved opened File").node_id;
            let file_id = self.volume.node(node_id).expect("reserved opened node").file_id;
            token.file_id = Some(file_id);
            token.create_charge = 0;
        }
        result
    }

    fn zw_create_file_with_reservation(
        &mut self,
        path: &str,
        desired_access: u32,
        file_attributes: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
        reservation: Option<&SnapshotCapacityReservation>,
    ) -> CreateResult {
        let fail = |status| CreateResult {
            status,
            handle: INVALID_HANDLE,
            information: 0,
        };
        if let Err(status) = validate_file_create_parameters(
            desired_access,
            file_attributes,
            share_access,
            disposition,
            options,
        ) {
            return fail(status);
        }
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return fail(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        let share = FileShareAccess::new(desired_access, share_access);
        if disposition != FILE_CREATE {
            if let Some((node_id, _)) = self.volume.lookup_entry_from(0, &rel) {
                if let Err(status) = self.check_share_access(node_id, share) {
                    return fail(status);
                }
            }
        }
        self.create_and_publish(options, share, reservation, |volume, allocator| {
            volume.prepare_create(&rel, disposition, options, file_attributes, allocator)
        })
    }

    /// `ZwCreateFile` for a caller that already resolved and folded a path into this volume.
    ///
    /// This is the same create/open semantics as [`Self::zw_create_file`], but avoids allocating an
    /// NT path string and folded lookup strings on hot in-kernel writable-overlay paths.
    pub fn zw_create_file_relative(
        &mut self,
        relative: &[u8],
        desired_access: u32,
        file_attributes: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
    ) -> CreateResult {
        let fail = |status| CreateResult {
            status,
            handle: INVALID_HANDLE,
            information: 0,
        };
        if let Err(status) = validate_file_create_parameters(
            desired_access,
            file_attributes,
            share_access,
            disposition,
            options,
        ) {
            return fail(status);
        }
        let share = FileShareAccess::new(desired_access, share_access);
        if disposition != FILE_CREATE {
            if let Some((node_id, _)) = self.volume.lookup_folded_entry_from(0, relative) {
                if let Err(status) = self.check_share_access(node_id, share) {
                    return fail(status);
                }
            }
        }
        self.create_and_publish(options, share, None, |volume, allocator| {
            volume.prepare_create_folded(
                0, relative, disposition, options, file_attributes, allocator,
            )
        })
    }

    /// Import a missing installed file into this volume before applying a caller's create
    /// disposition. The source supplies durable contents and metadata, while MemFs allocates the
    /// target volume's stable file identity. An existing writable entry always wins and is left
    /// unchanged.
    ///
    /// This is a filesystem composition primitive, not a syscall success path: it publishes no
    /// File object. The caller must subsequently use `zw_create_file_relative` so options,
    /// disposition, and open-description lifetime are handled exactly once by the normal path.
    pub fn import_file_relative(
        &mut self,
        relative: &[u8],
        metadata: FileMetadata,
        bytes: Vec<u8>,
    ) -> Result<bool, u32> {
        if self.volume.lookup_folded_relative(relative).is_some() {
            return Ok(false);
        }
        if relative.is_empty()
            || relative.first() == Some(&b'\\')
            || metadata.is_directory
            || metadata.delete_pending
            || metadata.reparse_tag != 0
            || metadata.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || metadata.end_of_file != bytes.len() as u64
            || metadata.valid_data_length > metadata.end_of_file
            || (metadata.allocation_size != 0 && metadata.allocation_size < metadata.end_of_file)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let (parent_path, leaf) =
            MemFs::parent_and_leaf_bytes(relative).ok_or(STATUS_INVALID_PARAMETER)?;
        let parent = self
            .volume
            .lookup_folded_relative(parent_path)
            .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        if !self.volume.is_dir(parent) {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        }
        let leaf = core::str::from_utf8(leaf).map_err(|_| STATUS_INVALID_PARAMETER)?;
        if leaf.is_empty() || leaf == "." || leaf == ".." {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let plan = self.volume.prepare_create_child(
            parent, leaf, FILE_NON_DIRECTORY_FILE, 0,
            &mut file_create::CreateAllocator::default(),
        )?;
        let next = self.project_provision_relative(relative, Some(&bytes))?;
        let (node_id, entry_id, _) = self.volume.apply_create(plan);
        if !self.volume.set_file_data_owned(node_id, bytes) {
            let _ = self.volume.unlink_entry(entry_id);
            self.volume.reap_unlinked(node_id);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let node = self.volume.node_mut(node_id).unwrap();
        node.creation_time = metadata.creation_time;
        node.last_access_time = metadata.last_access_time;
        node.last_write_time = metadata.last_write_time;
        node.change_time = metadata.change_time;
        node.allocation_size =
            allocation_size_for_eof(metadata.allocation_size.max(metadata.end_of_file));
        node.valid_data_length = metadata.valid_data_length;
        node.attributes = match metadata.attributes & FILE_ATTRIBUTE_SETTABLE {
            0 => FILE_ATTRIBUTE_NORMAL,
            attributes => attributes,
        };
        self.publish_snapshot_size(next);
        Ok(true)
    }

    /// Complete a prepared lower-layer CREATE as one resident namespace transaction. The caller
    /// has already proved `parent_path` against the immutable installed source and owns `bytes`.
    /// No backing-device I/O occurs here. A failed final CREATE removes only entries this call
    /// created; a pre-existing writable entry and its handles remain untouched.
    pub fn create_prepared_overlay_relative(
        &mut self,
        relative: &[u8],
        parent_path: Option<&[u8]>,
        import: Option<(FileMetadata, Vec<u8>)>,
        desired_access: u32,
        file_attributes: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
    ) -> CreateResult {
        let first_entry = self.volume.next_entry_id;
        let first_file = self.volume.next_file_id;
        let first_node_len = self.volume.nodes.len();
        let first_snapshot_size = self.snapshot_budget.as_ref().map(SnapshotBudget::encoded_len);
        let fail = |status| CreateResult {
            status, handle: INVALID_HANDLE, information: 0,
        };
        // The import must fit with all newly materialized parents before the first name effect.
        if let Some((_, bytes)) = &import {
            if let Err(status) = self.project_provision_relative(relative, Some(bytes)) {
                return fail(status);
            }
        } else if let Some(parent) = parent_path {
            if let Err(status) = self.project_provision_relative(parent, None) {
                return fail(status);
            }
        }
        let result = (|| {
            if let Some(parent) = parent_path {
                let next = match self.project_provision_relative(parent, None) {
                    Ok(next) => next,
                    Err(status) => return fail(status),
                };
                if let Err(status) = self.volume.materialize_parent_folded_relative(parent) {
                    return fail(status);
                }
                self.publish_snapshot_size(next);
            }
            if let Some((metadata, bytes)) = import {
                if let Err(status) = self.import_file_relative(relative, metadata, bytes) {
                    return fail(status);
                }
            }
            self.zw_create_file_relative(relative, desired_access, file_attributes,
                share_access, disposition, options)
        })();
        if result.status == STATUS_SUCCESS {
            return result;
        }
        // Provisioning and import publish neither handles nor notifications. `zw_create` plans
        // all fallible work before `apply_create`, so a failed result added no File object or
        // entry. Reverse identity order removes the imported leaf before any new parent.
        let mut entry = self.volume.next_entry_id;
        while entry > first_entry {
            entry -= 1;
            if self.volume.entry_location(entry).is_some() {
                let node = self.volume.unlink_entry(entry)
                    .expect("newly created transaction entry has no published child");
                self.volume.reap_unlinked(node);
            }
        }
        self.volume.nodes.truncate(first_node_len);
        self.volume.next_file_id = first_file;
        self.volume.next_entry_id = first_entry;
        if let Some(first) = first_snapshot_size {
            self.snapshot_budget.as_mut().expect("configured snapshot budget").publish(first);
        }
        result
    }

    /// Create or open a folded path beneath an existing directory FILE_OBJECT. The directory's
    /// node identity, rather than a reconstructed absolute string, is the parse root.
    pub fn zw_create_file_relative_to_directory(
        &mut self,
        root_directory: u64,
        relative: &[u8],
        desired_access: u32,
        file_attributes: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
    ) -> CreateResult {
        let fail = |status| CreateResult {
            status,
            handle: INVALID_HANDLE,
            information: 0,
        };
        if let Err(status) = validate_file_create_parameters(
            desired_access,
            file_attributes,
            share_access,
            disposition,
            options,
        ) {
            return fail(status);
        }
        let Some(root_node) = self.obj(root_directory).map(|object| object.node_id) else {
            return fail(STATUS_INVALID_HANDLE);
        };
        let Some(root) = self.volume.node(root_node) else {
            return fail(STATUS_INVALID_HANDLE);
        };
        if !root.is_dir {
            return fail(STATUS_NOT_A_DIRECTORY);
        }
        if relative.is_empty() || relative.first() == Some(&b'\\') {
            return fail(STATUS_INVALID_PARAMETER);
        }
        let share = FileShareAccess::new(desired_access, share_access);
        if disposition != FILE_CREATE {
            if let Some((node_id, _)) = self.volume.lookup_folded_entry_from(root_node, relative) {
                if let Err(status) = self.check_share_access(node_id, share) {
                    return fail(status);
                }
            }
        }
        self.create_and_publish(options, share, None, |volume, allocator| {
            volume.prepare_create_folded(
                root_node, relative, disposition, options, file_attributes, allocator,
            )
        })
    }

    /// `ZwReadFile` (spec §8.2). `byte_offset` `None` uses + advances the file object offset.
    /// Returns `(status, bytes)`; a read at/after EOF yields `STATUS_END_OF_FILE`.
    pub fn zw_read_file(
        &mut self,
        handle: u64,
        byte_offset: Option<u64>,
        length: usize,
    ) -> (u32, Vec<u8>) {
        let Some(obj) = self.obj(handle) else {
            return (STATUS_INVALID_HANDLE, Vec::new());
        };
        let node_id = obj.node_id;
        if self.volume.is_dir(node_id) {
            return (STATUS_INVALID_DEVICE_REQUEST, Vec::new());
        }
        let offset = byte_offset.unwrap_or(obj.current_offset);
        if offset >= self.volume.size(node_id) {
            return (STATUS_END_OF_FILE, Vec::new());
        }
        let bytes = self.volume.read_at(node_id, offset, length);
        self.recent_immutable_read =
            self.volume
                .immutable_read_extent(node_id, offset, bytes.len());
        if byte_offset.is_none() {
            self.obj_mut(handle).unwrap().current_offset = offset + bytes.len() as u64;
        }
        (STATUS_SUCCESS, bytes)
    }

    /// Read backing bytes without logical-file position or access-metadata side effects. Cache
    /// owners use this for fragments; the native operation accounts for the complete read once.
    /// An exact immutable source range is retained briefly so a following copy write can share it.
    pub fn read_backing_into(
        &mut self,
        handle: u64,
        offset: u64,
        output: &mut [u8],
    ) -> (u32, usize) {
        self.recent_immutable_read = None;
        let Some(obj) = self.obj(handle) else {
            return (STATUS_INVALID_HANDLE, 0);
        };
        let node_id = obj.node_id;
        if self.volume.is_dir(node_id) {
            return (STATUS_INVALID_DEVICE_REQUEST, 0);
        }
        if output.is_empty() {
            return (STATUS_SUCCESS, 0);
        }
        if offset >= self.volume.size(node_id) {
            return (STATUS_END_OF_FILE, 0);
        }
        let read = self.volume.read_at_into(node_id, offset, output);
        self.recent_immutable_read = self.volume.immutable_read_extent(node_id, offset, read);
        (STATUS_SUCCESS, read)
    }

    /// `ZwReadFile` into caller-provided storage. Same semantics as [`Self::zw_read_file`], but
    /// avoids allocating an intermediate byte vector on hot copy paths.
    pub fn zw_read_file_into(
        &mut self,
        handle: u64,
        byte_offset: Option<u64>,
        output: &mut [u8],
    ) -> (u32, usize) {
        let Some(obj) = self.obj(handle) else {
            return (STATUS_INVALID_HANDLE, 0);
        };
        let offset = byte_offset.unwrap_or(obj.current_offset);
        let (status, read) = self.read_backing_into(handle, offset, output);
        if status != STATUS_SUCCESS {
            return (status, read);
        }
        let position = byte_offset.is_none().then_some(offset + read as u64);
        let status = self.complete_read(handle, read, position);
        debug_assert_eq!(status, STATUS_SUCCESS);
        (STATUS_SUCCESS, read)
    }

    /// Account for one completed read, whether its bytes came from resident pages or backing.
    /// The I/O Manager supplies a position only when FILE_OBJECT mode requires an update.
    pub fn complete_read(&mut self, handle: u64, transferred: usize, position: Option<u64>) -> u32 {
        let Some(obj) = self.obj(handle) else {
            return STATUS_INVALID_HANDLE;
        };
        let node_id = obj.node_id;
        if self.volume.is_dir(node_id) {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        if transferred != 0 {
            self.volume.touch_access(node_id);
            self.report_handle_change(handle, crate::FILE_NOTIFY_CHANGE_LAST_ACCESS);
        }
        self.complete_file_position(handle, position)
    }

    /// Publish the I/O Manager's completed position on the retained FILE_OBJECT.
    pub fn complete_file_position(&mut self, handle: u64, position: Option<u64>) -> u32 {
        let Some(obj) = self.obj_mut(handle) else {
            return STATUS_INVALID_HANDLE;
        };
        if let Some(position) = position {
            obj.current_offset = position;
        }
        STATUS_SUCCESS
    }

    /// `ZwWriteFile` (spec §8.3). `byte_offset` `None` uses + advances the file object offset.
    /// Returns `(status, bytes_written)`.
    pub fn zw_write_file(
        &mut self,
        handle: u64,
        byte_offset: Option<u64>,
        data: &[u8],
    ) -> (u32, usize) {
        let Some(obj) = self.obj(handle) else {
            return (STATUS_INVALID_HANDLE, 0);
        };
        let node_id = obj.node_id;
        if self.volume.is_dir(node_id) {
            return (STATUS_INVALID_DEVICE_REQUEST, 0);
        }
        if self.wal_protected_node(node_id) {
            return (STATUS_ACCESS_DENIED, 0);
        }
        let offset = byte_offset.unwrap_or(obj.current_offset);
        let next_snapshot_size = if self.snapshot_budget.is_some() && !data.is_empty() {
            let next_data_cost = match self.volume.projected_write_data_cost(
                node_id, offset, data, self.recent_immutable_read,
            ) {
                Ok(cost) => cost,
                Err(status) => return (status, 0),
            };
            match self.project_snapshot_data_cost(node_id, next_data_cost) {
                Ok(next) => next,
                Err(status) => return (status, 0),
            }
        } else { None };
        let recent_read = self.recent_immutable_read.take();
        let n = self.volume.write_at(node_id, offset, data, recent_read);
        if !data.is_empty() && n == 0 {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        self.publish_snapshot_size(next_snapshot_size);
        if byte_offset.is_none() {
            self.obj_mut(handle).unwrap().current_offset = offset + n as u64;
        }
        if n != 0 {
            self.volume.ensure_allocation_covers_eof(node_id);
            self.volume
                .mark_data_initialized_through(node_id, offset + n as u64);
            self.volume.touch_write(node_id);
            self.report_handle_change(
                handle,
                crate::FILE_NOTIFY_CHANGE_SIZE | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
            );
        }
        (STATUS_SUCCESS, n)
    }

    /// Append bytes to the end of an open file without scanning unrelated immutable backing blobs.
    pub fn zw_append_file(&mut self, handle: u64, data: &[u8]) -> (u32, usize) {
        let Some(obj) = self.obj(handle) else {
            return (STATUS_INVALID_HANDLE, 0);
        };
        let node_id = obj.node_id;
        if self.volume.is_dir(node_id) {
            return (STATUS_INVALID_DEVICE_REQUEST, 0);
        }
        if self.wal_protected_node(node_id) {
            return (STATUS_ACCESS_DENIED, 0);
        }
        if data.is_empty() {
            return (STATUS_SUCCESS, 0);
        }
        let next_snapshot_size = match self.project_snapshot_append(node_id, data.len()) {
            Ok(next) => next,
            Err(status) => return (status, 0),
        };
        let n = self.volume.append_at_end(node_id, data);
        if n == 0 {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        self.publish_snapshot_size(next_snapshot_size);
        let end = self.volume.size(node_id);
        self.obj_mut(handle).unwrap().current_offset = end;
        self.volume.ensure_allocation_covers_eof(node_id);
        self.volume.mark_data_initialized_through(node_id, end);
        self.volume.touch_write(node_id);
        self.report_handle_change(
            handle,
            crate::FILE_NOTIFY_CHANGE_SIZE | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
        );
        (STATUS_SUCCESS, n)
    }

    /// Append bytes to a file named by NT path without allocating a transient `FILE_OBJECT`.
    ///
    /// This is still the same mounted-volume create/open and append operation as the Zw facade, but
    /// it is intended for kernel-owned metadata streams such as hive journals where the caller
    /// already has the path and does not need a handle cursor.
    pub fn append_file_by_path(&mut self, path: &str, data: &[u8]) -> (u32, usize) {
        if data.is_empty() {
            return (STATUS_SUCCESS, 0);
        }
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return (STATUS_OBJECT_PATH_NOT_FOUND, 0);
        };
        if self.volume.lookup(&rel).is_some_and(|node_id| {
            self.wal_protected_node(node_id) || self.reserved_replacement_node(node_id)
        }) {
            return (STATUS_ACCESS_DENIED, 0);
        }
        let mut allocator = file_create::CreateAllocator::default();
        let mut plan = match self.volume.prepare_create(
            &rel, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, 0, &mut allocator,
        ) {
            Ok(plan) => plan,
            Err(status) => return (status, 0),
        };
        let opened_name = if matches!(&plan, file_create::PreparedCreate::New { .. }) {
            match self.volume.create_opened_name(&plan, &mut allocator) {
                Ok(name) => name,
                Err(status) => return (status, 0),
            }
        } else { String::new() };
        let (node_id, next_snapshot_size) = match &mut plan {
            file_create::PreparedCreate::Existing { node, .. } => {
                if self.volume.is_dir(*node) { return (STATUS_FILE_IS_A_DIRECTORY, 0); }
                let next = match self.project_snapshot_append(*node, data.len()) {
                    Ok(next) => next,
                    Err(status) => return (status, 0),
                };
                let written = self.volume.append_at_end(*node, data);
                if written != data.len() {
                    return (STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                (*node, next)
            }
            file_create::PreparedCreate::New { node, entry, .. } => {
                let mut owned = Vec::new();
                if owned.try_reserve_exact(data.len()).is_err() {
                    return (STATUS_INSUFFICIENT_RESOURCES, 0);
                }
                owned.extend_from_slice(data);
                node.allocation_size = allocation_size_for_eof(data.len() as u64);
                node.valid_data_length = data.len() as u64;
                node.data = FileData::Bytes(owned);
                let next = match &self.snapshot_budget {
                    Some(budget) => {
                        let Some(cost) = SNAP_RECORD_FIXED_LEN
                            .checked_add(opened_name.trim_start_matches('\\').len())
                            .and_then(|len| len.checked_add(if data.is_empty() { 0 } else { 9 }))
                            .and_then(|len| len.checked_add(data.len()))
                        else { return (STATUS_DATA_ERROR, 0); };
                        match budget.project(0, cost) {
                            Ok(next) => Some(next),
                            Err(status) => return (status, 0),
                        }
                    }
                    None => None,
                };
                (entry.node_id, next)
            }
        };
        if matches!(&plan, file_create::PreparedCreate::New { .. }) {
            self.volume.apply_create(plan);
        }
        self.publish_snapshot_size(next_snapshot_size);
        self.volume.ensure_allocation_covers_eof(node_id);
        self.volume
            .mark_data_initialized_through(node_id, self.volume.size(node_id));
        self.volume.touch_write(node_id);
        (STATUS_SUCCESS, data.len())
    }

    /// Complete an append whose exact CREATE and data growth were reserved before a native
    /// durable effect. A refusal returns the same move-only token, including after uncertainty.
    pub fn append_file_by_path_reserved(
        &mut self,
        token: SnapshotCapacityReservation,
        path: &str,
        data: &[u8],
    ) -> Result<usize, (u32, SnapshotCapacityReservation)> {
        self.append_file_by_path_reserved_inner(token, path, data, false)
    }

    fn append_file_by_path_reserved_inner(
        &mut self,
        token: SnapshotCapacityReservation,
        path: &str,
        data: &[u8],
        replay_anchored_wal: bool,
    ) -> Result<usize, (u32, SnapshotCapacityReservation)> {
        let Some(budget) = &self.snapshot_budget else {
            return Err((STATUS_DEVICE_NOT_READY, token));
        };
        if !budget.owns(&token) || token.kind != SnapshotReservationKind::Append
            || token.create_charge != 0
            || token.bytes_len != data.len()
            || token.append_charge != if data.is_empty() { 0 } else {
                SNAP_EXTENT_HEADER_LEN.checked_add(data.len()).unwrap_or(usize::MAX)
            }
        {
            return Err((STATUS_DATA_ERROR, token));
        }
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return Err((STATUS_OBJECT_PATH_NOT_FOUND, token));
        };
        if !rel.eq_ignore_ascii_case(&token.relative_path) {
            return Err((STATUS_INVALID_PARAMETER, token));
        }
        let Some(node_id) = self.volume.lookup(&rel) else {
            return Err((STATUS_OBJECT_NAME_NOT_FOUND, token));
        };
        let Some(node) = self.volume.node(node_id) else {
            return Err((STATUS_DATA_ERROR, token));
        };
        if node.is_dir { return Err((STATUS_FILE_IS_A_DIRECTORY, token)); }
        if Some(node.file_id) != token.file_id {
            return Err((STATUS_DATA_ERROR, token));
        }
        if !replay_anchored_wal && self.wal_protected_node(node_id) {
            return Err((STATUS_ACCESS_DENIED, token));
        }
        let old = match self.volume.live_file_data_encoded_len(node_id) {
            Ok(old) => old,
            Err(_) => return Err((STATUS_DATA_ERROR, token)),
        };
        let Some(next_cost) = old.checked_add(token.append_charge) else {
            return Err((STATUS_DATA_ERROR, token));
        };
        let next = match budget.project_reserved(
            &token, old, next_cost, token.append_charge,
        ) {
            Ok(next) => next,
            Err(status) => return Err((status, token)),
        };
        if !data.is_empty() && self.volume.append_at_end(node_id, data) != data.len() {
            return Err((STATUS_INSUFFICIENT_RESOURCES, token));
        }
        self.snapshot_budget.as_mut().expect("reserved append budget")
            .publish_reserved(&token, next, token.append_charge);
        self.volume.ensure_allocation_covers_eof(node_id);
        self.volume.mark_data_initialized_through(node_id, self.volume.size(node_id));
        self.volume.touch_write(node_id);
        if let Err(status) = self.snapshot_budget.as_mut().expect("reserved append budget")
            .finish(&token)
        {
            return Err((status, token));
        }
        Ok(data.len())
    }

    /// Replace the whole contents of an open file by taking ownership of `data`.
    ///
    /// This is an internal helper for checkpoint providers that already materialized a complete
    /// image. It preserves the normal handle and directory validation of the Zw facade while
    /// avoiding an additional copy into MemFs storage.
    pub fn replace_file_data_owned(&mut self, handle: u64, data: Vec<u8>) -> u32 {
        let Some(obj) = self.obj(handle) else {
            return STATUS_INVALID_HANDLE;
        };
        let node_id = obj.node_id;
        if self.volume.is_dir(node_id) {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        if self.wal_protected_node(node_id) {
            return STATUS_ACCESS_DENIED;
        }
        let next_data_cost = if data.is_empty() { Some(0) } else {
            data.len().checked_add(9)
        };
        let Some(next_data_cost) = next_data_cost else { return STATUS_DATA_ERROR; };
        let next_snapshot_size = match self.project_snapshot_data_cost(node_id, next_data_cost) {
            Ok(next) => next,
            Err(status) => return status,
        };
        let len = data.len() as u64;
        if !self.volume.set_file_data_owned(node_id, data) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        self.publish_snapshot_size(next_snapshot_size);
        self.obj_mut(handle).unwrap().current_offset = len;
        self.volume.touch_write(node_id);
        self.report_handle_change(
            handle,
            crate::FILE_NOTIFY_CHANGE_SIZE | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
        );
        STATUS_SUCCESS
    }

    /// Consume a previously retained future replacement at the same instant as its file data
    /// effect. On refusal, ownership of both the charge and image returns to the caller.
    pub fn replace_file_data_owned_reserved(
        &mut self, token: SnapshotCapacityReservation, handle: u64, data: Vec<u8>,
    ) -> Result<(), (u32, SnapshotCapacityReservation, Vec<u8>)> {
        let fail = |status, token, data| Err((status, token, data));
        let Some(budget) = &self.snapshot_budget else {
            return fail(STATUS_DEVICE_NOT_READY, token, data);
        };
        if token.kind != SnapshotReservationKind::Replacement || !budget.owns(&token)
            || token.bytes_len != data.len() || token.create_charge != 0
        {
            return fail(STATUS_DATA_ERROR, token, data);
        }
        let Some(object) = self.obj(handle) else {
            return fail(STATUS_INVALID_HANDLE, token, data);
        };
        let node_id = object.node_id;
        let Some(node) = self.volume.node(node_id) else {
            return fail(STATUS_DATA_ERROR, token, data);
        };
        if node.is_dir { return fail(STATUS_FILE_IS_A_DIRECTORY, token, data); }
        if Some(node.file_id) != token.file_id {
            return fail(STATUS_DATA_ERROR, token, data);
        }
        let old = match self.volume.live_file_data_encoded_len(node_id) {
            Ok(old) => old,
            Err(_) => return fail(STATUS_DATA_ERROR, token, data),
        };
        let new = if data.is_empty() { 0 } else {
            match SNAP_EXTENT_HEADER_LEN.checked_add(data.len()) {
                Some(new) => new,
                None => return fail(STATUS_DATA_ERROR, token, data),
            }
        };
        if old != token.replacement_base_cost
            || new.saturating_sub(old) != token.append_charge {
            return fail(STATUS_DATA_ERROR, token, data);
        }
        let next = match budget.project_reserved(&token, old, new, token.append_charge) {
            Ok(next) => next,
            Err(status) => return fail(status, token, data),
        };
        let len = data.len() as u64;
        let Some(node) = self.volume.node_mut(node_id) else {
            return fail(STATUS_DATA_ERROR, token, data);
        };
        node.allocation_size = allocation_size_for_eof(len);
        node.valid_data_length = len;
        node.data = FileData::Bytes(data);
        self.snapshot_budget.as_mut().expect("reserved replacement budget")
            .publish_reserved(&token, next, token.append_charge);
        self.snapshot_budget.as_mut().expect("reserved replacement budget")
            .finish(&token).expect("fully consumed replacement reservation");
        self.obj_mut(handle).expect("validated replacement handle").current_offset = len;
        self.volume.touch_write(node_id);
        self.report_handle_change(handle,
            crate::FILE_NOTIFY_CHANGE_SIZE | crate::FILE_NOTIFY_CHANGE_LAST_WRITE);
        Ok(())
    }

    /// `ZwFlushBuffersFile` (spec §8.4) — MemFs is already coherent, so this is a no-op success.
    pub fn zw_flush_buffers_file(&mut self, handle: u64) -> u32 {
        if self.obj(handle).is_some() {
            STATUS_SUCCESS
        } else {
            STATUS_INVALID_HANDLE
        }
    }

    /// `ZwQueryInformationFile` for `FileStandardInformation` (spec §8.5, §18.2).
    pub fn zw_query_standard_information(&self, handle: u64) -> Option<StandardInformation> {
        let obj = self.obj(handle)?;
        Some(StandardInformation {
            end_of_file: self.volume.size(obj.node_id),
            is_directory: self.volume.is_dir(obj.node_id),
            attributes: self.volume.attributes(obj.node_id),
            number_of_links: self.volume.node(obj.node_id)?.link_count,
            delete_pending: obj.delete_pending,
        })
    }

    /// Query the filesystem-owned metadata for an open File object.
    pub fn zw_query_metadata(&self, handle: u64) -> Option<FileMetadata> {
        let obj = self.obj(handle)?;
        self.volume.metadata(obj.node_id, obj.delete_pending)
    }

    /// Return the volume-relative name of the exact entry used to open this File object.
    pub fn zw_query_opened_name(&self, handle: u64) -> Option<String> {
        let object = self.obj(handle)?;
        if object.entry_id == 0 || self.volume.entry_location(object.entry_id).is_some() {
            return self.volume.opened_name(object.entry_id);
        }
        let mut retained = String::new();
        retained.try_reserve_exact(object.opened_name.len()).ok()?;
        retained.push_str(&object.opened_name);
        Some(retained)
    }

    /// Return the alternate 8.3 name of the exact directory entry used to open this File object.
    /// An empty value means the filesystem supports short names but this entry has no alias.
    pub fn zw_query_short_name(&self, handle: u64) -> Option<FileShortName> {
        let object = self.obj(handle)?;
        self.volume.entry_short_name(object.entry_id)
    }

    /// `ZwQueryDirectoryFile` (spec §17): enumerate the directory this file object is open on,
    /// resuming from (and advancing) the file object's own cursor. `RestartScan` rewinds it. The
    /// record encoding is [`query_directory`] — the same encoder the read-only FAT volume uses.
    pub fn zw_query_directory_file(
        &mut self,
        handle: u64,
        information_class: u32,
        return_single_entry: bool,
        pattern: Option<&[u16]>,
        restart_scan: bool,
        output: &mut [u8],
    ) -> DirectoryQueryResult {
        let Some(obj) = self.obj(handle) else {
            return DirectoryQueryResult {
                status: STATUS_INVALID_HANDLE,
                information: 0,
            };
        };
        let node_id = obj.node_id;
        let Some(entry_count) = self.volume.directory_entry_count(node_id) else {
            return DirectoryQueryResult {
                status: STATUS_INVALID_PARAMETER,
                information: 0,
            };
        };
        let mut state = obj.query;
        let result = query_directory_by_index(
            &mut state,
            entry_count,
            |index| self.volume.directory_entry(node_id, index),
            information_class,
            return_single_entry,
            pattern,
            restart_scan,
            output,
        );
        self.obj_mut(handle).unwrap().query = state;
        result
    }

    /// `ZwSetInformationFile` (spec §19) for the classes a writable volume must serve:
    /// `FileBasicInformation` (attributes), disposition classes (delete-on-close),
    /// `FilePositionInformation`, `FileModeInformation`, and
    /// `FileEndOfFileInformation` / `FileAllocationInformation`
    /// (truncate/extend). Returns the NTSTATUS; unhandled classes are reported honestly.
    pub fn zw_set_information_file(&mut self, handle: u64, class: u32, data: &[u8]) -> u32 {
        let Some(obj) = self.obj(handle) else {
            return STATUS_INVALID_HANDLE;
        };
        let node_id = obj.node_id;
        if (self.wal_protected_subtree(node_id) || self.reserved_replacement_node(node_id))
            && matches!(class,
                FILE_DISPOSITION_INFORMATION | FILE_DISPOSITION_INFORMATION_EX
                | FILE_END_OF_FILE_INFORMATION | FILE_ALLOCATION_INFORMATION
                | FILE_VALID_DATA_LENGTH_INFORMATION | FILE_SHORT_NAME_INFORMATION
                | FILE_RENAME_INFORMATION | FILE_LINK_INFORMATION)
        {
            return STATUS_ACCESS_DENIED;
        }
        match class {
            FILE_MODE_INFORMATION => {
                if data.len() < 4 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let requested = u32::from_le_bytes(data[..4].try_into().unwrap());
                let next = match obj.mode_state.transition(requested) {
                    Ok(next) => next,
                    Err(status) => return status.raw() as u32,
                };
                debug_assert_eq!(
                    next.io_mode().map(|mode| mode.is_synchronous()),
                    crate::FileModeState::from_create_options(obj.create_options)
                        .io_mode().map(|mode| mode.is_synchronous()),
                );
                self.obj_mut(handle).expect("validated local File body").mode_state = next;
                STATUS_SUCCESS
            }
            FILE_BASIC_INFORMATION => self.set_basic_information(handle, data),
            FILE_DISPOSITION_INFORMATION => {
                if data.is_empty() {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                self.set_delete_disposition(handle, data[0] != 0, false)
            }
            FILE_DISPOSITION_INFORMATION_EX => {
                let flags = match Self::decode_disposition_ex_flags(data) {
                    Ok(flags) => flags,
                    Err(status) => return status,
                };
                self.set_delete_disposition(
                    handle,
                    flags & FILE_DISPOSITION_DELETE != 0,
                    flags & FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE != 0,
                )
            }
            FILE_POSITION_INFORMATION => {
                if data.len() < 8 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let offset = u64::from_le_bytes(data[0..8].try_into().unwrap());
                self.obj_mut(handle).unwrap().current_offset = offset;
                STATUS_SUCCESS
            }
            FILE_END_OF_FILE_INFORMATION => {
                if data.len() < 8 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let length = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let next_snapshot_size = if self.snapshot_budget.is_some() {
                    let next_data_cost = match self.volume.projected_end_of_file_data_cost(
                        node_id, length,
                    ) {
                        Ok(cost) => cost,
                        Err(status) => return status,
                    };
                    match self.project_snapshot_data_cost(node_id, next_data_cost) {
                        Ok(next) => next,
                        Err(status) => return status,
                    }
                } else { None };
                let status = self.volume.set_end_of_file(node_id, length);
                if status == STATUS_SUCCESS {
                    self.publish_snapshot_size(next_snapshot_size);
                    self.volume.touch_write(node_id);
                    self.report_handle_change(
                        handle,
                        crate::FILE_NOTIFY_CHANGE_SIZE | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
                    );
                }
                status
            }
            FILE_ALLOCATION_INFORMATION => {
                if data.len() < 8 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let allocation_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let next_snapshot_size = if self.snapshot_budget.is_some() {
                    let next_data_cost = match self.volume.projected_allocation_data_cost(
                        node_id, allocation_size,
                    ) {
                        Ok(cost) => cost,
                        Err(status) => return status,
                    };
                    match self.project_snapshot_data_cost(node_id, next_data_cost) {
                        Ok(next) => next,
                        Err(status) => return status,
                    }
                } else { None };
                let status = self.volume.set_allocation_size(node_id, allocation_size);
                if status == STATUS_SUCCESS {
                    self.publish_snapshot_size(next_snapshot_size);
                    self.volume.touch_write(node_id);
                    self.report_handle_change(
                        handle,
                        crate::FILE_NOTIFY_CHANGE_SIZE | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
                    );
                }
                status
            }
            FILE_VALID_DATA_LENGTH_INFORMATION => {
                if data.len() < 8 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                if !self.obj(handle).unwrap().open_privileges.manage_volume {
                    return STATUS_INVALID_PARAMETER;
                }
                let valid_data_length = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let status = self
                    .volume
                    .set_valid_data_length(node_id, valid_data_length);
                if status == STATUS_SUCCESS {
                    self.volume.touch_write(node_id);
                    self.report_handle_change(
                        handle,
                        crate::FILE_NOTIFY_CHANGE_SIZE | crate::FILE_NOTIFY_CHANGE_LAST_WRITE,
                    );
                }
                status
            }
            FILE_SHORT_NAME_INFORMATION => {
                let short_name = match parse_short_name_information(data) {
                    Ok(name) => name,
                    Err(status) => return status,
                };
                let entry_id = self.obj(handle).unwrap().entry_id;
                let status = self.volume.set_entry_short_name(entry_id, short_name);
                if status == STATUS_SUCCESS {
                    self.report_handle_change(handle, crate::FILE_NOTIFY_CHANGE_FILE_NAME);
                }
                status
            }
            // The filesystem's own image installers (hive checkpoints) rename through this
            // class and may replace a primary a reader still holds. Caller renames arrive
            // through `zw_rename_file`, which denies an open replace target.
            FILE_RENAME_INFORMATION => {
                let (replace_if_exists, root_directory, target) =
                    match Self::decode_rename_information(data) {
                        Ok(info) => info,
                        Err(status) => return status,
                    };
                if root_directory == 0 {
                    if let Some(target) = self.to_relative(&target) {
                        self.rename_file_decoded(
                            handle,
                            FileRenameRoot::VolumeRoot,
                            &target,
                            replace_if_exists,
                            OpenReplaceTarget::Allow,
                        )
                    } else if target.starts_with('\\') {
                        STATUS_NOT_SAME_DEVICE
                    } else {
                        self.rename_file_decoded(
                            handle,
                            FileRenameRoot::SourceParent,
                            &target,
                            replace_if_exists,
                            OpenReplaceTarget::Allow,
                        )
                    }
                } else {
                    self.rename_file_decoded(
                        handle,
                        FileRenameRoot::Directory(root_directory),
                        &target,
                        replace_if_exists,
                        OpenReplaceTarget::Allow,
                    )
                }
            }
            FILE_LINK_INFORMATION => {
                let (replace_if_exists, root_directory, target) =
                    match Self::decode_rename_information(data) {
                        Ok(info) => info,
                        Err(status) => return status,
                    };
                if root_directory == 0 {
                    if let Some(target) = self.to_relative(&target) {
                        self.link_file_decoded(
                            handle,
                            FileRenameRoot::VolumeRoot,
                            &target,
                            replace_if_exists,
                        )
                    } else if target.starts_with('\\') {
                        STATUS_NOT_SAME_DEVICE
                    } else {
                        self.link_file_decoded(
                            handle,
                            FileRenameRoot::SourceParent,
                            &target,
                            replace_if_exists,
                        )
                    }
                } else {
                    self.link_file_decoded(
                        handle,
                        FileRenameRoot::Directory(root_directory),
                        &target,
                        replace_if_exists,
                    )
                }
            }
            // These are valid native classes, but MemFs has no object-ID
            // namespace, physical cluster allocator, quota ledger, or link
            // tracking service. The request reached the filesystem, so report
            // an unsupported filesystem facility rather than an invalid class.
            29 | FILE_MOVE_CLUSTER_INFORMATION | 32 | FILE_TRACKING_INFORMATION => {
                STATUS_INVALID_PARAMETER
            }
            _ => STATUS_INVALID_INFO_CLASS,
        }
    }

    /// The file object's current byte offset — `FilePositionInformation`'s read side.
    pub fn current_offset(&self, handle: u64) -> Option<u64> {
        self.obj(handle).map(|obj| obj.current_offset)
    }

    /// I/O-Manager-owned `FileModeInformation` for this live `FILE_OBJECT`.
    pub fn file_mode(&self, handle: u64) -> Option<u32> {
        self.obj(handle).map(|obj| obj.mode_state.query_bits())
    }

    /// Create every missing directory along `path`, and return whether the leaf is a directory.
    /// This is volume PROVISIONING (the content a formatted/installed volume already carries), not
    /// a syscall path: hosted processes only ever reach the `Zw*` surface above.
    pub fn provision_directory(&mut self, path: &str) -> bool {
        self.provision_directory_checked(path).unwrap_or(false)
    }

    pub fn provision_directory_checked(&mut self, path: &str) -> Result<bool, u32> {
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        let next = self.project_provision_relative(rel.as_bytes(), None)?;
        let id = self.volume.ensure_dir(&rel);
        let is_dir = self.volume.is_dir(id);
        if is_dir { self.publish_snapshot_size(next); }
        Ok(is_dir)
    }

    /// Create every missing directory along a folded volume-relative path.
    ///
    /// This is the allocation-side twin of [`Self::zw_create_file_relative`]: callers that already
    /// resolved a path through the mount-prefix seam can provision installed volume content without
    /// depending on the `FileSystem` mount manager's DOS aliases.
    pub fn provision_directory_relative(&mut self, relative: &[u8]) -> bool {
        self.provision_directory_relative_checked(relative).unwrap_or(false)
    }

    pub fn provision_directory_relative_checked(&mut self, relative: &[u8])
        -> Result<bool, u32>
    {
        let next = self.project_provision_relative(relative, None)?;
        let Some(id) = self.volume.ensure_dir_folded_relative(relative) else {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        let is_dir = self.volume.is_dir(id);
        if is_dir { self.publish_snapshot_size(next); }
        Ok(is_dir)
    }

    /// Create `path` (and every missing directory above it) as a FILE holding `bytes`.
    ///
    /// This is volume PROVISIONING — the content an *installed* volume already carries because the
    /// installer put it there — not a syscall path: hosted processes only ever reach the `Zw*`
    /// surface above. It is the file-shaped sibling of [`provision_directory`](Self::provision_directory).
    /// Returns `false` if the path does not resolve to this volume or names an existing directory.
    pub fn provision_file(&mut self, path: &str, bytes: &[u8]) -> bool {
        self.provision_file_checked(path, bytes).unwrap_or(false)
    }

    pub fn provision_file_checked(&mut self, path: &str, bytes: &[u8])
        -> Result<bool, u32>
    {
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        let Some((parent_path, leaf)) = MemFs::parent_and_leaf(&rel) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let next = self.project_provision_relative(rel.as_bytes(), Some(bytes))?;
        let parent = self.volume.ensure_dir(parent_path);
        let id = match self.volume.child(parent, leaf) {
            Some(id) => id,
            None => self.volume.create_child(parent, leaf, false),
        };
        if self.volume.is_dir(id) {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let installed = self.volume.set_file_data(id, bytes);
        if installed {
            self.volume.touch_write(id);
        }
        if installed { self.publish_snapshot_size(next); }
        Ok(installed)
    }

    /// Create `path` as a FILE by taking ownership of `bytes`.
    ///
    /// This is for installed/kernel-owned provisioning paths that already built the complete image
    /// buffer. On path/type failure the buffer is returned to the caller so it can be retained for a
    /// later mount attempt instead of being silently dropped.
    pub fn provision_file_owned(&mut self, path: &str, bytes: Vec<u8>) -> Result<(), Vec<u8>> {
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return Err(bytes);
        };
        let Some((parent_path, leaf)) = MemFs::parent_and_leaf(&rel) else {
            return Err(bytes);
        };
        let next = match self.project_provision_relative(rel.as_bytes(), Some(&bytes)) {
            Ok(next) => next,
            Err(_) => return Err(bytes),
        };
        let parent = self.volume.ensure_dir(parent_path);
        let id = match self.volume.child(parent, leaf) {
            Some(id) => id,
            None => self.volume.create_child(parent, leaf, false),
        };
        if self.volume.is_dir(id) {
            return Err(bytes);
        }
        let installed = self.volume.set_file_data_owned(id, bytes);
        debug_assert!(installed);
        if installed {
            self.volume.touch_write(id);
            self.publish_snapshot_size(next);
        }
        Ok(())
    }

    /// Create a file by folded volume-relative path, and create every missing directory above it.
    pub fn provision_file_relative(&mut self, relative: &[u8], bytes: &[u8]) -> bool {
        self.provision_file_relative_checked(relative, bytes).unwrap_or(false)
    }

    pub fn provision_file_relative_checked(&mut self, relative: &[u8], bytes: &[u8])
        -> Result<bool, u32>
    {
        let Some((parent_path, leaf)) = MemFs::parent_and_leaf_bytes(relative) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let next = self.project_provision_relative(relative, Some(bytes))?;
        let Some(parent) = self.volume.ensure_dir_folded_relative(parent_path) else {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        let Ok(leaf) = core::str::from_utf8(leaf) else {
            return Err(STATUS_INVALID_PARAMETER);
        };
        let id = match self.volume.child(parent, leaf) {
            Some(id) => id,
            None => self.volume.create_child(parent, leaf, false),
        };
        if self.volume.is_dir(id) {
            return Err(STATUS_FILE_IS_A_DIRECTORY);
        }
        let installed = self.volume.set_file_data(id, bytes);
        if installed {
            self.volume.touch_write(id);
        }
        if installed { self.publish_snapshot_size(next); }
        Ok(installed)
    }

    /// A file's bytes, borrowed in place (no copy) — the read side [`provision_file`] writes.
    /// `None` when the path does not resolve to a file on this volume.
    pub fn file_bytes(&self, path: &str) -> Option<&[u8]> {
        let rel = self.to_relative(&normalize_separators(path))?;
        self.volume.file_data(&rel)
    }

    /// A file's bytes copied into an owned buffer. Unlike [`file_bytes`](Self::file_bytes), this
    /// works for extent-backed append files whose contents are not stored as one contiguous slice.
    pub fn file_bytes_owned(&self, path: &str) -> Option<Vec<u8>> {
        let rel = self.to_relative(&normalize_separators(path))?;
        self.volume.file_data_owned(&rel)
    }

    /// A file's logical byte length, including extent-backed append files.
    pub fn file_len(&self, path: &str) -> Option<u64> {
        let rel = self.to_relative(&normalize_separators(path))?;
        self.volume.file_len(&rel)
    }

    /// Stable node identity for an existing file. Missing paths and directories have no file id.
    pub fn existing_file_id(&self, path: &str) -> Option<u64> {
        self.query_metadata(path).filter(|metadata| !metadata.is_directory)
            .map(|metadata| metadata.file_id)
    }

    pub(crate) fn source_subtree_contains_file_id(&self, path: &str, file_id: u64) -> bool {
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return false;
        };
        self.volume.lookup(&rel)
            .is_some_and(|node| self.volume.subtree_contains_file_id(node, file_id))
    }

    /// Retain the exact log node and name while an anchored WAL suffix refers to its bytes.
    /// The caller must establish the durable baseline before its first physical WAL effect.
    pub fn protect_wal_log(&mut self, path: &str, file_id: u64) -> Result<(), u32> {
        let rel = self.to_relative(&normalize_separators(path))
            .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        let node_id = self.volume.lookup(&rel).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let node = self.volume.node(node_id).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if node.is_dir || node.file_id != file_id || node.link_count != 1
            || self.handles.iter().flatten()
                .any(|object| object.node_id == node_id && object.requests_delete())
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if !self.wal_protected_logs.contains(&node_id) {
            self.wal_protected_logs.try_reserve(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            self.wal_protected_logs.push(node_id);
        }
        Ok(())
    }

    /// Release names only after a durable two-slot fold covers every anchored WAL record.
    pub fn release_wal_log_protection_after_fold(&mut self) {
        self.wal_protected_logs.clear();
    }

    fn wal_protected_node(&self, node_id: u64) -> bool {
        self.wal_protected_logs.contains(&node_id)
    }

    fn wal_protected_subtree(&self, ancestor: u64) -> bool {
        self.wal_protected_logs.iter().copied().any(|mut node_id| {
            loop {
                if node_id == ancestor { return true; }
                let Some(node) = self.volume.node(node_id) else { return false; };
                if node_id == 0 || node.parent == node_id { return false; }
                node_id = node.parent;
            }
        })
    }

    fn wal_protected_target_name(&self, name: &str) -> bool {
        self.volume.lookup(name.trim_start_matches('\\'))
            .is_some_and(|node_id| self.wal_protected_subtree(node_id))
    }

    /// Apply one committed hive-log WAL record to an unpublished snapshot. The physical WAL
    /// already proves durability; this method checks the exact file and prior byte position.
    /// A newer snapshot may already include the record, in which case matching bytes are skipped.
    pub fn replay_hive_log_wal_payload(
        &mut self,
        payload: HiveLogWalPayload<'_>,
    ) -> Result<HiveLogWalReplay, HiveLogWalReplayError> {
        let (node_id, already_present) = self.classify_hive_log_wal_payload(payload)?;
        if already_present { return Ok(HiveLogWalReplay::AlreadyPresent); }
        let next = self.project_snapshot_append(node_id, payload.record.len())
            .map_err(|status| if status == STATUS_DISK_FULL {
                HiveLogWalReplayError::Capacity
            } else { HiveLogWalReplayError::OutOfMemory })?;
        if self.volume.append_at_end(node_id, payload.record) != payload.record.len() {
            return Err(HiveLogWalReplayError::OutOfMemory);
        }
        self.publish_snapshot_size(next);
        let end = self.volume.size(node_id);
        self.volume.ensure_allocation_covers_eof(node_id);
        self.volume.mark_data_initialized_through(node_id, end);
        self.volume.touch_write(node_id);
        Ok(HiveLogWalReplay::Appended)
    }

    /// Replay an anchored append under the charge retained before the WAL effect. The token
    /// returns on every refusal; an exact already-present record proves the charge can be freed.
    pub fn replay_hive_log_wal_payload_reserved(
        &mut self,
        token: SnapshotCapacityReservation,
        payload: HiveLogWalPayload<'_>,
    ) -> Result<HiveLogWalReplay, (HiveLogWalReplayError, SnapshotCapacityReservation)> {
        let (_, already_present) = match self.classify_hive_log_wal_payload(payload) {
            Ok(result) => result,
            Err(error) => return Err((error, token)),
        };
        if already_present {
            return match self.cancel_snapshot_reservation(token) {
                Ok(()) => Ok(HiveLogWalReplay::AlreadyPresent),
                Err((_, token)) => Err((HiveLogWalReplayError::ForeignIdentity, token)),
            };
        }
        self.append_file_by_path_reserved_inner(token, payload.path, payload.record, true)
            .map(|_| HiveLogWalReplay::Appended)
            .map_err(|(status, token)| (
                if status == STATUS_DISK_FULL { HiveLogWalReplayError::Capacity }
                else if status == STATUS_DATA_ERROR || status == STATUS_INVALID_PARAMETER {
                    HiveLogWalReplayError::ForeignIdentity
                } else { HiveLogWalReplayError::OutOfMemory },
                token,
            ))
    }

    fn classify_hive_log_wal_payload(
        &self,
        payload: HiveLogWalPayload<'_>,
    ) -> Result<(u64, bool), HiveLogWalReplayError> {
        validate_hive_log(payload).map_err(|_| HiveLogWalReplayError::InvalidPayload)?;
        let rel = self.to_relative(&normalize_separators(payload.path))
            .ok_or(HiveLogWalReplayError::MissingFile)?;
        let node_id = self.volume.lookup(&rel).ok_or(HiveLogWalReplayError::MissingFile)?;
        let node = self.volume.node(node_id).ok_or(HiveLogWalReplayError::MissingFile)?;
        if node.is_dir {
            return Err(HiveLogWalReplayError::MissingFile);
        }
        if node.file_id != payload.file_id {
            return Err(HiveLogWalReplayError::ForeignIdentity);
        }
        let length = self.volume.size(node_id);
        if length < payload.expected_log_len {
            return Err(HiveLogWalReplayError::UnexpectedLength);
        }
        if length == payload.expected_log_len {
            return Ok((node_id, false));
        }
        let record_end = payload.expected_log_len + payload.record.len() as u64;
        if length < record_end {
            return Err(HiveLogWalReplayError::ContradictoryBytes);
        }
        let mut checked = 0usize;
        let mut chunk = [0u8; 512];
        while checked < payload.record.len() {
            let take = chunk.len().min(payload.record.len() - checked);
            let offset = payload.expected_log_len + checked as u64;
            if self.volume.read_at_into(node_id, offset, &mut chunk[..take]) != take
                || chunk[..take] != payload.record[checked..checked + take]
            {
                return Err(HiveLogWalReplayError::ContradictoryBytes);
            }
            checked += take;
        }
        Ok((node_id, true))
    }

    /// A file's bytes by folded volume-relative path.
    pub fn file_bytes_relative(&self, relative: &[u8]) -> Option<&[u8]> {
        self.volume.file_data_folded_relative(relative)
    }

    /// Total live node count (root included) — the volume's occupancy, for diagnostics.
    pub fn node_count(&self) -> usize {
        self.volume.nodes.iter().filter(|n| n.is_some()).count()
    }

    /// Number of unique immutable file byte blobs retained by the volume.
    pub fn unique_data_blobs(&self) -> usize {
        self.volume.blobs.len()
    }

    #[cfg(test)]
    pub(crate) fn blob_slice_candidates_inspected(&self) -> usize {
        self.volume
            .blob_slice_candidates_inspected
            .load(Ordering::Relaxed)
    }

    /// `NtQueryAttributesFile` / `NtQueryFullAttributesFile` (spec §8.6): query a file's attributes
    /// by PATH, without opening a handle. Resolves the NT path through the mount manager, then reads
    /// the node's attributes. `None` if the path (or its volume) does not resolve — the syscall seam
    /// maps that to `STATUS_OBJECT_NAME_NOT_FOUND`.
    pub fn query_attributes(&self, path: &str) -> Option<StandardInformation> {
        let rel = self.to_relative(&normalize_separators(path))?;
        self.volume.query(&rel)
    }

    pub fn query_metadata(&self, path: &str) -> Option<FileMetadata> {
        let rel = self.to_relative(&normalize_separators(path))?;
        self.volume.query_metadata(&rel)
    }

    /// Query a lowercase volume-relative path produced by `nt_path_to_volume_relative{,_into}`.
    /// This avoids allocating a temporary NT path string on hot syscall paths that already own a
    /// canonical relative path.
    pub fn query_attributes_relative(&self, relative: &[u8]) -> Option<StandardInformation> {
        self.volume.query_folded_relative(relative)
    }

    pub fn query_metadata_relative(&self, relative: &[u8]) -> Option<FileMetadata> {
        self.volume.query_metadata_folded_relative(relative)
    }

    /// Query a folded path beneath an existing directory FILE_OBJECT without opening the child.
    pub fn query_attributes_relative_to_directory(
        &self,
        root_directory: u64,
        relative: &[u8],
    ) -> Result<StandardInformation, u32> {
        let Some(root_node) = self.obj(root_directory).map(|object| object.node_id) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let Some(root) = self.volume.node(root_node) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        if !root.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if relative.is_empty() || relative.first() == Some(&b'\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.volume
            .query_folded_from(root_node, relative)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    pub fn query_metadata_relative_to_directory(
        &self,
        root_directory: u64,
        relative: &[u8],
    ) -> Result<FileMetadata, u32> {
        let Some(root_node) = self.obj(root_directory).map(|object| object.node_id) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let Some(root) = self.volume.node(root_node) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        if !root.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if relative.is_empty() || relative.first() == Some(&b'\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.volume
            .query_metadata_folded_from(root_node, relative)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    /// `ObDuplicateObject` on a file object: one more handle now names it (spec §6.2).
    pub fn zw_retain(&mut self, handle: u64) -> u32 {
        match self.obj_mut(handle) {
            Some(obj) if obj.handle_references != 0 => {
                let Some(references) = obj.references.checked_add(1) else {
                    return STATUS_QUOTA_EXCEEDED;
                };
                let Some(handle_references) = obj.handle_references.checked_add(1) else {
                    return STATUS_QUOTA_EXCEEDED;
                };
                obj.references = references;
                obj.handle_references = handle_references;
                STATUS_SUCCESS
            }
            Some(_) | None => STATUS_INVALID_HANDLE,
        }
    }

    /// Whether one `ZwClose` will schedule final-handle cleanup, possibly behind admitted I/O.
    pub fn zw_is_final_reference(&self, handle: u64) -> Result<bool, u32> {
        self.obj(handle)
            .filter(|object| object.handle_references != 0)
            .map(|object| object.handle_references == 1)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn zw_set_file_signaled(&mut self, handle: u64, signaled: bool) -> Result<(), u32> {
        let object = self.obj_mut(handle).ok_or(STATUS_INVALID_HANDLE)?;
        object.signaled = signaled;
        Ok(())
    }

    pub fn zw_is_file_signaled(&self, handle: u64) -> Result<bool, u32> {
        self.obj(handle)
            .map(|object| object.signaled)
            .ok_or(STATUS_INVALID_HANDLE)
    }
}
