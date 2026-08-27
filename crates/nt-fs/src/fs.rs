//! MemFs (spec §12) + the `FileSystem` facade exposing the Zw* native file APIs (spec §8-§9).
//!
//! MemFs is an in-memory `NtFileSystemRuntime`: a node tree with create-disposition semantics.
//! `FileSystem` owns the volume + [`MountManager`], resolves NT paths, and manages file objects
//! and handles behind the `ZwCreateFile` / `ZwReadFile` / `ZwWriteFile` / `ZwFlushBuffersFile` /
//! `ZwQueryInformationFile` / `ZwClose` surface.

use alloc::string::String;
use alloc::vec::Vec;

use crate::directory::{
    query_directory_by_index, DirectoryEntry, DirectoryQueryResult, DirectoryQueryState,
};
use crate::path::{normalize_separators, MountManager, MEMFS_VOLUME};
use crate::snapshot_store::{
    SnapshotBlockDevice, SnapshotBlockStore, SnapshotBlockStoreError, SnapshotPayloadReader,
    SnapshotPayloadSink,
};
use crate::status::*;

/// A MemFs node (spec §12.3). File data and attributes belong to this shared identity; directory
/// entries own names. Directories retain their single parent for `..`, while regular files may have
/// any number of entries and a corresponding link count.
const ZERO_EXTENT_BLOB: usize = usize::MAX;
const MEMFS_SNAPSHOT_MAGIC: [u8; 8] = *b"USNTFS\0\x01";
const MEMFS_SNAPSHOT_VERSION_V1: u16 = 1;
const MEMFS_SNAPSHOT_VERSION_V2: u16 = 2;
const MEMFS_SNAPSHOT_VERSION: u16 = 3;
const MEMFS_SNAPSHOT_HEADER_LEN: usize = 32;
const SNAP_REC_DIR: u8 = 1;
const SNAP_REC_FILE: u8 = 2;
const SNAP_REC_LINK: u8 = 3;
const SNAP_EXTENT_ZERO: u8 = 0;
const SNAP_EXTENT_DATA: u8 = 1;

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

struct Crc32c {
    crc: u32,
}

impl Crc32c {
    fn new() -> Self {
        Self { crc: 0xFFFF_FFFF }
    }

    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.crc ^= b as u32;
            for _ in 0..8 {
                self.crc = if self.crc & 1 != 0 {
                    (self.crc >> 1) ^ 0x82F6_3B78
                } else {
                    self.crc >> 1
                };
            }
        }
    }

    fn finish(self) -> u32 {
        !self.crc
    }
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(data);
    crc.finish()
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
    data: FileData,
    children: Vec<MemFsDirEntry>,
}

/// A stable directory-entry identity. Multiple entries may name the same non-directory node; open
/// File objects retain `id` so rename and delete-on-close act on the entry that was actually opened.
struct MemFsDirEntry {
    id: u64,
    folded_name: String,
    created_name: String,
    node_id: u64,
}

/// An in-memory file system (spec §12) — the v0.1 `NtFileSystemRuntime`.
pub struct MemFs {
    nodes: Vec<Option<MemFsNode>>,
    blobs: Vec<Vec<u8>>,
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
            MEMFS_SNAPSHOT_VERSION_V1 | MEMFS_SNAPSHOT_VERSION_V2 | MEMFS_SNAPSHOT_VERSION
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
        let root = self.node(0).ok_or(MemFsSnapshotError::InvalidRecord)?;
        let mut record_count = 1u32;
        let mut path = String::new();
        let mut measured_files = Vec::new();
        let payload_len = self
            .snapshot_record_len("", root, false)?
            .checked_add(self.measure_snapshot_children(
                0,
                &mut path,
                &mut measured_files,
                &mut record_count,
            )?)
            .ok_or(MemFsSnapshotError::InvalidRecord)?;

        let mut out = Vec::new();
        let total_len = MEMFS_SNAPSHOT_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(MemFsSnapshotError::InvalidRecord)?;
        out.try_reserve_exact(total_len)
            .map_err(|_| MemFsSnapshotError::OutOfMemory)?;
        out.resize(MEMFS_SNAPSHOT_HEADER_LEN, 0);
        self.write_snapshot_record("", root, false, &mut out)?;
        let mut written_records = 1u32;
        let mut written_files = Vec::new();
        self.write_snapshot_children(
            0,
            &mut path,
            &mut written_files,
            &mut out,
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
        Ok(out)
    }

    /// Restore a volume from [`Self::to_snapshot`] bytes.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, MemFsSnapshotError> {
        let info = Self::snapshot_info(bytes)?;
        let mut fs = MemFs::new();
        let payload = &bytes[MEMFS_SNAPSHOT_HEADER_LEN..];
        let mut r = SnapshotReader::new(payload);
        let mut seen = 0u32;
        let mut hardlink_nodes = Vec::new();
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
            let times = if info.version >= MEMFS_SNAPSHOT_VERSION {
                [r.u64()?, r.u64()?, r.u64()?, r.u64()?]
            } else {
                [0; 4]
            };
            let logical_len =
                usize::try_from(r.u64()?).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
            let extent_count =
                usize::try_from(r.u32()?).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
            let path_bytes = r.take(path_len)?;
            let path =
                core::str::from_utf8(path_bytes).map_err(|_| MemFsSnapshotError::InvalidPath)?;
            if path.is_empty() {
                if info.version < MEMFS_SNAPSHOT_VERSION
                    || seen != 0
                    || kind != SNAP_REC_DIR
                    || node_key != 0
                    || logical_len != 0
                    || extent_count != 0
                {
                    return Err(MemFsSnapshotError::InvalidRecord);
                }
                let root = fs.node_mut(0).ok_or(MemFsSnapshotError::InvalidRecord)?;
                root.attributes = attributes | FILE_ATTRIBUTE_DIRECTORY;
                root.creation_time = times[0];
                root.last_access_time = times[1];
                root.last_write_time = times[2];
                root.change_time = times[3];
                seen = 1;
                continue;
            }
            if kind == SNAP_REC_LINK {
                if info.version < MEMFS_SNAPSHOT_VERSION_V2
                    || node_key == 0
                    || logical_len != 0
                    || extent_count != 0
                {
                    return Err(MemFsSnapshotError::InvalidRecord);
                }
                let target = hardlink_nodes
                    .iter()
                    .find(|(key, _)| *key == node_key)
                    .map(|(_, id)| *id)
                    .ok_or(MemFsSnapshotError::InvalidRecord)?;
                fs.restore_snapshot_link(path, target, attributes, times)?;
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
                Some(node_key)
            } else {
                None
            };
            let id = fs.restore_snapshot_node(path, is_dir, attributes, times, file_id)?;
            if is_dir {
                if logical_len != 0 || extent_count != 0 {
                    return Err(MemFsSnapshotError::InvalidRecord);
                }
            } else {
                let data = fs.read_snapshot_file_data(&mut r, logical_len, extent_count)?;
                let Some(node) = fs.node_mut(id) else {
                    return Err(MemFsSnapshotError::InvalidRecord);
                };
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
            let times = if header.info.version >= MEMFS_SNAPSHOT_VERSION {
                [r.u64()?, r.u64()?, r.u64()?, r.u64()?]
            } else {
                [0; 4]
            };
            let logical_len =
                usize::try_from(r.u64()?).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
            let extent_count =
                usize::try_from(r.u32()?).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
            let path_bytes = r.vec(path_len)?;
            let path =
                core::str::from_utf8(&path_bytes).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
            if path.is_empty() {
                if header.info.version < MEMFS_SNAPSHOT_VERSION
                    || seen != 0
                    || kind != SNAP_REC_DIR
                    || node_key != 0
                    || logical_len != 0
                    || extent_count != 0
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                let root = fs.node_mut(0).ok_or(SnapshotBlockStoreError::Corrupt)?;
                root.attributes = attributes | FILE_ATTRIBUTE_DIRECTORY;
                root.creation_time = times[0];
                root.last_access_time = times[1];
                root.last_write_time = times[2];
                root.change_time = times[3];
                seen = 1;
                continue;
            }
            if kind == SNAP_REC_LINK {
                if header.info.version < MEMFS_SNAPSHOT_VERSION_V2
                    || node_key == 0
                    || logical_len != 0
                    || extent_count != 0
                {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                let target = hardlink_nodes
                    .iter()
                    .find(|(key, _)| *key == node_key)
                    .map(|(_, id)| *id)
                    .ok_or(SnapshotBlockStoreError::Corrupt)?;
                fs.restore_snapshot_link(path, target, attributes, times)
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
            let id = fs
                .restore_snapshot_node(
                    path,
                    is_dir,
                    attributes,
                    times,
                    (header.info.version >= MEMFS_SNAPSHOT_VERSION_V2).then_some(node_key),
                )
                .map_err(snapshot_error_to_store_error)?;
            if is_dir {
                if logical_len != 0 || extent_count != 0 {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
            } else {
                let data =
                    fs.read_snapshot_file_data_streaming(&mut r, logical_len, extent_count)?;
                let Some(node) = fs.node_mut(id) else {
                    return Err(SnapshotBlockStoreError::Corrupt);
                };
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

        let mut store_crc_sink = SnapshotCrcSink::new();
        store_crc_sink.write_all(&header)?;
        let written_records = self.write_snapshot_payload_to_sink(&mut store_crc_sink)?;
        let (store_payload_crc, store_payload_len) = store_crc_sink.finish();
        if written_records != record_count || store_payload_len != total_len {
            return Err(SnapshotBlockStoreError::Corrupt);
        }

        let generation =
            store.commit_next_streaming(dev, total_len, store_payload_crc, |writer| {
                writer.write_all(&header)?;
                let written_records = self.write_snapshot_payload_to_sink(writer)?;
                if written_records != record_count {
                    return Err(SnapshotBlockStoreError::Corrupt);
                }
                Ok(())
            })?;
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
            self.write_snapshot_record(path, child, link_only, out)?;
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
        self.write_snapshot_record_to_sink("", root, false, sink)?;
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
            self.write_snapshot_record_to_sink(path, child, link_only, sink)?;
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
                .checked_add(self.snapshot_record_len(path, child, link_only)?)
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
    ) -> Result<usize, MemFsSnapshotError> {
        let path_len = u32::try_from(path.len()).map_err(|_| MemFsSnapshotError::InvalidPath)?;
        let data_len = if node.is_dir || link_only {
            0
        } else {
            Self::snapshot_file_data_encoded_len(&self.blobs, &node.data)?
        };
        1usize
            .checked_add(4)
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_add(8))
            .and_then(|n| n.checked_add(32))
            .and_then(|n| n.checked_add(8))
            .and_then(|n| n.checked_add(4))
            .and_then(|n| n.checked_add(path_len as usize))
            .and_then(|n| n.checked_add(data_len))
            .ok_or(MemFsSnapshotError::InvalidRecord)
    }

    fn write_snapshot_record(
        &self,
        path: &str,
        node: &MemFsNode,
        link_only: bool,
        out: &mut Vec<u8>,
    ) -> Result<(), MemFsSnapshotError> {
        let path_len = u32::try_from(path.len()).map_err(|_| MemFsSnapshotError::InvalidPath)?;
        let logical_len = if node.is_dir || link_only {
            0
        } else {
            node.data.len(&self.blobs) as u64
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
        put_u64(out, node.file_id);
        put_u64(out, node.creation_time);
        put_u64(out, node.last_access_time);
        put_u64(out, node.last_write_time);
        put_u64(out, node.change_time);
        put_u64(out, logical_len);
        put_u32(out, extent_count);
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
        sink: &mut S,
    ) -> Result<(), SnapshotBlockStoreError> {
        let path_len = u32::try_from(path.len()).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
        let logical_len = if node.is_dir || link_only {
            0
        } else {
            u64::try_from(node.data.len(&self.blobs))
                .map_err(|_| SnapshotBlockStoreError::Corrupt)?
        };
        let extent_count = if node.is_dir || link_only {
            0
        } else {
            u32::try_from(Self::snapshot_extent_count(&node.data))
                .map_err(|_| SnapshotBlockStoreError::Corrupt)?
        };
        let mut header = [0u8; 61];
        header[0] = if link_only {
            SNAP_REC_LINK
        } else if node.is_dir {
            SNAP_REC_DIR
        } else {
            SNAP_REC_FILE
        };
        put_u32_at(&mut header[1..5], node.attributes);
        put_u32_at(&mut header[5..9], path_len);
        put_u64_at(&mut header[9..17], node.file_id);
        put_u64_at(&mut header[17..25], node.creation_time);
        put_u64_at(&mut header[25..33], node.last_access_time);
        put_u64_at(&mut header[33..41], node.last_write_time);
        put_u64_at(&mut header[41..49], node.change_time);
        put_u64_at(&mut header[49..57], logical_len);
        put_u32_at(&mut header[57..61], extent_count);
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
                        .checked_add(1 + 8)
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
                        .checked_add(1 + 8)
                        .and_then(|n| n.checked_add(data_len))
                        .ok_or(MemFsSnapshotError::InvalidRecord)?;
                }
            }
        }
        Ok(total)
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
    ) -> Result<u64, MemFsSnapshotError> {
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
        let id = self.create_child(parent, leaf, is_dir);
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
        Ok(id)
    }

    fn restore_snapshot_link(
        &mut self,
        path: &str,
        target: u64,
        attributes: u32,
        times: [u64; 4],
    ) -> Result<(), MemFsSnapshotError> {
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
        })?;
        Ok(())
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
        self.node(dir)?
            .children
            .iter()
            .find(|entry| entry.folded_name == folded)
    }

    fn child_folded_bytes(&self, dir: u64, name: &[u8]) -> Option<u64> {
        self.node(dir)?
            .children
            .iter()
            .find(|entry| entry.folded_name.as_bytes().eq_ignore_ascii_case(name))
            .map(|entry| entry.node_id)
    }

    fn allocate_entry_id(&mut self) -> Result<u64, u32> {
        let id = self.next_entry_id;
        self.next_entry_id = self
            .next_entry_id
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(id)
    }

    fn insert_entry(&mut self, parent: u64, name: &str, node_id: u64) -> Result<u64, u32> {
        if name.is_empty() || name == "." || name == ".." || name.contains('\\') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let Some(link_count) = self.node(node_id).map(|node| node.link_count) else {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        let next_link_count = link_count
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let Some(parent_node) = self.node_mut(parent) else {
            return Err(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        if !parent_node.is_dir {
            return Err(STATUS_NOT_A_DIRECTORY);
        }
        if parent_node.children.try_reserve_exact(1).is_err() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let entry_id = self.allocate_entry_id()?;
        self.node_mut(parent).unwrap().children.push(MemFsDirEntry {
            id: entry_id,
            folded_name: fold(name),
            created_name: String::from(name),
            node_id,
        });
        self.node_mut(node_id).unwrap().link_count = next_link_count;
        Ok(entry_id)
    }

    fn create_child_with_entry(&mut self, parent: u64, name: &str, is_dir: bool) -> (u64, u64) {
        let node_id = self.nodes.len() as u64;
        let file_id = self.next_file_id;
        self.next_file_id = self
            .next_file_id
            .checked_add(1)
            .expect("MemFs file identity exhausted");
        let now = self.current_time_100ns;
        self.nodes.push(Some(MemFsNode {
            file_id,
            is_dir,
            attributes: if is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_ARCHIVE
            },
            creation_time: now,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
            link_count: 0,
            parent,
            data: FileData::empty(),
            children: Vec::new(),
        }));
        let entry_id = self
            .insert_entry(parent, name, node_id)
            .expect("new child has a valid parent and entry capacity");
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

    fn opened_name(&self, entry_id: u64) -> Option<String> {
        if entry_id == 0 {
            let mut root = String::new();
            root.try_reserve_exact(1).ok()?;
            root.push('\\');
            return Some(root);
        }
        let (mut parent, index, _) = self.entry_location(entry_id)?;
        let mut components = Vec::new();
        components.try_reserve_exact(1).ok()?;
        components.push(
            self.node(parent)?
                .children
                .get(index)?
                .created_name
                .as_str(),
        );
        let mut remaining = self.nodes.len();
        while parent != 0 {
            if remaining == 0 {
                return None;
            }
            remaining -= 1;
            let grandparent = self.node(parent)?.parent;
            let entry = self
                .node(grandparent)?
                .children
                .iter()
                .find(|entry| entry.node_id == parent)?;
            components.try_reserve(1).ok()?;
            components.push(entry.created_name.as_str());
            parent = grandparent;
        }

        let byte_len = components
            .iter()
            .try_fold(1usize, |length, component| {
                length.checked_add(component.len())
            })?
            .checked_add(components.len().saturating_sub(1))?;
        let mut name = String::new();
        name.try_reserve_exact(byte_len).ok()?;
        name.push('\\');
        for (index, component) in components.iter().rev().enumerate() {
            if index != 0 {
                name.push('\\');
            }
            name.push_str(component);
        }
        Some(name)
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

    fn rename_into_parent(
        &mut self,
        source: u64,
        source_entry: u64,
        target_parent: u64,
        leaf: &str,
        replace_if_exists: bool,
    ) -> u32 {
        if source == 0 || leaf.is_empty() || leaf == "." || leaf == ".." || leaf.contains('\\') {
            return STATUS_INVALID_PARAMETER;
        }
        let Some((source_parent, source_index, entry_node)) = self.entry_location(source_entry)
        else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if entry_node != source {
            return STATUS_INVALID_HANDLE;
        }
        let Some(source_node) = self.node(source) else {
            return STATUS_INVALID_HANDLE;
        };
        let source_is_dir = source_node.is_dir;
        let Some(target_parent_node) = self.node(target_parent) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        if !target_parent_node.is_dir {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        }
        if source_is_dir {
            let mut cur = target_parent;
            loop {
                if cur == source {
                    return STATUS_ACCESS_DENIED;
                }
                if cur == 0 {
                    break;
                }
                let Some(node) = self.node(cur) else {
                    return STATUS_OBJECT_PATH_NOT_FOUND;
                };
                cur = node.parent;
            }
        }

        let existing = self
            .child_entry(target_parent, leaf)
            .map(|entry| (entry.id, entry.node_id));
        if let Some((existing_entry, existing_node_id)) = existing {
            if existing_entry == source_entry {
                if let Some(parent_node) = self.node_mut(target_parent) {
                    let entry = &mut parent_node.children[source_index];
                    entry.folded_name = fold(leaf);
                    entry.created_name = String::from(leaf);
                    return STATUS_SUCCESS;
                }
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            if !replace_if_exists {
                return STATUS_OBJECT_NAME_COLLISION;
            }
            let Some(existing_node) = self.node(existing_node_id) else {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            };
            if source_is_dir || existing_node.is_dir {
                return STATUS_ACCESS_DENIED;
            }
            if source_parent != target_parent
                && self
                    .node_mut(target_parent)
                    .is_none_or(|parent| parent.children.try_reserve_exact(1).is_err())
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            if let Err(status) = self.unlink_entry(existing_entry) {
                return status;
            }
        } else if source_parent != target_parent {
            let Some(parent_node) = self.node_mut(target_parent) else {
                return STATUS_OBJECT_PATH_NOT_FOUND;
            };
            if parent_node.children.try_reserve_exact(1).is_err() {
                return STATUS_INSUFFICIENT_RESOURCES;
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
        entry.folded_name = fold(leaf);
        entry.created_name = String::from(leaf);
        parent_node.children.push(entry);
        STATUS_SUCCESS
    }

    fn rename_relative(
        &mut self,
        source: u64,
        source_entry: u64,
        target_path: &str,
        replace_if_exists: bool,
    ) -> u32 {
        let Some((parent_path, leaf)) = Self::parent_and_leaf_relative(target_path) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(parent) = self.lookup(parent_path) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        self.rename_into_parent(source, source_entry, parent, leaf, replace_if_exists)
    }

    fn rename_relative_to_dir(
        &mut self,
        source: u64,
        source_entry: u64,
        root: u64,
        target_path: &str,
        replace_if_exists: bool,
    ) -> u32 {
        let Some((parent_path, leaf)) = Self::parent_and_leaf_relative(target_path) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(parent) = self.lookup_from(root, parent_path) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        self.rename_into_parent(source, source_entry, parent, leaf, replace_if_exists)
    }

    fn rename_relative_to_source_parent(
        &mut self,
        source: u64,
        source_entry: u64,
        target_path: &str,
        replace_if_exists: bool,
    ) -> u32 {
        let Some((parent, _, entry_node)) = self.entry_location(source_entry) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if entry_node != source {
            return STATUS_INVALID_HANDLE;
        }
        self.rename_relative_to_dir(source, source_entry, parent, target_path, replace_if_exists)
    }

    fn link_into_parent(
        &mut self,
        source: u64,
        target_parent: u64,
        leaf: &str,
        replace_if_exists: bool,
    ) -> u32 {
        if source == 0 || leaf.is_empty() || leaf == "." || leaf == ".." || leaf.contains('\\') {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(source_node) = self.node(source) else {
            return STATUS_INVALID_HANDLE;
        };
        if source_node.is_dir {
            return STATUS_INVALID_PARAMETER;
        }
        let Some(parent) = self.node(target_parent) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        if !parent.is_dir {
            return STATUS_NOT_A_DIRECTORY;
        }
        let existing = self
            .child_entry(target_parent, leaf)
            .map(|entry| (entry.id, entry.node_id));
        if let Some((existing_entry, existing_node)) = existing {
            if existing_node == source {
                return STATUS_SUCCESS;
            }
            if !replace_if_exists {
                return STATUS_OBJECT_NAME_COLLISION;
            }
            if self.next_entry_id.checked_add(1).is_none() || source_node.link_count == u32::MAX {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            if self.node(existing_node).is_some_and(|node| node.is_dir) {
                return STATUS_ACCESS_DENIED;
            }
            if let Err(status) = self.unlink_entry(existing_entry) {
                return status;
            }
        } else if self.next_entry_id.checked_add(1).is_none() || source_node.link_count == u32::MAX
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        match self.insert_entry(target_parent, leaf, source) {
            Ok(_) => STATUS_SUCCESS,
            Err(status) => status,
        }
    }

    fn link_relative(&mut self, source: u64, target_path: &str, replace_if_exists: bool) -> u32 {
        let Some((parent_path, leaf)) = Self::parent_and_leaf_relative(target_path) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(parent) = self.lookup(parent_path) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        self.link_into_parent(source, parent, leaf, replace_if_exists)
    }

    fn link_relative_to_dir(
        &mut self,
        source: u64,
        root: u64,
        target_path: &str,
        replace_if_exists: bool,
    ) -> u32 {
        let Some((parent_path, leaf)) = Self::parent_and_leaf_relative(target_path) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(parent) = self.lookup_from(root, parent_path) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        self.link_into_parent(source, parent, leaf, replace_if_exists)
    }

    fn link_relative_to_source_parent(
        &mut self,
        source: u64,
        source_entry: u64,
        target_path: &str,
        replace_if_exists: bool,
    ) -> u32 {
        let Some((parent, _, entry_node)) = self.entry_location(source_entry) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if entry_node != source {
            return STATUS_INVALID_HANDLE;
        }
        self.link_relative_to_dir(source, parent, target_path, replace_if_exists)
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
        let mut cur = 0;
        for comp in path.split(|byte| *byte == b'\\').filter(|c| !c.is_empty()) {
            cur = match self.child_folded_bytes(cur, comp) {
                Some(id) => id,
                None => {
                    let name = core::str::from_utf8(comp)
                        .map_err(|_| STATUS_INVALID_PARAMETER)
                        .ok()?;
                    self.create_child(cur, name, true)
                }
            };
        }
        Some(cur)
    }

    /// Resolve a volume-relative path to a node id.
    fn lookup(&self, path: &str) -> Option<u64> {
        self.lookup_entry_from(0, path).map(|(node, _)| node)
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
            let entry = self
                .node(cur)?
                .children
                .iter()
                .find(|entry| entry.folded_name.as_bytes().eq_ignore_ascii_case(comp))?;
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

    /// `NtFileSystemRuntime::create` (spec §11, §12.5): apply the create disposition, returning
    /// `(node_id, information)` or an NTSTATUS.
    fn create(
        &mut self,
        rel_path: &str,
        disposition: u32,
        options: u32,
        file_attributes: u32,
    ) -> Result<(u64, u64, u32), u32> {
        let want_dir = options & FILE_DIRECTORY_FILE != 0;
        let existing = self.lookup_entry_from(0, rel_path);
        match existing {
            Some((id, entry_id)) => {
                let is_dir = self.node(id).unwrap().is_dir;
                if want_dir && !is_dir {
                    return Err(STATUS_NOT_A_DIRECTORY);
                }
                if !want_dir && is_dir && options & FILE_NON_DIRECTORY_FILE != 0 {
                    return Err(STATUS_FILE_IS_A_DIRECTORY);
                }
                match disposition {
                    FILE_OPEN | FILE_OPEN_IF => Ok((id, entry_id, FILE_OPENED)),
                    FILE_CREATE => Err(STATUS_OBJECT_NAME_COLLISION),
                    FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data = FileData::empty();
                        }
                        Ok((id, entry_id, FILE_OVERWRITTEN))
                    }
                    FILE_SUPERSEDE => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data = FileData::empty();
                        }
                        Ok((id, entry_id, FILE_SUPERSEDED))
                    }
                    _ => Err(STATUS_INVALID_PARAMETER),
                }
            }
            None => match disposition {
                FILE_OPEN | FILE_OVERWRITE => Err(STATUS_OBJECT_NAME_NOT_FOUND),
                FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE => {
                    let (parent_path, leaf) =
                        Self::parent_and_leaf(rel_path).ok_or(STATUS_INVALID_PARAMETER)?;
                    let parent = self
                        .lookup(parent_path)
                        .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
                    if !self.node(parent).unwrap().is_dir {
                        return Err(STATUS_OBJECT_PATH_NOT_FOUND);
                    }
                    let (id, entry_id) = self.create_child_with_entry(parent, leaf, want_dir);
                    // The caller's FileAttributes are honoured for a newly created file; a
                    // directory always carries FILE_ATTRIBUTE_DIRECTORY (NT sets it, not the
                    // caller). Zero means "defaults", which `create_child` already applied.
                    let requested = file_attributes & FILE_ATTRIBUTE_SETTABLE;
                    if requested != 0 {
                        let node = self.node_mut(id).unwrap();
                        node.attributes = if want_dir {
                            requested | FILE_ATTRIBUTE_DIRECTORY
                        } else {
                            requested
                        };
                    }
                    Ok((id, entry_id, FILE_CREATED))
                }
                _ => Err(STATUS_INVALID_PARAMETER),
            },
        }
    }

    fn create_folded_from(
        &mut self,
        start: u64,
        rel_path: &[u8],
        disposition: u32,
        options: u32,
        file_attributes: u32,
    ) -> Result<(u64, u64, u32), u32> {
        let want_dir = options & FILE_DIRECTORY_FILE != 0;
        let existing = self.lookup_folded_entry_from(start, rel_path);
        match existing {
            Some((id, entry_id)) => {
                let is_dir = self.node(id).unwrap().is_dir;
                if want_dir && !is_dir {
                    return Err(STATUS_NOT_A_DIRECTORY);
                }
                if !want_dir && is_dir && options & FILE_NON_DIRECTORY_FILE != 0 {
                    return Err(STATUS_FILE_IS_A_DIRECTORY);
                }
                match disposition {
                    FILE_OPEN | FILE_OPEN_IF => Ok((id, entry_id, FILE_OPENED)),
                    FILE_CREATE => Err(STATUS_OBJECT_NAME_COLLISION),
                    FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data = FileData::empty();
                        }
                        Ok((id, entry_id, FILE_OVERWRITTEN))
                    }
                    FILE_SUPERSEDE => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data = FileData::empty();
                        }
                        Ok((id, entry_id, FILE_SUPERSEDED))
                    }
                    _ => Err(STATUS_INVALID_PARAMETER),
                }
            }
            None => match disposition {
                FILE_OPEN | FILE_OVERWRITE => Err(STATUS_OBJECT_NAME_NOT_FOUND),
                FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE => {
                    let (parent_path, leaf) =
                        Self::parent_and_leaf_bytes(rel_path).ok_or(STATUS_INVALID_PARAMETER)?;
                    let parent = self
                        .lookup_folded_from(start, parent_path)
                        .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
                    if !self.node(parent).unwrap().is_dir {
                        return Err(STATUS_OBJECT_PATH_NOT_FOUND);
                    }
                    let leaf = core::str::from_utf8(leaf).map_err(|_| STATUS_INVALID_PARAMETER)?;
                    let (id, entry_id) = self.create_child_with_entry(parent, leaf, want_dir);
                    let requested = file_attributes & FILE_ATTRIBUTE_SETTABLE;
                    if requested != 0 {
                        let node = self.node_mut(id).unwrap();
                        node.attributes = if want_dir {
                            requested | FILE_ATTRIBUTE_DIRECTORY
                        } else {
                            requested
                        };
                    }
                    Ok((id, entry_id, FILE_CREATED))
                }
                _ => Err(STATUS_INVALID_PARAMETER),
            },
        }
    }

    fn create_folded_relative(
        &mut self,
        rel_path: &[u8],
        disposition: u32,
        options: u32,
        file_attributes: u32,
    ) -> Result<(u64, u64, u32), u32> {
        self.create_folded_from(0, rel_path, disposition, options, file_attributes)
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
        let allocation_size = if node.is_dir || end_of_file == 0 {
            0
        } else {
            end_of_file.saturating_add(0xfff) & !0xfff
        };
        Some(FileMetadata {
            creation_time: node.creation_time,
            last_access_time: node.last_access_time,
            last_write_time: node.last_write_time,
            change_time: node.change_time,
            allocation_size,
            end_of_file,
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
        let Ok(length) = usize::try_from(length) else {
            return STATUS_INVALID_PARAMETER;
        };
        let current = self.size(id) as usize;
        if length <= current {
            self.node_mut(id).unwrap().data.truncate(length);
            return STATUS_SUCCESS;
        }
        if !self.extend_with_zeroes(id, length - current) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        STATUS_SUCCESS
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
            0 => self.make_directory_entry(0, ".", node),
            1 => {
                let parent = self.node(node.parent).unwrap_or(node);
                self.make_directory_entry(1, "..", parent)
            }
            _ => {
                let child = node.children.get(index - 2)?;
                let target = self.node(child.node_id)?;
                self.make_directory_entry(index, &child.created_name, target)
            }
        }
    }

    fn make_directory_entry(
        &self,
        index: usize,
        name: &str,
        target: &MemFsNode,
    ) -> Option<DirectoryEntry> {
        let size = target.data.len(&self.blobs) as u64;
        let mut entry = DirectoryEntry {
            file_index: index as u32,
            attributes: target.attributes,
            end_of_file: size,
            allocation_size: size.div_ceil(0x1000) * 0x1000,
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
        let Some(blob) = self.intern_blob(bytes) else {
            return false;
        };
        let mut extents = Vec::new();
        if extents.try_reserve_exact(1).is_err() {
            return false;
        }
        extents.push(FileExtent {
            blob,
            offset: 0,
            len: bytes.len(),
        });
        let Some(node) = self.node_mut(id) else {
            return false;
        };
        node.data = FileData::Extents(extents);
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

    fn write_at(&mut self, id: u64, offset: u64, bytes: &[u8]) -> usize {
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
            let Some(extent) = self.extent_for_bytes(bytes) else {
                return 0;
            };
            return if self.splice_write_extent(id, start, extent) {
                bytes.len()
            } else {
                0
            };
        }
        let copied_extent = (start == current_len)
            .then(|| self.find_blob_slice(bytes))
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

        let data = {
            let Some(node) = self.node_mut(id) else {
                return 0;
            };
            core::mem::replace(&mut node.data, FileData::Extents(Vec::new()))
        };

        let mut extents = match data {
            FileData::Extents(mut extents) => {
                if extents.try_reserve_exact(1).is_err() {
                    if let Some(node) = self.node_mut(id) {
                        node.data = FileData::Extents(extents);
                    }
                    return 0;
                }
                extents
            }
            FileData::Bytes(existing) => {
                let existing_len = existing.len();
                let extent_count = usize::from(existing_len != 0) + 1;
                let mut extents = Vec::new();
                if extents.try_reserve_exact(extent_count).is_err() {
                    if let Some(node) = self.node_mut(id) {
                        node.data = FileData::Bytes(existing);
                    }
                    return 0;
                }
                if existing_len != 0 {
                    if self.blobs.try_reserve_exact(1).is_err() {
                        if let Some(node) = self.node_mut(id) {
                            node.data = FileData::Bytes(existing);
                        }
                        return 0;
                    }
                    let blob = self.blobs.len();
                    self.blobs.push(existing);
                    extents.push(FileExtent {
                        blob,
                        offset: 0,
                        len: existing_len,
                    });
                }
                extents
            }
        };

        if self.blobs.try_reserve_exact(1).is_err() {
            if let Some(node) = self.node_mut(id) {
                node.data = FileData::Extents(extents);
            }
            return 0;
        }
        let blob = self.blobs.len();
        self.blobs.push(appended);
        Self::push_extent_merged(
            &mut extents,
            FileExtent {
                blob,
                offset: 0,
                len: bytes.len(),
            },
        );
        let Some(node) = self.node_mut(id) else {
            return 0;
        };
        node.data = FileData::Extents(extents);
        bytes.len()
    }

    fn extent_for_bytes(&mut self, bytes: &[u8]) -> Option<FileExtent> {
        self.find_blob_slice(bytes).or_else(|| {
            let blob = self.intern_blob(bytes)?;
            Some(FileExtent {
                blob,
                offset: 0,
                len: bytes.len(),
            })
        })
    }

    fn splice_write_extent(&mut self, id: u64, start: usize, write: FileExtent) -> bool {
        let Some(write_end) = start.checked_add(write.len) else {
            return false;
        };
        let old_extents = {
            let Some(node) = self.node_mut(id) else {
                return false;
            };
            match core::mem::replace(&mut node.data, FileData::Extents(Vec::new())) {
                FileData::Extents(extents) => extents,
                other => {
                    node.data = other;
                    return false;
                }
            }
        };
        let old_len = old_extents.iter().map(|extent| extent.len).sum::<usize>();
        let mut next = Vec::new();
        if next.try_reserve_exact(old_extents.len() + 3).is_err() {
            if let Some(node) = self.node_mut(id) {
                node.data = FileData::Extents(old_extents);
            }
            return false;
        }

        let mut cursor = 0usize;
        let mut inserted = false;
        for extent in old_extents.iter().copied() {
            let extent_start = cursor;
            let Some(extent_end) = cursor.checked_add(extent.len) else {
                if let Some(node) = self.node_mut(id) {
                    node.data = FileData::Extents(old_extents);
                }
                return false;
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

        let Some(node) = self.node_mut(id) else {
            return false;
        };
        node.data = FileData::Extents(next);
        true
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

    fn find_blob_slice(&self, bytes: &[u8]) -> Option<FileExtent> {
        if bytes.is_empty() {
            return None;
        }
        for (blob_index, blob) in self.blobs.iter().enumerate() {
            if bytes.len() > blob.len() {
                continue;
            }
            for offset in 0..=blob.len() - bytes.len() {
                if &blob[offset..offset + bytes.len()] == bytes {
                    return Some(FileExtent {
                        blob: blob_index,
                        offset,
                        len: bytes.len(),
                    });
                }
            }
        }
        None
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

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct FileShareClaim {
    read: bool,
    write: bool,
    delete: bool,
    shared_read: bool,
    shared_write: bool,
    shared_delete: bool,
}

impl FileShareClaim {
    fn new(desired_access: u32, share_access: u32) -> Self {
        const GENERIC_ALL: u32 = 0x1000_0000;
        const GENERIC_EXECUTE: u32 = 0x2000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_READ: u32 = 0x8000_0000;
        const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

        let all = desired_access & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0;
        Self {
            read: all
                || desired_access & (FILE_READ_DATA | FILE_EXECUTE | GENERIC_READ | GENERIC_EXECUTE)
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

    fn compatible_with(self, existing: Self) -> bool {
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
    /// Create options retained as `FILE_OBJECT` mode flags for `FileModeInformation`.
    create_options: u32,
    /// One share claim belongs to this open description. Duplicated handles only increase
    /// `references`; the claim is released when the final reference closes.
    share: FileShareClaim,
    /// Handles referring to this file object. `NtDuplicateObject` adds one, `ZwClose` removes one;
    /// the object (and any pending delete) is actioned when the last one goes.
    references: u32,
    /// `FCB->DeletePending` — set by `FileDispositionInformation`, actioned by `ZwClose`.
    delete_pending: bool,
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
        || (options & FILE_NO_INTERMEDIATE_BUFFERING != 0
            && desired_access & FILE_APPEND_DATA != 0)
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
    mounts: MountManager,
    handles: Vec<Option<FileObject>>,
}

/// The result of `ZwCreateFile`: `(status, handle, information)` (spec §8.1).
pub struct CreateResult {
    pub status: u32,
    pub handle: u64,
    pub information: u32,
}

pub const INVALID_HANDLE: u64 = u64::MAX;

impl FileSystem {
    fn publish_file_object(
        &mut self,
        node_id: u64,
        entry_id: u64,
        information: u32,
        options: u32,
        share: FileShareClaim,
    ) -> CreateResult {
        let Some(opened_name) = self.volume.opened_name(entry_id) else {
            return CreateResult {
                status: STATUS_INSUFFICIENT_RESOURCES,
                handle: INVALID_HANDLE,
                information: 0,
            };
        };
        let handle = match self.handles.iter().position(|slot| slot.is_none()) {
            Some(free) => free as u64,
            None => {
                self.handles.push(None);
                (self.handles.len() - 1) as u64
            }
        };
        self.handles[handle as usize] = Some(FileObject {
            node_id,
            entry_id,
            opened_name,
            current_offset: 0,
            create_options: options,
            share,
            references: 1,
            delete_pending: options & FILE_DELETE_ON_CLOSE != 0,
            query: DirectoryQueryState::new(),
        });
        CreateResult {
            status: STATUS_SUCCESS,
            handle,
            information,
        }
    }

    /// A file system over `volume`, mounted with the required v0.1 mounts (spec §13.2).
    pub fn new(volume: MemFs) -> Self {
        FileSystem {
            volume,
            mounts: MountManager::new(),
            handles: Vec::new(),
        }
    }

    /// Publish the kernel's current NT system time to the filesystem for subsequent mutations.
    pub fn set_current_time_100ns(&mut self, now: u64) {
        self.volume.set_current_time_100ns(now);
    }

    /// Initialize a new volume and migrate pre-v3 snapshots whose format did not carry timestamps.
    /// Returns whether durable node metadata changed and therefore needs a checkpoint.
    pub fn initialize_timestamps(&mut self, now: u64) -> bool {
        self.volume.initialize_timestamps(now)
    }

    /// Export just the durable volume tree. Open handles are per-boot FILE_OBJECT state and are not
    /// included.
    pub fn export_volume_snapshot(&self) -> Result<Vec<u8>, MemFsSnapshotError> {
        self.volume.to_snapshot()
    }

    /// Reclaim immutable file-data blobs made unreachable by truncate, replace, or unlink.
    pub fn compact_volume_blobs(&mut self) -> Result<MemFsBlobCompaction, MemFsBlobCompactError> {
        self.volume.compact_blobs()
    }

    /// Commit the durable volume tree to a block-backed snapshot store without allocating the full
    /// snapshot image. The stored payload is byte-for-byte identical to [`Self::export_volume_snapshot`].
    pub fn commit_volume_snapshot<D: SnapshotBlockDevice>(
        &self,
        store: &SnapshotBlockStore,
        dev: &mut D,
    ) -> Result<(u64, usize), SnapshotBlockStoreError> {
        self.volume.commit_snapshot_to_store(store, dev)
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

    fn check_share_access(&self, node_id: u64, requested: FileShareClaim) -> Result<(), u32> {
        if self
            .handles
            .iter()
            .flatten()
            .filter(|object| object.node_id == node_id)
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
    ) -> u32 {
        let Some((source, source_entry)) = self
            .obj(handle)
            .map(|object| (object.node_id, object.entry_id))
        else {
            return STATUS_INVALID_HANDLE;
        };
        if target.is_empty() || self.to_relative(target).is_some() {
            return STATUS_INVALID_PARAMETER;
        }
        let status = match root {
            FileRenameRoot::SourceParent => {
                if target.starts_with('\\') {
                    return STATUS_INVALID_PARAMETER;
                }
                self.volume.rename_relative_to_source_parent(
                    source,
                    source_entry,
                    target,
                    replace_if_exists,
                )
            }
            FileRenameRoot::VolumeRoot => {
                let target = target.trim_start_matches('\\');
                if target.is_empty() {
                    return STATUS_INVALID_PARAMETER;
                }
                self.volume
                    .rename_relative(source, source_entry, target, replace_if_exists)
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
                self.volume.rename_relative_to_dir(
                    source,
                    source_entry,
                    root_id,
                    target,
                    replace_if_exists,
                )
            }
        };
        if status == STATUS_SUCCESS {
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

    /// Rename a live File using a canonical filesystem root and a UTF-16LE name.
    /// Caller handles never enter this API; `Directory` is this filesystem's
    /// retained File identity.
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
        self.rename_file_decoded(handle, root, &target, replace_if_exists)
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
        if target.is_empty() || self.to_relative(target).is_some() {
            return STATUS_INVALID_PARAMETER;
        }
        let status = match root {
            FileRenameRoot::SourceParent => {
                if target.starts_with('\\') {
                    return STATUS_INVALID_PARAMETER;
                }
                self.volume.link_relative_to_source_parent(
                    source,
                    source_entry,
                    target,
                    replace_if_exists,
                )
            }
            FileRenameRoot::VolumeRoot => {
                let target = target.trim_start_matches('\\');
                if target.is_empty() {
                    return STATUS_INVALID_PARAMETER;
                }
                self.volume.link_relative(source, target, replace_if_exists)
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
                self.volume
                    .link_relative_to_dir(source, root_id, target, replace_if_exists)
            }
        };
        if status == STATUS_SUCCESS {
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
        let share = FileShareClaim::new(desired_access, share_access);
        if disposition != FILE_CREATE {
            if let Some((node_id, _)) = self.volume.lookup_entry_from(0, &rel) {
                if let Err(status) = self.check_share_access(node_id, share) {
                    return fail(status);
                }
            }
        }
        match self
            .volume
            .create(&rel, disposition, options, file_attributes)
        {
            // Directory/non-directory intent already validated in create().
            Ok((node_id, entry_id, information)) => {
                self.publish_file_object(node_id, entry_id, information, options, share)
            }
            Err(status) => fail(status),
        }
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
        let share = FileShareClaim::new(desired_access, share_access);
        if disposition != FILE_CREATE {
            if let Some((node_id, _)) = self.volume.lookup_folded_entry_from(0, relative) {
                if let Err(status) = self.check_share_access(node_id, share) {
                    return fail(status);
                }
            }
        }
        match self
            .volume
            .create_folded_relative(relative, disposition, options, file_attributes)
        {
            Ok((node_id, entry_id, information)) => {
                self.publish_file_object(node_id, entry_id, information, options, share)
            }
            Err(status) => fail(status),
        }
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
        let (node_id, entry_id) = self.volume.create_child_with_entry(parent, leaf, false);
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
        node.attributes = match metadata.attributes & FILE_ATTRIBUTE_SETTABLE {
            0 => FILE_ATTRIBUTE_NORMAL,
            attributes => attributes,
        };
        Ok(true)
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
        let share = FileShareClaim::new(desired_access, share_access);
        if disposition != FILE_CREATE {
            if let Some((node_id, _)) = self.volume.lookup_folded_entry_from(root_node, relative) {
                if let Err(status) = self.check_share_access(node_id, share) {
                    return fail(status);
                }
            }
        }
        match self.volume.create_folded_from(
            root_node,
            relative,
            disposition,
            options,
            file_attributes,
        ) {
            Ok((node_id, entry_id, information)) => {
                self.publish_file_object(node_id, entry_id, information, options, share)
            }
            Err(status) => fail(status),
        }
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
        if byte_offset.is_none() {
            self.obj_mut(handle).unwrap().current_offset = offset + bytes.len() as u64;
        }
        (STATUS_SUCCESS, bytes)
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
        let node_id = obj.node_id;
        if self.volume.is_dir(node_id) {
            return (STATUS_INVALID_DEVICE_REQUEST, 0);
        }
        let offset = byte_offset.unwrap_or(obj.current_offset);
        if offset >= self.volume.size(node_id) {
            return (STATUS_END_OF_FILE, 0);
        }
        let read = self.volume.read_at_into(node_id, offset, output);
        if read != 0 {
            self.volume.touch_access(node_id);
        }
        if byte_offset.is_none() {
            self.obj_mut(handle).unwrap().current_offset = offset + read as u64;
        }
        (STATUS_SUCCESS, read)
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
        let offset = byte_offset.unwrap_or(obj.current_offset);
        let n = self.volume.write_at(node_id, offset, data);
        if !data.is_empty() && n == 0 {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        if byte_offset.is_none() {
            self.obj_mut(handle).unwrap().current_offset = offset + n as u64;
        }
        if n != 0 {
            self.volume.touch_write(node_id);
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
        if data.is_empty() {
            return (STATUS_SUCCESS, 0);
        }
        let n = self.volume.append_at_end(node_id, data);
        if n == 0 {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        let end = self.volume.size(node_id);
        self.obj_mut(handle).unwrap().current_offset = end;
        self.volume.touch_write(node_id);
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
        let (node_id, _, _) =
            match self
                .volume
                .create(&rel, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, 0)
            {
                Ok(result) => result,
                Err(status) => return (status, 0),
            };
        if self.volume.is_dir(node_id) {
            return (STATUS_FILE_IS_A_DIRECTORY, 0);
        }
        let written = self.volume.append_at_end(node_id, data);
        if written != data.len() {
            return (STATUS_INSUFFICIENT_RESOURCES, written);
        }
        self.volume.touch_write(node_id);
        (STATUS_SUCCESS, written)
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
        let len = data.len() as u64;
        if !self.volume.set_file_data_owned(node_id, data) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        self.obj_mut(handle).unwrap().current_offset = len;
        self.volume.touch_write(node_id);
        STATUS_SUCCESS
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
    /// `FilePositionInformation`, and `FileEndOfFileInformation` / `FileAllocationInformation`
    /// (truncate/extend). Returns the NTSTATUS; unhandled classes are reported honestly.
    pub fn zw_set_information_file(&mut self, handle: u64, class: u32, data: &[u8]) -> u32 {
        let Some(obj) = self.obj(handle) else {
            return STATUS_INVALID_HANDLE;
        };
        let node_id = obj.node_id;
        match class {
            FILE_BASIC_INFORMATION => {
                if data.len() < 40 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let creation_time = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let last_access_time = u64::from_le_bytes(data[8..16].try_into().unwrap());
                let last_write_time = u64::from_le_bytes(data[16..24].try_into().unwrap());
                let change_time = u64::from_le_bytes(data[24..32].try_into().unwrap());
                let attributes = u32::from_le_bytes(data[32..36].try_into().unwrap());
                let requested = attributes & FILE_ATTRIBUTE_SETTABLE;
                let is_dir = self.volume.is_dir(node_id);
                let now = self.volume.current_time_100ns;
                if let Some(node) = self.volume.node_mut(node_id) {
                    let mut changed = false;
                    if creation_time != 0 {
                        node.creation_time = creation_time;
                        changed = true;
                    }
                    if last_access_time != 0 {
                        node.last_access_time = last_access_time;
                        changed = true;
                    }
                    if last_write_time != 0 {
                        node.last_write_time = last_write_time;
                        changed = true;
                    }
                    if change_time != 0 {
                        node.change_time = change_time;
                        changed = true;
                    }
                    if requested != 0 {
                        node.attributes = if is_dir {
                            requested | FILE_ATTRIBUTE_DIRECTORY
                        } else {
                            requested
                        };
                        changed = true;
                    }
                    if changed && change_time == 0 {
                        node.change_time = now;
                    }
                }
                STATUS_SUCCESS
            }
            FILE_DISPOSITION_INFORMATION => {
                if data.is_empty() {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let delete = data[0] != 0;
                if delete {
                    let status = self.volume.can_mark_delete_pending(node_id, false);
                    if status != STATUS_SUCCESS {
                        return status;
                    }
                }
                self.obj_mut(handle).unwrap().delete_pending = delete;
                STATUS_SUCCESS
            }
            FILE_DISPOSITION_INFORMATION_EX => {
                let flags = match Self::decode_disposition_ex_flags(data) {
                    Ok(flags) => flags,
                    Err(status) => return status,
                };
                let delete = flags & FILE_DISPOSITION_DELETE != 0;
                if delete {
                    let status = self.volume.can_mark_delete_pending(
                        node_id,
                        flags & FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE != 0,
                    );
                    if status != STATUS_SUCCESS {
                        return status;
                    }
                }
                self.obj_mut(handle).unwrap().delete_pending = delete;
                STATUS_SUCCESS
            }
            FILE_POSITION_INFORMATION => {
                if data.len() < 8 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let offset = u64::from_le_bytes(data[0..8].try_into().unwrap());
                self.obj_mut(handle).unwrap().current_offset = offset;
                STATUS_SUCCESS
            }
            FILE_END_OF_FILE_INFORMATION | FILE_ALLOCATION_INFORMATION => {
                if data.len() < 8 {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                let length = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let status = self.volume.set_end_of_file(node_id, length);
                if status == STATUS_SUCCESS {
                    self.volume.touch_write(node_id);
                }
                status
            }
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
                        )
                    } else if target.starts_with('\\') {
                        STATUS_NOT_SAME_DEVICE
                    } else {
                        self.rename_file_decoded(
                            handle,
                            FileRenameRoot::SourceParent,
                            &target,
                            replace_if_exists,
                        )
                    }
                } else {
                    self.rename_file_decoded(
                        handle,
                        FileRenameRoot::Directory(root_directory),
                        &target,
                        replace_if_exists,
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
            _ => STATUS_INVALID_INFO_CLASS,
        }
    }

    /// The file object's current byte offset — `FilePositionInformation`'s read side.
    pub fn current_offset(&self, handle: u64) -> Option<u64> {
        self.obj(handle).map(|obj| obj.current_offset)
    }

    /// I/O-Manager-owned `FileModeInformation` for this live `FILE_OBJECT`.
    pub fn file_mode(&self, handle: u64) -> Option<u32> {
        self.obj(handle)
            .map(|obj| crate::file_mode_from_create_options(obj.create_options))
    }

    /// Create every missing directory along `path`, and return whether the leaf is a directory.
    /// This is volume PROVISIONING (the content a formatted/installed volume already carries), not
    /// a syscall path: hosted processes only ever reach the `Zw*` surface above.
    pub fn provision_directory(&mut self, path: &str) -> bool {
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return false;
        };
        let id = self.volume.ensure_dir(&rel);
        self.volume.is_dir(id)
    }

    /// Create every missing directory along a folded volume-relative path.
    ///
    /// This is the allocation-side twin of [`Self::zw_create_file_relative`]: callers that already
    /// resolved a path through the mount-prefix seam can provision installed volume content without
    /// depending on the `FileSystem` mount manager's DOS aliases.
    pub fn provision_directory_relative(&mut self, relative: &[u8]) -> bool {
        let Some(id) = self.volume.ensure_dir_folded_relative(relative) else {
            return false;
        };
        self.volume.is_dir(id)
    }

    /// Create `path` (and every missing directory above it) as a FILE holding `bytes`.
    ///
    /// This is volume PROVISIONING — the content an *installed* volume already carries because the
    /// installer put it there — not a syscall path: hosted processes only ever reach the `Zw*`
    /// surface above. It is the file-shaped sibling of [`provision_directory`](Self::provision_directory).
    /// Returns `false` if the path does not resolve to this volume or names an existing directory.
    pub fn provision_file(&mut self, path: &str, bytes: &[u8]) -> bool {
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return false;
        };
        let Some((parent_path, leaf)) = MemFs::parent_and_leaf(&rel) else {
            return false;
        };
        let parent = self.volume.ensure_dir(parent_path);
        let id = match self.volume.child(parent, leaf) {
            Some(id) => id,
            None => self.volume.create_child(parent, leaf, false),
        };
        if self.volume.is_dir(id) {
            return false;
        }
        let installed = self.volume.set_file_data(id, bytes);
        if installed {
            self.volume.touch_write(id);
        }
        installed
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
        }
        Ok(())
    }

    /// Create a file by folded volume-relative path, and create every missing directory above it.
    pub fn provision_file_relative(&mut self, relative: &[u8], bytes: &[u8]) -> bool {
        let Some((parent_path, leaf)) = MemFs::parent_and_leaf_bytes(relative) else {
            return false;
        };
        let Some(parent) = self.volume.ensure_dir_folded_relative(parent_path) else {
            return false;
        };
        let Ok(leaf) = core::str::from_utf8(leaf) else {
            return false;
        };
        let id = match self.volume.child(parent, leaf) {
            Some(id) => id,
            None => self.volume.create_child(parent, leaf, false),
        };
        if self.volume.is_dir(id) {
            return false;
        }
        let installed = self.volume.set_file_data(id, bytes);
        if installed {
            self.volume.touch_write(id);
        }
        installed
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

    /// `ZwClose` (spec §8.7, §6.2): cleanup-before-close, then free the file object. A file object
    /// with `DeletePending` set unlinks its node at cleanup, exactly like an FSD's `IRP_MJ_CLEANUP`.
    pub fn zw_close(&mut self, handle: u64) -> u32 {
        match self
            .handles
            .get_mut(handle as usize)
            .and_then(|h| h.as_mut())
        {
            Some(obj) => {
                obj.references = obj.references.saturating_sub(1);
                if obj.references != 0 {
                    return STATUS_SUCCESS;
                }
                let (entry_id, delete_pending) = (obj.entry_id, obj.delete_pending);
                // IRP_MJ_CLEANUP (last handle) then IRP_MJ_CLOSE → free the FILE_OBJECT.
                self.handles[handle as usize] = None;
                if delete_pending && entry_id != 0 {
                    let _ = self.volume.unlink_entry(entry_id);
                }
                self.reap_unlinked_nodes();
                STATUS_SUCCESS
            }
            None => STATUS_INVALID_HANDLE,
        }
    }

    /// `ObDuplicateObject` on a file object: one more handle now names it (spec §6.2).
    pub fn zw_retain(&mut self, handle: u64) -> u32 {
        match self.obj_mut(handle) {
            Some(obj) => {
                obj.references = obj.references.saturating_add(1);
                STATUS_SUCCESS
            }
            None => STATUS_INVALID_HANDLE,
        }
    }
}
