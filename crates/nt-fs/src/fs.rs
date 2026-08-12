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
use crate::status::*;

/// A MemFs node (spec §12.3). Carries the node's DOS attributes and its parent link so the volume
/// can serve directory enumeration (`.`/`..` + children) and unlink, exactly like a real FSD.
const ZERO_EXTENT_BLOB: usize = usize::MAX;
const MEMFS_SNAPSHOT_MAGIC: [u8; 8] = *b"USNTFS\0\x01";
const MEMFS_SNAPSHOT_VERSION: u16 = 1;
const MEMFS_SNAPSHOT_HEADER_LEN: usize = 32;
const SNAP_REC_DIR: u8 = 1;
const SNAP_REC_FILE: u8 = 2;
const SNAP_EXTENT_ZERO: u8 = 0;
const SNAP_EXTENT_DATA: u8 = 1;

/// A validated MemFs snapshot header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MemFsSnapshotInfo {
    pub version: u16,
    pub record_count: u32,
    pub payload_len: u64,
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
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
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
    is_dir: bool,
    attributes: u32,
    parent: u64,
    data: FileData,
    /// (folded name, as-created name, node id) — the folded name is the lookup key, the
    /// as-created name is what directory enumeration reports (NT preserves creation case).
    children: Vec<(String, String, u64)>,
}

/// An in-memory file system (spec §12) — the v0.1 `NtFileSystemRuntime`.
pub struct MemFs {
    nodes: Vec<Option<MemFsNode>>,
    blobs: Vec<Vec<u8>>,
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
        };
        fs.nodes.push(Some(MemFsNode {
            is_dir: true,
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            parent: 0,
            data: FileData::empty(),
            children: Vec::new(),
        }));
        fs
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

    /// Parse and validate a snapshot header without restoring the tree.
    pub fn snapshot_info(bytes: &[u8]) -> Result<MemFsSnapshotInfo, MemFsSnapshotError> {
        if bytes.len() < MEMFS_SNAPSHOT_HEADER_LEN {
            return Err(MemFsSnapshotError::Truncated);
        }
        let mut r = SnapshotReader::new(&bytes[..MEMFS_SNAPSHOT_HEADER_LEN]);
        if r.take(MEMFS_SNAPSHOT_MAGIC.len())? != MEMFS_SNAPSHOT_MAGIC {
            return Err(MemFsSnapshotError::BadMagic);
        }
        let header_len = r.u16()? as usize;
        if header_len != MEMFS_SNAPSHOT_HEADER_LEN {
            return Err(MemFsSnapshotError::UnsupportedVersion);
        }
        let version = r.u16()?;
        if version != MEMFS_SNAPSHOT_VERSION {
            return Err(MemFsSnapshotError::UnsupportedVersion);
        }
        let record_count = r.u32()?;
        let payload_len = r.u64()?;
        let payload_crc = r.u32()?;
        let header_crc = r.u32()?;
        if crc32c(&bytes[..MEMFS_SNAPSHOT_HEADER_LEN - 4]) != header_crc {
            return Err(MemFsSnapshotError::BadChecksum);
        }
        let payload_len_usize =
            usize::try_from(payload_len).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
        let end = MEMFS_SNAPSHOT_HEADER_LEN
            .checked_add(payload_len_usize)
            .ok_or(MemFsSnapshotError::InvalidRecord)?;
        if bytes.len() < end {
            return Err(MemFsSnapshotError::Truncated);
        }
        if bytes.len() != end {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        if crc32c(&bytes[MEMFS_SNAPSHOT_HEADER_LEN..end]) != payload_crc {
            return Err(MemFsSnapshotError::BadChecksum);
        }
        Ok(MemFsSnapshotInfo {
            version,
            record_count,
            payload_len,
        })
    }

    /// Serialize the volume tree to a versioned, checksummed snapshot. Open FILE_OBJECT handles are
    /// intentionally not part of the image; a restored boot reopens files through normal Zw paths.
    pub fn to_snapshot(&self) -> Result<Vec<u8>, MemFsSnapshotError> {
        let mut payload = Vec::new();
        let mut record_count = 0u32;
        self.write_snapshot_children(0, "", &mut payload, &mut record_count)?;

        let mut out = Vec::new();
        out.try_reserve_exact(MEMFS_SNAPSHOT_HEADER_LEN + payload.len())
            .map_err(|_| MemFsSnapshotError::OutOfMemory)?;
        out.extend_from_slice(&MEMFS_SNAPSHOT_MAGIC);
        put_u16(&mut out, MEMFS_SNAPSHOT_HEADER_LEN as u16);
        put_u16(&mut out, MEMFS_SNAPSHOT_VERSION);
        put_u32(&mut out, record_count);
        put_u64(&mut out, payload.len() as u64);
        put_u32(&mut out, crc32c(&payload));
        let header_crc = crc32c(&out);
        put_u32(&mut out, header_crc);
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Restore a volume from [`Self::to_snapshot`] bytes.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, MemFsSnapshotError> {
        let info = Self::snapshot_info(bytes)?;
        let mut fs = MemFs::new();
        let payload = &bytes[MEMFS_SNAPSHOT_HEADER_LEN..];
        let mut r = SnapshotReader::new(payload);
        let mut seen = 0u32;
        while !r.is_empty() {
            let kind = r.u8()?;
            let attributes = r.u32()?;
            let path_len =
                usize::try_from(r.u32()?).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
            let logical_len =
                usize::try_from(r.u64()?).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
            let extent_count =
                usize::try_from(r.u32()?).map_err(|_| MemFsSnapshotError::InvalidRecord)?;
            let path_bytes = r.take(path_len)?;
            let path =
                core::str::from_utf8(path_bytes).map_err(|_| MemFsSnapshotError::InvalidPath)?;
            let is_dir = match kind {
                SNAP_REC_DIR => true,
                SNAP_REC_FILE => false,
                _ => return Err(MemFsSnapshotError::InvalidRecord),
            };
            let id = fs.restore_snapshot_node(path, is_dir, attributes)?;
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

    fn node(&self, id: u64) -> Option<&MemFsNode> {
        self.nodes.get(id as usize)?.as_ref()
    }
    fn node_mut(&mut self, id: u64) -> Option<&mut MemFsNode> {
        self.nodes.get_mut(id as usize)?.as_mut()
    }

    fn write_snapshot_children(
        &self,
        parent: u64,
        prefix: &str,
        out: &mut Vec<u8>,
        record_count: &mut u32,
    ) -> Result<(), MemFsSnapshotError> {
        let Some(node) = self.node(parent) else {
            return Err(MemFsSnapshotError::InvalidRecord);
        };
        if !node.is_dir {
            return Err(MemFsSnapshotError::InvalidRecord);
        }
        for (_, name, child_id) in &node.children {
            let Some(child) = self.node(*child_id) else {
                return Err(MemFsSnapshotError::InvalidRecord);
            };
            let mut path = String::new();
            let extra_sep = usize::from(!prefix.is_empty());
            path.try_reserve_exact(prefix.len() + extra_sep + name.len())
                .map_err(|_| MemFsSnapshotError::OutOfMemory)?;
            path.push_str(prefix);
            if !prefix.is_empty() {
                path.push('\\');
            }
            path.push_str(name);
            self.write_snapshot_record(&path, child, out)?;
            *record_count = record_count
                .checked_add(1)
                .ok_or(MemFsSnapshotError::InvalidRecord)?;
            if child.is_dir {
                self.write_snapshot_children(*child_id, &path, out, record_count)?;
            }
        }
        Ok(())
    }

    fn write_snapshot_record(
        &self,
        path: &str,
        node: &MemFsNode,
        out: &mut Vec<u8>,
    ) -> Result<(), MemFsSnapshotError> {
        let path_len = u32::try_from(path.len()).map_err(|_| MemFsSnapshotError::InvalidPath)?;
        let logical_len = if node.is_dir {
            0
        } else {
            node.data.len(&self.blobs) as u64
        };
        let extent_count = if node.is_dir {
            0
        } else {
            u32::try_from(Self::snapshot_extent_count(&node.data))
                .map_err(|_| MemFsSnapshotError::InvalidRecord)?
        };
        out.push(if node.is_dir {
            SNAP_REC_DIR
        } else {
            SNAP_REC_FILE
        });
        put_u32(out, node.attributes);
        put_u32(out, path_len);
        put_u64(out, logical_len);
        put_u32(out, extent_count);
        out.extend_from_slice(path.as_bytes());
        if !node.is_dir {
            self.write_snapshot_file_data(&node.data, out)?;
        }
        Ok(())
    }

    fn snapshot_extent_count(data: &FileData) -> usize {
        match data {
            FileData::Bytes(bytes) => usize::from(!bytes.is_empty()),
            FileData::Extents(extents) => extents.iter().filter(|extent| extent.len != 0).count(),
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

    fn restore_snapshot_node(
        &mut self,
        path: &str,
        is_dir: bool,
        attributes: u32,
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
        let id = self.create_child(parent, leaf, is_dir);
        let Some(node) = self.node_mut(id) else {
            return Err(MemFsSnapshotError::InvalidRecord);
        };
        node.attributes = if is_dir {
            attributes | FILE_ATTRIBUTE_DIRECTORY
        } else {
            attributes
        };
        Ok(id)
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

    fn child(&self, dir: u64, name: &str) -> Option<u64> {
        let folded = fold(name);
        self.node(dir)?
            .children
            .iter()
            .find(|(n, _, _)| *n == folded)
            .map(|(_, _, id)| *id)
    }

    fn child_folded_bytes(&self, dir: u64, name: &[u8]) -> Option<u64> {
        self.node(dir)?
            .children
            .iter()
            .find(|(n, _, _)| n.as_bytes().eq_ignore_ascii_case(name))
            .map(|(_, _, id)| *id)
    }

    fn create_child(&mut self, parent: u64, name: &str, is_dir: bool) -> u64 {
        let id = self.nodes.len() as u64;
        self.nodes.push(Some(MemFsNode {
            is_dir,
            attributes: if is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_ARCHIVE
            },
            parent,
            data: FileData::empty(),
            children: Vec::new(),
        }));
        self.node_mut(parent)
            .unwrap()
            .children
            .push((fold(name), String::from(name), id));
        id
    }

    /// Unlink `id` from `parent` and free the node (spec §12.6 — delete-on-close). A non-empty
    /// directory is refused, exactly as `IRP_MJ_SET_INFORMATION`/`FileDispositionInformation` does.
    fn unlink(&mut self, parent: u64, id: u64) -> Result<(), u32> {
        let node = self.node(id).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if node.is_dir && !node.children.is_empty() {
            return Err(STATUS_DIRECTORY_NOT_EMPTY);
        }
        let parent_node = self.node_mut(parent).ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
        let before = parent_node.children.len();
        parent_node.children.retain(|(_, _, child)| *child != id);
        if parent_node.children.len() == before {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        self.nodes[id as usize] = None;
        Ok(())
    }

    fn rename_into_parent(
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
        let source_parent = source_node.parent;
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

        if let Some(existing) = self.child(target_parent, leaf) {
            if existing == source {
                if let Some(parent_node) = self.node_mut(target_parent) {
                    if let Some((folded, created, _)) = parent_node
                        .children
                        .iter_mut()
                        .find(|(_, _, child)| *child == source)
                    {
                        *folded = fold(leaf);
                        *created = String::from(leaf);
                        return STATUS_SUCCESS;
                    }
                }
                return STATUS_OBJECT_NAME_NOT_FOUND;
            }
            if !replace_if_exists {
                return STATUS_OBJECT_NAME_COLLISION;
            }
            let Some(existing_node) = self.node(existing) else {
                return STATUS_OBJECT_NAME_NOT_FOUND;
            };
            if source_is_dir || existing_node.is_dir {
                return STATUS_ACCESS_DENIED;
            }
            if let Err(status) = self.unlink(target_parent, existing) {
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
            .position(|(_, _, child)| *child == source)
        else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        old_parent.children.remove(old_index);

        let Some(source_node) = self.node_mut(source) else {
            return STATUS_INVALID_HANDLE;
        };
        source_node.parent = target_parent;

        let Some(parent_node) = self.node_mut(target_parent) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        parent_node
            .children
            .push((fold(leaf), String::from(leaf), source));
        STATUS_SUCCESS
    }

    fn rename_relative(&mut self, source: u64, target_path: &str, replace_if_exists: bool) -> u32 {
        let Some((parent_path, leaf)) = Self::parent_and_leaf_relative(target_path) else {
            return STATUS_INVALID_PARAMETER;
        };
        let Some(parent) = self.lookup(parent_path) else {
            return STATUS_OBJECT_PATH_NOT_FOUND;
        };
        self.rename_into_parent(source, parent, leaf, replace_if_exists)
    }

    fn rename_relative_to_dir(
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
        self.rename_into_parent(source, parent, leaf, replace_if_exists)
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
        let mut cur = 0;
        for comp in path.split('\\').filter(|c| !c.is_empty()) {
            cur = self.child(cur, comp)?;
        }
        Some(cur)
    }

    fn lookup_from(&self, start: u64, path: &str) -> Option<u64> {
        let mut cur = start;
        for comp in path.split('\\').filter(|c| !c.is_empty()) {
            cur = self.child(cur, comp)?;
        }
        Some(cur)
    }

    fn lookup_folded_relative(&self, path: &[u8]) -> Option<u64> {
        let mut cur = 0;
        for comp in path.split(|byte| *byte == b'\\').filter(|c| !c.is_empty()) {
            cur = self.child_folded_bytes(cur, comp)?;
        }
        Some(cur)
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
    ) -> Result<(u64, u32), u32> {
        let want_dir = options & FILE_DIRECTORY_FILE != 0;
        let existing = self.lookup(rel_path);
        match existing {
            Some(id) => {
                let is_dir = self.node(id).unwrap().is_dir;
                if want_dir && !is_dir {
                    return Err(STATUS_NOT_A_DIRECTORY);
                }
                if !want_dir && is_dir && options & FILE_NON_DIRECTORY_FILE != 0 {
                    return Err(STATUS_FILE_IS_A_DIRECTORY);
                }
                match disposition {
                    FILE_OPEN | FILE_OPEN_IF => Ok((id, FILE_OPENED)),
                    FILE_CREATE => Err(STATUS_OBJECT_NAME_COLLISION),
                    FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data = FileData::empty();
                        }
                        Ok((id, FILE_OVERWRITTEN))
                    }
                    FILE_SUPERSEDE => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data = FileData::empty();
                        }
                        Ok((id, FILE_SUPERSEDED))
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
                    let id = self.create_child(parent, leaf, want_dir);
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
                    Ok((id, FILE_CREATED))
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
    ) -> Result<(u64, u32), u32> {
        let want_dir = options & FILE_DIRECTORY_FILE != 0;
        let existing = self.lookup_folded_relative(rel_path);
        match existing {
            Some(id) => {
                let is_dir = self.node(id).unwrap().is_dir;
                if want_dir && !is_dir {
                    return Err(STATUS_NOT_A_DIRECTORY);
                }
                if !want_dir && is_dir && options & FILE_NON_DIRECTORY_FILE != 0 {
                    return Err(STATUS_FILE_IS_A_DIRECTORY);
                }
                match disposition {
                    FILE_OPEN | FILE_OPEN_IF => Ok((id, FILE_OPENED)),
                    FILE_CREATE => Err(STATUS_OBJECT_NAME_COLLISION),
                    FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data = FileData::empty();
                        }
                        Ok((id, FILE_OVERWRITTEN))
                    }
                    FILE_SUPERSEDE => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data = FileData::empty();
                        }
                        Ok((id, FILE_SUPERSEDED))
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
                        .lookup_folded_relative(parent_path)
                        .ok_or(STATUS_OBJECT_PATH_NOT_FOUND)?;
                    if !self.node(parent).unwrap().is_dir {
                        return Err(STATUS_OBJECT_PATH_NOT_FOUND);
                    }
                    let leaf = core::str::from_utf8(leaf).map_err(|_| STATUS_INVALID_PARAMETER)?;
                    let id = self.create_child(parent, leaf, want_dir);
                    let requested = file_attributes & FILE_ATTRIBUTE_SETTABLE;
                    if requested != 0 {
                        let node = self.node_mut(id).unwrap();
                        node.attributes = if want_dir {
                            requested | FILE_ATTRIBUTE_DIRECTORY
                        } else {
                            requested
                        };
                    }
                    Ok((id, FILE_CREATED))
                }
                _ => Err(STATUS_INVALID_PARAMETER),
            },
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
        })
    }

    fn query_folded_relative(&self, rel_path: &[u8]) -> Option<StandardInformation> {
        let id = self.lookup_folded_relative(rel_path)?;
        Some(StandardInformation {
            end_of_file: self.size(id),
            is_directory: self.is_dir(id),
            attributes: self.attributes(id),
        })
    }

    fn is_dir(&self, id: u64) -> bool {
        self.node(id).map(|n| n.is_dir).unwrap_or(false)
    }
    fn attributes(&self, id: u64) -> u32 {
        self.node(id).map(|n| n.attributes).unwrap_or(0)
    }
    fn parent(&self, id: u64) -> u64 {
        self.node(id).map(|n| n.parent).unwrap_or(0)
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
                let (_, name, child) = node.children.get(index - 2)?;
                let target = self.node(*child)?;
                self.make_directory_entry(index, name, target)
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

    fn file_data_folded_relative(&self, rel_path: &[u8]) -> Option<&[u8]> {
        let id = self.lookup_folded_relative(rel_path)?;
        let node = self.node(id)?;
        if node.is_dir {
            None
        } else {
            node.data.contiguous_slice(&self.blobs)
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

/// An open file instance (a simplified `FILE_OBJECT` + MemFs open handle, spec §6.1, §12.4).
struct FileObject {
    node_id: u64,
    current_offset: u64,
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
    /// A file system over `volume`, mounted with the required v0.1 mounts (spec §13.2).
    pub fn new(volume: MemFs) -> Self {
        FileSystem {
            volume,
            mounts: MountManager::new(),
            handles: Vec::new(),
        }
    }

    /// Export just the durable volume tree. Open handles are per-boot FILE_OBJECT state and are not
    /// included.
    pub fn export_volume_snapshot(&self) -> Result<Vec<u8>, MemFsSnapshotError> {
        self.volume.to_snapshot()
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
        if data.len() < 20 {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let replace_if_exists = data[0] != 0;
        let root_directory = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let name_len = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
        if name_len == 0 || data.len().saturating_sub(20) < name_len {
            return Err(STATUS_INFO_LENGTH_MISMATCH);
        }
        let name = Self::decode_utf16_name(&data[20..20 + name_len])?;
        Ok((
            replace_if_exists,
            root_directory,
            normalize_separators(&name),
        ))
    }

    fn rename_target_relative(&self, target: &str) -> Result<String, u32> {
        if let Some(rel) = self.to_relative(target) {
            return Ok(rel);
        }
        if target.starts_with('\\') {
            return Ok(String::from(target));
        }
        Err(STATUS_OBJECT_PATH_NOT_FOUND)
    }

    /// `ZwCreateFile` (spec §8.1): resolve the path, apply the create disposition, and return a
    /// file handle.
    pub fn zw_create_file(
        &mut self,
        path: &str,
        _desired_access: u32,
        file_attributes: u32,
        _share_access: u32,
        disposition: u32,
        options: u32,
    ) -> CreateResult {
        let fail = |status| CreateResult {
            status,
            handle: INVALID_HANDLE,
            information: 0,
        };
        let Some(rel) = self.to_relative(&normalize_separators(path)) else {
            return fail(STATUS_OBJECT_PATH_NOT_FOUND);
        };
        match self
            .volume
            .create(&rel, disposition, options, file_attributes)
        {
            Ok((node_id, information)) => {
                // Directory/non-directory intent already validated in create().
                let handle = match self.handles.iter().position(|slot| slot.is_none()) {
                    Some(free) => free as u64,
                    None => {
                        self.handles.push(None);
                        (self.handles.len() - 1) as u64
                    }
                };
                self.handles[handle as usize] = Some(FileObject {
                    node_id,
                    current_offset: 0,
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
        _desired_access: u32,
        file_attributes: u32,
        _share_access: u32,
        disposition: u32,
        options: u32,
    ) -> CreateResult {
        let fail = |status| CreateResult {
            status,
            handle: INVALID_HANDLE,
            information: 0,
        };
        match self
            .volume
            .create_folded_relative(relative, disposition, options, file_attributes)
        {
            Ok((node_id, information)) => {
                let handle = match self.handles.iter().position(|slot| slot.is_none()) {
                    Some(free) => free as u64,
                    None => {
                        self.handles.push(None);
                        (self.handles.len() - 1) as u64
                    }
                };
                self.handles[handle as usize] = Some(FileObject {
                    node_id,
                    current_offset: 0,
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
        (STATUS_SUCCESS, n)
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
        })
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
    /// `FileBasicInformation` (attributes), `FileDispositionInformation` (delete-on-close),
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
                let attributes = u32::from_le_bytes(data[32..36].try_into().unwrap());
                let requested = attributes & FILE_ATTRIBUTE_SETTABLE;
                if requested != 0 {
                    let is_dir = self.volume.is_dir(node_id);
                    if let Some(node) = self.volume.node_mut(node_id) {
                        node.attributes = if is_dir {
                            requested | FILE_ATTRIBUTE_DIRECTORY
                        } else {
                            requested
                        };
                    }
                }
                STATUS_SUCCESS
            }
            FILE_DISPOSITION_INFORMATION => {
                if data.is_empty() {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }
                self.obj_mut(handle).unwrap().delete_pending = data[0] != 0;
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
                self.volume.set_end_of_file(node_id, length)
            }
            FILE_RENAME_INFORMATION => {
                let (replace_if_exists, root_directory, target) =
                    match Self::decode_rename_information(data) {
                        Ok(info) => info,
                        Err(status) => return status,
                    };
                if root_directory == 0 {
                    let target = match self.rename_target_relative(&target) {
                        Ok(target) => target,
                        Err(status) => return status,
                    };
                    self.volume
                        .rename_relative(node_id, &target, replace_if_exists)
                } else {
                    let Some(root) = self.obj(root_directory) else {
                        return STATUS_INVALID_HANDLE;
                    };
                    let root_id = root.node_id;
                    if !self.volume.is_dir(root_id) {
                        return STATUS_NOT_A_DIRECTORY;
                    }
                    if self.to_relative(&target).is_some() || target.starts_with('\\') {
                        return STATUS_INVALID_PARAMETER;
                    }
                    self.volume
                        .rename_relative_to_dir(node_id, root_id, &target, replace_if_exists)
                }
            }
            _ => STATUS_NOT_IMPLEMENTED,
        }
    }

    /// The file object's current byte offset — `FilePositionInformation`'s read side.
    pub fn current_offset(&self, handle: u64) -> Option<u64> {
        self.obj(handle).map(|obj| obj.current_offset)
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
        self.volume.set_file_data(id, bytes)
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
        self.volume.set_file_data(id, bytes)
    }

    /// A file's bytes, borrowed in place (no copy) — the read side [`provision_file`] writes.
    /// `None` when the path does not resolve to a file on this volume.
    pub fn file_bytes(&self, path: &str) -> Option<&[u8]> {
        let rel = self.to_relative(&normalize_separators(path))?;
        self.volume.file_data(&rel)
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

    /// Query a lowercase volume-relative path produced by `nt_path_to_volume_relative{,_into}`.
    /// This avoids allocating a temporary NT path string on hot syscall paths that already own a
    /// canonical relative path.
    pub fn query_attributes_relative(&self, relative: &[u8]) -> Option<StandardInformation> {
        self.volume.query_folded_relative(relative)
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
                let (node_id, delete_pending) = (obj.node_id, obj.delete_pending);
                // IRP_MJ_CLEANUP (last handle) then IRP_MJ_CLOSE → free the FILE_OBJECT.
                self.handles[handle as usize] = None;
                if delete_pending && node_id != 0 {
                    let parent = self.volume.parent(node_id);
                    let _ = self.volume.unlink(parent, node_id);
                }
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
