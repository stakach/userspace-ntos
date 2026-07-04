//! MemFs (spec §12) + the `FileSystem` facade exposing the Zw* native file APIs (spec §8-§9).
//!
//! MemFs is an in-memory `NtFileSystemRuntime`: a node tree with create-disposition semantics.
//! `FileSystem` owns the volume + [`MountManager`], resolves NT paths, and manages file objects
//! and handles behind the `ZwCreateFile` / `ZwReadFile` / `ZwWriteFile` / `ZwFlushBuffersFile` /
//! `ZwQueryInformationFile` / `ZwClose` surface.

use alloc::string::String;
use alloc::vec::Vec;

use crate::path::{normalize_separators, MountManager, MEMFS_VOLUME};
use crate::status::*;

/// A MemFs node (spec §12.3). v0.1 stores only what the read/write/create paths use; `parent`,
/// timestamps, and attributes are deferred until directory enumeration lands.
struct MemFsNode {
    is_dir: bool,
    data: Vec<u8>,
    children: Vec<(String, u64)>, // (folded name, node id)
}

/// An in-memory file system (spec §12) — the v0.1 `NtFileSystemRuntime`.
pub struct MemFs {
    nodes: Vec<Option<MemFsNode>>,
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
        let mut fs = MemFs { nodes: Vec::new() };
        fs.nodes.push(Some(MemFsNode {
            is_dir: true,
            data: Vec::new(),
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

    fn node(&self, id: u64) -> Option<&MemFsNode> {
        self.nodes.get(id as usize)?.as_ref()
    }
    fn node_mut(&mut self, id: u64) -> Option<&mut MemFsNode> {
        self.nodes.get_mut(id as usize)?.as_mut()
    }

    fn child(&self, dir: u64, name: &str) -> Option<u64> {
        let folded = fold(name);
        self.node(dir)?
            .children
            .iter()
            .find(|(n, _)| *n == folded)
            .map(|(_, id)| *id)
    }

    fn create_child(&mut self, parent: u64, name: &str, is_dir: bool) -> u64 {
        let id = self.nodes.len() as u64;
        self.nodes.push(Some(MemFsNode {
            is_dir,
            data: Vec::new(),
            children: Vec::new(),
        }));
        self.node_mut(parent)
            .unwrap()
            .children
            .push((fold(name), id));
        id
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

    /// Resolve a volume-relative path to a node id.
    fn lookup(&self, path: &str) -> Option<u64> {
        let mut cur = 0;
        for comp in path.split('\\').filter(|c| !c.is_empty()) {
            cur = self.child(cur, comp)?;
        }
        Some(cur)
    }

    /// Split a path into (parent components, leaf name).
    fn parent_and_leaf(path: &str) -> Option<(&str, &str)> {
        let trimmed = path.trim_end_matches('\\');
        let idx = trimmed.rfind('\\')?;
        Some((&trimmed[..idx], &trimmed[idx + 1..]))
    }

    /// `NtFileSystemRuntime::create` (spec §11, §12.5): apply the create disposition, returning
    /// `(node_id, information)` or an NTSTATUS.
    fn create(
        &mut self,
        rel_path: &str,
        disposition: u32,
        options: u32,
    ) -> Result<(u64, u32), u32> {
        let want_dir = options & FILE_DIRECTORY_FILE != 0;
        let existing = self.lookup(rel_path);
        match existing {
            Some(id) => {
                let is_dir = self.node(id).unwrap().is_dir;
                if want_dir && !is_dir
                    || !want_dir && is_dir && options & FILE_NON_DIRECTORY_FILE != 0
                {
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
                match disposition {
                    FILE_OPEN | FILE_OPEN_IF => Ok((id, FILE_OPENED)),
                    FILE_CREATE => Err(STATUS_OBJECT_NAME_COLLISION),
                    FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data.clear();
                        }
                        Ok((id, FILE_OVERWRITTEN))
                    }
                    FILE_SUPERSEDE => {
                        if !is_dir {
                            self.node_mut(id).unwrap().data.clear();
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
                    Ok((id, FILE_CREATED))
                }
                _ => Err(STATUS_INVALID_PARAMETER),
            },
        }
    }

    fn is_dir(&self, id: u64) -> bool {
        self.node(id).map(|n| n.is_dir).unwrap_or(false)
    }
    fn size(&self, id: u64) -> u64 {
        self.node(id).map(|n| n.data.len() as u64).unwrap_or(0)
    }
    fn read_at(&self, id: u64, offset: u64, len: usize) -> Vec<u8> {
        let Some(n) = self.node(id) else {
            return Vec::new();
        };
        let start = (offset as usize).min(n.data.len());
        let end = (start + len).min(n.data.len());
        n.data[start..end].to_vec()
    }
    fn write_at(&mut self, id: u64, offset: u64, bytes: &[u8]) -> usize {
        let Some(n) = self.node_mut(id) else { return 0 };
        let start = offset as usize;
        if start + bytes.len() > n.data.len() {
            n.data.resize(start + bytes.len(), 0);
        }
        n.data[start..start + bytes.len()].copy_from_slice(bytes);
        bytes.len()
    }
}

/// An open file instance (a simplified `FILE_OBJECT` + MemFs open handle, spec §6.1, §12.4).
struct FileObject {
    node_id: u64,
    current_offset: u64,
}

/// File information classes (spec §18) supported in v0.1.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StandardInformation {
    pub end_of_file: u64,
    pub is_directory: bool,
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

    /// `ZwCreateFile` (spec §8.1): resolve the path, apply the create disposition, and return a
    /// file handle.
    pub fn zw_create_file(
        &mut self,
        path: &str,
        _desired_access: u32,
        _file_attributes: u32,
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
        match self.volume.create(&rel, disposition, options) {
            Ok((node_id, information)) => {
                // Directory/non-directory intent already validated in create().
                let handle = self.handles.len() as u64;
                self.handles.push(Some(FileObject {
                    node_id,
                    current_offset: 0,
                }));
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
        })
    }

    /// `ZwClose` (spec §8.7, §6.2): cleanup-before-close, then free the file object.
    pub fn zw_close(&mut self, handle: u64) -> u32 {
        match self.handles.get(handle as usize).and_then(|h| h.as_ref()) {
            Some(_) => {
                // IRP_MJ_CLEANUP (last handle) then IRP_MJ_CLOSE → free the FILE_OBJECT.
                self.handles[handle as usize] = None;
                STATUS_SUCCESS
            }
            None => STATUS_INVALID_HANDLE,
        }
    }
}
