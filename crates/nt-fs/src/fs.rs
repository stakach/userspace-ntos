//! MemFs (spec §12) + the `FileSystem` facade exposing the Zw* native file APIs (spec §8-§9).
//!
//! MemFs is an in-memory `NtFileSystemRuntime`: a node tree with create-disposition semantics.
//! `FileSystem` owns the volume + [`MountManager`], resolves NT paths, and manages file objects
//! and handles behind the `ZwCreateFile` / `ZwReadFile` / `ZwWriteFile` / `ZwFlushBuffersFile` /
//! `ZwQueryInformationFile` / `ZwClose` surface.

use alloc::string::String;
use alloc::vec::Vec;

use crate::directory::{query_directory, DirectoryEntry, DirectoryQueryResult, DirectoryQueryState};
use crate::path::{normalize_separators, MountManager, MEMFS_VOLUME};
use crate::status::*;

/// A MemFs node (spec §12.3). Carries the node's DOS attributes and its parent link so the volume
/// can serve directory enumeration (`.`/`..` + children) and unlink, exactly like a real FSD.
struct MemFsNode {
    is_dir: bool,
    attributes: u32,
    parent: u64,
    data: Vec<u8>,
    /// (folded name, as-created name, node id) — the folded name is the lookup key, the
    /// as-created name is what directory enumeration reports (NT preserves creation case).
    children: Vec<(String, String, u64)>,
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
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            parent: 0,
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
            .find(|(n, _, _)| *n == folded)
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
            data: Vec::new(),
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
        file_attributes: u32,
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
        let Some(n) = self.node_mut(id) else {
            return STATUS_INVALID_HANDLE;
        };
        if n.is_dir {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        let Ok(length) = usize::try_from(length) else {
            return STATUS_INVALID_PARAMETER;
        };
        n.data.resize(length, 0);
        STATUS_SUCCESS
    }

    /// The directory's contents as native `DirectoryEntry` records — `.`, `..`, then the children
    /// in creation order, exactly like the FAT enumerator the read-only volume uses.
    fn entries(&self, id: u64) -> Option<Vec<DirectoryEntry>> {
        let node = self.node(id)?;
        if !node.is_dir {
            return None;
        }
        let mut out = Vec::new();
        let mut push = |index: usize, name: &str, target: &MemFsNode| {
            let mut entry = DirectoryEntry {
                file_index: index as u32,
                attributes: target.attributes,
                end_of_file: target.data.len() as u64,
                allocation_size: (target.data.len() as u64).div_ceil(0x1000) * 0x1000,
                ..DirectoryEntry::default()
            };
            let wide: Vec<u16> = name.encode_utf16().collect();
            if entry.set_name(&wide) {
                out.push(entry);
            }
        };
        push(0, ".", node);
        let parent = self.node(node.parent).unwrap_or(node);
        push(1, "..", parent);
        for (index, (_, name, child)) in node.children.iter().enumerate() {
            if let Some(target) = self.node(*child) {
                push(index + 2, name, target);
            }
        }
        Some(out)
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
        let Some(entries) = self.volume.entries(obj.node_id) else {
            return DirectoryQueryResult {
                status: STATUS_INVALID_PARAMETER,
                information: 0,
            };
        };
        let mut state = obj.query;
        let result = query_directory(
            &mut state,
            &entries,
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

    /// Total live node count (root included) — the volume's occupancy, for diagnostics.
    pub fn node_count(&self) -> usize {
        self.volume.nodes.iter().filter(|n| n.is_some()).count()
    }

    /// `NtQueryAttributesFile` / `NtQueryFullAttributesFile` (spec §8.6): query a file's attributes
    /// by PATH, without opening a handle. Resolves the NT path through the mount manager, then reads
    /// the node's attributes. `None` if the path (or its volume) does not resolve — the syscall seam
    /// maps that to `STATUS_OBJECT_NAME_NOT_FOUND`.
    pub fn query_attributes(&self, path: &str) -> Option<StandardInformation> {
        let rel = self.to_relative(&normalize_separators(path))?;
        self.volume.query(&rel)
    }

    /// `ZwClose` (spec §8.7, §6.2): cleanup-before-close, then free the file object. A file object
    /// with `DeletePending` set unlinks its node at cleanup, exactly like an FSD's `IRP_MJ_CLEANUP`.
    pub fn zw_close(&mut self, handle: u64) -> u32 {
        match self.handles.get_mut(handle as usize).and_then(|h| h.as_mut()) {
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
