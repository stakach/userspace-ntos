//! The hive cell model + the mount table / path resolver (spec §6, §8-§9).
//!
//! A [`Hive`] is a cell arena — [`KeyCell`]s and [`ValueCell`]s addressed by a stable
//! [`CellId`], never a raw pointer. Registry operations navigate the arena by relative path.
//! The [`HiveMountTable`] resolves a full NT registry path to a mounted hive + a relative path,
//! applying the `CurrentControlSet` alias (spec §8).

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

pub use nt_config_manager::RegistryValueType;

/// A stable in-hive cell handle (spec §6.3) — never a Rust pointer.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct CellId(pub u64);

/// The kind of a hive (spec §7).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum HiveKind {
    System = 1,
    Software = 2,
    Default = 3,
    Sam = 4,
    Security = 5,
}

impl HiveKind {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::System,
            2 => Self::Software,
            3 => Self::Default,
            4 => Self::Sam,
            5 => Self::Security,
            _ => return None,
        })
    }
}

pub(crate) struct KeyCell {
    pub id: CellId,
    pub parent: Option<CellId>,
    pub name: String,
    pub subkeys: Vec<CellId>,
    pub values: Vec<CellId>,
    pub class_name: Option<String>,
    pub security_descriptor: Option<Vec<u8>>,
    pub last_write_sequence: u64,
}

pub(crate) struct ValueCell {
    pub id: CellId,
    pub parent_key: CellId,
    pub name: String,
    pub value_type: RegistryValueType,
    pub data_blob: usize,
    pub last_write_sequence: u64,
}

pub(crate) enum Cell {
    Key(KeyCell),
    Value(ValueCell),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeleteKeyError {
    NotFound,
    CannotDelete,
}

/// A mounted registry subtree as a cell arena (spec §6.1).
pub struct Hive {
    pub(crate) cells: Vec<Option<Cell>>,
    pub(crate) value_blobs: Vec<Rc<Vec<u8>>>,
    pub(crate) root: CellId,
    pub(crate) next_id: u64,
    pub kind: HiveKind,
    pub generation: u64,
    pub sequence: u64,
    pub(crate) clean_sequence: u64,
}

impl Hive {
    /// Create an empty hive of `kind` with a root key cell.
    pub fn new(kind: HiveKind) -> Self {
        let mut h = Hive {
            cells: Vec::new(),
            value_blobs: Vec::new(),
            root: CellId(0),
            next_id: 1,
            kind,
            generation: 0,
            sequence: 0,
            clean_sequence: 0,
        };
        h.root = h.alloc_key(None, "");
        h
    }

    pub fn root(&self) -> CellId {
        self.root
    }
    pub fn cell_count(&self) -> usize {
        self.cells.iter().filter(|c| c.is_some()).count()
    }

    pub fn reserve_cells(&mut self, additional: usize) -> bool {
        self.cells.try_reserve_exact(additional).is_ok()
    }

    pub fn reserve_value_blobs(&mut self, additional: usize) -> bool {
        self.value_blobs.try_reserve_exact(additional).is_ok()
    }

    fn alloc_id(&mut self) -> CellId {
        let id = CellId(self.next_id);
        self.next_id += 1;
        id
    }

    pub(crate) fn alloc_key(&mut self, parent: Option<CellId>, name: &str) -> CellId {
        let id = self.alloc_id();
        self.push_cell(Cell::Key(KeyCell {
            id,
            parent,
            name: name.into(),
            subkeys: Vec::new(),
            values: Vec::new(),
            class_name: None,
            security_descriptor: None,
            last_write_sequence: self.sequence,
        }));
        id
    }

    fn push_cell(&mut self, cell: Cell) {
        let idx = match &cell {
            Cell::Key(k) => k.id.0,
            Cell::Value(v) => v.id.0,
        } as usize;
        if idx >= self.cells.len() {
            self.cells.resize_with(idx + 1, || None);
        }
        self.cells[idx] = Some(cell);
    }

    fn key(&self, id: CellId) -> Option<&KeyCell> {
        match self.cells.get(id.0 as usize)?.as_ref()? {
            Cell::Key(k) => Some(k),
            _ => None,
        }
    }
    fn key_mut(&mut self, id: CellId) -> Option<&mut KeyCell> {
        match self.cells.get_mut(id.0 as usize)?.as_mut()? {
            Cell::Key(k) => Some(k),
            _ => None,
        }
    }
    fn value(&self, id: CellId) -> Option<&ValueCell> {
        match self.cells.get(id.0 as usize)?.as_ref()? {
            Cell::Value(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn value_data(&self, value: &ValueCell) -> Option<&[u8]> {
        self.value_blobs
            .get(value.data_blob)
            .map(|data| data.as_slice())
    }

    fn value_id_by_name(&self, key: CellId, name: &str) -> Option<CellId> {
        self.key(key)?
            .values
            .iter()
            .find(|vid| {
                self.value(**vid)
                    .is_some_and(|v| v.name.eq_ignore_ascii_case(name))
            })
            .copied()
    }

    fn components(path: &str) -> impl Iterator<Item = &str> {
        path.split('\\').filter(|c| !c.is_empty())
    }

    pub(crate) fn intern_value_data(&mut self, data: Vec<u8>) -> usize {
        if let Some(index) = self
            .value_blobs
            .iter()
            .position(|existing| existing.as_slice() == data.as_slice())
        {
            return index;
        }
        self.value_blobs.push(Rc::new(data));
        self.value_blobs.len() - 1
    }

    fn push_empty_value_blob_with_capacity(&mut self, len: usize) -> Option<usize> {
        let mut data = Vec::new();
        if data.try_reserve_exact(len).is_err() {
            return None;
        }
        self.value_blobs.push(Rc::new(data));
        Some(self.value_blobs.len() - 1)
    }

    fn intern_value_blob_handle(&mut self, data: Rc<Vec<u8>>) -> usize {
        if let Some(index) = self
            .value_blobs
            .iter()
            .position(|existing| Rc::ptr_eq(existing, &data))
        {
            return index;
        }
        self.value_blobs.push(data);
        self.value_blobs.len() - 1
    }

    fn value_blob_handle(&self, value: CellId) -> Option<Rc<Vec<u8>>> {
        let blob = self.value(value)?.data_blob;
        self.value_blobs.get(blob).cloned()
    }

    fn value_blob_ref_count(&self, blob: usize) -> usize {
        self.cells
            .iter()
            .filter_map(|cell| match cell {
                Some(Cell::Value(value)) if value.data_blob == blob => Some(()),
                _ => None,
            })
            .count()
    }

    /// Open a subkey by (case-insensitive) name.
    pub fn open_subkey(&self, parent: CellId, name: &str) -> Option<CellId> {
        self.key(parent)?
            .subkeys
            .iter()
            .find(|id| {
                self.key(**id)
                    .is_some_and(|child| child.name.eq_ignore_ascii_case(name))
            })
            .copied()
    }

    /// `ZwOpenKey` — resolve a relative path within the hive to a key cell.
    pub fn open_key(&self, rel_path: &str) -> Option<CellId> {
        let mut cur = self.root;
        for comp in Self::components(rel_path) {
            cur = self.open_subkey(cur, comp)?;
        }
        Some(cur)
    }

    /// Open or create an immediate subkey.
    pub fn create_subkey(&mut self, parent: CellId, name: &str) -> CellId {
        if let Some(id) = self.open_subkey(parent, name) {
            return id;
        }
        self.sequence += 1;
        let id = self.alloc_key(Some(parent), name);
        self.key_mut(parent).unwrap().subkeys.push(id);
        self.mark_dirty(parent);
        self.mark_dirty(id);
        id
    }

    /// `ZwCreateKey` — open or create a key at a relative path (creating intermediates).
    pub fn create_key(&mut self, rel_path: &str) -> CellId {
        let mut cur = self.root;
        for comp in Self::components(rel_path) {
            cur = self.create_subkey(cur, comp);
        }
        cur
    }

    pub fn set_key_class(&mut self, key: CellId, class_name: Option<&str>) -> bool {
        if self.key(key).is_none() {
            return false;
        }
        self.sequence += 1;
        let seq = self.sequence;
        let Some(cell) = self.key_mut(key) else {
            return false;
        };
        cell.class_name = class_name.map(String::from);
        cell.last_write_sequence = seq;
        self.mark_dirty(key);
        true
    }

    pub fn key_class(&self, key: CellId) -> Option<&str> {
        self.key(key)?.class_name.as_deref()
    }

    pub fn set_key_security_descriptor(&mut self, key: CellId, descriptor: &[u8]) -> bool {
        if self.key(key).is_none() {
            return false;
        }
        self.sequence += 1;
        let seq = self.sequence;
        let Some(cell) = self.key_mut(key) else {
            return false;
        };
        cell.security_descriptor = Some(descriptor.to_vec());
        cell.last_write_sequence = seq;
        self.mark_dirty(key);
        true
    }

    pub fn key_security_descriptor(&self, key: CellId) -> Option<&[u8]> {
        self.key(key)?.security_descriptor.as_deref()
    }

    fn mark_dirty(&mut self, id: CellId) {
        let seq = self.sequence;
        match self
            .cells
            .get_mut(id.0 as usize)
            .and_then(|cell| cell.as_mut())
        {
            Some(Cell::Key(key)) => key.last_write_sequence = seq,
            Some(Cell::Value(value)) => value.last_write_sequence = seq,
            None => {}
        }
    }
    pub fn dirty_count(&self) -> usize {
        self.cells
            .iter()
            .filter(|cell| match cell {
                Some(Cell::Key(key)) => key.last_write_sequence > self.clean_sequence,
                Some(Cell::Value(value)) => value.last_write_sequence > self.clean_sequence,
                None => false,
            })
            .count()
    }
    pub(crate) fn clear_dirty(&mut self) {
        self.clean_sequence = self.sequence;
    }

    /// A boot/import path has just populated this hive from already-persistent backing bytes.
    ///
    /// The imported cells are the new clean baseline: future `HiveManager::mutate` calls should be
    /// the first journalled sequence numbers, and a later checkpoint should not report import-time
    /// construction as dirty runtime state.
    pub fn finish_clean_import(&mut self) {
        self.sequence = 0;
        self.generation = 0;
        for cell in self.cells.iter_mut().filter_map(|cell| cell.as_mut()) {
            match cell {
                Cell::Key(key) => key.last_write_sequence = 0,
                Cell::Value(value) => value.last_write_sequence = 0,
            }
        }
        self.clear_dirty();
    }

    /// `ZwSetValueKey` — set (create or replace) a named value on a key cell.
    pub fn set_value(
        &mut self,
        key: CellId,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        if self.key(key).is_none() {
            return false;
        }
        let data_blob = self.intern_value_data(data);
        self.sequence += 1;
        let seq = self.sequence;
        // Existing value?
        let existing = self.value_id_by_name(key, name);
        match existing {
            Some(vid) => {
                if let Some(Cell::Value(v)) =
                    self.cells.get_mut(vid.0 as usize).and_then(|c| c.as_mut())
                {
                    v.value_type = value_type;
                    v.data_blob = data_blob;
                    v.last_write_sequence = seq;
                }
                self.mark_dirty(vid);
                true
            }
            None => {
                let vid = self.alloc_id();
                self.push_cell(Cell::Value(ValueCell {
                    id: vid,
                    parent_key: key,
                    name: name.into(),
                    value_type,
                    data_blob,
                    last_write_sequence: seq,
                }));
                self.key_mut(key).unwrap().values.push(vid);
                self.mark_dirty(key);
                self.mark_dirty(vid);
                true
            }
        }
    }

    /// Prepare a value's backing buffer for chunked replacement.
    ///
    /// Existing values reuse their current allocation when it is large enough, avoiding a second
    /// large registry blob on the executive bump heap. On reserve failure the old value is left
    /// untouched and `None` is returned.
    pub fn prepare_value_buffer(
        &mut self,
        key: CellId,
        name: &str,
        value_type: RegistryValueType,
        len: usize,
    ) -> Option<CellId> {
        if self.key(key).is_none() {
            return None;
        }
        if let Some(vid) = self.value_id_by_name(key, name) {
            let data_blob = self.value(vid)?.data_blob;
            let reuse_existing_blob = self.value_blob_ref_count(data_blob) == 1
                && self
                    .value_blobs
                    .get(data_blob)
                    .is_some_and(|data| Rc::strong_count(data) == 1)
                && self
                    .value_blobs
                    .get(data_blob)
                    .is_some_and(|data| data.capacity() >= len);
            let prepared_blob = if reuse_existing_blob {
                data_blob
            } else {
                self.push_empty_value_blob_with_capacity(len)?
            };
            self.sequence += 1;
            let seq = self.sequence;
            let Some(Cell::Value(value)) = self
                .cells
                .get_mut(vid.0 as usize)
                .and_then(|cell| cell.as_mut())
            else {
                return None;
            };
            value.value_type = value_type;
            value.data_blob = prepared_blob;
            if let Some(data) = self
                .value_blobs
                .get_mut(prepared_blob)
                .and_then(Rc::get_mut)
            {
                data.clear();
            }
            value.last_write_sequence = seq;
            self.mark_dirty(vid);
            return Some(vid);
        }

        let data_blob = self.push_empty_value_blob_with_capacity(len)?;
        self.sequence += 1;
        let seq = self.sequence;
        let vid = self.alloc_id();
        self.push_cell(Cell::Value(ValueCell {
            id: vid,
            parent_key: key,
            name: name.into(),
            value_type,
            data_blob,
            last_write_sequence: seq,
        }));
        self.key_mut(key).unwrap().values.push(vid);
        self.mark_dirty(key);
        self.mark_dirty(vid);
        Some(vid)
    }

    pub fn append_prepared_value_data(&mut self, value: CellId, chunk: &[u8]) -> bool {
        let Some(blob) = self.value(value).map(|value| value.data_blob) else {
            return false;
        };
        let Some(data) = self.value_blobs.get_mut(blob).and_then(Rc::get_mut) else {
            return false;
        };
        if data.len().saturating_add(chunk.len()) > data.capacity() {
            return false;
        }
        data.extend_from_slice(chunk);
        true
    }

    pub fn prepared_value_len(&self, value: CellId) -> Option<usize> {
        Some(self.value_data(self.value(value)?)?.len())
    }

    /// Set `name` on `key` to share the already-owned payload of `source`.
    ///
    /// This is the same-hive fast path a Configuration Manager subtree copy wants: the destination
    /// value gets its own cell metadata but references the same immutable payload bytes until a later
    /// replacement gives either cell a new blob.
    pub fn set_value_from_existing_value(
        &mut self,
        key: CellId,
        name: &str,
        value_type: RegistryValueType,
        source: CellId,
    ) -> bool {
        if self.key(key).is_none() {
            return false;
        }
        let Some(source_blob) = self.value(source).map(|source| source.data_blob) else {
            return false;
        };
        self.sequence += 1;
        let seq = self.sequence;
        if let Some(vid) = self.value_id_by_name(key, name) {
            let Some(Cell::Value(value)) = self
                .cells
                .get_mut(vid.0 as usize)
                .and_then(|cell| cell.as_mut())
            else {
                return false;
            };
            value.value_type = value_type;
            value.data_blob = source_blob;
            value.last_write_sequence = seq;
            self.mark_dirty(vid);
            return true;
        }

        let vid = self.alloc_id();
        self.push_cell(Cell::Value(ValueCell {
            id: vid,
            parent_key: key,
            name: name.into(),
            value_type,
            data_blob: source_blob,
            last_write_sequence: seq,
        }));
        self.key_mut(key).unwrap().values.push(vid);
        self.mark_dirty(key);
        self.mark_dirty(vid);
        true
    }

    fn set_value_from_blob_handle(
        &mut self,
        key: CellId,
        name: &str,
        value_type: RegistryValueType,
        data: Rc<Vec<u8>>,
    ) -> bool {
        if self.key(key).is_none() {
            return false;
        }
        let data_blob = self.intern_value_blob_handle(data);
        self.sequence += 1;
        let seq = self.sequence;
        if let Some(vid) = self.value_id_by_name(key, name) {
            let Some(Cell::Value(value)) = self
                .cells
                .get_mut(vid.0 as usize)
                .and_then(|cell| cell.as_mut())
            else {
                return false;
            };
            value.value_type = value_type;
            value.data_blob = data_blob;
            value.last_write_sequence = seq;
            self.mark_dirty(vid);
            return true;
        }

        let vid = self.alloc_id();
        self.push_cell(Cell::Value(ValueCell {
            id: vid,
            parent_key: key,
            name: name.into(),
            value_type,
            data_blob,
            last_write_sequence: seq,
        }));
        self.key_mut(key).unwrap().values.push(vid);
        self.mark_dirty(key);
        self.mark_dirty(vid);
        true
    }

    /// `ZwDeleteValueKey` — remove a named value from a key cell.
    pub fn delete_value(&mut self, key: CellId, name: &str) -> bool {
        let Some((pos, value_id)) = self.key(key).and_then(|k| {
            k.values
                .iter()
                .enumerate()
                .find(|(_, vid)| {
                    self.value(**vid)
                        .is_some_and(|v| v.name.eq_ignore_ascii_case(name))
                })
                .map(|(pos, vid)| (pos, *vid))
        }) else {
            return false;
        };
        self.sequence += 1;
        let seq = self.sequence;
        let Some(parent) = self.key_mut(key) else {
            return false;
        };
        parent.values.remove(pos);
        parent.last_write_sequence = seq;
        if let Some(cell) = self.cells.get_mut(value_id.0 as usize) {
            *cell = None;
        }
        self.mark_dirty(key);
        self.mark_dirty(value_id);
        true
    }

    /// `ZwDeleteKey` — delete a leaf key and its values from the hive.
    ///
    /// NT refuses the hive root and keys that still have subkeys; callers that need a subtree
    /// removal must enumerate/delete children first.
    pub fn delete_key(&mut self, key: CellId) -> Result<(), DeleteKeyError> {
        if key == self.root {
            return Err(DeleteKeyError::CannotDelete);
        }
        let (parent_id, value_ids) = {
            let Some(cell) = self.key(key) else {
                return Err(DeleteKeyError::NotFound);
            };
            if !cell.subkeys.is_empty() || cell.parent.is_none() {
                return Err(DeleteKeyError::CannotDelete);
            }
            (cell.parent.unwrap(), cell.values.clone())
        };
        self.sequence += 1;
        let seq = self.sequence;
        if let Some(parent) = self.key_mut(parent_id) {
            parent.subkeys.retain(|child| *child != key);
            parent.last_write_sequence = seq;
            self.mark_dirty(parent_id);
        } else {
            return Err(DeleteKeyError::NotFound);
        }
        for value_id in value_ids {
            if let Some(cell) = self.cells.get_mut(value_id.0 as usize) {
                *cell = None;
                self.mark_dirty(value_id);
            }
        }
        if let Some(cell) = self.cells.get_mut(key.0 as usize) {
            *cell = None;
            self.mark_dirty(key);
            Ok(())
        } else {
            Err(DeleteKeyError::NotFound)
        }
    }

    /// `ZwQueryValueKey` — read a named value (type + data).
    pub fn query_value(&self, key: CellId, name: &str) -> Option<(RegistryValueType, &[u8])> {
        let k = self.key(key)?;
        k.values
            .iter()
            .filter_map(|vid| self.value(*vid))
            .find(|v| v.name.eq_ignore_ascii_case(name))
            .and_then(|v| Some((v.value_type, self.value_data(v)?)))
    }

    /// Convenience: a `REG_DWORD` value.
    pub fn query_dword(&self, key: CellId, name: &str) -> Option<u32> {
        match self.query_value(key, name) {
            Some((RegistryValueType::Dword, d)) if d.len() == 4 => {
                Some(u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
            }
            _ => None,
        }
    }
    pub fn set_dword(&mut self, key: CellId, name: &str, v: u32) -> bool {
        self.set_value(
            key,
            name,
            RegistryValueType::Dword,
            v.to_le_bytes().to_vec(),
        )
    }

    pub fn enum_subkeys(&self, key: CellId) -> Vec<String> {
        self.key(key)
            .map(|k| {
                k.subkeys
                    .iter()
                    .filter_map(|id| self.key(*id).map(|c| c.name.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn enum_values(&self, key: CellId) -> Vec<String> {
        self.key(key)
            .map(|k| {
                k.values
                    .iter()
                    .filter_map(|id| self.value(*id).map(|v| v.name.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Number of immediate subkeys on `key`.
    pub fn subkey_count(&self, key: CellId) -> usize {
        self.key(key).map_or(0, |k| k.subkeys.len())
    }

    /// Borrow the original-case name of the immediate subkey at `index`.
    pub fn subkey_name_by_index(&self, key: CellId, index: usize) -> Option<&str> {
        let child = *self.key(key)?.subkeys.get(index)?;
        self.key(child).map(|k| k.name.as_str())
    }

    pub fn subkey_class_by_index(&self, key: CellId, index: usize) -> Option<&str> {
        let child = *self.key(key)?.subkeys.get(index)?;
        self.key_class(child)
    }

    /// Number of values on `key`.
    pub fn value_count(&self, key: CellId) -> usize {
        self.key(key).map_or(0, |k| k.values.len())
    }

    /// Borrow the value at `index` without cloning its name or data.
    pub fn value_by_index(
        &self,
        key: CellId,
        index: usize,
    ) -> Option<(&str, RegistryValueType, &[u8])> {
        let value = self.value(*self.key(key)?.values.get(index)?)?;
        Some((
            value.name.as_str(),
            value.value_type,
            self.value_data(value)?,
        ))
    }

    pub fn value_ref_by_index(
        &self,
        key: CellId,
        index: usize,
    ) -> Option<(CellId, &str, RegistryValueType, &[u8])> {
        let value = self.value(*self.key(key)?.values.get(index)?)?;
        Some((
            value.id,
            value.name.as_str(),
            value.value_type,
            self.value_data(value)?,
        ))
    }

    /// The relative path of a key cell within the hive (`\Sub\Key`).
    pub fn key_path(&self, id: CellId) -> Option<String> {
        let mut parts: Vec<&str> = Vec::new();
        let mut cur = self.key(id)?;
        while let Some(p) = cur.parent {
            parts.push(&cur.name);
            cur = self.key(p)?;
        }
        let mut path = String::new();
        for p in parts.iter().rev() {
            path.push('\\');
            path.push_str(p);
        }
        Some(path)
    }

    /// Iterate `(cell_id, parent, name, class, seq)` for every key cell (image encode).
    pub(crate) fn key_cells(&self) -> impl Iterator<Item = &KeyCell> {
        self.cells.iter().filter_map(|c| match c {
            Some(Cell::Key(k)) => Some(k),
            _ => None,
        })
    }
    pub(crate) fn value_cells(&self) -> impl Iterator<Item = &ValueCell> {
        self.cells.iter().filter_map(|c| match c {
            Some(Cell::Value(v)) => Some(v),
            _ => None,
        })
    }
}

// --- mount table + path resolver (spec §6.2, §8) -----------------------------

/// A hive identifier in the mount table.
pub type HiveId = u32;

/// The `\Registry\Machine\System` hive path — the v0.1 required hive (spec §6.1).
pub const SYSTEM_HIVE_PATH: &str = r"\Registry\Machine\System";
/// The live control set the `CurrentControlSet` alias resolves to (spec §8).
pub const CURRENT_CONTROL_SET_TARGET: &str = "ControlSet001";

/// The hive mount table + `CurrentControlSet` alias resolver (spec §6.2, §8).
#[derive(Default)]
pub struct HiveMountTable {
    mounts: Vec<(String, HiveId)>, // (root path, hive) — longest match wins
}

impl HiveMountTable {
    pub fn new() -> Self {
        Self { mounts: Vec::new() }
    }
    pub fn mount(&mut self, root_path: &str, hive: HiveId) {
        self.mounts
            .retain(|(p, _)| !p.eq_ignore_ascii_case(root_path));
        self.mounts.push((root_path.into(), hive));
    }

    pub fn unmount(&mut self, root_path: &str) -> Option<HiveId> {
        let index = self
            .mounts
            .iter()
            .position(|(path, _)| path.eq_ignore_ascii_case(root_path))?;
        Some(self.mounts.remove(index).1)
    }

    /// Resolve a full NT registry path to `(HiveId, relative_path)` (spec §6.2), applying the
    /// `CurrentControlSet` → `ControlSet001` alias (spec §8) before matching.
    pub fn resolve(&self, full_path: &str) -> Option<(HiveId, String)> {
        let aliased = apply_ccs_alias(full_path);
        // Longest matching mount root wins.
        let mut best: Option<(&str, HiveId)> = None;
        for (root, hive) in &self.mounts {
            if path_starts_with(&aliased, root)
                && best.map(|(b, _)| root.len() > b.len()).unwrap_or(true)
            {
                best = Some((root.as_str(), *hive));
            }
        }
        let (root, hive) = best?;
        let rel = &aliased[root.len()..];
        Some((hive, rel.into()))
    }

    /// True if a mounted hive owns this full NT registry path, whether or not the key exists.
    pub fn owns_path(&self, full_path: &str) -> bool {
        let aliased = apply_ccs_alias(full_path);
        self.mounts
            .iter()
            .any(|(root, _)| path_starts_with(&aliased, root))
    }
}

/// A resolved key in a mounted mutable hive.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResolvedHiveKey {
    pub hive: HiveId,
    pub key: CellId,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResolvedHiveValue {
    pub hive: HiveId,
    pub value: CellId,
}

/// A recently copied-out registry value payload.
///
/// ReactOS' `RegCopyTreeW` asks `NtEnumerateValueKey` for a full
/// `KEY_VALUE_FULL_INFORMATION` record and immediately passes the data field back to
/// `NtSetValueKey`. Keeping this source identity per caller thread lets the hive manager install a
/// destination value that shares the source blob after the SetValue handler has verified that the
/// user buffer still contains those bytes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistryValueCopyProvenance {
    source: Option<ResolvedHiveValue>,
    process_index: u64,
    thread_id: u64,
    data_va: u64,
    data_len: usize,
    value_type: u32,
}

impl RegistryValueCopyProvenance {
    pub fn new(
        source: ResolvedHiveValue,
        process_index: u64,
        thread_id: u64,
        data_va: u64,
        data_len: usize,
        value_type: u32,
    ) -> Self {
        Self {
            source: Some(source),
            process_index,
            thread_id,
            data_va,
            data_len,
            value_type,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.source.is_some() && self.data_len != 0
    }

    fn is_for_thread(&self, process_index: u64, thread_id: u64) -> bool {
        self.process_index == process_index && self.thread_id == thread_id
    }

    fn source_for_user_data(
        &self,
        process_index: u64,
        thread_id: u64,
        data_va: u64,
        data_len: usize,
        value_type: u32,
    ) -> Option<ResolvedHiveValue> {
        if self.is_for_thread(process_index, thread_id)
            && self.data_va == data_va
            && self.data_len == data_len
            && self.value_type == value_type
        {
            self.source
        } else {
            None
        }
    }
}

#[derive(Default)]
pub struct RegistryValueCopyProvenanceTable {
    entries: Vec<RegistryValueCopyProvenance>,
}

impl RegistryValueCopyProvenanceTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut entries = Vec::new();
        let _ = entries.try_reserve_exact(capacity);
        Self { entries }
    }

    pub fn clear_for_thread(&mut self, process_index: u64, thread_id: u64) {
        self.entries
            .retain(|entry| !entry.is_for_thread(process_index, thread_id));
    }

    pub fn record(&mut self, provenance: RegistryValueCopyProvenance) -> bool {
        if !provenance.is_valid() {
            self.clear_for_thread(provenance.process_index, provenance.thread_id);
            return true;
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_for_thread(provenance.process_index, provenance.thread_id))
        {
            *entry = provenance;
            return true;
        }
        if self.entries.len() == self.entries.capacity()
            && self.entries.try_reserve_exact(1).is_err()
        {
            return false;
        }
        self.entries.push(provenance);
        true
    }

    pub fn source_for_user_data(
        &self,
        process_index: u64,
        thread_id: u64,
        data_va: u64,
        data_len: usize,
        value_type: u32,
    ) -> Option<ResolvedHiveValue> {
        self.entries.iter().find_map(|entry| {
            entry.source_for_user_data(process_index, thread_id, data_va, data_len, value_type)
        })
    }
}

/// Owned mutable hives plus the NT registry namespace that mounts them.
///
/// This is the host-testable Configuration Manager authority D2 needs before the executive stops
/// pairing read-only `RegfHive` selectors with a separate `RegistryOverlay` write plane.
#[derive(Default)]
pub struct MutableHiveSet {
    mounts: HiveMountTable,
    hives: Vec<(HiveId, Hive)>,
}

impl MutableHiveSet {
    pub fn new() -> Self {
        Self {
            mounts: HiveMountTable::new(),
            hives: Vec::new(),
        }
    }

    pub fn mount(&mut self, root_path: &str, hive_id: HiveId, hive: Hive) {
        self.mounts.mount(root_path, hive_id);
        match self.hives.iter().position(|(id, _)| *id == hive_id) {
            Some(index) => self.hives[index] = (hive_id, hive),
            None => self.hives.push((hive_id, hive)),
        }
    }

    pub fn unmount(&mut self, root_path: &str) -> Option<Hive> {
        let hive_id = self.mounts.unmount(root_path)?;
        let index = self.hives.iter().position(|(id, _)| *id == hive_id)?;
        Some(self.hives.remove(index).1)
    }

    pub fn hive(&self, hive_id: HiveId) -> Option<&Hive> {
        self.hives
            .iter()
            .find(|(id, _)| *id == hive_id)
            .map(|(_, hive)| hive)
    }

    pub fn hive_mut(&mut self, hive_id: HiveId) -> Option<&mut Hive> {
        self.hives
            .iter_mut()
            .find(|(id, _)| *id == hive_id)
            .map(|(_, hive)| hive)
    }

    pub fn resolve_key(&self, full_path: &str) -> Option<ResolvedHiveKey> {
        let (hive_id, rel_path) = self.mounts.resolve(full_path)?;
        let hive = self.hive(hive_id)?;
        Some(ResolvedHiveKey {
            hive: hive_id,
            key: hive.open_key(&rel_path)?,
        })
    }

    pub fn owns_path(&self, full_path: &str) -> bool {
        self.mounts.owns_path(full_path)
    }

    pub fn create_key(&mut self, full_path: &str) -> Option<ResolvedHiveKey> {
        let (hive_id, rel_path) = self.mounts.resolve(full_path)?;
        let hive = self.hive_mut(hive_id)?;
        Some(ResolvedHiveKey {
            hive: hive_id,
            key: hive.create_key(&rel_path),
        })
    }

    /// Create or open an immediate child below an already-resolved mounted-hive key.
    pub fn create_subkey(
        &mut self,
        parent: ResolvedHiveKey,
        name: &str,
    ) -> Option<ResolvedHiveKey> {
        if name.is_empty() || name.contains('\\') {
            return None;
        }
        let hive = self.hive_mut(parent.hive)?;
        Some(ResolvedHiveKey {
            hive: parent.hive,
            key: hive.create_subkey(parent.key, name),
        })
    }

    pub fn set_value(
        &mut self,
        key: ResolvedHiveKey,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        self.hive_mut(key.hive)
            .is_some_and(|hive| hive.set_value(key.key, name, value_type, data))
    }

    pub fn set_value_from_existing_value(
        &mut self,
        key: ResolvedHiveKey,
        name: &str,
        value_type: RegistryValueType,
        source: ResolvedHiveValue,
    ) -> bool {
        if key.hive == source.hive {
            return self.hive_mut(key.hive).is_some_and(|hive| {
                hive.set_value_from_existing_value(key.key, name, value_type, source.value)
            });
        }

        let Some(source_blob) = self
            .hive(source.hive)
            .and_then(|hive| hive.value_blob_handle(source.value))
        else {
            return false;
        };
        let Some(source_type) = self
            .hive(source.hive)
            .and_then(|hive| hive.value(source.value))
            .map(|value| value.value_type)
        else {
            return false;
        };
        if source_type != value_type {
            return false;
        }
        self.hive_mut(key.hive).is_some_and(|hive| {
            hive.set_value_from_blob_handle(key.key, name, value_type, source_blob)
        })
    }

    pub fn prepare_value_buffer(
        &mut self,
        key: ResolvedHiveKey,
        name: &str,
        value_type: RegistryValueType,
        len: usize,
    ) -> Option<ResolvedHiveValue> {
        let hive = self.hive_mut(key.hive)?;
        Some(ResolvedHiveValue {
            hive: key.hive,
            value: hive.prepare_value_buffer(key.key, name, value_type, len)?,
        })
    }

    pub fn append_prepared_value_data(&mut self, value: ResolvedHiveValue, chunk: &[u8]) -> bool {
        self.hive_mut(value.hive)
            .is_some_and(|hive| hive.append_prepared_value_data(value.value, chunk))
    }

    pub fn prepared_value_len(&self, value: ResolvedHiveValue) -> Option<usize> {
        self.hive(value.hive)?.prepared_value_len(value.value)
    }

    pub fn query_resolved_value(
        &self,
        value: ResolvedHiveValue,
    ) -> Option<(RegistryValueType, &[u8])> {
        let hive = self.hive(value.hive)?;
        let value = hive.value(value.value)?;
        Some((value.value_type, hive.value_data(value)?))
    }

    pub fn delete_value(&mut self, key: ResolvedHiveKey, name: &str) -> bool {
        self.hive_mut(key.hive)
            .is_some_and(|hive| hive.delete_value(key.key, name))
    }

    pub fn delete_key(&mut self, key: ResolvedHiveKey) -> Result<(), DeleteKeyError> {
        self.hive_mut(key.hive)
            .ok_or(DeleteKeyError::NotFound)?
            .delete_key(key.key)
    }

    pub fn set_key_class(&mut self, key: ResolvedHiveKey, class_name: Option<&str>) -> bool {
        self.hive_mut(key.hive)
            .is_some_and(|hive| hive.set_key_class(key.key, class_name))
    }

    pub fn key_class(&self, key: ResolvedHiveKey) -> Option<&str> {
        self.hive(key.hive)?.key_class(key.key)
    }

    pub fn set_key_security_descriptor(&mut self, key: ResolvedHiveKey, descriptor: &[u8]) -> bool {
        self.hive_mut(key.hive)
            .is_some_and(|hive| hive.set_key_security_descriptor(key.key, descriptor))
    }

    pub fn key_security_descriptor(&self, key: ResolvedHiveKey) -> Option<&[u8]> {
        self.hive(key.hive)?.key_security_descriptor(key.key)
    }

    pub fn query_value(
        &self,
        key: ResolvedHiveKey,
        name: &str,
    ) -> Option<(RegistryValueType, &[u8])> {
        self.hive(key.hive)?.query_value(key.key, name)
    }

    pub fn value_ref_by_index(
        &self,
        key: ResolvedHiveKey,
        index: usize,
    ) -> Option<(ResolvedHiveValue, &str, RegistryValueType, &[u8])> {
        let hive = self.hive(key.hive)?;
        let (value, name, value_type, data) = hive.value_ref_by_index(key.key, index)?;
        Some((
            ResolvedHiveValue {
                hive: key.hive,
                value,
            },
            name,
            value_type,
            data,
        ))
    }
}

/// Replace a `CurrentControlSet` path component with the live control set (spec §8).
pub fn apply_ccs_alias(path: &str) -> String {
    let mut out = String::new();
    for comp in path.split('\\').filter(|c| !c.is_empty()) {
        out.push('\\');
        if comp.eq_ignore_ascii_case("CurrentControlSet") {
            out.push_str(CURRENT_CONTROL_SET_TARGET);
        } else {
            out.push_str(comp);
        }
    }
    out
}

/// Case-insensitive path-prefix test on `\`-delimited components.
fn path_starts_with(path: &str, prefix: &str) -> bool {
    let mut path_components = path.split('\\').filter(|c| !c.is_empty());
    for prefix_component in prefix.split('\\').filter(|c| !c.is_empty()) {
        let Some(path_component) = path_components.next() else {
            return false;
        };
        if !prefix_component.eq_ignore_ascii_case(path_component) {
            return false;
        }
    }
    true
}
