//! The hive cell model + the mount table / path resolver (spec §6, §8-§9).
//!
//! A [`Hive`] is a cell arena — [`KeyCell`]s and [`ValueCell`]s addressed by a stable
//! [`CellId`], never a raw pointer. Registry operations navigate the arena by relative path.
//! The [`HiveMountTable`] resolves a full NT registry path to a mounted hive + a relative path,
//! applying the `CurrentControlSet` alias (spec §8).

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
    pub subkeys: Vec<(String, CellId)>, // (folded name, id)
    pub values: Vec<CellId>,
    pub class_name: Option<String>,
    pub last_write_sequence: u64,
}

pub(crate) struct ValueCell {
    pub id: CellId,
    pub parent_key: CellId,
    pub name: String,
    pub value_type: RegistryValueType,
    pub data: Vec<u8>,
    pub last_write_sequence: u64,
}

pub(crate) enum Cell {
    Key(KeyCell),
    Value(ValueCell),
}

pub(crate) fn fold(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// A mounted registry subtree as a cell arena (spec §6.1).
pub struct Hive {
    pub(crate) cells: Vec<Option<Cell>>,
    pub(crate) root: CellId,
    pub(crate) next_id: u64,
    pub kind: HiveKind,
    pub generation: u64,
    pub sequence: u64,
    pub(crate) dirty: Vec<CellId>,
}

impl Hive {
    /// Create an empty hive of `kind` with a root key cell.
    pub fn new(kind: HiveKind) -> Self {
        let mut h = Hive {
            cells: Vec::new(),
            root: CellId(0),
            next_id: 1,
            kind,
            generation: 0,
            sequence: 0,
            dirty: Vec::new(),
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

    fn components(path: &str) -> impl Iterator<Item = &str> {
        path.split('\\').filter(|c| !c.is_empty())
    }

    /// Open a subkey by (case-insensitive) name.
    pub fn open_subkey(&self, parent: CellId, name: &str) -> Option<CellId> {
        let folded = fold(name);
        self.key(parent)?
            .subkeys
            .iter()
            .find(|(n, _)| *n == folded)
            .map(|(_, id)| *id)
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
        let id = self.alloc_key(Some(parent), name);
        let folded = fold(name);
        self.key_mut(parent).unwrap().subkeys.push((folded, id));
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

    fn mark_dirty(&mut self, id: CellId) {
        if !self.dirty.contains(&id) {
            self.dirty.push(id);
        }
    }
    pub fn dirty_count(&self) -> usize {
        self.dirty.len()
    }
    pub(crate) fn clear_dirty(&mut self) {
        self.dirty.clear();
    }

    /// `ZwSetValueKey` — set (create or replace) a named value on a key cell.
    pub fn set_value(
        &mut self,
        key: CellId,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        self.sequence += 1;
        let seq = self.sequence;
        let folded = fold(name);
        // Existing value?
        let existing = self
            .key(key)
            .map(|k| {
                k.values
                    .iter()
                    .find(|vid| self.value(**vid).is_some_and(|v| fold(&v.name) == folded))
                    .copied()
            })
            .unwrap_or(None);
        match existing {
            Some(vid) => {
                if let Some(Cell::Value(v)) = self.cells.get_mut(vid.0 as usize).and_then(|c| c.as_mut()) {
                    v.value_type = value_type;
                    v.data = data;
                    v.last_write_sequence = seq;
                }
                self.mark_dirty(vid);
                true
            }
            None => {
                if self.key(key).is_none() {
                    return false;
                }
                let vid = self.alloc_id();
                self.push_cell(Cell::Value(ValueCell {
                    id: vid,
                    parent_key: key,
                    name: name.into(),
                    value_type,
                    data,
                    last_write_sequence: seq,
                }));
                self.key_mut(key).unwrap().values.push(vid);
                self.mark_dirty(key);
                self.mark_dirty(vid);
                true
            }
        }
    }

    /// `ZwQueryValueKey` — read a named value (type + data).
    pub fn query_value(&self, key: CellId, name: &str) -> Option<(RegistryValueType, &[u8])> {
        let folded = fold(name);
        let k = self.key(key)?;
        k.values
            .iter()
            .filter_map(|vid| self.value(*vid))
            .find(|v| fold(&v.name) == folded)
            .map(|v| (v.value_type, v.data.as_slice()))
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
        self.set_value(key, name, RegistryValueType::Dword, v.to_le_bytes().to_vec())
    }

    pub fn enum_subkeys(&self, key: CellId) -> Vec<String> {
        self.key(key)
            .map(|k| {
                k.subkeys
                    .iter()
                    .filter_map(|(_, id)| self.key(*id).map(|c| c.name.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn enum_values(&self, key: CellId) -> Vec<String> {
        self.key(key)
            .map(|k| k.values.iter().filter_map(|id| self.value(*id).map(|v| v.name.clone())).collect())
            .unwrap_or_default()
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
        self.mounts.retain(|(p, _)| !p.eq_ignore_ascii_case(root_path));
        self.mounts.push((root_path.into(), hive));
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
    let p: Vec<&str> = path.split('\\').filter(|c| !c.is_empty()).collect();
    let q: Vec<&str> = prefix.split('\\').filter(|c| !c.is_empty()).collect();
    q.len() <= p.len() && q.iter().zip(&p).all(|(a, b)| a.eq_ignore_ascii_case(b))
}
