//! The projected-object table (spec §7.4). Tracks each local projection's guest
//! address, kind, and the canonical id it stands for — the basis for validating
//! driver-provided pointers (spec §19.2).

use alloc::vec::Vec;

use nt_kernel_abi::GuestAddr;

/// The kind of a projected object.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    DriverObject,
    DeviceObject,
    Irp,
    UnicodeString,
}

/// A tracked projection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ObjectEntry {
    pub addr: GuestAddr,
    pub size: usize,
    pub kind: ObjectKind,
    /// The canonical id this projection stands for (`DeviceId`/`IrpId`; 0 if none).
    pub canonical_id: u64,
    /// For devices: the `DeviceExtension` region.
    pub extension: Option<GuestAddr>,
    /// Live flag (cleared on delete → stale-pointer rejection).
    pub live: bool,
}

/// The projected-object table.
#[derive(Default)]
pub struct ObjectTable {
    entries: Vec<ObjectEntry>,
}

impl ObjectTable {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn register(&mut self, entry: ObjectEntry) {
        self.entries.push(entry);
    }

    /// Find a live projection at exactly `addr`.
    pub fn find(&self, addr: GuestAddr) -> Option<&ObjectEntry> {
        self.entries.iter().find(|e| e.addr == addr && e.live)
    }

    /// Find a live projection at `addr` of the given `kind`.
    pub fn find_kind(&self, addr: GuestAddr, kind: ObjectKind) -> Option<&ObjectEntry> {
        self.find(addr).filter(|e| e.kind == kind)
    }

    /// Find a live projection by canonical id + kind.
    pub fn find_by_id(&self, kind: ObjectKind, id: u64) -> Option<&ObjectEntry> {
        self.entries
            .iter()
            .find(|e| e.live && e.kind == kind && e.canonical_id == id)
    }

    /// Mark the projection at `addr` deleted (subsequent lookups fail).
    pub fn retire(&mut self, addr: GuestAddr) -> bool {
        match self.entries.iter_mut().find(|e| e.addr == addr && e.live) {
            Some(e) => {
                e.live = false;
                true
            }
            None => false,
        }
    }

    /// Set the canonical id of the projection at `addr` (once the I/O Manager
    /// assigns it, M6).
    pub fn set_canonical_id(&mut self, addr: GuestAddr, id: u64) -> bool {
        match self.entries.iter_mut().find(|e| e.addr == addr && e.live) {
            Some(e) => {
                e.canonical_id = id;
                true
            }
            None => false,
        }
    }

    /// All live projections of a kind.
    pub fn of_kind(&self, kind: ObjectKind) -> impl Iterator<Item = &ObjectEntry> + '_ {
        self.entries
            .iter()
            .filter(move |e| e.live && e.kind == kind)
    }
}
