//! The executive's compact object namespace table.
//!
//! An entry's index is the native identity of its object: handles, dispatcher state and wait
//! records name the object by index. The table is the only place an index is handed out and
//! the only place one is taken back.
//!
//! Slot policy lives in `nt_object_manager::slot_ledger`. A retired slot is reused, oldest
//! first, only when its retirement reported no outstanding reference; every occupant gets a
//! fresh `identity`, so a reference that records index plus identity cannot resolve to a later
//! occupant. An entry deleted in place with [`ObjEntry::unlink`] keeps its slot for good.
//!
//! Handles, dispatcher state and wait records name an object by bare index. They are counted
//! before a slot is freed (`slot_retirement.rs`, and the Event registry's retirement proof),
//! and the [`SLOT_REUSE_DELAY`] most recently freed slots are held back as a margin for an
//! index a running operation still holds in a local.

use crate::*;
use core::ops::{Deref, DerefMut};
use nt_object_manager::slot_ledger::SlotLedger;

/// One node in the executive's minimal object-manager namespace. Inline, `Copy`, no nested heap
/// allocation. NT object leaf names are allowed to be long enough for BaseNamedObjects mutexes
/// such as userenv's per-profile mutex; `target` is link-only data; `payload` carries backing object
/// identity for kinds whose state lives outside the namespace, such as LPC listen port handles and
/// I/O completion ports. `permanent` mirrors `OBJ_PERMANENT`; non-permanent named objects are
/// unlinked when their final body reference goes away.
#[derive(Clone, Copy)]
pub(crate) struct ObjEntry {
    /// The slot generation: issued once per entry and never reused, unlike the entry's index.
    pub(crate) identity: u64,
    pub(crate) name: [u8; OBJ_NAME_CAP], // stored ASCII leaf; directory objects retain caller spelling
    pub(crate) name_len: u8,
    pub(crate) parent: usize, // index of the parent directory; OBJ_PARENT_ROOT = the root itself
    pub(crate) kind: u8,
    pub(crate) permanent: bool,
    /// References held by published native wait records after the caller's handle capture.
    pub(crate) wait_references: u32,
    pub(crate) target: [u8; OBJ_NAME_CAP], // symbolic-link target (kind == 1)
    pub(crate) target_len: u8,
    pub(crate) payload: u64,
}

impl ObjEntry {
    fn vacant(identity: u64) -> Self {
        Self {
            identity,
            name: [0; OBJ_NAME_CAP],
            name_len: 0,
            parent: 0,
            kind: OBJ_KIND_DELETED,
            permanent: false,
            wait_references: 0,
            target: [0; OBJ_NAME_CAP],
            target_len: 0,
            payload: 0,
        }
    }

    pub(crate) fn is_live(&self) -> bool {
        self.kind != OBJ_KIND_DELETED
    }
    pub(crate) fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
    pub(crate) fn target(&self) -> &[u8] {
        &self.target[..self.target_len as usize]
    }

    /// Delete the object in place. The slot stays occupied, so its index is not handed out
    /// again; [`ObjectNamespace::retire`] is the form that can free it.
    pub(crate) fn unlink(&mut self) {
        self.name = [0; OBJ_NAME_CAP];
        self.name_len = 0;
        self.parent = OBJ_PARENT_ANONYMOUS;
        self.kind = OBJ_KIND_DELETED;
        self.permanent = false;
        self.wait_references = 0;
        self.target = [0; OBJ_NAME_CAP];
        self.target_len = 0;
        self.payload = 0;
    }
}

/// Freed slots held back from reuse. The table's length is bounded by its peak live entries
/// plus this many slots.
const SLOT_REUSE_DELAY: usize = 64;

/// What the periodic census reports about the table.
#[derive(Clone, Copy)]
pub(crate) struct ObjectNamespaceCensus {
    /// Table length: every index ever handed out.
    pub(crate) len: usize,
    pub(crate) live: usize,
    /// Retired slots waiting to be reused.
    pub(crate) free: usize,
}

/// The namespace entries plus the policy that hands out their indices. Entries are read and
/// updated in place through the slice view; only the table adds or frees one. Every slot the
/// ledger knows has an entry, and a free slot's entry is deleted.
pub(crate) struct ObjectNamespace {
    entries: Vec<ObjEntry>,
    slots: SlotLedger,
    /// The most recent allocation, until it is retired.
    newest: Option<usize>,
    growth_traces: u64,
}

impl Deref for ObjectNamespace {
    type Target = [ObjEntry];

    fn deref(&self) -> &[ObjEntry] {
        &self.entries
    }
}

impl DerefMut for ObjectNamespace {
    fn deref_mut(&mut self) -> &mut [ObjEntry] {
        &mut self.entries
    }
}

impl ObjectNamespace {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        let mut slots = SlotLedger::with_reuse_delay(SLOT_REUSE_DELAY);
        slots
            .reserve(capacity)
            .expect("initial object namespace slot ledger");
        Self {
            entries: Vec::with_capacity(capacity),
            slots,
            newest: None,
            growth_traces: 0,
        }
    }

    /// Make the next `additional` insertions infallible.
    pub(crate) fn try_reserve(&mut self, additional: usize) -> Result<(), ()> {
        let appends = self.slots.appends_needed(additional);
        if appends == 0 {
            return Ok(());
        }
        // The table outlives any transient scope its caller is in.
        let _durable = allocator::enter_durable();
        let old_capacity = self.entries.capacity();
        self.entries.try_reserve(appends).map_err(|_| ())?;
        self.trace_growth(old_capacity);
        self.slots.reserve(additional).map_err(|_| ())
    }

    fn trace_growth(&mut self, old_capacity: usize) {
        let new_capacity = self.entries.capacity();
        if new_capacity <= old_capacity {
            return;
        }
        self.growth_traces += 1;
        if self.growth_traces <= 8 {
            print_str(b"[obj-ns] grew capacity ");
            print_u64(old_capacity as u64);
            print_str(b" -> ");
            print_u64(new_capacity as u64);
            print_str(b" len=");
            print_u64(self.entries.len() as u64);
            print_str(b"\n");
        }
    }

    /// Hand out a slot holding a deleted entry with a fresh identity: a retired slot if one is
    /// free, otherwise a new index at the end of the table.
    fn allocate_vacant(&mut self) -> Option<usize> {
        if self.slots.appends_needed(1) != 0 {
            let _durable = allocator::enter_durable();
            if self.entries.len() == self.entries.capacity() {
                let old_capacity = self.entries.capacity();
                self.entries.try_reserve(64).ok()?;
                self.trace_growth(old_capacity);
            }
            self.slots.reserve(1).ok()?;
        }
        let slot = self.slots.allocate().ok()?;
        let entry = ObjEntry::vacant(slot.generation());
        if slot.index() == self.entries.len() {
            self.entries.push(entry);
        } else {
            self.entries[slot.index()] = entry;
        }
        self.newest = Some(slot.index());
        Some(slot.index())
    }

    pub(crate) fn push_kind(
        &mut self,
        name: &[u8],
        parent: usize,
        kind: u8,
        target: &[u8],
        permanent: bool,
    ) -> Option<usize> {
        let index = self.allocate_vacant()?;
        let entry = &mut self.entries[index];
        entry.parent = parent;
        entry.kind = kind;
        entry.permanent = permanent;
        let n = name.len().min(OBJ_NAME_CAP);
        entry.name[..n].copy_from_slice(&name[..n]);
        entry.name_len = n as u8;
        if kind == OBJ_KIND_SYMBOLIC_LINK {
            let n = target.len().min(OBJ_NAME_CAP);
            entry.target[..n].copy_from_slice(&target[..n]);
            entry.target_len = n as u8;
        }
        Some(index)
    }

    pub(crate) fn push_dir(&mut self, name: &[u8], parent: usize, permanent: bool) -> Option<usize> {
        self.push_kind(name, parent, OBJ_KIND_DIRECTORY, &[], permanent)
    }

    pub(crate) fn push_symlink(
        &mut self,
        name: &[u8],
        parent: usize,
        target: &[u8],
        permanent: bool,
    ) -> Option<usize> {
        self.push_kind(name, parent, OBJ_KIND_SYMBOLIC_LINK, target, permanent)
    }

    /// Delete the live object at `index` and decide whether its slot may be reused.
    ///
    /// `outstanding_references` counts whatever outside the table still names the index:
    /// process handles, wait records, dispatcher state, the Event registry binding. Only a
    /// retirement that reports none queues the slot for reuse; otherwise the entry is deleted
    /// in place and keeps its slot, exactly as [`ObjEntry::unlink`] does. Returns whether a
    /// live entry was deleted.
    pub(crate) fn retire(&mut self, index: usize, outstanding_references: usize) -> bool {
        let Some(entry) = self.entries.get_mut(index).filter(|entry| entry.is_live()) else {
            return false;
        };
        entry.unlink();
        if self.newest == Some(index) {
            self.newest = None;
        }
        if let Some(slot) = self.slots.current(index) {
            // A refusal leaves the slot occupied by the deleted entry.
            let _ = self.slots.release(slot, outstanding_references);
        }
        true
    }

    /// Whether `index` is the table's most recent allocation and still live. A creator that
    /// fails before publishing its object rolls back only such an entry: nothing allocated
    /// since can name it as a parent.
    pub(crate) fn is_newest(&self, index: usize) -> bool {
        self.newest == Some(index) && self.entries.get(index).is_some_and(ObjEntry::is_live)
    }

    pub(crate) fn census(&self) -> ObjectNamespaceCensus {
        ObjectNamespaceCensus {
            len: self.entries.len(),
            live: self.entries.iter().filter(|entry| entry.is_live()).count(),
            free: self.slots.census().free,
        }
    }
}
