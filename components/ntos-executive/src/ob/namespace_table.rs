//! The executive's compact object namespace table.
//!
//! An entry's index is the native identity of its object: handles, dispatcher state and wait
//! records name the object by index. The table is the only place an index is handed out, and
//! the only place a newly created entry is taken back before publication.

use crate::*;
use core::ops::{Deref, DerefMut};

/// One node in the executive's minimal object-manager namespace. Inline, `Copy`, no nested heap
/// allocation. NT object leaf names are allowed to be long enough for BaseNamedObjects mutexes
/// such as userenv's per-profile mutex; `target` is link-only data; `payload` carries backing object
/// identity for kinds whose state lives outside the namespace, such as LPC listen port handles and
/// I/O completion ports. `permanent` mirrors `OBJ_PERMANENT`; non-permanent named objects are
/// unlinked when their final body reference goes away.
#[derive(Clone, Copy)]
pub(crate) struct ObjEntry {
    /// Issued once per entry and never reused, unlike the entry's index.
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

    /// Delete the object in place. The slot keeps its index and is never handed out again.
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

/// The namespace entries plus the policy that hands out their indices. Entries are read and
/// updated in place through the slice view; only the table adds or removes one.
pub(crate) struct ObjectNamespace {
    entries: Vec<ObjEntry>,
    next_identity: u64,
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
        Self {
            entries: Vec::with_capacity(capacity),
            next_identity: 1,
            growth_traces: 0,
        }
    }

    /// Make the next `additional` insertions infallible.
    pub(crate) fn try_reserve(&mut self, additional: usize) -> Result<(), ()> {
        let old_capacity = self.entries.capacity();
        self.entries.try_reserve(additional).map_err(|_| ())?;
        self.trace_growth(old_capacity);
        Ok(())
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

    fn push_vacant(&mut self) -> Option<usize> {
        let identity = self.next_identity;
        let next_identity = identity.checked_add(1)?;
        if self.entries.len() == self.entries.capacity() {
            let old_capacity = self.entries.capacity();
            self.entries.try_reserve(64).ok()?;
            self.trace_growth(old_capacity);
        }
        self.next_identity = next_identity;
        let index = self.entries.len();
        self.entries.push(ObjEntry::vacant(identity));
        Some(index)
    }

    pub(crate) fn push_kind(
        &mut self,
        name: &[u8],
        parent: usize,
        kind: u8,
        target: &[u8],
        permanent: bool,
    ) -> Option<usize> {
        let index = self.push_vacant()?;
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

    /// Take back an entry the current operation created, before any reference to it was
    /// published. Returns whether the entry was removed; the caller then drops its backing.
    pub(crate) fn discard_unpublished(&mut self, index: usize) -> bool {
        if index + 1 != self.entries.len() {
            return false;
        }
        self.entries.pop();
        true
    }
}
