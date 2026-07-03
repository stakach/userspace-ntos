//! The object store: a generation-protected slot map of `Rc`-owned objects.
//!
//! Lifetime is realised through Rust ownership rather than manual counting
//! (compat note in `docs/compat-notes/object-manager.md`): `pointer_count` is
//! the `Rc` strong count. The store holds only a [`Weak`] per slot, so an object
//! lives exactly as long as some [`ObjectRef`] (or, later, an open handle /
//! directory entry / permanent flag) keeps a strong `Rc`. When the last strong
//! reference drops, [`ObjectInner`]'s `Drop` runs the type's delete callback
//! exactly once, and the slot's `Weak` goes dead. Slots are reclaimed lazily on
//! the next allocation, bumping the generation so any stale [`ObjectId`] into the
//! old occupant fails to resolve.

use alloc::rc::{Rc, Weak};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

use nt_status::NtStatus;
use nt_types::{Generation, ObjectId, ObjectTypeId, UnicodeString};

use crate::types::{DeleteFn, ObjectBody};

/// The heap allocation backing one object. Never exposed across a component
/// boundary (spec §8.2). `pointer_count` is intentionally *not* a field — it is
/// `Rc::strong_count` of the owning [`Rc`].
pub(crate) struct ObjectInner {
    id: ObjectId,
    ty: ObjectTypeId,
    name: RefCell<Option<UnicodeString>>,
    // Read back only via `parent()` (used by the namespace in M4).
    #[allow(dead_code)]
    parent: Cell<Option<ObjectId>>,
    handle_count: Cell<usize>,
    delete_pending: Cell<bool>,
    permanent: Cell<bool>,
    body: RefCell<ObjectBody>,
    delete_fn: Option<DeleteFn>,
}

impl Drop for ObjectInner {
    fn drop(&mut self) {
        // Final dereference → Deleted: run the delete callback exactly once
        // (Drop runs once). `get_mut` is borrow-check-free here since we hold
        // `&mut self`; the body is dropped immediately after.
        if let Some(f) = self.delete_fn {
            f(self.body.get_mut(), self.id);
        }
    }
}

/// A live, counted reference to an object. RAII: cloning adds a reference
/// (`pointer_count += 1`), dropping removes one; the object is deleted when the
/// last reference drops. Never holds or exposes a raw pointer.
#[derive(Clone)]
pub struct ObjectRef {
    inner: Rc<ObjectInner>,
}

impl ObjectRef {
    /// The object's canonical id.
    pub fn id(&self) -> ObjectId {
        self.inner.id
    }

    /// The object's type.
    pub fn type_id(&self) -> ObjectTypeId {
        self.inner.ty
    }

    /// Current reference count (`Rc` strong count).
    pub fn pointer_count(&self) -> usize {
        Rc::strong_count(&self.inner)
    }

    /// Current handle count.
    pub fn handle_count(&self) -> usize {
        self.inner.handle_count.get()
    }

    /// Whether the object is marked permanent.
    pub fn is_permanent(&self) -> bool {
        self.inner.permanent.get()
    }

    /// Whether deletion has been requested.
    pub fn is_delete_pending(&self) -> bool {
        self.inner.delete_pending.get()
    }

    /// The object's name, if named.
    pub fn name(&self) -> Option<UnicodeString> {
        self.inner.name.borrow().clone()
    }

    /// Read the body.
    pub fn with_body<R>(&self, f: impl FnOnce(&ObjectBody) -> R) -> R {
        f(&self.inner.body.borrow())
    }

    /// Mutate the body.
    pub fn with_body_mut<R>(&self, f: impl FnOnce(&mut ObjectBody) -> R) -> R {
        f(&mut self.inner.body.borrow_mut())
    }
}

// Internal count / field adjustments used by the handle tables (M3) and the
// namespace (M4). Allowed dead until those milestones wire them up.
#[allow(dead_code)]
impl ObjectRef {
    pub(crate) fn set_name(&self, name: Option<UnicodeString>) {
        *self.inner.name.borrow_mut() = name;
    }
    pub(crate) fn set_parent(&self, parent: Option<ObjectId>) {
        self.inner.parent.set(parent);
    }
    pub(crate) fn parent(&self) -> Option<ObjectId> {
        self.inner.parent.get()
    }
    pub(crate) fn set_permanent(&self, permanent: bool) {
        self.inner.permanent.set(permanent);
    }
    pub(crate) fn set_delete_pending(&self, pending: bool) {
        self.inner.delete_pending.set(pending);
    }
    pub(crate) fn inc_handle_count(&self) -> usize {
        let n = self.inner.handle_count.get() + 1;
        self.inner.handle_count.set(n);
        n
    }
    pub(crate) fn dec_handle_count(&self) -> usize {
        let n = self.inner.handle_count.get().saturating_sub(1);
        self.inner.handle_count.set(n);
        n
    }
}

impl core::fmt::Debug for ObjectRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectRef")
            .field("id", &self.id())
            .field("type", &self.type_id())
            .field("pointer_count", &self.pointer_count())
            .field("handle_count", &self.handle_count())
            .finish()
    }
}

struct Slot {
    generation: Generation,
    weak: Weak<ObjectInner>,
}

/// A generation-protected arena of objects, indexed by [`ObjectId`] slot.
#[derive(Default)]
pub struct ObjectStore {
    slots: Vec<Slot>,
}

impl ObjectStore {
    pub fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Allocate an object, returning the initial [`ObjectRef`] (`pointer_count`
    /// = 1). Reuses a free (dead-`Weak`) slot when available, bumping its
    /// generation so stale ids to the previous occupant no longer resolve.
    pub fn allocate(
        &mut self,
        ty: ObjectTypeId,
        delete_fn: Option<DeleteFn>,
        body: ObjectBody,
    ) -> ObjectRef {
        let idx = self.find_free_slot();
        let generation = if idx < self.slots.len() {
            self.slots[idx].generation.next()
        } else {
            Generation(1) // generations start at 1 so no live id is ever 0 (null)
        };
        let id = ObjectId::new(generation, idx as u64);
        let inner = Rc::new(ObjectInner {
            id,
            ty,
            name: RefCell::new(None),
            parent: Cell::new(None),
            handle_count: Cell::new(0),
            delete_pending: Cell::new(false),
            permanent: Cell::new(false),
            body: RefCell::new(body),
            delete_fn,
        });
        let slot = Slot {
            generation,
            weak: Rc::downgrade(&inner),
        };
        if idx < self.slots.len() {
            self.slots[idx] = slot;
        } else {
            self.slots.push(slot);
        }
        ObjectRef { inner }
    }

    /// Resolve an id to a new counted reference. A stale generation, an
    /// out-of-range slot, or a deleted (dead-`Weak`) object all yield
    /// `STATUS_INVALID_HANDLE`.
    pub fn resolve(&self, id: ObjectId) -> Result<ObjectRef, NtStatus> {
        let idx = id.slot() as usize;
        let slot = self.slots.get(idx).ok_or(NtStatus::INVALID_HANDLE)?;
        if slot.generation != id.generation() {
            return Err(NtStatus::INVALID_HANDLE); // stale generation (slot reused)
        }
        slot.weak
            .upgrade()
            .map(|inner| ObjectRef { inner })
            .ok_or(NtStatus::INVALID_HANDLE) // deleted, slot not yet reused
    }

    /// Number of objects currently alive.
    pub fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.weak.strong_count() > 0)
            .count()
    }

    /// First slot whose object is gone (reusable), else one past the end.
    fn find_free_slot(&self) -> usize {
        self.slots
            .iter()
            .position(|s| s.weak.strong_count() == 0)
            .unwrap_or(self.slots.len())
    }
}
