//! # `nt-wdf-object` — the WDF object model core
//!
//! The canonical KMDF/WDF object table (spec: NT KMDF/WDF Runtime, Milestone 1, §7-§8).
//! Every WDF handle (`WDFDRIVER`, `WDFDEVICE`, `WDFQUEUE`, `WDFREQUEST`, `WDFMEMORY`, …)
//! is a **generation-validated** encoded value over a slot table, so a stale or wrong-type
//! handle is rejected rather than dereferenced. Objects form a parent/child tree
//! (a driver owns its devices; a device owns its queues); deleting a parent deletes its
//! children depth-first, running each object's cleanup then destroy callback exactly once.
//!
//! Callbacks are driver function pointers held as opaque integers — the table never calls
//! into the driver itself. `delete` / `dereference` return the ordered list of callbacks the
//! runtime must invoke **after** the table borrow is released (the re-entrancy discipline
//! the Driver Host relies on). `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// A WDF object type tag (spec §7.1). Encoded into the high byte of a handle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WdfObjectType {
    Driver = 1,
    Device = 2,
    Queue = 3,
    Request = 4,
    Memory = 5,
    SpinLock = 6,
    WaitLock = 7,
}

impl WdfObjectType {
    fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::Driver,
            2 => Self::Device,
            3 => Self::Queue,
            4 => Self::Request,
            5 => Self::Memory,
            6 => Self::SpinLock,
            7 => Self::WaitLock,
            _ => return None,
        })
    }
}

/// A WDF handle: `[type:8 | generation:24 | slot:32]`, never zero for a live object
/// (a null `WDFOBJECT` is always invalid). Opaque to the driver (spec §8.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct WdfHandle(pub u64);

impl WdfHandle {
    pub const NULL: WdfHandle = WdfHandle(0);

    fn encode(object_type: WdfObjectType, generation: u32, slot: u32) -> Self {
        WdfHandle(
            ((object_type as u64) << 56) | ((generation as u64 & 0xFF_FFFF) << 32) | slot as u64,
        )
    }
    fn slot(self) -> u32 {
        self.0 as u32
    }
    fn generation(self) -> u32 {
        ((self.0 >> 32) & 0xFF_FFFF) as u32
    }
    fn type_tag(self) -> u8 {
        (self.0 >> 56) as u8
    }
    pub fn is_null(self) -> bool {
        self.0 == 0
    }
    pub fn object_type(self) -> Option<WdfObjectType> {
        WdfObjectType::from_tag(self.type_tag())
    }
}

/// Why a handle/object operation was rejected (spec §8.2, §24.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WdfObjectError {
    /// Handle was `NULL` where an object was required.
    NullHandle,
    /// No live object for this handle's slot, or the generation is stale.
    StaleHandle,
    /// The object exists but is a different type than expected.
    WrongType,
    /// The object has already been marked deleted.
    Deleted,
    /// A context of a different type is already attached (spec §18.2).
    ContextAlreadyPresent,
}

/// A callback the runtime must invoke after the table borrow is released — a
/// `(callback_fn, context_ptr, handle)` triple (spec §7.3 ordering).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PendingCallback {
    pub callback: u64,
    pub context: u64,
    pub handle: WdfHandle,
}

struct ObjectRecord {
    live: bool,
    generation: u32,
    object_type: WdfObjectType,
    parent: Option<u32>,
    children: Vec<u32>,
    ref_count: u32,
    deleted: bool,
    cleanup_callback: u64,
    destroy_callback: u64,
    context_ptr: u64,
    context_type: u64,
}

/// The canonical WDF object table.
#[derive(Default)]
pub struct WdfObjectTable {
    slots: Vec<ObjectRecord>,
    free: Vec<u32>,
    next_generation: u32,
}

impl WdfObjectTable {
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            next_generation: 1,
        }
    }

    /// Create an object of `object_type`, optionally parented to `parent` (which must be a
    /// live handle). The object starts with one implicit framework reference (spec §7.4).
    pub fn create(
        &mut self,
        object_type: WdfObjectType,
        parent: Option<WdfHandle>,
    ) -> Result<WdfHandle, WdfObjectError> {
        let parent_slot = match parent {
            Some(p) if !p.is_null() => Some(self.resolve_any(p)?),
            _ => None,
        };
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1) & 0xFF_FFFF;
        if self.next_generation == 0 {
            self.next_generation = 1;
        }
        let record = ObjectRecord {
            live: true,
            generation,
            object_type,
            parent: parent_slot,
            children: Vec::new(),
            ref_count: 1,
            deleted: false,
            cleanup_callback: 0,
            destroy_callback: 0,
            context_ptr: 0,
            context_type: 0,
        };
        let slot = if let Some(s) = self.free.pop() {
            self.slots[s as usize] = record;
            s
        } else {
            self.slots.push(record);
            (self.slots.len() - 1) as u32
        };
        if let Some(ps) = parent_slot {
            self.slots[ps as usize].children.push(slot);
        }
        Ok(WdfHandle::encode(object_type, generation, slot))
    }

    /// Locate a handle's live slot, validating slot/generation/type but **not** the
    /// deleted flag — the raw lookup `dereference`/`delete` need to touch a deleted object.
    fn locate(&self, h: WdfHandle) -> Result<u32, WdfObjectError> {
        if h.is_null() {
            return Err(WdfObjectError::NullHandle);
        }
        let slot = h.slot();
        let rec = self
            .slots
            .get(slot as usize)
            .filter(|r| r.live)
            .ok_or(WdfObjectError::StaleHandle)?;
        if rec.generation != h.generation() || rec.object_type as u8 != h.type_tag() {
            return Err(WdfObjectError::StaleHandle);
        }
        Ok(slot)
    }

    /// Resolve a handle of any type to its slot, additionally rejecting a deleted object
    /// (spec §8.2) — the precondition for every driver-facing WDF API.
    fn resolve_any(&self, h: WdfHandle) -> Result<u32, WdfObjectError> {
        let slot = self.locate(h)?;
        if self.slots[slot as usize].deleted {
            return Err(WdfObjectError::Deleted);
        }
        Ok(slot)
    }

    /// Resolve + type-check a handle (every typed WDF API's precondition, spec §8.2).
    fn resolve_typed(&self, h: WdfHandle, expected: WdfObjectType) -> Result<u32, WdfObjectError> {
        if h.is_null() {
            return Err(WdfObjectError::NullHandle);
        }
        if h.type_tag() != expected as u8 {
            return Err(WdfObjectError::WrongType);
        }
        self.resolve_any(h)
    }

    /// Validate a handle is a live object of `expected` type.
    pub fn validate(&self, h: WdfHandle, expected: WdfObjectType) -> Result<(), WdfObjectError> {
        self.resolve_typed(h, expected).map(|_| ())
    }

    pub fn object_type(&self, h: WdfHandle) -> Result<WdfObjectType, WdfObjectError> {
        let slot = self.resolve_any(h)?;
        Ok(self.slots[slot as usize].object_type)
    }

    pub fn parent(&self, h: WdfHandle) -> Result<Option<WdfHandle>, WdfObjectError> {
        let slot = self.resolve_any(h)?;
        Ok(self.slots[slot as usize]
            .parent
            .map(|ps| self.handle_for(ps)))
    }

    fn handle_for(&self, slot: u32) -> WdfHandle {
        let r = &self.slots[slot as usize];
        WdfHandle::encode(r.object_type, r.generation, slot)
    }

    /// `WdfObjectReference` — add a driver reference (spec §7.4).
    pub fn reference(&mut self, h: WdfHandle) -> Result<(), WdfObjectError> {
        let slot = self.resolve_any(h)?;
        self.slots[slot as usize].ref_count += 1;
        Ok(())
    }

    /// Set the cleanup/destroy callbacks (from `WDF_OBJECT_ATTRIBUTES`, spec §18.1).
    pub fn set_callbacks(
        &mut self,
        h: WdfHandle,
        cleanup: u64,
        destroy: u64,
    ) -> Result<(), WdfObjectError> {
        let slot = self.resolve_any(h)?;
        let r = &mut self.slots[slot as usize];
        r.cleanup_callback = cleanup;
        r.destroy_callback = destroy;
        Ok(())
    }

    /// Attach a driver context pointer of a given type-info tag (spec §18.2). Fails if a
    /// context is already present (WDF allows only one per type-info in v0.1).
    pub fn set_context(
        &mut self,
        h: WdfHandle,
        context_ptr: u64,
        context_type: u64,
    ) -> Result<(), WdfObjectError> {
        let slot = self.resolve_any(h)?;
        let r = &mut self.slots[slot as usize];
        if r.context_ptr != 0 {
            return Err(WdfObjectError::ContextAlreadyPresent);
        }
        r.context_ptr = context_ptr;
        r.context_type = context_type;
        Ok(())
    }

    /// `WdfObjectGetTypedContext` — retrieve the context pointer (0 if none), validating
    /// the type-info tag matches (spec §18.3).
    pub fn get_context(&self, h: WdfHandle, context_type: u64) -> Result<u64, WdfObjectError> {
        let slot = self.resolve_any(h)?;
        let r = &self.slots[slot as usize];
        if r.context_ptr == 0 || r.context_type != context_type {
            return Ok(0);
        }
        Ok(r.context_ptr)
    }

    /// `WdfObjectDelete` — mark the object (and its children, depth-first) deleted, and
    /// return the cleanup+destroy callbacks to run, in spec §7.3 order (each child fully
    /// before its parent; cleanup before destroy). The implicit framework reference is
    /// released, so an object with no outstanding driver references is freed here.
    pub fn delete(&mut self, h: WdfHandle) -> Result<Vec<PendingCallback>, WdfObjectError> {
        let slot = self.resolve_any(h)?;
        let mut pending = Vec::new();
        self.delete_slot(slot, &mut pending);
        Ok(pending)
    }

    fn delete_slot(&mut self, slot: u32, pending: &mut Vec<PendingCallback>) {
        if self.slots[slot as usize].deleted {
            return;
        }
        self.slots[slot as usize].deleted = true;
        // Children depth-first, before the parent.
        let children = core::mem::take(&mut self.slots[slot as usize].children);
        for c in children {
            self.delete_slot(c, pending);
        }
        let handle = self.handle_for(slot);
        let (cleanup, destroy, context) = {
            let r = &self.slots[slot as usize];
            (r.cleanup_callback, r.destroy_callback, r.context_ptr)
        };
        // Cleanup runs first (object still valid), destroy last (memory going away).
        if cleanup != 0 {
            pending.push(PendingCallback {
                callback: cleanup,
                context,
                handle,
            });
        }
        // Release the implicit reference; free when it reaches zero.
        let r = &mut self.slots[slot as usize];
        r.ref_count = r.ref_count.saturating_sub(1);
        if r.ref_count == 0 {
            if destroy != 0 {
                pending.push(PendingCallback {
                    callback: destroy,
                    context,
                    handle,
                });
            }
            self.free_slot(slot);
        }
    }

    /// `WdfObjectDereference` — release a driver reference; frees + returns the destroy
    /// callback if this was the last reference on a deleted object (spec §7.4).
    pub fn dereference(&mut self, h: WdfHandle) -> Result<Option<PendingCallback>, WdfObjectError> {
        let slot = self.locate(h)?;
        let r = &mut self.slots[slot as usize];
        r.ref_count = r.ref_count.saturating_sub(1);
        if r.ref_count == 0 && r.deleted {
            let out = if r.destroy_callback != 0 {
                Some(PendingCallback {
                    callback: r.destroy_callback,
                    context: r.context_ptr,
                    handle: h,
                })
            } else {
                None
            };
            self.free_slot(slot);
            return Ok(out);
        }
        Ok(None)
    }

    fn free_slot(&mut self, slot: u32) {
        let r = &mut self.slots[slot as usize];
        r.live = false;
        r.children = Vec::new();
        self.free.push(slot);
    }

    /// Count of live (non-freed) objects — for diagnostics/tests.
    pub fn live_count(&self) -> usize {
        self.slots.iter().filter(|r| r.live).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_validate_wrong_type_and_stale() {
        let mut t = WdfObjectTable::new();
        let d = t.create(WdfObjectType::Driver, None).unwrap();
        assert!(t.validate(d, WdfObjectType::Driver).is_ok());
        assert_eq!(
            t.validate(d, WdfObjectType::Device),
            Err(WdfObjectError::WrongType)
        );
        assert_eq!(
            t.validate(WdfHandle::NULL, WdfObjectType::Driver),
            Err(WdfObjectError::NullHandle)
        );
        // Delete then reuse the slot → old handle is stale by generation.
        t.delete(d).unwrap();
        let d2 = t.create(WdfObjectType::Driver, None).unwrap();
        assert_ne!(d.0, d2.0);
        assert_eq!(
            t.validate(d, WdfObjectType::Driver),
            Err(WdfObjectError::StaleHandle)
        );
    }

    #[test]
    fn parent_child_depth_first_delete() {
        let mut t = WdfObjectTable::new();
        let drv = t.create(WdfObjectType::Driver, None).unwrap();
        let dev = t.create(WdfObjectType::Device, Some(drv)).unwrap();
        let q1 = t.create(WdfObjectType::Queue, Some(dev)).unwrap();
        let q2 = t.create(WdfObjectType::Queue, Some(dev)).unwrap();
        assert_eq!(t.parent(q1).unwrap(), Some(dev));
        assert_eq!(t.live_count(), 4);
        // Deleting the driver deletes device + both queues.
        let pending = t.delete(drv).unwrap();
        assert_eq!(t.live_count(), 0);
        // All four gone; every handle now stale.
        for h in [drv, dev, q1, q2] {
            assert!(t.object_type(h).is_err());
        }
        assert!(pending.is_empty()); // no callbacks registered
    }

    #[test]
    fn cleanup_then_destroy_callback_order() {
        let mut t = WdfObjectTable::new();
        let dev = t.create(WdfObjectType::Device, None).unwrap();
        t.set_callbacks(dev, 0xC1EA_1234, 0xDE57_5678).unwrap();
        let pending = t.delete(dev).unwrap();
        // Cleanup first, then destroy (ref hit zero).
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].callback, 0xC1EA_1234);
        assert_eq!(pending[1].callback, 0xDE57_5678);
        assert_eq!(pending[0].handle, dev);
    }

    #[test]
    fn destroy_deferred_until_last_reference() {
        let mut t = WdfObjectTable::new();
        let m = t.create(WdfObjectType::Memory, None).unwrap();
        t.set_callbacks(m, 0, 0xD0_0000).unwrap();
        t.reference(m).unwrap(); // driver holds a ref
                                 // Delete marks deleted + drops the implicit ref, but destroy is deferred.
        let pending = t.delete(m).unwrap();
        assert!(pending.is_empty());
        // The object is deleted but still allocated (refcount 1).
        assert_eq!(
            t.validate(m, WdfObjectType::Memory),
            Err(WdfObjectError::Deleted)
        );
        // Final dereference frees it + yields the destroy callback.
        let out = t.dereference(m).unwrap().unwrap();
        assert_eq!(out.callback, 0xD0_0000);
    }

    #[test]
    fn context_storage() {
        let mut t = WdfObjectTable::new();
        let dev = t.create(WdfObjectType::Device, None).unwrap();
        assert_eq!(t.get_context(dev, 0xAAAA).unwrap(), 0); // none yet
        t.set_context(dev, 0x8000_0000, 0xAAAA).unwrap();
        assert_eq!(t.get_context(dev, 0xAAAA).unwrap(), 0x8000_0000);
        assert_eq!(t.get_context(dev, 0xBBBB).unwrap(), 0); // wrong type-info
        assert_eq!(
            t.set_context(dev, 0x9000_0000, 0xAAAA),
            Err(WdfObjectError::ContextAlreadyPresent)
        );
    }
}
