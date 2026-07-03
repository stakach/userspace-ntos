//! # `nt-object-manager` — the NT Object Manager core
//!
//! Library-mode object model for the userspace-ntos personality: a
//! generation-protected object [`store`](ObjectStore), a [`TypeRegistry`], and
//! the reference/dereference lifecycle. Handle tables, the named namespace,
//! symbolic links, and access checks are layered on in later milestones.
//!
//! `no_std` + `alloc`, single-threaded (spec §15): the manager is used through
//! `&mut self`, and lifetime is `Rc`-based — see [`ObjectStore`] and the compat
//! notes. There is no `unsafe` in this crate.

#![no_std]

extern crate alloc;

mod store;
mod types;

pub use store::{ObjectRef, ObjectStore};
pub use types::{
    ComponentId, DeleteFn, DirectoryBody, EventBody, ObjectBody, ObjectType, ObjectTypeDef,
    OpaqueBody, OpaqueFlags, SymbolicLinkBody, TypeRegistry,
};

use nt_status::NtStatus;
use nt_types::{ObjectId, ObjectTypeId};

/// The library-mode Object Manager (spec §11). Owns the object store and the
/// type registry; grows handle tables + namespace in later milestones.
#[derive(Default)]
pub struct ObjectManager {
    store: ObjectStore,
    types: TypeRegistry,
}

impl ObjectManager {
    /// A fresh Object Manager with no types and an empty store.
    pub fn new() -> Self {
        Self {
            store: ObjectStore::new(),
            types: TypeRegistry::new(),
        }
    }

    /// Register an object type. `STATUS_OBJECT_NAME_COLLISION` on a duplicate name.
    pub fn register_type(&mut self, def: ObjectTypeDef) -> Result<ObjectTypeId, NtStatus> {
        self.types.register(def)
    }

    /// Look up a registered type.
    pub fn object_type(&self, ty: ObjectTypeId) -> Option<&ObjectType> {
        self.types.get(ty)
    }

    /// Create an unnamed object of type `ty`, returning its initial reference
    /// (`pointer_count == 1`). Named creation, handles, and access checks arrive
    /// in later milestones. `STATUS_INVALID_PARAMETER` if the type is unknown.
    pub fn create_object(
        &mut self,
        ty: ObjectTypeId,
        body: ObjectBody,
    ) -> Result<ObjectRef, NtStatus> {
        let type_def = self.types.get(ty).ok_or(NtStatus::INVALID_PARAMETER)?;
        let delete_fn = type_def.delete_fn();
        Ok(self.store.allocate(ty, delete_fn, body))
    }

    /// Take a new counted reference to an object by id. A stale or unknown id
    /// yields `STATUS_INVALID_HANDLE`. Dropping the returned [`ObjectRef`]
    /// dereferences the object.
    pub fn reference_by_id(&self, id: ObjectId) -> Result<ObjectRef, NtStatus> {
        self.store.resolve(id)
    }

    /// Number of objects currently alive (debug / tests).
    pub fn live_object_count(&self) -> usize {
        self.store.live_count()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use nt_types::{AccessMask, GenericMapping, UnicodeString};
    use proptest::prelude::*;

    fn type_def(delete: Option<DeleteFn>) -> ObjectTypeDef {
        ObjectTypeDef {
            name: "Test",
            valid_access: AccessMask::GENERIC_ALL,
            generic_mapping: GenericMapping::default(),
            delete,
        }
    }

    fn opaque() -> ObjectBody {
        ObjectBody::Opaque(OpaqueBody::default())
    }

    #[test]
    fn create_returns_initial_reference() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(None)).unwrap();
        let r = om.create_object(ty, opaque()).unwrap();
        assert_eq!(r.pointer_count(), 1);
        assert_eq!(r.type_id(), ty);
        assert!(!r.id().is_null());
        assert_eq!(om.live_object_count(), 1);
    }

    #[test]
    fn unknown_type_rejected() {
        let mut om = ObjectManager::new();
        assert_eq!(
            om.create_object(ObjectTypeId(7), opaque()).unwrap_err(),
            NtStatus::INVALID_PARAMETER
        );
    }

    #[test]
    fn duplicate_type_name_collides() {
        let mut om = ObjectManager::new();
        om.register_type(type_def(None)).unwrap();
        assert_eq!(
            om.register_type(type_def(None)).unwrap_err(),
            NtStatus::OBJECT_NAME_COLLISION
        );
    }

    #[test]
    fn reference_increments_and_drop_decrements() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(None)).unwrap();
        let r = om.create_object(ty, opaque()).unwrap();
        let id = r.id();
        assert_eq!(r.pointer_count(), 1);
        let r2 = om.reference_by_id(id).unwrap();
        assert_eq!(r.pointer_count(), 2);
        assert_eq!(r2.id(), id);
        drop(r2);
        assert_eq!(r.pointer_count(), 1);
    }

    #[test]
    fn unknown_id_rejected() {
        let om = ObjectManager::new();
        assert_eq!(
            om.reference_by_id(ObjectId(0xdead_beef)).unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            om.reference_by_id(ObjectId::NULL).unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
    }

    #[test]
    fn delete_runs_once_and_id_goes_stale() {
        static DELETED: AtomicUsize = AtomicUsize::new(0);
        fn del(_body: &mut ObjectBody, _id: ObjectId) {
            DELETED.fetch_add(1, Ordering::Relaxed);
        }
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(Some(del))).unwrap();
        let r = om.create_object(ty, opaque()).unwrap();
        let id = r.id();

        let r2 = om.reference_by_id(id).unwrap();
        drop(r2);
        assert_eq!(DELETED.load(Ordering::Relaxed), 0); // still referenced
        assert_eq!(om.live_object_count(), 1);

        drop(r); // final dereference
        assert_eq!(DELETED.load(Ordering::Relaxed), 1); // deleted exactly once
        assert_eq!(om.live_object_count(), 0);
        assert_eq!(
            om.reference_by_id(id).unwrap_err(),
            NtStatus::INVALID_HANDLE // stale id no longer resolves
        );
    }

    #[test]
    fn stale_id_after_slot_reuse() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(None)).unwrap();
        let a = om.create_object(ty, opaque()).unwrap();
        let a_id = a.id();
        assert_eq!(a_id.slot(), 0);
        drop(a); // frees slot 0

        let b = om.create_object(ty, opaque()).unwrap();
        let b_id = b.id();
        assert_eq!(b_id.slot(), 0); // reused slot 0
        assert_ne!(a_id.generation(), b_id.generation()); // generation bumped

        assert_eq!(
            om.reference_by_id(a_id).unwrap_err(),
            NtStatus::INVALID_HANDLE // stale id -> new occupant not returned
        );
        assert!(om.reference_by_id(b_id).is_ok());
    }

    #[test]
    fn header_fields_and_body() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(None)).unwrap();
        let r = om
            .create_object(
                ty,
                ObjectBody::Event(EventBody {
                    signaled: true,
                    manual_reset: false,
                }),
            )
            .unwrap();

        // handle count
        assert_eq!(r.handle_count(), 0);
        assert_eq!(r.inc_handle_count(), 1);
        assert_eq!(r.inc_handle_count(), 2);
        assert_eq!(r.dec_handle_count(), 1);

        // flags
        assert!(!r.is_permanent());
        r.set_permanent(true);
        assert!(r.is_permanent());
        assert!(!r.is_delete_pending());
        r.set_delete_pending(true);
        assert!(r.is_delete_pending());

        // name + parent
        assert!(r.name().is_none());
        r.set_name(Some(UnicodeString::from_str("Foo")));
        assert_eq!(r.name().unwrap(), UnicodeString::from_str("Foo"));
        assert!(r.parent().is_none());
        r.set_parent(Some(r.id()));
        assert_eq!(r.parent(), Some(r.id()));

        // body read + mutate
        r.with_body(|b| assert!(matches!(b, ObjectBody::Event(e) if e.signaled)));
        r.with_body_mut(|b| {
            if let ObjectBody::Event(e) = b {
                e.signaled = false;
            }
        });
        r.with_body(|b| assert!(matches!(b, ObjectBody::Event(e) if !e.signaled)));
    }

    proptest! {
        /// For any sequence of reference/dereference operations, the object is
        /// alive iff at least one reference is held, and `pointer_count` equals
        /// the number of live references. No object is ever freed while
        /// referenced; no stale id resolves.
        #[test]
        fn pointer_count_tracks_live_refs(ops in prop::collection::vec(any::<bool>(), 0..64)) {
            let mut om = ObjectManager::new();
            let ty = om.register_type(type_def(None)).unwrap();
            let first = om.create_object(ty, opaque()).unwrap();
            let id = first.id();
            let mut refs: Vec<ObjectRef> = Vec::new();
            refs.push(first);

            for take_ref in ops {
                if take_ref {
                    if let Ok(r) = om.reference_by_id(id) {
                        refs.push(r);
                    }
                } else {
                    refs.pop();
                }
            }

            if refs.is_empty() {
                prop_assert!(om.reference_by_id(id).is_err());
                prop_assert_eq!(om.live_object_count(), 0);
            } else {
                prop_assert_eq!(refs[0].pointer_count(), refs.len());
                prop_assert!(om.reference_by_id(id).is_ok());
                prop_assert_eq!(om.live_object_count(), 1);
            }
        }
    }
}
