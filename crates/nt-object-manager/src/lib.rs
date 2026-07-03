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

mod access;
mod handles;
mod namespace;
mod store;
mod types;

pub use access::compute_granted;
pub use handles::{ClientKind, ClientRegistry, HandleTable};
pub use store::{ObjectRef, ObjectStore};
pub use types::{
    ComponentId, DeleteFn, DirectoryBody, EventBody, ObjectBody, ObjectType, ObjectTypeDef,
    OpaqueBody, OpaqueFlags, SymbolicLinkBody, TypeRegistry,
};

use nt_status::NtStatus;
use nt_types::{
    AccessMask, AccessMode, ClientId, HandleValue, ObjAttrFlags, ObjectId, ObjectTypeId,
};

/// The library-mode Object Manager (spec §11). Owns the object store and the
/// type registry; grows handle tables + namespace in later milestones.
#[derive(Default)]
pub struct ObjectManager {
    store: ObjectStore,
    types: TypeRegistry,
    clients: ClientRegistry,
    /// The root directory `\`, once `bootstrap_namespace` has run (holds the
    /// whole named tree alive).
    root: Option<ObjectRef>,
    /// The built-in Directory type id.
    directory_type: Option<ObjectTypeId>,
    /// The built-in SymbolicLink type id.
    symlink_type: Option<ObjectTypeId>,
}

impl ObjectManager {
    /// A fresh Object Manager with no types and an empty store.
    pub fn new() -> Self {
        Self {
            store: ObjectStore::new(),
            types: TypeRegistry::new(),
            clients: ClientRegistry::new(),
            root: None,
            directory_type: None,
            symlink_type: None,
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

    // --- Clients + handles (Milestone 3) -----------------------------------

    /// Register a connected client, returning its id.
    pub fn register_client(&mut self, kind: ClientKind, access_mode: AccessMode) -> ClientId {
        self.clients.register(kind, access_mode)
    }

    /// Close a client: close all its handles (dropping their references) and
    /// retire its id. Temporary named objects whose last handle was here lose
    /// their names; objects still referenced elsewhere survive.
    pub fn close_client(&mut self, client: ClientId) -> Result<(), NtStatus> {
        let closed = self.clients.close(client)?;
        for obj in &closed {
            self.on_handle_closed(obj);
        }
        Ok(())
    }

    /// Open a handle to `object` for `client` with `granted_access`. Increments
    /// the object's handle + pointer counts (the handle holds a strong reference).
    pub fn open_handle(
        &mut self,
        client: ClientId,
        object: &ObjectRef,
        granted_access: AccessMask,
        attributes: ObjAttrFlags,
    ) -> Result<HandleValue, NtStatus> {
        self.clients
            .open_handle(client, object.clone(), granted_access, attributes)
    }

    /// Reference an object by handle (spec §11.5). Enforces `expected_type`
    /// (`STATUS_OBJECT_TYPE_MISMATCH`) and that `desired_access` is within the
    /// handle's granted access (`STATUS_ACCESS_DENIED`). Returns a new counted
    /// reference. A stale/unknown handle yields `STATUS_INVALID_HANDLE`.
    pub fn reference_by_handle(
        &self,
        client: ClientId,
        handle: HandleValue,
        expected_type: Option<ObjectTypeId>,
        desired_access: AccessMask,
    ) -> Result<ObjectRef, NtStatus> {
        self.clients
            .reference_by_handle(client, handle, expected_type, desired_access)
    }

    /// Close a handle in `client`'s table (decrements handle + pointer counts).
    /// If this was the last handle on a temporary named object, its name is
    /// removed from the namespace.
    pub fn close_handle(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus> {
        let obj = self.clients.close_handle(client, handle)?;
        self.on_handle_closed(&obj);
        Ok(())
    }

    /// Number of open handles held by `client` (debug / tests).
    pub fn open_handle_count(&self, client: ClientId) -> Result<usize, NtStatus> {
        self.clients.open_handle_count(client)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use nt_types::{
        AccessMask, AccessMode, CaseSensitivity, ClientId, GenericMapping, HandleValue, NtPath,
        ObjAttrFlags, ObjectId, ObjectTypeId, UnicodeString,
    };
    use proptest::prelude::*;

    const CI: CaseSensitivity = CaseSensitivity::CaseInsensitive;

    fn path(s: &str) -> NtPath {
        NtPath::parse_str(s).unwrap()
    }

    fn uni(s: &str) -> UnicodeString {
        UnicodeString::from_str(s)
    }

    fn named_type_def(name: &'static str, delete: Option<DeleteFn>) -> ObjectTypeDef {
        ObjectTypeDef {
            name,
            valid_access: AccessMask::GENERIC_ALL,
            generic_mapping: GenericMapping::default(),
            delete,
        }
    }

    fn type_def(delete: Option<DeleteFn>) -> ObjectTypeDef {
        named_type_def("Test", delete)
    }

    fn test_client(om: &mut ObjectManager) -> ClientId {
        om.register_client(ClientKind::Test, AccessMode::UserMode)
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

    // --- Milestone 3: handles -----------------------------------------------

    #[test]
    fn open_handle_bumps_counts_and_close_decrements() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(None)).unwrap();
        let client = test_client(&mut om);
        let obj = om.create_object(ty, opaque()).unwrap();
        assert_eq!(obj.pointer_count(), 1);
        assert_eq!(obj.handle_count(), 0);

        let h = om
            .open_handle(client, &obj, AccessMask::GENERIC_ALL, ObjAttrFlags::empty())
            .unwrap();
        assert_eq!(obj.pointer_count(), 2); // creator ref + handle
        assert_eq!(obj.handle_count(), 1);
        assert_eq!(om.open_handle_count(client).unwrap(), 1);

        om.close_handle(client, h).unwrap();
        assert_eq!(obj.pointer_count(), 1);
        assert_eq!(obj.handle_count(), 0);
        assert_eq!(om.open_handle_count(client).unwrap(), 0);

        // closing again is a stale handle
        assert_eq!(
            om.close_handle(client, h).unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
    }

    #[test]
    fn reference_by_handle_roundtrip() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(None)).unwrap();
        let client = test_client(&mut om);
        let obj = om.create_object(ty, opaque()).unwrap();
        let id = obj.id();
        let h = om
            .open_handle(
                client,
                &obj,
                AccessMask::GENERIC_READ,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        let r = om
            .reference_by_handle(client, h, Some(ty), AccessMask::GENERIC_READ)
            .unwrap();
        assert_eq!(r.id(), id);
    }

    #[test]
    fn stale_handle_rejected_after_close_and_reuse() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(None)).unwrap();
        let client = test_client(&mut om);
        let obj = om.create_object(ty, opaque()).unwrap();

        let h1 = om
            .open_handle(client, &obj, AccessMask::GENERIC_ALL, ObjAttrFlags::empty())
            .unwrap();
        om.close_handle(client, h1).unwrap();
        assert_eq!(
            om.reference_by_handle(client, h1, None, AccessMask::empty())
                .unwrap_err(),
            NtStatus::INVALID_HANDLE
        );

        let h2 = om
            .open_handle(client, &obj, AccessMask::GENERIC_ALL, ObjAttrFlags::empty())
            .unwrap();
        assert_eq!(h2.slot(), h1.slot()); // reused slot
        assert_ne!(h2.generation(), h1.generation()); // generation bumped
        assert_eq!(
            om.reference_by_handle(client, h1, None, AccessMask::empty())
                .unwrap_err(),
            NtStatus::INVALID_HANDLE // old handle stays stale
        );
        assert!(om
            .reference_by_handle(client, h2, None, AccessMask::empty())
            .is_ok());
    }

    #[test]
    fn per_client_isolation() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(None)).unwrap();
        let a = test_client(&mut om);
        let b = test_client(&mut om);
        let obj = om.create_object(ty, opaque()).unwrap();
        let h = om
            .open_handle(a, &obj, AccessMask::GENERIC_ALL, ObjAttrFlags::empty())
            .unwrap();

        // B cannot use A's handle value.
        assert_eq!(
            om.reference_by_handle(b, h, None, AccessMask::empty())
                .unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(om.close_handle(b, h).unwrap_err(), NtStatus::INVALID_HANDLE);
        // A can.
        assert!(om
            .reference_by_handle(a, h, None, AccessMask::empty())
            .is_ok());
    }

    #[test]
    fn type_mismatch_and_access_denied() {
        let mut om = ObjectManager::new();
        let ev = om.register_type(named_type_def("Event", None)).unwrap();
        let dir = om.register_type(named_type_def("Directory", None)).unwrap();
        let client = test_client(&mut om);
        let obj = om
            .create_object(ev, ObjectBody::Event(EventBody::default()))
            .unwrap();
        let h = om
            .open_handle(
                client,
                &obj,
                AccessMask::GENERIC_READ,
                ObjAttrFlags::empty(),
            )
            .unwrap();

        assert_eq!(
            om.reference_by_handle(client, h, Some(dir), AccessMask::GENERIC_READ)
                .unwrap_err(),
            NtStatus::OBJECT_TYPE_MISMATCH
        );
        assert_eq!(
            om.reference_by_handle(client, h, Some(ev), AccessMask::GENERIC_WRITE)
                .unwrap_err(),
            NtStatus::ACCESS_DENIED
        );
        assert!(om
            .reference_by_handle(client, h, Some(ev), AccessMask::GENERIC_READ)
            .is_ok());
    }

    #[test]
    fn client_death_closes_handles() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(type_def(None)).unwrap();
        let client = test_client(&mut om);
        let obj = om.create_object(ty, opaque()).unwrap();
        let id = obj.id();
        let _h = om
            .open_handle(client, &obj, AccessMask::GENERIC_ALL, ObjAttrFlags::empty())
            .unwrap();
        assert_eq!(obj.pointer_count(), 2);
        assert_eq!(obj.handle_count(), 1);

        om.close_client(client).unwrap();
        assert_eq!(obj.handle_count(), 0);
        assert_eq!(obj.pointer_count(), 1); // handle ref dropped; creator survives

        // The client id is retired.
        assert_eq!(
            om.open_handle(client, &obj, AccessMask::GENERIC_ALL, ObjAttrFlags::empty())
                .unwrap_err(),
            NtStatus::INVALID_HANDLE
        );

        // The object dies once the creator drops it.
        drop(obj);
        assert_eq!(
            om.reference_by_id(id).unwrap_err(),
            NtStatus::INVALID_HANDLE
        );
    }

    proptest! {
        /// `handle_count` equals the number of open handles; each open handle
        /// holds a strong reference (so `pointer_count` = 1 creator + open
        /// handles); every open handle resolves and closed ones do not.
        #[test]
        fn handle_count_tracks_open_handles(ops in prop::collection::vec(any::<bool>(), 0..64)) {
            let mut om = ObjectManager::new();
            let ty = om.register_type(type_def(None)).unwrap();
            let client = test_client(&mut om);
            let obj = om.create_object(ty, opaque()).unwrap();
            let mut open: Vec<HandleValue> = Vec::new();

            for do_open in ops {
                if do_open {
                    let h = om
                        .open_handle(client, &obj, AccessMask::GENERIC_ALL, ObjAttrFlags::empty())
                        .unwrap();
                    open.push(h);
                } else if let Some(h) = open.pop() {
                    om.close_handle(client, h).unwrap();
                }
            }

            prop_assert_eq!(obj.handle_count(), open.len());
            prop_assert_eq!(obj.pointer_count(), 1 + open.len());
            prop_assert_eq!(om.open_handle_count(client).unwrap(), open.len());
            for h in &open {
                prop_assert!(om
                    .reference_by_handle(client, *h, Some(ty), AccessMask::GENERIC_ALL)
                    .is_ok());
            }
        }
    }

    // --- Milestone 4: namespace ---------------------------------------------

    fn bootstrapped() -> ObjectManager {
        let mut om = ObjectManager::new();
        om.bootstrap_namespace().unwrap();
        om
    }

    #[test]
    fn bootstrap_creates_root_and_mvp_dirs() {
        let om = bootstrapped();
        let root = om.lookup_path(&path("\\"), CI).unwrap();
        assert!(root.is_permanent());
        for p in ["\\Device", "\\Driver", "\\??", "\\BaseNamedObjects"] {
            let d = om.lookup_path(&path(p), CI).unwrap();
            assert!(d.is_permanent());
        }
        assert_eq!(
            om.lookup_path(&path("\\NoSuch"), CI).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn nested_lookup_case_and_missing() {
        let mut om = bootstrapped();
        let device = om.lookup_path(&path("\\Device"), CI).unwrap();
        let ev = om.register_type(named_type_def("Event", None)).unwrap();
        let obj = om
            .create_object(ev, ObjectBody::Event(EventBody::default()))
            .unwrap();
        om.insert_named_object(&device, &uni("Test0"), &obj, true)
            .unwrap();

        assert_eq!(
            om.lookup_path(&path("\\Device\\Test0"), CI).unwrap().id(),
            obj.id()
        );
        // case-insensitive hit
        assert_eq!(
            om.lookup_path(&path("\\device\\test0"), CI).unwrap().id(),
            obj.id()
        );
        // case-sensitive miss
        assert!(om
            .lookup_path(&path("\\device\\test0"), CaseSensitivity::CaseSensitive)
            .is_err());
        // missing intermediate -> PATH_NOT_FOUND
        assert_eq!(
            om.lookup_path(&path("\\NoDir\\X"), CI).unwrap_err(),
            NtStatus::OBJECT_PATH_NOT_FOUND
        );
        // missing final -> NAME_NOT_FOUND
        assert_eq!(
            om.lookup_path(&path("\\Device\\Missing"), CI).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        // traverse into a non-directory -> PATH_NOT_FOUND
        assert_eq!(
            om.lookup_path(&path("\\Device\\Test0\\Foo"), CI)
                .unwrap_err(),
            NtStatus::OBJECT_PATH_NOT_FOUND
        );
    }

    #[test]
    fn name_collision_case_insensitive() {
        let mut om = bootstrapped();
        let device = om.lookup_path(&path("\\Device"), CI).unwrap();
        let ev = om.register_type(named_type_def("Event", None)).unwrap();
        let a = om
            .create_object(ev, ObjectBody::Event(EventBody::default()))
            .unwrap();
        let b = om
            .create_object(ev, ObjectBody::Event(EventBody::default()))
            .unwrap();
        om.insert_named_object(&device, &uni("Dup"), &a, false)
            .unwrap();
        assert_eq!(
            om.insert_named_object(&device, &uni("Dup"), &b, false)
                .unwrap_err(),
            NtStatus::OBJECT_NAME_COLLISION
        );
        assert_eq!(
            om.insert_named_object(&device, &uni("DUP"), &b, false)
                .unwrap_err(),
            NtStatus::OBJECT_NAME_COLLISION
        );
        // inserting into a non-directory
        assert_eq!(
            om.insert_named_object(&a, &uni("X"), &b, false)
                .unwrap_err(),
            NtStatus::OBJECT_TYPE_MISMATCH
        );
    }

    #[test]
    fn temporary_name_removed_on_last_handle_close() {
        let mut om = bootstrapped();
        let device = om.lookup_path(&path("\\Device"), CI).unwrap();
        let ev = om.register_type(named_type_def("Event", None)).unwrap();
        let client = test_client(&mut om);
        let obj = om
            .create_object(ev, ObjectBody::Event(EventBody::default()))
            .unwrap();
        let id = obj.id();
        om.insert_named_object(&device, &uni("Temp0"), &obj, false)
            .unwrap(); // temporary
        let h = om
            .open_handle(client, &obj, AccessMask::GENERIC_ALL, ObjAttrFlags::empty())
            .unwrap();
        drop(obj); // only the directory entry + the handle keep it now

        assert!(om.lookup_path(&path("\\Device\\Temp0"), CI).is_ok());
        om.close_handle(client, h).unwrap(); // last handle -> temporary name removed
        assert_eq!(
            om.lookup_path(&path("\\Device\\Temp0"), CI).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            om.reference_by_id(id).unwrap_err(),
            NtStatus::INVALID_HANDLE // object deleted
        );
    }

    #[test]
    fn permanent_retained_then_make_temporary() {
        let mut om = bootstrapped();
        let device = om.lookup_path(&path("\\Device"), CI).unwrap();
        let ev = om.register_type(named_type_def("Event", None)).unwrap();
        let client = test_client(&mut om);
        let obj = om
            .create_object(ev, ObjectBody::Event(EventBody::default()))
            .unwrap();
        om.insert_named_object(&device, &uni("Perm0"), &obj, true)
            .unwrap(); // permanent
        let h = om
            .open_handle(client, &obj, AccessMask::GENERIC_ALL, ObjAttrFlags::empty())
            .unwrap();
        drop(obj);
        om.close_handle(client, h).unwrap(); // last handle closed

        // permanent -> name retained
        let found = om.lookup_path(&path("\\Device\\Perm0"), CI).unwrap();
        // make it temporary with no handles -> name removed immediately
        om.make_temporary(&found).unwrap();
        drop(found);
        assert_eq!(
            om.lookup_path(&path("\\Device\\Perm0"), CI).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn remove_named_object_unlinks() {
        let mut om = bootstrapped();
        let device = om.lookup_path(&path("\\Device"), CI).unwrap();
        let ev = om.register_type(named_type_def("Event", None)).unwrap();
        let obj = om
            .create_object(ev, ObjectBody::Event(EventBody::default()))
            .unwrap();
        om.insert_named_object(&device, &uni("R0"), &obj, true)
            .unwrap();
        assert!(om.lookup_path(&path("\\Device\\R0"), CI).is_ok());

        om.remove_named_object(&device, &uni("R0"), CI).unwrap();
        assert_eq!(obj.name(), None);
        assert_eq!(
            om.lookup_path(&path("\\Device\\R0"), CI).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            om.remove_named_object(&device, &uni("R0"), CI).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
    }

    // --- Milestone 5: symbolic links ----------------------------------------

    #[test]
    fn symlink_follow_query_and_openlink() {
        let mut om = bootstrapped();
        let device = om.lookup_path(&path("\\Device"), CI).unwrap();
        let dosdev = om.lookup_path(&path("\\??"), CI).unwrap();
        let ev = om.register_type(named_type_def("Event", None)).unwrap();
        let bar = om
            .create_object(ev, ObjectBody::Event(EventBody::default()))
            .unwrap();
        om.insert_named_object(&device, &uni("Bar"), &bar, true)
            .unwrap();
        // \??\Foo -> \Device\Bar
        let link = om
            .create_symbolic_link(&dosdev, &uni("Foo"), path("\\Device\\Bar"), true)
            .unwrap();

        // lookup_path follows the link to the target object
        assert_eq!(
            om.lookup_path(&path("\\??\\Foo"), CI).unwrap().id(),
            bar.id()
        );
        // lookup_link returns the link object itself (OBJ_OPENLINK)
        assert_eq!(
            om.lookup_link(&path("\\??\\Foo"), CI).unwrap().id(),
            link.id()
        );
        // query the target
        assert_eq!(
            om.query_symbolic_link(&link).unwrap(),
            path("\\Device\\Bar")
        );
        // querying a non-symlink is a type mismatch
        assert_eq!(
            om.query_symbolic_link(&bar).unwrap_err(),
            NtStatus::OBJECT_TYPE_MISMATCH
        );
    }

    #[test]
    fn intermediate_symlink_followed() {
        let mut om = bootstrapped();
        let device = om.lookup_path(&path("\\Device"), CI).unwrap();
        let dosdev = om.lookup_path(&path("\\??"), CI).unwrap();
        let ev = om.register_type(named_type_def("Event", None)).unwrap();
        let sub = om.create_directory(&device, &uni("Sub"), true).unwrap();
        let x = om
            .create_object(ev, ObjectBody::Event(EventBody::default()))
            .unwrap();
        om.insert_named_object(&sub, &uni("X"), &x, true).unwrap();
        // \??\D -> \Device
        om.create_symbolic_link(&dosdev, &uni("D"), path("\\Device"), true)
            .unwrap();
        // \??\D\Sub\X resolves to \Device\Sub\X
        assert_eq!(
            om.lookup_path(&path("\\??\\D\\Sub\\X"), CI).unwrap().id(),
            x.id()
        );
    }

    #[test]
    fn broken_symlink_target_errors() {
        let mut om = bootstrapped();
        let dosdev = om.lookup_path(&path("\\??"), CI).unwrap();
        om.create_symbolic_link(&dosdev, &uni("Broken"), path("\\Device\\Nope"), true)
            .unwrap();
        // follows into \Device (exists) then a missing final name
        assert_eq!(
            om.lookup_path(&path("\\??\\Broken"), CI).unwrap_err(),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        // the link object itself is still openable
        assert!(om.lookup_link(&path("\\??\\Broken"), CI).is_ok());
    }

    #[test]
    fn symlink_self_loop_rejected() {
        let mut om = bootstrapped();
        let dosdev = om.lookup_path(&path("\\??"), CI).unwrap();
        om.create_symbolic_link(&dosdev, &uni("Self"), path("\\??\\Self"), true)
            .unwrap();
        assert_eq!(
            om.lookup_path(&path("\\??\\Self"), CI).unwrap_err(),
            NtStatus::OBJECT_PATH_NOT_FOUND
        );
    }

    #[test]
    fn symlink_mutual_loop_rejected() {
        let mut om = bootstrapped();
        let dosdev = om.lookup_path(&path("\\??"), CI).unwrap();
        om.create_symbolic_link(&dosdev, &uni("A"), path("\\??\\B"), true)
            .unwrap();
        om.create_symbolic_link(&dosdev, &uni("B"), path("\\??\\A"), true)
            .unwrap();
        assert_eq!(
            om.lookup_path(&path("\\??\\A"), CI).unwrap_err(),
            NtStatus::OBJECT_PATH_NOT_FOUND
        );
    }

    // --- Milestone 6: access checks -----------------------------------------

    fn event_type_def() -> ObjectTypeDef {
        use nt_types::rights::event as ev;
        ObjectTypeDef {
            name: "Event",
            valid_access: ev::ALL_ACCESS,
            generic_mapping: GenericMapping {
                generic_read: AccessMask::STANDARD_RIGHTS_READ
                    | AccessMask::SYNCHRONIZE
                    | ev::QUERY_STATE,
                generic_write: AccessMask::STANDARD_RIGHTS_WRITE
                    | AccessMask::SYNCHRONIZE
                    | ev::MODIFY_STATE,
                generic_execute: AccessMask::STANDARD_RIGHTS_EXECUTE | AccessMask::SYNCHRONIZE,
                generic_all: ev::ALL_ACCESS,
            },
            delete: None,
        }
    }

    #[test]
    fn compute_granted_policy() {
        use nt_types::rights::event as ev;
        let def = event_type_def();
        let valid = def.valid_access;
        let m = &def.generic_mapping;

        // GENERIC_ALL -> all valid rights
        assert_eq!(
            compute_granted(AccessMask::GENERIC_ALL, valid, m, AccessMode::UserMode).unwrap(),
            valid
        );
        // GENERIC_READ -> read rights only (no generic bits left)
        let g = compute_granted(AccessMask::GENERIC_READ, valid, m, AccessMode::UserMode).unwrap();
        assert!(g.contains(ev::QUERY_STATE));
        assert!(!g.contains(ev::MODIFY_STATE));
        assert!(!g.has_generic());
        // MAXIMUM_ALLOWED -> all valid rights
        assert_eq!(
            compute_granted(AccessMask::MAXIMUM_ALLOWED, valid, m, AccessMode::UserMode).unwrap(),
            valid
        );
        // user-mode requesting a right the type does not define -> denied
        let bogus = AccessMask::from_bits_retain(0x0800);
        assert_eq!(
            compute_granted(bogus, valid, m, AccessMode::UserMode).unwrap_err(),
            NtStatus::ACCESS_DENIED
        );
        // kernel-mode -> trusted; the bit is masked off, not denied
        assert_eq!(
            compute_granted(bogus, valid, m, AccessMode::KernelMode).unwrap(),
            AccessMask::empty()
        );
    }

    #[test]
    fn open_records_granted_and_reference_checks() {
        use nt_types::rights::event as ev;
        let mut om = ObjectManager::new();
        let ty = om.register_type(event_type_def()).unwrap();
        let user = om.register_client(ClientKind::NativeUser, AccessMode::UserMode);
        let obj = om
            .create_object(ty, ObjectBody::Event(EventBody::default()))
            .unwrap();

        // Open for GENERIC_READ -> handle records the mapped read rights.
        let h = om
            .open(user, &obj, AccessMask::GENERIC_READ, ObjAttrFlags::empty())
            .unwrap();
        assert!(om
            .reference_by_handle(user, h, Some(ty), ev::QUERY_STATE)
            .is_ok());
        assert_eq!(
            om.reference_by_handle(user, h, Some(ty), ev::MODIFY_STATE)
                .unwrap_err(),
            NtStatus::ACCESS_DENIED
        );
    }

    #[test]
    fn open_user_over_request_denied_kernel_masked() {
        let mut om = ObjectManager::new();
        let ty = om.register_type(event_type_def()).unwrap();
        let user = om.register_client(ClientKind::NativeUser, AccessMode::UserMode);
        let kernel = om.register_client(ClientKind::ExecutiveService, AccessMode::KernelMode);
        let obj = om
            .create_object(ty, ObjectBody::Event(EventBody::default()))
            .unwrap();
        let bogus = AccessMask::from_bits_retain(0x0800);

        assert_eq!(
            om.open(user, &obj, bogus, ObjAttrFlags::empty())
                .unwrap_err(),
            NtStatus::ACCESS_DENIED
        );
        // kernel-mode opens fine (granted is masked to empty).
        let h = om.open(kernel, &obj, bogus, ObjAttrFlags::empty()).unwrap();
        assert!(om
            .reference_by_handle(kernel, h, Some(ty), AccessMask::empty())
            .is_ok());
    }

    #[test]
    fn open_directory_via_access_check() {
        use nt_types::rights::directory as dir;
        let mut om = bootstrapped();
        let user = om.register_client(ClientKind::NativeUser, AccessMode::UserMode);
        let device = om.lookup_path(&path("\\Device"), CI).unwrap();

        let h = om
            .open(
                user,
                &device,
                AccessMask::GENERIC_READ,
                ObjAttrFlags::empty(),
            )
            .unwrap();
        // read maps to QUERY | TRAVERSE
        assert!(om
            .reference_by_handle(user, h, om.directory_type(), dir::QUERY | dir::TRAVERSE)
            .is_ok());
        // but not a create (write) right
        assert_eq!(
            om.reference_by_handle(user, h, om.directory_type(), dir::CREATE_OBJECT)
                .unwrap_err(),
            NtStatus::ACCESS_DENIED
        );
    }
}
