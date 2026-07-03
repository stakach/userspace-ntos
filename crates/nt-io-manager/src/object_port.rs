//! Object Manager integration (spec §8, §28 Task 4).
//!
//! The I/O Manager never owns object identity, names, handles, or references —
//! the Object Manager does. [`ObjectManagerPort`] is the trait through which the
//! I/O Manager reaches it, so the core stays testable against a [`MockObjectPort`]
//! and, in a real deployment, drives the actual Object Manager (the in-process
//! [`library`] adapter, or a brokered service client later).

use alloc::vec::Vec;

use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath, ObjectId};

/// The Object Manager operations the I/O Manager depends on. All object identity,
/// naming, handle tables, references, and symbolic links stay canonical in the
/// Object Manager; the I/O Manager only holds the returned ids/handles.
pub trait ObjectManagerPort {
    /// Register a connected I/O client with the Object Manager, returning the
    /// canonical [`ClientId`] used for that client's handles.
    fn register_client(&mut self) -> ClientId;

    /// Retire a client: close its handles (Object Manager side).
    fn close_client(&mut self, client: ClientId) -> Result<(), NtStatus>;

    /// Create a named `Driver` object (e.g. `\Driver\Foo`). `owner_local_id` is
    /// the I/O Manager's `DriverId`, stored in the object's opaque routing body.
    fn create_driver_object(
        &mut self,
        name: &NtPath,
        owner_local_id: u64,
    ) -> Result<ObjectId, NtStatus>;

    /// Create a `Device` object, named under `\Device` (or unnamed for tests).
    /// `owner_local_id` is the I/O Manager's `DeviceId`.
    fn create_device_object(
        &mut self,
        name: Option<&NtPath>,
        owner_local_id: u64,
    ) -> Result<ObjectId, NtStatus>;

    /// Resolve a device path (following symbolic links) to its `Device` object.
    fn open_device_object(&mut self, path: &NtPath) -> Result<ObjectId, NtStatus>;

    /// Create a symbolic link `link -> target` (e.g. `\??\Foo -> \Device\Foo`).
    fn create_symbolic_link(&mut self, link: &NtPath, target: &NtPath) -> Result<(), NtStatus>;

    /// Delete a symbolic link.
    fn delete_symbolic_link(&mut self, link: &NtPath) -> Result<(), NtStatus>;

    /// Brokered create (spec §8.4): create a `File` object bound to `device_object`
    /// **and** open a handle to it for `client`, returning both. `owner_local_id`
    /// is the I/O Manager's `FileId`.
    fn create_file_object_and_handle(
        &mut self,
        client: ClientId,
        device_object: ObjectId,
        owner_local_id: u64,
        desired_access: AccessMask,
    ) -> Result<(ObjectId, HandleValue), NtStatus>;

    /// Reference a `File` object by `handle` on behalf of `client`, checking
    /// `desired_access`. Returns the file object id.
    fn reference_file_by_handle(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        desired_access: AccessMask,
    ) -> Result<ObjectId, NtStatus>;

    /// Validate that `device_object` still names a live `Device` object.
    fn reference_device(&mut self, device_object: ObjectId) -> Result<(), NtStatus>;

    /// Close a client's handle (Object Manager side).
    fn close_handle(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus>;
}

// ---------------------------------------------------------------------------
// Mock port — an in-memory fake for host tests.
// ---------------------------------------------------------------------------

const SYMLINK_HOP_LIMIT: usize = 16;

struct MockHandle {
    client: ClientId,
    handle: HandleValue,
    object: ObjectId,
    access: AccessMask,
    live: bool,
}

/// An in-memory [`ObjectManagerPort`] for tests: it assigns object ids + handles,
/// tracks named devices/drivers, symbolic links, and per-client handles, and does
/// exact + symlink path resolution. Not generation-protected (test fake).
#[derive(Default)]
pub struct MockObjectPort {
    next_object: u64,
    next_handle: u64,
    next_client: u64,
    devices: Vec<(NtPath, ObjectId)>,
    device_ids: Vec<ObjectId>,
    drivers: Vec<(NtPath, ObjectId)>,
    files: Vec<ObjectId>,
    symlinks: Vec<(NtPath, NtPath)>,
    handles: Vec<MockHandle>,
}

impl MockObjectPort {
    pub fn new() -> Self {
        Self::default()
    }

    fn new_object(&mut self) -> ObjectId {
        self.next_object += 1;
        ObjectId(self.next_object)
    }

    /// Follow symbolic links from `path` (exact-match, hop-limited).
    fn resolve(&self, path: &NtPath) -> NtPath {
        let mut cur = path.clone();
        for _ in 0..SYMLINK_HOP_LIMIT {
            match self.symlinks.iter().find(|(link, _)| link == &cur) {
                Some((_, target)) => cur = target.clone(),
                None => break,
            }
        }
        cur
    }
}

impl ObjectManagerPort for MockObjectPort {
    fn register_client(&mut self) -> ClientId {
        self.next_client += 1;
        ClientId(self.next_client)
    }

    fn close_client(&mut self, client: ClientId) -> Result<(), NtStatus> {
        for h in self.handles.iter_mut().filter(|h| h.client == client) {
            h.live = false;
        }
        Ok(())
    }

    fn create_driver_object(
        &mut self,
        name: &NtPath,
        _owner_local_id: u64,
    ) -> Result<ObjectId, NtStatus> {
        let id = self.new_object();
        self.drivers.push((name.clone(), id));
        Ok(id)
    }

    fn create_device_object(
        &mut self,
        name: Option<&NtPath>,
        _owner_local_id: u64,
    ) -> Result<ObjectId, NtStatus> {
        let id = self.new_object();
        if let Some(n) = name {
            if self.devices.iter().any(|(p, _)| p == n) {
                return Err(NtStatus::OBJECT_NAME_COLLISION);
            }
            self.devices.push((n.clone(), id));
        }
        self.device_ids.push(id);
        Ok(id)
    }

    fn open_device_object(&mut self, path: &NtPath) -> Result<ObjectId, NtStatus> {
        let resolved = self.resolve(path);
        self.devices
            .iter()
            .find(|(p, _)| p == &resolved)
            .map(|(_, id)| *id)
            .ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)
    }

    fn create_symbolic_link(&mut self, link: &NtPath, target: &NtPath) -> Result<(), NtStatus> {
        if self.symlinks.iter().any(|(l, _)| l == link) {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        self.symlinks.push((link.clone(), target.clone()));
        Ok(())
    }

    fn delete_symbolic_link(&mut self, link: &NtPath) -> Result<(), NtStatus> {
        let before = self.symlinks.len();
        self.symlinks.retain(|(l, _)| l != link);
        if self.symlinks.len() == before {
            Err(NtStatus::OBJECT_NAME_NOT_FOUND)
        } else {
            Ok(())
        }
    }

    fn create_file_object_and_handle(
        &mut self,
        client: ClientId,
        device_object: ObjectId,
        _owner_local_id: u64,
        desired_access: AccessMask,
    ) -> Result<(ObjectId, HandleValue), NtStatus> {
        if !self.device_ids.contains(&device_object) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let file = self.new_object();
        self.files.push(file);
        self.next_handle += 1;
        let handle = HandleValue(self.next_handle);
        self.handles.push(MockHandle {
            client,
            handle,
            object: file,
            access: desired_access,
            live: true,
        });
        Ok((file, handle))
    }

    fn reference_file_by_handle(
        &mut self,
        client: ClientId,
        handle: HandleValue,
        desired_access: AccessMask,
    ) -> Result<ObjectId, NtStatus> {
        let h = self
            .handles
            .iter()
            .find(|h| h.live && h.client == client && h.handle == handle)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        if !h.access.contains(desired_access) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        Ok(h.object)
    }

    fn reference_device(&mut self, device_object: ObjectId) -> Result<(), NtStatus> {
        if self.device_ids.contains(&device_object) {
            Ok(())
        } else {
            Err(NtStatus::OBJECT_TYPE_MISMATCH)
        }
    }

    fn close_handle(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus> {
        let h = self
            .handles
            .iter_mut()
            .find(|h| h.live && h.client == client && h.handle == handle)
            .ok_or(NtStatus::INVALID_HANDLE)?;
        h.live = false;
        Ok(())
    }
}

#[cfg(feature = "object-manager")]
pub use library::ObjectManagerLibraryPort;

/// In-process adapter driving the real Object Manager (`nt-object-manager`),
/// gated behind the `object-manager` feature. Library mode: the I/O Manager and
/// Object Manager share a node; the port owns a bootstrapped `ObjectManager`.
#[cfg(feature = "object-manager")]
mod library {
    use super::ObjectManagerPort;
    use nt_object_manager::{ClientKind, ComponentId, ObjectManager, ObjectRef};
    use nt_status::NtStatus;
    use nt_types::{
        AccessMask, AccessMode, CaseSensitivity, ClientId, HandleValue, NtPath, ObjAttrFlags,
        ObjectId, UnicodeString,
    };

    const CI: CaseSensitivity = CaseSensitivity::CaseInsensitive;

    /// The I/O Manager's view of the real Object Manager (in-process).
    pub struct ObjectManagerLibraryPort {
        om: ObjectManager,
        component: ComponentId,
    }

    impl ObjectManagerLibraryPort {
        /// Build a port over a freshly-bootstrapped Object Manager, owned by
        /// `component` (the I/O Manager's component id).
        pub fn new(component: ComponentId) -> Result<Self, NtStatus> {
            let mut om = ObjectManager::new();
            om.bootstrap_namespace()?;
            Ok(Self { om, component })
        }

        /// Borrow the underlying Object Manager (e.g. to seed test devices).
        pub fn object_manager(&mut self) -> &mut ObjectManager {
            &mut self.om
        }

        /// Resolve `path`'s parent directory + leaf name for a create.
        fn split(&self, path: &NtPath) -> Result<(ObjectRef, UnicodeString), NtStatus> {
            let leaf = path.leaf().ok_or(NtStatus::INVALID_PARAMETER)?.clone();
            let parent = path.parent().ok_or(NtStatus::INVALID_PARAMETER)?;
            let parent_ref = self.om.lookup_path(&parent, CI)?;
            Ok((parent_ref, leaf))
        }
    }

    impl ObjectManagerPort for ObjectManagerLibraryPort {
        fn register_client(&mut self) -> ClientId {
            self.om
                .register_client(ClientKind::NativeUser, AccessMode::UserMode)
        }

        fn close_client(&mut self, client: ClientId) -> Result<(), NtStatus> {
            self.om.close_client(client)
        }

        fn create_driver_object(
            &mut self,
            name: &NtPath,
            owner_local_id: u64,
        ) -> Result<ObjectId, NtStatus> {
            let (parent, leaf) = self.split(name)?;
            let r = self
                .om
                .create_driver(&parent, &leaf, self.component, owner_local_id, true)?;
            Ok(r.id())
        }

        fn create_device_object(
            &mut self,
            name: Option<&NtPath>,
            owner_local_id: u64,
        ) -> Result<ObjectId, NtStatus> {
            let name = name.ok_or(NtStatus::INVALID_PARAMETER)?; // named devices only
            let (parent, leaf) = self.split(name)?;
            let r = self
                .om
                .create_device(&parent, &leaf, self.component, owner_local_id, true)?;
            Ok(r.id())
        }

        fn open_device_object(&mut self, path: &NtPath) -> Result<ObjectId, NtStatus> {
            let r = self.om.lookup_path(path, CI)?;
            if Some(r.type_id()) != self.om.device_type() {
                return Err(NtStatus::OBJECT_TYPE_MISMATCH);
            }
            Ok(r.id())
        }

        fn create_symbolic_link(&mut self, link: &NtPath, target: &NtPath) -> Result<(), NtStatus> {
            let (parent, leaf) = self.split(link)?;
            self.om
                .create_symbolic_link(&parent, &leaf, target.clone(), true)?;
            Ok(())
        }

        fn delete_symbolic_link(&mut self, link: &NtPath) -> Result<(), NtStatus> {
            let (parent, leaf) = self.split(link)?;
            self.om.remove_named_object(&parent, &leaf, CI)?;
            Ok(())
        }

        fn create_file_object_and_handle(
            &mut self,
            client: ClientId,
            device_object: ObjectId,
            owner_local_id: u64,
            desired_access: AccessMask,
        ) -> Result<(ObjectId, HandleValue), NtStatus> {
            let file = self
                .om
                .create_file(self.component, owner_local_id, device_object)?;
            // Trusted create: grant the requested access directly.
            let handle =
                self.om
                    .open_handle(client, &file, desired_access, ObjAttrFlags::empty())?;
            Ok((file.id(), handle))
        }

        fn reference_file_by_handle(
            &mut self,
            client: ClientId,
            handle: HandleValue,
            desired_access: AccessMask,
        ) -> Result<ObjectId, NtStatus> {
            let r =
                self.om
                    .reference_by_handle(client, handle, self.om.file_type(), desired_access)?;
            Ok(r.id())
        }

        fn reference_device(&mut self, device_object: ObjectId) -> Result<(), NtStatus> {
            let r = self.om.reference_by_id(device_object)?;
            if Some(r.type_id()) != self.om.device_type() {
                return Err(NtStatus::OBJECT_TYPE_MISMATCH);
            }
            Ok(())
        }

        fn close_handle(&mut self, client: ClientId, handle: HandleValue) -> Result<(), NtStatus> {
            self.om.close_handle(client, handle)
        }
    }
}
