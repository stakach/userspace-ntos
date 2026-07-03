//! Object types, the type registry, and object bodies.

use alloc::vec::Vec;
use nt_status::NtStatus;
use nt_types::{
    AccessMask, CaseSensitivity, GenericMapping, NtPath, ObjectId, ObjectTypeId, UnicodeString,
};

use crate::store::ObjectRef;

/// Identifies a service-mode owner component (for [`OpaqueBody`]).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct ComponentId(pub u64);

/// A type's deletion callback. Runs exactly once, when the object's last
/// reference drops (final dereference → deleted), with `&mut` access to the body
/// so type-specific resources can be released. A plain `fn` pointer (not a trait
/// object) per spec §8.5 — no captured state, no allocation.
pub type DeleteFn = fn(body: &mut ObjectBody, id: ObjectId);

/// Definition supplied when registering an object type.
#[derive(Clone)]
pub struct ObjectTypeDef {
    /// Type name (e.g. `"Directory"`). Must be unique.
    pub name: &'static str,
    /// The union of valid access bits for this type.
    pub valid_access: AccessMask,
    /// `GENERIC_*` → specific-rights mapping for this type.
    pub generic_mapping: GenericMapping,
    /// Optional deletion callback.
    pub delete: Option<DeleteFn>,
}

/// A registered object type.
pub struct ObjectType {
    id: ObjectTypeId,
    name: &'static str,
    valid_access: AccessMask,
    generic_mapping: GenericMapping,
    delete: Option<DeleteFn>,
}

impl ObjectType {
    pub fn id(&self) -> ObjectTypeId {
        self.id
    }
    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn valid_access(&self) -> AccessMask {
        self.valid_access
    }
    pub fn generic_mapping(&self) -> &GenericMapping {
        &self.generic_mapping
    }
    pub(crate) fn delete_fn(&self) -> Option<DeleteFn> {
        self.delete
    }
}

/// The set of registered object types. `ObjectTypeId` is the registration index.
#[derive(Default)]
pub struct TypeRegistry {
    types: Vec<ObjectType>,
}

impl TypeRegistry {
    pub fn new() -> Self {
        Self { types: Vec::new() }
    }

    /// Register a new type. Returns `STATUS_OBJECT_NAME_COLLISION` if the name is
    /// already registered.
    pub fn register(&mut self, def: ObjectTypeDef) -> Result<ObjectTypeId, NtStatus> {
        if self.types.iter().any(|t| t.name == def.name) {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        let id = ObjectTypeId(self.types.len() as u32);
        self.types.push(ObjectType {
            id,
            name: def.name,
            valid_access: def.valid_access,
            generic_mapping: def.generic_mapping,
            delete: def.delete,
        });
        Ok(id)
    }

    pub fn get(&self, id: ObjectTypeId) -> Option<&ObjectType> {
        self.types.get(id.0 as usize)
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Object bodies (spec §13.1). The Object Manager owns common identity/lifetime;
// each body carries the type-specific data. Variants are fleshed out as their
// subsystems land; Driver/Device/File/Timer arrive with the I/O Manager.
// ---------------------------------------------------------------------------

/// The type-specific payload of an object.
#[non_exhaustive]
pub enum ObjectBody {
    Directory(DirectoryBody),
    SymbolicLink(SymbolicLinkBody),
    Event(EventBody),
    /// A driver object (the I/O Manager owns the real `DriverObject`).
    Driver(DriverBody),
    /// A device object (the I/O Manager owns the real `DeviceObject`).
    Device(DeviceBody),
    /// A file object (the I/O Manager owns the real `FileObject`).
    File(FileBody),
    /// A body whose real state lives in another component (service mode).
    Opaque(OpaqueBody),
}

/// One directory entry: the ASCII-folded lookup key, the original name, and a
/// **strong** reference to the child (so a named object stays alive while it is
/// in the namespace).
struct DirEntry {
    key: UnicodeString,
    name: UnicodeString,
    child: ObjectRef,
}

/// A directory body: a name → child map. Case-insensitive lookups match on the
/// ASCII-folded key; case-sensitive lookups match the original name. Insertion
/// is case-insensitive (one entry per folded name), matching NT's default.
#[derive(Default)]
pub struct DirectoryBody {
    entries: Vec<DirEntry>,
}

impl DirectoryBody {
    /// Insert `child` under `name`. `STATUS_OBJECT_NAME_COLLISION` if a name that
    /// folds to the same key already exists.
    pub(crate) fn insert(&mut self, name: UnicodeString, child: ObjectRef) -> Result<(), NtStatus> {
        let key = name.to_ascii_folded();
        if self.entries.iter().any(|e| e.key == key) {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        self.entries.push(DirEntry { key, name, child });
        Ok(())
    }

    /// Look up a child by name, returning a new counted reference.
    pub(crate) fn lookup(&self, name: &UnicodeString, case: CaseSensitivity) -> Option<ObjectRef> {
        self.find(name, case).map(|e| e.child.clone())
    }

    /// Remove a child by name, returning the (now unlinked) reference.
    pub(crate) fn remove(
        &mut self,
        name: &UnicodeString,
        case: CaseSensitivity,
    ) -> Option<ObjectRef> {
        let pos = self.position(name, case)?;
        Some(self.entries.remove(pos).child)
    }

    fn find(&self, name: &UnicodeString, case: CaseSensitivity) -> Option<&DirEntry> {
        match case {
            CaseSensitivity::CaseInsensitive => {
                let key = name.to_ascii_folded();
                self.entries.iter().find(|e| e.key == key)
            }
            CaseSensitivity::CaseSensitive => self.entries.iter().find(|e| &e.name == name),
        }
    }

    fn position(&self, name: &UnicodeString, case: CaseSensitivity) -> Option<usize> {
        match case {
            CaseSensitivity::CaseInsensitive => {
                let key = name.to_ascii_folded();
                self.entries.iter().position(|e| e.key == key)
            }
            CaseSensitivity::CaseSensitive => self.entries.iter().position(|e| &e.name == name),
        }
    }

    /// The names of the direct children (for debug / namespace dump).
    pub fn names(&self) -> impl Iterator<Item = &UnicodeString> {
        self.entries.iter().map(|e| &e.name)
    }

    /// Number of direct children.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the directory is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A symbolic-link body.
pub struct SymbolicLinkBody {
    pub target: NtPath,
}

/// A dispatcher event (minimal — full wait semantics are out of scope for v0.1).
#[derive(Clone, Copy, Debug, Default)]
pub struct EventBody {
    pub signaled: bool,
    pub manual_reset: bool,
}

/// A driver object body — the Object Manager owns the identity/name/lifetime; the
/// I/O Manager owns the real `DriverObject`, reached via `owner`/`owner_local_id`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriverBody {
    pub owner: ComponentId,
    pub owner_local_id: u64,
}

/// A device object body (routing to the owning I/O Manager, spec §13.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceBody {
    pub owner: ComponentId,
    pub owner_local_id: u64,
}

/// A file object body — routes to the owner and names the device it targets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileBody {
    pub owner: ComponentId,
    pub owner_local_id: u64,
    pub device: ObjectId,
}

bitflags::bitflags! {
    /// Flags on an [`OpaqueBody`].
    #[repr(transparent)]
    #[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
    pub struct OpaqueFlags: u32 {
        /// Lookups on this object route to the owner component.
        const ROUTES_TO_OWNER = 0x0000_0001;
    }
}

/// An object whose canonical identity/lifetime the Object Manager owns, but
/// whose real state lives in `owner_component` (e.g. an I/O Manager device).
#[derive(Clone, Copy, Debug, Default)]
pub struct OpaqueBody {
    pub owner_component: ComponentId,
    pub owner_local_id: u64,
    pub flags: OpaqueFlags,
}
