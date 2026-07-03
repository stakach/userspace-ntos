//! Object types, the type registry, and object bodies.

use alloc::vec::Vec;
use nt_status::NtStatus;
use nt_types::{AccessMask, GenericMapping, NtPath, ObjectId, ObjectTypeId};

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
    /// A body whose real state lives in another component (service mode).
    Opaque(OpaqueBody),
}

/// A directory body (name → child map). Filled in with the namespace milestone
/// (M4), where each entry holds a strong reference to keep named children alive;
/// a placeholder here so the object/type/lifetime machinery is exercised first.
#[derive(Default)]
pub struct DirectoryBody {}

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
