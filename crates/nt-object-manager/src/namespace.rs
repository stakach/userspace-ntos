//! The named object namespace: the directory tree, path lookup, the root
//! bootstrap, and temporary-name reaping.
//!
//! Directories are ordinary objects whose body ([`DirectoryBody`]) maps names to
//! **strong** child references, so the whole named tree is kept alive by the
//! Object Manager's strong reference to the root. A named temporary object loses
//! its name (and the directory's reference) when its last handle closes; a
//! permanent object keeps its name until made temporary.

use nt_status::NtStatus;
use nt_types::{AccessMask, CaseSensitivity, GenericMapping, NtPath, ObjectTypeId, UnicodeString};

use crate::store::ObjectRef;
use crate::types::{DirectoryBody, ObjectBody, ObjectTypeDef};
use crate::ObjectManager;

/// The built-in Directory object type name.
const DIRECTORY_TYPE_NAME: &str = "Directory";

/// The MVP root directories created at bootstrap (spec §9.1).
const ROOT_DIRECTORIES: &[&str] = &["Device", "Driver", "??", "BaseNamedObjects"];

impl ObjectManager {
    /// Register the Directory type (idempotent), returning its id.
    fn ensure_directory_type(&mut self) -> Result<ObjectTypeId, NtStatus> {
        if let Some(id) = self.directory_type {
            return Ok(id);
        }
        let id = self.register_type(ObjectTypeDef {
            name: DIRECTORY_TYPE_NAME,
            valid_access: AccessMask::GENERIC_ALL, // refined in M6
            generic_mapping: GenericMapping::default(),
            delete: None, // children drop with the DirectoryBody
        })?;
        self.directory_type = Some(id);
        Ok(id)
    }

    /// The Directory type id, once the namespace is bootstrapped.
    pub fn directory_type(&self) -> Option<ObjectTypeId> {
        self.directory_type
    }

    /// A reference to the root directory `\`, once bootstrapped.
    pub fn root(&self) -> Option<ObjectRef> {
        self.root.clone()
    }

    /// Create the root namespace: `\` (permanent) plus the MVP directories
    /// `\Device`, `\Driver`, `\??`, `\BaseNamedObjects`. Idempotent.
    pub fn bootstrap_namespace(&mut self) -> Result<(), NtStatus> {
        if self.root.is_some() {
            return Ok(());
        }
        let dir_ty = self.ensure_directory_type()?;
        let root = self.create_object(dir_ty, ObjectBody::Directory(DirectoryBody::default()))?;
        root.set_permanent(true);
        self.root = Some(root.clone());
        for name in ROOT_DIRECTORIES {
            self.create_directory(&root, &UnicodeString::from_str(name), true)?;
        }
        Ok(())
    }

    /// Create a directory named `name` inside `parent`.
    pub fn create_directory(
        &mut self,
        parent: &ObjectRef,
        name: &UnicodeString,
        permanent: bool,
    ) -> Result<ObjectRef, NtStatus> {
        let dir_ty = self.ensure_directory_type()?;
        let dir = self.create_object(dir_ty, ObjectBody::Directory(DirectoryBody::default()))?;
        self.insert_named_object(parent, name, &dir, permanent)?;
        Ok(dir)
    }

    /// Insert `child` into the directory `parent` under `name`, setting the
    /// child's name/parent (and permanence). The directory holds a strong
    /// reference. `STATUS_OBJECT_NAME_COLLISION` on a duplicate name;
    /// `STATUS_OBJECT_TYPE_MISMATCH` if `parent` is not a directory.
    pub fn insert_named_object(
        &mut self,
        parent: &ObjectRef,
        name: &UnicodeString,
        child: &ObjectRef,
        permanent: bool,
    ) -> Result<(), NtStatus> {
        parent.with_body_mut(|b| match b {
            ObjectBody::Directory(d) => d.insert(name.clone(), child.clone()),
            _ => Err(NtStatus::OBJECT_TYPE_MISMATCH),
        })?;
        child.set_name(Some(name.clone()));
        child.set_parent(Some(parent.id()));
        if permanent {
            child.set_permanent(true);
        }
        Ok(())
    }

    /// Remove `name` from the directory `parent`, unlinking the child.
    /// `STATUS_OBJECT_NAME_NOT_FOUND` if absent.
    pub fn remove_named_object(
        &mut self,
        parent: &ObjectRef,
        name: &UnicodeString,
        case: CaseSensitivity,
    ) -> Result<(), NtStatus> {
        let removed = parent.with_body_mut(|b| match b {
            ObjectBody::Directory(d) => d.remove(name, case),
            _ => None,
        });
        match removed {
            Some(child) => {
                child.set_name(None);
                child.set_parent(None);
                Ok(())
            }
            None => Err(NtStatus::OBJECT_NAME_NOT_FOUND),
        }
    }

    /// Resolve an absolute NT path to its target object (spec §9), returning a
    /// new counted reference. A missing/non-directory *intermediate* component
    /// yields `STATUS_OBJECT_PATH_NOT_FOUND`; a missing *final* name yields
    /// `STATUS_OBJECT_NAME_NOT_FOUND`. The root path `\` returns the root.
    pub fn lookup_path(&self, path: &NtPath, case: CaseSensitivity) -> Result<ObjectRef, NtStatus> {
        let mut current = self.root.clone().ok_or(NtStatus::OBJECT_PATH_NOT_FOUND)?;
        let comps = path.components();
        for (i, comp) in comps.iter().enumerate() {
            let is_final = i + 1 == comps.len();
            let step = current.with_body(|b| match b {
                ObjectBody::Directory(d) => Ok(d.lookup(comp, case)),
                _ => Err(()),
            });
            current = match step {
                Err(()) => return Err(NtStatus::OBJECT_PATH_NOT_FOUND), // not a directory
                Ok(Some(child)) => child,
                Ok(None) => {
                    return Err(if is_final {
                        NtStatus::OBJECT_NAME_NOT_FOUND
                    } else {
                        NtStatus::OBJECT_PATH_NOT_FOUND
                    })
                }
            };
        }
        Ok(current)
    }

    /// Make a named object temporary: clear its permanent flag, and if it has no
    /// open handles, remove its name now (spec §11.7).
    pub fn make_temporary(&mut self, obj: &ObjectRef) -> Result<(), NtStatus> {
        obj.set_permanent(false);
        if obj.handle_count() == 0 {
            self.unlink_from_parent(obj);
        }
        Ok(())
    }

    /// Reap after a handle close: a temporary named object with no remaining
    /// handles loses its name and its directory reference (spec §8.6 / §14).
    pub(crate) fn on_handle_closed(&mut self, obj: &ObjectRef) {
        if obj.handle_count() == 0 && !obj.is_permanent() && obj.name().is_some() {
            self.unlink_from_parent(obj);
        }
    }

    /// Remove `obj`'s name from its parent directory (dropping the directory's
    /// strong reference) and clear its name/parent.
    fn unlink_from_parent(&mut self, obj: &ObjectRef) {
        if let (Some(parent_id), Some(name)) = (obj.parent(), obj.name()) {
            if let Ok(parent) = self.reference_by_id(parent_id) {
                parent.with_body_mut(|b| {
                    if let ObjectBody::Directory(d) = b {
                        d.remove(&name, CaseSensitivity::CaseInsensitive);
                    }
                });
            }
        }
        obj.set_name(None);
        obj.set_parent(None);
    }
}
