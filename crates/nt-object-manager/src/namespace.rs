//! The named object namespace: the directory tree, path lookup, the root
//! bootstrap, and temporary-name reaping.
//!
//! Directories are ordinary objects whose body ([`DirectoryBody`]) maps names to
//! **strong** child references, so the whole named tree is kept alive by the
//! Object Manager's strong reference to the root. A named temporary object loses
//! its name (and the directory's reference) when its last handle closes; a
//! permanent object keeps its name until made temporary.

use alloc::vec::Vec;

use nt_status::NtStatus;
use nt_types::rights;
use nt_types::{AccessMask, CaseSensitivity, GenericMapping, NtPath, ObjectTypeId, UnicodeString};

use crate::store::ObjectRef;
use crate::types::{DirectoryBody, ObjectBody, ObjectTypeDef, SymbolicLinkBody};
use crate::ObjectManager;

/// The built-in Directory object type name.
const DIRECTORY_TYPE_NAME: &str = "Directory";

/// The built-in SymbolicLink object type name.
const SYMLINK_TYPE_NAME: &str = "SymbolicLink";

/// The MVP root directories created at bootstrap (spec §9.1).
const ROOT_DIRECTORIES: &[&str] = &["Device", "Driver", "??", "BaseNamedObjects"];

/// Maximum symbolic-link expansions during one lookup (spec §9.3), to bound loops.
const SYMLINK_LIMIT: u32 = 32;

impl ObjectManager {
    /// Register the Directory type (idempotent), returning its id.
    fn ensure_directory_type(&mut self) -> Result<ObjectTypeId, NtStatus> {
        if let Some(id) = self.directory_type {
            return Ok(id);
        }
        use rights::directory as dir;
        let id = self.register_type(ObjectTypeDef {
            name: DIRECTORY_TYPE_NAME,
            valid_access: dir::ALL_ACCESS,
            generic_mapping: GenericMapping {
                generic_read: AccessMask::STANDARD_RIGHTS_READ | dir::QUERY | dir::TRAVERSE,
                generic_write: AccessMask::STANDARD_RIGHTS_WRITE
                    | dir::CREATE_OBJECT
                    | dir::CREATE_SUBDIRECTORY,
                generic_execute: AccessMask::STANDARD_RIGHTS_EXECUTE | dir::QUERY | dir::TRAVERSE,
                generic_all: dir::ALL_ACCESS,
            },
            delete: None, // children drop with the DirectoryBody
        })?;
        self.directory_type = Some(id);
        Ok(id)
    }

    /// Register the SymbolicLink type (idempotent), returning its id.
    fn ensure_symlink_type(&mut self) -> Result<ObjectTypeId, NtStatus> {
        if let Some(id) = self.symlink_type {
            return Ok(id);
        }
        use rights::symbolic_link as sym;
        let id = self.register_type(ObjectTypeDef {
            name: SYMLINK_TYPE_NAME,
            valid_access: sym::ALL_ACCESS,
            generic_mapping: GenericMapping {
                generic_read: AccessMask::STANDARD_RIGHTS_READ | sym::QUERY,
                generic_write: AccessMask::STANDARD_RIGHTS_WRITE,
                generic_execute: AccessMask::STANDARD_RIGHTS_EXECUTE | sym::QUERY,
                generic_all: sym::ALL_ACCESS,
            },
            delete: None,
        })?;
        self.symlink_type = Some(id);
        Ok(id)
    }

    /// The Directory type id, once the namespace is bootstrapped.
    pub fn directory_type(&self) -> Option<ObjectTypeId> {
        self.directory_type
    }

    /// The SymbolicLink type id, once one has been created.
    pub fn symlink_type(&self) -> Option<ObjectTypeId> {
        self.symlink_type
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

    /// Create an object of type `ty` with `body` and insert it into `parent`
    /// under `name` in one step (create + link). Used by `create_directory`, the
    /// I/O-object helpers, etc.
    pub fn create_named_object(
        &mut self,
        ty: ObjectTypeId,
        body: ObjectBody,
        parent: &ObjectRef,
        name: &UnicodeString,
        permanent: bool,
    ) -> Result<ObjectRef, NtStatus> {
        let obj = self.create_object(ty, body)?;
        self.insert_named_object(parent, name, &obj, permanent)?;
        Ok(obj)
    }

    /// Create a directory named `name` inside `parent`.
    pub fn create_directory(
        &mut self,
        parent: &ObjectRef,
        name: &UnicodeString,
        permanent: bool,
    ) -> Result<ObjectRef, NtStatus> {
        let dir_ty = self.ensure_directory_type()?;
        self.create_named_object(
            dir_ty,
            ObjectBody::Directory(DirectoryBody::default()),
            parent,
            name,
            permanent,
        )
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

    /// Create a symbolic link named `name` in `parent` pointing at `target`.
    pub fn create_symbolic_link(
        &mut self,
        parent: &ObjectRef,
        name: &UnicodeString,
        target: NtPath,
        permanent: bool,
    ) -> Result<ObjectRef, NtStatus> {
        let ty = self.ensure_symlink_type()?;
        let link = self.create_object(ty, ObjectBody::SymbolicLink(SymbolicLinkBody { target }))?;
        self.insert_named_object(parent, name, &link, permanent)?;
        Ok(link)
    }

    /// The target of a symbolic-link object. `STATUS_OBJECT_TYPE_MISMATCH` if
    /// `link` is not a symbolic link.
    pub fn query_symbolic_link(&self, link: &ObjectRef) -> Result<NtPath, NtStatus> {
        link.with_body(|b| match b {
            ObjectBody::SymbolicLink(s) => Ok(s.target.clone()),
            _ => Err(NtStatus::OBJECT_TYPE_MISMATCH),
        })
    }

    /// Resolve an absolute NT path to its target object (spec §9), **following
    /// symbolic links**. A missing/non-directory *intermediate* component yields
    /// `STATUS_OBJECT_PATH_NOT_FOUND`; a missing *final* name yields
    /// `STATUS_OBJECT_NAME_NOT_FOUND`. The root path `\` returns the root.
    pub fn lookup_path(&self, path: &NtPath, case: CaseSensitivity) -> Result<ObjectRef, NtStatus> {
        self.lookup_path_ex(path, case, true)
    }

    /// Like [`lookup_path`](Self::lookup_path) but returns the symbolic-link
    /// object itself if the final component is a link (does not follow it) — the
    /// `OBJ_OPENLINK` behaviour, used to query a link.
    pub fn lookup_link(&self, path: &NtPath, case: CaseSensitivity) -> Result<ObjectRef, NtStatus> {
        self.lookup_path_ex(path, case, false)
    }

    /// Core path resolver. Intermediate symbolic links are always followed; the
    /// final component is followed only when `follow_final`. A symbolic link is
    /// followed by restarting resolution from the root with the link's target
    /// prepended to the remaining components; more than [`SYMLINK_LIMIT`]
    /// expansions in one lookup is treated as a loop (`STATUS_OBJECT_PATH_NOT_FOUND`).
    fn lookup_path_ex(
        &self,
        path: &NtPath,
        case: CaseSensitivity,
        follow_final: bool,
    ) -> Result<ObjectRef, NtStatus> {
        let root = self.root.clone().ok_or(NtStatus::OBJECT_PATH_NOT_FOUND)?;
        let mut comps: Vec<UnicodeString> = path.components().to_vec();
        let mut current = root.clone();
        let mut idx = 0usize;
        let mut hops = 0u32;

        while idx < comps.len() {
            let is_final = idx + 1 == comps.len();
            let step = current.with_body(|b| match b {
                ObjectBody::Directory(d) => Ok(d.lookup(&comps[idx], case)),
                _ => Err(()),
            });
            let child = match step {
                Err(()) => return Err(NtStatus::OBJECT_PATH_NOT_FOUND), // not a directory
                Ok(None) => {
                    return Err(if is_final {
                        NtStatus::OBJECT_NAME_NOT_FOUND
                    } else {
                        NtStatus::OBJECT_PATH_NOT_FOUND
                    })
                }
                Ok(Some(c)) => c,
            };

            let target = child.with_body(|b| match b {
                ObjectBody::SymbolicLink(s) => Some(s.target.clone()),
                _ => None,
            });
            match target {
                Some(t) if !is_final || follow_final => {
                    hops += 1;
                    if hops > SYMLINK_LIMIT {
                        return Err(NtStatus::OBJECT_PATH_NOT_FOUND); // loop / too many links
                    }
                    let mut rebuilt: Vec<UnicodeString> = t.components().to_vec();
                    rebuilt.extend_from_slice(&comps[idx + 1..]);
                    comps = rebuilt;
                    current = root.clone();
                    idx = 0;
                }
                _ => {
                    current = child;
                    idx += 1;
                }
            }
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
