//! Staged native directory-object opens over the executive's canonical namespace.

use super::*;

pub(crate) struct StagedDirectoryObjectOpen {
    pub(crate) publication: nt_process::ObjectDirectoryHandlePublication,
    pub(crate) identity: u64,
    pub(crate) created_index: Option<usize>,
    pub(crate) cap_before: usize,
    pub(crate) status: u32,
}

/// An invisible handle reservation. Namespace resolution is deferred until PUBLISH, after the
/// component has written the handle output to its caller.
pub(crate) struct ReservedProviderDirectoryObject {
    publication: nt_process::ObjectDirectoryHandlePublication,
    captured: CapturedNamedObjectAttributes,
    desired_access: u32,
    create: bool,
    cap_before: usize,
    created_index: Option<usize>,
}

impl ReservedProviderDirectoryObject {
    pub(crate) fn value(&self) -> u64 {
        self.publication.value()
    }
}

impl ExecNtHandler {
    /// The provider upload carries UTF-16, but the current native namespace is ASCII-only.
    pub(crate) fn reserve_provider_directory_object(
        &mut self,
        root: u64,
        attributes: u32,
        name: &[u16],
        caller: nt_process::native_handle::NativeHandleCaller,
        desired_access: u32,
        create: bool,
    ) -> Result<ReservedProviderDirectoryObject, u32> {
        const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
        if name.is_empty() || name.len() > NAMED_OBJECT_PATH_CAP {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let mut captured = CapturedNamedObjectAttributes {
            root,
            attributes,
            path_len: Some(name.len()),
            path: [0; NAMED_OBJECT_PATH_CAP],
        };
        for (index, &unit) in name.iter().enumerate() {
            if unit == 0 || unit > 0x7f {
                return Err(STATUS_OBJECT_NAME_INVALID);
            }
            captured.path[index] = (unit as u8).to_ascii_lowercase();
        }
        let mut components = captured.path[..name.len()].split(|&byte| byte == b'\\');
        if captured.path[0] == b'\\' {
            components.next();
        }
        if components.any(|component| component.is_empty() || component.len() > OBJ_NAME_CAP) {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let handle_attributes = attributes & (nt_process::native_handle::OBJ_KERNEL_HANDLE | 0x2);
        let cap_before = self.pm.handle_capacity(caller.effective_process());
        let publication = self
            .pm
            .reserve_native_object_directory_handle(caller, handle_attributes)?;
        Ok(ReservedProviderDirectoryObject {
            publication,
            captured,
            desired_access,
            create,
            cap_before,
            created_index: None,
        })
    }

    pub(super) fn stage_native_directory_object_open(
        &mut self,
        captured: &CapturedNamedObjectAttributes,
        caller: nt_process::native_handle::NativeHandleCaller,
        desired_access: u32,
        create: bool,
    ) -> Result<StagedDirectoryObjectOpen, u32> {
        let path = captured.path().ok_or(0xC000_0033u32)?;
        let permanent = captured.attributes & OBJ_PERMANENT != 0;
        let (root_idx, path) = self.native_directory_root_and_path(caller, captured.root, path)?;
        let mut opened_existing = false;
        let existing = if create {
            match self.obj_resolve(path, root_idx) {
                Some(index) if self.obj_ns[index].kind == OBJ_KIND_DIRECTORY => {
                    if captured.attributes & 0x80 == 0 {
                        return Err(0xC000_0035); // STATUS_OBJECT_NAME_COLLISION
                    }
                    opened_existing = true;
                    Some(index)
                }
                Some(_) => return Err(0xC000_0024), // STATUS_OBJECT_TYPE_MISMATCH
                None => None,
            }
        } else {
            let index = self.obj_resolve(path, root_idx).ok_or(0xC000_0034u32)?;
            if self.obj_ns[index].kind != OBJ_KIND_DIRECTORY {
                return Err(0xC000_0024); // STATUS_OBJECT_TYPE_MISMATCH
            }
            Some(index)
        };
        let handle_attributes =
            captured.attributes & (nt_process::native_handle::OBJ_KERNEL_HANDLE | 0x2);
        let cap_before = self.pm.handle_capacity(caller.effective_process());
        let mut publication = self
            .pm
            .reserve_native_object_directory_handle(caller, handle_attributes)?;
        let created_index = if existing.is_none() {
            match self.obj_create(path, root_idx, OBJ_KIND_DIRECTORY, &[], permanent) {
                Some(index) => Some(index),
                None => {
                    assert_eq!(publication.abort(&mut self.pm), Ok(None));
                    return Err(0xC000_003A); // STATUS_OBJECT_PATH_NOT_FOUND
                }
            }
        } else {
            None
        };
        let index = existing
            .or(created_index)
            .expect("directory resolved or created");
        let identity = self.obj_ns[index].identity;
        let access = Self::map_directory_object_access(desired_access);
        if let Err(status) = publication.bind(&mut self.pm, identity, access) {
            assert_eq!(publication.abort(&mut self.pm), Ok(None));
            if let Some(index) = created_index {
                self.rollback_new_namespace_object(index);
            }
            return Err(status);
        }
        Ok(StagedDirectoryObjectOpen {
            publication,
            identity,
            created_index,
            cap_before,
            status: if opened_existing { 0x4000_0000 } else { 0 },
        })
    }

    pub(crate) fn publish_provider_directory_object(
        &mut self,
        staged: &mut ReservedProviderDirectoryObject,
        caller: nt_process::native_handle::NativeHandleCaller,
    ) -> Result<u32, u32> {
        let result = (|| {
            let path = staged.captured.path().ok_or(0xC000_0033u32)?;
            let (root_idx, path) =
                self.native_directory_root_and_path(caller, staged.captured.root, path)?;
            let existing = if staged.create {
                match self.obj_resolve(path, root_idx) {
                    Some(index) if self.obj_ns[index].kind == OBJ_KIND_DIRECTORY => {
                        if staged.captured.attributes & 0x80 == 0 {
                            return Err(0xC000_0035); // STATUS_OBJECT_NAME_COLLISION
                        }
                        Some(index)
                    }
                    Some(_) => return Err(0xC000_0024), // STATUS_OBJECT_TYPE_MISMATCH
                    None => None,
                }
            } else {
                let index = self.obj_resolve(path, root_idx).ok_or(0xC000_0034u32)?;
                if self.obj_ns[index].kind != OBJ_KIND_DIRECTORY {
                    return Err(0xC000_0024);
                }
                Some(index)
            };
            let index = match existing {
                Some(index) => index,
                None => {
                    let permanent = staged.captured.attributes & OBJ_PERMANENT != 0;
                    let index = self
                        .obj_create(path, root_idx, OBJ_KIND_DIRECTORY, &[], permanent)
                        .ok_or(0xC000_003Au32)?; // STATUS_OBJECT_PATH_NOT_FOUND
                    staged.created_index = Some(index);
                    index
                }
            };
            let identity = self.obj_ns[index].identity;
            let access = Self::map_directory_object_access(staged.desired_access);
            staged.publication.bind(&mut self.pm, identity, access)?;
            staged.publication.publish(&mut self.pm)?;
            self.record_process_handle_insert(staged.publication.process_id(), staged.cap_before);
            Ok(if staged.create && existing.is_some() {
                0x4000_0000
            } else {
                0
            })
        })();
        if result.is_err() {
            self.abort_reserved_provider_directory_object(staged);
        }
        result
    }

    pub(crate) fn abort_reserved_provider_directory_object(
        &mut self,
        staged: &mut ReservedProviderDirectoryObject,
    ) {
        staged
            .publication
            .abort(&mut self.pm)
            .expect("unpublished directory reservation remains owned");
        if let Some(index) = staged.created_index.take() {
            self.rollback_new_namespace_object(index);
        }
    }

    pub(crate) fn close_provider_directory_object(
        &mut self,
        caller: nt_process::native_handle::NativeHandleCaller,
        handle: u64,
    ) -> Result<(), u32> {
        let identity = match self.pm.close_native_object_directory_handle(caller, handle) {
            Ok(identity) => identity,
            Err(nt_process::native_handle::NativePsCloseError::Status(status)) => {
                return Err(status)
            }
            Err(nt_process::native_handle::NativePsCloseError::BugCheck { .. }) => {
                panic!("protected kernel directory handle close")
            }
        };
        self.release_directory_namespace_reference(identity);
        PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub(crate) fn abort_staged_directory_object_open(
        &mut self,
        staged: &mut StagedDirectoryObjectOpen,
    ) {
        assert_eq!(
            staged.publication.abort(&mut self.pm),
            Ok(Some(staged.identity))
        );
        if let Some(index) = staged.created_index {
            if index + 1 == self.obj_ns.len() {
                self.rollback_new_namespace_object(index);
            } else if self
                .pm
                .handle_object_count(nt_process::HandleObject::ObjectDirectory(staged.identity))
                == 0
            {
                self.obj_ns[index].unlink();
            }
        }
    }
}
