//! Staged native directory-object opens over the executive's canonical namespace.

use super::*;

pub(super) struct StagedDirectoryObjectOpen {
    pub(super) publication: nt_process::ObjectDirectoryHandlePublication,
    pub(super) identity: u64,
    pub(super) created_index: Option<usize>,
    pub(super) cap_before: usize,
    pub(super) status: u32,
}

impl ExecNtHandler {
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
        let index = existing.or(created_index).expect("directory resolved or created");
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

    pub(super) fn abort_staged_directory_object_open(
        &mut self,
        staged: &mut StagedDirectoryObjectOpen,
    ) {
        assert_eq!(staged.publication.abort(&mut self.pm), Ok(Some(staged.identity)));
        if let Some(index) = staged.created_index {
            self.rollback_new_namespace_object(index);
        }
    }
}
