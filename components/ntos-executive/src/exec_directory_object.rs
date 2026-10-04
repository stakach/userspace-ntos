//! Staged native directory-object opens over the executive's canonical namespace.

use super::*;

pub(crate) struct StagedDirectoryObjectOpen {
    pub(crate) publication: nt_process::ObjectDirectoryHandlePublication,
    pub(crate) identity: u64,
    pub(crate) created_index: Option<usize>,
    pub(crate) cap_before: usize,
    pub(crate) status: u32,
    pub(crate) security: directory_security::DirectorySecurityAdmission,
}

/// An invisible handle reservation with captured security and pinned namespace bodies. Handle
/// publication is deferred until the component's existing output protocol acknowledges it.
pub(crate) struct ReservedProviderDirectoryObject {
    publication: nt_process::ObjectDirectoryHandlePublication,
    cap_before: usize,
    created_index: Option<usize>,
    security: directory_security::DirectorySecurityAdmission,
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
        let _durable = allocator::enter_durable();
        const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
        if name.is_empty() || name.len() > NAMED_OBJECT_PATH_CAP {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let mut captured = CapturedNamedObjectAttributes {
            root,
            attributes,
            security_descriptor: 0,
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
        let mut security =
            self.prepare_directory_object_security(&captured, caller, desired_access, create)?;
        let handle_attributes = security.handle_attributes;
        let cap_before = self.pm.handle_capacity(caller.effective_process());
        let publication = match self
            .pm
            .reserve_native_object_directory_handle(caller, handle_attributes)
        {
            Ok(publication) => publication,
            Err(status) => {
                self.release_directory_object_security(&mut security);
                return Err(status);
            }
        };
        Ok(ReservedProviderDirectoryObject {
            publication,
            cap_before,
            created_index: None,
            security,
        })
    }

    pub(super) fn stage_native_directory_object_open(
        &mut self,
        captured: &CapturedNamedObjectAttributes,
        caller: nt_process::native_handle::NativeHandleCaller,
        desired_access: u32,
        create: bool,
    ) -> Result<StagedDirectoryObjectOpen, u32> {
        let _durable = allocator::enter_durable();
        let mut security =
            self.prepare_directory_object_security(captured, caller, desired_access, create)?;
        let handle_attributes = security.handle_attributes;
        let cap_before = self.pm.handle_capacity(caller.effective_process());
        let mut publication = match self
            .pm
            .reserve_native_object_directory_handle(caller, handle_attributes)
        {
            Ok(publication) => publication,
            Err(status) => {
                self.release_directory_object_security(&mut security);
                return Err(status);
            }
        };
        let (index, created) = match self.commit_directory_object_security(&mut security) {
            Ok(result) => result,
            Err(status) => {
                assert_eq!(publication.abort(&mut self.pm), Ok(None));
                self.release_directory_object_security(&mut security);
                return Err(status);
            }
        };
        let created_index = created.then_some(index);
        let identity = self.obj_ns[index].identity;
        let access = security.granted_access;
        if let Err(status) = publication.bind(&mut self.pm, identity, access) {
            assert_eq!(publication.abort(&mut self.pm), Ok(None));
            if let Some(index) = created_index {
                self.rollback_new_namespace_object(index);
            }
            self.release_directory_object_security(&mut security);
            return Err(status);
        }
        Ok(StagedDirectoryObjectOpen {
            publication,
            identity,
            created_index,
            cap_before,
            status: if security.opened_existing {
                0x4000_0000
            } else {
                0
            },
            security,
        })
    }

    pub(crate) fn publish_provider_directory_object(
        &mut self,
        staged: &mut ReservedProviderDirectoryObject,
        caller: nt_process::native_handle::NativeHandleCaller,
    ) -> Result<u32, u32> {
        let _durable = allocator::enter_durable();
        let result = (|| {
            if caller != staged.security.caller() {
                return Err(0xC000_0008);
            }
            self.pm.validate_native_handle_caller(caller)?;
            let (index, created) = self.commit_directory_object_security(&mut staged.security)?;
            staged.created_index = created.then_some(index);
            let identity = self.obj_ns[index].identity;
            let access = staged.security.granted_access;
            staged.publication.bind(&mut self.pm, identity, access)?;
            staged.publication.publish(&mut self.pm)?;
            self.record_process_handle_insert(staged.publication.process_id(), staged.cap_before);
            self.release_directory_object_security(&mut staged.security);
            Ok(if staged.security.opened_existing {
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
        self.release_directory_object_security(&mut staged.security);
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
        self.release_directory_object_security(&mut staged.security);
    }
}
