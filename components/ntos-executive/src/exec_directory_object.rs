//! Staged native directory-object opens over the executive's canonical namespace.

use super::*;
use nt_user_host::canonical_directory_backing::{BackingError, DirectoryAction, Publication};

pub(crate) enum DirectoryPublishProgress { Ready(u32), Pending, Failed(u32) }

/// An invisible handle reservation with captured security and pinned namespace bodies. Handle
/// publication is deferred until the component's existing output protocol acknowledges it.
pub(crate) struct ReservedDirectoryObjectOpen {
    publication: nt_process::ObjectDirectoryHandlePublication,
    cap_before: usize,
    created_index: Option<usize>,
    security: directory_security::DirectorySecurityAdmission,
    canonical: CanonicalDirectoryReservation,
    canonical_pending: bool,
    rollback_failure: Option<u32>,
    rollback_pending: bool,
    canonical_quarantined: bool,
    canonical_acquired: bool,
    cleanup_credit: bool,
    local_committed: bool,
    local_status: u32,
    local_identity: Option<u64>,
    native_aborted: bool,
}

pub(crate) type ReservedProviderDirectoryObject = ReservedDirectoryObjectOpen;

#[derive(Clone, Copy)]
enum CanonicalDirectoryReservation {
    Existing(u64),
    Reserved(u64),
}

impl ReservedDirectoryObjectOpen {
    pub(crate) fn value(&self) -> u64 {
        self.publication.value()
    }

    pub(crate) fn rollback_failure_status(&self) -> Option<u32> {
        self.rollback_failure
    }

    /// An uncertain canonical effect retains ownership but has no safe retry or timer wake.
    pub(crate) fn canonical_retryable(&self) -> bool {
        !self.canonical_quarantined
    }
}

fn backing_status(error: BackingError) -> u32 {
    match error {
        BackingError::NoMemory => 0xC000_009A,
        BackingError::PathOccupied => 0xC000_0035,
        BackingError::InvalidPath => 0xC000_0033,
        BackingError::NoEffect(status) | BackingError::Terminal(status) => status,
        BackingError::DuplicateOwner | BackingError::WrongOwner
        | BackingError::InvalidPhase | BackingError::LocalIdentityCollision
        | BackingError::EffectUncertain => 0xC000_0008,
    }
}

impl ExecNtHandler {
    fn canonical_directory_path(
        &self,
        security: &directory_security::DirectorySecurityAdmission,
    ) -> Result<Vec<u16>, u32> {
        let (parent, leaf) = security.parent_and_leaf();
        let mut parent_path = [0u8; NAMED_OBJECT_PATH_CAP];
        let parent_len = self.object_namespace_path_exact(parent, &mut parent_path)
            .ok_or(0xC000_0033u32)?;
        let separator = usize::from(parent_len > 1 && !leaf.is_empty());
        let length = parent_len.checked_add(separator).and_then(|n| n.checked_add(leaf.len()))
            .ok_or(0xC000_0033u32)?;
        if length > NAMED_OBJECT_PATH_CAP { return Err(0xC000_0033); }
        let mut path = Vec::new();
        path.try_reserve_exact(length).map_err(|_| 0xC000_009Au32)?;
        path.extend(parent_path[..parent_len].iter().map(|&unit| u16::from(unit)));
        if separator != 0 { path.push(b'\\' as u16); }
        path.extend(leaf.iter().map(|&unit| u16::from(unit)));
        Ok(path)
    }

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
        let security =
            self.prepare_directory_object_security(&captured, caller, desired_access, create)?;
        self.reserve_directory_object_open_from_security(security, caller, attributes)
    }

    pub(crate) fn reserve_native_directory_object_open(
        &mut self,
        captured: &CapturedNamedObjectAttributes,
        caller: nt_process::native_handle::NativeHandleCaller,
        desired_access: u32,
        create: bool,
    ) -> Result<ReservedDirectoryObjectOpen, u32> {
        let _durable = allocator::enter_durable();
        let security = self.prepare_directory_object_security(captured, caller, desired_access, create)?;
        self.reserve_directory_object_open_from_security(security, caller, captured.attributes)
    }

    fn reserve_directory_object_open_from_security(
        &mut self,
        mut security: directory_security::DirectorySecurityAdmission,
        caller: nt_process::native_handle::NativeHandleCaller,
        attributes: u32,
    ) -> Result<ReservedDirectoryObjectOpen, u32> {
        let canonical_path = match self.canonical_directory_path(&security) {
            Ok(path) => path,
            Err(status) => {
                self.release_directory_object_security(&mut security);
                return Err(status);
            }
        };
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
        let canonical = if let Some(identity) = security.existing_identity()
            .filter(|&identity| self.canonical_directories.owner_for_local(identity).is_some())
        {
            CanonicalDirectoryReservation::Existing(identity)
        } else {
            let owner = self.directory_next_owner;
            let next = owner.checked_add(1).ok_or(0xC000_009Au32);
            let result = next.and_then(|next| {
                self.directory_next_owner = next;
                let action = if security.existing_identity().is_some() {
                    DirectoryAction::Open
                } else {
                    DirectoryAction::Create
                };
                self.canonical_directories.reserve(owner, action, &canonical_path,
                    nt_types::AccessMask::GENERIC_ALL.bits(), attributes)
                    .map_err(backing_status)?;
                Ok(owner)
            });
            match result {
                Ok(owner) => CanonicalDirectoryReservation::Reserved(owner),
                Err(status) => {
                    let mut publication = publication;
                    assert_eq!(publication.abort(&mut self.pm), Ok(None));
                    self.release_directory_object_security(&mut security);
                    return Err(status);
                }
            }
        };
        Ok(ReservedProviderDirectoryObject {
            publication,
            cap_before,
            created_index: None,
            security,
            canonical,
            canonical_pending: false,
            rollback_failure: None,
            rollback_pending: false,
            canonical_quarantined: false,
            canonical_acquired: false,
            cleanup_credit: false,
            local_committed: false,
            local_status: 0,
            local_identity: None,
            native_aborted: false,
        })
    }

    pub(crate) fn publish_provider_directory_object(
        &mut self,
        staged: &mut ReservedProviderDirectoryObject,
        caller: nt_process::native_handle::NativeHandleCaller,
    ) -> DirectoryPublishProgress {
        match self.canonical_publish_directory_object(staged, caller) {
            DirectoryPublishProgress::Ready(_) => self.finish_provider_directory_local(staged),
            other => other,
        }
    }

    pub(crate) fn canonical_publish_directory_object(
        &mut self,
        staged: &mut ReservedDirectoryObjectOpen,
        caller: nt_process::native_handle::NativeHandleCaller,
    ) -> DirectoryPublishProgress {
        let _durable = allocator::enter_durable();
        if caller != staged.security.caller()
            || self.pm.validate_native_handle_caller(caller).is_err()
        {
            return if self.abort_reserved_provider_directory_object(staged) {
                DirectoryPublishProgress::Failed(0xC000_0008)
            } else { DirectoryPublishProgress::Pending };
        }
        match staged.canonical {
            CanonicalDirectoryReservation::Existing(_) => DirectoryPublishProgress::Ready(0),
            CanonicalDirectoryReservation::Reserved(owner) => {
                let mut port = crate::canonical_directory_port::CanonicalDirectoryPort::new();
                match self.canonical_directories.publish(owner, &mut port) {
                    Ok(Publication::Ready) => DirectoryPublishProgress::Ready(0),
                    Ok(Publication::Pending) => {
                        staged.canonical_pending = true;
                        DirectoryPublishProgress::Pending
                    }
                    Err(BackingError::EffectUncertain) => {
                        staged.canonical_quarantined = true;
                        DirectoryPublishProgress::Pending
                    }
                    Err(error) => {
                        if self.abort_reserved_provider_directory_object(staged) {
                            DirectoryPublishProgress::Failed(backing_status(error))
                        } else { DirectoryPublishProgress::Pending }
                    }
                }
            }
        }
    }

    pub(crate) fn poll_provider_directory_object(
        &mut self,
        staged: &mut ReservedProviderDirectoryObject,
    ) -> DirectoryPublishProgress {
        match self.canonical_poll_directory_object(staged) {
            DirectoryPublishProgress::Ready(_) => self.finish_provider_directory_local(staged),
            other => other,
        }
    }

    pub(crate) fn canonical_poll_directory_object(
        &mut self,
        staged: &mut ReservedDirectoryObjectOpen,
    ) -> DirectoryPublishProgress {
        let _durable = allocator::enter_durable();
        if staged.canonical_quarantined { return DirectoryPublishProgress::Pending; }
        if let CanonicalDirectoryReservation::Existing(identity) = staged.canonical {
            let Some(failure) = staged.rollback_failure else {
                return DirectoryPublishProgress::Failed(0xC000_0008);
            };
            let mut port = crate::canonical_directory_port::CanonicalDirectoryPort::new();
            let result = if staged.rollback_pending {
                self.canonical_directories.poll_close(identity, &mut port)
            } else {
                self.canonical_directories.release_local(identity, &mut port).map(Some)
            };
            return match result {
                Ok(Some(Publication::Ready)) => {
                    staged.canonical_acquired = false;
                    if self.abort_reserved_provider_directory_object(staged) {
                        DirectoryPublishProgress::Failed(failure)
                    } else { DirectoryPublishProgress::Pending }
                }
                Ok(None) | Ok(Some(Publication::Pending)) => {
                    staged.rollback_pending = true;
                    DirectoryPublishProgress::Pending
                }
                Err(BackingError::NoEffect(_)) | Err(BackingError::Terminal(_)) => {
                    staged.rollback_pending = false;
                    DirectoryPublishProgress::Pending
                }
                Err(_) => {
                    staged.canonical_quarantined = true;
                    DirectoryPublishProgress::Pending
                }
            };
        }
        let CanonicalDirectoryReservation::Reserved(owner) = staged.canonical else {
            return DirectoryPublishProgress::Failed(0xC000_0008);
        };
        let mut port = crate::canonical_directory_port::CanonicalDirectoryPort::new();
        if let Some(failure) = staged.rollback_failure {
            let result = if staged.rollback_pending {
                self.canonical_directories.poll_rollback(owner, &mut port)
            } else {
                self.canonical_directories.rollback_ready(owner, &mut port).map(Some)
            };
            return match result {
                Ok(Some(Publication::Ready)) => {
                    staged.canonical_acquired = false;
                    if self.abort_reserved_provider_directory_object(staged) {
                        DirectoryPublishProgress::Failed(failure)
                    } else { DirectoryPublishProgress::Pending }
                }
                Ok(None) | Ok(Some(Publication::Pending)) => {
                    staged.rollback_pending = true;
                    DirectoryPublishProgress::Pending
                }
                Err(BackingError::EffectUncertain) => {
                    staged.canonical_quarantined = true;
                    DirectoryPublishProgress::Pending
                }
                Err(BackingError::NoEffect(_)) | Err(BackingError::Terminal(_)) => {
                    staged.rollback_pending = false;
                    DirectoryPublishProgress::Pending
                }
                Err(_) => {
                    staged.canonical_quarantined = true;
                    DirectoryPublishProgress::Pending
                }
            };
        }
        if !staged.canonical_pending { return DirectoryPublishProgress::Failed(0xC000_0008); }
        match self.canonical_directories.poll_publish(owner, &mut port) {
            Ok(Some(Publication::Ready)) => {
                staged.canonical_pending = false;
                DirectoryPublishProgress::Ready(0)
            }
            Ok(None) | Ok(Some(Publication::Pending)) => DirectoryPublishProgress::Pending,
            Err(BackingError::EffectUncertain) => {
                staged.canonical_quarantined = true;
                DirectoryPublishProgress::Pending
            }
            Err(error) => {
                staged.canonical_pending = false;
                if self.abort_reserved_provider_directory_object(staged) {
                    DirectoryPublishProgress::Failed(backing_status(error))
                } else { DirectoryPublishProgress::Pending }
            }
        }
    }

    fn finish_provider_directory_local(
        &mut self,
        staged: &mut ReservedProviderDirectoryObject,
    ) -> DirectoryPublishProgress {
        match self.commit_directory_local(staged) {
            DirectoryPublishProgress::Ready(_) => self.publish_directory_local(staged),
            other => other,
        }
    }

    pub(crate) fn commit_directory_local(
        &mut self,
        staged: &mut ReservedDirectoryObjectOpen,
    ) -> DirectoryPublishProgress {
        let _durable = allocator::enter_durable();
        if staged.local_committed { return DirectoryPublishProgress::Ready(staged.local_status); }
        let result = (|| {
            self.pm.validate_native_handle_caller(staged.security.caller())?;
            let (index, created) = self.commit_directory_object_security(&mut staged.security)?;
            staged.created_index = created.then_some(index);
            let identity = self.obj_ns[index].identity;
            if !staged.cleanup_credit {
                self.directory_cleanup.reserve().map_err(|_| 0xC000_009Au32)?;
                staged.cleanup_credit = true;
            }
            if let CanonicalDirectoryReservation::Existing(expected) = staged.canonical {
                if identity != expected { return Err(0xC000_0008); }
                self.canonical_directories.acquire_existing(identity).map_err(backing_status)?;
                staged.canonical_acquired = true;
            }
            let access = staged.security.granted_access;
            staged.publication.bind(&mut self.pm, identity, access)?;
            if let CanonicalDirectoryReservation::Reserved(owner) = staged.canonical {
                self.canonical_directories.bind_local(owner, identity).map_err(backing_status)?;
                staged.canonical_acquired = true;
            }
            staged.local_status = if staged.security.opened_existing { 0x4000_0000 } else { 0 };
            staged.local_identity = Some(identity);
            staged.local_committed = true;
            self.release_directory_object_security(&mut staged.security);
            Ok(staged.local_status)
        })();
        match result {
            Ok(status) => DirectoryPublishProgress::Ready(status),
            Err(status) => self.rollback_unpublished_directory_open(staged, status),
        }
    }

    /// The reserved native handle becomes visible only after the caller's output protocol
    /// has accepted its value. The provider's op 4 upload acknowledges that value before op 5.
    pub(crate) fn publish_directory_local(
        &mut self,
        staged: &mut ReservedDirectoryObjectOpen,
    ) -> DirectoryPublishProgress {
        if !staged.local_committed { return DirectoryPublishProgress::Failed(0xC000_0008); }
        match staged.publication.publish(&mut self.pm) {
            Ok(_) => {
                self.record_process_handle_insert(staged.publication.process_id(), staged.cap_before);
                DirectoryPublishProgress::Ready(staged.local_status)
            }
            Err(status) => self.rollback_unpublished_directory_open(staged, status),
        }
    }

    /// Retire an invisible native directory reservation after a definite local or output
    /// failure. A pending canonical cleanup retains the reservation and its exact owner.
    pub(crate) fn rollback_unpublished_directory_open(
        &mut self,
        staged: &mut ReservedDirectoryObjectOpen,
        status: u32,
    ) -> DirectoryPublishProgress {
        if !staged.native_aborted {
            if staged.publication.abort(&mut self.pm).is_err() {
                staged.canonical_quarantined = true;
                return DirectoryPublishProgress::Pending;
            }
            staged.native_aborted = true;
        }
        if let CanonicalDirectoryReservation::Existing(identity) = staged.canonical {
            if staged.canonical_acquired {
                let mut port = crate::canonical_directory_port::CanonicalDirectoryPort::new();
                match self.canonical_directories.release_local(identity, &mut port) {
                    Ok(Publication::Ready) => staged.canonical_acquired = false,
                    Ok(Publication::Pending) => {
                        staged.rollback_failure = Some(status);
                        staged.rollback_pending = true;
                        return DirectoryPublishProgress::Pending;
                    }
                    Err(BackingError::NoEffect(_)) | Err(BackingError::Terminal(_)) => {
                        staged.rollback_failure = Some(status);
                        staged.rollback_pending = false;
                        return DirectoryPublishProgress::Pending;
                    }
                    Err(_) => {
                        staged.canonical_quarantined = true;
                        return DirectoryPublishProgress::Pending;
                    }
                }
            }
            return if self.abort_reserved_provider_directory_object(staged) {
                DirectoryPublishProgress::Failed(status)
            } else { DirectoryPublishProgress::Pending };
        }
        let CanonicalDirectoryReservation::Reserved(owner) = staged.canonical else { unreachable!() };
        let mut port = crate::canonical_directory_port::CanonicalDirectoryPort::new();
        let rollback = if staged.canonical_acquired {
            let Some(identity) = staged.local_identity else {
                staged.canonical_quarantined = true;
                return DirectoryPublishProgress::Pending;
            };
            self.canonical_directories.rollback_bound(identity, &mut port)
        } else {
            self.canonical_directories.rollback_ready(owner, &mut port)
        };
        match rollback {
            Ok(Publication::Ready) => {
                staged.canonical_acquired = false;
                if self.abort_reserved_provider_directory_object(staged) {
                    DirectoryPublishProgress::Failed(status)
                } else { DirectoryPublishProgress::Pending }
            }
            Ok(Publication::Pending) => {
                staged.rollback_failure = Some(status);
                staged.rollback_pending = true;
                DirectoryPublishProgress::Pending
            }
            Err(BackingError::NoEffect(_)) | Err(BackingError::Terminal(_)) => {
                staged.rollback_failure = Some(status);
                staged.rollback_pending = false;
                DirectoryPublishProgress::Pending
            }
            Err(BackingError::EffectUncertain) => {
                staged.canonical_quarantined = true;
                DirectoryPublishProgress::Pending
            }
            Err(_) => {
                staged.canonical_quarantined = true;
                DirectoryPublishProgress::Pending
            }
        }
    }

    pub(crate) fn abort_reserved_provider_directory_object(
        &mut self,
        staged: &mut ReservedProviderDirectoryObject,
    ) -> bool {
        if staged.canonical_pending || staged.canonical_quarantined
            || (staged.local_committed && !staged.native_aborted)
        {
            return false;
        }
        if !staged.native_aborted && staged.publication.abort(&mut self.pm).is_err() {
            staged.canonical_quarantined = true;
            return false;
        }
        staged.native_aborted = true;
        if let CanonicalDirectoryReservation::Reserved(owner) = staged.canonical {
            if self.canonical_directories.abort_before_effect(owner).is_err()
                && self.canonical_directories.retire_terminal(owner).is_err()
            {
                staged.canonical_quarantined = true;
                return false;
            }
        } else if let CanonicalDirectoryReservation::Existing(identity) = staged.canonical {
            if self.canonical_directories.lease_count(identity) == Some(0) {
                let Some(owner) = self.canonical_directories.owner_for_local(identity) else {
                    staged.canonical_quarantined = true;
                    return false;
                };
                if self.canonical_directories.retire_terminal(owner).is_err() {
                    staged.canonical_quarantined = true;
                    return false;
                }
            }
        }
        if staged.cleanup_credit {
            if staged.canonical_acquired { return false; }
            self.directory_cleanup.cancel();
            staged.cleanup_credit = false;
        }
        if let Some(index) = staged.created_index.take() {
            self.rollback_new_namespace_object(index);
        }
        self.release_directory_object_security(&mut staged.security);
        true
    }

    pub(crate) fn provider_directory_effect_identity(
        &self,
        caller: nt_process::native_handle::NativeHandleCaller,
        handle: u64,
        required_access: u32,
    ) -> Result<u64, u32> {
        let identity = self.pm.lookup_native_object_directory_handle(
            caller, handle, required_access)?;
        self.directory_namespace_index_for_identity(identity)?;
        if self.canonical_directories.owner_for_local(identity).is_none() {
            return Err(0xC000_0008);
        }
        Ok(identity)
    }

    pub(crate) fn close_provider_directory_native_handle(
        &mut self,
        caller: nt_process::native_handle::NativeHandleCaller,
        handle: u64,
        expected: u64,
    ) -> Result<(), u32> {
        if self.provider_directory_effect_identity(caller, handle, 0)? != expected {
            return Err(0xC000_0008);
        }
        let identity = match self.pm.close_native_object_directory_handle(caller, handle) {
            Ok(identity) => identity,
            Err(nt_process::native_handle::NativePsCloseError::Status(status)) => {
                return Err(status)
            }
            Err(nt_process::native_handle::NativePsCloseError::BugCheck { .. }) => {
                panic!("protected kernel directory handle close")
            }
        };
        debug_assert_eq!(identity, expected, "single-threaded PM close changed identity");
        // This provider-owned retained effect now owns close completion directly.
        // Its publication credit need not enter the generic detached queue.
        self.directory_cleanup.cancel();
        PM_HANDLES_CLOSED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub(crate) fn release_provider_directory_canonical(
        &mut self,
        identity: u64,
    ) -> Result<Publication, BackingError> {
        let mut port = crate::canonical_directory_port::CanonicalDirectoryPort::new();
        self.canonical_directories.release_local(identity, &mut port)
    }

    pub(crate) fn poll_provider_directory_canonical_close(
        &mut self,
        identity: u64,
    ) -> Result<Option<Publication>, BackingError> {
        let mut port = crate::canonical_directory_port::CanonicalDirectoryPort::new();
        self.canonical_directories.poll_close(identity, &mut port)
    }

    pub(crate) fn finish_provider_directory_close(&mut self, identity: u64) -> Result<(), u32> {
        let index = self.directory_namespace_index_for_identity(identity)?;
        if self.pm.handle_object_count(nt_process::HandleObject::ObjectDirectory(identity)) == 0 {
            self.obj_delete_name_check(index);
        }
        if self.canonical_directories.lease_count(identity) == Some(0) {
            let owner = self.canonical_directories.owner_for_local(identity)
                .ok_or(0xC000_0008u32)?;
            self.canonical_directories.retire_terminal(owner)
                .map_err(backing_status)?;
        }
        Ok(())
    }

    pub(crate) fn make_temporary_provider_directory_canonical(
        &mut self,
        identity: u64,
    ) -> Result<Publication, BackingError> {
        let mut port = crate::canonical_directory_port::CanonicalDirectoryPort::new();
        self.canonical_directories.make_temporary(identity, &mut port)
    }

    pub(crate) fn poll_provider_directory_make_temporary(
        &mut self,
        identity: u64,
    ) -> Result<Option<Publication>, BackingError> {
        let mut port = crate::canonical_directory_port::CanonicalDirectoryPort::new();
        self.canonical_directories.poll_make_temporary(identity, &mut port)
    }

    pub(crate) fn finish_provider_directory_make_temporary(
        &mut self,
        identity: u64,
    ) -> Result<(), u32> {
        let index = self.directory_namespace_index_for_identity(identity)?;
        let entry = self.obj_ns.get_mut(index).ok_or(0xC000_0008u32)?;
        if !entry.is_live() || entry.kind != OBJ_KIND_DIRECTORY || entry.identity != identity {
            return Err(0xC000_0008);
        }
        // The handle still owns the body. Its eventual close removes the nonpermanent name
        // once child and wait references have released their exact directory identity.
        entry.permanent = false;
        Ok(())
    }

}
