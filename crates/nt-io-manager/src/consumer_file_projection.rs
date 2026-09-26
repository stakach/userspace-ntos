//! A consumer driver's FILE_OBJECT pointer is independent of its opening handle.
//!
//! The owner supplies a component-local allocation and an exact hosted binding. This ledger
//! retains canonical File references for pointers handed to the consumer; it never treats a
//! handle value or a provider's pointer as an address in the consumer's VSpace.

use alloc::vec::Vec;
use nt_status::NtStatus;

use crate::{
    DeviceId, FileId, FileReference, FileState, HostedDevicePointerRegistration, HostedFileIdentity,
    HostedFileUnbindOutcome, IoManager, WdmFileObjectInit, WDM_X64_FILE_OBJECT_SIZE,
};

/// Fields that can be copied into a consumer-domain FILE_OBJECT. FsContext and the related
/// File are provider-owned state and must be recovered through the canonical File identity.
pub struct ConsumerFileMetadata {
    pub file_name: Vec<u16>,
    pub create_options: u32,
    pub opened_case_sensitive: bool,
}

pub fn consumer_file_metadata<P>(
    io: &IoManager<P>,
    file_id: FileId,
    device_id: DeviceId,
) -> Result<ConsumerFileMetadata, NtStatus> {
    let file = io.file(file_id).ok_or(NtStatus::INVALID_HANDLE)?;
    if file.device_id != device_id || file.state != FileState::Open {
        return Err(NtStatus::INVALID_HANDLE);
    }
    let units = file.file_name.as_units();
    let mut file_name = Vec::new();
    file_name.try_reserve_exact(units.len())
        .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
    file_name.extend_from_slice(units);
    Ok(ConsumerFileMetadata {
        file_name,
        create_options: file.create_options.bits(),
        opened_case_sensitive: file.opened_case_sensitive(),
    })
}

/// Initialize a File body in the consumer's address space from exact canonical bindings.
/// Provider FsContext is deliberately not projected into a different address space.
pub fn write_consumer_wdm_file_object<P>(
    io: &IoManager<P>,
    identity: HostedFileIdentity,
    device: HostedDevicePointerRegistration,
    bytes: &mut [u8],
) -> Result<(), NtStatus> {
    if identity.domain() != device.domain()
        || io.hosted_file_identity_at(identity.domain(), identity.file_id(), identity.address())?
            != Some(identity)
        || io.hosted_device_pointer_registration(device.domain(), device.address()) != Some(device)
    {
        return Err(NtStatus::INVALID_HANDLE);
    }
    let metadata = consumer_file_metadata(io, identity.file_id(), device.device_id())?;
    if bytes.len() < WDM_X64_FILE_OBJECT_SIZE {
        return Err(NtStatus::BUFFER_TOO_SMALL);
    }
    crate::write_wdm_file_object(
        bytes,
        WdmFileObjectInit {
            file_object_address: identity.address(),
            opened_case_sensitive: metadata.opened_case_sensitive,
            create_options: metadata.create_options,
            device_object: device.address(),
            fs_context: 0,
            related_file_object: 0,
            file_name_len: 0,
            file_name_max_len: 0,
            file_name_buffer: 0,
        },
    )
    .map_err(|_| NtStatus::INVALID_PARAMETER)
}

#[derive(Debug)]
#[must_use = "retain the projection until its handle and pointer references are released"]
pub struct ConsumerFileProjection {
    identity: HostedFileIdentity,
    device: HostedDevicePointerRegistration,
    handle_open: bool,
    references: Vec<FileReference>,
    file_bound: bool,
    device_pointer_held: bool,
}

impl ConsumerFileProjection {
    /// Both receipts identify allocations in the consumer's domain. The caller owns those
    /// allocations; this ledger pins the registered DeviceObject until FileObject retirement.
    pub fn new<P>(
        io: &mut IoManager<P>,
        identity: HostedFileIdentity,
        device: HostedDevicePointerRegistration,
    ) -> Result<Self, NtStatus> {
        if identity.file_id().raw() == 0
            || identity.address() == 0
            || identity.binding_generation() == 0
            || identity.domain() != device.domain()
            || io.hosted_file_identity_at(
                identity.domain(), identity.file_id(), identity.address(),
            )? != Some(identity)
            || io.file(identity.file_id()).is_none_or(|file| {
                file.device_id != device.device_id() || file.state != FileState::Open
            })
            || io.hosted_device_pointer_registration(device.domain(), device.address())
                != Some(device)
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        io.reference_hosted_device_pointer(device)?;
        Ok(Self {
            identity,
            device,
            handle_open: true,
            references: Vec::new(),
            file_bound: true,
            device_pointer_held: true,
        })
    }

    pub const fn identity(&self) -> HostedFileIdentity {
        self.identity
    }

    pub const fn device_registration(&self) -> HostedDevicePointerRegistration {
        self.device
    }

    /// Only the registered consumer-local address may appear in FileObject.DeviceObject.
    pub fn related_device_address<P>(&self, io: &IoManager<P>) -> Result<u64, NtStatus> {
        self.validate_live(io)?;
        Ok(self.device.address())
    }

    pub fn pointer_reference_count(&self) -> usize {
        self.references.len()
    }

    pub fn is_ready_to_retire(&self) -> bool {
        !self.handle_open && self.references.is_empty()
    }

    fn validate_live<P>(&self, io: &IoManager<P>) -> Result<(), NtStatus> {
        if !self.file_bound
            || !self.device_pointer_held
            || io.hosted_file_identity_at(
                self.identity.domain(), self.identity.file_id(), self.identity.address(),
            )? != Some(self.identity)
            || io.hosted_device_pointer_registration(self.device.domain(), self.device.address())
                != Some(self.device)
        {
            return Err(NtStatus::INVALID_HANDLE);
        }
        Ok(())
    }

    /// Called only after an authenticated, typed File-handle lookup. Retain the canonical File
    /// before returning a pointer; a failed acquisition never changes the local count.
    pub fn reference_by_handle<P>(
        &mut self,
        io: &mut IoManager<P>,
        identity: HostedFileIdentity,
    ) -> Result<u64, NtStatus> {
        if identity != self.identity || !self.handle_open {
            return Err(NtStatus::INVALID_HANDLE);
        }
        self.validate_live(io)?;
        self.retain(io)
    }

    /// `ObfReferenceObject` can duplicate a live pointer after the opening handle has closed.
    pub fn reference_by_pointer<P>(
        &mut self,
        io: &mut IoManager<P>,
        identity: HostedFileIdentity,
    ) -> Result<u64, NtStatus> {
        if identity != self.identity || self.references.is_empty() {
            return Err(NtStatus::INVALID_HANDLE);
        }
        self.validate_live(io)?;
        self.retain(io)
    }

    fn retain<P>(&mut self, io: &mut IoManager<P>) -> Result<u64, NtStatus> {
        self.references
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
        let owner = io.retain_file_reference(self.identity.file_id())?;
        self.references.push(owner);
        Ok(self.identity.address())
    }

    /// The caller closes the typed table handle first, then records that exact close here. This
    /// does not release pointer references or authorize freeing the consumer-local allocation.
    pub fn handle_closed(&mut self, identity: HostedFileIdentity) -> Result<(), NtStatus> {
        if identity != self.identity || !self.handle_open {
            return Err(NtStatus::INVALID_HANDLE);
        }
        self.handle_open = false;
        Ok(())
    }

    /// Release one pointer reference through its issuing manager. A failed checked release leaves
    /// the owner in the row, so neither the count nor the allocation can be retired prematurely.
    pub fn dereference<P>(
        &mut self,
        io: &mut IoManager<P>,
        identity: HostedFileIdentity,
    ) -> Result<(), NtStatus> {
        if identity != self.identity {
            return Err(NtStatus::INVALID_HANDLE);
        }
        let owner = self.references.last_mut().ok_or(NtStatus::INVALID_HANDLE)?;
        io.release_file_reference(owner)?;
        self.references.pop();
        Ok(())
    }

    /// Checked retirement is retryable: a publication lease may delay unbind, and a failed
    /// DeviceObject dereference retains its exact registration until it can be retried.
    pub fn retire<P>(&mut self, io: &mut IoManager<P>) -> Result<(), NtStatus> {
        if !self.is_ready_to_retire() || !self.device_pointer_held {
            return Err(NtStatus::DEVICE_BUSY);
        }
        if self.file_bound {
            if io.unbind_hosted_file_identity(self.identity)? != HostedFileUnbindOutcome::Removed {
                return Err(NtStatus::INVALID_HANDLE);
            }
            self.file_bound = false;
        }
        io.dereference_hosted_device_pointer(self.device)?;
        self.device_pointer_held = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use crate::{
        CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend,
        MockObjectPort, ShareAccess,
    };
    use nt_types::{AccessMask, NtPath};

    fn opened() -> (
        IoManager<MockObjectPort>, HostedFileIdentity, HostedDevicePointerRegistration,
    ) {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\ConsumerProjection").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let path = NtPath::parse_str(r"\Device\ConsumerProjection").unwrap();
        let device = io.create_device(
            driver,
            Some(&path),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
        let handle = io
            .open(
                client,
                &path,
                AccessMask::GENERIC_READ,
                ShareAccess::READ,
                CreateOptions::empty(),
                0,
            )
            .unwrap();
        let file = io
            .reference_open_file(client, handle, AccessMask::empty())
            .unwrap()
            .0;
        let domain = io.register_hosted_domain();
        let registration = io.bind_hosted_device_pointer(domain, 0x6000, device).unwrap();
        let identity = io.bind_hosted_file_identity(domain, 0x5000, file).unwrap();
        (io, identity, registration)
    }

    #[test]
    fn provider_context_is_opaque_to_consumer_file_metadata() {
        let (mut io, identity, device) = opened();
        io.file_mut(identity.file_id()).unwrap().driver_context = Some(0xdead_beef);
        let metadata = consumer_file_metadata(&io, identity.file_id(), device.device_id()).unwrap();
        assert!(!metadata.file_name.is_empty());
        assert_eq!(metadata.create_options, CreateOptions::empty().bits());
        assert_eq!(io.file(identity.file_id()).unwrap().driver_context, Some(0xdead_beef));

        let mut projection = ConsumerFileProjection::new(&mut io, identity, device).unwrap();
        assert_eq!(projection.reference_by_handle(&mut io, identity), Ok(identity.address()));
        projection.handle_closed(identity).unwrap();
        assert!(!projection.is_ready_to_retire());
        projection.dereference(&mut io, identity).unwrap();
        projection.retire(&mut io).unwrap();
    }

    #[test]
    fn consumer_file_body_uses_local_device_and_never_provider_context() {
        let (mut io, identity, device) = opened();
        io.file_mut(identity.file_id()).unwrap().driver_context = Some(0xdead_beef);
        let mut bytes = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
        write_consumer_wdm_file_object(&io, identity, device, &mut bytes).unwrap();
        let word = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        assert_eq!(word(0x08), device.address());
        assert_eq!(word(0x18), 0);
        assert_eq!(word(0x98 + 8), identity.address() + 0x98 + 8);
        assert_eq!(word(0x98 + 0x10), identity.address() + 0x98 + 8);
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), 5);
    }

    #[test]
    fn stale_file_binding_cannot_modify_consumer_file_body() {
        let (mut io, stale, device) = opened();
        assert_eq!(io.unbind_hosted_file_identity(stale), Ok(HostedFileUnbindOutcome::Removed));
        let current = io
            .bind_hosted_file_identity(stale.domain(), stale.address(), stale.file_id())
            .unwrap();
        assert_ne!(stale, current);
        let mut bytes = [0xa5; WDM_X64_FILE_OBJECT_SIZE];
        assert_eq!(
            write_consumer_wdm_file_object(&io, stale, device, &mut bytes),
            Err(NtStatus::INVALID_HANDLE),
        );
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
        write_consumer_wdm_file_object(&io, current, device, &mut bytes).unwrap();
        assert_eq!(u64::from_le_bytes(bytes[0x08..0x10].try_into().unwrap()), device.address());
    }

    #[test]
    fn stale_file_binding_cannot_authorize_consumer_projection() {
        let (mut io, stale, device) = opened();
        assert_eq!(
            io.unbind_hosted_file_identity(stale),
            Ok(HostedFileUnbindOutcome::Removed),
        );
        let current = io.bind_hosted_file_identity(
            stale.domain(), stale.address(), stale.file_id(),
        ).unwrap();
        assert_ne!(stale, current);
        assert_eq!(
            ConsumerFileProjection::new(&mut io, stale, device).err(),
            Some(NtStatus::INVALID_PARAMETER),
        );
        assert_eq!(io.hosted_device_pointer_count(device), Ok(0));
        assert_eq!(
            consumer_file_metadata(&io, FileId::NULL, device.device_id()).err(),
            Some(NtStatus::INVALID_HANDLE),
        );
        assert_eq!(
            consumer_file_metadata(&io, current.file_id(), DeviceId::NULL).err(),
            Some(NtStatus::INVALID_HANDLE),
        );
    }

    #[test]
    fn handle_close_does_not_retire_referenced_projection() {
        let (mut io, identity, device) = opened();
        let mut projection = ConsumerFileProjection::new(&mut io, identity, device).unwrap();
        assert_eq!(projection.related_device_address(&io), Ok(0x6000));
        assert_eq!(io.hosted_device_pointer_count(device), Ok(1));
        assert_eq!(projection.reference_by_handle(&mut io, identity), Ok(0x5000));
        assert_eq!(io.file_reference_count(identity.file_id()), 1);
        projection.handle_closed(identity).unwrap();
        assert!(!projection.is_ready_to_retire());
        assert_eq!(projection.reference_by_handle(&mut io, identity), Err(NtStatus::INVALID_HANDLE));
        assert_eq!(projection.reference_by_pointer(&mut io, identity), Ok(0x5000));
        assert_eq!(io.file_reference_count(identity.file_id()), 2);
        projection.dereference(&mut io, identity).unwrap();
        assert!(!projection.is_ready_to_retire());
        projection.dereference(&mut io, identity).unwrap();
        assert!(projection.is_ready_to_retire());
        assert_eq!(io.file_reference_count(identity.file_id()), 0);
        assert_eq!(projection.dereference(&mut io, identity), Err(NtStatus::INVALID_HANDLE));
        projection.retire(&mut io).unwrap();
        assert_eq!(io.hosted_device_pointer_count(device), Ok(0));
        assert_eq!(io.hosted_file_by_identity(identity.domain(), identity.address()), None);
    }

    #[test]
    fn stale_generation_cannot_mutate_replacement_projection() {
        let (mut io, first, device) = opened();
        let mut projection = ConsumerFileProjection::new(&mut io, first, device).unwrap();
        let second = {
            let domain = io.register_hosted_domain();
            io.bind_hosted_file_identity(domain, first.address(), first.file_id())
                .unwrap()
        };
        assert_ne!(first, second);
        assert_eq!(projection.reference_by_handle(&mut io, second), Err(NtStatus::INVALID_HANDLE));
        assert_eq!(projection.handle_closed(second), Err(NtStatus::INVALID_HANDLE));
        assert_eq!(projection.dereference(&mut io, second), Err(NtStatus::INVALID_HANDLE));
        assert_eq!(projection.pointer_reference_count(), 0);
        assert!(!projection.is_ready_to_retire());
    }

    #[test]
    fn device_projection_cannot_retire_while_file_projection_is_live() {
        let (mut io, identity, device) = opened();
        let mut projection = ConsumerFileProjection::new(&mut io, identity, device).unwrap();
        assert_eq!(io.unregister_hosted_device_pointer(device), Err(NtStatus::DEVICE_BUSY));
        projection.handle_closed(identity).unwrap();
        projection.retire(&mut io).unwrap();
        io.unregister_hosted_device_pointer(device).unwrap();
    }

    #[test]
    fn file_publication_lease_delays_projection_retirement() {
        let (mut io, identity, device) = opened();
        let mut projection = ConsumerFileProjection::new(&mut io, identity, device).unwrap();
        let mut lease = io.lease_hosted_file_identity(identity).unwrap();
        projection.handle_closed(identity).unwrap();
        assert_eq!(projection.retire(&mut io), Err(NtStatus::DELETE_PENDING));
        assert_eq!(io.hosted_device_pointer_count(device), Ok(1));
        io.release_hosted_file_publication(&mut lease).unwrap();
        projection.retire(&mut io).unwrap();
    }

    #[test]
    fn mismatched_device_binding_cannot_authorize_file_pointer() {
        let (mut io, identity, device) = opened();
        let other_domain = io.register_hosted_domain();
        let foreign = io.bind_hosted_device_pointer(other_domain, 0x6000, device.device_id()).unwrap();
        assert_eq!(
            ConsumerFileProjection::new(&mut io, identity, foreign).err(),
            Some(NtStatus::INVALID_PARAMETER),
        );
        assert_eq!(io.hosted_device_pointer_count(foreign), Ok(0));
    }
}
