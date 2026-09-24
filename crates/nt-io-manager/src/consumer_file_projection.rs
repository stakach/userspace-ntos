//! A consumer driver's FILE_OBJECT pointer is independent of its opening handle.
//!
//! The owner supplies a component-local allocation and an exact hosted binding. This ledger
//! retains canonical File references for pointers handed to the consumer; it never treats a
//! handle value or a provider's pointer as an address in the consumer's VSpace.

use alloc::vec::Vec;
use nt_status::NtStatus;

use crate::{FileReference, HostedFileIdentity, IoManager};

#[derive(Debug)]
#[must_use = "retain the projection until its handle and pointer references are released"]
pub struct ConsumerFileProjection {
    identity: HostedFileIdentity,
    handle_open: bool,
    references: Vec<FileReference>,
}

impl ConsumerFileProjection {
    /// `identity` is the receipt from binding the consumer-local allocation, not a provider
    /// projection. The caller owns that allocation and its eventual unbind/free operation.
    pub fn new(identity: HostedFileIdentity) -> Result<Self, NtStatus> {
        if identity.file_id().raw() == 0
            || identity.address() == 0
            || identity.binding_generation() == 0
        {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(Self {
            identity,
            handle_open: true,
            references: Vec::new(),
        })
    }

    pub const fn identity(&self) -> HostedFileIdentity {
        self.identity
    }

    pub fn pointer_reference_count(&self) -> usize {
        self.references.len()
    }

    pub fn is_ready_to_retire(&self) -> bool {
        !self.handle_open && self.references.is_empty()
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

    fn opened() -> (IoManager<MockObjectPort>, HostedFileIdentity) {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\ConsumerProjection").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let path = NtPath::parse_str(r"\Device\ConsumerProjection").unwrap();
        io.create_device(
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
        let identity = io.bind_hosted_file_identity(domain, 0x5000, file).unwrap();
        (io, identity)
    }

    #[test]
    fn handle_close_does_not_retire_referenced_projection() {
        let (mut io, identity) = opened();
        let mut projection = ConsumerFileProjection::new(identity).unwrap();
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
    }

    #[test]
    fn stale_generation_cannot_mutate_replacement_projection() {
        let (mut io, first) = opened();
        let mut projection = ConsumerFileProjection::new(first).unwrap();
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
}
