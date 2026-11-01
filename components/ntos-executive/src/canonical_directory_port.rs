//! Owned Object Manager transport for native directory backing transactions.

use alloc::vec::Vec;
use nt_object_client::{
    DirectoryOwnedOutcome, DirectoryOwnedTerminal, HandleMutationOutcome,
    HandleMutationTerminal, ObjectClient, PendingDirectoryCall, PendingHandleMutation,
};
use nt_types::{AccessMask, HandleValue, ObjAttrFlags, UnicodeString};
use nt_user_host::canonical_directory_backing::{
    CanonicalHandle, DirectoryPort, PortCreate, PortEffect, PortTerminal,
};

use crate::{allocator, ObChan, OBJECT_CLIENT_PTR};

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_DEVICE_NOT_READY: u32 = 0xC000_00A3;

pub(crate) enum NativeDirectoryPending {
    Directory(PendingDirectoryCall),
    Mutation(PendingHandleMutation),
}

pub(crate) struct CanonicalDirectoryPort;

impl CanonicalDirectoryPort {
    pub(crate) const fn new() -> Self { Self }

    fn client(&mut self) -> Option<&mut ObjectClient<ObChan<'static>>> {
        // The executive's service loop serializes calls to the one Object
        // Manager channel. A pending owned call occupies that channel until
        // its exact completion is polled.
        unsafe { OBJECT_CLIENT_PTR.as_mut() }
    }

    fn name(path: &[u16]) -> Result<UnicodeString, u32> {
        let mut units = Vec::new();
        units.try_reserve_exact(path.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        units.extend_from_slice(path);
        Ok(UnicodeString::from_owned_units(units))
    }

    fn directory_outcome(outcome: DirectoryOwnedOutcome)
        -> PortCreate<HandleValue, NativeDirectoryPending> {
        match outcome {
            DirectoryOwnedOutcome::NoEffect(status) => PortCreate::NoEffect(status.raw() as u32),
            DirectoryOwnedOutcome::Completed(DirectoryOwnedTerminal::Success(result)) =>
                PortCreate::Completed(Ok(CanonicalHandle {
                    handle: result.handle,
                    created: result.created,
                })),
            DirectoryOwnedOutcome::Completed(DirectoryOwnedTerminal::Failure(status)) =>
                PortCreate::Completed(Err(status.raw() as u32)),
            DirectoryOwnedOutcome::Completed(DirectoryOwnedTerminal::Incoherent(_)) =>
                PortCreate::Incoherent,
            DirectoryOwnedOutcome::Indeterminate(pending) =>
                PortCreate::Indeterminate(NativeDirectoryPending::Directory(pending)),
        }
    }

    fn effect_outcome(outcome: HandleMutationOutcome)
        -> PortEffect<NativeDirectoryPending> {
        match outcome {
            HandleMutationOutcome::NoEffect(status) => PortEffect::NoEffect(status.raw() as u32),
            HandleMutationOutcome::Completed(HandleMutationTerminal::Success) =>
                PortEffect::Completed(Ok(())),
            HandleMutationOutcome::Completed(HandleMutationTerminal::Failure(status)) =>
                PortEffect::Completed(Err(status.raw() as u32)),
            HandleMutationOutcome::Completed(HandleMutationTerminal::Incoherent(_)) =>
                PortEffect::Incoherent,
            HandleMutationOutcome::Indeterminate(pending) =>
                PortEffect::Indeterminate(NativeDirectoryPending::Mutation(pending)),
        }
    }
}

impl DirectoryPort for CanonicalDirectoryPort {
    type Handle = HandleValue;
    type Pending = NativeDirectoryPending;

    fn create(&mut self, path: &[u16], desired_access: u32, attributes: u32)
        -> PortCreate<Self::Handle, Self::Pending> {
        let _durable = allocator::enter_durable();
        let name = match Self::name(path) {
            Ok(name) => name,
            Err(status) => return PortCreate::NoEffect(status),
        };
        let Some(client) = self.client() else {
            return PortCreate::NoEffect(STATUS_DEVICE_NOT_READY);
        };
        Self::directory_outcome(client.create_directory_handle_owned(None, &name,
            AccessMask::from_bits_retain(desired_access),
            ObjAttrFlags::from_bits_retain(attributes)))
    }

    fn open(&mut self, path: &[u16], desired_access: u32, attributes: u32)
        -> PortCreate<Self::Handle, Self::Pending> {
        let _durable = allocator::enter_durable();
        let name = match Self::name(path) {
            Ok(name) => name,
            Err(status) => return PortCreate::NoEffect(status),
        };
        let Some(client) = self.client() else {
            return PortCreate::NoEffect(STATUS_DEVICE_NOT_READY);
        };
        Self::directory_outcome(client.open_directory_handle_owned(None, &name,
            AccessMask::from_bits_retain(desired_access),
            ObjAttrFlags::from_bits_retain(attributes)))
    }

    fn poll_create(&mut self, pending: &mut Self::Pending)
        -> Option<PortTerminal<CanonicalHandle<Self::Handle>>> {
        let _durable = allocator::enter_durable();
        let NativeDirectoryPending::Directory(pending) = pending else {
            return Some(PortTerminal::Incoherent);
        };
        let client = self.client()?;
        client.poll_directory_handle_owned(pending).map(|terminal| match terminal {
            DirectoryOwnedTerminal::Success(result) => PortTerminal::Success(CanonicalHandle {
                handle: result.handle,
                created: result.created,
            }),
            DirectoryOwnedTerminal::Failure(status) => PortTerminal::Failure(status.raw() as u32),
            DirectoryOwnedTerminal::Incoherent(_) => PortTerminal::Incoherent,
        })
    }

    fn make_temporary(&mut self, handle: Self::Handle) -> PortEffect<Self::Pending> {
        let _durable = allocator::enter_durable();
        let Some(client) = self.client() else {
            return PortEffect::NoEffect(STATUS_DEVICE_NOT_READY);
        };
        Self::effect_outcome(client.make_temporary_owned(handle))
    }

    fn make_permanent(&mut self, handle: Self::Handle) -> PortEffect<Self::Pending> {
        let _durable = allocator::enter_durable();
        let Some(client) = self.client() else {
            return PortEffect::NoEffect(STATUS_DEVICE_NOT_READY);
        };
        Self::effect_outcome(client.make_permanent_owned(handle))
    }

    fn close(&mut self, handle: Self::Handle) -> PortEffect<Self::Pending> {
        let _durable = allocator::enter_durable();
        let Some(client) = self.client() else {
            return PortEffect::NoEffect(STATUS_DEVICE_NOT_READY);
        };
        Self::effect_outcome(client.close_handle_owned(handle))
    }

    fn poll_effect(&mut self, pending: &mut Self::Pending) -> Option<PortTerminal<()>> {
        let _durable = allocator::enter_durable();
        let NativeDirectoryPending::Mutation(pending) = pending else {
            return Some(PortTerminal::Incoherent);
        };
        let client = self.client()?;
        client.poll_handle_mutation_owned(pending).map(|terminal| match terminal {
            HandleMutationTerminal::Success => PortTerminal::Success(()),
            HandleMutationTerminal::Failure(status) => PortTerminal::Failure(status.raw() as u32),
            HandleMutationTerminal::Incoherent(_) => PortTerminal::Incoherent,
        })
    }
}
