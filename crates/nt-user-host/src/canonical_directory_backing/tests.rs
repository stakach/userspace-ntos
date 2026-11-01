use super::*;
use nt_object_abi::ObReply;
use nt_object_client::{Backend, ObjectClient};
use nt_object_manager::ClientKind;
use nt_object_server::Server;
use nt_types::{AccessMask, AccessMode, ClientId, HandleValue, ObjAttrFlags, UnicodeString};

struct Direct<'a> { server: &'a mut Server, client: ClientId }

impl Backend for Direct<'_> {
    fn call(&mut self, op: u16, request: &[u8], response: &mut [u8]) -> ObReply {
        self.server.dispatch(self.client, op, request, response)
    }
}

impl DirectoryPort for ObjectClient<Direct<'_>> {
    type Handle = HandleValue;
    type Pending = ();

    fn create(&mut self, path: &[u16], access: u32, attributes: u32)
        -> PortCreate<Self::Handle, Self::Pending> {
        let name = UnicodeString::from_units(path);
        PortCreate::Completed(self.create_directory_handle(None, &name,
            AccessMask::from_bits_retain(access), ObjAttrFlags::from_bits_retain(attributes))
            .map(|result| CanonicalHandle { handle: result.handle, created: result.created })
            .map_err(|status| status.raw() as u32))
    }

    fn open(&mut self, path: &[u16], access: u32, attributes: u32)
        -> PortCreate<Self::Handle, Self::Pending> {
        let name = UnicodeString::from_units(path);
        PortCreate::Completed(self.open_directory_handle(None, &name,
            AccessMask::from_bits_retain(access), ObjAttrFlags::from_bits_retain(attributes))
            .map(|handle| CanonicalHandle { handle, created: false })
            .map_err(|status| status.raw() as u32))
    }

    fn poll_create(&mut self, _: &mut Self::Pending)
        -> Option<PortTerminal<CanonicalHandle<Self::Handle>>> {
        None
    }

    fn make_temporary(&mut self, handle: Self::Handle) -> PortEffect<Self::Pending> {
        PortEffect::Completed(ObjectClient::make_temporary(self, handle)
            .map_err(|status| status.raw() as u32))
    }

    fn make_permanent(&mut self, handle: Self::Handle) -> PortEffect<Self::Pending> {
        PortEffect::Completed(ObjectClient::make_permanent(self, handle)
            .map_err(|status| status.raw() as u32))
    }

    fn close(&mut self, handle: Self::Handle) -> PortEffect<Self::Pending> {
        PortEffect::Completed(self.close_handle(handle).map_err(|status| status.raw() as u32))
    }

    fn poll_effect(&mut self, _: &mut Self::Pending) -> Option<PortTerminal<()>> { None }
}

#[test]
fn native_directory_publication_must_make_device_child_visible_across_services() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut client = ObjectClient::new(Direct { server: &mut server, client: cid });
    let path: Vec<u16> = "\\Device\\Harddisk0".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, HandleValue, ()>::new();
    backing.reserve(7, DirectoryAction::Create, &path, AccessMask::GENERIC_ALL.bits(),
        (ObjAttrFlags::CASE_INSENSITIVE | ObjAttrFlags::PERMANENT).bits()).unwrap();
    assert_eq!(backing.publish(7, &mut client), Ok(Publication::Ready));
    backing.bind_local(7, 55).unwrap();
    client.create_device("\\Device\\Harddisk0\\DR0", 0x494f, 17, true).unwrap();
}

#[test]
fn open_if_shares_exact_backing_and_reaps_temporary_name_after_last_lease() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut client = ObjectClient::new(Direct { server: &mut server, client: cid });
    let path: Vec<u16> = "\\Device\\SharedDirectory".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, HandleValue, ()>::new();
    backing.reserve(9, DirectoryAction::Create, &path,
        (AccessMask::GENERIC_ALL | AccessMask::DELETE).bits(),
        (ObjAttrFlags::CASE_INSENSITIVE | ObjAttrFlags::PERMANENT).bits()).unwrap();
    assert_eq!(backing.publish(9, &mut client), Ok(Publication::Ready));
    let canonical = backing.bind_local(9, 123).unwrap();
    assert_eq!(backing.acquire_existing(123), Ok(canonical));
    assert_eq!(backing.lease_count(123), Some(2));
    assert_eq!(backing.make_temporary(123, &mut client), Ok(Publication::Ready));
    assert_eq!(backing.release_local(123, &mut client), Ok(Publication::Ready));
    assert_eq!(backing.lease_count(123), Some(1));
    assert!(client.lookup("\\Device\\SharedDirectory", true).is_ok());
    assert_eq!(backing.release_local(123, &mut client), Ok(Publication::Ready));
    assert!(backing.handle_for(123).is_none());
    assert!(client.lookup("\\Device\\SharedDirectory", true).is_err());
}

#[test]
fn temporary_directory_promotion_retains_name_after_last_local_lease() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut client = ObjectClient::new(Direct { server: &mut server, client: cid });
    let path: Vec<u16> = "\\Device\\PromotedDirectory".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, HandleValue, ()>::new();
    backing.reserve(15, DirectoryAction::Create, &path, AccessMask::GENERIC_READ.bits(),
        ObjAttrFlags::CASE_INSENSITIVE.bits()).unwrap();
    assert_eq!(backing.publish(15, &mut client), Ok(Publication::Ready));
    backing.bind_local(15, 125).unwrap();
    assert_eq!(backing.owner_for_local(125), Some(15));
    assert_eq!(backing.make_permanent(125, &mut client), Ok(Publication::Ready));
    assert_eq!(backing.release_local(125, &mut client), Ok(Publication::Ready));
    assert_eq!(backing.owner_for_local(125), Some(15));
    assert!(client.lookup("\\Device\\PromotedDirectory", true).is_ok());
    assert_eq!(backing.retire_terminal(15), Ok(()));
    assert_eq!(backing.owner_for_local(125), None);
}

#[test]
fn open_if_existing_temporary_directory_requires_real_promotion() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut client = ObjectClient::new(Direct { server: &mut server, client: cid });
    let name = UnicodeString::from_str("\\Device\\ExistingTemporary");
    let original = client.create_directory_handle(None, &name, AccessMask::DELETE,
        ObjAttrFlags::CASE_INSENSITIVE).unwrap().handle;
    let path: Vec<u16> = "\\Device\\ExistingTemporary".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, HandleValue, ()>::new();
    backing.reserve(19, DirectoryAction::Create, &path, AccessMask::DELETE.bits(),
        (ObjAttrFlags::CASE_INSENSITIVE | ObjAttrFlags::OPEN_IF
            | ObjAttrFlags::PERMANENT).bits()).unwrap();
    assert_eq!(backing.publish(19, &mut client), Ok(Publication::Ready));
    backing.bind_local(19, 128).unwrap();
    assert_eq!(backing.make_permanent(128, &mut client), Ok(Publication::Ready));
    client.close_handle(original).unwrap();
    assert_eq!(backing.release_local(128, &mut client), Ok(Publication::Ready));
    assert!(client.lookup("\\Device\\ExistingTemporary", true).is_ok());
}

#[test]
fn existing_boot_directory_uses_open_and_retains_canonical_name() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut client = ObjectClient::new(Direct { server: &mut server, client: cid });
    let name = UnicodeString::from_str("\\Device\\BootExisting");
    let first = client.create_directory_handle(None, &name, AccessMask::GENERIC_ALL,
        ObjAttrFlags::CASE_INSENSITIVE | ObjAttrFlags::PERMANENT).unwrap();
    let path: Vec<u16> = "\\Device\\BootExisting".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, HandleValue, ()>::new();
    backing.reserve(10, DirectoryAction::Open, &path, AccessMask::GENERIC_READ.bits(),
        ObjAttrFlags::CASE_INSENSITIVE.bits()).unwrap();
    assert_eq!(backing.publish(10, &mut client), Ok(Publication::Ready));
    backing.bind_local(10, 124).unwrap();
    client.close_handle(first.handle).unwrap();
    assert_eq!(backing.release_local(124, &mut client), Ok(Publication::Ready));
    assert!(client.lookup("\\Device\\BootExisting", true).is_ok());
    assert_eq!(backing.retire_terminal(10), Ok(()));
}

#[test]
fn concurrent_case_variant_name_cannot_cross_an_unsettled_canonical_operation() {
    let first: Vec<u16> = "\\Device\\PendingName".encode_utf16().collect();
    let alias: Vec<u16> = "\\device\\pendingname".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, HandleValue, ()>::new();
    backing.reserve(1, DirectoryAction::Create, &first, 0, 0).unwrap();
    assert_eq!(backing.reserve(2, DirectoryAction::Create, &alias, 0, 0),
        Err(BackingError::PathOccupied));
}

#[test]
fn abort_before_effect_frees_exact_reservation_but_never_submitted_request() {
    let path: Vec<u16> = "\\Device\\AbortReservation".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, u64, u64>::new();
    backing.reserve(21, DirectoryAction::Create, &path, 0, 0).unwrap();
    assert_eq!(backing.reserve(22, DirectoryAction::Create, &path, 0, 0),
        Err(BackingError::PathOccupied));
    assert_eq!(backing.abort_before_effect(21), Ok(()));
    assert_eq!(backing.abort_before_effect(21), Err(BackingError::WrongOwner));
    backing.reserve(22, DirectoryAction::Create, &path, 0, 0).unwrap();

    let mut port = DelayedPort { create_calls: 0, close_calls: 0,
        create_ready: false, close_ready: false, incoherent: false };
    assert_eq!(backing.publish(22, &mut port), Ok(Publication::Pending));
    assert_eq!(backing.abort_before_effect(22), Err(BackingError::InvalidPhase));
    assert_eq!(backing.reserve(23, DirectoryAction::Create, &path, 0, 0),
        Err(BackingError::PathOccupied));
    assert_eq!(port.create_calls, 1);
}

#[test]
fn definite_native_commit_failure_rolls_back_permanent_canonical_name() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut client = ObjectClient::new(Direct { server: &mut server, client: cid });
    let path: Vec<u16> = "\\Device\\RollbackDirectory".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, HandleValue, ()>::new();
    backing.reserve(11, DirectoryAction::Create, &path,
        AccessMask::GENERIC_READ.bits(),
        (ObjAttrFlags::CASE_INSENSITIVE | ObjAttrFlags::PERMANENT).bits()).unwrap();
    assert_eq!(backing.publish(11, &mut client), Ok(Publication::Ready));
    assert!(client.lookup("\\Device\\RollbackDirectory", true).is_ok());
    assert_eq!(backing.rollback_ready(11, &mut client), Ok(Publication::Ready));
    assert!(client.lookup("\\Device\\RollbackDirectory", true).is_err());
    assert_eq!(backing.retire_terminal(11), Ok(()));
}

struct DelayedPort { create_calls: u32, close_calls: u32, create_ready: bool, close_ready: bool,
    incoherent: bool }

impl DirectoryPort for DelayedPort {
    type Handle = u64;
    type Pending = u64;
    fn create(&mut self, _: &[u16], _: u32, _: u32) -> PortCreate<u64, u64> {
        self.create_calls += 1;
        PortCreate::Indeterminate(41)
    }
    fn open(&mut self, _: &[u16], _: u32, _: u32) -> PortCreate<u64, u64> {
        self.create(&[], 0, 0)
    }
    fn poll_create(&mut self, pending: &mut u64) -> Option<PortTerminal<CanonicalHandle<u64>>> {
        assert_eq!(*pending, 41);
        if !self.create_ready { return None; }
        Some(if self.incoherent { PortTerminal::Incoherent } else {
            PortTerminal::Success(CanonicalHandle { handle: 77, created: true })
        })
    }
    fn make_temporary(&mut self, _: u64) -> PortEffect<u64> {
        PortEffect::Completed(Ok(()))
    }
    fn make_permanent(&mut self, _: u64) -> PortEffect<u64> {
        PortEffect::Completed(Ok(()))
    }
    fn close(&mut self, handle: u64) -> PortEffect<u64> {
        assert_eq!(handle, 77);
        self.close_calls += 1;
        PortEffect::Indeterminate(42)
    }
    fn poll_effect(&mut self, pending: &mut u64) -> Option<PortTerminal<()>> {
        assert_eq!(*pending, 42);
        self.close_ready.then_some(PortTerminal::Success(()))
    }
}

#[test]
fn uncertain_create_and_close_hold_exact_owner_without_replay() {
    let mut port = DelayedPort { create_calls: 0, close_calls: 0,
        create_ready: false, close_ready: false, incoherent: false };
    let path: Vec<u16> = "\\Device\\Delayed".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, u64, u64>::new();
    backing.reserve(1, DirectoryAction::Create, &path, 0, 0).unwrap();
    assert_eq!(backing.publish(1, &mut port), Ok(Publication::Pending));
    assert_eq!(backing.publish(1, &mut port), Err(BackingError::InvalidPhase));
    assert_eq!(backing.reserve(2, DirectoryAction::Create, &path, 0, 0),
        Err(BackingError::PathOccupied));
    assert_eq!(backing.poll_publish(1, &mut port), Ok(None));
    port.create_ready = true;
    assert_eq!(backing.poll_publish(1, &mut port), Ok(Some(Publication::Ready)));
    assert_eq!(port.create_calls, 1);
    backing.bind_local(1, 5).unwrap();
    assert_eq!(backing.release_local(5, &mut port), Ok(Publication::Pending));
    assert_eq!(backing.release_local(5, &mut port), Err(BackingError::InvalidPhase));
    assert_eq!(backing.poll_close(5, &mut port), Ok(None));
    port.close_ready = true;
    assert_eq!(backing.poll_close(5, &mut port), Ok(Some(Publication::Ready)));
    assert_eq!(port.close_calls, 1);
    backing.retire_terminal(1).unwrap();
}

#[test]
fn incoherent_late_create_quarantines_path_and_owner() {
    let mut port = DelayedPort { create_calls: 0, close_calls: 0,
        create_ready: true, close_ready: false, incoherent: true };
    let path: Vec<u16> = "\\Device\\Quarantined".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, u64, u64>::new();
    backing.reserve(1, DirectoryAction::Create, &path, 0, 0).unwrap();
    assert_eq!(backing.publish(1, &mut port), Ok(Publication::Pending));
    assert_eq!(backing.poll_publish(1, &mut port), Err(BackingError::EffectUncertain));
    assert_eq!(backing.retire_terminal(1), Err(BackingError::InvalidPhase));
    assert_eq!(backing.reserve(2, DirectoryAction::Create, &path, 0, 0),
        Err(BackingError::PathOccupied));
    assert_eq!(port.create_calls, 1);
}

struct DelayedPromotionPort {
    promote_calls: u32,
    close_calls: u32,
    ready: bool,
    incoherent: bool,
}

impl DirectoryPort for DelayedPromotionPort {
    type Handle = u64;
    type Pending = u64;

    fn create(&mut self, _: &[u16], _: u32, _: u32) -> PortCreate<u64, u64> {
        PortCreate::Completed(Ok(CanonicalHandle { handle: 77, created: true }))
    }
    fn open(&mut self, _: &[u16], _: u32, _: u32) -> PortCreate<u64, u64> {
        PortCreate::Completed(Ok(CanonicalHandle { handle: 77, created: false }))
    }
    fn poll_create(&mut self, _: &mut u64) -> Option<PortTerminal<CanonicalHandle<u64>>> {
        None
    }
    fn make_temporary(&mut self, _: u64) -> PortEffect<u64> {
        PortEffect::Completed(Ok(()))
    }
    fn make_permanent(&mut self, handle: u64) -> PortEffect<u64> {
        assert_eq!(handle, 77);
        self.promote_calls += 1;
        PortEffect::Indeterminate(45)
    }
    fn close(&mut self, handle: u64) -> PortEffect<u64> {
        assert_eq!(handle, 77);
        self.close_calls += 1;
        PortEffect::Completed(Ok(()))
    }
    fn poll_effect(&mut self, pending: &mut u64) -> Option<PortTerminal<()>> {
        assert_eq!(*pending, 45);
        self.ready.then_some(if self.incoherent { PortTerminal::Incoherent }
            else { PortTerminal::Success(()) })
    }
}

#[test]
fn uncertain_promotion_retains_handle_and_does_not_replay() {
    let path: Vec<u16> = "\\Device\\LatePromotion".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, u64, u64>::new();
    let mut port = DelayedPromotionPort {
        promote_calls: 0, close_calls: 0, ready: false, incoherent: false,
    };
    backing.reserve(16, DirectoryAction::Create, &path, 0, 0).unwrap();
    assert_eq!(backing.publish(16, &mut port), Ok(Publication::Ready));
    backing.bind_local(16, 126).unwrap();
    assert_eq!(backing.make_permanent(126, &mut port), Ok(Publication::Pending));
    assert_eq!(backing.make_permanent(126, &mut port), Err(BackingError::InvalidPhase));
    assert_eq!(backing.release_local(126, &mut port), Err(BackingError::InvalidPhase));
    assert_eq!(backing.poll_make_permanent(126, &mut port), Ok(None));
    assert_eq!(port.promote_calls, 1);
    port.ready = true;
    assert_eq!(backing.poll_make_permanent(126, &mut port), Ok(Some(Publication::Ready)));
    assert_eq!(backing.make_permanent(126, &mut port), Ok(Publication::Ready));
    assert_eq!(port.promote_calls, 1);
    assert_eq!(backing.release_local(126, &mut port), Ok(Publication::Ready));
    assert_eq!(port.close_calls, 1);
}

#[test]
fn incoherent_promotion_quarantines_exact_handle_and_path() {
    let path: Vec<u16> = "\\Device\\BadPromotion".encode_utf16().collect();
    let mut backing = CanonicalDirectoryBackings::<u64, u64, u64, u64>::new();
    let mut port = DelayedPromotionPort {
        promote_calls: 0, close_calls: 0, ready: true, incoherent: true,
    };
    backing.reserve(17, DirectoryAction::Create, &path, 0, 0).unwrap();
    assert_eq!(backing.publish(17, &mut port), Ok(Publication::Ready));
    backing.bind_local(17, 127).unwrap();
    assert_eq!(backing.make_permanent(127, &mut port), Ok(Publication::Pending));
    assert_eq!(backing.poll_make_permanent(127, &mut port), Err(BackingError::EffectUncertain));
    assert_eq!(backing.quarantined_handle(17), Some(77));
    assert_eq!(backing.release_local(127, &mut port), Err(BackingError::InvalidPhase));
    assert_eq!(backing.reserve(18, DirectoryAction::Create, &path, 0, 0),
        Err(BackingError::PathOccupied));
    assert_eq!(port.promote_calls, 1);
    assert_eq!(port.close_calls, 0);
}
