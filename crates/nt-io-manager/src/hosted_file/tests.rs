use super::*;
use crate::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceId, DeviceType, MockDriverBackend,
    MockObjectPort, ShareAccess,
};
use alloc::boxed::Box;
use nt_types::{AccessMask, ClientId, NtPath};

struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
    domain: HostedDomainIdentity,
    device: DeviceId,
    file: FileId,
}

impl Fixture {
    fn new() -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\FileBindings").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                Some(&NtPath::parse_str(r"\Device\FileBindings").unwrap()),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let handle = io
            .open(
                client,
                &NtPath::parse_str(r"\Device\FileBindings").unwrap(),
                AccessMask::GENERIC_READ,
                ShareAccess::READ | ShareAccess::WRITE,
                CreateOptions::empty(),
                1,
            )
            .unwrap();
        let file = io
            .reference_open_file(client, handle, AccessMask::empty())
            .unwrap()
            .0;
        let domain = io.register_hosted_domain();
        Self {
            io,
            client,
            domain,
            device,
            file,
        }
    }

    fn another_file(&mut self) -> FileId {
        let handle = self
            .io
            .open(
                self.client,
                &NtPath::parse_str(r"\Device\FileBindings").unwrap(),
                AccessMask::GENERIC_READ,
                ShareAccess::READ | ShareAccess::WRITE,
                CreateOptions::empty(),
                1,
            )
            .unwrap();
        self.io
            .reference_open_file(self.client, handle, AccessMask::empty())
            .unwrap()
            .0
    }

    fn bind(&mut self, address: u64) -> HostedFileIdentity {
        self.io
            .bind_hosted_file_identity(self.domain, address, self.file)
            .unwrap()
    }
}

#[test]
fn exact_replay_and_generation_receipts_prevent_same_tuple_aba() {
    let mut f = Fixture::new();
    let first = f.bind(0x5000);
    assert_eq!(first.domain(), f.domain);
    assert_eq!(first.file_id(), f.file);
    assert_eq!(first.address(), 0x5000);
    assert_ne!(first.binding_generation(), 0);
    assert_eq!(f.bind(0x5000), first);
    assert_eq!(
        f.io.unbind_hosted_file_identity(first),
        Ok(HostedFileUnbindOutcome::Removed)
    );
    assert_eq!(
        f.io.unbind_hosted_file_identity(first),
        Ok(HostedFileUnbindOutcome::AlreadyAbsent)
    );
    let replacement = f.bind(0x5000);
    assert_ne!(replacement, first);
    assert!(replacement.binding_generation() > first.binding_generation());
    assert_eq!(
        f.io.unbind_hosted_file_identity(first),
        Ok(HostedFileUnbindOutcome::AlreadyAbsent)
    );
    assert_eq!(
        f.io.lease_hosted_file_identity(first).unwrap_err(),
        NtStatus::INVALID_PARAMETER
    );
    assert_eq!(
        f.io.hosted_file_identities(f.file),
        Ok(alloc::vec![replacement])
    );
}

#[test]
fn projections_are_one_to_one_per_domain_but_snapshots_span_domains() {
    let mut f = Fixture::new();
    let first = f.bind(0x5000);
    let other = f.another_file();
    assert_eq!(
        f.io.bind_hosted_file_identity(f.domain, 0x5008, f.file),
        Err(NtStatus::OBJECT_NAME_COLLISION)
    );
    assert_eq!(
        f.io.bind_hosted_file_identity(f.domain, 0x5000, other),
        Err(NtStatus::OBJECT_NAME_COLLISION)
    );
    let second_domain = f.io.register_hosted_domain();
    let second =
        f.io.bind_hosted_file_identity(second_domain, 0x5000, f.file)
            .unwrap();
    f.io.bind_hosted_file_identity(second_domain, 0x5010, other)
        .unwrap();
    f.io.device_mut(f.device).unwrap().delete_pending = true;
    f.io.device_mut(f.device).unwrap().top_of_stack = DeviceId::NULL;
    let snapshot = f.io.hosted_file_identities(f.file).unwrap();
    assert_eq!(snapshot.len(), 2);
    assert!(snapshot.contains(&first));
    assert!(snapshot.contains(&second));
    assert!(f.io.has_hosted_file_bindings(f.file));
    assert_eq!(
        f.io.hosted_file_address_by_identity(f.domain, f.file),
        Some(0x5000)
    );
    assert_eq!(
        f.io.hosted_file_by_identity(second_domain, 0x5010),
        Some(other)
    );
    assert_eq!(
        f.io.hosted_file_identities(FileId::NULL),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert!(!f.io.has_hosted_file_bindings(FileId::NULL));
}

#[test]
fn retired_receipt_cannot_remove_address_reused_by_another_file() {
    let mut f = Fixture::new();
    let retired = f.bind(0x5000);
    f.io.unbind_hosted_file_identity(retired).unwrap();
    let other = f.another_file();
    let replacement =
        f.io.bind_hosted_file_identity(f.domain, 0x5000, other)
            .unwrap();
    assert_eq!(
        f.io.unbind_hosted_file_identity(retired),
        Ok(HostedFileUnbindOutcome::AlreadyAbsent)
    );
    assert_eq!(
        f.io.hosted_file_identities(other),
        Ok(alloc::vec![replacement])
    );
    assert_eq!(f.io.hosted_file_by_identity(f.domain, 0x5000), Some(other));
    assert!(!f.io.has_hosted_file_bindings(f.file));
}

#[test]
fn foreign_managers_and_stale_domain_generations_cannot_consume_receipts_or_leases() {
    let mut first = Fixture::new();
    let mut second = Fixture::new();
    let receipt = first.bind(0x5000);
    let foreign = second.bind(0x5000);
    assert_eq!(receipt.domain(), foreign.domain());
    assert_ne!(receipt, foreign);
    assert_eq!(
        second.io.unbind_hosted_file_identity(receipt),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        second.io.lease_hosted_file_identity(receipt).unwrap_err(),
        NtStatus::INVALID_PARAMETER
    );
    let mut lease = first.io.lease_hosted_file_identity(receipt).unwrap();
    assert_eq!(
        second.io.release_hosted_file_publication(&mut lease),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert!(lease.is_held());
    first
        .io
        .release_hosted_file_publication(&mut lease)
        .unwrap();
    first.io.unbind_hosted_file_identity(receipt).unwrap();
    first.io.unregister_hosted_domain(first.domain).unwrap();
    let replacement_domain = first.io.register_hosted_domain();
    assert_eq!(
        replacement_domain.domain_id.slot(),
        first.domain.domain_id.slot()
    );
    let replacement = first
        .io
        .bind_hosted_file_identity(replacement_domain, 0x5000, first.file)
        .unwrap();
    assert_eq!(
        first.io.unbind_hosted_file_identity(receipt),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(first.io.hosted_file_by_identity(first.domain, 0x5000), None);
    assert_eq!(
        first.io.hosted_file_identities(first.file),
        Ok(alloc::vec![replacement])
    );
}

#[test]
fn explicit_leases_pin_projection_without_taking_file_pointer_references() {
    let mut f = Fixture::new();
    let receipt = f.bind(0x5000);
    let references = f.io.file_reference_count(f.file);
    let mut first = f.io.lease_hosted_file_identity(receipt).unwrap();
    let mut second = f.io.lease_hosted_file_identity(receipt).unwrap();
    assert_eq!(first.identity(), receipt);
    assert_eq!(f.io.file_reference_count(f.file), references);
    assert_eq!(
        f.io.unbind_hosted_file_identity(receipt),
        Err(NtStatus::DELETE_PENDING)
    );
    assert_eq!(
        f.io.unregister_hosted_domain(f.domain),
        Err(NtStatus::DEVICE_BUSY)
    );
    f.io.release_hosted_file_publication(&mut first).unwrap();
    assert!(!first.is_held());
    assert_eq!(
        f.io.release_hosted_file_publication(&mut first),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        f.io.unbind_hosted_file_identity(receipt),
        Err(NtStatus::DELETE_PENDING)
    );
    f.io.release_hosted_file_publication(&mut second).unwrap();
    assert_eq!(
        f.io.unbind_hosted_file_identity(receipt),
        Ok(HostedFileUnbindOutcome::Removed)
    );
    assert_eq!(f.io.unregister_hosted_domain(f.domain), Ok(()));
}

#[test]
fn dropping_a_lease_does_not_silently_release_projection_ownership() {
    let mut f = Fixture::new();
    let receipt = f.bind(0x5000);
    let lease = f.io.lease_hosted_file_identity(receipt).unwrap();
    drop(lease);
    assert_eq!(
        f.io.unbind_hosted_file_identity(receipt),
        Err(NtStatus::DELETE_PENDING)
    );
    assert_eq!(
        f.io.unregister_hosted_domain(f.domain),
        Err(NtStatus::DEVICE_BUSY)
    );
}

#[test]
fn sequence_and_lease_count_exhaustion_are_nonmutating() {
    let mut f = Fixture::new();
    let receipt = f.bind(0x5000);
    f.io.hosted_domains
        .get_mut(f.domain.domain_id)
        .unwrap()
        .file_binding_sequence = u64::MAX;
    assert_eq!(f.bind(0x5000), receipt);
    let other = f.another_file();
    assert_eq!(
        f.io.bind_hosted_file_identity(f.domain, 0x5010, other),
        Err(NtStatus::INSUFFICIENT_RESOURCES)
    );
    assert_eq!(
        f.io.hosted_file_identities(f.file),
        Ok(alloc::vec![receipt])
    );
    f.io.hosted_domains
        .get_mut(f.domain.domain_id)
        .unwrap()
        .files[0]
        .leases = u64::MAX;
    assert_eq!(
        f.io.lease_hosted_file_identity(receipt).unwrap_err(),
        NtStatus::INSUFFICIENT_RESOURCES
    );
    assert_eq!(
        f.io.hosted_domains.get(f.domain.domain_id).unwrap().files[0].leases,
        u64::MAX
    );
    f.io.hosted_domains
        .get_mut(f.domain.domain_id)
        .unwrap()
        .files[0]
        .leases = 0;
    let mut lease = f.io.lease_hosted_file_identity(receipt).unwrap();
    f.io.hosted_domains
        .get_mut(f.domain.domain_id)
        .unwrap()
        .files[0]
        .leases = 0;
    assert_eq!(
        f.io.release_hosted_file_publication(&mut lease),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert!(lease.is_held());
    f.io.hosted_domains
        .get_mut(f.domain.domain_id)
        .unwrap()
        .files[0]
        .leases = 1;
    f.io.release_hosted_file_publication(&mut lease).unwrap();
}

#[test]
fn close_blocks_new_bindings_but_not_existing_receipts_or_retirement() {
    let mut f = Fixture::new();
    let receipt = f.bind(0x5000);
    let other_domain = f.io.register_hosted_domain();
    for state in [FileState::Open, FileState::Closed] {
        f.io.file_mut(f.file).unwrap().state = state;
        f.io.file_mut(f.file).unwrap().close_dispatched = true;
        assert_eq!(f.bind(0x5000), receipt);
        assert_eq!(
            f.io.bind_hosted_file_identity(other_domain, 0x5000, f.file),
            Err(NtStatus::FILE_CLOSED)
        );
        assert_eq!(
            f.io.hosted_file_identities(f.file),
            Ok(alloc::vec![receipt])
        );
        let mut lease = f.io.lease_hosted_file_identity(receipt).unwrap();
        f.io.release_hosted_file_publication(&mut lease).unwrap();
    }
    assert_eq!(
        f.io.unbind_hosted_file_identity(receipt),
        Ok(HostedFileUnbindOutcome::Removed)
    );
    assert!(f.io.file(f.file).unwrap().close_retry_queued);
}

#[test]
fn invalid_file_address_and_cookie_never_publish_bindings() {
    let mut f = Fixture::new();
    assert_eq!(
        f.io.bind_hosted_file_identity(f.domain, 0, f.file),
        Err(NtStatus::INVALID_PARAMETER)
    );
    assert_eq!(
        f.io.bind_hosted_file_identity(f.domain, 0x5000, FileId::NULL),
        Err(NtStatus::INVALID_HANDLE)
    );
    for cookie in [0, f.domain.cookie.wrapping_add(1)] {
        let stale = HostedDomainIdentity { cookie, ..f.domain };
        assert_eq!(
            f.io.bind_hosted_file_identity(stale, 0x5000, f.file),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }
    assert_eq!(f.io.hosted_file_identities(f.file), Ok(Vec::new()));
}
