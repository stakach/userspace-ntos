//! Host composition of canonical bindings, local projection slots, and service receipt decoding.
//! Lost replies are modeled explicitly; these tests do not execute native IPC or free guest memory.

use nt_driver_runtime::{decode_file_projection_reply, FileProjectionSlot};
use nt_io_manager::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, FileId, HostedDomainIdentity,
    HostedFileIdentity, HostedFileUnbindOutcome, IoManager, MockDriverBackend, MockObjectPort,
    ShareAccess,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath};

struct Fixture {
    io: IoManager<MockObjectPort>,
    client: ClientId,
    domain: HostedDomainIdentity,
    file: FileId,
    handle: HandleValue,
}

impl Fixture {
    fn new() -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\ProjectionProtocol").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let path = NtPath::parse_str(r"\Device\ProjectionProtocol").unwrap();
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
                ShareAccess::READ | ShareAccess::WRITE,
                CreateOptions::empty(),
                1,
            )
            .unwrap();
        let file = io
            .reference_open_file_details(client, handle, AccessMask::empty())
            .unwrap()
            .0;
        let domain = io.register_hosted_domain();
        Self {
            io,
            client,
            domain,
            file,
            handle,
        }
    }

    fn bind(&mut self, slot: FileProjectionSlot) -> HostedFileIdentity {
        self.io
            .bind_hosted_file_identity(self.domain, slot.address(), self.file)
            .unwrap()
    }

    fn query(&self, slot: FileProjectionSlot) -> u64 {
        let result = self
            .io
            .hosted_file_identity_at(self.domain, self.file, slot.address())
            .map(|identity| identity.map_or(0, HostedFileIdentity::binding_generation));
        decode(result, 3).unwrap().unwrap()
    }

    fn unbind(&mut self, slot: FileProjectionSlot) -> Result<HostedFileUnbindOutcome, NtStatus> {
        self.io.unbind_authenticated_hosted_file(
            self.domain,
            self.file,
            slot.address(),
            slot.generation(),
        )
    }

    fn close(&mut self) {
        self.io.close(self.client, self.handle).unwrap();
        self.io.pump();
    }
}

fn decode(result: Result<u64, NtStatus>, operation: u64) -> Option<Result<u64, i32>> {
    let (status, generation) = match result {
        Ok(generation) => (0, generation),
        Err(status) => (status.raw() as u32 as u64, 0),
    };
    decode_file_projection_reply(4, status, generation, [0; 2], operation)
}

#[test]
fn successful_binding_stays_live_until_exact_unbind_receipt() {
    let mut f = Fixture::new();
    let mut slot = FileProjectionSlot::new(f.file.raw(), 0x5000).unwrap();
    let expected = slot;
    let receipt = f.bind(slot);
    let generation = decode(Ok(receipt.binding_generation()), 1)
        .unwrap()
        .unwrap();
    assert!(slot.publish(expected, generation));
    assert!(slot.is_live());
    assert_eq!(f.query(slot), slot.generation());
    f.close();
    assert!(
        f.io.file(f.file).is_some(),
        "binding pins final canonical record removal"
    );
    assert!(slot.retire());
    let expected = slot;
    let result = f.unbind(slot);
    assert_eq!(result, Ok(HostedFileUnbindOutcome::Removed));
    assert_eq!(decode(result.map(|_| 0), 2), Some(Ok(0)));
    assert_eq!(slot, expected);
    assert_eq!(f.query(slot), 0);
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
}

#[test]
fn dropped_bind_reply_recovers_generation_by_query_without_publishing_live() {
    let mut f = Fixture::new();
    let mut slot = FileProjectionSlot::new(f.file.raw(), 0x5000).unwrap();
    let bind_snapshot = slot;
    let accepted = f.bind(slot);
    // BIND changed canonical state, but no authoritative receipt reached the local registry.
    assert_eq!(decode_file_projection_reply(0, 0, 0, [0; 2], 1), None);
    slot.retire();
    assert_eq!(slot.generation(), 0);
    assert!(!slot.publish(bind_snapshot, accepted.binding_generation()));
    f.close();
    assert!(f.io.file(f.file).is_some());
    let query_snapshot = slot;
    let generation = f.query(slot);
    assert_eq!(generation, accepted.binding_generation());
    assert!(slot.resolve_retirement(query_snapshot, generation));
    assert!(slot.is_retiring());
    assert!(!slot.is_live());
    assert_eq!(decode(f.unbind(slot).map(|_| 0), 2), Some(Ok(0)));
    assert_eq!(f.query(slot), 0);
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
}

#[test]
fn dropped_unbind_reply_replays_exact_generation_after_canonical_record_removal() {
    let mut f = Fixture::new();
    let mut slot = FileProjectionSlot::new(f.file.raw(), 0x5000).unwrap();
    let receipt = f.bind(slot);
    assert!(slot.publish(
        slot,
        decode(Ok(receipt.binding_generation()), 1)
            .unwrap()
            .unwrap()
    ));
    f.close();
    slot.retire();
    let pending_receipt = slot;
    assert_eq!(f.unbind(slot), Ok(HostedFileUnbindOutcome::Removed));
    assert_eq!(decode_file_projection_reply(0, 0, 0, [0; 2], 2), None);
    assert_eq!(slot, pending_receipt);
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
    let replay = f.unbind(slot);
    assert_eq!(replay, Ok(HostedFileUnbindOutcome::AlreadyAbsent));
    assert_eq!(decode(replay.map(|_| 0), 2), Some(Ok(0)));
    assert_eq!(slot, pending_receipt);
    assert_eq!(f.query(slot), 0);
}

#[test]
fn publication_lease_refusal_retains_canonical_binding_and_exact_retiring_slot() {
    let mut f = Fixture::new();
    let mut owner = f.io.retain_file_reference(f.file).unwrap();
    let mut slot = FileProjectionSlot::new(f.file.raw(), 0x5000).unwrap();
    let receipt = f.bind(slot);
    assert!(slot.publish(
        slot,
        decode(Ok(receipt.binding_generation()), 1)
            .unwrap()
            .unwrap()
    ));
    let mut lease = f.io.lease_hosted_file_identity(receipt).unwrap();
    f.close();
    slot.retire();
    let expected = slot;
    assert_eq!(
        decode(f.unbind(slot).map(|_| 0), 2),
        Some(Err(NtStatus::DELETE_PENDING.raw()))
    );
    assert_eq!(slot, expected);
    assert_eq!(f.query(slot), receipt.binding_generation());
    assert_eq!(f.io.file_reference_count(f.file), 1);
    assert!(lease.is_held());
    f.io.release_hosted_file_publication(&mut lease).unwrap();
    assert_eq!(decode(f.unbind(slot).map(|_| 0), 2), Some(Ok(0)));
    assert_eq!(slot, expected);
    assert_eq!(f.query(slot), 0);
    f.io.release_file_reference(&mut owner).unwrap();
    f.io.pump();
    assert!(f.io.file(f.file).is_none());
}

#[test]
fn stale_receipts_never_unbind_or_retire_replacement_at_reused_or_new_address() {
    for replacement_address in [0x5000, 0x6000] {
        let mut f = Fixture::new();
        let mut old = FileProjectionSlot::new(f.file.raw(), 0x5000).unwrap();
        let old_reserved = old;
        let first = f.bind(old);
        assert!(old.publish(
            old_reserved,
            decode(Ok(first.binding_generation()), 1).unwrap().unwrap()
        ));
        old.retire();
        assert_eq!(f.unbind(old), Ok(HostedFileUnbindOutcome::Removed));
        let mut replacement = FileProjectionSlot::new(f.file.raw(), replacement_address).unwrap();
        let current_reserved = replacement;
        let current = f.bind(replacement);
        assert_ne!(current.binding_generation(), first.binding_generation());
        assert!(!replacement.publish(old_reserved, first.binding_generation()));
        assert!(replacement.publish(
            current_reserved,
            decode(Ok(current.binding_generation()), 1)
                .unwrap()
                .unwrap()
        ));
        let current_live = replacement;
        let stale_unbind = f.unbind(old);
        assert_eq!(stale_unbind, Ok(HostedFileUnbindOutcome::AlreadyAbsent));
        assert_eq!(decode(stale_unbind.map(|_| 0), 2), Some(Ok(0)));
        // Even a successful old receipt cannot authorize a local update against this snapshot.
        assert_ne!(old, replacement);
        assert!(!replacement.resolve_retirement(old, first.binding_generation()));
        assert_eq!(replacement, current_live);
        assert!(replacement.is_live());
        assert_eq!(f.query(replacement), current.binding_generation());
        f.close();
        replacement.retire();
        assert_eq!(decode(f.unbind(replacement).map(|_| 0), 2), Some(Ok(0)));
        f.io.pump();
        assert!(f.io.file(f.file).is_none());
    }
}
