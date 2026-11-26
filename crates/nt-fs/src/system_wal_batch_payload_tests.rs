//! RED contract for a bounded SYSTEM WAL batch payload.
//!
//! `reserve` owns the exact journal and preallocates room before the caller enters CM COMMIT.
//! Only a positive, binding-checked CM receipt permits `append_committed` to consume that
//! move-only reservation. `seal` hands one complete HLR1 payload to the physical WAL owner.

use crate::snapshot_test_device::CachedDisk;
use crate::{
    decode_volume_wal_payload, RegistryWal, SystemWalBatchError, SystemWalBatchPayload,
    VolumeWalPayload,
};
use alloc::vec::Vec;
use nt_hive_core::{complete_log_sequence_span, encode_log_record, HiveLogOp, RegistryValueType};

fn create_key(sequence: u64, name: &str) -> Vec<u8> {
    encode_log_record(&HiveLogOp::CreateKey { path: name }, sequence)
}

fn large_set_value(sequence: u64) -> Vec<u8> {
    encode_log_record(
        &HiveLogOp::SetValue {
            path: r"\Registry\Machine\System\ControlSet001\Services\Example",
            name: "Payload",
            value_type: RegistryValueType::Binary,
            data: &[0x5a; 600],
        },
        sequence,
    )
}

fn append_confirmed(batch: &mut SystemWalBatchPayload, generation: u64, journal: Vec<u8>) {
    let reservation = batch.reserve(generation, journal).unwrap();
    // The executive may cross this boundary only with the exact positive CM COMMIT receipt.
    batch.append_committed(reservation).unwrap();
}

#[test]
fn two_complete_journals_recover_as_one_physical_wal_frame() {
    let first = create_key(11, r"\Registry\Machine\System\ControlSet001\Services\One");
    let second = create_key(12, r"\Registry\Machine\System\ControlSet001\Services\Two");
    let mut batch = SystemWalBatchPayload::new(34, 10, 32, 512).unwrap();
    append_confirmed(&mut batch, 35, first.clone());
    append_confirmed(&mut batch, 36, second.clone());
    assert_eq!(batch.durable_floor(), 34);
    assert_eq!(batch.published_generation(), 36);

    let sealed = batch.seal().unwrap();
    assert_eq!(sealed.target_generation(), 36);
    let payload = sealed
        .wal_payload()
        .expect("two persistent journals need one frame");
    let expected = [first.as_slice(), second.as_slice()].concat();
    assert_eq!(payload, expected.as_slice());
    assert_eq!(complete_log_sequence_span(payload), Ok((11, 12)));
    assert_eq!(
        decode_volume_wal_payload(payload),
        Ok(VolumeWalPayload::System(payload))
    );

    let mut unmarked = RegistryWal::recover(CachedDisk::with_sectors(32), 77).unwrap();
    unmarked.begin(payload.to_vec()).unwrap();
    unmarked.prepare().unwrap();
    let mut disk = unmarked.into_device_for_test();
    disk.power_cut();
    let mut recovered = RegistryWal::recover(disk, 77).unwrap();
    assert!(
        recovered.records().is_empty(),
        "an unmarked batch is not replayed"
    );
    recovered.clear_recovered_tail().unwrap();

    let mut wal = RegistryWal::recover(CachedDisk::with_sectors(32), 77).unwrap();
    wal.begin(payload.to_vec()).unwrap();
    wal.prepare().unwrap();
    wal.commit().unwrap();
    let mut disk = wal.into_device().unwrap();
    disk.power_cut();
    let recovered = RegistryWal::recover(disk, 77).unwrap();
    assert_eq!(recovered.records().len(), 1);
    assert_eq!(recovered.records()[0].payload.as_slice(), payload);
}

#[test]
fn sequence_gap_and_capacity_refuse_before_an_append() {
    let first = create_key(11, r"\Registry\Machine\System\ControlSet001\Services\One");
    let skipped = create_key(
        13,
        r"\Registry\Machine\System\ControlSet001\Services\Skipped",
    );
    let mut batch = SystemWalBatchPayload::new(34, 10, 32, 512).unwrap();
    let first_gap = create_key(12, r"\Registry\Machine\System\ControlSet001\Services\Gap");
    let (error, returned) = batch.reserve(35, first_gap.clone()).unwrap_err();
    assert_eq!(error, SystemWalBatchError::SequenceGap);
    assert_eq!(
        returned, first_gap,
        "a new batch must bridge the previous WAL frame"
    );
    append_confirmed(&mut batch, 35, first.clone());
    let (error, returned) = batch.reserve(36, skipped.clone()).unwrap_err();
    assert_eq!(error, SystemWalBatchError::SequenceGap);
    assert_eq!(
        returned, skipped,
        "refusal preserves the caller's exact journal"
    );
    assert_eq!(batch.published_generation(), 35);
    assert_eq!(batch.payload(), first.as_slice());

    let foreign_generation = create_key(
        12,
        r"\Registry\Machine\System\ControlSet001\Services\Foreign",
    );
    let (error, returned) = batch.reserve(38, foreign_generation.clone()).unwrap_err();
    assert_eq!(error, SystemWalBatchError::GenerationGap);
    assert_eq!(returned, foreign_generation);
    assert_eq!(batch.published_generation(), 35);

    let truncated = create_key(12, r"\Registry\Machine\System\ControlSet001\Services\Torn");
    let torn = truncated[..truncated.len() - 1].to_vec();
    let (error, returned) = batch.reserve(36, torn.clone()).unwrap_err();
    assert_eq!(error, SystemWalBatchError::InvalidJournal);
    assert_eq!(returned, torn);
    assert_eq!(batch.payload(), first.as_slice());

    // Three free sectors can hold only one 512-byte payload sector plus its two frame sectors.
    let mut tight = SystemWalBatchPayload::new(34, 10, 3, 512).unwrap();
    append_confirmed(&mut tight, 35, first.clone());
    let oversized = large_set_value(12);
    assert!(oversized.len() > 512);
    let (error, returned) = tight.reserve(36, oversized.clone()).unwrap_err();
    assert_eq!(error, SystemWalBatchError::OutOfSpace);
    assert_eq!(returned, oversized);
    assert_eq!(tight.published_generation(), 35);
    assert_eq!(tight.payload(), first.as_slice());
}

#[test]
fn zero_byte_generation_cannot_pass_an_older_pending_durable_floor() {
    let first = create_key(11, r"\Registry\Machine\System\ControlSet001\Services\One");
    let next = create_key(12, r"\Registry\Machine\System\ControlSet001\Services\Two");
    let mut batch = SystemWalBatchPayload::new(34, 10, 32, 512).unwrap();
    append_confirmed(&mut batch, 35, first.clone());
    append_confirmed(&mut batch, 36, Vec::new());
    assert_eq!(batch.published_generation(), 36);
    assert_eq!(
        batch.durable_floor(),
        34,
        "empty journal cannot skip pending bytes"
    );
    append_confirmed(&mut batch, 37, next.clone());
    let sealed = batch.seal().unwrap();
    assert_eq!(sealed.target_generation(), 37);
    assert_eq!(sealed.durable_floor(), 34);
    let expected = [first, next].concat();
    assert_eq!(sealed.wal_payload().unwrap(), expected.as_slice());

    let mut empty_only = SystemWalBatchPayload::new(34, 10, 32, 512).unwrap();
    append_confirmed(&mut empty_only, 35, Vec::new());
    assert_eq!(empty_only.published_generation(), 35);
    assert_eq!(
        empty_only.durable_floor(),
        35,
        "no persistent bytes need a marker"
    );
    assert!(empty_only.seal().unwrap().wal_payload().is_none());
}

#[test]
fn in_flight_reservation_refuses_seal_and_returns_the_same_owner() {
    let journal = create_key(11, r"\Registry\Machine\System\ControlSet001\Services\One");
    let mut batch = SystemWalBatchPayload::new(34, 10, 32, 512).unwrap();
    let reservation = batch.reserve(35, journal.clone()).unwrap();
    let (error, mut batch) = batch.seal().unwrap_err();
    assert_eq!(error, SystemWalBatchError::Busy);
    assert_eq!(batch.published_generation(), 34);
    batch.append_committed(reservation).unwrap();
    assert_eq!(
        batch.seal().unwrap().wal_payload().unwrap(),
        journal.as_slice()
    );
}

#[test]
fn another_batch_cannot_consume_or_cancel_the_exact_reservation() {
    let first = create_key(11, r"\Registry\Machine\System\ControlSet001\Services\One");
    let second = create_key(11, r"\Registry\Machine\System\ControlSet001\Services\Two");
    let mut owner = SystemWalBatchPayload::new(34, 10, 32, 512).unwrap();
    let mut other = SystemWalBatchPayload::new(34, 10, 32, 512).unwrap();
    let reservation = owner.reserve(35, first.clone()).unwrap();
    let other_reservation = other.reserve(35, second.clone()).unwrap();

    let (error, reservation) = other.append_committed(reservation).unwrap_err();
    assert_eq!(error, SystemWalBatchError::ReservationMismatch);
    assert_eq!(other.published_generation(), 34);
    let (error, reservation) = other.cancel(reservation).unwrap_err();
    assert_eq!(error, SystemWalBatchError::ReservationMismatch);
    owner.append_committed(reservation).unwrap();
    other.append_committed(other_reservation).unwrap();
    assert_eq!(owner.payload(), first.as_slice());
    assert_eq!(other.payload(), second.as_slice());
}
