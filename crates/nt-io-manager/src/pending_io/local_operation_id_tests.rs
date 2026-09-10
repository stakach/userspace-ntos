use super::*;

fn terminal(id: u64) -> PendingFileIo {
    PendingFileIo {
        file_id: 1,
        irp_id: id,
        major: nt_io_abi::major::IRP_MJ_LOCK_CONTROL,
        operation: PendingFileIoOperation::LocalInline(PendingLocalInline {
            status: 0,
            information: 0,
        }),
        ..PendingFileIo::default()
    }
}

#[test]
fn exact_active_claim_has_one_stable_tagged_local_identity() {
    let mut table = PendingFileIoTable::new();
    let first = table.reserve().unwrap();
    let second = table.reserve().unwrap();
    let first_id = table.local_operation_id(first).unwrap();
    let second_id = table.local_operation_id(second).unwrap();
    assert_eq!(first_id, LOCAL_OPERATION_ID_TAG | first.generation);
    assert_eq!(second_id, LOCAL_OPERATION_ID_TAG | second.generation);
    assert_ne!(first_id, second_id);
    assert_eq!(
        first_id & !LOCAL_OPERATION_ID_GENERATION_MASK,
        LOCAL_OPERATION_ID_TAG
    );
    for _ in 0..3 {
        assert_eq!(table.local_operation_id(first), Some(first_id));
        assert_eq!(table.local_operation_id(second), Some(second_id));
    }
    assert_eq!(table.len(), 0);
}

#[test]
fn invalid_and_crossed_claims_cannot_derive_an_identity() {
    let mut table = PendingFileIoTable::new();
    let first = table.reserve().unwrap();
    let second = table.reserve().unwrap();
    for invalid in [
        PendingFileIoReservation {
            slot: usize::MAX,
            generation: first.generation,
        },
        PendingFileIoReservation {
            slot: first.slot,
            generation: 0,
        },
        PendingFileIoReservation {
            slot: first.slot,
            generation: second.generation,
        },
        PendingFileIoReservation {
            slot: second.slot,
            generation: first.generation,
        },
    ] {
        assert_eq!(table.local_operation_id(invalid), None);
    }
    assert!(table.local_operation_id(first).is_some());
    assert!(table.local_operation_id(second).is_some());
}

#[test]
fn cancelled_claim_and_reused_slot_never_reuse_local_identity() {
    let mut table = PendingFileIoTable::new();
    let first = table.reserve().unwrap();
    let first_id = table.local_operation_id(first).unwrap();
    assert!(table.cancel_reservation(first));
    assert_eq!(table.local_operation_id(first), None);
    let replacement = table.reserve().unwrap();
    assert_eq!(replacement.slot, first.slot);
    let replacement_id = table.local_operation_id(replacement).unwrap();
    assert_ne!(replacement_id, first_id);
    assert_eq!(table.local_operation_id(first), None);
    assert_eq!(table.local_operation_id(replacement), Some(replacement_id));
}

#[test]
fn committed_claim_no_longer_authorizes_local_identity_observation() {
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    let id = table.local_operation_id(reservation).unwrap();
    let slot = table.park_reserved(reservation, terminal(id)).unwrap();
    assert_eq!(table.local_operation_id(reservation), None);
    assert!(!table.cancel_reservation(reservation));
    assert_eq!(table.get(slot).unwrap().irp_id, id);
}

#[test]
fn local_generation_exhaustion_does_not_truncate_or_block_provider_reservations() {
    let mut table = PendingFileIoTable::new();
    table.next_reservation_generation = LOCAL_OPERATION_ID_GENERATION_MASK;
    let last = table.reserve().unwrap();
    assert_eq!(
        table.local_operation_id(last),
        Some(LOCAL_OPERATION_ID_TAG | LOCAL_OPERATION_ID_GENERATION_MASK)
    );
    assert!(table.cancel_reservation(last));
    let exhausted = table.reserve().unwrap();
    assert_eq!(exhausted.generation, LOCAL_OPERATION_ID_GENERATION_MASK + 1);
    assert_eq!(table.local_operation_id(exhausted), None);
    let provider = PendingFileIo {
        file_id: 1,
        irp_id: 2,
        major: nt_io_abi::major::IRP_MJ_READ,
        ..PendingFileIo::default()
    };
    assert!(table.park_reserved(exhausted, provider).is_ok());
    assert_eq!(table.local_operation_id(last), None);
}

#[test]
fn full_generation_exhaustion_never_wraps_even_after_cancellation() {
    let mut table = PendingFileIoTable::new();
    table.next_reservation_generation = u64::MAX;
    let last = table.reserve().unwrap();
    assert_eq!(last.generation, u64::MAX);
    assert_eq!(table.local_operation_id(last), None);
    assert_eq!(table.next_reservation_generation, 0);
    let allocated_slots = table.slots.len();
    assert_eq!(table.reserve(), None);
    assert_eq!(table.slots.len(), allocated_slots);
    assert!(table.cancel_reservation(last));
    for _ in 0..3 {
        assert_eq!(table.reserve(), None);
        assert_eq!(table.next_reservation_generation, 0);
    }
    assert!(table.is_empty());
}
