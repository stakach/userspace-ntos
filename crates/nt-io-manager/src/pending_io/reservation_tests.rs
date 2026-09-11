use super::*;

fn pending() -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(11),
        irp_id: 12,
        major: nt_io_abi::major::IRP_MJ_READ,
        tid: 13,
        busy: Some(test_busy(11, 13)),
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    }
}

#[test]
fn foreign_table_reservation_cannot_commit_cancel_or_access_local_storage() {
    let mut first = PendingFileIoTable::new();
    let mut second = PendingFileIoTable::new();
    let a = first.reserve().unwrap();
    let b = second.reserve().unwrap();
    assert_eq!(a.slot, b.slot);
    assert_eq!(a.generation, b.generation);
    assert_ne!(a.table, b.table);
    second.reserve_local_output(b, 4).unwrap();
    second
        .reserved_local_output_mut(b)
        .unwrap()
        .copy_from_slice(b"live");
    assert!(!second.cancel_reservation(a));
    assert_eq!(second.local_operation_id(a), None);
    assert!(second.reserve_local_output(a, 4).is_err());
    assert!(second.reserved_local_output_mut(a).is_err());
    assert_eq!(
        second.park_reserved(a, pending()),
        Err(PendingFileIoParkError::StaleReservation)
    );
    assert_eq!(second.reserved_local_output_mut(b).unwrap(), b"live");
    assert!(second.cancel_reservation(b));
    assert!(first.park_reserved(a, pending()).is_ok());
}

#[test]
fn reset_and_slot_reuse_never_reauthorize_old_reservation() {
    let mut table = PendingFileIoTable::new();
    let old = table.reserve().unwrap();
    assert!(!table.reset());
    assert!(table.cancel_reservation(old));
    assert!(table.reset());
    let new = table.reserve().unwrap();
    assert_eq!(old.slot, new.slot);
    assert_eq!(old.table, new.table);
    assert_ne!(old.generation, new.generation);
    assert!(!table.cancel_reservation(old));
    assert_eq!(
        table.park_reserved(old, pending()),
        Err(PendingFileIoParkError::StaleReservation)
    );
    assert_eq!(table.local_operation_id(old), None);
    assert!(table.park_reserved(new, pending()).is_ok());
}

#[test]
fn identity_exhaustion_refuses_before_creating_any_claim_or_storage() {
    let exhausted = AtomicU64::new(u64::MAX);
    let mut table = PendingFileIoTable::new();
    assert!(table.reserve_with_identity_source(&exhausted).is_none());
    assert_eq!(table.identity, 0);
    assert_eq!(table.next_reservation_generation, 1);
    assert_eq!(table.allocation_capacity(), (0, 0));
    assert_eq!(table.local_output_allocation_capacity(), 0);
    assert_eq!(table.owner_generation_allocation_capacity(), 0);
    assert!(table.is_empty());

    let source = AtomicU64::new(1);
    table.next_reservation_generation = 0;
    assert!(table.reserve_with_identity_source(&source).is_none());
    assert_eq!(source.load(Ordering::Relaxed), 1);
    assert!(table.is_empty());
}

#[test]
fn reserved_last_generation_commits_busy_after_both_budgets_are_exhausted() {
    let source = AtomicU64::new(u64::MAX - 1);
    let mut table = PendingFileIoTable::new();
    table.next_reservation_generation = u64::MAX;
    let reservation = table.reserve_with_identity_source(&source).unwrap();
    assert_eq!(source.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(table.next_reservation_generation, 0);
    assert!(table.reserve_with_identity_source(&source).is_none());
    let capacity = (
        table.allocation_capacity(),
        table.local_output_allocation_capacity(),
        table.owner_generation_allocation_capacity(),
    );
    let pointers = (
        table.slots.as_ptr(),
        table.reservations.as_ptr(),
        table.local_outputs.as_ptr(),
        table.owner_generations.as_ptr(),
    );
    let slot = table.park_reserved(reservation, pending()).unwrap();
    assert_eq!(
        capacity,
        (
            table.allocation_capacity(),
            table.local_output_allocation_capacity(),
            table.owner_generation_allocation_capacity(),
        )
    );
    assert_eq!(
        pointers,
        (
            table.slots.as_ptr(),
            table.reservations.as_ptr(),
            table.local_outputs.as_ptr(),
            table.owner_generations.as_ptr(),
        )
    );
    assert_eq!(source.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(table.next_reservation_generation, 0);
    assert_eq!(table.identity(slot), Some(reservation.identity()));
    settle_test_busy(&mut table, slot, 12);
    table.mark_backend_acked_exact(slot, 12).unwrap();
    table.finish_exact(slot, 12).unwrap();
    assert!(table.reset());
    assert!(table.reserve_with_identity_source(&source).is_none());
}

#[test]
fn existing_table_can_reserve_after_global_table_budget_exhausts() {
    let source = AtomicU64::new(u64::MAX - 1);
    let mut table = PendingFileIoTable::new();
    let first = table.reserve_with_identity_source(&source).unwrap();
    assert!(table.cancel_reservation(first));
    let second = table.reserve_with_identity_source(&source).unwrap();
    assert_eq!(first.table, second.table);
    assert_ne!(first.generation, second.generation);
    assert!(table.park_reserved(second, pending()).is_ok());
    let mut foreign = PendingFileIoTable::new();
    assert!(foreign.reserve_with_identity_source(&source).is_none());
}
