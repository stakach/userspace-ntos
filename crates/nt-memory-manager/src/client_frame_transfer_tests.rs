use super::*;
use crate::client_frame::ClientFrameInsertError;

fn fixture() -> (ClientFrameRegistry, Vec<ClientFrameRecord>) {
    let mut registry = ClientFrameRegistry::new();
    for (pi, page, cap) in [(7, 0x1000, 10), (7, 0x2000, 20), (8, 0x1000, 30)] {
        registry
            .insert(pi, page, cap, page + 0x10000, cap + 1, cap + 2, false)
            .unwrap();
    }
    let records = registry.records().to_vec();
    (registry, records)
}

fn storage(count: usize) -> Result<Vec<ClientFrameRecord>, ClientFrameTransferError> {
    Ok(Vec::with_capacity(count))
}

#[test]
fn transfer_retains_every_selected_row_until_final_commit() {
    let (mut registry, records) = fixture();
    let transfer = registry.prepare_transfer_exact(&records[..2]).unwrap();
    assert_eq!(transfer.records().len(), 2);
    for (held, original) in transfer.records().iter().zip(&records) {
        assert!(held.is_reclaiming());
        assert_eq!(held.frame, original.frame);
        assert_eq!(held.alias_cap, original.alias_cap);
        assert_eq!(held.source_cap, original.source_cap);
        assert_eq!(registry.get(held.pi, held.page), Some(*held));
    }
    assert!(!registry.is_process_empty(7));
    assert_eq!(registry.get(8, 0x1000), Some(records[2]));
    registry.finish_transfer(transfer).unwrap();
    assert!(registry.is_process_empty(7));
    assert_eq!(registry.records(), &records[2..]);
}

#[test]
fn empty_or_duplicate_selections_leave_all_rows_unchanged() {
    let (mut registry, records) = fixture();
    assert!(matches!(
        registry.prepare_transfer_exact(&[]),
        Err(ClientFrameTransferError::EmptySelection)
    ));
    for duplicate in [
        records[0],
        ClientFrameRecord {
            age: 999,
            ..records[0]
        },
    ] {
        assert!(matches!(
            registry.prepare_transfer_exact(&[records[0], records[1], duplicate]),
            Err(ClientFrameTransferError::DuplicateRecord),
        ));
        assert_eq!(registry.records(), records);
    }
}

#[test]
fn stale_or_missing_members_refuse_the_entire_selection() {
    for missing in [false, true] {
        let (mut registry, records) = fixture();
        if missing {
            registry.take(7, 0x2000).unwrap();
        } else {
            assert!(registry.touch(7, 0x2000));
        }
        let before = registry.records().to_vec();
        assert!(matches!(
            registry.prepare_transfer_exact(&records[..2]),
            Err(ClientFrameTransferError::StaleRecord)
        ));
        assert_eq!(registry.records(), before);
        assert_eq!(registry.get(7, 0x1000), Some(records[0]));
    }
}

#[test]
fn existing_reclamation_refuses_handoff_without_claiming_other_rows() {
    let (mut registry, records) = fixture();
    let reclaiming = registry
        .begin_reclaim_exact(records[1], crate::ClientFrameReclaimIntent::Release)
        .unwrap();
    assert!(matches!(
        registry.prepare_transfer_exact(&[records[0], reclaiming]),
        Err(ClientFrameTransferError::Reclaiming)
    ));
    assert_eq!(registry.get(7, 0x1000), Some(records[0]));
    assert_eq!(registry.get(7, 0x2000), Some(reclaiming));
}

#[test]
fn allocation_failure_does_not_change_rows_or_consume_an_attempt() {
    let (mut registry, records) = fixture();
    let counter = AtomicU64::new(17);
    assert!(matches!(
        registry.prepare_transfer_with(&records, &counter, |_| Err(
            ClientFrameTransferError::InsufficientResources
        )),
        Err(ClientFrameTransferError::InsufficientResources),
    ));
    assert_eq!(registry.records(), records);
    assert_eq!(counter.load(Ordering::Relaxed), 17);
    // Even an unusable supplied journal cannot trigger an allocation after the first row changes.
    assert!(matches!(
        registry.prepare_transfer_with(&records, &counter, |_| Ok(Vec::new())),
        Err(ClientFrameTransferError::InsufficientResources),
    ));
    assert_eq!(registry.records(), records);
    assert_eq!(counter.load(Ordering::Relaxed), 17);
}

#[test]
fn transfer_identity_exhaustion_never_wraps_or_claims_rows() {
    let (mut registry, records) = fixture();
    let counter = AtomicU64::new(u64::MAX);
    for _ in 0..3 {
        assert!(matches!(
            registry.prepare_transfer_with(&records, &counter, storage),
            Err(ClientFrameTransferError::IdentityExhausted),
        ));
        assert_eq!(registry.records(), records);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}

#[test]
fn ordinary_removal_and_exact_mutation_cannot_steal_transferred_rows() {
    let (mut registry, records) = fixture();
    let transfer = registry.prepare_transfer_exact(&records).unwrap();
    for &held in transfer.records() {
        assert_eq!(registry.take(held.pi, held.page), None);
        assert_eq!(registry.take_exact(held), None);
        let intent = crate::ClientFrameReclaimIntent::Release;
        let error = Err(crate::ClientFrameReclaimError::InvalidState);
        assert_eq!(registry.begin_reclaim_exact(held, intent), error);
        assert_eq!(
            registry.cleanup_reclaim_exact(held, intent, &mut super::super::SuccessfulCleanup),
            error
        );
        assert_eq!(
            registry.commit_reclaim_exact(held, intent, |_| panic!("transfer owns publication")),
            error
        );
        assert_eq!(registry.cancel_pageout_to_release_exact(held), error);
        assert_eq!(registry.get(held.pi, held.page), Some(held));
    }
    registry.finish_transfer(transfer).unwrap();
    assert!(registry.records().is_empty());
}

#[test]
fn transferred_rows_cannot_be_republished_touched_or_used_for_resident_access() {
    let (mut registry, records) = fixture();
    let transfer = registry.prepare_transfer_exact(&records[..1]).unwrap();
    let held = transfer.records()[0];
    assert!(!held.is_resident());
    assert_eq!(held.mapped_alias(), None);
    assert_eq!(held.clone_source_cap(), None);
    assert!(!registry.touch(held.pi, held.page));
    assert_eq!(
        registry.insert(
            held.pi,
            held.page,
            held.frame,
            held.alias,
            held.alias_cap,
            held.source_cap,
            held.owns_frame
        ),
        Err(ClientFrameInsertError::Reclaiming),
    );
    assert_eq!(registry.get(held.pi, held.page), Some(held));
    registry.finish_transfer(transfer).unwrap();
    registry.insert(7, 0x1000, 99, 0, 0, 0, true).unwrap();
    assert!(registry.get(7, 0x1000).unwrap().is_resident());
}

#[test]
fn overlapping_transfer_refusal_preserves_both_existing_and_unclaimed_rows() {
    let (mut registry, records) = fixture();
    let first = registry.prepare_transfer_exact(&records[..1]).unwrap();
    assert!(matches!(
        registry.prepare_transfer_exact(&[records[1], first.records()[0]]),
        Err(ClientFrameTransferError::Reclaiming),
    ));
    assert_eq!(registry.get(7, 0x2000), Some(records[1]));
    registry.finish_transfer(first).unwrap();
}

#[test]
fn wrong_registry_completion_returns_owner_intact_for_retry() {
    let (mut registry, records) = fixture();
    let (mut other, other_records) = fixture();
    let transfer = registry.prepare_transfer_exact(&records).unwrap();
    let held = transfer.records().to_vec();
    let (error, transfer) = other.finish_transfer(transfer).unwrap_err();
    assert_eq!(error, ClientFrameTransferError::StaleRecord);
    assert_eq!(transfer.records(), held);
    assert_eq!(registry.records(), held);
    assert_eq!(other.records(), other_records);
    registry.finish_transfer(transfer).unwrap();
}

#[test]
fn final_commit_validates_the_whole_batch_before_removing_any_member() {
    let (mut registry, records) = fixture();
    let transfer = registry.prepare_transfer_exact(&records).unwrap();
    let held = transfer.records().to_vec();
    // Simulate owner corruption outside the guarded API. No preceding member may disappear.
    registry.records[2].transfer_id = NonZeroU64::new(u64::MAX);
    let (error, transfer) = registry.finish_transfer(transfer).unwrap_err();
    assert_eq!(error, ClientFrameTransferError::StaleRecord);
    assert_eq!(&registry.records()[..2], &held[..2]);
    assert_eq!(registry.records().len(), 3);
    registry.records[2] = held[2];
    registry.finish_transfer(transfer).unwrap();
    assert!(registry.records().is_empty());
}

#[test]
fn dropping_a_transfer_retains_its_unavailable_placeholders() {
    let (mut registry, records) = fixture();
    drop(registry.prepare_transfer_exact(&records).unwrap());
    assert_eq!(registry.records().len(), records.len());
    for record in records {
        assert!(!registry.get(record.pi, record.page).unwrap().is_resident());
        assert_eq!(registry.take(record.pi, record.page), None);
    }
}

#[test]
fn unrelated_vector_growth_and_swap_removal_do_not_change_transfer_ownership() {
    let (mut registry, records) = fixture();
    let transfer = registry.prepare_transfer_exact(&[records[1]]).unwrap();
    registry.take(7, 0x1000).unwrap();
    for i in 0..50 {
        registry
            .insert(9, 0x1000 + i * 0x1000, 100 + i, 0, 0, 0, true)
            .unwrap();
    }
    registry.take(8, 0x1000).unwrap();
    registry.finish_transfer(transfer).unwrap();
    assert!(registry.is_process_empty(7));
    assert_eq!(registry.records().len(), 50);
}

#[test]
fn independent_transfers_finish_without_releasing_each_others_rows() {
    let (mut registry, records) = fixture();
    let first = registry.prepare_transfer_exact(&records[..2]).unwrap();
    let second = registry.prepare_transfer_exact(&records[2..]).unwrap();
    assert_ne!(first.id, second.id);
    let second_record = second.records()[0];
    registry.finish_transfer(first).unwrap();
    assert_eq!(registry.records(), &[second_record]);
    registry.finish_transfer(second).unwrap();
}

#[test]
fn identical_replacement_cannot_reuse_pretransfer_snapshots() {
    let (mut registry, records) = fixture();
    let old = records[0];
    let transfer = registry.prepare_transfer_exact(&records[..1]).unwrap();
    registry.finish_transfer(transfer).unwrap();
    registry
        .insert_at_age(
            old.pi,
            old.page,
            old.frame,
            old.alias,
            old.alias_cap,
            old.source_cap,
            old.owns_frame,
            old.age,
        )
        .unwrap();
    let replacement = registry.get(old.pi, old.page).unwrap();
    assert!(matches!(
        registry.prepare_transfer_exact(&[old]),
        Err(ClientFrameTransferError::StaleRecord)
    ));
    assert_eq!(registry.get(old.pi, old.page), Some(replacement));
    let fresh = registry.prepare_transfer_exact(&[replacement]).unwrap();
    registry.finish_transfer(fresh).unwrap();
}
