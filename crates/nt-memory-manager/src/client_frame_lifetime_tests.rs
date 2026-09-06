use super::*;

fn populated() -> (ClientFrameRegistry, ClientFrameRecord) {
    let mut registry = ClientFrameRegistry::new();
    registry
        .insert_at_age(7, 0x1000, 11, 0x2000, 12, 13, false, 40)
        .unwrap();
    let record = registry.get(7, 0x1000).unwrap();
    (registry, record)
}

#[test]
fn invalid_registration_never_creates_or_enriches_a_row() {
    let mut registry = ClientFrameRegistry::new();
    for (frame, alias, alias_cap) in [(0, 0, 0), (11, 0x2000, 0)] {
        assert_eq!(
            registry.insert(7, 0x1000, frame, alias, alias_cap, 13, false),
            Err(ClientFrameInsertError::InvalidRecord),
        );
        assert!(registry.is_process_empty(7));
    }
    registry.insert(7, 0x1000, 11, 0, 0, 0, false).unwrap();
    let before = registry.get(7, 0x1000).unwrap();
    assert_eq!(
        registry.insert(7, 0x1000, 11, 0x2000, 0, 13, false),
        Err(ClientFrameInsertError::InvalidRecord),
    );
    assert_eq!(registry.get(7, 0x1000), Some(before));
    assert_eq!(registry.stats().invalid_records, 3);
}

#[test]
fn alias_conflicts_leave_the_whole_row_unchanged() {
    let (mut registry, before) = populated();
    for (alias, cap) in [(0x3000, 12), (0x2000, 14), (0x3000, 14), (0, 14)] {
        assert_eq!(
            registry.insert_at_age(7, 0x1000, 11, alias, cap, 13, false, 999),
            Err(ClientFrameInsertError::ConflictingAlias),
        );
        assert_eq!(registry.get(7, 0x1000), Some(before));
    }
    assert_eq!(registry.stats().alias_conflicts, 4);
}

#[test]
fn source_conflict_cannot_partially_enrich_an_alias() {
    let mut registry = ClientFrameRegistry::new();
    registry.insert(7, 0x1000, 11, 0, 0, 13, false).unwrap();
    let before = registry.get(7, 0x1000).unwrap();
    assert_eq!(
        registry.insert(7, 0x1000, 11, 0x2000, 12, 14, false),
        Err(ClientFrameInsertError::ConflictingSource),
    );
    assert_eq!(registry.get(7, 0x1000), Some(before));
    assert_eq!(registry.stats().source_conflicts, 1);
}

#[test]
fn replay_and_omissions_preserve_richer_ownership() {
    let (mut registry, before) = populated();
    for (alias, cap, source) in [(0x2000, 12, 13), (0, 0, 0), (0, 12, 0), (0, 0, 13)] {
        assert_eq!(
            registry.insert_at_age(7, 0x1000, 11, alias, cap, source, false, 40),
            Ok(ClientFrameInsert::Updated),
        );
        assert_eq!(registry.get(7, 0x1000), Some(before));
    }
}

#[test]
fn dormant_alias_requires_the_same_explicit_cap_for_address_enrichment() {
    let mut registry = ClientFrameRegistry::new();
    registry.insert(7, 0x1000, 11, 0, 12, 13, false).unwrap();
    let before = registry.get(7, 0x1000).unwrap();
    assert_eq!(before.mapped_alias(), None);
    for (cap, error) in [
        (0, ClientFrameInsertError::InvalidRecord),
        (14, ClientFrameInsertError::ConflictingAlias),
    ] {
        assert_eq!(
            registry.insert(7, 0x1000, 11, 0x2000, cap, 13, false),
            Err(error)
        );
        assert_eq!(registry.get(7, 0x1000), Some(before));
    }
    registry
        .insert(7, 0x1000, 11, 0x2000, 12, 0, false)
        .unwrap();
    let mapped = registry.get(7, 0x1000).unwrap();
    assert_eq!(mapped.mapped_alias(), Some(0x2000));
    assert_eq!(mapped.source_cap, 13);
    assert_eq!(mapped.record_id, before.record_id);
}

#[test]
fn refused_registration_does_not_advance_working_set_age() {
    let (mut registry, before) = populated();
    assert_eq!(
        registry.insert_at_age(7, 0x1000, 11, 0x3000, 12, 13, false, u64::MAX),
        Err(ClientFrameInsertError::ConflictingAlias),
    );
    assert_eq!(registry.get(7, 0x1000), Some(before));
    assert!(registry.touch(7, 0x1000));
    assert_eq!(registry.get(7, 0x1000).unwrap().age, 41);
}

#[test]
fn reclaim_begin_is_terminal_even_when_no_capability_operation_succeeds() {
    let (mut registry, before) = populated();
    let retiring = registry.begin_reclaim_exact(before).unwrap();
    assert!(retiring.is_reclaiming());
    assert!(!retiring.is_resident());
    assert_eq!(retiring.mapped_alias(), None);
    assert_eq!(retiring.clone_source_cap(), None);
    assert_eq!(retiring.frame, before.frame);
    assert_eq!(retiring.alias_cap, before.alias_cap);
    assert_eq!(retiring.source_cap, before.source_cap);
    assert_eq!(registry.begin_reclaim_exact(before), None);
    assert_eq!(registry.begin_reclaim_exact(retiring), Some(retiring));
    assert!(!registry.touch(7, 0x1000));
    assert_eq!(registry.get(7, 0x1000), Some(retiring));
}

#[test]
fn retiring_rows_refuse_replay_enrichment_and_replacement() {
    let (mut registry, before) = populated();
    let retiring = registry.begin_reclaim_exact(before).unwrap();
    for (frame, alias, cap, source, owned) in [
        (11, 0x2000, 12, 13, false),
        (11, 0, 0, 0, false),
        (11, 0x3000, 14, 15, false),
        (21, 0x3000, 22, 23, true),
    ] {
        assert_eq!(
            registry.insert(7, 0x1000, frame, alias, cap, source, owned),
            Err(ClientFrameInsertError::Reclaiming),
        );
        assert_eq!(registry.get(7, 0x1000), Some(retiring));
    }
    assert_eq!(registry.stats().reclaim_refusals, 4);
}

#[test]
fn alias_first_reclamation_cannot_resurrect_after_clearing_unmap_progress() {
    let (mut registry, before) = populated();
    let unmapped = registry.mark_alias_unmapped_exact(before).unwrap();
    let cleared = registry.clear_alias_cap_exact(unmapped).unwrap();
    assert!(!cleared.alias_unmapped);
    assert!(!cleared.frame_unmapped);
    assert_eq!(cleared.frame, 11);
    assert!(cleared.is_reclaiming());
    assert!(!cleared.is_resident());
    assert_eq!(cleared.clone_source_cap(), None);
    assert_eq!(
        registry.insert(7, 0x1000, 11, 0x2000, 14, 13, false),
        Err(ClientFrameInsertError::Reclaiming),
    );
}

#[test]
fn source_first_reclamation_also_closes_resident_access() {
    let (mut registry, before) = populated();
    let cleared = registry.clear_source_cap_exact(before).unwrap();
    assert!(cleared.is_reclaiming());
    assert_eq!(cleared.mapped_alias(), None);
    assert_eq!(cleared.clone_source_cap(), None);
    assert_eq!(registry.clear_source_cap_exact(before), None);
}

#[test]
fn identical_key_caps_and_age_reuse_cannot_accept_an_old_snapshot() {
    let (mut registry, old) = populated();
    assert_eq!(registry.take_exact(old), Some(old));
    registry
        .insert_at_age(7, 0x1000, 11, 0x2000, 12, 13, false, 40)
        .unwrap();
    let new = registry.get(7, 0x1000).unwrap();
    assert_ne!(new.record_id, old.record_id);
    assert_eq!(registry.begin_reclaim_exact(old), None);
    assert_eq!(registry.mark_frame_unmapped_exact(old), None);
    assert_eq!(registry.mark_alias_unmapped_exact(old), None);
    assert_eq!(registry.clear_source_cap_exact(old), None);
    assert_eq!(registry.take_exact(old), None);
    assert_eq!(registry.get(7, 0x1000), Some(new));
}

#[test]
fn replacement_after_retirement_has_a_fresh_live_identity() {
    let (mut registry, before) = populated();
    let retiring = registry.begin_reclaim_exact(before).unwrap();
    assert_eq!(registry.take_exact(retiring), Some(retiring));
    registry
        .insert_at_age(7, 0x1000, 11, 0x2000, 12, 13, false, 40)
        .unwrap();
    let new = registry.get(7, 0x1000).unwrap();
    assert!(new.is_resident());
    assert!(!new.is_reclaiming());
    assert_ne!(new.record_id, retiring.record_id);
    assert_eq!(registry.take_exact(retiring), None);
}

#[test]
fn snapshots_are_not_interchangeable_between_registries() {
    let (_, old) = populated();
    let (mut registry, own) = populated();
    assert_ne!(old.record_id, own.record_id);
    assert_eq!(registry.begin_reclaim_exact(old), None);
    assert_eq!(registry.take_exact(old), None);
    assert_eq!(registry.get(7, 0x1000), Some(own));
}

#[test]
fn record_identity_exhaustion_never_wraps() {
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(allocate_record_id(&counter), Ok(u64::MAX - 1));
    for _ in 0..3 {
        assert_eq!(
            allocate_record_id(&counter),
            Err(ClientFrameInsertError::IdentityExhausted)
        );
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
