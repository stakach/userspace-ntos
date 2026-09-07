use super::*;
use crate::thread_resources::ThreadMemoryLayout;
use crate::thread_rollback::{
    ThreadRollback, ThreadRollbackIdentity, ThreadRollbackResourceKind as Kind,
};

const REGISTERED: [u64; 4] = [0x10000, 0x11000, 0x13000, 0x14000];

fn partial() -> ThreadMemoryResources<3> {
    ThreadMemoryResources::new(27, resources(27).layout().unwrap()).unwrap()
}

#[test]
fn partial_teb_alias_inventory_survives_exact_registry_publication() {
    let mut resources = partial();
    resources.teb_owner = 30;
    resources.teb_target = 31;
    resources.teb_scratch = 32;
    resources.teb_local_mirror = 33;
    resources.teb_local_source = 34;
    resources.teb2_owner = 40;
    resources.teb2_target = 41;
    resources.teb2_scratch = 42;
    resources.teb2_local_mirror = 43;
    resources.teb2_local_source = 44;
    let mut registry = ClientFrameRegistry::new();
    let before = ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[]).unwrap();
    assert_eq!(before.rollback_resources().len(), 10);
    registry
        .insert(27, 0x13000, 31, 0x100000, 33, 34, true)
        .unwrap();
    registry
        .insert(27, 0x14000, 41, 0x101000, 43, 44, true)
        .unwrap();
    // Registry insertion acknowledges ownership of these two copies per page.
    resources.teb_local_mirror = 0;
    resources.teb_local_source = 0;
    resources.teb2_local_mirror = 0;
    resources.teb2_local_source = 0;
    let after = ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[0x13000, 0x14000])
        .unwrap();
    assert_eq!(after.rollback_resources(), before.rollback_resources());
    assert_eq!(
        before.revalidate(&resources, &registry),
        Err(ThreadRegistryError::StaleResources)
    );
    let transfer = after
        .prepare_transfer(&resources, &mut registry)
        .unwrap()
        .unwrap();
    assert_eq!(transfer.records().len(), 2);
}

#[test]
fn unpublished_teb_caps_cannot_be_shared_with_an_unselected_registry_row() {
    for cap in [33, 34, 43, 44] {
        let mut resources = resources(27);
        resources.teb_local_mirror = 33;
        resources.teb_local_source = 34;
        resources.teb2_local_mirror = 43;
        resources.teb2_local_source = 44;
        let mut registry = ClientFrameRegistry::new();
        registry.insert(28, 0x20000, 100, 0, 0, cap, false).unwrap();
        assert!(
            matches!(ThreadRegistrySnapshot::capture(&resources, &registry, &[]),
            Err(ThreadRegistryError::SharedCapability { cap: found }) if found == cap)
        );
    }
}

#[test]
fn newly_created_teb_alias_invalidates_an_earlier_cleanup_snapshot() {
    let mut resources = resources(27);
    let registry = ClientFrameRegistry::new();
    let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &[]).unwrap();
    resources.teb_local_source = 34;
    assert_eq!(
        snapshot.revalidate(&resources, &registry),
        Err(ThreadRegistryError::StaleResources)
    );
}

#[test]
fn empty_construction_retains_geometry_without_fabricated_frame_owners() {
    let resources = partial();
    let mut registry = ClientFrameRegistry::new();
    assert!(ThreadRegistrySnapshot::capture(&resources, &registry, &[]).is_err());
    let snapshot = ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[]).unwrap();
    assert!(snapshot.records().is_empty());
    assert!(snapshot.rollback_resources().is_empty());
    assert!(snapshot
        .prepare_transfer(&resources, &mut registry)
        .unwrap()
        .is_none());
    assert_eq!(snapshot.revalidate(&resources, &registry), Ok(()));
}

#[test]
fn partial_capture_merges_only_constructed_backing_and_exact_registered_aliases() {
    let mut resources = partial();
    resources.stack_owner[0] = 10;
    resources.stack_target[0] = 11;
    resources.stack_mirror[0] = 12;
    resources.ipc_owner = 60;
    let mut registry = ClientFrameRegistry::new();
    registry
        .insert(27, 0x10000, 11, 0x100000, 12, 13, true)
        .unwrap();
    let snapshot =
        ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[0x10000]).unwrap();
    let owners: Vec<_> = snapshot
        .rollback_resources()
        .iter()
        .filter(|entry| entry.kind == Kind::Frame)
        .map(|entry| entry.cap)
        .collect();
    assert_eq!(owners, [10, 60]);
    let aliases: Vec<_> = snapshot
        .rollback_resources()
        .iter()
        .filter(|entry| entry.kind == Kind::Alias)
        .map(|entry| entry.cap)
        .collect();
    assert_eq!(aliases, [11, 12, 13]);
    assert_eq!(snapshot.records(), registry.records());
}

#[test]
fn partial_capture_refuses_registry_coverage_for_an_unbuilt_page() {
    let resources = partial();
    let registry = ClientFrameRegistry::new();
    assert!(matches!(
        ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[0x10000]),
        Err(ThreadRegistryError::InvalidCoverage)
    ));
}

#[test]
fn partial_capture_refuses_orphan_aliases_and_duplicate_physical_owners() {
    let mut resources = partial();
    resources.stack_target[0] = 11;
    let registry = ClientFrameRegistry::new();
    assert!(matches!(
        ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[]),
        Err(ThreadRegistryError::Resources(
            crate::thread_rollback::ThreadRollbackError::ConflictingOwnership
        ))
    ));
    resources.stack_owner[0] = 10;
    resources.stack_owner[1] = 10;
    assert!(matches!(
        ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[]),
        Err(ThreadRegistryError::Resources(
            crate::thread_rollback::ThreadRollbackError::ConflictingOwnership
        ))
    ));
}

#[test]
fn partial_capture_checks_unbuilt_geometry_for_unexpected_rows() {
    let mut resources = partial();
    resources.stack_owner[0] = 10;
    let mut registry = ClientFrameRegistry::new();
    registry.insert(27, 0x14000, 40, 0, 0, 40, true).unwrap();
    assert!(matches!(
        ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[]),
        Err(ThreadRegistryError::UnexpectedRecord { page: 0x14000 })
    ));
    assert_eq!(registry.records().len(), 1);
}

#[test]
fn partial_snapshot_rejects_later_construction_or_new_aliases_before_transfer() {
    let mut resources = partial();
    resources.stack_owner[0] = 10;
    let mut registry = ClientFrameRegistry::new();
    let snapshot = ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[]).unwrap();
    resources.teb_owner = 30;
    assert_eq!(
        snapshot.revalidate(&resources, &registry),
        Err(ThreadRegistryError::StaleResources)
    );
    resources.teb_owner = 0;
    registry.insert(27, 0x14000, 40, 0, 0, 40, true).unwrap();
    assert!(matches!(
        snapshot.prepare_transfer(&resources, &mut registry),
        Err(ThreadRegistryError::UnexpectedRecord { page: 0x14000 })
    ));
}

#[test]
fn partial_inventory_rejects_capabilities_shared_by_foreign_registry_rows() {
    let mut resources = partial();
    resources.stack_owner[0] = 10;
    resources.stack_target[0] = 11;
    let mut registry = ClientFrameRegistry::new();
    registry
        .insert(28, 0x80000, 100, 0x90000, 11, 100, false)
        .unwrap();
    assert!(matches!(
        ThreadRegistrySnapshot::capture_partial(&resources, &registry, &[]),
        Err(ThreadRegistryError::SharedCapability { cap: 11 })
    ));
}

fn resources(pi: usize) -> ThreadMemoryResources<3> {
    let layout = ThreadMemoryLayout::new(0x10000, 2, 0x12000, 0x13000, 0x16000).unwrap();
    let mut resources = ThreadMemoryResources::new(pi, layout).unwrap();
    resources.stack_owner = [10, 20, 0];
    resources.stack_target = [11, 21, 0];
    resources.stack_mirror = [12, 22, 0];
    resources.teb_owner = 30;
    resources.teb_target = 31;
    resources.teb_scratch = 32;
    resources.teb2_owner = 40;
    resources.teb2_target = 41;
    resources.teb2_scratch = 42;
    resources.acs_owner = 50;
    resources.acs_target = 51;
    resources.ipc_owner = 60;
    resources.tramp_owner = 70;
    resources.tramp_target = 71;
    resources
}

fn registry(pi: usize) -> ClientFrameRegistry {
    let mut registry = ClientFrameRegistry::new();
    for (page, frame, alias, source) in [
        (0x10000, 10, 12, 10),
        (0x11000, 20, 22, 20),
        (0x13000, 31, 33, 34),
        (0x14000, 41, 43, 44),
    ] {
        registry
            .insert(pi as u64, page, frame, page + 0x100000, alias, source, true)
            .unwrap();
    }
    registry
}

#[test]
fn native_target_teb_records_never_become_second_physical_owners() {
    let resources = resources(27);
    let registry = registry(27);
    let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED).unwrap();
    let owners: Vec<_> = snapshot
        .rollback_resources()
        .iter()
        .filter(|resource| resource.kind == Kind::Frame)
        .map(|resource| resource.cap)
        .collect();
    assert_eq!(owners, [10, 20, 30, 40, 50, 60, 70]);
    for cap in [31, 33, 34, 41, 43, 44] {
        assert_eq!(
            snapshot
                .rollback_resources()
                .iter()
                .filter(|resource| resource.cap == cap)
                .count(),
            1
        );
        assert_eq!(
            snapshot
                .rollback_resources()
                .iter()
                .find(|resource| resource.cap == cap)
                .unwrap()
                .kind,
            Kind::Alias
        );
    }
    assert_eq!(snapshot.records(), registry.records());
    assert!(registry.records().iter().all(|record| record.is_resident()));
}

#[test]
fn owner_and_target_representations_use_runtime_authority_not_registry_flags() {
    for owns_frame in [false, true] {
        let resources = resources(27);
        let mut registry = registry(27);
        registry.take(27, 0x13000).unwrap();
        registry
            .insert(27, 0x13000, 30, 0, 0, 30, owns_frame)
            .unwrap();
        let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED).unwrap();
        assert_eq!(
            snapshot
                .rollback_resources()
                .iter()
                .filter(|entry| entry.cap == 30)
                .count(),
            1
        );
        assert_eq!(
            snapshot
                .rollback_resources()
                .iter()
                .find(|entry| entry.cap == 30)
                .unwrap()
                .kind,
            Kind::Frame
        );
    }
}

#[test]
fn same_page_dormant_and_duplicate_registry_aliases_are_retained_once() {
    let resources = resources(27);
    let mut registry = registry(27);
    registry.take(27, 0x13000).unwrap();
    registry.insert(27, 0x13000, 31, 0, 33, 33, true).unwrap();
    let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED).unwrap();
    assert_eq!(
        snapshot
            .rollback_resources()
            .iter()
            .filter(|entry| entry.cap == 33)
            .count(),
        1
    );
    assert_eq!(
        snapshot
            .records()
            .iter()
            .find(|row| row.page == 0x13000)
            .unwrap()
            .alias,
        0
    );
}

#[test]
fn registration_coverage_is_explicit_for_zero_and_nonzero_process_indices() {
    for pi in [0, 27] {
        let resources = resources(pi);
        let mut empty = ClientFrameRegistry::new();
        let snapshot = ThreadRegistrySnapshot::capture(&resources, &empty, &[]).unwrap();
        assert!(snapshot.records().is_empty());
        assert_eq!(
            snapshot.rollback_resources(),
            resources.rollback_resources().unwrap()
        );
        assert!(snapshot
            .prepare_transfer(&resources, &mut empty)
            .unwrap()
            .is_none());
        assert!(matches!(
            ThreadRegistrySnapshot::capture(&resources, &empty, &REGISTERED),
            Err(ThreadRegistryError::MissingRecord { .. })
        ));
        let populated = registry(pi);
        assert!(ThreadRegistrySnapshot::capture(&resources, &populated, &REGISTERED).is_ok());
        assert!(matches!(
            ThreadRegistrySnapshot::capture(&resources, &populated, &[]),
            Err(ThreadRegistryError::UnexpectedRecord { .. })
        ));
    }
}

#[test]
fn arbitrary_backing_pages_can_be_explicitly_registered_without_role_policy() {
    let resources = resources(0);
    let mut registry = ClientFrameRegistry::new();
    let mut pages = Vec::new();
    for (page, owner, _) in resources.backing_pages() {
        registry.insert(0, page, owner, 0, 0, owner, false).unwrap();
        pages.push(page);
    }
    pages.reverse();
    let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &pages).unwrap();
    assert_eq!(snapshot.records().len(), 7);
    assert_eq!(
        snapshot.rollback_resources(),
        resources.rollback_resources().unwrap()
    );
    let transfer = snapshot
        .prepare_transfer(&resources, &mut registry)
        .unwrap()
        .unwrap();
    registry.finish_transfer(transfer).unwrap();
    assert!(registry.is_process_empty(0));
}

#[test]
fn empty_coverage_is_revalidated_before_reporting_no_registry_transfer() {
    let resources = resources(27);
    let mut registry = ClientFrameRegistry::new();
    let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &[]).unwrap();
    registry.insert(27, 0x13000, 31, 0, 0, 0, true).unwrap();
    let before = registry.records().to_vec();
    assert!(matches!(
        snapshot.prepare_transfer(&resources, &mut registry),
        Err(ThreadRegistryError::UnexpectedRecord { page: 0x13000 }),
    ));
    assert_eq!(registry.records(), before);
}

#[test]
fn malformed_coverage_and_partial_resources_are_refused_without_mutation() {
    let mut resources = resources(27);
    let registry = registry(27);
    let before = registry.records().to_vec();
    for pages in [&[0x10000, 0x10000][..], &[0x10001][..], &[0x17000][..]] {
        assert!(matches!(
            ThreadRegistrySnapshot::capture(&resources, &registry, pages),
            Err(ThreadRegistryError::InvalidCoverage)
        ));
    }
    resources.ipc_owner = 0;
    assert!(matches!(
        ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED),
        Err(ThreadRegistryError::Resources(_))
    ));
    resources = self::resources(27);
    resources.stack_owner[2] = 99;
    assert!(matches!(
        ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED),
        Err(ThreadRegistryError::Resources(_))
    ));
    assert!(matches!(
        ThreadRegistrySnapshot::capture(&ThreadMemoryResources::<3>::empty(), &registry, &[]),
        Err(ThreadRegistryError::Resources(_))
    ));
    assert_eq!(registry.records(), before);
}

#[test]
fn missing_or_wrong_process_rows_cannot_satisfy_coverage() {
    let resources = resources(27);
    assert!(matches!(
        ThreadRegistrySnapshot::capture(&resources, &registry(28), &REGISTERED),
        Err(ThreadRegistryError::MissingRecord { page: 0x10000 })
    ));
    let mut registry = registry(27);
    registry.take(27, 0x14000).unwrap();
    assert!(matches!(
        ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED),
        Err(ThreadRegistryError::MissingRecord { page: 0x14000 })
    ));
}

#[test]
fn registry_frame_must_match_the_pages_owner_or_target_not_an_arbitrary_copy() {
    let resources = resources(27);
    for wrong in [32, 99, 40] {
        let mut registry = registry(27);
        registry.take(27, 0x13000).unwrap();
        registry.insert(27, 0x13000, wrong, 0, 0, 0, true).unwrap();
        assert!(matches!(
            ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED),
            Err(ThreadRegistryError::WrongFrame { page: 0x13000 })
        ));
    }
}

#[test]
fn every_unselected_geometry_page_and_overlapping_unaligned_row_is_checked() {
    let resources = resources(27);
    for page in [0x12000, 0x15000, 0x16000, 0x10001] {
        let mut registry = registry(27);
        registry.insert(27, page, 99, 0, 0, 0, true).unwrap();
        assert!(matches!(
            ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED),
            Err(ThreadRegistryError::UnexpectedRecord { .. })
        ));
    }
}

#[test]
fn cross_page_capability_reuse_is_rejected_even_for_the_same_capability_kind() {
    let resources = resources(27);
    for cap in [10, 11, 12, 20, 40, 41, 43, 50, 51, 60, 70, 71] {
        let mut registry = registry(27);
        registry.take(27, 0x13000).unwrap();
        registry.insert(27, 0x13000, 31, 0, cap, cap, true).unwrap();
        assert!(matches!(
            ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED),
            Err(ThreadRegistryError::Resources(
                ThreadRollbackError::ConflictingOwnership
            ))
        ));
    }
}

#[test]
fn unselected_registry_rows_must_not_share_any_captured_capability() {
    let resources = resources(27);
    for pi in [27, 28] {
        for cap in [10, 31, 33, 34, 50, 60, 70] {
            for field in 0..3 {
                let mut registry = registry(27);
                let mut caps = [101, 102, 103];
                caps[field] = cap;
                registry
                    .insert(pi, 0x90000, caps[0], 0, caps[1], caps[2], false)
                    .unwrap();
                assert!(
                    matches!(ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED), Err(ThreadRegistryError::SharedCapability { cap: found }) if found == cap)
                );
            }
        }
    }
}

#[test]
fn reclaiming_or_already_transferred_records_cannot_be_captured() {
    let resources = resources(27);
    let mut registry = registry(27);
    let row = registry.get(27, 0x13000).unwrap();
    let transfer = registry.prepare_transfer_exact(&[row]).unwrap();
    assert!(matches!(
        ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED),
        Err(ThreadRegistryError::UnavailableRecord { page: 0x13000 })
    ));
    registry.finish_transfer(transfer).unwrap();
    registry.insert(27, 0x13000, 31, 0, 0, 0, true).unwrap();
    let row = registry.get(27, 0x13000).unwrap();
    registry.begin_reclaim_exact(row).unwrap();
    assert!(matches!(
        ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED),
        Err(ThreadRegistryError::UnavailableRecord { page: 0x13000 })
    ));
}

#[test]
fn exact_record_replacement_and_resource_changes_invalidate_capture() {
    let resources = resources(27);
    let mut registry = registry(27);
    let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED).unwrap();
    let mut changed = resources;
    changed.ipc_owner = 199;
    assert_eq!(
        snapshot.revalidate(&changed, &registry),
        Err(ThreadRegistryError::StaleResources)
    );
    let old = registry.take(27, 0x13000).unwrap();
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
    let before = registry.records().to_vec();
    assert!(matches!(
        snapshot.prepare_transfer(&resources, &mut registry),
        Err(ThreadRegistryError::StaleRecord { page: 0x13000 })
    ));
    assert_eq!(registry.records(), before);
}

#[test]
fn newly_present_unselected_pages_prevent_handoff_without_claiming_selected_rows() {
    let resources = resources(27);
    let mut registry = registry(27);
    let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED).unwrap();
    registry.insert(27, 0x12000, 60, 0, 0, 0, true).unwrap();
    let before = registry.records().to_vec();
    assert!(matches!(
        snapshot.prepare_transfer(&resources, &mut registry),
        Err(ThreadRegistryError::UnexpectedRecord { page: 0x12000 })
    ));
    assert_eq!(registry.records(), before);
}

#[test]
fn newly_shared_caps_prevent_handoff_but_unrelated_registry_growth_does_not() {
    let resources = resources(27);
    let mut registry = registry(27);
    let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED).unwrap();
    registry.insert(28, 0x90000, 100, 0, 0, 34, false).unwrap();
    assert!(matches!(
        snapshot.prepare_transfer(&resources, &mut registry),
        Err(ThreadRegistryError::SharedCapability { cap: 34 })
    ));
    registry.take(28, 0x90000).unwrap();
    registry.insert(28, 0x90000, 100, 0, 0, 101, false).unwrap();
    let transfer = snapshot
        .prepare_transfer(&resources, &mut registry)
        .unwrap()
        .unwrap();
    assert_eq!(transfer.records().len(), 4);
    assert!(matches!(
        snapshot.prepare_transfer(&resources, &mut registry),
        Err(ThreadRegistryError::StaleRecord { .. })
    ));
    registry.finish_transfer(transfer).unwrap();
    assert!(registry.is_process_empty(27));
    assert!(registry.get(28, 0x90000).is_some());
}

#[test]
fn rollback_admission_detects_tcb_and_mechanism_collisions_with_registry_only_aliases() {
    let resources = resources(27);
    let registry = registry(27);
    let snapshot = ThreadRegistrySnapshot::capture(&resources, &registry, &REGISTERED).unwrap();
    let identity = ThreadRollbackIdentity {
        pi: 27,
        pid: 90,
        process_generation: crate::process_identity::ProcessGeneration::Hosted(7),
        tid: 301,
    };
    for cap in [33, 34, 43, 44] {
        assert!(matches!(
            ThreadRollback::prepare(identity, cap, snapshot.rollback_resources()),
            Err(ThreadRollbackError::ConflictingOwnership)
        ));
        let mut inventory = snapshot.rollback_resources().to_vec();
        inventory.push(ThreadRollbackResource {
            cap,
            kind: Kind::Mechanism,
        });
        assert!(matches!(
            ThreadRollback::prepare(identity, 1000, &inventory),
            Err(ThreadRollbackError::ConflictingOwnership)
        ));
    }
    let rollback = ThreadRollback::prepare(identity, 1000, snapshot.rollback_resources()).unwrap();
    assert_eq!(
        rollback.pending_resources().collect::<Vec<_>>(),
        snapshot.rollback_resources()
    );
}
