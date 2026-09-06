use super::*;
use nt_memory_manager::{
    private_backing_pages, ClientFrameRegistry, PagefilePage, PagefileStore, ProcessCommitLedger,
};

fn table(protect: u32, type_: u32) -> VmCommittedRangeTable<8> {
    let mut table = VmCommittedRangeTable::new();
    table
        .register(VmCommittedRange {
            base: 0x1000,
            size: 0x4000,
            allocation_base: 0x1000,
            allocation_protect: PAGE_EXECUTE_WRITECOPY,
            protect,
            type_,
        })
        .unwrap();
    table
}

#[test]
fn cow_reprotection_retains_consumed_commitment_but_returns_unused_reservation() {
    for type_ in [MEM_IMAGE, MEM_MAPPED] {
        for protect in [
            PAGE_READONLY,
            PAGE_NOACCESS,
            PAGE_EXECUTE_READ,
            PAGE_READONLY | PAGE_GUARD,
        ] {
            let mut mapping = table(PAGE_WRITECOPY, type_);
            assert_eq!(
                mapping.process_commit_bytes_with_private_pages([0x1000, 0x3000]),
                0x4000
            );
            mapping.protect(0x1000, 0x4000, protect).unwrap();
            assert_eq!(mapping.process_commit_bytes(), 0);
            assert_eq!(
                mapping.process_commit_bytes_with_private_pages([0x1000, 0x3000]),
                0x2000
            );
            assert_eq!(
                mapping
                    .allocation_process_commit_bytes_with_private_pages(0x1000, [0x1000, 0x3000]),
                0x2000
            );
            mapping
                .protect(0x1000, 0x4000, PAGE_EXECUTE_WRITECOPY)
                .unwrap();
            assert_eq!(
                mapping.process_commit_bytes_with_private_pages([0x1000, 0x3000]),
                0x4000
            );
        }
    }
}

#[test]
fn only_registered_owned_section_pages_outside_reservations_add_charge() {
    let mut mapping = table(PAGE_READONLY, MEM_IMAGE);
    mapping
        .register(VmCommittedRange::mapped(0x9000, 0x2000, PAGE_READONLY))
        .unwrap();
    mapping
        .register(VmCommittedRange::private(0xc000, 0x2000, PAGE_READWRITE))
        .unwrap();
    let pages = [0, 0x1000, 0x4000, 0x5000, 0x9000, 0xa000, 0xc000, 0xd000];
    assert_eq!(
        mapping.process_commit_bytes_with_private_pages(pages),
        0x6000
    );
    assert_eq!(
        mapping.allocation_process_commit_bytes_with_private_pages(0x1000, pages),
        0x2000
    );
    assert_eq!(
        mapping.allocation_process_commit_bytes_with_private_pages(0x9000, pages),
        0x2000
    );
    assert_eq!(
        mapping.allocation_process_commit_bytes_with_private_pages(0xc000, pages),
        0x2000
    );
    assert_eq!(
        mapping.allocation_process_commit_bytes_with_private_pages(0x5000, pages),
        0
    );
}

#[test]
fn admission_consumes_existing_reservation_or_requires_one_new_charge() {
    for type_ in [MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE] {
        for protect in [
            PAGE_READWRITE,
            PAGE_EXECUTE_READWRITE,
            PAGE_READONLY,
            PAGE_NOACCESS,
            PAGE_WRITECOPY,
            PAGE_EXECUTE_WRITECOPY | PAGE_GUARD,
        ] {
            let info = table(protect, type_).query_basic(0x1000).unwrap();
            let reserved = type_ == MEM_PRIVATE
                || matches!(protect & 0xff, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY);
            assert_eq!(
                private_backing_admission_bytes(info, false),
                if reserved { 0 } else { PAGE_SIZE }
            );
            assert_eq!(private_backing_admission_bytes(info, true), 0);
        }
    }
}

fn charge(
    mapping: &VmCommittedRangeTable<8>,
    frames: &ClientFrameRegistry,
    pages: &PagefileStore,
) -> u64 {
    mapping.process_commit_bytes_with_private_pages(private_backing_pages(1, frames, pages))
}

#[test]
fn actual_owner_union_survives_pageout_failed_restore_and_unmap() {
    let mut mapping = table(PAGE_WRITECOPY, MEM_IMAGE);
    let mut frames = ClientFrameRegistry::new();
    let mut pages = PagefileStore::new();
    frames.insert(1, 0x1000, 42, 0, 0, 0, true).unwrap();
    frames.insert(2, 0x2000, 43, 0, 0, 0, true).unwrap();
    frames.insert(1, 0x3000, 44, 0, 0, 0, false).unwrap();
    assert_eq!(charge(&mapping, &frames, &pages), 0x4000);
    mapping.protect(0x1000, 0x4000, PAGE_READONLY).unwrap();
    assert_eq!(charge(&mapping, &frames, &pages), PAGE_SIZE);
    let publish = pages
        .prepare_publish(PagefilePage {
            owner: 1,
            page: 0x1000,
            protection: PAGE_READONLY,
            backing: 42,
        })
        .unwrap();
    frames.take(1, 0x1000).unwrap();
    pages.commit_publish(publish).unwrap();
    assert_eq!(charge(&mapping, &frames, &pages), PAGE_SIZE);
    let transition = pages.take(1, 0x1000).unwrap().unwrap();
    pages.restore(transition).unwrap();
    assert_eq!(charge(&mapping, &frames, &pages), PAGE_SIZE);
    let transition = pages.take(1, 0x1000).unwrap().unwrap();
    frames
        .insert(1, 0x1000, transition.backing, 0, 0, 0, true)
        .unwrap();
    assert_eq!(charge(&mapping, &frames, &pages), PAGE_SIZE);
    let release = mapping.allocation_process_commit_bytes_with_private_pages(
        0x1000,
        private_backing_pages(1, &frames, &pages),
    );
    frames.take(1, 0x1000).unwrap();
    mapping.unregister_allocation_base(0x1000);
    assert_eq!(release, PAGE_SIZE);
    assert_eq!(charge(&mapping, &frames, &pages), 0);
}

#[test]
fn direct_writable_image_admission_precedes_ownership_and_can_fail_cleanly() {
    let mapping = table(PAGE_READWRITE, MEM_IMAGE);
    let mut frames = ClientFrameRegistry::new();
    let pages = PagefileStore::new();
    let mut ledger = ProcessCommitLedger::new();
    ledger.register_with_limit(1, 0, PAGE_SIZE).unwrap();
    let info = mapping.query_basic(0x1000).unwrap();
    let bytes = private_backing_admission_bytes(info, false);
    let prepared = ledger.prepare_charge(1, bytes).unwrap();
    assert_eq!(charge(&mapping, &frames, &pages), 0);
    frames.insert(1, 0x1000, 42, 0, 0, 0, true).unwrap();
    ledger.commit_charge(prepared).unwrap();
    assert_eq!(charge(&mapping, &frames, &pages), PAGE_SIZE);
    assert_eq!(
        ledger.prepare_charge(1, bytes).unwrap_err(),
        nt_memory_manager::STATUS_COMMITMENT_LIMIT
    );
    assert!(frames.get(1, 0x2000).is_none());
    assert_eq!(charge(&mapping, &frames, &pages), PAGE_SIZE);
    assert_eq!(private_backing_admission_bytes(info, true), 0);
}

#[test]
fn failed_backing_publication_does_not_consume_prepared_charge() {
    let mut ledger = ProcessCommitLedger::new();
    ledger.register_with_limit(1, 0, PAGE_SIZE).unwrap();
    let _rejected_mapping = ledger.prepare_charge(1, PAGE_SIZE).unwrap();
    // No MM/Ps commit is published when frame mapping or ownership publication fails.
    let retry = ledger.prepare_charge(1, PAGE_SIZE).unwrap();
    ledger.commit_charge(retry).unwrap();
    ledger.release(1, PAGE_SIZE).unwrap();
    assert!(ledger.prepare_charge(1, PAGE_SIZE).is_ok());
}

#[test]
fn reprotection_admission_counts_only_unowned_pages_and_preserves_old_state_on_failure() {
    let mut mapping = table(PAGE_READONLY, MEM_IMAGE);
    let mut ledger = ProcessCommitLedger::new();
    ledger.register_with_limit(1, PAGE_SIZE, 0x3000).unwrap();
    let before = mapping.process_commit_bytes_with_private_pages([0x2000]);
    let mut proposed = mapping;
    proposed.protect(0x1000, 0x4000, PAGE_READWRITE).unwrap();
    let after = proposed.process_commit_bytes_with_private_pages([0x2000]);
    assert_eq!(after - before, 0x3000);
    assert!(ledger.prepare_charge(1, after - before).is_err());
    assert_eq!(mapping.query_basic(0x2000).unwrap().protect, PAGE_READONLY);
    proposed = mapping;
    proposed.protect(0x1000, 0x2000, PAGE_READWRITE).unwrap();
    let added = proposed.process_commit_bytes_with_private_pages([0x2000]) - before;
    assert_eq!(added, PAGE_SIZE);
    let plan = ledger.prepare_charge(1, added).unwrap();
    mapping = proposed;
    ledger.commit_charge(plan).unwrap();
    assert_eq!(
        mapping.process_commit_bytes_with_private_pages([0x2000]),
        0x2000
    );
}

#[test]
fn sparse_backing_does_not_require_walking_the_virtual_reservation() {
    let mut mapping = VmCommittedRangeTable::<1>::new();
    mapping
        .register(VmCommittedRange::mapped(PAGE_SIZE, 1 << 40, PAGE_READONLY))
        .unwrap();
    assert_eq!(
        mapping.process_commit_bytes_with_private_pages([PAGE_SIZE, 1 << 40]),
        2 * PAGE_SIZE
    );
}
