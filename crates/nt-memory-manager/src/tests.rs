use super::*;
use nt_cache_manager::{FileSizes, MemoryBacking, SharedCacheMap};

fn file_cache(bytes: &[u8]) -> SharedCacheMap<MemoryBacking> {
    let n = bytes.len() as u64;
    SharedCacheMap::cc_initialize_cache_map(
        MemoryBacking::with_bytes(bytes.to_vec()),
        FileSizes {
            allocation_size: n,
            file_size: n,
            valid_data_length: n,
        },
        false,
    )
}

#[test]
fn process_commit_ledger_is_transactional_and_limit_checked() {
    let mut ledger = ProcessCommitLedger::new();
    ledger.register(4, 0x2000).unwrap();
    ledger.set_limit(4, 0x5000).unwrap();

    let plan = ledger.prepare_charge(4, 0x3000).unwrap();
    assert_eq!(ledger.accounting(4).unwrap().current_bytes, 0x2000);
    let accounting = ledger.commit_charge(plan).unwrap();
    assert_eq!(accounting.current_bytes, 0x5000);
    assert_eq!(accounting.peak_bytes, 0x5000);
    assert_eq!(
        ledger.prepare_charge(4, 0x1000),
        Err(STATUS_COMMITMENT_LIMIT)
    );

    let accounting = ledger.release(4, 0x4000).unwrap();
    assert_eq!(accounting.current_bytes, 0x1000);
    assert_eq!(accounting.peak_bytes, 0x5000);
    assert_eq!(ledger.unregister(4), Some(accounting));
}

#[test]
fn process_commit_ledger_rejects_stale_plans_and_scales_by_owner() {
    let mut ledger = ProcessCommitLedger::new();
    for owner in 1..=40 {
        ledger.register(owner, 0).unwrap();
    }
    assert_eq!(ledger.owner_count(), 40);

    let stale = ledger.prepare_charge(40, 0x1000).unwrap();
    let current = ledger.prepare_charge(40, 0x2000).unwrap();
    ledger.commit_charge(current).unwrap();
    assert_eq!(
        ledger.commit_charge(stale),
        Err(commit::STATUS_CONFLICTING_ADDRESSES)
    );
    assert_eq!(
        ledger.set_limit(40, 1),
        Err(commit::STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        ledger.release(40, 0x3000),
        Err(commit::STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn process_commit_limit_updates_prepare_without_partial_mutation() {
    let mut ledger = ProcessCommitLedger::new();
    ledger.register_with_limit(4, 0x3000, 0x5000).unwrap();
    ledger.register(8, 0x1000).unwrap();

    let first = ledger.prepare_limit_update(4, 0x2000).unwrap();
    let second = ledger.prepare_limit_update(8, 0x4000).unwrap();
    assert_eq!(ledger.accounting(4).unwrap().limit_bytes, 0x5000);
    assert_eq!(ledger.accounting(8).unwrap().limit_bytes, 0);

    ledger.commit_limit_updates(&[first, second]).unwrap();
    assert_eq!(ledger.accounting(4).unwrap().limit_bytes, 0x2000);
    assert_eq!(ledger.accounting(8).unwrap().limit_bytes, 0x4000);
    assert_eq!(
        ledger.prepare_charge(4, 0x1000),
        Err(STATUS_COMMITMENT_LIMIT)
    );

    let stale = ledger.prepare_limit_update(8, 0x6000).unwrap();
    ledger.set_limit(8, 0x7000).unwrap();
    assert_eq!(
        ledger.commit_limit_update(stale),
        Err(commit::STATUS_CONFLICTING_ADDRESSES)
    );

    let duplicate_a = ledger.prepare_limit_update(4, 0x5000).unwrap();
    let duplicate_b = ledger.prepare_limit_update(4, 0x6000).unwrap();
    assert_eq!(
        ledger.commit_limit_updates(&[duplicate_a, duplicate_b]),
        Err(commit::STATUS_CONFLICTING_ADDRESSES)
    );
    assert_eq!(ledger.accounting(4).unwrap().limit_bytes, 0x2000);
}

#[test]
fn process_commit_registration_validates_initial_limit_atomically() {
    let mut ledger = ProcessCommitLedger::new();
    assert_eq!(
        ledger.register_with_limit(4, 0x3000, 0x2000),
        Err(STATUS_COMMITMENT_LIMIT)
    );
    assert!(!ledger.contains(4));
    assert_eq!(
        ledger.register_with_limit(4, 0x2000, 1),
        Err(commit::STATUS_INVALID_PARAMETER)
    );
    assert!(!ledger.contains(4));
}

#[test]
fn acceptance_mapped_file_edit_flushes_back() {
    // Spec §24: map a file-backed section, edit through the view, unmap, flush → file reflects it.
    let mut cache = file_cache(b"abcdef");
    let mut mm = MemoryManager::new();
    let sec = mm
        .zw_create_section_file(6, PAGE_READWRITE, SEC_COMMIT)
        .unwrap();
    let view = mm
        .zw_map_view_of_section_file(sec, &mut cache, 0, 0, PAGE_READWRITE, AddressSpace::Process)
        .unwrap();
    assert_eq!(mm.view_read(view, 0, 6).unwrap(), b"abcdef"); // materialised from the cache
    mm.view_write(view, 1, b"XYZ").unwrap(); // edit "aXYZef"
    assert_eq!(mm.view_count(sec), 1);
    mm.zw_unmap_view_of_section_file(view, &mut cache).unwrap(); // writeback → cache dirty
    assert!(cache.cc_is_there_dirty_data());
    cache.cc_flush_cache(None, None); // → backing store (the file)
    assert_eq!(&cache.backing().bytes[..], b"aXYZef");
    assert_eq!(mm.view_count(sec), 0);
    assert!(mm.close_section(sec));
}

#[test]
fn system_space_mapping() {
    // Spec §16 acceptance: MmMapViewInSystemSpace edit reflects in the file.
    let mut cache = file_cache(b"0123456789");
    let mut mm = MemoryManager::new();
    let sec = mm
        .zw_create_section_file(10, PAGE_READWRITE, SEC_COMMIT)
        .unwrap();
    let view = mm.mm_map_view_in_system_space(sec, &mut cache, 0).unwrap();
    mm.view_write(view, 5, b"XX").unwrap();
    mm.zw_unmap_view_of_section_file(view, &mut cache).unwrap();
    cache.cc_flush_cache(None, None);
    assert_eq!(&cache.backing().bytes[..], b"01234XX789");
}

#[test]
fn anonymous_section_shares_between_views() {
    // A pagefile section: write via one view, re-map, and see it (spec §9.3, §11.2).
    let mut mm = MemoryManager::new();
    let sec = mm
        .zw_create_section_pagefile(16, PAGE_READWRITE, SEC_COMMIT)
        .unwrap();
    let v1 = mm
        .zw_map_view_of_section_anon(sec, 0, 16, PAGE_READWRITE, AddressSpace::Process)
        .unwrap();
    assert_eq!(mm.view_read(v1, 0, 4).unwrap(), &[0, 0, 0, 0]); // zero-filled
    mm.view_write(v1, 2, b"hi").unwrap();
    mm.zw_unmap_view_of_section_anon(v1).unwrap();
    let v2 = mm
        .zw_map_view_of_section_anon(sec, 0, 16, PAGE_READONLY, AddressSpace::Process)
        .unwrap();
    assert_eq!(mm.view_read(v2, 2, 2).unwrap(), b"hi");
}

#[test]
fn protection_and_access_checks() {
    let mut cache = file_cache(b"data");
    let mut mm = MemoryManager::new();
    // Invalid protection + SEC_IMAGE rejected (spec §8.3, §17).
    assert_eq!(
        mm.zw_create_section_file(4, 0x999, SEC_COMMIT),
        Err(STATUS_INVALID_PAGE_PROTECTION)
    );
    assert_eq!(
        mm.zw_create_section_file(4, PAGE_READWRITE, SEC_IMAGE),
        Err(STATUS_NOT_SUPPORTED)
    );
    // A read-only view rejects writes; a NOACCESS view rejects reads.
    let sec = mm
        .zw_create_section_file(4, PAGE_READONLY, SEC_COMMIT)
        .unwrap();
    let ro = mm
        .zw_map_view_of_section_file(sec, &mut cache, 0, 0, PAGE_READONLY, AddressSpace::Process)
        .unwrap();
    assert_eq!(mm.view_write(ro, 0, b"x"), Err(STATUS_ACCESS_VIOLATION));
    assert_eq!(mm.view_read(ro, 0, 4).unwrap(), b"data");
    let na = mm
        .zw_map_view_of_section_file(sec, &mut cache, 0, 0, PAGE_NOACCESS, AddressSpace::Process)
        .unwrap();
    assert_eq!(mm.view_read(na, 0, 4), Err(STATUS_ACCESS_VIOLATION));
    // A read-only view is not written back even if it were dirtied.
    mm.zw_unmap_view_of_section_file(ro, &mut cache).unwrap();
    assert!(!cache.cc_is_there_dirty_data());
}

#[test]
fn partial_view_offset() {
    // Map a sub-range and confirm the offset maps to the right file bytes.
    let mut cache = file_cache(b"HELLOWORLD");
    let mut mm = MemoryManager::new();
    let sec = mm
        .zw_create_section_file(10, PAGE_READWRITE, SEC_COMMIT)
        .unwrap();
    let view = mm
        .zw_map_view_of_section_file(sec, &mut cache, 5, 5, PAGE_READWRITE, AddressSpace::Process)
        .unwrap();
    assert_eq!(mm.view_read(view, 0, 5).unwrap(), b"WORLD");
    mm.view_write(view, 0, b"world").unwrap();
    mm.zw_unmap_view_of_section_file(view, &mut cache).unwrap();
    cache.cc_flush_cache(None, None);
    assert_eq!(&cache.backing().bytes[..], b"HELLOworld");
}
