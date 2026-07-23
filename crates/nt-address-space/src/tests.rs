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
fn space() -> AddressSpace {
    AddressSpace::new(0x1_0000, 0x1000_0000, 0x1000_0000)
}

#[test]
fn va_allocation_and_overlap() {
    let mut a = space();
    let (_, b1) = a
        .reserve_view(
            None,
            0x2000,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(b1 % ALLOCATION_GRANULARITY, 0); // granularity-aligned
    let (_, b2) = a
        .reserve_view(
            None,
            0x2000,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_ne!(b1, b2); // distinct regions
                        // Reserving over an existing region conflicts.
    assert_eq!(
        a.reserve_view(
            Some(b1),
            0x1000,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0
        ),
        Err(STATUS_CONFLICTING_ADDRESSES)
    );
    assert_eq!(a.vad_count(), 2);
}

#[test]
fn demand_paging_faults_on_touch() {
    // A reserved section view is NOT resident until a fault touches it (spec §10.3, §12).
    let mut cache = file_cache(b"abcdef");
    let mut a = space();
    let (_, base) = a
        .reserve_view(
            None,
            6,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(a.resident_page_count(), 0); // demand mode: nothing resident yet
    let got = a.read(base, 6, &mut cache).unwrap();
    assert_eq!(&got[..], b"abcdef"); // fault materialised the page from the cache
    assert_eq!(a.resident_page_count(), 1);
}

#[test]
fn acceptance_mapped_edit_through_fault_path() {
    // Map a file view, edit through the fault/write path, unmap → writeback, flush → file edited.
    let mut cache = file_cache(b"abcdef");
    let mut a = space();
    let (vad, base) = a
        .reserve_view(
            None,
            6,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(a.read(base, 6, &mut cache).unwrap(), b"abcdef");
    a.write(base + 1, b"XYZ", &mut cache).unwrap(); // "aXYZef"
    a.unmap_view(vad, &mut cache).unwrap(); // dirty page → CcCopyWrite
    cache.cc_flush_cache(None, None);
    assert_eq!(&cache.backing().bytes[..], b"aXYZef");
    assert_eq!(a.commit_charge(), 0); // commit released on unmap
}

#[test]
fn anonymous_view_zero_fill_and_private() {
    let mut a = space();
    let (vad, base) = a
        .reserve_view(
            None,
            0x1000,
            PAGE_READWRITE,
            ViewType::PrivateAnonymous,
            None,
            0,
        )
        .unwrap();
    assert_eq!(a.fault_anonymous(base, FaultAccess::Read), STATUS_SUCCESS);
    // A fresh anonymous page is zero.
    let mut c = file_cache(b"");
    assert_eq!(a.read(base, 4, &mut c).unwrap(), &[0, 0, 0, 0]);
    a.unmap_anonymous(vad).unwrap();
}

#[test]
fn access_violations() {
    let mut cache = file_cache(b"data");
    let mut a = space();
    // Fault on an unreserved address → access violation (spec §12.2).
    assert_eq!(
        a.fault(0x5000_0000, FaultAccess::Read, &mut cache),
        STATUS_ACCESS_VIOLATION
    );
    // Write to a read-only view → access violation (spec §12.4).
    let (_, ro) = a
        .reserve_view(
            None,
            4,
            PAGE_READONLY,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(
        a.fault(ro, FaultAccess::Write, &mut cache),
        STATUS_ACCESS_VIOLATION
    );
    assert_eq!(a.fault(ro, FaultAccess::Read, &mut cache), STATUS_SUCCESS); // read is fine
                                                                            // A NOACCESS view rejects everything.
    let (_, na) = a
        .reserve_view(
            None,
            4,
            PAGE_NOACCESS,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(
        a.fault(na, FaultAccess::Read, &mut cache),
        STATUS_ACCESS_VIOLATION
    );
}

#[test]
fn commit_limit_enforced() {
    let mut a = AddressSpace::new(0x1_0000, 0x1000_0000, 0x8000); // 32 KiB commit limit
    a.reserve_view(
        None,
        0x4000,
        PAGE_READWRITE,
        ViewType::PrivateAnonymous,
        None,
        0,
    )
    .unwrap();
    a.reserve_view(
        None,
        0x4000,
        PAGE_READWRITE,
        ViewType::PrivateAnonymous,
        None,
        0,
    )
    .unwrap();
    assert_eq!(a.commit_charge(), 0x8000);
    // The next reservation exceeds the commit limit.
    assert_eq!(
        a.reserve_view(
            None,
            0x1000,
            PAGE_READWRITE,
            ViewType::PrivateAnonymous,
            None,
            0
        ),
        Err(STATUS_COMMITMENT_LIMIT)
    );
}

#[test]
fn mdl_probe_lock_unlock() {
    let mut cache = file_cache(b"lockable data here");
    let mut a = space();
    let (_, base) = a
        .reserve_view(
            None,
            18,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    let mut mdl = a
        .mm_probe_and_lock_pages(base, 18, LockAccess::Write, &mut cache)
        .unwrap();
    assert!(mdl.is_locked());
    assert_eq!(a.page_locked_count(base), 1); // page faulted in + locked
    a.mm_unlock_pages(&mut mdl);
    assert!(!mdl.is_locked());
    assert_eq!(a.page_locked_count(base), 0);
    // Locking a read-only view for write fails.
    let (_, ro) = a
        .reserve_view(
            None,
            4,
            PAGE_READONLY,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert!(a
        .mm_probe_and_lock_pages(ro, 4, LockAccess::Write, &mut cache)
        .is_err());
}

#[test]
fn fixed_vm_map_reserves_commits_and_reuses_without_allocation() {
    let mut map = VmRegionMap::<8>::new(0x10000, 0x10_0000);
    let first = map
        .allocate(None, 0x2800, MEM_RESERVE, PAGE_READWRITE)
        .unwrap();
    assert_eq!(
        first,
        VmAllocatePlan {
            base: 0x10000,
            size: 0x3000
        }
    );
    assert!(!map.is_committed(first.base));
    map.allocate(
        Some(first.base + 0x1000),
        0x1000,
        MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();
    assert!(!map.is_committed(first.base));
    assert!(map.is_committed(first.base + 0x1000));
    assert_eq!(map.extent_count(), 3);

    let freed = map.free(first.base, 0, MEM_RELEASE).unwrap();
    assert_eq!(freed.base, first.base);
    assert_eq!(freed.size, first.size);
    assert_eq!(map.extent_count(), 0);
    assert_eq!(
        map.allocate(None, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
            .unwrap()
            .base,
        first.base
    );
}

#[test]
fn fixed_vm_map_decommit_and_partial_release_split_vad() {
    let mut map = VmRegionMap::<8>::new(0x10000, 0x20_0000);
    let allocation = map
        .allocate(
            Some(0x23456),
            0x5000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
        .unwrap();
    assert_eq!(allocation.base, 0x20000);
    assert_eq!(allocation.size, 0x9000);

    let decommit = map.free(0x22001, 0x1800, MEM_DECOMMIT).unwrap();
    assert_eq!(
        decommit,
        VmFreePlan {
            base: 0x22000,
            size: 0x2000,
            free_type: MEM_DECOMMIT
        }
    );
    assert!(map.is_committed(0x21000));
    assert!(!map.is_committed(0x22000));
    assert!(map.is_committed(0x24000));

    map.free(0x24000, 0x1000, MEM_RELEASE).unwrap();
    assert!(map.extent_at(0x23000).is_some());
    assert!(map.extent_at(0x24000).is_none());
    assert!(map.extent_at(0x25000).is_some());
    let right = map.free(0x25fff, 0, MEM_RELEASE).unwrap();
    assert_eq!(right.base, 0x25000);
    assert_eq!(right.size, 0x4000);
    assert!(map.extent_at(0x25000).is_none());
    let left = map.free(0x20000, 0, MEM_RELEASE).unwrap();
    assert_eq!(left.base, 0x20000);
    assert_eq!(left.size, 0x4000);
    assert_eq!(map.extent_count(), 0);
}

#[test]
fn fixed_vm_map_preserves_failure_state_and_reactos_statuses() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    let before = map.extent_count();
    assert_eq!(
        map.free(allocation.base + 0x1000, 0, MEM_RELEASE),
        Err(STATUS_FREE_VM_NOT_AT_BASE)
    );
    assert_eq!(map.extent_count(), before);
    assert!(map.is_committed(allocation.base));
    assert_eq!(
        map.free(allocation.base, 0x5000, MEM_RELEASE),
        Err(STATUS_UNABLE_TO_FREE_VM)
    );
    assert_eq!(
        map.free(allocation.base, 0, MEM_RELEASE | MEM_DECOMMIT),
        Err(STATUS_INVALID_PARAMETER_4)
    );
    assert_eq!(
        map.free(0x90000, 0x1000, MEM_DECOMMIT),
        Err(STATUS_MEMORY_NOT_ALLOCATED)
    );
}

#[test]
fn fixed_vm_map_zero_size_free_accepts_first_page_address() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    let freed = map.free(allocation.base + 0x0fff, 0, MEM_RELEASE).unwrap();
    assert_eq!(freed.base, allocation.base);
    assert_eq!(freed.size, allocation.size);
}

#[test]
fn fixed_vm_map_front_release_rebases_surviving_vad() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    map.free(allocation.base, 0x1000, MEM_RELEASE).unwrap();
    let remainder = map.free(allocation.base + 0x1fff, 0, MEM_RELEASE).unwrap();
    assert_eq!(remainder.base, allocation.base + 0x1000);
    assert_eq!(remainder.size, 0x2000);
}

#[test]
fn fixed_vm_map_null_commit_reserves_and_commit_updates_protection() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let implicit = map
        .allocate(None, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        .unwrap();
    assert!(map.is_committed(implicit.base));
    assert_eq!(
        map.extent_at(implicit.base).unwrap().protection,
        PAGE_EXECUTE_READWRITE
    );

    let reserved = map
        .allocate(None, 0x2000, MEM_RESERVE, PAGE_NOACCESS)
        .unwrap();
    map.allocate(
        Some(reserved.base),
        0x1000,
        MEM_COMMIT,
        PAGE_READWRITE | PAGE_GUARD,
    )
    .unwrap();
    assert_eq!(
        map.extent_at(reserved.base).unwrap().protection,
        PAGE_READWRITE | PAGE_GUARD
    );
    assert_eq!(
        map.allocate(None, 0x1000, MEM_COMMIT, 0x8000),
        Err(STATUS_INVALID_PAGE_PROTECTION)
    );
    assert_eq!(
        map.allocate(
            Some(reserved.base + 0x1000),
            0x1000,
            MEM_COMMIT,
            PAGE_WRITECOPY
        ),
        Err(STATUS_INVALID_PAGE_PROTECTION)
    );
    assert_eq!(
        map.allocate(
            None,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_WRITECOPY
        ),
        Err(STATUS_INVALID_PAGE_PROTECTION)
    );
}

#[test]
fn fixed_vm_map_normalizes_during_capacity_bounded_rewrite() {
    let mut map = VmRegionMap::<2>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    map.free(allocation.base + 0x1000, 0x1000, MEM_DECOMMIT)
        .unwrap();
    assert_eq!(map.extent_count(), 2);
    map.allocate(
        Some(allocation.base + 0x1000),
        0x1000,
        MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();
    assert_eq!(map.extent_count(), 1);
}

#[test]
fn fixed_vm_map_recommit_changes_subrange_protection() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    map.allocate(
        Some(allocation.base + 0x1000),
        0x1000,
        MEM_COMMIT,
        PAGE_EXECUTE_READ,
    )
    .unwrap();
    assert_eq!(map.extent_count(), 3);
    assert_eq!(
        map.extent_at(allocation.base + 0x1000).unwrap().protection,
        PAGE_EXECUTE_READ
    );
}

#[test]
fn fixed_vm_map_idempotent_recommit_coalesces_at_exact_capacity() {
    let mut map = VmRegionMap::<1>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    map.allocate(
        Some(allocation.base + 0x1000),
        0x1000,
        MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();
    assert_eq!(map.extent_count(), 1);
}

#[test]
fn fixed_vm_map_allocate_validation_matches_native_precedence() {
    let mut map = VmRegionMap::<2>::new(0x10000, 0x10_0000);
    assert_eq!(map.allocate(None, 0, 0, 0), Err(STATUS_INVALID_PARAMETER_5));
    assert_eq!(
        map.allocate(None, 0, MEM_COMMIT, 0),
        Err(STATUS_INVALID_PAGE_PROTECTION)
    );
    assert_eq!(
        map.allocate(Some(0x10_0000), 0, MEM_COMMIT, PAGE_READWRITE),
        Err(STATUS_INVALID_PARAMETER_2)
    );
    assert_eq!(
        map.allocate(None, 0x10_0000, MEM_COMMIT, PAGE_READWRITE),
        Err(STATUS_NO_MEMORY)
    );
    assert_eq!(
        map.allocate(None, 0x10_0001, MEM_COMMIT, PAGE_READWRITE),
        Err(STATUS_INVALID_PARAMETER_4)
    );
}
