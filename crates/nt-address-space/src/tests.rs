use super::*;

#[test]
fn page_chunks_cover_in_page_boundary_and_cross_page_ranges() {
    assert_eq!(page_chunks(0x1234, 0).unwrap().next(), None);
    assert_eq!(
        page_chunks(0x1234, 3).unwrap().collect::<Vec<_>>(),
        vec![PageChunk {
            page_base: 0x1000,
            page_offset: 0x234,
            length: 3,
        }]
    );
    assert_eq!(
        page_chunks(0x1fff, 1).unwrap().collect::<Vec<_>>(),
        vec![PageChunk {
            page_base: 0x1000,
            page_offset: 0xfff,
            length: 1,
        }]
    );
    assert_eq!(
        page_chunks(0x1ffe, 5).unwrap().collect::<Vec<_>>(),
        vec![
            PageChunk {
                page_base: 0x1000,
                page_offset: 0xffe,
                length: 2,
            },
            PageChunk {
                page_base: 0x2000,
                page_offset: 0,
                length: 3,
            },
        ]
    );
}

#[test]
fn page_chunks_reject_address_space_overflow() {
    assert!(page_chunks(u64::MAX, 0).is_some());
    assert!(page_chunks(u64::MAX, 1).is_none());
    assert!(page_chunks(u64::MAX - 6, 8).is_none());
}

#[test]
fn page_chunks_cover_the_grown_stack_native_tail_window() {
    let chunks = page_chunks(0x0000_0100_105b_ffe0, 0x50)
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(
        chunks,
        vec![
            PageChunk {
                page_base: 0x0000_0100_105b_f000,
                page_offset: 0xfe0,
                length: 0x20,
            },
            PageChunk {
                page_base: 0x0000_0100_105c_0000,
                page_offset: 0,
                length: 0x30,
            },
        ]
    );
}
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
                                                                            // An execute-only view accepts fetches but rejects data reads.
    let (_, exec_only) = a
        .reserve_view(
            None,
            4,
            PAGE_EXECUTE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(
        a.fault(exec_only, FaultAccess::Execute, &mut cache),
        STATUS_SUCCESS
    );
    assert_eq!(
        a.fault(exec_only, FaultAccess::Read, &mut cache),
        STATUS_ACCESS_VIOLATION
    );
    let (_, exec_rw) = a
        .reserve_view(
            None,
            4,
            PAGE_EXECUTE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(
        a.fault(exec_rw, FaultAccess::Write, &mut cache),
        STATUS_SUCCESS
    );
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
fn fixed_vm_map_partial_decommit_queries_rejects_protect_and_recommits() {
    let mut map = VmRegionMap::<8>::new(0x10000, 0x20_0000);
    let allocation = map
        .allocate(None, 0x5000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    map.protect(allocation.base + 0x1000, 0x1000, PAGE_READONLY)
        .unwrap();

    let decommit = map
        .free(allocation.base + 0x1000, 0x2000, MEM_DECOMMIT)
        .unwrap();
    assert_eq!(
        decommit,
        VmFreePlan {
            base: allocation.base + 0x1000,
            size: 0x2000,
            free_type: MEM_DECOMMIT,
        }
    );
    assert_eq!(map.protection_override_count(), 0);
    assert_eq!(
        map.query_basic(allocation.base + 0x1000, 0x20_0000)
            .unwrap(),
        VmBasicInformation {
            base_address: allocation.base + 0x1000,
            allocation_base: allocation.base,
            allocation_protect: PAGE_READWRITE,
            region_size: 0x2000,
            state: MEM_RESERVE,
            protect: 0,
            type_: MEM_PRIVATE,
        }
    );
    assert_eq!(
        map.protect(allocation.base, 0x3000, PAGE_READONLY),
        Err(STATUS_NOT_COMMITTED)
    );
    assert!(!map.permits_read(allocation.base + 0x1000));

    let recommit = map
        .allocate(
            Some(allocation.base + 0x2000),
            0x1000,
            MEM_COMMIT,
            PAGE_EXECUTE_READ,
        )
        .unwrap();
    assert_eq!(
        recommit,
        VmAllocatePlan {
            base: allocation.base + 0x2000,
            size: 0x1000,
        }
    );
    assert_eq!(
        map.query_basic(allocation.base + 0x2000, 0x20_0000)
            .unwrap()
            .protect,
        PAGE_EXECUTE_READ
    );
    assert!(map.permits_read(allocation.base + 0x2000));
    assert!(!map.permits_write(allocation.base + 0x2000));
}

#[test]
fn fixed_vm_map_partial_decommit_capacity_failure_preserves_state() {
    let mut map = VmRegionMap::<1>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();

    assert_eq!(
        map.free(allocation.base + 0x1000, 0x1000, MEM_DECOMMIT),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(map.extent_count(), 1);
    assert!(map.is_committed(allocation.base));
    assert!(map.is_committed(allocation.base + 0x1000));
    assert!(map.is_committed(allocation.base + 0x2000));
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
fn fixed_vm_map_middle_release_rebases_queries_and_reuses_gap() {
    let mut map = VmRegionMap::<8>::new(0x10000, 0x80_0000);
    let allocation = map
        .allocate(
            Some(0x20000),
            0x30000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
        .unwrap();
    assert_eq!(
        allocation,
        VmAllocatePlan {
            base: 0x20000,
            size: 0x30000,
        }
    );

    let released = map.free(0x30000, 0x10000, MEM_RELEASE).unwrap();
    assert_eq!(
        released,
        VmFreePlan {
            base: 0x30000,
            size: 0x10000,
            free_type: MEM_RELEASE,
        }
    );
    assert_eq!(
        map.query_basic(0x20000, 0x80_0000).unwrap(),
        VmBasicInformation {
            base_address: 0x20000,
            allocation_base: 0x20000,
            allocation_protect: PAGE_READWRITE,
            region_size: 0x10000,
            state: MEM_COMMIT,
            protect: PAGE_READWRITE,
            type_: MEM_PRIVATE,
        }
    );
    assert_eq!(
        map.query_basic(0x30000, 0x80_0000).unwrap(),
        VmBasicInformation {
            base_address: 0x30000,
            allocation_base: 0,
            allocation_protect: 0,
            region_size: 0x10000,
            state: MEM_FREE,
            protect: PAGE_NOACCESS,
            type_: 0,
        }
    );
    assert_eq!(
        map.query_basic(0x40000, 0x80_0000).unwrap(),
        VmBasicInformation {
            base_address: 0x40000,
            allocation_base: 0x40000,
            allocation_protect: PAGE_READWRITE,
            region_size: 0x10000,
            state: MEM_COMMIT,
            protect: PAGE_READWRITE,
            type_: MEM_PRIVATE,
        }
    );

    let reused = map
        .allocate(
            Some(0x30000),
            0x2000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READONLY,
        )
        .unwrap();
    assert_eq!(
        reused,
        VmAllocatePlan {
            base: 0x30000,
            size: 0x2000,
        }
    );
    assert_eq!(
        map.query_basic(0x32000, 0x80_0000).unwrap().region_size,
        0xe000
    );
    let right = map.free(0x40fff, 0, MEM_RELEASE).unwrap();
    assert_eq!(right.base, 0x40000);
    assert_eq!(right.size, 0x10000);
    assert!(map.extent_at(0x20000).is_some());
    assert!(map.extent_at(0x30000).is_some());
    assert!(map.extent_at(0x40000).is_none());
}

#[test]
fn fixed_vm_map_middle_release_capacity_failure_preserves_state() {
    let mut map = VmRegionMap::<1>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();

    assert_eq!(
        map.free(allocation.base + 0x1000, 0x1000, MEM_RELEASE),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(map.extent_count(), 1);
    assert!(map.is_committed(allocation.base));
    assert!(map.is_committed(allocation.base + 0x1000));
    assert!(map.is_committed(allocation.base + 0x2000));
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
    map.allocate(
        Some(reserved.base + 0x1000),
        0x1000,
        MEM_COMMIT,
        PAGE_WRITECOPY,
    )
    .unwrap();
    map.allocate(
        None,
        0x1000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_WRITECOPY,
    )
    .unwrap();
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
        Err(STATUS_CONFLICTING_ADDRESSES)
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

#[test]
fn fixed_vm_allocate_argument_validation_matches_reactos_order() {
    assert_eq!(
        validate_allocate_parameters(54, 0, 0),
        Err(STATUS_INVALID_PARAMETER_3)
    );
    assert_eq!(
        validate_allocate_parameters(0, 0, 0),
        Err(STATUS_INVALID_PARAMETER_5)
    );
    assert_eq!(
        validate_allocate_parameters(0, MEM_RESET | MEM_COMMIT, PAGE_READWRITE),
        Err(STATUS_INVALID_PARAMETER_5)
    );
    assert_eq!(
        validate_allocate_parameters(0, MEM_WRITE_WATCH | MEM_COMMIT, PAGE_READWRITE),
        Err(STATUS_INVALID_PARAMETER_5)
    );
    assert_eq!(
        validate_allocate_parameters(0, MEM_PHYSICAL | MEM_RESERVE, PAGE_READONLY),
        Err(STATUS_INVALID_PARAMETER_6)
    );
    assert_eq!(
        validate_allocate_parameters(0, MEM_COMMIT, PAGE_WRITECOPY),
        Ok(())
    );
    assert_eq!(
        validate_allocate_parameters(0, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE,),
        Ok(())
    );
}

#[test]
fn fixed_vm_map_places_top_down_and_honors_zero_bits_ceiling() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let first = map
        .allocate(
            None,
            0x1000,
            MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
            PAGE_READWRITE,
        )
        .unwrap();
    assert_eq!(first.base, 0xF_0000);
    let second = map
        .allocate(
            None,
            0x1000,
            MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
            PAGE_READWRITE,
        )
        .unwrap();
    assert_eq!(second.base, 0xE_0000);
    assert_eq!(
        map.allocate_below(
            None,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            0x10000,
        ),
        Err(STATUS_NO_MEMORY)
    );
}

#[test]
fn fixed_vm_map_top_down_skips_conflicts_and_reports_high_gap() {
    let mut map = VmRegionMap::<8>::new(0x10000, 0x20_0000);
    map.allocate(
        Some(0x1f_0000),
        0x10000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();
    map.allocate(
        Some(0x1c_0000),
        0x10000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();

    let first = map
        .allocate(
            None,
            0x1000,
            MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
            PAGE_READWRITE,
        )
        .unwrap();
    assert_eq!(first.base, 0x1e_0000);

    let second = map
        .allocate(
            None,
            0x1000,
            MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
            PAGE_READWRITE,
        )
        .unwrap();
    assert_eq!(second.base, 0x1d_0000);
    assert_eq!(
        map.query_basic(0x1d_1000, 0x20_0000).unwrap(),
        VmBasicInformation {
            base_address: 0x1d_1000,
            allocation_base: 0,
            allocation_protect: 0,
            region_size: 0xf000,
            state: MEM_FREE,
            protect: PAGE_NOACCESS,
            type_: 0,
        }
    );
}

#[test]
fn fixed_vm_map_reset_preserves_existing_commit() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    let reset = map
        .allocate(
            Some(allocation.base + 0x800),
            0x800,
            MEM_RESET,
            PAGE_READONLY,
        )
        .unwrap();
    assert_eq!(reset.base, allocation.base);
    assert_eq!(reset.size, 0x1000);
    assert_eq!(
        map.extent_at(allocation.base).unwrap().protection,
        PAGE_READWRITE
    );
}

#[test]
fn fixed_vm_map_reset_matches_reactos_overlap_hack() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x30_0000);
    let allocation = map
        .allocate(None, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    assert_eq!(
        map.allocate(
            Some(allocation.base + 0x1000),
            0x20_0000,
            MEM_RESET,
            PAGE_WRITECOPY,
        ),
        Ok(VmAllocatePlan {
            base: allocation.base + 0x1000,
            size: 0x20_0000,
        })
    );
    assert_eq!(
        map.allocate(Some(0x280000), 0x1000, MEM_RESET, PAGE_READWRITE),
        Err(STATUS_CONFLICTING_ADDRESSES)
    );
    let new_reset = map
        .allocate(None, 0x1000, MEM_RESET, PAGE_READWRITE)
        .unwrap();
    assert_eq!(
        map.extent_at(new_reset.base).unwrap().state,
        VmExtentState::Reserved
    );
}

#[test]
fn fixed_vm_map_reports_committed_access_permissions() {
    let mut map = VmRegionMap::<6>::new(0x10000, 0x10_0000);
    let no_access = map
        .allocate(None, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS)
        .unwrap();
    let execute_only = map
        .allocate(None, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE)
        .unwrap();
    let executable = map
        .allocate(None, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ)
        .unwrap();
    let writable = map
        .allocate(
            None,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
        .unwrap();
    let guarded = map
        .allocate(
            None,
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE | PAGE_GUARD,
        )
        .unwrap();
    assert!(!map.permits_read(no_access.base));
    assert!(!map.permits_write(no_access.base));
    assert!(!map.permits_read(execute_only.base));
    assert!(!map.permits_write(execute_only.base));
    assert!(map.permits_read(executable.base));
    assert!(!map.permits_write(executable.base));
    assert!(map.permits_read(writable.base));
    assert!(map.permits_write(writable.base));
    assert!(!map.permits_read(guarded.base));
    assert!(!map.permits_write(guarded.base));
    assert!(!map.permits_read(0xF_0000));
}

#[test]
fn fixed_vm_map_protect_rounds_range_and_returns_old_protection() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();

    let protected = map
        .protect(allocation.base + 0x108, 0x800, PAGE_READONLY)
        .unwrap();
    assert_eq!(
        protected,
        VmProtectPlan {
            base: allocation.base,
            size: 0x1000,
            old_protection: PAGE_READWRITE,
            new_protection: PAGE_READONLY,
        }
    );
    assert_eq!(map.extent_count(), 1);
    assert_eq!(map.protection_override_count(), 1);
    assert_eq!(map.protection_at(allocation.base), Some(PAGE_READONLY));
    assert_eq!(
        map.extent_at(allocation.base).unwrap().protection,
        PAGE_READWRITE
    );
    assert!(!map.permits_write(allocation.base));
    assert!(map.permits_write(allocation.base + 0x1000));

    let mixed = map.protect(allocation.base, 0x2000, PAGE_NOACCESS).unwrap();
    assert_eq!(mixed.old_protection, PAGE_READONLY);
    assert_eq!(mixed.size, 0x2000);
    assert_eq!(map.extent_count(), 1);
    assert_eq!(map.protection_override_count(), 2);
    assert!(!map.permits_read(allocation.base));
    assert!(!map.permits_read(allocation.base + 0x1000));
    assert!(map.permits_write(allocation.base + 0x2000));
}

#[test]
fn fixed_vm_map_protect_rejects_uncommitted_and_cross_allocation_ranges() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let reserved = map
        .allocate(None, 0x2000, MEM_RESERVE, PAGE_NOACCESS)
        .unwrap();
    assert_eq!(
        map.protect(reserved.base, 0x1000, PAGE_READWRITE),
        Err(STATUS_NOT_COMMITTED)
    );

    let first = map
        .allocate(None, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    let second = map
        .allocate(
            Some(first.base + 0x10000),
            0x1000,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
        .unwrap();
    assert_eq!(
        map.protect(first.base, second.base - first.base + 0x1000, PAGE_READONLY),
        Err(STATUS_CONFLICTING_ADDRESSES)
    );
}

#[test]
fn fixed_vm_map_protect_validation_matches_reactos_private_path() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    assert_eq!(
        validate_protect_parameters(PAGE_READWRITE | PAGE_GUARD),
        Ok(())
    );
    assert_eq!(
        validate_protect_parameters(PAGE_READWRITE | PAGE_WRITECOMBINE),
        Err(STATUS_INVALID_PAGE_PROTECTION)
    );
    assert_eq!(
        map.protect(allocation.base, 0x1000, PAGE_WRITECOPY),
        Err(STATUS_INVALID_PARAMETER_4)
    );
    assert_eq!(
        map.protect(allocation.base, 0, PAGE_READONLY),
        Err(STATUS_INVALID_PARAMETER_3)
    );
}

#[test]
fn fixed_vm_map_protect_capacity_failure_preserves_state() {
    let mut map = VmRegionMap::<1>::new(0x10000, 0x20_0000);
    let allocation = map
        .allocate(
            None,
            (VM_PROTECTION_OVERRIDE_CAPACITY as u64 + 1) * PAGE_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
        .unwrap();

    assert_eq!(
        map.protect(
            allocation.base,
            (VM_PROTECTION_OVERRIDE_CAPACITY as u64 + 1) * PAGE_SIZE,
            PAGE_READONLY,
        ),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(map.protection_override_count(), 0);
    assert!(map.permits_write(allocation.base));
    assert!(
        map.permits_write(allocation.base + (VM_PROTECTION_OVERRIDE_CAPACITY as u64) * PAGE_SIZE)
    );
}

#[test]
fn fixed_vm_map_protect_clears_overrides_on_default_recommit_and_free() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x10_0000);
    let allocation = map
        .allocate(None, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();

    map.protect(allocation.base, 0x2000, PAGE_READONLY).unwrap();
    assert_eq!(map.extent_count(), 1);
    assert_eq!(map.protection_override_count(), 2);
    assert!(!map.permits_write(allocation.base));
    assert!(!map.permits_write(allocation.base + 0x1000));

    map.protect(allocation.base, 0x1000, PAGE_READWRITE)
        .unwrap();
    assert_eq!(map.protection_override_count(), 1);
    assert!(map.permits_write(allocation.base));
    assert!(!map.permits_write(allocation.base + 0x1000));

    map.free(allocation.base + 0x1000, 0x1000, MEM_DECOMMIT)
        .unwrap();
    assert_eq!(map.protection_override_count(), 0);
    map.allocate(
        Some(allocation.base + 0x1000),
        0x1000,
        MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();
    assert!(map.permits_write(allocation.base + 0x1000));

    map.protect(allocation.base, 0x1000, PAGE_READONLY).unwrap();
    assert_eq!(map.protection_override_count(), 1);
    map.free(allocation.base, 0, MEM_RELEASE).unwrap();
    assert_eq!(map.extent_count(), 0);
    assert_eq!(map.protection_override_count(), 0);
}

#[test]
fn fixed_vm_map_query_basic_reports_free_gap_to_next_vad() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x20_0000);
    map.allocate(
        Some(0x30000),
        0x2000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();

    let free = map.query_basic(0x12345, 0x20_0000).unwrap();
    assert_eq!(
        free,
        VmBasicInformation {
            base_address: 0x12000,
            allocation_base: 0,
            allocation_protect: 0,
            region_size: 0x1e000,
            state: MEM_FREE,
            protect: PAGE_NOACCESS,
            type_: 0,
        }
    );
}

#[test]
fn fixed_vm_map_query_basic_reports_reserved_and_committed_private_regions() {
    let mut map = VmRegionMap::<8>::new(0x10000, 0x20_0000);
    let allocation = map
        .allocate(None, 0x4000, MEM_RESERVE, PAGE_READWRITE)
        .unwrap();
    map.allocate(
        Some(allocation.base + 0x2000),
        0x2000,
        MEM_COMMIT,
        PAGE_READONLY,
    )
    .unwrap();

    let reserved = map.query_basic(allocation.base, 0x20_0000).unwrap();
    assert_eq!(
        reserved,
        VmBasicInformation {
            base_address: allocation.base,
            allocation_base: allocation.base,
            allocation_protect: PAGE_READWRITE,
            region_size: 0x2000,
            state: MEM_RESERVE,
            protect: 0,
            type_: MEM_PRIVATE,
        }
    );

    let committed = map
        .query_basic(allocation.base + 0x2345, 0x20_0000)
        .unwrap();
    assert_eq!(
        committed,
        VmBasicInformation {
            base_address: allocation.base + 0x2000,
            allocation_base: allocation.base,
            allocation_protect: PAGE_READONLY,
            region_size: 0x2000,
            state: MEM_COMMIT,
            protect: PAGE_READONLY,
            type_: MEM_PRIVATE,
        }
    );
}

#[test]
fn fixed_vm_map_query_basic_splits_on_page_protection_override() {
    let mut map = VmRegionMap::<4>::new(0x10000, 0x20_0000);
    let allocation = map
        .allocate(None, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    map.protect(allocation.base + 0x1000, 0x1000, PAGE_READONLY)
        .unwrap();

    assert_eq!(
        map.query_basic(allocation.base, 0x20_0000).unwrap(),
        VmBasicInformation {
            base_address: allocation.base,
            allocation_base: allocation.base,
            allocation_protect: PAGE_READWRITE,
            region_size: 0x1000,
            state: MEM_COMMIT,
            protect: PAGE_READWRITE,
            type_: MEM_PRIVATE,
        }
    );
    assert_eq!(
        map.query_basic(allocation.base + 0x1000, 0x20_0000)
            .unwrap(),
        VmBasicInformation {
            base_address: allocation.base + 0x1000,
            allocation_base: allocation.base,
            allocation_protect: PAGE_READWRITE,
            region_size: 0x1000,
            state: MEM_COMMIT,
            protect: PAGE_READONLY,
            type_: MEM_PRIVATE,
        }
    );
    assert_eq!(
        map.query_basic(allocation.base + 0x2000, 0x20_0000)
            .unwrap()
            .region_size,
        0x1000
    );
}

#[test]
fn committed_range_table_queries_and_coalesces_runtime_mappings() {
    let mut table = VmCommittedRangeTable::<4>::new();
    table
        .register(VmCommittedRange {
            base: 0x1600_0000,
            size: 0x1000,
            allocation_base: 0x1600_0000,
            allocation_protect: PAGE_READWRITE,
            protect: PAGE_READWRITE,
            type_: MEM_PRIVATE,
        })
        .unwrap();
    table
        .register(VmCommittedRange {
            base: 0x1600_1000,
            size: 0x1000,
            allocation_base: 0x1600_0000,
            allocation_protect: PAGE_READWRITE,
            protect: PAGE_READWRITE,
            type_: MEM_PRIVATE,
        })
        .unwrap();

    assert_eq!(table.range_count(), 1);
    assert_eq!(
        table.query_basic(0x1600_0123).unwrap(),
        VmBasicInformation {
            base_address: 0x1600_0000,
            allocation_base: 0x1600_0000,
            allocation_protect: PAGE_READWRITE,
            region_size: 0x2000,
            state: MEM_COMMIT,
            protect: PAGE_READWRITE,
            type_: MEM_PRIVATE,
        }
    );
    assert_eq!(table.query_basic(0x1600_1000).unwrap().region_size, 0x1000);
}

#[test]
fn committed_range_table_rejects_overlaps_and_tracks_next_base() {
    let mut table = VmCommittedRangeTable::<4>::new();
    table
        .register(VmCommittedRange::mapped(0x2000_0000, 0x2000, PAGE_READONLY))
        .unwrap();
    table
        .register(VmCommittedRange::mapped(0x3000_0000, 0x1000, PAGE_READONLY))
        .unwrap();

    assert_eq!(
        table.register(VmCommittedRange::mapped(0x2000_1000, 0x1000, PAGE_READONLY,)),
        Err(STATUS_CONFLICTING_ADDRESSES)
    );
    assert_eq!(table.next_base_after(0x1000_0000), Some(0x2000_0000));
    assert_eq!(table.next_base_after(0x2000_0000), Some(0x3000_0000));
    assert!(table.query_basic(0x2800_0000).is_none());
}

#[test]
fn committed_range_table_reports_range_overlap_without_touching_adjacent_gaps() {
    let mut table = VmCommittedRangeTable::<4>::new();
    table
        .register(VmCommittedRange::mapped(0x2000_0000, 0x3000, PAGE_READONLY))
        .unwrap();
    table
        .register(VmCommittedRange::mapped(
            0x3000_0000,
            0x1000,
            PAGE_READWRITE,
        ))
        .unwrap();

    assert_eq!(table.overlaps_range(0x2000_1000, 0x1000), Ok(true));
    assert_eq!(table.overlaps_range(0x1fff_f000, 0x2000), Ok(true));
    assert_eq!(table.overlaps_range(0x2000_3000, 0x1000), Ok(false));
    assert_eq!(table.overlaps_range(0x2fff_f000, 0x1000), Ok(false));
    assert_eq!(
        table.overlaps_range(0x2000_0001, 0x1000),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        table.overlaps_range(0x2000_0000, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn committed_range_table_protect_capacity_failure_preserves_state() {
    let mut table = VmCommittedRangeTable::<1>::new();
    table
        .register(VmCommittedRange::mapped(0x2000_0000, 0x3000, PAGE_READONLY))
        .unwrap();

    assert_eq!(
        table.protect(0x2000_1000, 0x1000, PAGE_READWRITE),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(table.range_count(), 1);
    assert_eq!(
        table.query_basic(0x2000_0000).unwrap(),
        VmBasicInformation {
            base_address: 0x2000_0000,
            allocation_base: 0x2000_0000,
            allocation_protect: PAGE_READONLY,
            region_size: 0x3000,
            state: MEM_COMMIT,
            protect: PAGE_READONLY,
            type_: MEM_MAPPED,
        }
    );
}

#[test]
fn committed_range_table_reports_section_granular_image_views_and_unregisters_allocation() {
    let mut table = VmCommittedRangeTable::<4>::new();
    let headers = VmCommittedRange::image_region(0x8000_0000, 0x1000, 0x8000_0000, PAGE_READWRITE);
    let text = VmCommittedRange::image_region(0x8000_1000, 0x2000, 0x8000_0000, PAGE_EXECUTE_READ);
    table.register(headers).unwrap();
    table.register(text).unwrap();
    table
        .register(VmCommittedRange::mapped(0x9000_0000, 0x1000, PAGE_READONLY))
        .unwrap();

    assert_eq!(
        table.query_basic(0x8000_0123).unwrap(),
        VmBasicInformation {
            base_address: 0x8000_0000,
            allocation_base: 0x8000_0000,
            allocation_protect: PAGE_EXECUTE_WRITECOPY,
            region_size: 0x1000,
            state: MEM_COMMIT,
            protect: PAGE_READWRITE,
            type_: MEM_IMAGE,
        }
    );
    assert_eq!(
        table.query_basic(0x8000_1000).unwrap(),
        VmBasicInformation {
            base_address: 0x8000_1000,
            allocation_base: 0x8000_0000,
            allocation_protect: PAGE_EXECUTE_WRITECOPY,
            region_size: 0x2000,
            state: MEM_COMMIT,
            protect: PAGE_EXECUTE_READ,
            type_: MEM_IMAGE,
        }
    );
    assert_eq!(
        table.image_allocation_for_page(0x8000_2123),
        Some(VmImageAllocation {
            allocation_base: 0x8000_0000,
            allocation_end: 0x8000_3000,
        })
    );
    assert_eq!(
        table.protect(0x8000_1800, 0x800, PAGE_NOACCESS),
        Ok(VmCommittedProtectPlan {
            base: 0x8000_1000,
            size: 0x1000,
            old_protection: PAGE_EXECUTE_READ,
            new_protection: PAGE_NOACCESS,
        })
    );
    assert_eq!(
        table.query_basic(0x8000_1000).unwrap().protect,
        PAGE_NOACCESS
    );
    assert_eq!(
        table.query_basic(0x8000_2000).unwrap().protect,
        PAGE_EXECUTE_READ
    );
    assert_eq!(
        table.protect(0x8000_2000, 0x1000, PAGE_EXECUTE_WRITECOPY),
        Ok(VmCommittedProtectPlan {
            base: 0x8000_2000,
            size: 0x1000,
            old_protection: PAGE_EXECUTE_READ,
            new_protection: PAGE_EXECUTE_WRITECOPY,
        })
    );
    assert_eq!(
        table.query_basic(0x8000_2000).unwrap().protect,
        PAGE_EXECUTE_WRITECOPY
    );
    assert_eq!(
        table.image_allocation_for_page(0x8000_2123),
        Some(VmImageAllocation {
            allocation_base: 0x8000_0000,
            allocation_end: 0x8000_3000,
        })
    );
    assert_eq!(
        table.protect(0x8000_1000, 0x1000, PAGE_READONLY | PAGE_NOCACHE),
        Err(STATUS_INVALID_PARAMETER_4)
    );
    assert_eq!(
        table.protect(0x9000_0000, 0x1000, PAGE_READWRITE),
        Ok(VmCommittedProtectPlan {
            base: 0x9000_0000,
            size: 0x1000,
            old_protection: PAGE_READONLY,
            new_protection: PAGE_READWRITE,
        })
    );
    assert_eq!(
        table.query_basic(0x9000_0000).unwrap().protect,
        PAGE_READWRITE
    );
    assert_eq!(table.unregister_base(0x8000_0000), Some(headers));
    assert!(table.query_basic(0x8000_0123).is_none());
    assert_eq!(
        table.query_basic(0x8000_1000).unwrap().protect,
        PAGE_NOACCESS
    );
    assert_eq!(table.unregister_allocation_base(0x8000_0000), 2);
    assert!(table.query_basic(0x8000_1000).is_none());
    assert_eq!(table.image_allocation_for_page(0x8000_1000), None);
    assert_eq!(table.range_count(), 1);
    assert_eq!(table.unregister_base(0x8000_1000), None);
}

#[test]
fn committed_range_table_unregister_range_splits_and_tears_down_views() {
    let mut table = VmCommittedRangeTable::<6>::new();
    table
        .register(VmCommittedRange::mapped(0x4000_0000, 0x4000, PAGE_READONLY))
        .unwrap();

    assert_eq!(table.unregister_range(0x4000_1000, 0x2000), Ok(1));
    assert_eq!(table.range_count(), 2);
    assert_eq!(
        table.query_basic(0x4000_0000).unwrap(),
        VmBasicInformation {
            base_address: 0x4000_0000,
            allocation_base: 0x4000_0000,
            allocation_protect: PAGE_READONLY,
            region_size: 0x1000,
            state: MEM_COMMIT,
            protect: PAGE_READONLY,
            type_: MEM_MAPPED,
        }
    );
    assert!(table.query_basic(0x4000_1000).is_none());
    assert_eq!(
        table.query_basic(0x4000_3000).unwrap(),
        VmBasicInformation {
            base_address: 0x4000_3000,
            allocation_base: 0x4000_0000,
            allocation_protect: PAGE_READONLY,
            region_size: 0x1000,
            state: MEM_COMMIT,
            protect: PAGE_READONLY,
            type_: MEM_MAPPED,
        }
    );

    table
        .register(VmCommittedRange::mapped(0x5000_0000, 0x4000, PAGE_READONLY))
        .unwrap();
    table.protect(0x5000_1000, 0x1000, PAGE_READWRITE).unwrap();
    assert_eq!(table.unregister_range(0x5000_0000, 0x4000), Ok(3));
    assert!(table.query_basic(0x5000_0000).is_none());
    assert!(table.query_basic(0x5000_1000).is_none());
    assert!(table.query_basic(0x5000_3000).is_none());
    assert_eq!(table.unregister_range(0x5000_0000, 0x4000), Ok(0));
    assert_eq!(
        table.unregister_range(0x4000_0001, 0x1000),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn mapped_view_fault_plan_tracks_write_fault_promotion() {
    assert_eq!(
        mapped_view_fault_plan(PAGE_READWRITE, false),
        VmMappedViewFaultPlan {
            map_protection: PAGE_READONLY,
            mark_dirty: false,
            copy_on_write: false,
        }
    );
    assert_eq!(
        mapped_view_fault_plan(PAGE_READWRITE, true),
        VmMappedViewFaultPlan {
            map_protection: PAGE_READWRITE,
            mark_dirty: true,
            copy_on_write: false,
        }
    );
    assert_eq!(
        mapped_view_fault_plan(PAGE_EXECUTE_READWRITE, false),
        VmMappedViewFaultPlan {
            map_protection: PAGE_EXECUTE_READ,
            mark_dirty: false,
            copy_on_write: false,
        }
    );
    assert_eq!(
        mapped_view_fault_plan(PAGE_EXECUTE_READWRITE | PAGE_GUARD, true),
        VmMappedViewFaultPlan {
            map_protection: PAGE_EXECUTE_READWRITE | PAGE_GUARD,
            mark_dirty: true,
            copy_on_write: false,
        }
    );
    assert_eq!(
        mapped_view_fault_plan(PAGE_WRITECOPY, false),
        VmMappedViewFaultPlan {
            map_protection: PAGE_READONLY,
            mark_dirty: false,
            copy_on_write: false,
        }
    );
    assert_eq!(
        mapped_view_fault_plan(PAGE_WRITECOPY, true),
        VmMappedViewFaultPlan {
            map_protection: PAGE_READWRITE,
            mark_dirty: false,
            copy_on_write: true,
        }
    );
    assert_eq!(
        mapped_view_fault_plan(PAGE_EXECUTE_WRITECOPY, true),
        VmMappedViewFaultPlan {
            map_protection: PAGE_EXECUTE_READWRITE,
            mark_dirty: false,
            copy_on_write: true,
        }
    );
}

#[test]
fn mapped_view_fault_access_denies_protection_violations_before_mapping() {
    assert_eq!(
        mapped_view_fault_access_status(PAGE_READONLY, FaultAccess::Read),
        Ok(())
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_READONLY, FaultAccess::Write),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_READWRITE, FaultAccess::Write),
        Ok(())
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_EXECUTE_READWRITE, FaultAccess::Write),
        Ok(())
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_READWRITE, FaultAccess::Execute),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_EXECUTE_READ, FaultAccess::Execute),
        Ok(())
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_EXECUTE, FaultAccess::Read),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_NOACCESS, FaultAccess::Read),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_READWRITE | PAGE_GUARD, FaultAccess::Read),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_WRITECOPY, FaultAccess::Write),
        Ok(())
    );
    assert_eq!(
        mapped_view_fault_access_status(PAGE_EXECUTE_WRITECOPY, FaultAccess::Write),
        Ok(())
    );
}

#[test]
fn image_view_fault_access_supports_execute_and_writecopy_cow() {
    assert_eq!(
        image_view_fault_access_status(PAGE_EXECUTE_READ, FaultAccess::Execute),
        Ok(())
    );
    assert_eq!(
        image_view_fault_access_status(PAGE_READONLY, FaultAccess::Execute),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(
        image_view_fault_access_status(PAGE_WRITECOPY, FaultAccess::Write),
        Ok(())
    );
    assert_eq!(
        image_view_fault_access_status(PAGE_EXECUTE_WRITECOPY, FaultAccess::Write),
        Ok(())
    );
    assert_eq!(
        image_view_fault_access_status(PAGE_EXECUTE | PAGE_GUARD, FaultAccess::Execute),
        Err(STATUS_ACCESS_VIOLATION)
    );
}

#[test]
fn image_view_fault_plan_tracks_writecopy_cow() {
    assert_eq!(
        image_view_fault_plan(PAGE_WRITECOPY, false),
        VmImageViewFaultPlan {
            map_protection: PAGE_READONLY,
            copy_on_write: false,
        }
    );
    assert_eq!(
        image_view_fault_plan(PAGE_WRITECOPY, true),
        VmImageViewFaultPlan {
            map_protection: PAGE_READWRITE,
            copy_on_write: true,
        }
    );
    assert_eq!(
        image_view_fault_plan(PAGE_EXECUTE_WRITECOPY, false),
        VmImageViewFaultPlan {
            map_protection: PAGE_EXECUTE_READ,
            copy_on_write: false,
        }
    );
    assert_eq!(
        image_view_fault_plan(PAGE_EXECUTE_WRITECOPY | PAGE_GUARD, true),
        VmImageViewFaultPlan {
            map_protection: PAGE_EXECUTE_READWRITE | PAGE_GUARD,
            copy_on_write: true,
        }
    );
    assert_eq!(
        image_view_fault_plan(PAGE_EXECUTE_READ, true),
        VmImageViewFaultPlan {
            map_protection: PAGE_EXECUTE_READ,
            copy_on_write: false,
        }
    );
}

#[test]
fn committed_range_table_rejects_unbounded_or_unaligned_ranges() {
    let mut table = VmCommittedRangeTable::<4>::new();
    assert_eq!(
        table.register(VmCommittedRange::private(
            u64::MAX - 0xfff,
            0x2000,
            PAGE_READWRITE
        )),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        table.register(VmCommittedRange::private(0x1001, 0x1000, PAGE_READWRITE)),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        table.register(VmCommittedRange::private(0x1000, 0x800, PAGE_READWRITE)),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(table.range_count(), 0);
}
