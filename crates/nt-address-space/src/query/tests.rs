use super::*;

fn mapping(base: u64, size: u64, allocation: u64, protect: u32, type_: u32) -> VmCommittedRange {
    VmCommittedRange {
        base,
        size,
        allocation_base: allocation,
        allocation_protect: PAGE_EXECUTE_WRITECOPY,
        protect,
        type_,
    }
}

#[test]
fn mixed_private_pages_split_native_queries_but_not_view_policy() {
    for type_ in [MEM_IMAGE, MEM_MAPPED] {
        for (copy, private) in [
            (PAGE_WRITECOPY, PAGE_READWRITE),
            (PAGE_EXECUTE_WRITECOPY, PAGE_EXECUTE_READWRITE),
        ] {
            let mut table = VmCommittedRangeTable::<4>::new();
            table
                .register(mapping(0x1000, 0x6000, 0x1000, copy, type_))
                .unwrap();
            // The native query sees both resident and transition ownership, in arbitrary order.
            let resident = [0x4000, 0x2000];
            let transition = [0x5000, 0x3000];
            for (page, protect, size) in [
                (0x1000, copy, PAGE_SIZE),
                (0x2000, private, 4 * PAGE_SIZE),
                (0x3000, private, 3 * PAGE_SIZE),
                (0x4000, private, 2 * PAGE_SIZE),
                (0x5000, private, PAGE_SIZE),
                (0x6000, copy, PAGE_SIZE),
            ] {
                let info = table
                    .query_basic_with_private_pages(
                        page + 13,
                        resident.into_iter().chain(transition),
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(info.base_address, page);
                assert_eq!(info.region_size, size);
                assert_eq!(info.protect, protect);
                assert_eq!(info.type_, type_);
                assert_eq!(info.allocation_base, 0x1000);
                assert_eq!(info.allocation_protect, PAGE_EXECUTE_WRITECOPY);
                assert_eq!(info.state, MEM_COMMIT);
            }
            assert_eq!(table.range_count(), 1);
            assert_eq!(table.query_basic(0x2000).unwrap().protect, copy);
            assert_eq!(table.process_commit_bytes(), 0x6000);
        }
    }
}

#[test]
fn query_coalesces_different_view_policies_with_equal_effective_protection() {
    let mut table = VmCommittedRangeTable::<4>::new();
    for (base, protect) in [
        (0x1000, PAGE_READWRITE),
        (0x2000, PAGE_WRITECOPY),
        (0x3000, PAGE_READWRITE),
        (0x4000, PAGE_WRITECOPY),
    ] {
        table
            .register(mapping(base, PAGE_SIZE, 0x1000, protect, MEM_MAPPED))
            .unwrap();
    }
    let info = table
        .query_basic_with_private_pages(0x1000, [0x2000])
        .unwrap()
        .unwrap();
    assert_eq!(info.protect, PAGE_READWRITE);
    assert_eq!(info.region_size, 0x3000);
    let info = table
        .query_basic_with_private_pages(0x2000, [0x2000, 0x4000])
        .unwrap()
        .unwrap();
    assert_eq!(info.region_size, 0x3000);
    assert_eq!(table.query_basic(0x2000).unwrap().protect, PAGE_WRITECOPY);
}

#[test]
fn query_stops_at_holes_and_allocation_or_mapping_identity_boundaries() {
    for next in [
        mapping(0x3000, PAGE_SIZE, 0x1000, PAGE_WRITECOPY, MEM_IMAGE),
        mapping(0x2000, PAGE_SIZE, 0x2000, PAGE_WRITECOPY, MEM_IMAGE),
        mapping(0x2000, PAGE_SIZE, 0x1000, PAGE_WRITECOPY, MEM_MAPPED),
        VmCommittedRange {
            allocation_protect: PAGE_READONLY,
            ..mapping(0x2000, PAGE_SIZE, 0x1000, PAGE_WRITECOPY, MEM_IMAGE)
        },
    ] {
        let mut table = VmCommittedRangeTable::<4>::new();
        table
            .register(mapping(
                0x1000,
                PAGE_SIZE,
                0x1000,
                PAGE_WRITECOPY,
                MEM_IMAGE,
            ))
            .unwrap();
        table.register(next).unwrap();
        let info = table
            .query_basic_with_private_pages(0x1000, [0x1000, next.base])
            .unwrap()
            .unwrap();
        assert_eq!(info.protect, PAGE_READWRITE);
        assert_eq!(info.region_size, PAGE_SIZE);
    }
}

#[test]
fn duplicate_and_irrelevant_backing_records_do_not_change_region_size() {
    let mut table = VmCommittedRangeTable::<4>::new();
    table
        .register(mapping(0x1000, 0x4000, 0x1000, PAGE_WRITECOPY, MEM_IMAGE))
        .unwrap();
    table
        .register(mapping(
            0x9000,
            PAGE_SIZE,
            0x9000,
            PAGE_WRITECOPY,
            MEM_IMAGE,
        ))
        .unwrap();
    let info = table
        .query_basic_with_private_pages(0x1000, [0x2000, 0x1000, 0x2000, 0x9000, 0, u64::MAX])
        .unwrap()
        .unwrap();
    assert_eq!(info.region_size, 2 * PAGE_SIZE);
    assert_eq!(
        table
            .query_basic_with_private_pages(0x8000, [0x1000])
            .unwrap(),
        None
    );
    assert_eq!(
        table.query_basic_with_private_pages(0x1000, [0x1234]),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn guard_and_noncopy_policies_are_preserved() {
    for type_ in [MEM_IMAGE, MEM_MAPPED] {
        for protect in [
            PAGE_WRITECOPY | PAGE_GUARD,
            PAGE_EXECUTE_WRITECOPY | PAGE_GUARD,
            PAGE_NOACCESS,
            PAGE_READONLY,
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            PAGE_READWRITE,
        ] {
            let mut table = VmCommittedRangeTable::<4>::new();
            table
                .register(mapping(0x1000, 0x2000, 0x1000, protect, type_))
                .unwrap();
            let info = table
                .query_basic_with_private_pages(0x1000, [0x1000])
                .unwrap()
                .unwrap();
            assert_eq!(info.protect, private_backing_protection(protect));
            assert_eq!(info.protect & PAGE_GUARD, protect & PAGE_GUARD);
            assert_eq!(
                info.region_size,
                if info.protect == protect {
                    0x2000
                } else {
                    PAGE_SIZE
                }
            );
        }
    }
    let mut table = VmCommittedRangeTable::<1>::new();
    table
        .register(VmCommittedRange::private(0x1000, 0x3000, PAGE_READWRITE))
        .unwrap();
    assert_eq!(
        table
            .query_basic_with_private_pages(0x1000, [0x2000])
            .unwrap(),
        table.query_basic(0x1000)
    );
    assert_eq!(
        page_protection(MEM_PRIVATE, PAGE_WRITECOPY, true),
        PAGE_WRITECOPY
    );
}

#[test]
fn private_query_survives_reprotection_and_reports_first_page_old_protection() {
    for type_ in [MEM_IMAGE, MEM_MAPPED] {
        let mut table = VmCommittedRangeTable::<4>::new();
        table
            .register(mapping(0x1000, 0x3000, 0x1000, PAGE_WRITECOPY, type_))
            .unwrap();
        for (request, old_expected, new_expected) in [
            (PAGE_READONLY, PAGE_READWRITE, PAGE_READONLY),
            (PAGE_NOACCESS, PAGE_READONLY, PAGE_NOACCESS),
            (
                PAGE_EXECUTE_WRITECOPY,
                PAGE_NOACCESS,
                PAGE_EXECUTE_READWRITE,
            ),
            (
                PAGE_WRITECOPY | PAGE_GUARD,
                PAGE_EXECUTE_READWRITE,
                PAGE_READWRITE | PAGE_GUARD,
            ),
        ] {
            let first = table.query_basic(0x2000).unwrap();
            let old = page_protection(first.type_, first.protect, true);
            assert_eq!(old, old_expected);
            table.protect(0x2000, PAGE_SIZE, request).unwrap();
            assert_eq!(
                table
                    .query_basic_with_private_pages(0x2000, [0x2000])
                    .unwrap()
                    .unwrap()
                    .protect,
                new_expected
            );
            assert_eq!(table.query_basic(0x1000).unwrap().protect, PAGE_WRITECOPY);
        }
        let first = table.query_basic(0x1000).unwrap();
        assert_eq!(
            page_protection(first.type_, first.protect, false),
            PAGE_WRITECOPY
        );
    }
}

#[test]
fn query_uses_sparse_backing_not_a_virtual_page_walk() {
    let mut table = VmCommittedRangeTable::<1>::new();
    let size = 1u64 << 40;
    table
        .register(mapping(0x1000, size, 0x1000, PAGE_WRITECOPY, MEM_MAPPED))
        .unwrap();
    let mut records_visited = 0;
    let pages = [size].into_iter().inspect(|_| records_visited += 1);
    let info = table
        .query_basic_with_private_pages(0x1000, pages)
        .unwrap()
        .unwrap();
    assert_eq!(records_visited, 1);
    assert_eq!(info.region_size, size - PAGE_SIZE);
    assert_eq!(info.protect, PAGE_WRITECOPY);
    assert_eq!(
        table
            .query_basic_with_private_pages(size, [size])
            .unwrap()
            .unwrap()
            .region_size,
        PAGE_SIZE
    );
}

#[test]
fn independent_process_backing_and_unmap_do_not_leak_private_state() {
    let mut table = VmCommittedRangeTable::<1>::new();
    let range = mapping(0x1000, 0x2000, 0x1000, PAGE_WRITECOPY, MEM_IMAGE);
    table.register(range).unwrap();
    assert_eq!(
        table
            .query_basic_with_private_pages(0x1000, [0x1000])
            .unwrap()
            .unwrap()
            .protect,
        PAGE_READWRITE
    );
    assert_eq!(
        table
            .query_basic_with_private_pages(0x1000, [])
            .unwrap()
            .unwrap()
            .protect,
        PAGE_WRITECOPY
    );
    table.unregister_allocation_base(0x1000);
    assert_eq!(
        table
            .query_basic_with_private_pages(0x1000, [0x1000])
            .unwrap(),
        None
    );
    table.register(range).unwrap();
    assert_eq!(
        table
            .query_basic_with_private_pages(0x1000, [])
            .unwrap()
            .unwrap()
            .region_size,
        0x2000
    );
}

#[test]
fn sparse_projection_matches_a_pagewise_oracle_for_every_ownership_mask() {
    for type_ in [MEM_IMAGE, MEM_MAPPED] {
        for policies in [
            [PAGE_WRITECOPY; 8],
            [
                PAGE_READWRITE,
                PAGE_WRITECOPY,
                PAGE_WRITECOPY,
                PAGE_READWRITE,
                PAGE_READONLY,
                PAGE_EXECUTE_WRITECOPY,
                PAGE_EXECUTE_READWRITE,
                PAGE_EXECUTE_WRITECOPY,
            ],
            [
                PAGE_WRITECOPY | PAGE_GUARD,
                PAGE_READWRITE | PAGE_GUARD,
                PAGE_NOACCESS,
                PAGE_WRITECOPY,
                PAGE_WRITECOPY,
                PAGE_EXECUTE_WRITECOPY | PAGE_GUARD,
                PAGE_EXECUTE_READ,
                PAGE_EXECUTE_WRITECOPY,
            ],
        ] {
            let mut table = VmCommittedRangeTable::<8>::new();
            for (index, protect) in policies.into_iter().enumerate() {
                table
                    .register(mapping(
                        (index as u64 + 1) * PAGE_SIZE,
                        PAGE_SIZE,
                        PAGE_SIZE,
                        protect,
                        type_,
                    ))
                    .unwrap();
            }
            for mask in 0u16..256 {
                for start in 0..8 {
                    let effective = |index: usize| {
                        if mask & (1 << index) != 0 {
                            match policies[index] & 0xff {
                                PAGE_WRITECOPY => PAGE_READWRITE | (policies[index] & !0xff),
                                PAGE_EXECUTE_WRITECOPY => {
                                    PAGE_EXECUTE_READWRITE | (policies[index] & !0xff)
                                }
                                _ => policies[index],
                            }
                        } else {
                            policies[index]
                        }
                    };
                    let expected = effective(start);
                    let end = (start + 1..8)
                        .find(|index| effective(*index) != expected)
                        .unwrap_or(8);
                    let pages = (0..8)
                        .rev()
                        .filter(|index| mask & (1 << index) != 0)
                        .map(|index| (index as u64 + 1) * PAGE_SIZE);
                    let info = table
                        .query_basic_with_private_pages((start as u64 + 1) * PAGE_SIZE, pages)
                        .unwrap()
                        .unwrap();
                    assert_eq!(info.protect, expected);
                    assert_eq!(
                        info.region_size,
                        (end - start) as u64 * PAGE_SIZE,
                        "mask={mask:#x}, start={start}, type={type_:#x}"
                    );
                }
            }
        }
    }
}
