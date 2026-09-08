use super::*;
use nt_address_space::{MEM_DECOMMIT, MEM_RELEASE, PAGE_READONLY};

type Map = VmRegionMap<24>;
const BASE: u64 = 0x10_0000;
const TOP: u64 = BASE + 16 * PAGE_SIZE;
const OTHER: u64 = 0x20_0000;
const RW: StackGrowthPolicy = StackGrowthPolicy {
    extension_disabled: false,
    protection: PAGE_READWRITE,
};

fn empty() -> Map {
    Map::new(PAGE_SIZE, 0x100_0000)
}

#[test]
fn plan_size_does_not_embed_vad_tables() {
    assert_eq!(
        core::mem::size_of::<StackVadPlan<'static, 1>>(),
        core::mem::size_of::<StackVadPlan<'static, 4096>>()
    );
    assert!(core::mem::size_of::<StackVadPlan<'static, 4096>>() <= 128);
}

fn geometry(guard_page: u64) -> StackGeometry {
    StackGeometry {
        allocation_base: BASE,
        stack_base: TOP,
        stack_limit: BASE + (guard_page + 1) * PAGE_SIZE,
        guard_base: Some(BASE + guard_page * PAGE_SIZE),
    }
}

fn initialized(geometry: StackGeometry, protection: u32) -> Map {
    let before = empty();
    let mut scratch = empty();
    let mut current = before;
    prepare_initial_into(&before, &mut scratch, geometry, protection, u64::MAX)
        .unwrap()
        .apply_exact(&mut current)
        .unwrap();
    current
}

#[test]
fn initial_reservation_suffix_and_guard_have_exact_charge() {
    let mut before = empty();
    before
        .allocate(
            Some(OTHER),
            PAGE_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READONLY,
        )
        .unwrap();
    let original = before;
    let mut scratch = empty();
    let shape = geometry(11);
    let plan =
        prepare_initial_into(&before, &mut scratch, shape, PAGE_READWRITE, 5 * PAGE_SIZE).unwrap();
    let changes = plan.changes();
    assert_eq!(changes.commit_base, shape.guard_base);
    assert_eq!(changes.commit_bytes, 5 * PAGE_SIZE);
    assert_eq!(changes.outcome, StackVadOutcome::Initialized);
    assert_eq!(
        plan.candidate().extent_at(BASE).unwrap().state,
        VmExtentState::Reserved
    );
    assert_eq!(
        plan.candidate().protection_at(BASE + 11 * PAGE_SIZE),
        Some(PAGE_READWRITE | PAGE_GUARD)
    );
    assert_eq!(
        plan.candidate().protection_at(shape.stack_limit),
        Some(PAGE_READWRITE)
    );
    assert_eq!(plan.candidate().protection_at(OTHER), Some(PAGE_READONLY));
    assert!(before == original);
    let mut current = before;
    plan.apply_exact(&mut current).unwrap();
    assert_eq!(current.committed_bytes(), 6 * PAGE_SIZE);
}

#[test]
fn no_guard_and_fully_committed_input_does_not_invent_growth() {
    let shape = StackGeometry {
        allocation_base: BASE,
        stack_base: TOP,
        stack_limit: BASE,
        guard_base: None,
    };
    let before = initialized(shape, PAGE_READWRITE);
    assert_eq!(before.committed_bytes(), TOP - BASE);
    let mut scratch = empty();
    assert!(matches!(
        prepare_guard_growth_into(&before, &mut scratch, shape, BASE, RW, PAGE_SIZE),
        Err(StackVadError::NotStackGuard)
    ));
}

#[test]
fn invalid_geometry_and_protection_never_change_live_map() {
    let good = geometry(11);
    let cases = [
        StackGeometry {
            allocation_base: 0,
            ..good
        },
        StackGeometry {
            allocation_base: BASE + PAGE_SIZE,
            ..good
        },
        StackGeometry {
            stack_base: TOP + 1,
            ..good
        },
        StackGeometry {
            stack_limit: TOP,
            ..good
        },
        StackGeometry {
            stack_limit: BASE - PAGE_SIZE,
            ..good
        },
        StackGeometry {
            guard_base: Some(BASE - PAGE_SIZE),
            ..good
        },
        StackGeometry {
            guard_base: Some(u64::MAX),
            ..good
        },
        StackGeometry {
            guard_base: Some(BASE + 10 * PAGE_SIZE),
            ..good
        },
    ];
    let before = empty();
    let mut scratch = empty();
    for shape in cases {
        assert!(matches!(
            prepare_initial_into(&before, &mut scratch, shape, PAGE_READWRITE, u64::MAX),
            Err(StackVadError::InvalidGeometry)
        ));
        assert!(before == empty());
    }
    for protection in [0, PAGE_READONLY, PAGE_READWRITE | PAGE_GUARD] {
        assert!(matches!(
            prepare_initial_into(&before, &mut scratch, good, protection, u64::MAX),
            Err(StackVadError::InvalidProtection)
        ));
    }
}

#[test]
fn initial_collision_and_commit_limit_do_not_authorize_candidate() {
    let mut before = empty();
    before
        .allocate(Some(BASE), PAGE_SIZE, MEM_RESERVE, PAGE_READWRITE)
        .unwrap();
    let original = before;
    let mut scratch = empty();
    assert!(matches!(
        prepare_initial_into(
            &before,
            &mut scratch,
            geometry(11),
            PAGE_READWRITE,
            u64::MAX
        ),
        Err(StackVadError::Vm(_))
    ));
    assert!(before == original);
    assert!(matches!(
        prepare_initial_into(
            &empty(),
            &mut scratch,
            geometry(11),
            PAGE_READWRITE,
            5 * PAGE_SIZE - 1
        ),
        Err(StackVadError::CommitLimit)
    ));
}

#[test]
fn guard_growth_consumes_exact_guard_preserves_other_pages_and_charges_one_page() {
    let shape = geometry(11);
    let guard = shape.guard_base.unwrap();
    let mut before = initialized(shape, PAGE_READWRITE);
    before
        .protect(TOP - PAGE_SIZE, PAGE_SIZE, PAGE_READONLY)
        .unwrap();
    before
        .allocate(
            Some(OTHER),
            PAGE_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READONLY,
        )
        .unwrap();
    let original = before;
    let mut scratch = empty();
    let plan = prepare_guard_growth_into(&before, &mut scratch, shape, guard + 123, RW, PAGE_SIZE)
        .unwrap();
    let changes = plan.changes();
    assert_eq!(changes.outcome, StackVadOutcome::Grown);
    assert_eq!(changes.consumed_guard, Some(guard));
    assert_eq!(changes.new_guard, Some(guard - PAGE_SIZE));
    assert_eq!(changes.geometry.stack_limit, guard);
    assert_eq!(changes.commit_base, changes.new_guard);
    assert_eq!(changes.commit_bytes, PAGE_SIZE);
    assert_eq!(plan.candidate().protection_at(guard), Some(PAGE_READWRITE));
    assert_eq!(
        plan.candidate().protection_at(guard - PAGE_SIZE),
        Some(PAGE_READWRITE | PAGE_GUARD)
    );
    assert_eq!(
        plan.candidate().protection_at(TOP - PAGE_SIZE),
        Some(PAGE_READONLY)
    );
    assert_eq!(plan.candidate().protection_at(OTHER), Some(PAGE_READONLY));
    assert!(before == original);
    let mut current = before;
    plan.apply_exact(&mut current).unwrap();
    assert_eq!(
        current.committed_bytes(),
        before.committed_bytes() + PAGE_SIZE
    );
}

#[test]
fn executable_stack_policy_is_preserved() {
    let shape = geometry(11);
    let before = initialized(shape, PAGE_EXECUTE_READWRITE);
    let mut scratch = empty();
    let plan = prepare_guard_growth_into(
        &before,
        &mut scratch,
        shape,
        shape.guard_base.unwrap(),
        StackGrowthPolicy {
            protection: PAGE_EXECUTE_READWRITE,
            ..RW
        },
        PAGE_SIZE,
    )
    .unwrap();
    assert_eq!(
        plan.candidate().protection_at(shape.guard_base.unwrap()),
        Some(PAGE_EXECUTE_READWRITE)
    );
    assert_eq!(
        plan.candidate()
            .protection_at(plan.changes().new_guard.unwrap()),
        Some(PAGE_EXECUTE_READWRITE | PAGE_GUARD)
    );
}

#[test]
fn disabled_extension_consumes_guard_and_returns_terminal_overflow_without_charge() {
    let shape = geometry(11);
    let before = initialized(shape, PAGE_READWRITE);
    let mut scratch = empty();
    let plan = prepare_guard_growth_into(
        &before,
        &mut scratch,
        shape,
        shape.guard_base.unwrap(),
        StackGrowthPolicy {
            extension_disabled: true,
            ..RW
        },
        0,
    )
    .unwrap();
    assert_eq!(plan.changes().outcome, StackVadOutcome::StackOverflow);
    assert_eq!(plan.changes().commit_bytes, 0);
    assert_eq!(plan.changes().new_guard, None);
    assert_eq!(plan.changes().geometry.stack_limit, shape.stack_limit);
    assert_eq!(
        plan.candidate().protection_at(shape.guard_base.unwrap()),
        Some(PAGE_READWRITE)
    );
}

#[test]
fn last_growth_then_emergency_page_is_terminal_and_bottom_stays_reserved() {
    let shape = geometry(3);
    let before = initialized(shape, PAGE_READWRITE);
    let mut scratch = empty();
    let plan = prepare_guard_growth_into(
        &before,
        &mut scratch,
        shape,
        BASE + 3 * PAGE_SIZE,
        RW,
        PAGE_SIZE,
    )
    .unwrap();
    assert_eq!(plan.changes().outcome, StackVadOutcome::Grown);
    let next = plan.changes().geometry;
    let mut current = before;
    plan.apply_exact(&mut current).unwrap();
    let before = current;
    let plan = prepare_guard_growth_into(
        &before,
        &mut scratch,
        next,
        BASE + 2 * PAGE_SIZE,
        RW,
        PAGE_SIZE,
    )
    .unwrap();
    assert_eq!(plan.changes().outcome, StackVadOutcome::StackOverflow);
    assert_eq!(plan.changes().geometry.stack_limit, BASE + PAGE_SIZE);
    assert_eq!(plan.changes().new_guard, None);
    assert_eq!(plan.changes().commit_base, Some(BASE + PAGE_SIZE));
    assert_eq!(plan.changes().commit_bytes, PAGE_SIZE);
    assert_eq!(
        plan.candidate().extent_at(BASE).unwrap().state,
        VmExtentState::Reserved
    );
    assert_eq!(
        plan.candidate().protection_at(BASE + PAGE_SIZE),
        Some(PAGE_READWRITE)
    );
    assert_eq!(
        plan.candidate().protection_at(BASE + 2 * PAGE_SIZE),
        Some(PAGE_READWRITE)
    );
}

#[test]
fn initially_low_guards_do_not_underflow_or_double_charge_emergency_page() {
    for guard_page in [0, 1] {
        let shape = geometry(guard_page);
        let before = initialized(shape, PAGE_READWRITE);
        let mut scratch = empty();
        let plan = prepare_guard_growth_into(
            &before,
            &mut scratch,
            shape,
            shape.guard_base.unwrap(),
            RW,
            0,
        )
        .unwrap();
        assert_eq!(plan.changes().outcome, StackVadOutcome::StackOverflow);
        assert_eq!(plan.changes().commit_bytes, 0);
        assert_eq!(plan.changes().commit_base, None);
        assert_eq!(plan.changes().new_guard, None);
        assert_eq!(plan.changes().geometry.stack_limit, BASE + PAGE_SIZE);
    }
}

#[test]
fn repeated_fault_wrong_page_and_consumed_guard_are_rejected() {
    let shape = geometry(11);
    let before = initialized(shape, PAGE_READWRITE);
    let mut scratch = empty();
    for fault in [BASE, shape.stack_limit, TOP, u64::MAX] {
        assert!(matches!(
            prepare_guard_growth_into(&before, &mut scratch, shape, fault, RW, PAGE_SIZE),
            Err(StackVadError::NotStackGuard)
        ));
    }
    let plan = prepare_guard_growth_into(
        &before,
        &mut scratch,
        shape,
        shape.guard_base.unwrap(),
        RW,
        PAGE_SIZE,
    )
    .unwrap();
    let mut current = before;
    plan.apply_exact(&mut current).unwrap();
    assert!(matches!(
        prepare_guard_growth_into(
            &current,
            &mut scratch,
            shape,
            shape.guard_base.unwrap(),
            RW,
            PAGE_SIZE
        ),
        Err(StackVadError::NotStackGuard)
    ));
}

#[test]
fn changed_allocation_holes_and_extra_commit_are_not_stack_growth() {
    let shape = geometry(11);
    let original = initialized(shape, PAGE_READWRITE);
    for change in 0..3 {
        let mut before = original;
        match change {
            0 => {
                before
                    .free(TOP - PAGE_SIZE, PAGE_SIZE, MEM_DECOMMIT)
                    .unwrap();
            }
            1 => {
                before
                    .allocate(Some(BASE), PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE)
                    .unwrap();
            }
            _ => {
                before.free(BASE, 0, MEM_RELEASE).unwrap();
                before
                    .allocate(
                        Some(BASE),
                        TOP - BASE + PAGE_SIZE,
                        MEM_RESERVE,
                        PAGE_READWRITE,
                    )
                    .unwrap();
                before
                    .allocate(
                        Some(shape.guard_base.unwrap()),
                        TOP - shape.guard_base.unwrap(),
                        MEM_COMMIT,
                        PAGE_READWRITE,
                    )
                    .unwrap();
                before
                    .protect(
                        shape.guard_base.unwrap(),
                        PAGE_SIZE,
                        PAGE_READWRITE | PAGE_GUARD,
                    )
                    .unwrap();
            }
        }
        let mut scratch = empty();
        assert!(matches!(
            prepare_guard_growth_into(
                &before,
                &mut scratch,
                shape,
                shape.guard_base.unwrap(),
                RW,
                PAGE_SIZE
            ),
            Err(StackVadError::AllocationChanged)
        ));
    }
}

#[test]
fn insufficient_growth_commitment_consumes_guard_with_exact_overflow_limit() {
    for guard_page in [2, 11] {
        let shape = geometry(guard_page);
        let before = initialized(shape, PAGE_READWRITE);
        let original = before;
        let mut scratch = empty();
        let plan = prepare_guard_growth_into(
            &before,
            &mut scratch,
            shape,
            shape.guard_base.unwrap(),
            RW,
            PAGE_SIZE - 1,
        )
        .unwrap();
        let changes = plan.changes();
        assert_eq!(changes.outcome, StackVadOutcome::StackOverflow);
        assert_eq!(changes.commit_base, None);
        assert_eq!(changes.commit_bytes, 0);
        assert_eq!(changes.new_guard, None);
        assert_eq!(changes.geometry.guard_base, None);
        assert_eq!(changes.consumed_guard, shape.guard_base);
        assert_eq!(
            changes.geometry.stack_limit,
            if guard_page == 2 {
                shape.stack_limit
            } else {
                shape.guard_base.unwrap()
            }
        );
        assert_eq!(plan.candidate().committed_bytes(), before.committed_bytes());
        assert_eq!(
            plan.candidate().protection_at(shape.guard_base.unwrap()),
            Some(PAGE_READWRITE)
        );
        assert_eq!(
            plan.candidate()
                .extent_at(shape.guard_base.unwrap() - PAGE_SIZE)
                .unwrap()
                .state,
            VmExtentState::Reserved
        );
        assert!(before == original);
        assert_eq!(
            before.protection_at(shape.guard_base.unwrap()),
            Some(PAGE_READWRITE | PAGE_GUARD)
        );
        let mut current = before;
        plan.apply_exact(&mut current).unwrap();
        assert_eq!(
            current.protection_at(shape.guard_base.unwrap()),
            Some(PAGE_READWRITE)
        );
        assert!(matches!(
            prepare_guard_growth_into(
                &current,
                &mut scratch,
                changes.geometry,
                shape.guard_base.unwrap(),
                RW,
                PAGE_SIZE
            ),
            Err(StackVadError::NotStackGuard)
        ));
    }
}

#[test]
fn exact_apply_rejects_unrelated_vad_or_protection_changes() {
    let shape = geometry(11);
    let before = initialized(shape, PAGE_READWRITE);
    for change in 0..2 {
        let mut scratch = empty();
        let plan = prepare_guard_growth_into(
            &before,
            &mut scratch,
            shape,
            shape.guard_base.unwrap(),
            RW,
            PAGE_SIZE,
        )
        .unwrap();
        let mut current = before;
        if change == 0 {
            current
                .allocate(Some(OTHER), PAGE_SIZE, MEM_RESERVE, PAGE_READWRITE)
                .unwrap();
        } else {
            current
                .protect(TOP - PAGE_SIZE, PAGE_SIZE, PAGE_READONLY)
                .unwrap();
        }
        let changed = current;
        assert_eq!(plan.apply_exact(&mut current), Err(StackVadError::StaleMap));
        assert!(current == changed);
    }
}

#[test]
fn insufficient_vad_capacity_cannot_publish_partial_initial_reservation() {
    let before = VmRegionMap::<1>::new(PAGE_SIZE, 0x100_0000);
    let mut scratch = before;
    assert!(matches!(
        prepare_initial_into(
            &before,
            &mut scratch,
            geometry(11),
            PAGE_READWRITE,
            u64::MAX
        ),
        Err(StackVadError::Vm(_))
    ));
    assert_eq!(before.extent_count(), 0);
}

fn initial_teb(shape: StackGeometry) -> crate::InitialTeb64 {
    crate::InitialTeb64 {
        stack_base: shape.stack_base,
        stack_limit: shape.stack_limit,
        allocated_stack_base: shape.allocation_base,
    }
}

#[test]
fn existing_stack_derives_actual_guard_and_preserves_all_metadata() {
    let shape = geometry(11);
    for protection in [PAGE_READWRITE, PAGE_EXECUTE_READWRITE] {
        let mut map = initialized(shape, protection);
        map.protect(shape.stack_limit, PAGE_SIZE, PAGE_READONLY)
            .unwrap();
        map.allocate(
            Some(OTHER),
            PAGE_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READONLY,
        )
        .unwrap();
        let original = map;
        let commitment = map.committed_bytes();
        assert_eq!(
            validate_existing(&map, initial_teb(shape), TOP - 1),
            Ok(shape)
        );
        assert!(map == original);
        assert_eq!(map.committed_bytes(), commitment);
        assert_eq!(map.protection_at(shape.stack_limit), Some(PAGE_READONLY));
        assert_eq!(map.protection_at(OTHER), Some(PAGE_READONLY));
    }
}

#[test]
fn existing_stack_without_guard_accepts_actual_committed_suffix() {
    for limit in [BASE, BASE + 12 * PAGE_SIZE] {
        let shape = StackGeometry {
            allocation_base: BASE,
            stack_base: TOP,
            stack_limit: limit,
            guard_base: None,
        };
        let map = initialized(shape, PAGE_READWRITE);
        assert_eq!(
            validate_existing(&map, initial_teb(shape), limit),
            Ok(shape)
        );
        assert_eq!(
            validate_existing(&map, initial_teb(shape), TOP - 1),
            Ok(shape)
        );
    }
}

#[test]
fn existing_stack_does_not_adopt_neighboring_allocation_guard() {
    let shape = StackGeometry {
        allocation_base: BASE,
        stack_base: TOP,
        stack_limit: BASE,
        guard_base: None,
    };
    let mut map = initialized(shape, PAGE_READWRITE);
    map.allocate(
        Some(BASE - ALLOCATION_GRANULARITY),
        ALLOCATION_GRANULARITY,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();
    map.protect(BASE - PAGE_SIZE, PAGE_SIZE, PAGE_READWRITE | PAGE_GUARD)
        .unwrap();
    assert_eq!(validate_existing(&map, initial_teb(shape), BASE), Ok(shape));
}

#[test]
fn existing_stack_accepts_guard_at_its_own_reservation_base() {
    let shape = geometry(0);
    let map = initialized(shape, PAGE_READWRITE);
    assert_eq!(
        validate_existing(&map, initial_teb(shape), shape.stack_limit),
        Ok(shape)
    );
}

#[test]
fn existing_stack_rejects_rsp_outside_usable_suffix() {
    let shape = geometry(11);
    let map = initialized(shape, PAGE_READWRITE);
    for rsp in [
        0,
        BASE,
        shape.guard_base.unwrap(),
        shape.stack_limit - 1,
        TOP,
        u64::MAX,
    ] {
        assert_eq!(
            validate_existing(&map, initial_teb(shape), rsp),
            Err(StackVadError::InvalidStackPointer)
        );
    }
}

#[test]
fn existing_stack_requires_writable_non_guard_rsp_page() {
    let shape = geometry(11);
    for protection in [
        PAGE_READONLY,
        nt_address_space::PAGE_NOACCESS,
        PAGE_READWRITE | PAGE_GUARD,
    ] {
        let mut map = initialized(shape, PAGE_READWRITE);
        map.protect(TOP - PAGE_SIZE, PAGE_SIZE, protection).unwrap();
        let original = map;
        assert_eq!(
            validate_existing(&map, initial_teb(shape), TOP - 8),
            Err(StackVadError::InvalidStackPointer)
        );
        assert!(map == original);
    }
}

#[test]
fn existing_stack_rejects_unsupported_guard_protection() {
    let shape = geometry(11);
    let mut map = initialized(shape, PAGE_READWRITE);
    map.protect(
        shape.guard_base.unwrap(),
        PAGE_SIZE,
        PAGE_READONLY | PAGE_GUARD,
    )
    .unwrap();
    assert_eq!(
        validate_existing(&map, initial_teb(shape), TOP - 8),
        Err(StackVadError::InvalidProtection)
    );
}

#[test]
fn existing_stack_rejects_inexact_initial_teb_geometry() {
    let shape = geometry(11);
    let map = initialized(shape, PAGE_READWRITE);
    let valid = initial_teb(shape);
    for teb in [
        crate::InitialTeb64 {
            allocated_stack_base: 0,
            ..valid
        },
        crate::InitialTeb64 {
            allocated_stack_base: BASE + PAGE_SIZE,
            ..valid
        },
        crate::InitialTeb64 {
            stack_limit: valid.stack_limit + 1,
            ..valid
        },
        crate::InitialTeb64 {
            stack_limit: TOP,
            ..valid
        },
        crate::InitialTeb64 {
            stack_base: TOP + 1,
            ..valid
        },
    ] {
        assert_eq!(
            validate_existing(&map, teb, TOP - 8),
            Err(StackVadError::InvalidGeometry)
        );
    }
    for teb in [
        crate::InitialTeb64 {
            allocated_stack_base: BASE - ALLOCATION_GRANULARITY,
            ..valid
        },
        crate::InitialTeb64 {
            stack_base: TOP - PAGE_SIZE,
            ..valid
        },
        crate::InitialTeb64 {
            stack_base: TOP + PAGE_SIZE,
            ..valid
        },
        crate::InitialTeb64 {
            stack_limit: valid.stack_limit + PAGE_SIZE,
            ..valid
        },
        crate::InitialTeb64 {
            stack_limit: valid.stack_limit - 2 * PAGE_SIZE,
            ..valid
        },
    ] {
        assert_eq!(
            validate_existing(&map, teb, TOP - 2 * PAGE_SIZE),
            Err(StackVadError::AllocationChanged)
        );
    }
}

#[test]
fn existing_stack_rejects_missing_vad_holes_and_unexpected_prefix_commit() {
    let shape = geometry(11);
    assert_eq!(
        validate_existing(&empty(), initial_teb(shape), TOP - 8),
        Err(StackVadError::AllocationChanged)
    );
    for change in 0..3 {
        let mut map = initialized(shape, PAGE_READWRITE);
        match change {
            0 => {
                map.free(TOP - 2 * PAGE_SIZE, PAGE_SIZE, MEM_DECOMMIT)
                    .unwrap();
            }
            1 => {
                map.allocate(Some(BASE), PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE)
                    .unwrap();
            }
            _ => {
                map.protect(shape.guard_base.unwrap(), PAGE_SIZE, PAGE_READWRITE)
                    .unwrap();
            }
        }
        assert_eq!(
            validate_existing(&map, initial_teb(shape), TOP - 8),
            Err(StackVadError::AllocationChanged)
        );
    }
}

#[test]
fn existing_stack_cannot_span_two_allocations_or_use_a_mapped_vad() {
    let mut map = empty();
    map.allocate(
        Some(BASE),
        ALLOCATION_GRANULARITY,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();
    map.allocate(
        Some(TOP),
        ALLOCATION_GRANULARITY,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    )
    .unwrap();
    let teb = crate::InitialTeb64 {
        allocated_stack_base: BASE,
        stack_limit: BASE,
        stack_base: TOP + ALLOCATION_GRANULARITY,
    };
    assert_eq!(
        validate_existing(&map, teb, TOP - 8),
        Err(StackVadError::AllocationChanged)
    );
    let mut map = empty();
    map.allocate_mapped_between(
        Some(BASE),
        ALLOCATION_GRANULARITY,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
        BASE,
        TOP,
    )
    .unwrap();
    let teb = crate::InitialTeb64 {
        stack_base: TOP,
        ..teb
    };
    assert_eq!(
        validate_existing(&map, teb, TOP - 8),
        Err(StackVadError::AllocationChanged)
    );
}
