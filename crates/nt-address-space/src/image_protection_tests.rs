use crate::*;

#[test]
fn image_writable_requests_normalize_metadata_and_returned_protection() {
    for (requested, expected) in [
        (PAGE_READWRITE, PAGE_WRITECOPY),
        (PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY),
    ] {
        for modifier in [0, PAGE_GUARD] {
            let mut table = VmCommittedRangeTable::<4>::new();
            table
                .register(VmCommittedRange::image_region(
                    0x1000,
                    0x3000,
                    0x1000,
                    PAGE_READONLY,
                ))
                .unwrap();
            let allocation_protect = table.query_basic(0x1000).unwrap().allocation_protect;
            let plan = table.protect(0x2100, 0x800, requested | modifier).unwrap();
            assert_eq!(
                plan,
                VmCommittedProtectPlan {
                    base: 0x2000,
                    size: PAGE_SIZE,
                    old_protection: PAGE_READONLY,
                    new_protection: expected | modifier,
                }
            );
            let info = table.query_basic(0x2000).unwrap();
            assert_eq!(info.protect, expected | modifier);
            assert_eq!(info.allocation_protect, allocation_protect);
            assert_eq!(table.query_basic(0x1000).unwrap().protect, PAGE_READONLY);
            assert_eq!(table.query_basic(0x3000).unwrap().protect, PAGE_READONLY);
            assert_eq!(table.process_commit_bytes(), PAGE_SIZE);
            assert_eq!(
                table
                    .protect(0x2000, PAGE_SIZE, PAGE_READONLY)
                    .unwrap()
                    .old_protection,
                expected | modifier
            );
        }
    }
}

#[test]
fn image_registration_and_other_protections_keep_their_original_policy() {
    for protect in [PAGE_READWRITE, PAGE_EXECUTE_READWRITE] {
        let mut table = VmCommittedRangeTable::<2>::new();
        table
            .register(VmCommittedRange::image_region(
                0x1000, PAGE_SIZE, 0x1000, protect,
            ))
            .unwrap();
        assert_eq!(table.query_basic(0x1000).unwrap().protect, protect);
        assert_eq!(table.process_commit_bytes(), 0);
    }
    for protect in [
        PAGE_NOACCESS,
        PAGE_READONLY,
        PAGE_EXECUTE,
        PAGE_EXECUTE_READ,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_WRITECOPY,
    ] {
        let mut table = VmCommittedRangeTable::<2>::new();
        table
            .register(VmCommittedRange::image_region(
                0x1000,
                PAGE_SIZE,
                0x1000,
                PAGE_READONLY,
            ))
            .unwrap();
        assert_eq!(
            table
                .protect(0x1000, PAGE_SIZE, protect)
                .unwrap()
                .new_protection,
            protect
        );
        assert_eq!(table.query_basic(0x1000).unwrap().protect, protect);
    }
}

#[test]
fn non_image_writable_protection_is_not_implicitly_writecopy() {
    for type_ in [MEM_PRIVATE, MEM_MAPPED] {
        let mut table = VmCommittedRangeTable::<2>::new();
        table
            .register(VmCommittedRange {
                base: 0x1000,
                size: PAGE_SIZE,
                allocation_base: 0x1000,
                protect: PAGE_READONLY,
                allocation_protect: PAGE_READONLY,
                type_,
            })
            .unwrap();
        for protect in [PAGE_READWRITE, PAGE_EXECUTE_READWRITE] {
            assert_eq!(
                table
                    .protect(0x1000, PAGE_SIZE, protect)
                    .unwrap()
                    .new_protection,
                protect
            );
            assert_eq!(table.query_basic(0x1000).unwrap().protect, protect);
        }
        if type_ == MEM_PRIVATE {
            assert_eq!(
                table.protect(0x1000, PAGE_SIZE, PAGE_WRITECOPY),
                Err(STATUS_INVALID_PARAMETER_4)
            );
        }
    }
}

#[test]
fn image_cow_admission_charges_only_newly_normalized_spans() {
    let mut table = VmCommittedRangeTable::<4>::new();
    table
        .register(VmCommittedRange::image_region(
            0x1000,
            0x2000,
            0x1000,
            PAGE_READONLY,
        ))
        .unwrap();
    table
        .register(VmCommittedRange::image_region(
            0x3000,
            PAGE_SIZE,
            0x1000,
            PAGE_WRITECOPY,
        ))
        .unwrap();
    table
        .register(VmCommittedRange::mapped(0x5000, PAGE_SIZE, PAGE_READWRITE))
        .unwrap();
    assert_eq!(table.process_commit_bytes(), PAGE_SIZE);
    table.protect(0x1000, 0x3000, PAGE_READWRITE).unwrap();
    assert_eq!(table.allocation_process_commit_bytes(0x1000), 0x3000);
    assert_eq!(table.process_commit_bytes(), 0x3000);
    table.protect(0x1000, 0x3000, PAGE_READWRITE).unwrap();
    assert_eq!(table.process_commit_bytes(), 0x3000);
    assert_eq!(table.query_basic(0x5000).unwrap().protect, PAGE_READWRITE);
}

#[test]
fn normalization_rejections_preserve_metadata_and_charge() {
    let mut table = VmCommittedRangeTable::<2>::new();
    table
        .register(VmCommittedRange::image_region(
            0x1000,
            PAGE_SIZE,
            0x1000,
            PAGE_READONLY,
        ))
        .unwrap();
    table
        .register(VmCommittedRange::image_region(
            0x3000,
            PAGE_SIZE,
            0x1000,
            PAGE_EXECUTE_READ,
        ))
        .unwrap();
    let first = table.query_basic(0x1000).unwrap();
    let second = table.query_basic(0x3000).unwrap();
    assert_eq!(
        table.protect(0x1000, 0x3000, PAGE_READWRITE),
        Err(STATUS_NOT_COMMITTED)
    );
    assert_eq!(
        table.protect(0x1000, PAGE_SIZE, PAGE_READWRITE | PAGE_NOCACHE),
        Err(STATUS_INVALID_PARAMETER_4)
    );
    assert_eq!(table.query_basic(0x1000), Some(first));
    assert_eq!(table.query_basic(0x3000), Some(second));
    assert_eq!(table.process_commit_bytes(), 0);

    let mut full = VmCommittedRangeTable::<1>::new();
    full.register(VmCommittedRange::image_region(
        0x1000,
        0x3000,
        0x1000,
        PAGE_READONLY,
    ))
    .unwrap();
    assert_eq!(
        full.protect(0x2000, PAGE_SIZE, PAGE_EXECUTE_READWRITE),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(full.range_count(), 1);
    assert_eq!(full.query_basic(0x2000).unwrap().protect, PAGE_READONLY);
    assert_eq!(full.process_commit_bytes(), 0);
}

#[test]
fn clearing_an_image_guard_does_not_normalize_or_add_commitment() {
    for protect in [
        PAGE_READWRITE,
        PAGE_EXECUTE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_WRITECOPY,
    ] {
        let mut table = VmCommittedRangeTable::<4>::new();
        table
            .register(VmCommittedRange::image_region(
                0x1000,
                0x3000,
                0x1000,
                protect | PAGE_GUARD,
            ))
            .unwrap();
        let charge = table.process_commit_bytes();
        let allocation_protect = table.query_basic(0x2000).unwrap().allocation_protect;
        let change = table.clear_guard(0x2100).unwrap();
        assert_eq!(change.old_protection, protect | PAGE_GUARD);
        assert_eq!(change.new_protection, protect);
        assert_eq!(table.query_basic(0x2000).unwrap().protect, protect);
        assert_eq!(
            table.query_basic(0x2000).unwrap().allocation_protect,
            allocation_protect
        );
        assert_eq!(
            table.query_basic(0x1000).unwrap().protect,
            protect | PAGE_GUARD
        );
        assert_eq!(
            table.query_basic(0x3000).unwrap().protect,
            protect | PAGE_GUARD
        );
        assert_eq!(table.process_commit_bytes(), charge);
    }
}

#[test]
fn guard_consumption_rejects_missing_guards_and_capacity_failure_atomically() {
    let mut table = VmCommittedRangeTable::<1>::new();
    assert_eq!(table.clear_guard(0x1000), Err(STATUS_NOT_COMMITTED));
    table
        .register(VmCommittedRange::image_region(
            0x1000,
            0x3000,
            0x1000,
            PAGE_READWRITE | PAGE_GUARD,
        ))
        .unwrap();
    let original = table.query_basic(0x2000).unwrap();
    assert_eq!(
        table.clear_guard(0x2000),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(table.query_basic(0x2000), Some(original));
    assert_eq!(table.process_commit_bytes(), 0);
    table.protect(0x1000, 0x3000, PAGE_READONLY).unwrap();
    assert_eq!(table.clear_guard(0x2000), Err(STATUS_ACCESS_VIOLATION));
    assert_eq!(table.query_basic(0x2000).unwrap().protect, PAGE_READONLY);
}

#[test]
fn secured_writable_ranges_accept_normalized_cow_but_not_access_loss() {
    let mut secured = SecuredVirtualMemoryTable::new();
    secured
        .secure(7, 0x1000, PAGE_SIZE, SecuredVirtualMemoryAccess::ReadWrite)
        .unwrap();
    for requested in [PAGE_READWRITE, PAGE_EXECUTE_READWRITE] {
        let mut table = VmCommittedRangeTable::<1>::new();
        table
            .register(VmCommittedRange::image_region(
                0x1000,
                PAGE_SIZE,
                0x1000,
                PAGE_READONLY,
            ))
            .unwrap();
        let plan = table.protect(0x1000, PAGE_SIZE, requested).unwrap();
        assert!(secured.permits_protection(7, plan.base, plan.size, plan.new_protection));
        assert!(!secured.permits_protection(
            7,
            plan.base,
            plan.size,
            plan.new_protection | PAGE_GUARD
        ));
        assert!(!secured.permits_protection(7, plan.base, plan.size, PAGE_READONLY));
        assert!(!secured.permits_protection(7, plan.base, plan.size, PAGE_NOACCESS));
    }
}

#[test]
fn normalized_image_secure_admission_uses_the_mapping_type() {
    let mut table = VmCommittedRangeTable::<1>::new();
    table
        .register(VmCommittedRange::image_region(
            0x1000,
            PAGE_SIZE,
            0x1000,
            PAGE_READONLY,
        ))
        .unwrap();
    table.protect(0x1000, PAGE_SIZE, PAGE_READWRITE).unwrap();
    let info = table.query_basic(0x1000).unwrap();
    assert_eq!(info.protect, PAGE_WRITECOPY);
    assert!(vm_access_page_plan(0x1000, info, FaultAccess::Write).is_ok());
    let private = VmBasicInformation {
        type_: MEM_PRIVATE,
        ..info
    };
    assert_eq!(
        vm_access_page_plan(0x1000, private, FaultAccess::Write),
        Err(STATUS_ACCESS_VIOLATION)
    );
    let mapped = VmBasicInformation {
        type_: MEM_MAPPED,
        ..info
    };
    assert!(vm_access_page_plan(0x1000, mapped, FaultAccess::Write).is_ok());
    let guarded = VmBasicInformation {
        protect: info.protect | PAGE_GUARD,
        ..info
    };
    assert_eq!(
        vm_access_page_plan(0x1000, guarded, FaultAccess::Write),
        Err(STATUS_ACCESS_VIOLATION)
    );
}

#[test]
fn physical_protection_retains_private_cow_ownership() {
    for type_ in [MEM_IMAGE, MEM_MAPPED] {
        for (view, shared, private) in [
            (PAGE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE),
            (
                PAGE_EXECUTE_WRITECOPY,
                PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE,
            ),
        ] {
            for modifiers in [0, PAGE_GUARD, PAGE_NOCACHE] {
                assert_eq!(
                    resident_backing_protection(type_, view | modifiers, false),
                    shared | modifiers
                );
                assert_eq!(
                    resident_backing_protection(type_, view | modifiers, true),
                    private | modifiers
                );
            }
        }
    }
    assert_eq!(
        resident_backing_protection(MEM_PRIVATE, PAGE_READWRITE, true),
        PAGE_READWRITE
    );
}
