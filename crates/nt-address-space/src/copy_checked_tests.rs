use super::*;
use crate::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, PAGE_NOACCESS,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, STATUS_NOT_COMMITTED,
};
use alloc::vec::Vec;

fn mapping() -> VmBasicInformation {
    VmBasicInformation {
        base_address: PAGE_SIZE,
        allocation_base: PAGE_SIZE,
        allocation_protect: PAGE_READWRITE,
        region_size: PAGE_SIZE,
        state: MEM_COMMIT,
        protect: PAGE_READWRITE,
        type_: MEM_PRIVATE,
    }
}

#[test]
fn checked_range_rejections_are_user_faults_before_backend_access() {
    for (address, len, limit) in [
        (PAGE_SIZE - 1, 2, PAGE_SIZE),
        (u64::MAX - 3, 8, u64::MAX),
        (PAGE_SIZE, 1, PAGE_SIZE),
    ] {
        assert_eq!(
            validate_kernel_write_range(address, len, limit),
            Err(MemoryCopyFailure::UserFault(STATUS_ACCESS_VIOLATION))
        );
        assert_eq!(
            write_kernel_buffer_checked(address, &[0; 8][..len], limit, |_, _| {
                panic!("invalid range reached backend")
            }),
            Err(MemoryCopyFailure::UserFault(STATUS_ACCESS_VIOLATION))
        );
    }
    assert_eq!(validate_kernel_write_range(u64::MAX, 0, 0), Ok(()));
    assert_eq!(
        write_kernel_buffer_checked(u64::MAX, &[], 0, |_, _| panic!("empty write")),
        Ok(())
    );
    assert_eq!(
        validate_kernel_write_range(PAGE_SIZE - 1, 1, PAGE_SIZE),
        Ok(())
    );
}

#[test]
fn identical_backend_statuses_preserve_distinct_origins_and_exact_prefix() {
    for failure in [
        MemoryCopyFailure::UserFault(STATUS_ACCESS_VIOLATION),
        MemoryCopyFailure::Retry(STATUS_ACCESS_VIOLATION),
    ] {
        let mut calls = Vec::new();
        let mut accepted = Vec::new();
        let result = write_kernel_buffer_checked(
            PAGE_SIZE - 2,
            &[1, 2, 3, 4],
            2 * PAGE_SIZE,
            |address, bytes| {
                calls.push((address, bytes.to_vec()));
                if address == PAGE_SIZE {
                    return Err(failure);
                }
                accepted.extend_from_slice(bytes);
                Ok(())
            },
        );
        assert_eq!(result, Err(failure));
        assert_eq!(failure.status(), STATUS_ACCESS_VIOLATION);
        assert_eq!(accepted, [1, 2]);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], (PAGE_SIZE - 2, [1, 2].to_vec()));
        assert_eq!(calls[1], (PAGE_SIZE, [3, 4].to_vec()));
    }
}

#[test]
fn malformed_mapping_geometry_and_unknown_committed_type_are_retryable() {
    let valid = mapping();
    for (page, info) in [
        (PAGE_SIZE + 1, valid),
        (
            PAGE_SIZE,
            VmBasicInformation {
                base_address: PAGE_SIZE + 1,
                ..valid
            },
        ),
        (
            PAGE_SIZE,
            VmBasicInformation {
                region_size: 0,
                ..valid
            },
        ),
        (
            PAGE_SIZE,
            VmBasicInformation {
                region_size: u64::MAX,
                ..valid
            },
        ),
        (0, valid),
        (2 * PAGE_SIZE, valid),
        (PAGE_SIZE, VmBasicInformation { type_: 0, ..valid }),
    ] {
        assert_eq!(
            copy_page_plan_checked(page, info, FaultAccess::Write, false),
            Err(MemoryCopyFailure::Retry(STATUS_ACCESS_VIOLATION))
        );
        assert_eq!(
            copy_page_plan(page, info, FaultAccess::Write, false),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
}

#[test]
fn real_uncommitted_regions_are_user_faults_but_unknown_state_is_not() {
    for state in [MEM_RESERVE, MEM_FREE, 0xdead_beef] {
        for type_ in [0, MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE] {
            let info = VmBasicInformation {
                state,
                type_,
                protect: 0,
                ..mapping()
            };
            let expected = if state == 0xdead_beef {
                MemoryCopyFailure::Retry(STATUS_NOT_COMMITTED)
            } else {
                MemoryCopyFailure::UserFault(STATUS_NOT_COMMITTED)
            };
            assert_eq!(
                copy_page_plan_checked(PAGE_SIZE, info, FaultAccess::Write, false),
                Err(expected)
            );
            assert_eq!(
                copy_page_plan(PAGE_SIZE, info, FaultAccess::Write, false),
                Err(STATUS_NOT_COMMITTED)
            );
        }
    }
}

#[test]
fn protection_policy_denials_and_malformed_encodings_have_distinct_origins() {
    for type_ in [MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE] {
        for protect in [
            PAGE_NOACCESS,
            PAGE_READONLY,
            0,
            PAGE_READONLY | PAGE_READWRITE,
        ] {
            let info = VmBasicInformation {
                type_,
                protect,
                ..mapping()
            };
            let expected = if protect == PAGE_NOACCESS || protect == PAGE_READONLY {
                MemoryCopyFailure::UserFault(STATUS_ACCESS_VIOLATION)
            } else {
                MemoryCopyFailure::Retry(STATUS_ACCESS_VIOLATION)
            };
            assert_eq!(
                copy_page_plan_checked(PAGE_SIZE, info, FaultAccess::Write, false),
                Err(expected)
            );
            assert_eq!(
                copy_page_plan(PAGE_SIZE, info, FaultAccess::Write, false),
                Err(STATUS_ACCESS_VIOLATION)
            );
        }
    }
}

#[test]
fn guard_and_copy_on_write_plans_preserve_existing_source_policy() {
    for type_ in [MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE] {
        let info = VmBasicInformation {
            type_,
            protect: PAGE_READWRITE | PAGE_GUARD,
            ..mapping()
        };
        assert!(matches!(
            copy_page_plan_checked(PAGE_SIZE, info, FaultAccess::Write, false),
            Ok(CopyPagePlan::ConsumeGuard(_))
        ));
        assert_eq!(
            copy_page_plan_checked(PAGE_SIZE, info, FaultAccess::Write, true),
            Err(MemoryCopyFailure::UserFault(STATUS_ACCESS_VIOLATION))
        );
    }
    for type_ in [MEM_MAPPED, MEM_IMAGE] {
        let info = VmBasicInformation {
            type_,
            protect: PAGE_WRITECOPY,
            ..mapping()
        };
        let checked = copy_page_plan_checked(PAGE_SIZE, info, FaultAccess::Write, false);
        assert!(matches!(checked, Ok(CopyPagePlan::Resident(_))));
        assert_eq!(
            checked.map_err(MemoryCopyFailure::status),
            copy_page_plan(PAGE_SIZE, info, FaultAccess::Write, false)
        );
    }
}

#[test]
fn checked_planner_does_not_expand_legacy_protection_rejection_policy() {
    let info = VmBasicInformation {
        protect: PAGE_READWRITE | 0x8000_0000,
        ..mapping()
    };
    let expected = vm_access_page_plan(PAGE_SIZE, info, FaultAccess::Write).unwrap();
    assert_eq!(
        copy_page_plan_checked(PAGE_SIZE, info, FaultAccess::Write, false),
        Ok(CopyPagePlan::Resident(expected))
    );
}
