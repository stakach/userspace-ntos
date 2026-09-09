use super::*;
use alloc::vec;

fn mapping() -> GenericMapping {
    GenericMapping {
        generic_read: 1,
        generic_write: 2,
        generic_execute: 4,
        generic_all: 7,
    }
}

fn read_only() -> SecurityDescriptor {
    SecurityDescriptor {
        dacl: Some(Acl::new(vec![
            Ace::deny(Sid::everyone(), 2),
            Ace::allow(Sid::everyone(), 3),
        ])),
        ..Default::default()
    }
}

#[test]
fn maximum_allowed_does_not_discard_explicit_or_generic_requested_rights() {
    let token = AccessToken::user(123);
    for request in [
        MAXIMUM_ALLOWED | 2,
        MAXIMUM_ALLOWED | GENERIC_WRITE,
        MAXIMUM_ALLOWED | 4,
    ] {
        let result = access_check(
            &read_only(),
            &token,
            request,
            &mapping(),
            ProcessorMode::UserMode,
        );
        assert_eq!(result.status, STATUS_ACCESS_DENIED);
        assert_eq!(result.granted_access, 0);
    }
    for request in [
        MAXIMUM_ALLOWED,
        MAXIMUM_ALLOWED | 1,
        MAXIMUM_ALLOWED | GENERIC_READ,
    ] {
        let result = access_check(
            &read_only(),
            &token,
            request,
            &mapping(),
            ProcessorMode::UserMode,
        );
        assert!(result.granted());
        assert_eq!(result.granted_access, 1);
    }
}

#[test]
fn by_type_maximum_results_and_aggregate_require_the_explicit_subset() {
    let types = [ObjectTypeEntry {
        level: 0,
        object_type: [3; 16],
    }];
    for result_list in [true, false] {
        let results = access_check_by_type(
            &read_only(),
            &AccessToken::user(123),
            None,
            MAXIMUM_ALLOWED | GENERIC_WRITE,
            &types,
            &mapping(),
            ProcessorMode::UserMode,
            result_list,
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, STATUS_ACCESS_DENIED);
        assert_eq!(results[0].granted_access, if result_list { 1 } else { 0 });
    }
}

#[test]
fn kernel_zero_access_and_security_rights_bypass_user_checks_without_privilege_use() {
    let denied = SecurityDescriptor {
        dacl: Some(Acl::empty()),
        ..Default::default()
    };
    let token = AccessToken::user(123);
    for request in [
        0,
        ACCESS_SYSTEM_SECURITY,
        MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY,
    ] {
        let result = access_check(
            &denied,
            &token,
            request,
            &mapping(),
            ProcessorMode::KernelMode,
        );
        assert!(result.granted());
        assert_eq!(
            result.granted_access,
            if request & MAXIMUM_ALLOWED != 0 {
                7 | ACCESS_SYSTEM_SECURITY
            } else {
                request
            }
        );
        assert!(result.privileges_used.is_empty());
        assert_eq!(
            access_check(
                &denied,
                &token,
                request,
                &mapping(),
                ProcessorMode::UserMode
            )
            .status,
            STATUS_ACCESS_DENIED
        );
    }
}

#[test]
fn kernel_by_type_zero_and_security_rights_match_ordinary_kernel_admission() {
    let types = [ObjectTypeEntry {
        level: 0,
        object_type: [3; 16],
    }];
    for result_list in [true, false] {
        for request in [0, ACCESS_SYSTEM_SECURITY] {
            let results = access_check_by_type(
                &read_only(),
                &AccessToken::user(123),
                None,
                request,
                &types,
                &mapping(),
                ProcessorMode::KernelMode,
                result_list,
            )
            .unwrap();
            assert!(results[0].granted());
            assert_eq!(results[0].granted_access, request);
            assert!(results[0].privileges_used.is_empty());
        }
    }
}

#[test]
fn kernel_maximum_with_empty_type_mapping_preserves_successful_zero_grant() {
    let mapping = GenericMapping {
        generic_read: 0,
        generic_write: 0,
        generic_execute: 0,
        generic_all: 0,
    };
    let types = [ObjectTypeEntry {
        level: 0,
        object_type: [3; 16],
    }];
    for result_list in [true, false] {
        let results = access_check_by_type(
            &read_only(),
            &AccessToken::user(123),
            None,
            MAXIMUM_ALLOWED,
            &types,
            &mapping,
            ProcessorMode::KernelMode,
            result_list,
        )
        .unwrap();
        assert!(results[0].granted());
        assert_eq!(results[0].granted_access, 0);
    }
}
