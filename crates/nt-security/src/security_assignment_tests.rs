use super::super::{SE_DACL_DEFAULTED, SE_SACL_DEFAULTED};
use super::*;
use crate::{Luid, NativeAcl, TokenGroup, TokenPrivilege, GENERIC_ALL, STATUS_INVALID_ACL};
use alloc::vec;

fn mapping() -> GenericMapping {
    GenericMapping {
        generic_read: 1,
        generic_write: 2,
        generic_execute: 4,
        generic_all: 7,
    }
}

fn ace(flags: u8, mask: u32, trustee: &Sid) -> Vec<u8> {
    let mut bytes = vec![0, flags, 0, 0];
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&sid_bytes(trustee, STATUS_INVALID_OWNER).unwrap());
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn acl(aces: &[Vec<u8>]) -> NativeAcl {
    acl_revision(2, aces)
}

fn acl_revision(revision: u8, aces: &[Vec<u8>]) -> NativeAcl {
    let mut bytes = vec![revision, 0, 0, 0, 0, 0, 0, 0];
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    NativeAcl::from_bytes(&bytes).unwrap()
}

fn sd(
    owner: Option<&Sid>,
    group: Option<&Sid>,
    dacl: Option<Option<&NativeAcl>>,
    sacl: Option<Option<&NativeAcl>>,
    control: u16,
) -> Vec<u8> {
    let owner = owner.map(|sid| sid_bytes(sid, STATUS_INVALID_OWNER).unwrap());
    let group = group.map(|sid| sid_bytes(sid, STATUS_INVALID_PRIMARY_GROUP).unwrap());
    build_self_relative_descriptor(DescriptorBuild {
        owner: owner.as_deref(),
        group: group.as_deref(),
        dacl_present: dacl.is_some(),
        dacl: dacl.flatten().map(NativeAcl::as_bytes),
        sacl_present: sacl.is_some(),
        sacl: sacl.flatten().map(NativeAcl::as_bytes),
        control,
    })
    .unwrap()
}

fn primary() -> AccessToken {
    let mut token = AccessToken::user(1);
    token.default_dacl = Some(acl(&[ace(0, 4, &Sid::everyone())]));
    token
}

fn client() -> AccessToken {
    let mut token = AccessToken::user(2);
    token.token_type = TokenType::Impersonation;
    token.impersonation_level = SecurityImpersonationLevel::Impersonation;
    token.default_dacl = Some(acl(&[ace(0, 2, &Sid::everyone())]));
    token
}

fn assignment<'a>(
    primary: &'a AccessToken,
    mapping: &'a GenericMapping,
) -> ObjectSecurityAssignment<'a> {
    ObjectSecurityAssignment {
        primary,
        client: None,
        creator: None,
        parent: None,
        mapping,
        is_container: true,
        mode: ProcessorMode::UserMode,
        object_type: None,
        inheritance: SecurityAssignmentInheritance::Legacy,
    }
}

fn extended(request: &mut ObjectSecurityAssignment<'_>, flags: u32) {
    request.inheritance = SecurityAssignmentInheritance::Extended { flags };
}

fn entries(bytes: Option<&[u8]>) -> Vec<&[u8]> {
    let Some(bytes) = bytes else {
        return Vec::new();
    };
    let mut offset = 8;
    let mut entries = Vec::new();
    for _ in 0..u16::from_le_bytes(bytes[4..6].try_into().unwrap()) {
        let size = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()) as usize;
        entries.push(&bytes[offset..offset + size]);
        offset += size;
    }
    entries
}

fn masks(bytes: Option<&[u8]>) -> Vec<u32> {
    entries(bytes)
        .iter()
        .map(|ace| u32::from_le_bytes(ace[4..8].try_into().unwrap()))
        .collect()
}

fn privilege(token: &mut AccessToken, name: &'static str) {
    token.privileges.push(TokenPrivilege {
        name,
        luid: Luid::new(8),
        enabled: true,
        enabled_by_default: false,
    });
}

#[test]
fn no_creator_or_parent_uses_authenticated_primary_defaults() {
    let primary = primary();
    let mapping = mapping();
    let result = assign_object_security(&assignment(&primary, &mapping)).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(
        parsed.owner.unwrap(),
        sid_bytes(&primary.owner, STATUS_INVALID_OWNER).unwrap()
    );
    assert_eq!(
        parsed.group.unwrap(),
        sid_bytes(&primary.primary_group, STATUS_INVALID_PRIMARY_GROUP).unwrap()
    );
    assert_eq!(masks(parsed.dacl), [4]);
    assert!(!parsed.sacl_present);
    assert_eq!(parsed.control, 0x8004);
}

#[test]
fn client_defaults_take_precedence_even_when_primary_is_privileged() {
    let primary = AccessToken::system();
    let client = client();
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    request.client = Some(SecurityAssignmentClient {
        token: &client,
        level: SecurityImpersonationLevel::Identification,
    });
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(
        parsed.owner.unwrap(),
        sid_bytes(&client.owner, STATUS_INVALID_OWNER).unwrap()
    );
    assert_eq!(masks(parsed.dacl), [2]);
}

#[test]
fn overstated_client_level_never_falls_back_to_primary() {
    let primary = AccessToken::system();
    let client = client();
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    request.client = Some(SecurityAssignmentClient {
        token: &client,
        level: SecurityImpersonationLevel::Delegation,
    });
    assert_eq!(
        assign_object_security(&request),
        Err(STATUS_BAD_IMPERSONATION_LEVEL)
    );
}

#[test]
fn anonymous_kernel_subject_uses_client_defaults_but_cannot_assign_user_mode_owner() {
    let primary = AccessToken::system();
    let client = client();
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    request.client = Some(SecurityAssignmentClient {
        token: &client,
        level: SecurityImpersonationLevel::Anonymous,
    });
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(
        parsed.owner.unwrap(),
        sid_bytes(&client.owner, STATUS_INVALID_OWNER).unwrap()
    );
    assert_eq!(masks(parsed.dacl), [2]);
    let owner = sd(Some(&client.user), None, None, None, 0);
    request.creator = Some(&owner);
    assert_eq!(assign_object_security(&request), Err(STATUS_INVALID_OWNER));
    let sacl = sd(None, None, None, Some(None), 0);
    request.creator = Some(&sacl);
    assert_eq!(
        assign_object_security(&request),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    );
}

#[test]
fn kernel_mode_explicit_assignment_is_not_rejected_by_anonymous_client_level() {
    let primary = primary();
    let client = client();
    let mapping = mapping();
    let descriptor = sd(Some(&Sid::local_system()), None, None, Some(None), 0);
    let mut request = assignment(&primary, &mapping);
    request.client = Some(SecurityAssignmentClient {
        token: &client,
        level: SecurityImpersonationLevel::Anonymous,
    });
    request.mode = ProcessorMode::KernelMode;
    request.creator = Some(&descriptor);
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(
        parsed.owner.unwrap(),
        sid_bytes(&Sid::local_system(), STATUS_INVALID_OWNER).unwrap()
    );
    assert_eq!(masks(parsed.dacl), [2]);
    assert!(parsed.sacl_present && parsed.sacl.is_none());
}

#[test]
fn subject_token_roles_are_checked_before_using_defaults() {
    let primary = primary();
    let client = client();
    let mapping = mapping();
    let mut request = assignment(&client, &mapping);
    assert_eq!(assign_object_security(&request), Err(STATUS_BAD_TOKEN_TYPE));
    request.primary = &primary;
    request.client = Some(SecurityAssignmentClient {
        token: &primary,
        level: SecurityImpersonationLevel::Identification,
    });
    assert_eq!(assign_object_security(&request), Err(STATUS_BAD_TOKEN_TYPE));
}

#[test]
fn explicit_owner_requires_user_owner_group_or_enabled_restore() {
    let mut primary = primary();
    let owner_group = Sid::administrators();
    primary
        .groups
        .push(TokenGroup::enabled_owner(owner_group.clone()));
    let mapping = mapping();
    for owner in [&primary.user, &owner_group] {
        let descriptor = sd(Some(owner), None, None, None, 0);
        let mut request = assignment(&primary, &mapping);
        request.creator = Some(&descriptor);
        assert!(assign_object_security(&request).is_ok());
    }
    let foreign = Sid::local_system();
    let descriptor = sd(Some(&foreign), None, None, None, 0);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&descriptor);
    assert_eq!(assign_object_security(&request), Err(STATUS_INVALID_OWNER));
    drop(request);
    privilege(&mut primary, SE_RESTORE);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&descriptor);
    assert!(assign_object_security(&request).is_ok());
}

#[test]
fn enabled_nonowner_group_and_disabled_restore_are_not_owner_authority() {
    let mut primary = primary();
    let group = Sid::administrators();
    primary.groups.push(TokenGroup::enabled(group.clone()));
    privilege(&mut primary, SE_RESTORE);
    primary.privileges.last_mut().unwrap().enabled = false;
    let descriptor = sd(Some(&group), None, None, None, 0);
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&descriptor);
    assert_eq!(assign_object_security(&request), Err(STATUS_INVALID_OWNER));
}

#[test]
fn identification_context_can_default_owner_but_cannot_explicitly_assign_one() {
    let primary = primary();
    let mut client = client();
    privilege(&mut client, SE_RESTORE);
    let descriptor = sd(Some(&client.user), None, None, None, 0);
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    request.client = Some(SecurityAssignmentClient {
        token: &client,
        level: SecurityImpersonationLevel::Identification,
    });
    assert!(assign_object_security(&request).is_ok());
    request.creator = Some(&descriptor);
    assert_eq!(assign_object_security(&request), Err(STATUS_INVALID_OWNER));
    extended(&mut request, SEF_AVOID_OWNER_CHECK);
    assert!(assign_object_security(&request).is_ok());
}

#[test]
fn primary_restore_privilege_does_not_authorize_client_owner_assignment() {
    let primary = AccessToken::system();
    let client = client();
    let descriptor = sd(Some(&Sid::local_system()), None, None, None, 0);
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    request.client = Some(SecurityAssignmentClient {
        token: &client,
        level: SecurityImpersonationLevel::Impersonation,
    });
    request.creator = Some(&descriptor);
    assert_eq!(assign_object_security(&request), Err(STATUS_INVALID_OWNER));
}

#[test]
fn any_valid_explicit_primary_group_is_allowed_without_membership_check() {
    let primary = primary();
    let foreign = Sid::local_account(99, 77);
    let descriptor = sd(None, Some(&foreign), None, None, 0);
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&descriptor);
    let result = assign_object_security(&request).unwrap();
    assert_eq!(
        parse_self_relative_descriptor(&result)
            .unwrap()
            .group
            .unwrap(),
        sid_bytes(&foreign, STATUS_INVALID_PRIMARY_GROUP).unwrap()
    );
}

#[test]
fn parent_owner_group_defaults_are_explicit_and_missing_components_fail() {
    let primary = primary();
    let mapping = mapping();
    let parent = sd(Some(&primary.user), Some(&Sid::everyone()), None, None, 0);
    let mut request = assignment(&primary, &mapping);
    extended(&mut request, SEF_DEFAULT_OWNER_FROM_PARENT);
    assert_eq!(assign_object_security(&request), Err(STATUS_INVALID_OWNER));
    extended(&mut request, SEF_DEFAULT_GROUP_FROM_PARENT);
    assert_eq!(
        assign_object_security(&request),
        Err(STATUS_INVALID_PRIMARY_GROUP)
    );
    request.parent = Some(&parent);
    extended(
        &mut request,
        SEF_DEFAULT_OWNER_FROM_PARENT | SEF_DEFAULT_GROUP_FROM_PARENT,
    );
    let result = assign_object_security(&request).unwrap();
    let result = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(
        result.group.unwrap(),
        sid_bytes(&Sid::everyone(), STATUS_INVALID_PRIMARY_GROUP).unwrap()
    );
    let foreign_parent = sd(
        Some(&Sid::local_system()),
        Some(&Sid::everyone()),
        None,
        None,
        0,
    );
    request.parent = Some(&foreign_parent);
    assert_eq!(assign_object_security(&request), Err(STATUS_INVALID_OWNER));
}

#[test]
fn explicit_creator_owner_group_override_parent_default_flags() {
    let primary = primary();
    let mapping = mapping();
    let creator = sd(Some(&primary.user), Some(&Sid::everyone()), None, None, 0);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    extended(
        &mut request,
        SEF_DEFAULT_OWNER_FROM_PARENT | SEF_DEFAULT_GROUP_FROM_PARENT,
    );
    assert!(assign_object_security(&request).is_ok());
}

#[test]
fn explicit_null_empty_and_defaulted_sacls_all_require_security_privilege() {
    let primary = primary();
    let mapping = mapping();
    let empty = acl(&[]);
    for sacl in [None, Some(&empty)] {
        for control in [0, SE_SACL_DEFAULTED] {
            let descriptor = sd(None, None, None, Some(sacl), control);
            let mut request = assignment(&primary, &mapping);
            request.creator = Some(&descriptor);
            assert_eq!(
                assign_object_security(&request),
                Err(STATUS_PRIVILEGE_NOT_HELD)
            );
            extended(&mut request, SEF_AVOID_PRIVILEGE_CHECK);
            assert!(assign_object_security(&request).is_ok());
        }
    }
}

#[test]
fn inherited_sacl_needs_no_assignment_privilege() {
    let primary = primary();
    let mapping = mapping();
    let inherited = acl(&[ace(2, 1, &Sid::everyone())]);
    let parent = sd(None, None, None, Some(Some(&inherited)), 0);
    let mut request = assignment(&primary, &mapping);
    request.parent = Some(&parent);
    let result = assign_object_security(&request).unwrap();
    assert_eq!(
        masks(parse_self_relative_descriptor(&result).unwrap().sacl),
        [1]
    );
}

#[test]
fn explicit_sacl_uses_client_enabled_privilege_and_effective_impersonation_level() {
    let primary = AccessToken::system();
    let mut client = client();
    let descriptor = sd(None, None, None, Some(None), 0);
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&descriptor);
    request.client = Some(SecurityAssignmentClient {
        token: &client,
        level: SecurityImpersonationLevel::Impersonation,
    });
    assert_eq!(
        assign_object_security(&request),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    );
    drop(request);
    privilege(&mut client, SE_SECURITY);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&descriptor);
    request.client = Some(SecurityAssignmentClient {
        token: &client,
        level: SecurityImpersonationLevel::Identification,
    });
    assert_eq!(
        assign_object_security(&request),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    );
    request.client.as_mut().unwrap().level = SecurityImpersonationLevel::Impersonation;
    assert!(assign_object_security(&request).is_ok());
}

#[test]
fn kernel_mode_bypasses_assignment_checks_but_not_descriptor_validation() {
    let primary = primary();
    let descriptor = sd(Some(&Sid::local_system()), None, None, Some(None), 0);
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    request.mode = ProcessorMode::KernelMode;
    request.creator = Some(&descriptor);
    assert!(assign_object_security(&request).is_ok());
    request.creator = Some(&[1]);
    assert!(assign_object_security(&request).is_err());
}

#[test]
fn dacl_absent_null_empty_defaulted_selection_matrix() {
    let primary = primary();
    let mapping = mapping();
    let parent_acl = acl(&[ace(2, 1, &Sid::everyone())]);
    let parent = sd(None, None, Some(Some(&parent_acl)), None, 0);
    let empty = acl(&[]);
    let explicit = acl(&[ace(0, 2, &Sid::everyone())]);
    for automatic in [false, true] {
        for defaulted in [false, true] {
            for (index, child) in [None, Some(None), Some(Some(&empty)), Some(Some(&explicit))]
                .into_iter()
                .enumerate()
            {
                let creator = sd(
                    None,
                    None,
                    child,
                    None,
                    if defaulted { SE_DACL_DEFAULTED } else { 0 },
                );
                // The serializer clears DEFAULTED when PRESENT is absent, matching a valid absent ACL.
                let child_defaulted = defaulted && index != 0;
                let mut request = assignment(&primary, &mapping);
                request.creator = Some(&creator);
                request.parent = Some(&parent);
                extended(
                    &mut request,
                    if automatic { SEF_DACL_AUTO_INHERIT } else { 0 },
                );
                if automatic && index == 1 && !child_defaulted {
                    assert_eq!(assign_object_security(&request), Err(STATUS_INVALID_ACL));
                    continue;
                }
                let result = assign_object_security(&request).unwrap();
                let parsed = parse_self_relative_descriptor(&result).unwrap();
                let expected = if index == 0 || child_defaulted {
                    vec![1]
                } else if automatic {
                    if index == 3 {
                        vec![2, 1]
                    } else {
                        vec![1]
                    }
                } else if index == 3 {
                    vec![2]
                } else {
                    vec![]
                };
                assert_eq!(
                    masks(parsed.dacl),
                    expected,
                    "auto={automatic} defaulted={defaulted} state={index}"
                );
                assert!(parsed.dacl_present);
                if !automatic && !child_defaulted && index == 1 {
                    assert!(parsed.dacl.is_none());
                }
                if !automatic && !child_defaulted && index == 2 {
                    assert_eq!(parsed.dacl.unwrap().len(), 8);
                }
            }
        }
    }
}

#[test]
fn empty_parent_or_no_inheritable_ace_uses_token_default_not_empty_denial() {
    let primary = primary();
    let mapping = mapping();
    for parent_acl in [acl(&[]), acl(&[ace(0, 1, &Sid::everyone())])] {
        let parent = sd(None, None, Some(Some(&parent_acl)), None, 0);
        let mut request = assignment(&primary, &mapping);
        request.parent = Some(&parent);
        let result = assign_object_security(&request).unwrap();
        assert_eq!(
            masks(parse_self_relative_descriptor(&result).unwrap().dacl),
            [4]
        );
    }
}

#[test]
fn defaulted_null_acl_fallback_is_preserved_and_auto_null_is_protected() {
    let primary = primary();
    let mapping = mapping();
    let creator = sd(None, None, Some(None), None, SE_DACL_DEFAULTED);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    extended(&mut request, SEF_DACL_AUTO_INHERIT);
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert!(parsed.dacl_present && parsed.dacl.is_none());
    assert_ne!(parsed.control & SE_DACL_PROTECTED, 0);
    assert_ne!(parsed.control & SE_DACL_AUTO_INHERITED, 0);
    assert_eq!(parsed.control & SE_DACL_DEFAULTED, 0);
}

#[test]
fn token_null_default_is_absent_not_explicit_null_and_auto_marks_it_protected() {
    let mut primary = primary();
    primary.default_dacl = None;
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    let result = assign_object_security(&request).unwrap();
    assert!(
        !parse_self_relative_descriptor(&result)
            .unwrap()
            .dacl_present
    );
    extended(&mut request, SEF_DACL_AUTO_INHERIT);
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert!(!parsed.dacl_present);
    assert_eq!(
        parsed.control & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED),
        SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED
    );
}

#[test]
fn protected_explicit_null_blocks_parent_and_is_valid_under_auto_inheritance() {
    let primary = primary();
    let mapping = mapping();
    let parent_acl = acl(&[ace(2, 1, &Sid::everyone())]);
    let parent = sd(None, None, Some(Some(&parent_acl)), None, 0);
    let creator = sd(None, None, Some(None), None, SE_DACL_PROTECTED);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    request.parent = Some(&parent);
    extended(&mut request, SEF_DACL_AUTO_INHERIT);
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert!(parsed.dacl_present && parsed.dacl.is_none());
    assert_ne!(parsed.control & SE_DACL_PROTECTED, 0);
}

#[test]
fn legacy_auto_policy_is_derived_per_absent_creator_acl_not_globally() {
    let mut primary = primary();
    privilege(&mut primary, SE_SECURITY);
    let mapping = mapping();
    let parent_acl = acl(&[ace(2, 1, &Sid::everyone())]);
    let explicit_acl = acl(&[ace(0, 2, &Sid::everyone())]);
    let parent = sd(
        None,
        None,
        Some(Some(&parent_acl)),
        Some(Some(&parent_acl)),
        SE_DACL_AUTO_INHERITED | SE_SACL_AUTO_INHERITED,
    );
    let creator = sd(None, None, Some(Some(&explicit_acl)), None, 0);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    request.parent = Some(&parent);
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(masks(parsed.dacl), [2]);
    assert_eq!(masks(parsed.sacl), [1]);
    assert_eq!(parsed.control & SE_DACL_AUTO_INHERITED, 0);
    assert_ne!(parsed.control & SE_SACL_AUTO_INHERITED, 0);
}

#[test]
fn extended_zero_flags_do_not_implicitly_inherit_parent_auto_policy() {
    let primary = primary();
    let mapping = mapping();
    let parent_acl = acl(&[ace(2, 1, &Sid::everyone())]);
    let parent = sd(
        None,
        None,
        Some(Some(&parent_acl)),
        None,
        SE_DACL_AUTO_INHERITED,
    );
    let mut request = assignment(&primary, &mapping);
    request.parent = Some(&parent);
    extended(&mut request, 0);
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(parsed.control & SE_DACL_AUTO_INHERITED, 0);
    assert_eq!(entries(parsed.dacl)[0][1], 2);
}

#[test]
fn auto_child_replaces_old_inherited_aces_but_protected_child_retains_them_as_explicit() {
    let primary = primary();
    let mapping = mapping();
    let old = acl(&[ace(16, 2, &Sid::everyone()), ace(0, 4, &Sid::everyone())]);
    let inherited = acl(&[ace(2, 1, &Sid::everyone())]);
    let parent = sd(None, None, Some(Some(&inherited)), None, 0);
    for protected in [false, true] {
        let creator = sd(
            None,
            None,
            Some(Some(&old)),
            None,
            if protected { SE_DACL_PROTECTED } else { 0 },
        );
        let mut request = assignment(&primary, &mapping);
        request.parent = Some(&parent);
        request.creator = Some(&creator);
        extended(&mut request, SEF_DACL_AUTO_INHERIT);
        let result = assign_object_security(&request).unwrap();
        let parsed = parse_self_relative_descriptor(&result).unwrap();
        assert_eq!(
            masks(parsed.dacl),
            if protected { vec![2, 4] } else { vec![4, 1] }
        );
        assert_eq!(entries(parsed.dacl)[0][1] & 16, 0);
        assert_eq!(
            entries(parsed.dacl)[1][1] & 16,
            if protected { 0 } else { 16 }
        );
    }
}

#[test]
fn explicit_child_creator_mapping_is_auto_only_and_split_keeps_no_propagate() {
    let primary = primary();
    let mapping = mapping();
    let creator_sid = Sid::creator_owner();
    let original = acl(&[ace(2 | 4, GENERIC_ALL, &creator_sid)]);
    let creator = sd(None, None, Some(Some(&original)), None, 0);
    for automatic in [false, true] {
        let mut request = assignment(&primary, &mapping);
        request.creator = Some(&creator);
        extended(
            &mut request,
            if automatic { SEF_DACL_AUTO_INHERIT } else { 0 },
        );
        let result = assign_object_security(&request).unwrap();
        let parsed = parse_self_relative_descriptor(&result).unwrap();
        let entries = entries(parsed.dacl);
        if automatic {
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0][1], 0);
            assert_eq!(
                &entries[0][8..],
                sid_bytes(&primary.owner, STATUS_INVALID_OWNER).unwrap()
            );
            assert_eq!(entries[1][1], 2 | 4 | 8);
            assert_eq!(
                &entries[1][8..],
                sid_bytes(&creator_sid, STATUS_INVALID_OWNER).unwrap()
            );
        } else {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0][1], 2 | 4);
            assert_eq!(
                &entries[0][8..],
                sid_bytes(&creator_sid, STATUS_INVALID_OWNER).unwrap()
            );
        }
    }
}

fn inherited_object_ace(mask: u32, guid: [u8; 16]) -> Vec<u8> {
    let mut object = vec![5, 2, 0, 0];
    object.extend_from_slice(&mask.to_le_bytes());
    object.extend_from_slice(&2u32.to_le_bytes());
    object.extend_from_slice(&guid);
    object.extend_from_slice(&sid_bytes(&Sid::everyone(), STATUS_INVALID_OWNER).unwrap());
    let size = object.len() as u16;
    object[2..4].copy_from_slice(&size.to_le_bytes());
    object
}

#[test]
fn explicit_child_object_guid_does_not_filter_or_strip_its_payload() {
    let primary = primary();
    let mapping = mapping();
    let original = acl_revision(4, &[inherited_object_ace(1, [7; 16])]);
    let creator = sd(None, None, Some(Some(&original)), None, 0);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    extended(&mut request, SEF_DACL_AUTO_INHERIT);
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(entries(parsed.dacl).len(), 1);
    assert_eq!(&entries(parsed.dacl)[0][12..28], [7; 16]);
    assert_eq!(entries(parsed.dacl)[0][0], 5);
}

#[test]
fn object_default_descriptor_is_discarded_only_on_matched_parent_object_inheritance() {
    let primary = primary();
    let mapping = mapping();
    let inherited = acl_revision(4, &[inherited_object_ace(1, [7; 16])]);
    let explicit = acl(&[ace(0, 2, &Sid::everyone())]);
    let parent = sd(None, None, Some(Some(&inherited)), None, 0);
    let creator = sd(None, None, Some(Some(&explicit)), None, 0);
    for guid in [None, Some([6; 16]), Some([7; 16])] {
        let mut request = assignment(&primary, &mapping);
        request.parent = Some(&parent);
        request.creator = Some(&creator);
        request.object_type = guid.as_ref();
        extended(
            &mut request,
            SEF_DACL_AUTO_INHERIT | SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT,
        );
        let result = assign_object_security(&request).unwrap();
        let parsed = parse_self_relative_descriptor(&result).unwrap();
        assert_eq!(
            masks(parsed.dacl),
            if guid == Some([7; 16]) {
                vec![1]
            } else {
                vec![2, 1]
            }
        );
        if guid != Some([7; 16]) {
            assert_ne!(entries(parsed.dacl)[1][1] & 8, 0);
        }
    }
}

#[test]
fn unsupported_flags_descriptor_modes_and_aces_return_errors_without_input_mutation() {
    let primary = primary();
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    for bit in 7..32 {
        extended(&mut request, 1 << bit);
        assert_eq!(assign_object_security(&request), Err(STATUS_NOT_SUPPORTED));
    }
    extended(&mut request, 0);
    for control in [0x40u16, 0x80, 0x4000] {
        let mut creator = sd(None, None, None, None, 0);
        creator[2..4].copy_from_slice(&(0x8000 | control).to_le_bytes());
        let before = creator.clone();
        let mut request = assignment(&primary, &mapping);
        request.creator = Some(&creator);
        assert_eq!(assign_object_security(&request), Err(STATUS_NOT_SUPPORTED));
        assert_eq!(creator, before);
    }
    let unknown = acl_revision(4, &[vec![9, 0, 4, 0]]);
    let creator = sd(None, None, Some(Some(&unknown)), None, 0);
    request.creator = Some(&creator);
    assert_eq!(assign_object_security(&request), Err(STATUS_NOT_SUPPORTED));
}

#[test]
fn acl_merge_overflow_is_unpublished_and_preserves_both_descriptors() {
    let primary = primary();
    let mapping = mapping();
    let mut large = ace(2, 1, &Sid::everyone());
    large.resize(40000, 0);
    large[2..4].copy_from_slice(&40000u16.to_le_bytes());
    let large = acl(&[large]);
    let creator = sd(None, None, Some(Some(&large)), None, 0);
    let parent = creator.clone();
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    request.parent = Some(&parent);
    extended(&mut request, SEF_DACL_AUTO_INHERIT);
    assert_eq!(assign_object_security(&request), Err(0xc000_007d));
    assert_eq!(creator, parent);
}

#[test]
fn output_is_owned_and_remains_valid_after_source_descriptors_are_dropped() {
    let primary = primary();
    let mapping = mapping();
    let result = {
        let raw_acl = acl(&[ace(0, 2, &Sid::everyone())]);
        let creator = sd(None, None, Some(Some(&raw_acl)), None, 0);
        let mut request = assignment(&primary, &mapping);
        request.creator = Some(&creator);
        assign_object_security(&request).unwrap()
    };
    assert_eq!(
        masks(parse_self_relative_descriptor(&result).unwrap().dacl),
        [2]
    );
}

#[test]
fn invalid_token_default_sids_are_rejected_without_an_owner_fallback() {
    let mut primary = primary();
    let mapping = mapping();
    primary.owner.revision = 2;
    assert_eq!(
        assign_object_security(&assignment(&primary, &mapping)),
        Err(STATUS_INVALID_OWNER)
    );
    primary.owner = primary.user.clone();
    primary.primary_group.revision = 2;
    assert_eq!(
        assign_object_security(&assignment(&primary, &mapping)),
        Err(STATUS_INVALID_PRIMARY_GROUP)
    );
}

#[test]
fn audit_trace_resets_before_validation_and_on_check_free_success() {
    let primary = primary();
    let mapping = mapping();
    let mut request = assignment(&primary, &mapping);
    let mut audit = SecurityAssignmentAudit {
        security: Some(SecurityAssignmentPrivilegeOutcome::Granted),
        restore: Some(SecurityAssignmentPrivilegeOutcome::Denied),
    };
    request.creator = Some(&[1]);
    assert!(assign_object_security_with_audit(&request, &mut audit).is_err());
    assert_eq!(audit, SecurityAssignmentAudit::default());
    audit.security = Some(SecurityAssignmentPrivilegeOutcome::Denied);
    request.creator = None;
    assert!(assign_object_security_with_audit(&request, &mut audit).is_ok());
    assert_eq!(audit, SecurityAssignmentAudit::default());
}

#[test]
fn audit_records_denied_and_granted_security_privilege_attempts() {
    let creator = sd(None, None, None, Some(None), 0);
    let mapping = mapping();
    for granted in [false, true] {
        let mut primary = primary();
        privilege(&mut primary, SE_SECURITY);
        primary.privileges.last_mut().unwrap().enabled = granted;
        let mut request = assignment(&primary, &mapping);
        request.creator = Some(&creator);
        let mut audit = SecurityAssignmentAudit::default();
        let result = assign_object_security_with_audit(&request, &mut audit);
        if granted {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(STATUS_PRIVILEGE_NOT_HELD));
        }
        assert_eq!(
            audit.security,
            Some(if granted {
                SecurityAssignmentPrivilegeOutcome::Granted
            } else {
                SecurityAssignmentPrivilegeOutcome::Denied
            })
        );
        assert_eq!(audit.restore, None);
    }
}

#[test]
fn audit_records_restore_only_when_foreign_owner_needs_it() {
    let mapping = mapping();
    for granted in [false, true] {
        let mut primary = primary();
        if granted {
            privilege(&mut primary, SE_RESTORE);
        }
        let foreign = sd(Some(&Sid::local_system()), None, None, None, 0);
        let mut request = assignment(&primary, &mapping);
        request.creator = Some(&foreign);
        let mut audit = SecurityAssignmentAudit::default();
        let result = assign_object_security_with_audit(&request, &mut audit);
        if granted {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(STATUS_INVALID_OWNER));
        }
        assert_eq!(
            audit.restore,
            Some(if granted {
                SecurityAssignmentPrivilegeOutcome::Granted
            } else {
                SecurityAssignmentPrivilegeOutcome::Denied
            })
        );
        assert_eq!(audit.security, None);
        let own = sd(Some(&primary.user), None, None, None, 0);
        request.creator = Some(&own);
        assert!(assign_object_security_with_audit(&request, &mut audit).is_ok());
        assert_eq!(audit, SecurityAssignmentAudit::default());
    }
}

#[test]
fn audit_retains_earlier_granted_security_check_when_later_owner_check_fails() {
    let mut primary = primary();
    privilege(&mut primary, SE_SECURITY);
    let mapping = mapping();
    let creator = sd(Some(&Sid::local_system()), None, None, Some(None), 0);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    let mut audit = SecurityAssignmentAudit::default();
    assert_eq!(
        assign_object_security_with_audit(&request, &mut audit),
        Err(STATUS_INVALID_OWNER)
    );
    assert_eq!(
        audit.security,
        Some(SecurityAssignmentPrivilegeOutcome::Granted)
    );
    assert_eq!(
        audit.restore,
        Some(SecurityAssignmentPrivilegeOutcome::Denied)
    );
}

#[test]
fn low_client_level_denies_security_audit_but_never_reaches_restore_check() {
    let primary = AccessToken::system();
    let mut client = client();
    privilege(&mut client, SE_SECURITY);
    privilege(&mut client, SE_RESTORE);
    let mapping = mapping();
    let sacl = sd(None, None, None, Some(None), 0);
    let owner = sd(Some(&Sid::local_system()), None, None, None, 0);
    let mut request = assignment(&primary, &mapping);
    request.client = Some(SecurityAssignmentClient {
        token: &client,
        level: SecurityImpersonationLevel::Anonymous,
    });
    request.creator = Some(&sacl);
    let mut audit = SecurityAssignmentAudit::default();
    assert_eq!(
        assign_object_security_with_audit(&request, &mut audit),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    );
    assert_eq!(
        audit.security,
        Some(SecurityAssignmentPrivilegeOutcome::Denied)
    );
    assert_eq!(audit.restore, None);
    request.creator = Some(&owner);
    assert_eq!(
        assign_object_security_with_audit(&request, &mut audit),
        Err(STATUS_INVALID_OWNER)
    );
    assert_eq!(audit, SecurityAssignmentAudit::default());
}

#[test]
fn kernel_and_explicit_bypass_flags_report_no_privilege_use() {
    let primary = primary();
    let mapping = mapping();
    let creator = sd(Some(&Sid::local_system()), None, None, Some(None), 0);
    for mode in [ProcessorMode::UserMode, ProcessorMode::KernelMode] {
        let mut request = assignment(&primary, &mapping);
        request.creator = Some(&creator);
        request.mode = mode;
        if mode == ProcessorMode::UserMode {
            extended(
                &mut request,
                SEF_AVOID_OWNER_CHECK | SEF_AVOID_PRIVILEGE_CHECK,
            );
        }
        let mut audit = SecurityAssignmentAudit::default();
        assert!(assign_object_security_with_audit(&request, &mut audit).is_ok());
        assert_eq!(audit, SecurityAssignmentAudit::default());
    }
}

#[test]
fn failed_security_check_does_not_record_unreached_restore_check() {
    let primary = primary();
    let mapping = mapping();
    let creator = sd(Some(&Sid::local_system()), None, None, Some(None), 0);
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    let mut audit = SecurityAssignmentAudit::default();
    assert_eq!(
        assign_object_security_with_audit(&request, &mut audit),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    );
    assert_eq!(
        audit.security,
        Some(SecurityAssignmentPrivilegeOutcome::Denied)
    );
    assert_eq!(audit.restore, None);
}

#[test]
fn protected_absent_acl_obeys_legacy_vs_automatic_parent_selection() {
    let primary = primary();
    let mapping = mapping();
    let parent_acl = acl(&[ace(2, 1, &Sid::everyone())]);
    let parent = sd(None, None, Some(Some(&parent_acl)), None, 0);
    let creator = sd(None, None, None, None, SE_DACL_PROTECTED);
    for automatic in [false, true] {
        let mut request = assignment(&primary, &mapping);
        request.creator = Some(&creator);
        request.parent = Some(&parent);
        extended(
            &mut request,
            if automatic { SEF_DACL_AUTO_INHERIT } else { 0 },
        );
        let result = assign_object_security(&request).unwrap();
        let parsed = parse_self_relative_descriptor(&result).unwrap();
        assert!(parsed.dacl_present);
        assert_ne!(parsed.control & SE_DACL_PROTECTED, 0);
        if automatic {
            assert!(parsed.dacl.is_none());
        } else {
            assert_eq!(masks(parsed.dacl), [1]);
        }
    }
}

#[test]
fn protected_defaulted_child_does_not_block_parent_inheritance() {
    let primary = primary();
    let mapping = mapping();
    let parent_acl = acl(&[ace(2, 1, &Sid::everyone())]);
    let child_acl = acl(&[ace(0, 2, &Sid::everyone())]);
    let parent = sd(None, None, Some(Some(&parent_acl)), None, 0);
    let creator = sd(
        None,
        None,
        Some(Some(&child_acl)),
        None,
        SE_DACL_DEFAULTED | SE_DACL_PROTECTED,
    );
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    request.parent = Some(&parent);
    extended(&mut request, SEF_DACL_AUTO_INHERIT);
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert_eq!(masks(parsed.dacl), [1]);
    assert_eq!(parsed.control & SE_DACL_PROTECTED, 0);
}

#[test]
fn matched_object_inheritance_with_zero_rights_still_discards_default_child() {
    let primary = primary();
    let mapping = mapping();
    let parent_acl = acl_revision(4, &[inherited_object_ace(0, [7; 16])]);
    let child_acl = acl(&[ace(0, 2, &Sid::everyone())]);
    let parent = sd(None, None, Some(Some(&parent_acl)), None, 0);
    let creator = sd(None, None, Some(Some(&child_acl)), None, 0);
    let guid = [7; 16];
    let mut request = assignment(&primary, &mapping);
    request.creator = Some(&creator);
    request.parent = Some(&parent);
    request.object_type = Some(&guid);
    extended(
        &mut request,
        SEF_DACL_AUTO_INHERIT | SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT,
    );
    let result = assign_object_security(&request).unwrap();
    let parsed = parse_self_relative_descriptor(&result).unwrap();
    assert!(parsed.dacl_present);
    assert_eq!(parsed.dacl.unwrap(), [4, 0, 8, 0, 0, 0, 0, 0]);
}

#[test]
fn explicit_inherit_only_leaf_ace_is_removed_only_in_automatic_mode() {
    let primary = primary();
    let mapping = mapping();
    let child_acl = acl(&[ace(1 | 8, GENERIC_ALL, &Sid::creator_owner())]);
    let creator = sd(None, None, Some(Some(&child_acl)), None, 0);
    for automatic in [false, true] {
        let mut request = assignment(&primary, &mapping);
        request.creator = Some(&creator);
        request.is_container = false;
        extended(
            &mut request,
            if automatic { SEF_DACL_AUTO_INHERIT } else { 0 },
        );
        let result = assign_object_security(&request).unwrap();
        let parsed = parse_self_relative_descriptor(&result).unwrap();
        assert!(parsed.dacl.is_some());
        assert_eq!(
            masks(parsed.dacl),
            if automatic { vec![] } else { vec![GENERIC_ALL] }
        );
    }
}
