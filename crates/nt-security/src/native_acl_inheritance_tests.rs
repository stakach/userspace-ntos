use super::*;
use crate::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use alloc::vec;

fn mapping() -> GenericMapping {
    GenericMapping {
        generic_read: 1,
        generic_write: 2,
        generic_execute: 4,
        generic_all: 7,
    }
}

fn sid(sid: &Sid) -> Vec<u8> {
    let mut bytes = vec![0; sid.native_len().unwrap()];
    sid.write_native(&mut bytes).unwrap();
    bytes
}

fn basic(kind: u8, flags: u8, mask: u32, trustee: &Sid) -> Vec<u8> {
    let mut bytes = vec![kind, flags, 0, 0];
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&sid(trustee));
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn object(
    kind: u8,
    flags: u8,
    mask: u32,
    trustee: &Sid,
    object: Option<[u8; 16]>,
    inherited: Option<[u8; 16]>,
) -> Vec<u8> {
    let mut bytes = vec![kind, flags, 0, 0];
    bytes.extend_from_slice(&mask.to_le_bytes());
    let fields = u32::from(object.is_some()) | (u32::from(inherited.is_some()) << 1);
    bytes.extend_from_slice(&fields.to_le_bytes());
    if let Some(guid) = object {
        bytes.extend_from_slice(&guid);
    }
    if let Some(guid) = inherited {
        bytes.extend_from_slice(&guid);
    }
    bytes.extend_from_slice(&sid(trustee));
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn compound(flags: u8, mask: u32, server: &Sid, client: &Sid) -> Vec<u8> {
    let mut bytes = vec![4, flags, 0, 0];
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&[1, 0, 0, 0]);
    bytes.extend_from_slice(&sid(server));
    bytes.extend_from_slice(&sid(client));
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes
}

fn acl(revision: u8, aces: &[Vec<u8>]) -> NativeAcl {
    let mut bytes = vec![revision, 0, 0, 0, 0, 0, 0, 0];
    for ace in aces {
        bytes.extend_from_slice(ace);
    }
    let size = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&size.to_le_bytes());
    bytes[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    NativeAcl::from_bytes(&bytes).unwrap()
}

fn aces(acl: &NativeAcl) -> Vec<&[u8]> {
    let bytes = acl.as_bytes();
    let mut offset = 8;
    let mut result = Vec::new();
    for _ in 0..u16::from_le_bytes(bytes[4..6].try_into().unwrap()) {
        let size = u16::from_le_bytes(bytes[offset + 2..offset + 4].try_into().unwrap()) as usize;
        result.push(&bytes[offset..offset + size]);
        offset += size;
    }
    assert_eq!(offset, bytes.len());
    result
}

fn transform(parent: &NativeAcl, container: bool) -> NativeAcl {
    inherit_native_acl(
        parent,
        &NativeAclInheritance {
            is_container: container,
            auto_inherit: true,
            owner: &Sid::local_system(),
            group: &Sid::administrators(),
            server_owner: None,
            server_group: None,
            mapping: &mapping(),
            object_type: None,
        },
    )
    .unwrap()
}

fn ace_mask(ace: &[u8]) -> u32 {
    u32::from_le_bytes(ace[4..8].try_into().unwrap())
}

#[test]
fn full_flag_matrix_covers_leaf_container_and_legacy_automatic_inheritance() {
    for kind in 0..=3 {
        for flags in 0..32 {
            for container in [false, true] {
                for automatic in [false, true] {
                    let parent = acl(2, &[basic(kind, flags | 0xc0, 1, &Sid::everyone())]);
                    let result = inherit_native_acl(
                        &parent,
                        &NativeAclInheritance {
                            is_container: container,
                            auto_inherit: automatic,
                            owner: &Sid::local_system(),
                            group: &Sid::administrators(),
                            server_owner: None,
                            server_group: None,
                            mapping: &mapping(),
                            object_type: None,
                        },
                    )
                    .unwrap();
                    let actual = aces(&result);
                    let effective = flags & (if container { CI } else { OI }) != 0;
                    let propagation = container && flags & (OI | CI) != 0 && flags & NP == 0;
                    if !effective && !propagation {
                        assert!(actual.is_empty());
                        continue;
                    }
                    assert_eq!(actual.len(), 1);
                    let expected = if effective {
                        0xc0 | if automatic { INHERITED } else { 0 }
                            | if propagation { flags & (OI | CI) } else { 0 }
                    } else {
                        0xc0 | flags | IO | if automatic { INHERITED } else { 0 }
                    };
                    assert_eq!(
                        actual[0][1], expected,
                        "kind={kind} flags={flags} container={container} automatic={automatic}"
                    );
                    assert_eq!(actual[0][0], kind);
                    assert_eq!(ace_mask(actual[0]), 1);
                }
            }
        }
    }
}

#[test]
fn generics_split_effective_rights_from_original_propagation() {
    for generic in [GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE, GENERIC_ALL] {
        let original = basic(0, OI | CI, generic, &Sid::everyone());
        let result = transform(&acl(2, &[original.clone()]), true);
        let entries = aces(&result);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0][1], INHERITED);
        assert_eq!(ace_mask(entries[0]), mapping().map(generic));
        let mut propagation = original;
        propagation[1] |= IO | INHERITED;
        assert_eq!(entries[1], propagation);
    }
}

#[test]
fn inherit_only_ace_becomes_effective_on_child_and_does_not_substitute_on_container_passthrough() {
    let creator = Sid::creator_owner();
    let original = basic(0, OI | IO, GENERIC_ALL, &creator);
    let container = transform(&acl(2, &[original.clone()]), true);
    let container_aces = aces(&container);
    assert_eq!(container_aces.len(), 1);
    assert_eq!(ace_mask(container_aces[0]), GENERIC_ALL);
    assert_eq!(&container_aces[0][8..], sid(&creator));
    let leaf = transform(&container, false);
    let leaf_aces = aces(&leaf);
    assert_eq!(leaf_aces.len(), 1);
    assert_eq!(leaf_aces[0][1], INHERITED);
    assert_eq!(&leaf_aces[0][8..], sid(&Sid::local_system()));
    assert_eq!(ace_mask(leaf_aces[0]), 7);
}

#[test]
fn creator_owner_group_and_server_identities_replace_only_effective_sids() {
    let owner = Sid::local_account(3, 4);
    let group = Sid::administrators();
    let server_owner = Sid::local_service();
    let server_group = Sid::users();
    for (rid, replacement) in [
        (0, &owner),
        (1, &group),
        (2, &server_owner),
        (3, &server_group),
    ] {
        let creator = Sid::new(3, &[rid]);
        let original = basic(0, OI | CI, 1, &creator);
        let result = inherit_native_acl(
            &acl(2, &[original.clone()]),
            &NativeAclInheritance {
                is_container: true,
                auto_inherit: true,
                owner: &owner,
                group: &group,
                server_owner: Some(&server_owner),
                server_group: Some(&server_group),
                mapping: &mapping(),
                object_type: None,
            },
        )
        .unwrap();
        let entries = aces(&result);
        assert_eq!(entries.len(), 2);
        assert_eq!(&entries[0][8..], sid(replacement));
        assert_eq!(&entries[1][8..], sid(&creator));
        assert_eq!(entries[0][1], INHERITED);
        assert_eq!(entries[1][1], OI | CI | IO | INHERITED);
    }
}

#[test]
fn absent_server_identities_follow_nt5_child_identity_default() {
    for (rid, replacement) in [(2, Sid::local_system()), (3, Sid::administrators())] {
        let result = transform(&acl(2, &[basic(0, OI, 1, &Sid::new(3, &[rid]))]), false);
        assert_eq!(&aces(&result)[0][8..], sid(&replacement));
    }
}

#[test]
fn unrelated_creator_authority_sids_are_not_substituted() {
    for original in [Sid::new(3, &[4]), Sid::new(3, &[0, 1]), Sid::new(5, &[0])] {
        let result = transform(&acl(2, &[basic(0, CI, 1, &original)]), true);
        assert_eq!(aces(&result).len(), 1);
        assert_eq!(&aces(&result)[0][8..], sid(&original));
    }
}

#[test]
fn no_propagate_stops_after_one_generation_even_with_generic_creator_mapping() {
    let parent = acl(
        2,
        &[basic(0, OI | CI | NP, GENERIC_ALL, &Sid::creator_owner())],
    );
    let child = transform(&parent, true);
    assert_eq!(aces(&child).len(), 1);
    assert_eq!(aces(&child)[0][1], INHERITED);
    assert!(aces(&transform(&child, true)).is_empty());
    assert!(aces(&transform(&child, false)).is_empty());
}

#[test]
fn zero_effective_masks_are_dropped_without_discarding_nonzero_propagation() {
    let original = basic(0, CI, 0x2000, &Sid::everyone());
    let result = transform(&acl(2, &[original]), true);
    assert_eq!(aces(&result).len(), 1);
    assert_eq!(aces(&result)[0][1], CI | IO | INHERITED);
    assert_eq!(ace_mask(aces(&result)[0]), 0x2000);
    assert!(aces(&transform(
        &acl(2, &[basic(0, OI, 0x2000, &Sid::everyone())]),
        false
    ))
    .is_empty());
    assert!(aces(&transform(
        &acl(2, &[basic(0, OI | CI, 0, &Sid::everyone())]),
        true
    ))
    .is_empty());
}

#[test]
fn audit_and_alarm_keep_system_security_while_access_aces_remove_it() {
    for kind in 0..=3 {
        let result = transform(
            &acl(
                2,
                &[basic(
                    kind,
                    OI | 0xc0,
                    ACCESS_SYSTEM_SECURITY | 1,
                    &Sid::everyone(),
                )],
            ),
            false,
        );
        let entry = aces(&result)[0];
        assert_eq!(
            ace_mask(entry),
            if kind >= 2 {
                ACCESS_SYSTEM_SECURITY | 1
            } else {
                1
            }
        );
        assert_eq!(entry[1], INHERITED | 0xc0);
    }
    for kind in 5..=8 {
        let result = transform(
            &acl(
                4,
                &[object(
                    kind,
                    OI | 0xc0,
                    ACCESS_SYSTEM_SECURITY | 1,
                    &Sid::everyone(),
                    None,
                    None,
                )],
            ),
            false,
        );
        assert_eq!(
            ace_mask(aces(&result)[0]),
            if kind >= 7 {
                ACCESS_SYSTEM_SECURITY | 1
            } else {
                1
            }
        );
    }
}

#[test]
fn object_guid_filter_controls_effective_ace_but_preserves_container_propagation() {
    let expected = [7; 16];
    let original = object(5, OI | CI, 1, &Sid::everyone(), None, Some(expected));
    for container in [false, true] {
        for supplied in [None, Some([8; 16])] {
            let result = inherit_native_acl(
                &acl(4, &[original.clone()]),
                &NativeAclInheritance {
                    is_container: container,
                    auto_inherit: true,
                    owner: &Sid::local_system(),
                    group: &Sid::administrators(),
                    server_owner: None,
                    server_group: None,
                    mapping: &mapping(),
                    object_type: supplied.as_ref(),
                },
            )
            .unwrap();
            let entries = aces(&result);
            assert_eq!(entries.len(), usize::from(container));
            if container {
                assert_eq!(entries[0][1], OI | CI | IO | INHERITED);
                assert_eq!(&entries[0][12..28], expected);
            }
        }
    }
}

#[test]
fn matching_leaf_guid_is_removed_and_object_only_inheritance_converts_to_base_type() {
    for kind in 5..=8 {
        for object_guid in [None, Some([3; 16])] {
            let required = [7; 16];
            let parent = acl(
                4,
                &[object(
                    kind,
                    OI,
                    1,
                    &Sid::everyone(),
                    object_guid,
                    Some(required),
                )],
            );
            let result = inherit_native_acl(
                &parent,
                &NativeAclInheritance {
                    is_container: false,
                    auto_inherit: true,
                    owner: &Sid::local_system(),
                    group: &Sid::administrators(),
                    server_owner: None,
                    server_group: None,
                    mapping: &mapping(),
                    object_type: Some(&required),
                },
            )
            .unwrap();
            assert_eq!(result.as_bytes()[0], 4);
            let entry = aces(&result)[0];
            assert_eq!(
                entry[0],
                if object_guid.is_some() {
                    kind
                } else {
                    kind - 5
                }
            );
            assert_eq!(entry[1], INHERITED);
            if let Some(guid) = object_guid {
                assert_eq!(&entry[8..12], 1u32.to_le_bytes());
                assert_eq!(&entry[12..28], guid);
                assert_eq!(&entry[28..], sid(&Sid::everyone()));
            } else {
                assert_eq!(&entry[8..], sid(&Sid::everyone()));
            }
        }
    }
}

#[test]
fn matching_container_guid_remains_on_merged_unmapped_ace() {
    let required = [7; 16];
    let original = object(
        5,
        OI | CI,
        1,
        &Sid::everyone(),
        Some([3; 16]),
        Some(required),
    );
    let result = inherit_native_acl(
        &acl(4, &[original.clone()]),
        &NativeAclInheritance {
            is_container: true,
            auto_inherit: true,
            owner: &Sid::local_system(),
            group: &Sid::administrators(),
            server_owner: None,
            server_group: None,
            mapping: &mapping(),
            object_type: Some(&required),
        },
    )
    .unwrap();
    assert_eq!(aces(&result).len(), 1);
    let mut expected = original;
    expected[1] |= INHERITED;
    assert_eq!(aces(&result)[0], expected);
}

#[test]
fn matching_container_guid_is_removed_only_from_mapped_effective_half() {
    for object_guid in [None, Some([3; 16])] {
        let required = [7; 16];
        let original = object(
            5,
            OI | CI,
            GENERIC_ALL,
            &Sid::creator_owner(),
            object_guid,
            Some(required),
        );
        let result = inherit_native_acl(
            &acl(4, &[original.clone()]),
            &NativeAclInheritance {
                is_container: true,
                auto_inherit: true,
                owner: &Sid::local_system(),
                group: &Sid::administrators(),
                server_owner: None,
                server_group: None,
                mapping: &mapping(),
                object_type: Some(&required),
            },
        )
        .unwrap();
        let entries = aces(&result);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0][0], if object_guid.is_some() { 5 } else { 0 });
        assert_eq!(entries[0][1], INHERITED);
        assert_eq!(ace_mask(entries[0]), 7);
        let mut propagation = original;
        propagation[1] |= IO | INHERITED;
        assert_eq!(entries[1], propagation);
    }
}

#[test]
fn compound_replaces_both_sids_and_keeps_original_propagation_payload() {
    let original = compound(CI | OI, 1, &Sid::new(3, &[2]), &Sid::new(3, &[1]));
    let server = Sid::local_account(5, 6);
    let group = Sid::administrators();
    let result = inherit_native_acl(
        &acl(3, &[original.clone()]),
        &NativeAclInheritance {
            is_container: true,
            auto_inherit: true,
            owner: &Sid::local_system(),
            group: &group,
            server_owner: Some(&server),
            server_group: None,
            mapping: &mapping(),
            object_type: None,
        },
    )
    .unwrap();
    let entries = aces(&result);
    assert_eq!(entries.len(), 2);
    let mut payload = sid(&server);
    payload.extend_from_slice(&sid(&group));
    assert_eq!(&entries[0][12..], payload);
    assert_eq!(entries[0][0], 4);
    let mut propagation = original;
    propagation[1] |= IO | INHERITED;
    assert_eq!(entries[1], propagation);
}

#[test]
fn compound_client_creator_owner_and_server_creator_group_use_child_roles() {
    let result = transform(
        &acl(
            3,
            &[compound(OI, 1, &Sid::new(3, &[1]), &Sid::creator_owner())],
        ),
        false,
    );
    let mut expected = sid(&Sid::administrators());
    expected.extend_from_slice(&sid(&Sid::local_system()));
    assert_eq!(&aces(&result)[0][12..], expected);
}

#[test]
fn trailing_payload_and_original_ace_order_are_preserved() {
    let mut first = basic(1, CI, GENERIC_ALL, &Sid::creator_owner());
    first.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let size = first.len() as u16;
    first[2..4].copy_from_slice(&size.to_le_bytes());
    let second = basic(0, CI, 2, &Sid::everyone());
    let parent = acl(2, &[first, second]);
    let before = parent.clone();
    let result = transform(&parent, true);
    assert_eq!(parent, before);
    let entries = aces(&result);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0][0], 1);
    assert_eq!(entries[1][0], 1);
    assert_eq!(entries[2][0], 0);
    for entry in &entries[..2] {
        assert_eq!(&entry[entry.len() - 4..], [0xde, 0xad, 0xbe, 0xef]);
    }
}

#[test]
fn empty_result_remains_concrete_empty_acl_with_parent_revision() {
    let parent = acl(4, &[object(5, 0, 1, &Sid::everyone(), None, None)]);
    let result = transform(&parent, false);
    assert_eq!(result.as_bytes(), [4, 0, 8, 0, 0, 0, 0, 0]);
    assert_eq!(
        transform(&acl(2, &[]), true).as_bytes(),
        [2, 0, 8, 0, 0, 0, 0, 0]
    );
}

#[test]
fn unsupported_types_fail_explicitly_even_when_not_inheritable() {
    for kind in [9, 10, 11, 12, 13, 14, 15, 16, 17, 255] {
        let parent = acl(4, &[vec![kind, 0, 4, 0]]);
        assert_eq!(
            inherit_native_acl(
                &parent,
                &NativeAclInheritance {
                    is_container: true,
                    auto_inherit: true,
                    owner: &Sid::local_system(),
                    group: &Sid::administrators(),
                    server_owner: None,
                    server_group: None,
                    mapping: &mapping(),
                    object_type: None,
                }
            ),
            Err(STATUS_NOT_SUPPORTED)
        );
    }
}

#[test]
fn compound_and_audit_object_payloads_are_validated_beyond_native_storage_header() {
    let options = NativeAclInheritance {
        is_container: true,
        auto_inherit: true,
        owner: &Sid::local_system(),
        group: &Sid::administrators(),
        server_owner: None,
        server_group: None,
        mapping: &mapping(),
        object_type: None,
    };
    for kind in [4, 7, 8] {
        assert_eq!(
            inherit_native_acl(&acl(4, &[vec![kind, CI, 4, 0]]), &options),
            Err(STATUS_INVALID_ACL)
        );
    }
    for kind in [7, 8] {
        let mut bad = object(kind, CI, 1, &Sid::everyone(), None, None);
        bad[12] = 2;
        assert_eq!(
            inherit_native_acl(&acl(4, &[bad]), &options),
            Err(STATUS_INVALID_ACL)
        );
        let bad_revision = object(kind, CI, 1, &Sid::everyone(), None, None);
        assert_eq!(
            inherit_native_acl(&acl(2, &[bad_revision]), &options),
            Err(STATUS_INVALID_ACL)
        );
        let mut truncated_guid = vec![kind, CI, 12, 0, 1, 0, 0, 0];
        truncated_guid.extend_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            inherit_native_acl(&acl(4, &[truncated_guid]), &options),
            Err(STATUS_INVALID_ACL)
        );
        let mut flags = object(kind, CI, 1, &Sid::everyone(), None, None);
        flags[8] = 4;
        assert_eq!(
            inherit_native_acl(&acl(4, &[flags]), &options),
            Err(STATUS_NOT_SUPPORTED)
        );
    }
    let mut bad_compound = compound(CI, 1, &Sid::everyone(), &Sid::everyone());
    bad_compound[24] = 2;
    assert_eq!(
        inherit_native_acl(&acl(3, &[bad_compound]), &options),
        Err(STATUS_INVALID_ACL)
    );
    let mut unknown_compound = compound(CI, 1, &Sid::everyone(), &Sid::everyone());
    unknown_compound[8] = 2;
    assert_eq!(
        inherit_native_acl(&acl(3, &[unknown_compound]), &options),
        Err(STATUS_NOT_SUPPORTED)
    );
    assert_eq!(
        inherit_native_acl(
            &acl(2, &[compound(CI, 1, &Sid::everyone(), &Sid::everyone())]),
            &options
        ),
        Err(STATUS_INVALID_ACL)
    );
}

#[test]
fn expansion_cannot_overflow_native_acl_size_or_mutate_parent() {
    let mut huge = basic(0, CI, GENERIC_ALL, &Sid::creator_owner());
    huge.resize(32760, 0);
    huge[2..4].copy_from_slice(&32760u16.to_le_bytes());
    let parent = acl(2, &[huge]);
    let before = parent.clone();
    let owner = Sid::new(5, &[1; 15]);
    assert_eq!(
        inherit_native_acl(
            &parent,
            &NativeAclInheritance {
                is_container: true,
                auto_inherit: true,
                owner: &owner,
                group: &Sid::administrators(),
                server_owner: None,
                server_group: None,
                mapping: &mapping(),
                object_type: None,
            }
        ),
        Err(STATUS_BAD_INHERITANCE_ACL)
    );
    assert_eq!(parent, before);
}

#[test]
fn invalid_child_and_server_sids_fail_before_inheritance() {
    let mut invalid = Sid::everyone();
    invalid.revision = 2;
    let owner = Sid::local_system();
    let group = Sid::administrators();
    for index in 0..4 {
        assert_eq!(
            inherit_native_acl(
                &acl(2, &[]),
                &NativeAclInheritance {
                    is_container: true,
                    auto_inherit: true,
                    owner: if index == 0 { &invalid } else { &owner },
                    group: if index == 1 { &invalid } else { &group },
                    server_owner: (index == 2).then_some(&invalid),
                    server_group: (index == 3).then_some(&invalid),
                    mapping: &mapping(),
                    object_type: None,
                }
            ),
            Err(STATUS_INVALID_SID)
        );
    }
}
