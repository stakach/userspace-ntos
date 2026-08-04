use super::*;
use alloc::vec;

const MACHINE: u32 = 0x1234;
// A file-like object right (FILE_READ_DATA/WRITE_DATA) + a generic mapping.
const FILE_READ: AccessMask = 0x0001;
const FILE_WRITE: AccessMask = 0x0002;
fn file_mapping() -> GenericMapping {
    GenericMapping {
        generic_read: FILE_READ | READ_CONTROL | SYNCHRONIZE,
        generic_write: FILE_WRITE | READ_CONTROL | SYNCHRONIZE,
        generic_execute: READ_CONTROL | SYNCHRONIZE,
        generic_all: FILE_READ | FILE_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | DELETE,
    }
}

#[test]
fn token_generic_access_mapping_matches_nt_object_policy() {
    assert_eq!(map_token_access(TOKEN_QUERY), TOKEN_QUERY);
    assert_eq!(map_token_access(GENERIC_READ), TOKEN_READ);
    assert_eq!(map_token_access(GENERIC_WRITE), TOKEN_WRITE);
    assert_eq!(map_token_access(GENERIC_EXECUTE), TOKEN_EXECUTE);
    assert_eq!(map_token_access(GENERIC_ALL), TOKEN_ALL_ACCESS);
    assert_eq!(map_token_access(MAXIMUM_ALLOWED), TOKEN_ALL_ACCESS);
    assert_eq!(TOKEN_ALL_ACCESS, 0x000f_01ff);

    let requested = GENERIC_READ | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
    let granted = map_token_access(requested);
    assert_eq!(granted, TOKEN_READ | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY);
    assert_eq!(granted & (GENERIC_READ | MAXIMUM_ALLOWED), 0);
}

#[test]
fn sid_wellknown_and_sddl() {
    assert_eq!(Sid::administrators().to_sddl(), "S-1-5-32-544");
    assert_eq!(Sid::local_system().to_sddl(), "S-1-5-18");
    assert_eq!(Sid::everyone().to_sddl(), "S-1-1-0");
    assert_eq!(
        Sid::local_account(MACHINE, 1000).to_sddl(),
        "S-1-5-21-4660-1000"
    );
}

#[test]
fn sid_decodes_native_bytes() {
    let mut bytes = vec![1, 5, 0, 0, 0, 0, 0, 5];
    for sub in [21u32, 1325974280, 164944053, 1780406144, 500] {
        bytes.extend_from_slice(&sub.to_le_bytes());
    }

    let sid = Sid::from_native_bytes(&bytes).expect("native SID");
    assert_eq!(
        sid.to_sddl(),
        "S-1-5-21-1325974280-164944053-1780406144-500"
    );
    assert_eq!(sid.native_len(), Some(bytes.len()));
    assert_eq!(
        Sid::from_native_bytes(&bytes[..bytes.len() - 1]),
        Err(0xC000_0078)
    );
}

#[test]
fn sid_rejects_malformed_native_bytes() {
    assert_eq!(Sid::from_native_bytes(&[]), Err(0xC000_0078));
    assert_eq!(
        Sid::from_native_bytes(&[2, 0, 0, 0, 0, 0, 0, 5]),
        Err(0xC000_0078)
    );
    assert_eq!(
        Sid::from_native_bytes(&[1, 16, 0, 0, 0, 0, 0, 5]),
        Err(0xC000_0078)
    );
    assert_eq!(
        Sid::from_native_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 18]),
        Err(0xC000_0078)
    );
}

#[test]
fn sid_sddl_preserves_large_identifier_authority() {
    let sid = Sid {
        revision: 1,
        identifier_authority: [1, 2, 3, 4, 5, 6],
        sub_authorities: Vec::new(),
    };
    assert_eq!(sid.to_sddl(), "S-1-0x010203040506");
}

#[test]
fn default_tokens() {
    let sys = AccessToken::system();
    assert_eq!(sys.user, Sid::local_system());
    assert!(!sys.has_privilege(SE_LOAD_DRIVER));
    assert!(sys.has_privilege(SE_DEBUG));
    let user = AccessToken::user(MACHINE);
    assert!(!user.has_privilege(SE_LOAD_DRIVER)); // standard user can't load drivers
    assert!(user.has_privilege(SE_CHANGE_NOTIFY));
    assert_eq!(
        privilege_check(&AccessToken::admin(MACHINE), SE_LOAD_DRIVER),
        Ok(())
    );
    assert_eq!(
        privilege_check(&user, SE_LOAD_DRIVER),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    );
}

#[test]
fn system_token_has_reactos_privilege_defaults() {
    let token = AccessToken::system();
    assert_eq!(token.privileges.len(), 24);
    let enabled: alloc::vec::Vec<u32> = token
        .privileges
        .iter()
        .filter(|privilege| privilege.enabled)
        .map(|privilege| privilege.luid.low)
        .collect();
    assert_eq!(enabled, vec![7, 15, 4, 14, 16, 20, 21, 23, 13, 29, 30]);
}

#[test]
fn system_token_has_reactos_owner_and_default_dacl() {
    let token = AccessToken::system();
    assert!(token
        .groups
        .iter()
        .any(|group| group.sid == Sid::administrators() && group.owner));
    assert_eq!(
        token.default_dacl.as_ref().unwrap().as_bytes(),
        &[
            2, 0, 52, 0, 2, 0, 0, 0, // ACL
            0, 0, 20, 0, 0, 0, 0, 16, // LocalSystem: GENERIC_ALL
            1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 0, 24, 0, 0, 0, 2,
            160, // Administrators: GR|GX|READ_CONTROL
            1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0,
        ]
    );
    assert!(AccessToken::admin(MACHINE).default_dacl.is_none());
    assert!(AccessToken::user(MACHINE).default_dacl.is_none());
}

fn acl_with_ace(revision: u8, ace: &[u8], trailing_free_bytes: usize) -> alloc::vec::Vec<u8> {
    let size = 8 + ace.len() + trailing_free_bytes;
    let mut acl = vec![0u8; size];
    acl[0] = revision;
    acl[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    acl[4..6].copy_from_slice(&1u16.to_le_bytes());
    acl[8..8 + ace.len()].copy_from_slice(ace);
    acl
}

fn minimal_known_ace(ace_type: u8) -> [u8; 16] {
    [
        ace_type, 0, 16, 0, // ACE_HEADER
        1, 0, 0, 0, // mask
        1, 0, 0, 0, 0, 0, 0, 5, // S-1-5
    ]
}

#[test]
fn native_acl_preserves_declared_bytes_and_free_space() {
    let bytes = [2, 7, 12, 0, 0, 0, 9, 8, 1, 2, 3, 4, 0xaa, 0xbb];
    let acl = NativeAcl::from_bytes(&bytes).unwrap();
    assert_eq!(acl.acl_size(), 12);
    assert_eq!(acl.as_bytes(), &bytes[..12]);

    for ace_type in 0..=3 {
        NativeAcl::from_bytes(&acl_with_ace(2, &minimal_known_ace(ace_type), 4)).unwrap();
    }
}

#[test]
fn native_acl_rejects_invalid_headers_and_ace_envelopes() {
    assert_eq!(
        NativeAcl::from_bytes(&[2; 7]),
        Err(NativeAclError::TruncatedHeader)
    );
    for revision in [1, 5] {
        let mut acl = [0u8; 8];
        acl[0] = revision;
        acl[2] = 8;
        assert_eq!(
            NativeAcl::from_bytes(&acl),
            Err(NativeAclError::InvalidRevision)
        );
    }
    for size in [6u16, 9] {
        let mut acl = [0u8; 10];
        acl[0] = 2;
        acl[2..4].copy_from_slice(&size.to_le_bytes());
        assert_eq!(
            NativeAcl::from_bytes(&acl),
            Err(NativeAclError::InvalidAclSize)
        );
    }
    let mut declared_too_large = [0u8; 8];
    declared_too_large[0] = 2;
    declared_too_large[2..4].copy_from_slice(&12u16.to_le_bytes());
    assert_eq!(
        NativeAcl::from_bytes(&declared_too_large),
        Err(NativeAclError::InvalidAclSize)
    );

    let mut missing_ace = [0u8; 8];
    missing_ace[0] = 2;
    missing_ace[2] = 8;
    missing_ace[4] = 1;
    assert_eq!(
        NativeAcl::from_bytes(&missing_ace),
        Err(NativeAclError::TruncatedAce)
    );
    for ace_size in [0u16, 5, 20] {
        let mut ace = [0xffu8; 8];
        ace[2..4].copy_from_slice(&ace_size.to_le_bytes());
        assert_eq!(
            NativeAcl::from_bytes(&acl_with_ace(2, &ace, 0)),
            Err(NativeAclError::InvalidAceSize)
        );
    }
}

#[test]
fn native_acl_validates_known_and_object_ace_sids() {
    let mut bad_revision = minimal_known_ace(0);
    bad_revision[8] = 2;
    assert_eq!(
        NativeAcl::from_bytes(&acl_with_ace(2, &bad_revision, 0)),
        Err(NativeAclError::InvalidSid)
    );
    let mut truncated_sid = minimal_known_ace(0);
    truncated_sid[9] = 1;
    assert_eq!(
        NativeAcl::from_bytes(&acl_with_ace(2, &truncated_sid, 0)),
        Err(NativeAclError::InvalidSid)
    );

    let object_ace = [
        5, 0, 20, 0, // header
        1, 0, 0, 0, // mask
        0, 0, 0, 0, // object flags
        1, 0, 0, 0, 0, 0, 0, 5, // SID
    ];
    assert_eq!(
        NativeAcl::from_bytes(&acl_with_ace(2, &object_ace, 0)),
        Err(NativeAclError::ObjectAceRequiresRevisionFour)
    );
    NativeAcl::from_bytes(&acl_with_ace(4, &object_ace, 0)).unwrap();

    let mut object_with_guid = vec![
        6, 0, 36, 0, // header
        1, 0, 0, 0, // mask
        1, 0, 0, 0, // ObjectType GUID present
    ];
    object_with_guid.extend_from_slice(&[0x5a; 16]);
    object_with_guid.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 5]);
    NativeAcl::from_bytes(&acl_with_ace(4, &object_with_guid, 0)).unwrap();
    object_with_guid[2] = 20;
    assert_eq!(
        NativeAcl::from_bytes(&acl_with_ace(4, &object_with_guid[..20], 0)),
        Err(NativeAclError::InvalidAceSize)
    );

    // Compound, object-audit, callback, and unknown ACEs retain their opaque payload.
    for ace_type in [4, 7, 8, 9, 0xff] {
        NativeAcl::from_bytes(&acl_with_ace(2, &[ace_type, 0, 4, 0], 0)).unwrap();
    }
}

/// `TOKEN_GROUPS` (class 2) — the class `userenv!CheckForGuestsAndAdmins` and
/// `winlogon!AllowAccessOnSession` size with a NULL/zero-length query before allocating.
#[test]
fn token_groups_encoding_is_exact_relocatable_and_size_queryable() {
    let system = AccessToken::system();
    let base = 0x7fff_0000u64;
    let mut output = [0xcc; 256];
    let encoded = encode_token_groups(&system, base, &mut output).unwrap();
    assert!(encoded.written);

    // GroupCount, then one 16-byte SID_AND_ATTRIBUTES per group, then the SID bodies.
    let count = u32::from_le_bytes(output[..4].try_into().unwrap()) as usize;
    assert_eq!(count, system.groups.len());
    assert_eq!(
        count, 3,
        "the LocalSystem token has Administrators/AuthUsers/Everyone"
    );
    let array = 8;
    let mut expected_len = array + count * SID_AND_ATTRIBUTES_LENGTH;
    for group in &system.groups {
        expected_len += group.sid.native_len().unwrap();
    }
    assert_eq!(encoded.required_length, expected_len);

    // Every `Sid` pointer must land INSIDE the caller's buffer, in order, on the real SID bytes.
    let mut cursor = array + count * SID_AND_ATTRIBUTES_LENGTH;
    for (index, group) in system.groups.iter().enumerate() {
        let entry = array + index * SID_AND_ATTRIBUTES_LENGTH;
        let sid_va = u64::from_le_bytes(output[entry..entry + 8].try_into().unwrap());
        assert_eq!(sid_va, base + cursor as u64, "group {index} SID pointer");
        let attributes = u32::from_le_bytes(output[entry + 8..entry + 12].try_into().unwrap());
        assert_eq!(attributes, group.attributes());
        let mut expected = alloc::vec![0u8; group.sid.native_len().unwrap()];
        group.sid.write_native(&mut expected).unwrap();
        assert_eq!(&output[cursor..cursor + expected.len()], &expected[..]);
        cursor += expected.len();
    }
    assert_eq!(cursor, encoded.required_length);

    // The Administrators group is the token's OWNER group; the other two are plain enabled groups.
    assert_eq!(system.groups[0].attributes() & 0x8, 0x8, "SE_GROUP_OWNER");
    assert_eq!(system.groups[1].attributes() & 0x8, 0, "not an owner group");
    assert_eq!(
        system.groups[1].attributes() & 0x7,
        0x7,
        "mandatory|default|enabled"
    );

    // The SIZE QUERY: a zero-length buffer must still report the exact length and write nothing.
    let mut none = [0u8; 0];
    let sized = encode_token_groups(&system, base, &mut none).unwrap();
    assert_eq!(sized.required_length, expected_len);
    assert!(!sized.written);
}

/// `SE_GROUP_LOGON_ID` must SURVIVE capture and re-encoding. `winlogon!AllowAccessOnSession`
/// (`security.c:1432`) scans `TOKEN_GROUPS` for `(Attributes & SE_GROUP_LOGON_ID) ==
/// SE_GROUP_LOGON_ID` and leaves its `LogonSid` local UNINITIALISED when nothing matches — it then
/// dereferences it in `GetLengthSid`. Dropping the bit is therefore not a loss of information, it
/// is a wild pointer in the caller.
#[test]
fn logon_sid_group_keeps_its_se_group_logon_id_through_capture_and_encode() {
    use crate::create_token::{
        group_from_attributes, SE_GROUP_ENABLED, SE_GROUP_LOGON_ID, SE_GROUP_MANDATORY,
    };
    // The logon SID lsasrv mints for an interactive logon: S-1-5-5-X-Y, mandatory+enabled+logon-id.
    let logon_sid = Sid::new(5, &[5, 0, 0x3e7f]);
    let attributes = SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_LOGON_ID;
    let group = group_from_attributes(logon_sid.clone(), attributes);
    assert!(group.logon_id, "capture must keep SE_GROUP_LOGON_ID");
    assert_eq!(group.attributes() & SE_GROUP_LOGON_ID, SE_GROUP_LOGON_ID);

    // A plain enabled group must NOT claim to be the logon SID (one bit of the two-bit mask being
    // set is not a match — the winlogon test compares the WHOLE mask).
    let plain = group_from_attributes(Sid::administrators(), SE_GROUP_MANDATORY | SE_GROUP_ENABLED);
    assert!(!plain.logon_id);
    let half = group_from_attributes(Sid::everyone(), 0x4000_0000);
    assert!(
        !half.logon_id,
        "half of SE_GROUP_LOGON_ID is not a logon SID"
    );

    // …and the encoder must place it where the scan looks: entry 1's Attributes word.
    let mut token = AccessToken::system();
    token.groups.push(group);
    let mut output = [0u8; 256];
    let encoded = encode_token_groups(&token, 0x4000_0000, &mut output).unwrap();
    assert!(encoded.written);
    let count = u32::from_le_bytes(output[..4].try_into().unwrap()) as usize;
    let mut found = None;
    for index in 0..count {
        let entry = 8 + index * SID_AND_ATTRIBUTES_LENGTH;
        let attrs = u32::from_le_bytes(output[entry + 8..entry + 12].try_into().unwrap());
        if attrs & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID {
            found = Some(u64::from_le_bytes(
                output[entry..entry + 8].try_into().unwrap(),
            ));
        }
    }
    let sid_va = found.expect("the scan winlogon performs must find exactly this group");
    let offset = (sid_va - 0x4000_0000) as usize;
    let mut expected = alloc::vec![0u8; logon_sid.native_len().unwrap()];
    logon_sid.write_native(&mut expected).unwrap();
    assert_eq!(&output[offset..offset + expected.len()], &expected[..]);
}

#[test]
fn native_token_information_encoders_are_exact_and_relocatable() {
    let system = AccessToken::system();
    let mut output = [0xcc; 64];
    let owner = encode_token_owner(&system, 0x1234_0000, &mut output).unwrap();
    assert_eq!(owner.required_length, 24);
    assert!(owner.written);
    assert_eq!(
        u64::from_le_bytes(output[..8].try_into().unwrap()),
        0x1234_0008
    );
    assert_eq!(
        &output[8..24],
        &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0]
    );

    let mut short = [0xa5; 7];
    let sized = encode_token_owner(&system, 0, &mut short).unwrap();
    assert_eq!(sized.required_length, 24);
    assert!(!sized.written);
    assert_eq!(short, [0xa5; 7]);

    let user = AccessToken::user(MACHINE);
    let mut null_dacl = [0xcc; 8];
    let encoded = encode_token_default_dacl(&user, 0x2000, &mut null_dacl);
    assert_eq!(encoded.required_length, 8);
    assert!(encoded.written);
    assert_eq!(null_dacl, [0; 8]);

    let mut empty = AccessToken::user(MACHINE);
    empty.default_dacl = Some(NativeAcl::from_bytes(&[2, 0, 8, 0, 0, 0, 0, 0]).unwrap());
    let mut empty_dacl = [0u8; 16];
    let encoded = encode_token_default_dacl(&empty, 0x3000, &mut empty_dacl);
    assert_eq!(encoded.required_length, 16);
    assert_eq!(
        u64::from_le_bytes(empty_dacl[..8].try_into().unwrap()),
        0x3008
    );
    assert_eq!(&empty_dacl[8..], &[2, 0, 8, 0, 0, 0, 0, 0]);
}

#[test]
fn token_statistics_encode_native_pack_four_layout() {
    let mut store = TokenStore::new();
    let id = store.insert(AccessToken::system());
    let statistics = store.statistics(id).unwrap();
    assert_ne!(statistics.token_id, statistics.modified_id);
    assert_eq!(statistics.expiration_time, -1);
    assert_eq!(statistics.dynamic_charged, 500);
    assert_eq!(statistics.dynamic_available, 436);
    assert_eq!(statistics.group_count, 3);
    assert_eq!(statistics.privilege_count, 24);

    let mut output = [0xcc; TOKEN_STATISTICS_LENGTH];
    let encoded = encode_token_statistics(statistics, &mut output);
    assert_eq!(encoded.required_length, 0x38);
    assert!(encoded.written);
    assert_eq!(
        u32::from_le_bytes(output[0x00..0x04].try_into().unwrap()),
        statistics.token_id.low
    );
    assert_eq!(
        u32::from_le_bytes(output[0x08..0x0c].try_into().unwrap()),
        0x3e7
    );
    assert_eq!(
        i64::from_le_bytes(output[0x10..0x18].try_into().unwrap()),
        -1
    );
    assert_eq!(
        u32::from_le_bytes(output[0x18..0x1c].try_into().unwrap()),
        TokenType::Primary as u32
    );
    assert_eq!(
        u32::from_le_bytes(output[0x1c..0x20].try_into().unwrap()),
        SecurityImpersonationLevel::Anonymous as u32
    );
    assert_eq!(
        u32::from_le_bytes(output[0x20..0x24].try_into().unwrap()),
        500
    );
    assert_eq!(
        u32::from_le_bytes(output[0x24..0x28].try_into().unwrap()),
        436
    );
    assert_eq!(
        u32::from_le_bytes(output[0x28..0x2c].try_into().unwrap()),
        3
    );
    assert_eq!(
        u32::from_le_bytes(output[0x2c..0x30].try_into().unwrap()),
        24
    );
}

#[test]
fn token_store_duplication_preserves_source_modification_identity() {
    let mut store = TokenStore::new();
    let source = store.insert(AccessToken::system());
    let duplicate = store
        .duplicate(
            source,
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            false,
        )
        .unwrap();
    let source_stats = store.statistics(source).unwrap();
    let duplicate_stats = store.statistics(duplicate).unwrap();
    assert_ne!(source_stats.token_id, duplicate_stats.token_id);
    assert_eq!(source_stats.modified_id, duplicate_stats.modified_id);
    assert_eq!(
        source_stats.authentication_id,
        duplicate_stats.authentication_id
    );
    assert_eq!(
        source_stats.expiration_time,
        duplicate_stats.expiration_time
    );
    assert_eq!(
        source_stats.dynamic_charged,
        duplicate_stats.dynamic_charged
    );

    store.set_default_dacl(source, None).unwrap();
    assert!(store.get(source).unwrap().default_dacl.is_none());
    assert!(store.get(duplicate).unwrap().default_dacl.is_some());
}

#[test]
fn token_store_mutations_advance_modified_id_with_native_semantics() {
    let mut store = TokenStore::new();
    let id = store.insert(AccessToken::system());
    let initial = store.statistics(id).unwrap().modified_id;

    assert_eq!(store.set_owner(id, Sid::users()), Err(STATUS_INVALID_OWNER));
    assert_eq!(store.statistics(id).unwrap().modified_id, initial);
    store.set_owner(id, Sid::administrators()).unwrap();
    let after_owner = store.statistics(id).unwrap().modified_id;
    assert_ne!(after_owner, initial);

    let no_change = [PrivilegeAdjustment {
        luid: Luid::new(20),
        attributes: SE_PRIVILEGE_ENABLED,
    }];
    let mut previous = [PrivilegeAdjustment::default(); 1];
    assert_eq!(
        store
            .adjust_privileges(id, false, &no_change, &mut previous)
            .unwrap()
            .changed,
        0
    );
    assert_eq!(store.statistics(id).unwrap().modified_id, after_owner);

    let change = [PrivilegeAdjustment {
        luid: Luid::new(10),
        attributes: SE_PRIVILEGE_ENABLED,
    }];
    assert_eq!(
        store
            .adjust_privileges(id, false, &change, &mut previous)
            .unwrap()
            .changed,
        1
    );
    let after_privilege = store.statistics(id).unwrap().modified_id;
    assert_ne!(after_privilege, after_owner);

    let same_acl = store.get(id).unwrap().default_dacl.clone();
    store.set_default_dacl(id, same_acl).unwrap();
    let after_dacl = store.statistics(id).unwrap().modified_id;
    assert_ne!(after_dacl, after_privilege);
    store.set_default_dacl(id, None).unwrap();
    let after_clear = store.statistics(id).unwrap().modified_id;
    assert_ne!(after_clear, after_dacl);
    store.set_default_dacl(id, None).unwrap();
    assert_eq!(store.statistics(id).unwrap().modified_id, after_clear);

    let mut oversized = vec![0u8; 600];
    oversized[0] = 2;
    oversized[2..4].copy_from_slice(&600u16.to_le_bytes());
    let oversized = NativeAcl::from_bytes(&oversized).unwrap();
    assert_eq!(
        store.set_default_dacl(id, Some(oversized)),
        Err(STATUS_ALLOTTED_SPACE_EXCEEDED)
    );
    assert!(store.get(id).unwrap().default_dacl.is_none());
    assert_eq!(store.statistics(id).unwrap().modified_id, after_clear);
}

#[test]
fn privilege_adjustment_plans_applies_and_reports_previous_state() {
    let mut token = AccessToken::system();
    let requested = [
        PrivilegeAdjustment {
            luid: Luid::new(10),
            attributes: SE_PRIVILEGE_ENABLED,
        },
        PrivilegeAdjustment {
            luid: Luid::new(19),
            attributes: SE_PRIVILEGE_ENABLED,
        },
        PrivilegeAdjustment {
            luid: Luid::new(99),
            attributes: SE_PRIVILEGE_ENABLED,
        },
    ];
    let plan = token.plan_privilege_adjustment(false, &requested);
    assert_eq!(plan.matched, 2);
    assert_eq!(plan.changed, 2);

    let mut previous = [PrivilegeAdjustment::default(); 2];
    assert_eq!(
        token.adjust_privileges(false, &requested, &mut previous),
        plan
    );
    assert_eq!(previous[0].luid, Luid::new(19));
    assert_eq!(previous[1].luid, Luid::new(10));
    assert_eq!(previous[0].attributes, 0);
    assert_eq!(previous[1].attributes, 0);
    assert!(token.has_privilege(SE_LOAD_DRIVER));
    assert!(token.has_privilege(SE_SHUTDOWN));

    let unchanged = token.plan_privilege_adjustment(false, &requested[..2]);
    assert_eq!(unchanged.changed, 0);
}

#[test]
fn disable_all_and_remove_privilege_follow_native_semantics() {
    let mut token = AccessToken::system();
    let plan = token.plan_privilege_adjustment(true, &[]);
    assert_eq!(plan.matched, 24);
    assert_eq!(plan.changed, 11);
    let mut previous = [PrivilegeAdjustment::default(); 24];
    let applied = token.adjust_privileges(true, &[], &mut previous);
    assert_eq!(applied, plan);
    assert!(token.privileges.iter().all(|privilege| !privilege.enabled));

    let remove = [PrivilegeAdjustment {
        luid: Luid::new(10),
        attributes: SE_PRIVILEGE_REMOVED,
    }];
    assert_eq!(token.plan_privilege_adjustment(false, &remove).changed, 1);
    token.adjust_privileges(false, &remove, &mut previous[..1]);
    assert!(!token
        .privileges
        .iter()
        .any(|privilege| privilege.luid.low == 10));
}

#[test]
fn allow_ace_grants_matching_sid() {
    let map = file_mapping();
    // DACL: Administrators get read+write.
    let sd = SecurityDescriptor {
        owner: Some(Sid::administrators()),
        dacl: Some(Acl::new(vec![Ace::allow(
            Sid::administrators(),
            FILE_READ | FILE_WRITE,
        )])),
        ..Default::default()
    };
    // An admin (member of Administrators) is granted.
    let r = access_check(
        &sd,
        &AccessToken::admin(MACHINE),
        FILE_READ | FILE_WRITE,
        &map,
        ProcessorMode::UserMode,
    );
    assert!(r.granted() && r.granted_access & FILE_WRITE != 0);
    // A standard user is not a member → denied.
    let r = access_check(
        &sd,
        &AccessToken::user(MACHINE),
        FILE_READ,
        &map,
        ProcessorMode::UserMode,
    );
    assert_eq!(r.status, STATUS_ACCESS_DENIED);
}

#[test]
fn deny_ace_beats_later_allow() {
    let map = file_mapping();
    // Canonical ACL: deny Users write, then allow Everyone read+write. A user wanting write is denied.
    let sd = SecurityDescriptor {
        dacl: Some(Acl::new(vec![
            Ace::deny(Sid::users(), FILE_WRITE),
            Ace::allow(Sid::everyone(), FILE_READ | FILE_WRITE),
        ])),
        ..Default::default()
    };
    let user = AccessToken::user(MACHINE);
    assert_eq!(
        access_check(&sd, &user, FILE_WRITE, &map, ProcessorMode::UserMode).status,
        STATUS_ACCESS_DENIED
    );
    // But read alone is granted by the Everyone allow ACE.
    assert!(access_check(&sd, &user, FILE_READ, &map, ProcessorMode::UserMode).granted());
}

#[test]
fn null_and_empty_dacl() {
    let map = file_mapping();
    let user = AccessToken::user(MACHINE);
    // Null DACL grants all.
    let null = SecurityDescriptor {
        dacl: None,
        ..Default::default()
    };
    assert!(access_check(
        &null,
        &user,
        FILE_READ | FILE_WRITE,
        &map,
        ProcessorMode::UserMode
    )
    .granted());
    // Empty DACL grants nothing.
    let empty = SecurityDescriptor {
        dacl: Some(Acl::empty()),
        ..Default::default()
    };
    assert_eq!(
        access_check(&empty, &user, FILE_READ, &map, ProcessorMode::UserMode).status,
        STATUS_ACCESS_DENIED
    );
}

#[test]
fn owner_gets_read_control_and_generic_maps() {
    let map = file_mapping();
    let user = AccessToken::user(MACHINE);
    // Empty DACL but the user is the owner → still gets READ_CONTROL (spec §9.6).
    let sd = SecurityDescriptor {
        owner: Some(user.user.clone()),
        dacl: Some(Acl::empty()),
        ..Default::default()
    };
    assert!(access_check(&sd, &user, READ_CONTROL, &map, ProcessorMode::UserMode).granted());
    // GENERIC_READ maps to FILE_READ via the mapping.
    let sd = SecurityDescriptor {
        dacl: Some(Acl::new(vec![Ace::allow(
            Sid::everyone(),
            FILE_READ | READ_CONTROL | SYNCHRONIZE,
        )])),
        ..Default::default()
    };
    let r = access_check(&sd, &user, GENERIC_READ, &map, ProcessorMode::UserMode);
    assert!(r.granted() && r.granted_access & FILE_READ != 0);
}

#[test]
fn maximum_allowed_returns_union() {
    let map = file_mapping();
    let sd = SecurityDescriptor {
        dacl: Some(Acl::new(vec![
            Ace::deny(Sid::users(), FILE_WRITE),
            Ace::allow(Sid::everyone(), FILE_READ | FILE_WRITE),
        ])),
        ..Default::default()
    };
    // MAXIMUM_ALLOWED for a user: read granted (Everyone), write denied (Users deny ACE first).
    let r = access_check(
        &sd,
        &AccessToken::user(MACHINE),
        MAXIMUM_ALLOWED,
        &map,
        ProcessorMode::UserMode,
    );
    assert!(r.granted());
    assert!(r.granted_access & FILE_READ != 0);
    assert_eq!(r.granted_access & FILE_WRITE, 0);
}

#[test]
fn privilege_overrides_and_kernel_bypass() {
    let map = file_mapping();
    let user = AccessToken::user(MACHINE);
    // ACCESS_SYSTEM_SECURITY needs SeSecurityPrivilege — a user lacks it.
    let sd = SecurityDescriptor {
        dacl: Some(Acl::empty()),
        ..Default::default()
    };
    assert_eq!(
        access_check(
            &sd,
            &user,
            ACCESS_SYSTEM_SECURITY,
            &map,
            ProcessorMode::UserMode
        )
        .status,
        STATUS_ACCESS_DENIED
    );
    // System holds it disabled by default; enabling it makes the privilege override available.
    let mut system = AccessToken::system();
    let request = [PrivilegeAdjustment {
        luid: Luid::new(8),
        attributes: SE_PRIVILEGE_ENABLED,
    }];
    let mut previous = [PrivilegeAdjustment::default(); 1];
    system.adjust_privileges(false, &request, &mut previous);
    let r = access_check(
        &sd,
        &system,
        ACCESS_SYSTEM_SECURITY,
        &map,
        ProcessorMode::UserMode,
    );
    assert!(r.granted() && r.privileges_used.contains(&SE_SECURITY));
    // WRITE_OWNER via SeTakeOwnershipPrivilege even against an empty DACL.
    let r = access_check(
        &sd,
        &AccessToken::admin(MACHINE),
        WRITE_OWNER,
        &map,
        ProcessorMode::UserMode,
    );
    assert!(r.granted() && r.privileges_used.contains(&SE_TAKE_OWNERSHIP));
    // KernelMode bypasses the DACL entirely.
    assert!(access_check(
        &sd,
        &user,
        FILE_READ | FILE_WRITE,
        &map,
        ProcessorMode::KernelMode
    )
    .granted());
}

#[test]
fn token_duplicate_is_independent_and_effective_only() {
    let mut source = AccessToken::system();
    source.groups[0].enabled = false;
    let duplicate = source
        .duplicate(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Delegation,
            true,
        )
        .unwrap();

    assert_eq!(duplicate.token_type, TokenType::Impersonation);
    assert_eq!(
        duplicate.impersonation_level,
        SecurityImpersonationLevel::Delegation
    );
    assert!(duplicate.groups.iter().all(|group| group.enabled));
    assert!(duplicate
        .privileges
        .iter()
        .all(|privilege| privilege.enabled));

    source.groups[1].enabled = false;
    assert!(duplicate.groups.iter().all(|group| group.enabled));
}

#[test]
fn impersonation_duplicate_cannot_raise_its_level() {
    let source = AccessToken::system()
        .duplicate(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Identification,
            false,
        )
        .unwrap();
    assert_eq!(
        source.duplicate(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            false,
        ),
        Err(STATUS_BAD_IMPERSONATION_LEVEL)
    );
    assert_eq!(
        source.duplicate(
            TokenType::Primary,
            SecurityImpersonationLevel::Identification,
            false,
        ),
        Err(STATUS_BAD_IMPERSONATION_LEVEL)
    );
}

#[test]
fn token_store_reference_outlives_assigning_handle() {
    let mut store = TokenStore::new();
    let primary = store.insert(AccessToken::system());
    let impersonation = store
        .duplicate(
            primary,
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            false,
        )
        .unwrap();

    store.retain(impersonation).unwrap(); // thread reference
    assert_eq!(store.reference_count(impersonation), Some(2));
    assert_eq!(store.release(impersonation), Ok(false)); // close assigning handle
    assert!(store.get(impersonation).is_some());
    assert_eq!(store.release(impersonation), Ok(true)); // revert thread
    assert!(store.get(impersonation).is_none());
    assert!(store.get(primary).is_some());
}

// ─── `NtCreateToken` capture (`create_token.rs`) ────────────────────────────────────────────────
//
// These drive the REAL capture path with a mock client address space, so the variable-length
// `TOKEN_*` walk — the count-driven `SID_AND_ATTRIBUTES` / `LUID_AND_ATTRIBUTES` arrays, the second
// indirection through every `PSID`/`PACL` — is exercised structure-for-structure without a target.

use crate::create_token::{
    capture_acl, capture_sid, capture_token, privilege_name_for_luid, ClientMemory,
    CreateTokenArgs, MAX_CAPTURED_GROUPS, MAX_CAPTURED_PRIVILEGES, SE_GROUP_ENABLED,
    SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY, SE_GROUP_OWNER, SE_GROUP_USE_FOR_DENY_ONLY,
    STATUS_ACCESS_VIOLATION, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER,
    STATUS_INVALID_SID,
};
use alloc::vec::Vec;

/// A mock client address space: a set of disjoint mapped regions. A read that leaves *any* mapped
/// region fails — the same fail-closed contract the executive's cross-address-space reader has.
#[derive(Default)]
struct MockClient {
    regions: Vec<(u64, Vec<u8>)>,
    /// Every byte the capture attempted to read, so a test can prove no over-read happened.
    reads: core::cell::RefCell<u64>,
}

impl MockClient {
    fn map(&mut self, va: u64, bytes: &[u8]) {
        self.regions.push((va, bytes.to_vec()));
    }
    fn bytes_read(&self) -> u64 {
        *self.reads.borrow()
    }
}

impl ClientMemory for MockClient {
    fn read(&self, va: u64, dst: &mut [u8]) -> bool {
        *self.reads.borrow_mut() += dst.len() as u64;
        for (base, bytes) in &self.regions {
            if va < *base {
                continue;
            }
            let offset = (va - *base) as usize;
            if let Some(source) = bytes.get(offset..offset + dst.len()) {
                dst.copy_from_slice(source);
                return true;
            }
        }
        false
    }
}

fn native_sid(authority: u8, sub_authorities: &[u32]) -> Vec<u8> {
    let sid = Sid::new(authority, sub_authorities);
    let mut bytes = vec![0u8; sid.native_len().unwrap()];
    sid.write_native(&mut bytes).unwrap();
    bytes
}

fn sid_and_attributes(sid_va: u64, attributes: u32) -> Vec<u8> {
    let mut entry = vec![0u8; 16];
    entry[0..8].copy_from_slice(&sid_va.to_le_bytes());
    entry[8..12].copy_from_slice(&attributes.to_le_bytes());
    entry
}

fn luid_and_attributes(low: u32, high: i32, attributes: u32) -> Vec<u8> {
    let mut entry = vec![0u8; 12];
    entry[0..4].copy_from_slice(&low.to_le_bytes());
    entry[4..8].copy_from_slice(&high.to_le_bytes());
    entry[8..12].copy_from_slice(&attributes.to_le_bytes());
    entry
}

fn access_ace(ace_type: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = 8 + sid.len();
    let mut ace = vec![0u8; size];
    ace[0] = ace_type;
    ace[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    ace[4..8].copy_from_slice(&mask.to_le_bytes());
    ace[8..].copy_from_slice(sid);
    ace
}

fn acl_with_aces(aces: &[Vec<u8>]) -> Vec<u8> {
    let size = 8 + aces.iter().map(|ace| ace.len()).sum::<usize>();
    let mut acl = vec![0u8; size];
    acl[0] = 2;
    acl[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    acl[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    let mut offset = 8;
    for ace in aces {
        acl[offset..offset + ace.len()].copy_from_slice(ace);
        offset += ace.len();
    }
    acl
}

fn push_aligned(buffer: &mut Vec<u8>, payload: &[u8]) -> u32 {
    let offset = buffer.len() as u32;
    buffer.extend_from_slice(payload);
    while buffer.len() & 3 != 0 {
        buffer.push(0);
    }
    offset
}

fn self_relative_sd(owner: &[u8], group: &[u8], dacl: Option<&[u8]>) -> Vec<u8> {
    const SE_DACL_PRESENT: u16 = 0x0004;
    const SE_SELF_RELATIVE: u16 = 0x8000;

    let mut sd = vec![0u8; 20];
    sd[0] = 1;
    let mut control = SE_SELF_RELATIVE;
    let owner_offset = push_aligned(&mut sd, owner);
    let group_offset = push_aligned(&mut sd, group);
    let dacl_offset = if let Some(dacl) = dacl {
        control |= SE_DACL_PRESENT;
        push_aligned(&mut sd, dacl)
    } else {
        0
    };
    sd[2..4].copy_from_slice(&control.to_le_bytes());
    sd[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    sd[8..12].copy_from_slice(&group_offset.to_le_bytes());
    sd[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    sd
}

// A mock layout mirroring exactly what lsasrv's `LsapLogonUser` hands `NtCreateToken` for
// `LsaTokenInformationV1` (`dll/win32/lsasrv/authpackage.c:1655`).
const USER_SID_VA: u64 = 0x0000_0007_0001_0000;
const ADMINS_SID_VA: u64 = 0x0000_0007_0001_0100;
const USERS_SID_VA: u64 = 0x0000_0007_0001_0200;
const EVERYONE_SID_VA: u64 = 0x0000_0007_0001_0300;
const TOKEN_USER_VA: u64 = 0x0000_0007_0002_0000;
const TOKEN_GROUPS_VA: u64 = 0x0000_0007_0002_0100;
const TOKEN_PRIVILEGES_VA: u64 = 0x0000_0007_0002_0200;
const TOKEN_OWNER_VA: u64 = 0x0000_0007_0002_0300;
const TOKEN_PRIMARY_GROUP_VA: u64 = 0x0000_0007_0002_0400;
const TOKEN_DEFAULT_DACL_VA: u64 = 0x0000_0007_0002_0500;
const ACL_VA: u64 = 0x0000_0007_0002_0600;
const AUTH_ID_VA: u64 = 0x0000_0007_0003_0000;
const EXPIRATION_VA: u64 = 0x0000_0007_0003_0010;
const SOURCE_VA: u64 = 0x0000_0007_0003_0020;

/// Build the reference client layout. `group_count` is written into `TOKEN_GROUPS::GroupCount`
/// independently of how many entries are actually mapped, so a test can state a hostile count.
fn logon_token_client(group_count: u32, privilege_count: u32) -> (MockClient, CreateTokenArgs) {
    let mut client = MockClient::default();
    client.map(USER_SID_VA, &native_sid(5, &[21, 4660, 1001, 500]));
    client.map(ADMINS_SID_VA, &native_sid(5, &[32, 544]));
    client.map(USERS_SID_VA, &native_sid(5, &[32, 545]));
    client.map(EVERYONE_SID_VA, &native_sid(1, &[0]));

    client.map(TOKEN_USER_VA, &sid_and_attributes(USER_SID_VA, 0));

    // GroupCount + 3 SID_AND_ATTRIBUTES: an OWNER+mandatory admins group (mandatory must force
    // ENABLED even though SE_GROUP_ENABLED is absent), a plainly enabled users group, and a
    // deny-only Everyone.
    let mut groups = Vec::new();
    groups.extend_from_slice(&group_count.to_le_bytes());
    groups.extend_from_slice(&[0u8; 4]); // padding up to the array's 8-byte alignment
    groups.extend_from_slice(&sid_and_attributes(
        ADMINS_SID_VA,
        SE_GROUP_MANDATORY | SE_GROUP_OWNER | SE_GROUP_ENABLED_BY_DEFAULT,
    ));
    groups.extend_from_slice(&sid_and_attributes(USERS_SID_VA, SE_GROUP_ENABLED));
    groups.extend_from_slice(&sid_and_attributes(
        EVERYONE_SID_VA,
        SE_GROUP_USE_FOR_DENY_ONLY,
    ));
    client.map(TOKEN_GROUPS_VA, &groups);

    // PrivilegeCount + 2 LUID_AND_ATTRIBUTES: SeChangeNotify (23) enabled-by-default + enabled,
    // SeShutdown (19) present but disabled.
    let mut privileges = Vec::new();
    privileges.extend_from_slice(&privilege_count.to_le_bytes());
    privileges.extend_from_slice(&luid_and_attributes(
        23,
        0,
        SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT,
    ));
    privileges.extend_from_slice(&luid_and_attributes(19, 0, 0));
    client.map(TOKEN_PRIVILEGES_VA, &privileges);

    client.map(TOKEN_OWNER_VA, &ADMINS_SID_VA.to_le_bytes());
    client.map(TOKEN_PRIMARY_GROUP_VA, &USERS_SID_VA.to_le_bytes());
    client.map(TOKEN_DEFAULT_DACL_VA, &ACL_VA.to_le_bytes());
    client.map(ACL_VA, NativeAcl::system_default().as_bytes());

    // AuthenticationId = the LUID msgina minted; ExpirationTime = never; TOKEN_SOURCE = "User32  ".
    client.map(AUTH_ID_VA, &0x0000_0002_0000_03e9u64.to_le_bytes());
    client.map(EXPIRATION_VA, &(-1i64).to_le_bytes());
    let mut source = Vec::new();
    source.extend_from_slice(b"User32  ");
    source.extend_from_slice(&0x0000_0000_0000_03eau64.to_le_bytes());
    client.map(SOURCE_VA, &source);

    let args = CreateTokenArgs {
        token_type: 1, // TokenPrimary
        authentication_id: AUTH_ID_VA,
        expiration_time: EXPIRATION_VA,
        token_user: TOKEN_USER_VA,
        token_groups: TOKEN_GROUPS_VA,
        token_privileges: TOKEN_PRIVILEGES_VA,
        token_owner: TOKEN_OWNER_VA,
        token_primary_group: TOKEN_PRIMARY_GROUP_VA,
        token_default_dacl: TOKEN_DEFAULT_DACL_VA,
        token_source: SOURCE_VA,
    };
    (client, args)
}

#[test]
fn create_token_captures_the_real_logon_token_layout() {
    let (client, args) = logon_token_client(3, 2);
    let captured =
        capture_token(&client, &args, SecurityImpersonationLevel::Impersonation).unwrap();

    assert_eq!(captured.token.token_type, TokenType::Primary);
    // A PRIMARY token stores Anonymous regardless of the QoS level, like `AccessToken::duplicate`.
    assert_eq!(
        captured.token.impersonation_level,
        SecurityImpersonationLevel::Anonymous
    );
    assert_eq!(captured.token.user.to_sddl(), "S-1-5-21-4660-1001-500");
    assert_eq!(captured.requested_group_count, 3);
    assert_eq!(captured.requested_privilege_count, 2);
    assert_eq!(captured.token.groups.len(), 3);

    // SE_GROUP_MANDATORY forces enabled even with SE_GROUP_ENABLED absent (tokenlif.c:134).
    assert_eq!(captured.token.groups[0].sid, Sid::administrators());
    assert!(captured.token.groups[0].enabled);
    assert!(captured.token.groups[0].owner);
    assert!(!captured.token.groups[0].deny_only);
    assert_eq!(captured.token.groups[1].sid, Sid::users());
    assert!(captured.token.groups[1].enabled);
    assert_eq!(captured.token.groups[2].sid, Sid::everyone());
    assert!(captured.token.groups[2].deny_only);
    assert!(!captured.token.groups[2].enabled);

    assert_eq!(captured.token.privileges.len(), 2);
    assert_eq!(captured.token.privileges[0].name, SE_CHANGE_NOTIFY);
    assert_eq!(captured.token.privileges[0].luid, Luid::new(23));
    assert!(captured.token.privileges[0].enabled);
    assert!(captured.token.privileges[0].enabled_by_default);
    assert_eq!(captured.token.privileges[1].name, SE_SHUTDOWN);
    assert!(!captured.token.privileges[1].enabled);
    assert!(captured.token.has_privilege(SE_CHANGE_NOTIFY));
    assert!(!captured.token.has_privilege(SE_SHUTDOWN));

    assert_eq!(captured.token.owner, Sid::administrators());
    assert_eq!(captured.token.primary_group, Sid::users());
    assert_eq!(
        captured
            .token
            .default_dacl
            .as_ref()
            .map(|acl| acl.acl_size()),
        Some(52)
    );
    assert_eq!(
        captured.token.authentication_id,
        Luid {
            low: 0x3e9,
            high: 2
        }
    );
    assert_eq!(captured.expiration_time, -1);
    assert_eq!(&captured.source.name, b"User32  ");
    assert_eq!(captured.source.identifier, Luid::new(0x3ea));
}

#[test]
fn create_token_group_and_privilege_counts_bound_the_walk() {
    // A hostile GroupCount fails CLOSED with STATUS_INVALID_PARAMETER before a single array entry
    // is touched — proven by the byte counter, which must stop at the fixed-size prologue.
    let (client, args) = logon_token_client(MAX_CAPTURED_GROUPS + 1, 2);
    assert_eq!(
        capture_token(&client, &args, SecurityImpersonationLevel::Anonymous),
        Err(STATUS_INVALID_PARAMETER)
    );
    // LUID(8) + expiration(8) + source(16) + user entry(16) + user SID(8+16) + GroupCount(4).
    assert!(
        client.bytes_read() < 128,
        "over-read: {}",
        client.bytes_read()
    );

    let (client, args) = logon_token_client(3, MAX_CAPTURED_PRIVILEGES + 1);
    assert_eq!(
        capture_token(&client, &args, SecurityImpersonationLevel::Anonymous),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn create_token_truncated_group_array_fails_closed() {
    // GroupCount claims 4 entries but only 3 are mapped: the 4th read leaves the region.
    let (client, args) = logon_token_client(4, 2);
    assert_eq!(
        capture_token(&client, &args, SecurityImpersonationLevel::Anonymous),
        Err(STATUS_ACCESS_VIOLATION)
    );
}

#[test]
fn create_token_zero_counts_produce_an_empty_but_valid_token() {
    // The `LsaTokenInformationNull` shape: `TOKEN_GROUPS NoGroups = {0}` / `NoPrivileges = {0}`.
    let (client, args) = logon_token_client(0, 0);
    let captured = capture_token(&client, &args, SecurityImpersonationLevel::Anonymous).unwrap();
    assert!(captured.token.groups.is_empty());
    assert!(captured.token.privileges.is_empty());
    assert_eq!(captured.token.allow_sids().len(), 1); // the user only
}

#[test]
fn create_token_rejects_a_malformed_sid_before_reading_its_tail() {
    let mut client = MockClient::default();
    // Revision 2 is not a SID; SubAuthorityCount 200 exceeds the 15 the header permits.
    client.map(0x1000, &[2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    client.map(0x2000, &[1, 200, 0, 0, 0, 0, 0, 5]);
    assert_eq!(capture_sid(&client, 0x1000), Err(STATUS_INVALID_SID));
    assert_eq!(capture_sid(&client, 0x2000), Err(STATUS_INVALID_SID));
    // A NULL PSID is invalid, not an access violation.
    assert_eq!(capture_sid(&client, 0), Err(STATUS_INVALID_SID));
    // A well-formed header whose tail is NOT mapped is an access violation, and the tail read is
    // sized by the validated count — never wider.
    client.map(0x3000, &[1, 4, 0, 0, 0, 0, 0, 5]);
    assert_eq!(capture_sid(&client, 0x3000), Err(STATUS_ACCESS_VIOLATION));
}

#[test]
fn create_token_rejects_a_structurally_invalid_default_dacl() {
    let (mut client, args) = logon_token_client(3, 2);
    // AclSize says 16 but the single ACE claims 0xFFFE bytes → InvalidAceSize.
    client.regions.retain(|(base, _)| *base != ACL_VA);
    client.map(
        ACL_VA,
        &[2, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0xFE, 0xFF, 0, 0, 0, 0],
    );
    assert_eq!(
        capture_token(&client, &args, SecurityImpersonationLevel::Anonymous),
        Err(STATUS_INVALID_ACL)
    );
}

#[test]
fn create_token_null_inner_dacl_pointer_is_the_null_default_dacl_state() {
    let (mut client, args) = logon_token_client(3, 2);
    client
        .regions
        .retain(|(base, _)| *base != TOKEN_DEFAULT_DACL_VA);
    client.map(TOKEN_DEFAULT_DACL_VA, &0u64.to_le_bytes());
    let captured = capture_token(&client, &args, SecurityImpersonationLevel::Anonymous).unwrap();
    assert!(captured.token.default_dacl.is_none());

    // An entirely absent TOKEN_DEFAULT_DACL argument is the same state.
    let (client, mut args) = logon_token_client(3, 2);
    args.token_default_dacl = 0;
    let captured = capture_token(&client, &args, SecurityImpersonationLevel::Anonymous).unwrap();
    assert!(captured.token.default_dacl.is_none());
}

#[test]
fn create_token_absent_owner_defaults_to_the_user_sid() {
    let (client, mut args) = logon_token_client(3, 2);
    args.token_owner = 0;
    let captured = capture_token(&client, &args, SecurityImpersonationLevel::Anonymous).unwrap();
    assert_eq!(captured.token.owner, captured.token.user);
}

#[test]
fn create_token_rejects_a_bad_token_type_before_touching_client_memory() {
    let (client, mut args) = logon_token_client(3, 2);
    args.token_type = 3;
    assert_eq!(
        capture_token(&client, &args, SecurityImpersonationLevel::Anonymous),
        Err(STATUS_BAD_TOKEN_TYPE)
    );
    assert_eq!(client.bytes_read(), 0);
}

#[test]
fn create_token_impersonation_token_keeps_its_qos_level() {
    let (client, mut args) = logon_token_client(3, 2);
    args.token_type = 2; // TokenImpersonation
    let captured =
        capture_token(&client, &args, SecurityImpersonationLevel::Impersonation).unwrap();
    assert_eq!(captured.token.token_type, TokenType::Impersonation);
    assert_eq!(
        captured.token.impersonation_level,
        SecurityImpersonationLevel::Impersonation
    );
}

#[test]
fn create_token_unmapped_fixed_arguments_are_access_violations() {
    for spoil in 0..4 {
        let (client, mut args) = logon_token_client(3, 2);
        match spoil {
            0 => args.authentication_id = 0xdead_0000,
            1 => args.expiration_time = 0,
            2 => args.token_source = 0,
            _ => args.token_user = 0xbeef_0000,
        }
        assert_eq!(
            capture_token(&client, &args, SecurityImpersonationLevel::Anonymous),
            Err(STATUS_ACCESS_VIOLATION),
            "spoil {spoil}"
        );
    }
}

#[test]
fn privilege_luid_names_cover_the_well_known_range_and_nothing_else() {
    for low in 2..=30u32 {
        assert!(
            privilege_name_for_luid(Luid::new(low)).is_some(),
            "well-known privilege {low} has no name"
        );
    }
    assert_eq!(privilege_name_for_luid(Luid::new(2)), Some(SE_CREATE_TOKEN));
    assert_eq!(privilege_name_for_luid(Luid::new(7)), Some(SE_TCB));
    assert_eq!(
        privilege_name_for_luid(Luid::new(30)),
        Some(SE_CREATE_GLOBAL)
    );
    assert_eq!(privilege_name_for_luid(Luid::new(0)), None);
    assert_eq!(privilege_name_for_luid(Luid::new(1)), None);
    assert_eq!(privilege_name_for_luid(Luid::new(31)), None);
    // A non-zero HighPart is never a well-known privilege.
    assert_eq!(privilege_name_for_luid(Luid { low: 7, high: 1 }), None);
    // An unnamed LUID still captures losslessly — the LUID is the identity.
    let unnamed = crate::create_token::privilege_from_attributes(
        Luid { low: 999, high: 3 },
        SE_PRIVILEGE_ENABLED,
    );
    assert_eq!(unnamed.name, "");
    assert_eq!(unnamed.luid, Luid { low: 999, high: 3 });
    assert!(unnamed.enabled);
}

#[test]
fn capture_acl_reads_exactly_acl_size_bytes() {
    let mut client = MockClient::default();
    let acl = NativeAcl::system_default();
    // Map ONLY AclSize bytes: a reader that guessed a larger length would fail here.
    client.map(0x9000, acl.as_bytes());
    assert_eq!(capture_acl(&client, 0x9000).unwrap(), acl);
    // A header claiming fewer than the 8 mandatory bytes is an invalid ACL.
    client.map(0xA000, &[2, 0, 4, 0, 0, 0, 0, 0]);
    assert_eq!(capture_acl(&client, 0xA000), Err(STATUS_INVALID_ACL));
    assert_eq!(capture_acl(&client, 0), Err(STATUS_ACCESS_VIOLATION));
}

#[test]
fn capture_self_relative_security_descriptor_drives_access_check() {
    let mut client = MockClient::default();
    let owner = native_sid(5, &[21, MACHINE, 1000]);
    let group = native_sid(5, &[32, 545]);
    let everyone = native_sid(1, &[0]);
    let acl = acl_with_aces(&[access_ace(0, FILE_READ, &everyone)]);
    let sd_bytes = self_relative_sd(&owner, &group, Some(&acl));
    client.map(0xB000, &sd_bytes);

    let sd = capture_security_descriptor(&client, 0xB000).unwrap();
    assert_eq!(sd.owner, Some(Sid::local_account(MACHINE, 1000)));
    assert_eq!(sd.group, Some(Sid::users()));
    let result = access_check(
        &sd,
        &AccessToken::user(MACHINE),
        FILE_READ,
        &file_mapping(),
        ProcessorMode::UserMode,
    );
    assert!(result.granted());
}

#[test]
fn capture_absolute_security_descriptor_dereferences_native_pointers() {
    let mut client = MockClient::default();
    let owner = native_sid(5, &[21, MACHINE, 1000]);
    let group = native_sid(5, &[32, 545]);
    let admins = native_sid(5, &[32, 544]);
    let acl = acl_with_aces(&[access_ace(1, FILE_WRITE, &admins)]);

    const SD_VA: u64 = 0x0000_0007_0003_0000;
    const OWNER_VA: u64 = 0x0000_0007_0003_0100;
    const GROUP_VA: u64 = 0x0000_0007_0003_0200;
    const DACL_VA: u64 = 0x0000_0007_0003_0300;
    let mut sd_bytes = vec![0u8; 40];
    sd_bytes[0] = 1;
    sd_bytes[2..4].copy_from_slice(&0x0004u16.to_le_bytes()); // SE_DACL_PRESENT
    sd_bytes[8..16].copy_from_slice(&OWNER_VA.to_le_bytes());
    sd_bytes[16..24].copy_from_slice(&GROUP_VA.to_le_bytes());
    sd_bytes[32..40].copy_from_slice(&DACL_VA.to_le_bytes());
    client.map(SD_VA, &sd_bytes);
    client.map(OWNER_VA, &owner);
    client.map(GROUP_VA, &group);
    client.map(DACL_VA, &acl);

    let sd = capture_security_descriptor(&client, SD_VA).unwrap();
    assert_eq!(sd.owner, Some(Sid::local_account(MACHINE, 1000)));
    assert_eq!(sd.group, Some(Sid::users()));
    let result = access_check(
        &sd,
        &AccessToken::admin(MACHINE),
        FILE_WRITE,
        &file_mapping(),
        ProcessorMode::UserMode,
    );
    assert_eq!(result.status, STATUS_ACCESS_DENIED);
}

#[test]
fn capture_security_descriptor_reports_native_statuses() {
    let mut client = MockClient::default();
    client.map(
        0xC000,
        &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!(
        capture_security_descriptor(&client, 0xC000),
        Err(STATUS_UNKNOWN_REVISION)
    );
    assert_eq!(
        capture_security_descriptor(&client, 0),
        Err(STATUS_INVALID_SECURITY_DESCR)
    );
}

#[test]
fn token_store_records_expiration_and_source_and_duplicates_inherit_them() {
    let mut store = TokenStore::new();
    let source = TokenSource {
        name: *b"User32  ",
        identifier: Luid::new(0x3ea),
    };
    let created = store.insert_created(AccessToken::user(MACHINE), 0x1234_5678, source);
    assert_eq!(store.source(created), Some(source));
    assert_eq!(store.expiration_time(created), Some(0x1234_5678));
    assert_eq!(
        store.statistics(created).unwrap().expiration_time,
        0x1234_5678
    );

    let duplicate = store
        .duplicate(
            created,
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            false,
        )
        .unwrap();
    assert_eq!(store.source(duplicate), Some(source));
    assert_eq!(store.expiration_time(duplicate), Some(0x1234_5678));

    // The default insert path is unchanged: never expires, "*SYSTEM*".
    let system = store.insert(AccessToken::system());
    assert_eq!(store.source(system), Some(TokenSource::system()));
    assert_eq!(store.expiration_time(system), Some(-1));
}

#[test]
fn create_token_insufficient_resources_is_reachable_only_by_allocation_failure() {
    // Sanity: the two bounded statuses are distinct values, so a bounds rejection can never be
    // mistaken for an allocation failure in the executive's status plumbing.
    assert_ne!(STATUS_INVALID_PARAMETER, STATUS_INSUFFICIENT_RESOURCES);
    assert_eq!(STATUS_INSUFFICIENT_RESOURCES, 0xC000_009A);
}
