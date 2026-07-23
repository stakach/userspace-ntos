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
