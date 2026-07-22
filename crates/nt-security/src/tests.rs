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
    assert_eq!(token.adjust_privileges(false, &requested, &mut previous), plan);
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
    assert!(!token.privileges.iter().any(|privilege| privilege.luid.low == 10));
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
