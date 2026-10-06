use nt_security::{
    assign_dos_devices_directory_security, assign_section_security,
    assign_security_directory_security, authorize_directory_open, authorize_section_open,
    AccessToken, CapturedSubjectTokens, ProcessorMode, SecurityAssignmentAudit, Sid,
    STATUS_ACCESS_DENIED,
};

fn subject(token: &AccessToken) -> CapturedSubjectTokens<'_> {
    CapturedSubjectTokens {
        primary: token,
        client: None,
        process_audit_id: 1,
    }
}

fn aces(descriptor: &[u8]) -> Vec<(Sid, u32, u8)> {
    let start = u32::from_le_bytes(descriptor[16..20].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(descriptor[start + 4..start + 6].try_into().unwrap());
    let mut at = start + 8;
    let mut result = Vec::new();
    for _ in 0..count {
        assert_eq!(descriptor[at], 0, "ACCESS_ALLOWED_ACE");
        let size = u16::from_le_bytes(descriptor[at + 2..at + 4].try_into().unwrap()) as usize;
        result.push((
            Sid::from_native_bytes(&descriptor[at + 8..at + size]).unwrap(),
            u32::from_le_bytes(descriptor[at + 4..at + 8].try_into().unwrap()),
            descriptor[at + 1],
        ));
        at += size;
    }
    result
}

#[test]
fn security_directory_has_exact_system_admin_world_policy() {
    let system = AccessToken::system();
    let mut audit = SecurityAssignmentAudit::default();
    let descriptor = assign_security_directory_security(&subject(&system), &mut audit).unwrap();
    assert_eq!(
        aces(&descriptor),
        vec![
            (system.user.clone(), 0xf000f, 0),
            (Sid::administrators(), 0x20003, 0),
            (Sid::everyone(), 2, 0),
        ]
    );
    let parsed = nt_security::security_descriptor_bytes_for_access(&descriptor).unwrap();
    assert_eq!(parsed.owner, Some(system.owner));
    assert_eq!(parsed.group, Some(system.primary_group));
    assert_eq!(audit, SecurityAssignmentAudit::default());
}

#[test]
fn security_directory_world_traverses_but_cannot_query_or_create() {
    let descriptor = assign_security_directory_security(
        &subject(&AccessToken::system()),
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let user = AccessToken::user(31);
    let allowed =
        authorize_directory_open(&subject(&user), &descriptor, 2, ProcessorMode::UserMode).unwrap();
    assert_eq!((allowed.status, allowed.granted_access), (0, 2));
    for right in [1, 4, 8] {
        let denied =
            authorize_directory_open(&subject(&user), &descriptor, right, ProcessorMode::UserMode)
                .unwrap();
        assert_eq!(
            (denied.status, denied.granted_access),
            (STATUS_ACCESS_DENIED, 0)
        );
    }
    let admin = AccessToken::admin(31);
    let allowed = authorize_directory_open(
        &subject(&admin),
        &descriptor,
        0x20003,
        ProcessorMode::UserMode,
    )
    .unwrap();
    assert_eq!((allowed.status, allowed.granted_access), (0, 0x20003));
    let denied =
        authorize_directory_open(&subject(&admin), &descriptor, 4, ProcessorMode::UserMode)
            .unwrap();
    assert_eq!(denied.status, STATUS_ACCESS_DENIED);
}

#[test]
fn unprotected_dos_directory_has_actual_world_write_and_inherit_only_all() {
    let system = AccessToken::system();
    let mut audit = SecurityAssignmentAudit::default();
    let descriptor =
        assign_dos_devices_directory_security(&subject(&system), 0, &mut audit).unwrap();
    assert_eq!(
        aces(&descriptor),
        vec![
            (Sid::everyone(), 0x2000f, 0),
            (system.user.clone(), 0xf000f, 0),
            (Sid::everyone(), nt_security::GENERIC_ALL, 0x0b),
        ]
    );
    let user = AccessToken::user(31);
    let create =
        authorize_directory_open(&subject(&user), &descriptor, 4, ProcessorMode::UserMode).unwrap();
    assert_eq!((create.status, create.granted_access), (0, 4));
    let delete = authorize_directory_open(
        &subject(&user),
        &descriptor,
        nt_security::DELETE,
        ProcessorMode::UserMode,
    )
    .unwrap();
    assert_eq!(
        delete.status, STATUS_ACCESS_DENIED,
        "inherit-only ACE cannot authorize the directory itself"
    );
    assert_eq!(audit, SecurityAssignmentAudit::default());
}

#[test]
fn protected_dos_directory_preserves_exact_inherit_only_trustees() {
    let system = AccessToken::system();
    let creator_owner = Sid::from_native_bytes(&[1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0]).unwrap();
    let descriptor = assign_dos_devices_directory_security(
        &subject(&system),
        1,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    assert_eq!(
        aces(&descriptor),
        vec![
            (Sid::everyone(), 0x20003, 0),
            (system.user.clone(), 0xf000f, 0),
            (Sid::everyone(), nt_security::GENERIC_EXECUTE, 0x0b),
            (Sid::administrators(), nt_security::GENERIC_ALL, 0x0b),
            (system.user, nt_security::GENERIC_ALL, 0x0b),
            (creator_owner, nt_security::GENERIC_ALL, 0x0b),
        ]
    );
    let user = AccessToken::user(31);
    let denied =
        authorize_directory_open(&subject(&user), &descriptor, 4, ProcessorMode::UserMode).unwrap();
    assert_eq!(denied.status, STATUS_ACCESS_DENIED);
    let traverse =
        authorize_directory_open(&subject(&user), &descriptor, 3, ProcessorMode::UserMode).unwrap();
    assert_eq!((traverse.status, traverse.granted_access), (0, 3));
}

#[test]
fn inherited_generic_mask_maps_to_child_section_not_parent_directory_rights() {
    let system = AccessToken::system();
    let parent = assign_dos_devices_directory_security(
        &subject(&system),
        0,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let child = assign_section_security(
        &subject(&system),
        None,
        Some(&parent),
        ProcessorMode::KernelMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let user = AccessToken::user(31);
    let granted = authorize_section_open(
        &subject(&user),
        &child,
        nt_security::GENERIC_ALL,
        ProcessorMode::UserMode,
    )
    .unwrap();
    assert_eq!((granted.status, granted.granted_access), (0, 0xf001f));
    let parent_delete = authorize_directory_open(
        &subject(&user),
        &parent,
        nt_security::DELETE,
        ProcessorMode::UserMode,
    )
    .unwrap();
    assert_eq!(parent_delete.status, STATUS_ACCESS_DENIED);
}

#[test]
fn dos_protection_uses_actual_low_bit_not_nonzero_boolean() {
    let system = AccessToken::system();
    let subject = subject(&system);
    let mut audit = SecurityAssignmentAudit::default();
    let unprotected = assign_dos_devices_directory_security(&subject, 0, &mut audit).unwrap();
    let protected = assign_dos_devices_directory_security(&subject, 1, &mut audit).unwrap();
    assert_eq!(
        assign_dos_devices_directory_security(&subject, 2, &mut audit).unwrap(),
        unprotected
    );
    assert_eq!(
        assign_dos_devices_directory_security(&subject, 3, &mut audit).unwrap(),
        protected
    );
}
