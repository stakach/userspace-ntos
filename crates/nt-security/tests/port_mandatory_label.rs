use nt_security::{
    assign_object_security_with_audit, authorize_port_connect,
    capture_security_descriptor_bytes, AccessToken, ClientMemory,
    CapturedClientToken, CapturedSubjectTokens, ObjectSecurityAssignment, ProcessorMode,
    SecurityAssignmentAudit, SecurityAssignmentInheritance, SecurityAssignmentPrivilegeOutcome,
    SecurityImpersonationLevel, TokenType, PORT_CONNECT, PORT_GENERIC_MAPPING,
    SE_SECURITY, STATUS_ACCESS_DENIED, STATUS_INVALID_ACL, STATUS_PRIVILEGE_NOT_HELD,
};

fn ace(kind: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 0, 0, 0];
    out.extend_from_slice(&mask.to_le_bytes());
    out.extend_from_slice(sid);
    let size = out.len() as u16;
    out[2..4].copy_from_slice(&size.to_le_bytes());
    out
}

fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![2, 0, 0, 0, 0, 0, 0, 0];
    for ace in aces { out.extend_from_slice(ace); }
    let size = out.len() as u16;
    out[2..4].copy_from_slice(&size.to_le_bytes());
    out[4..6].copy_from_slice(&(aces.len() as u16).to_le_bytes());
    out
}

fn system_label(mask: u32) -> Vec<u8> {
    ace(0x11, mask, &[1, 1, 0, 0, 0, 0, 0, 16, 0, 0x40, 0, 0])
}

fn descriptor_with_sacl(aces: &[Vec<u8>]) -> Vec<u8> {
    let system = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let administrators = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
    let sacl = acl(aces);
    let dacl = acl(&[ace(0, 0x1000_0000, &system), ace(0, 0x1000_0000, &administrators)]);
    let mut out = vec![0; 20];
    out[0] = 1;
    out[2..4].copy_from_slice(&0x8014u16.to_le_bytes());
    out[12..16].copy_from_slice(&20u32.to_le_bytes());
    out.extend_from_slice(&sacl);
    let dacl_offset = out.len() as u32;
    out[16..20].copy_from_slice(&dacl_offset.to_le_bytes());
    out.extend_from_slice(&dacl);
    out
}

fn smss_descriptor(label: &[u8]) -> Vec<u8> {
    descriptor_with_sacl(&[label.to_vec()])
}

fn subject<'a>(primary: &'a AccessToken, client: Option<&'a AccessToken>) -> CapturedSubjectTokens<'a> {
    CapturedSubjectTokens {
        primary,
        client: client.map(|token| CapturedClientToken {
            token,
            level: SecurityImpersonationLevel::Impersonation,
        }),
        process_audit_id: 4,
    }
}

#[test]
fn absolute_descriptor_capture_owns_both_dacl_and_mandatory_sacl() {
    struct Memory(Vec<u8>);
    impl ClientMemory for Memory {
        fn read(&self, va: u64, dst: &mut [u8]) -> bool {
            let Some(src) = self.0.get(va as usize..va as usize + dst.len()) else {
                return false;
            };
            dst.copy_from_slice(src);
            true
        }
    }
    let relative = smss_descriptor(&system_label(7));
    let sacl_offset = u32::from_le_bytes(relative[12..16].try_into().unwrap()) as usize;
    let dacl_offset = u32::from_le_bytes(relative[16..20].try_into().unwrap()) as usize;
    let mut memory = Memory(vec![0; 512]);
    memory.0[64] = 1;
    memory.0[66..68].copy_from_slice(&0x14u16.to_le_bytes());
    memory.0[88..96].copy_from_slice(&128u64.to_le_bytes());
    memory.0[96..104].copy_from_slice(&256u64.to_le_bytes());
    memory.0[128..256].fill(0);
    memory.0[128..128 + dacl_offset - sacl_offset]
        .copy_from_slice(&relative[sacl_offset..dacl_offset]);
    memory.0[256..256 + relative.len() - dacl_offset]
        .copy_from_slice(&relative[dacl_offset..]);
    let owned = capture_security_descriptor_bytes(&memory, 64).unwrap();
    memory.0[128..256].fill(0);
    assert!(authorize_port_connect(&subject(&AccessToken::system(), None),
        &owned, ProcessorMode::UserMode).unwrap().granted());
    let assigned_sacl = u32::from_le_bytes(owned[12..16].try_into().unwrap()) as usize;
    assert_eq!(&owned[assigned_sacl + 8..assigned_sacl + 28], system_label(7));
}

#[test]
fn label_only_assignment_preserves_policy_without_audit_privilege() {
    let creator = smss_descriptor(&system_label(7));
    let system = AccessToken::system();
    let mut audit = SecurityAssignmentAudit::default();
    let request = ObjectSecurityAssignment {
        primary: &system, client: None, creator: Some(&creator), parent: None,
        mapping: &PORT_GENERIC_MAPPING, is_container: false,
        mode: ProcessorMode::UserMode, object_type: None,
        inheritance: SecurityAssignmentInheritance::Legacy,
    };
    let assigned = assign_object_security_with_audit(&request, &mut audit).unwrap();
    assert_eq!(audit.security, None);
    let sacl_offset = u32::from_le_bytes(assigned[12..16].try_into().unwrap()) as usize;
    assert_eq!(&assigned[sacl_offset + 8..sacl_offset + 28], system_label(7));
}

#[test]
fn mixed_label_and_audit_sacl_still_requires_security_privilege() {
    let system_sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    let creator = descriptor_with_sacl(&[
        system_label(1), ace(2, PORT_CONNECT, &system_sid),
    ]);
    let mut system = AccessToken::system();
    let mut audit = SecurityAssignmentAudit::default();
    {
        let request = ObjectSecurityAssignment {
            primary: &system, client: None, creator: Some(&creator), parent: None,
            mapping: &PORT_GENERIC_MAPPING, is_container: false,
            mode: ProcessorMode::UserMode, object_type: None,
            inheritance: SecurityAssignmentInheritance::Legacy,
        };
        assert_eq!(assign_object_security_with_audit(&request, &mut audit),
            Err(STATUS_PRIVILEGE_NOT_HELD));
    }
    assert_eq!(audit.security, Some(SecurityAssignmentPrivilegeOutcome::Denied));
    system.privileges.iter_mut().find(|privilege| privilege.name == SE_SECURITY)
        .unwrap().enabled = true;
    let request = ObjectSecurityAssignment {
        primary: &system, client: None, creator: Some(&creator), parent: None,
        mapping: &PORT_GENERIC_MAPPING, is_container: false,
        mode: ProcessorMode::UserMode, object_type: None,
        inheritance: SecurityAssignmentInheritance::Legacy,
    };
    assert!(assign_object_security_with_audit(&request, &mut audit).is_ok());
    assert_eq!(audit.security, Some(SecurityAssignmentPrivilegeOutcome::Granted));
}

#[test]
fn protected_smss_connect_requires_both_dacl_and_integrity() {
    let sd = smss_descriptor(&system_label(1));
    let system = AccessToken::system();
    let admin = AccessToken::admin(7);
    let user = AccessToken::user(7);
    assert!(authorize_port_connect(&subject(&system, None), &sd, ProcessorMode::UserMode)
        .unwrap().granted());
    for lower in [&admin, &user] {
        let result = authorize_port_connect(&subject(lower, None), &sd, ProcessorMode::UserMode)
            .unwrap();
        assert_eq!(result.status, STATUS_ACCESS_DENIED);
        assert_eq!(result.granted_access, 0);
    }
    assert_eq!(PORT_CONNECT, 1);
}

#[test]
fn mandatory_read_and_execute_policies_follow_port_connect_mapping() {
    let admin = AccessToken::admin(7);
    assert_eq!(authorize_port_connect(&subject(&admin, None),
        &smss_descriptor(&system_label(2)), ProcessorMode::UserMode)
        .unwrap().status, STATUS_ACCESS_DENIED);
    assert!(authorize_port_connect(&subject(&admin, None),
        &smss_descriptor(&system_label(4)), ProcessorMode::UserMode)
        .unwrap().granted());
}

#[test]
fn token_duplication_retains_integrity_without_elevation() {
    let admin = AccessToken::admin(7);
    let duplicate = admin.duplicate(TokenType::Impersonation,
        SecurityImpersonationLevel::Impersonation, true).unwrap();
    assert_eq!(duplicate.integrity_level, admin.integrity_level);
    assert_eq!(authorize_port_connect(&subject(&duplicate, None),
        &smss_descriptor(&system_label(1)), ProcessorMode::UserMode)
        .unwrap().status, STATUS_ACCESS_DENIED);
}

#[test]
fn impersonation_uses_client_integrity_not_primary_system_integrity() {
    let sd = smss_descriptor(&system_label(1));
    let primary = AccessToken::system();
    let mut client = AccessToken::admin(7);
    client.token_type = TokenType::Impersonation;
    client.impersonation_level = SecurityImpersonationLevel::Impersonation;
    let result = authorize_port_connect(&subject(&primary, Some(&client)), &sd,
        ProcessorMode::UserMode).unwrap();
    assert_eq!(result.status, STATUS_ACCESS_DENIED);
}

#[test]
fn missing_integrity_and_invalid_label_fail_closed() {
    let sd = smss_descriptor(&system_label(1));
    let mut system = AccessToken::system();
    system.integrity_level = None;
    assert_eq!(authorize_port_connect(&subject(&system, None), &sd,
        ProcessorMode::UserMode).unwrap().status, STATUS_ACCESS_DENIED);

    for malformed in [
        system_label(8),
        ace(0x11, 1, &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]),
    ] {
        assert_eq!(authorize_port_connect(&subject(&AccessToken::system(), None),
            &smss_descriptor(&malformed), ProcessorMode::UserMode), Err(STATUS_INVALID_ACL));
    }
}
