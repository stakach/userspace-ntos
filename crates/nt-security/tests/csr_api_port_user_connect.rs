//! The CSR ApiPort connect as the pinned binaries perform it.
//!
//! csrsrv (`subsystems/csr/csrsrv/api.c`, `CsrApiPortInitialize`) creates
//! `\Windows\ApiPort` with an absolute descriptor carrying a NULL DACL and one
//! `S-1-16-0` (Untrusted) `NO_WRITE_UP` mandatory label. lsasrv hands
//! `NtCreateToken` a group list with no integrity group, and the kernel's
//! `SepCreateToken` (`ntoskrnl/se/tokenlif.c`) supplies one: System for
//! LocalSystem, High for a member of Administrators, Medium otherwise.

use nt_security::{
    assign_object_security_with_audit, authorize_port_connect, capture_security_descriptor_bytes,
    capture_token, AccessToken, CapturedSubjectTokens, ClientMemory, CreateTokenArgs,
    ObjectSecurityAssignment, ProcessorMode, SecurityAssignmentAudit,
    SecurityAssignmentInheritance, SecurityImpersonationLevel, Sid, PORT_CONNECT,
    PORT_GENERIC_MAPPING, STATUS_ACCESS_DENIED,
};

const SE_GROUP_MANDATORY: u32 = 0x1;
const SE_GROUP_ENABLED_BY_DEFAULT: u32 = 0x2;
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_INTEGRITY: u32 = 0x20;
const SE_GROUP_INTEGRITY_ENABLED: u32 = 0x40;
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
const ENABLED: u32 = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;

#[derive(Default)]
struct Client {
    regions: Vec<(u64, Vec<u8>)>,
    next: u64,
}

impl Client {
    fn place(&mut self, bytes: &[u8]) -> u64 {
        self.next += 0x1000;
        self.regions.push((self.next, bytes.to_vec()));
        self.next
    }
}

impl ClientMemory for Client {
    fn read(&self, va: u64, dst: &mut [u8]) -> bool {
        for (base, bytes) in &self.regions {
            if let Some(offset) = va.checked_sub(*base) {
                if let Some(src) = bytes.get(offset as usize..offset as usize + dst.len()) {
                    dst.copy_from_slice(src);
                    return true;
                }
            }
        }
        false
    }
}

fn native(sid: &Sid) -> Vec<u8> {
    let mut bytes = vec![0u8; sid.native_len().unwrap()];
    sid.write_native(&mut bytes).unwrap();
    bytes
}

/// `RtlCreateAcl` + `RtlAddMandatoryAce(Sacl, ACL_REVISION, 0, NO_WRITE_UP,
/// SYSTEM_MANDATORY_LABEL_ACE_TYPE, S-1-16-<rid>)`.
fn label_sacl(rid: u32) -> Vec<u8> {
    let sid = native(&Sid::new(16, &[rid]));
    let mut ace = vec![0x11, 0, 0, 0, 1, 0, 0, 0];
    ace.extend_from_slice(&sid);
    let ace_size = ace.len() as u16;
    ace[2..4].copy_from_slice(&ace_size.to_le_bytes());
    let mut acl = vec![2, 0, 0, 0, 1, 0, 0, 0];
    acl.extend_from_slice(&ace);
    let acl_size = acl.len() as u16;
    acl[2..4].copy_from_slice(&acl_size.to_le_bytes());
    acl
}

/// The absolute x64 `SECURITY_DESCRIPTOR` csrsrv passes: `RtlSetDaclSecurityDescriptor(Sd, TRUE,
/// NULL, FALSE)` then `RtlSetSaclSecurityDescriptor(Sd, TRUE, Sacl, FALSE)`; no owner or group.
/// Captured and assigned exactly as the executive's port create does for a SYSTEM creator.
fn api_port_descriptor(label_rid: u32) -> Vec<u8> {
    let mut client = Client::default();
    let sacl = client.place(&label_sacl(label_rid));
    let mut absolute = vec![0u8; 40];
    absolute[0] = 1;
    absolute[2..4].copy_from_slice(&0x0014u16.to_le_bytes());
    absolute[24..32].copy_from_slice(&sacl.to_le_bytes());
    let va = client.place(&absolute);
    let creator = capture_security_descriptor_bytes(&client, va).unwrap();
    assert_eq!(u16::from_le_bytes([creator[2], creator[3]]), 0x8014);

    let system = AccessToken::system();
    let mut audit = SecurityAssignmentAudit::default();
    assign_object_security_with_audit(
        &ObjectSecurityAssignment {
            primary: &system,
            client: None,
            creator: Some(&creator),
            parent: None,
            mapping: &PORT_GENERIC_MAPPING,
            is_container: false,
            mode: ProcessorMode::UserMode,
            object_type: None,
            inheritance: SecurityAssignmentInheritance::Legacy,
        },
        &mut audit,
    )
    .unwrap()
}

/// The `NtCreateToken` arguments lsasrv's `LsapLogonUser` builds: the account, then the groups
/// in `groups`, with the token's primary group and owner both naming the account.
fn lsa_token(user: &Sid, groups: &[(Sid, u32)]) -> AccessToken {
    let mut client = Client::default();
    let user_va = client.place(&native(user));
    let mut token_user = user_va.to_le_bytes().to_vec();
    token_user.extend_from_slice(&[0u8; 8]);
    let token_user = client.place(&token_user);

    let mut token_groups = (groups.len() as u32).to_le_bytes().to_vec();
    token_groups.extend_from_slice(&[0u8; 4]);
    for (sid, attributes) in groups {
        let sid_va = client.place(&native(sid));
        token_groups.extend_from_slice(&sid_va.to_le_bytes());
        token_groups.extend_from_slice(&attributes.to_le_bytes());
        token_groups.extend_from_slice(&[0u8; 4]);
    }
    let token_groups = client.place(&token_groups);
    let token_privileges = client.place(&0u32.to_le_bytes());
    let primary_group = client.place(&user_va.to_le_bytes());
    let authentication_id = client.place(&0x3efu64.to_le_bytes());
    let expiration_time = client.place(&(-1i64).to_le_bytes());
    let mut source = b"User32  ".to_vec();
    source.extend_from_slice(&[0u8; 8]);
    let token_source = client.place(&source);

    capture_token(
        &client,
        &CreateTokenArgs {
            token_type: 1,
            authentication_id,
            expiration_time,
            token_user,
            token_groups,
            token_privileges,
            token_owner: 0,
            token_primary_group: primary_group,
            token_default_dacl: 0,
            token_source,
        },
        SecurityImpersonationLevel::Anonymous,
    )
    .unwrap()
    .token
}

fn interactive_groups() -> Vec<(Sid, u32)> {
    vec![
        (Sid::new(5, &[21, 4660, 513]), ENABLED),
        (Sid::everyone(), ENABLED),
        (Sid::users(), ENABLED),
        (Sid::new(5, &[4]), ENABLED),
        (Sid::authenticated_users(), ENABLED),
        (Sid::new(5, &[5, 0, 0x3ef]), ENABLED | SE_GROUP_LOGON_ID),
        (Sid::new(2, &[0]), ENABLED),
    ]
}

fn connect(token: &AccessToken, descriptor: &[u8]) -> (u32, u32) {
    let subject = CapturedSubjectTokens { primary: token, client: None, process_audit_id: 4 };
    let result = authorize_port_connect(&subject, descriptor, ProcessorMode::UserMode).unwrap();
    (result.status, result.granted_access)
}

#[test]
fn kernel_supplies_the_integrity_group_lsass_leaves_out() {
    let user = Sid::new(5, &[21, 4660, 1000]);
    assert_eq!(lsa_token(&user, &interactive_groups()).integrity_level, Some(0x2000));

    let mut administrator = interactive_groups();
    administrator.push((Sid::administrators(), ENABLED));
    assert_eq!(lsa_token(&user, &administrator).integrity_level, Some(0x3000));

    // NetworkService and LocalService: service accounts outside Administrators.
    for service in [Sid::new(5, &[20]), Sid::new(5, &[19])] {
        assert_eq!(lsa_token(&service, &[(Sid::everyone(), ENABLED)]).integrity_level,
            Some(0x2000));
    }
    assert_eq!(lsa_token(&Sid::local_system(), &[(Sid::everyone(), ENABLED)]).integrity_level,
        Some(0x4000));

    // A caller-supplied integrity group is authoritative, even for an administrator.
    administrator.push((Sid::new(16, &[0x1000]), SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED));
    assert_eq!(lsa_token(&user, &administrator).integrity_level, Some(0x1000));
}

#[test]
fn logged_on_user_and_service_accounts_connect_to_the_csr_api_port() {
    let api_port = api_port_descriptor(0);
    let user = lsa_token(&Sid::new(5, &[21, 4660, 1000]), &interactive_groups());
    assert_eq!(connect(&user, &api_port), (0, PORT_CONNECT));
    for service in [Sid::new(5, &[20]), Sid::new(5, &[19])] {
        let token = lsa_token(&service, &[(Sid::everyone(), ENABLED)]);
        assert_eq!(connect(&token, &api_port), (0, PORT_CONNECT));
    }
    assert_eq!(connect(&AccessToken::system(), &api_port), (0, PORT_CONNECT));
}

#[test]
fn a_token_without_an_integrity_level_dominates_only_an_untrusted_label() {
    let mut token = lsa_token(&Sid::new(5, &[21, 4660, 1000]), &interactive_groups());
    token.integrity_level = None;
    assert_eq!(connect(&token, &api_port_descriptor(0)), (0, PORT_CONNECT));
    for higher in [0x1000, 0x2000, 0x4000] {
        assert_eq!(connect(&token, &api_port_descriptor(higher)), (STATUS_ACCESS_DENIED, 0));
    }
}

#[test]
fn medium_user_is_still_refused_above_its_integrity() {
    let user = lsa_token(&Sid::new(5, &[21, 4660, 1000]), &interactive_groups());
    assert_eq!(connect(&user, &api_port_descriptor(0x2000)), (0, PORT_CONNECT));
    assert_eq!(connect(&user, &api_port_descriptor(0x3000)), (STATUS_ACCESS_DENIED, 0));
}
