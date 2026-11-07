//! BASESRV reuses an absolute SD while replacing the BNO DACL for its Restricted child.

use nt_security::{
    assign_directory_security, assign_object_directory_root_security, authorize_directory_open,
    capture_security_descriptor_bytes, AccessToken, CapturedSubjectTokens, ClientMemory,
    ProcessorMode, SecurityAssignmentAudit, Sid,
};

fn subject(token: &AccessToken) -> CapturedSubjectTokens<'_> {
    CapturedSubjectTokens { primary: token, client: None, process_audit_id: 72 }
}

fn basesrv_dacl(restricted_access: u32) -> Vec<u8> {
    const WORLD_ACCESS: u32 = 0x0002_000f;
    const DIRECTORY_ALL_ACCESS: u32 = 0x000f_000f;
    let mut acl = vec![2, 0, 0, 0, 3, 0, 0, 0];
    for (sid, access) in [
        (Sid::everyone(), WORLD_ACCESS),
        (Sid::local_system(), DIRECTORY_ALL_ACCESS),
        (Sid::new(5, &[12]), restricted_access),
    ] {
        let mut sid_bytes = vec![0; sid.native_len().unwrap()];
        sid.write_native(&mut sid_bytes).unwrap();
        let ace_len = 8 + sid_bytes.len();
        acl.extend_from_slice(&[0, 0]); // ACCESS_ALLOWED_ACE_TYPE, no inheritance flags
        acl.extend_from_slice(&(ace_len as u16).to_le_bytes());
        acl.extend_from_slice(&access.to_le_bytes());
        acl.extend_from_slice(&sid_bytes);
    }
    let acl_len = acl.len() as u16;
    acl[2..4].copy_from_slice(&acl_len.to_le_bytes());
    acl
}

fn creator_with_dacl(dacl: Vec<u8>) -> Vec<u8> {
    // SECURITY_DESCRIPTOR_RELATIVE: revision 1, DACL present, self-relative, DACL offset 20.
    let mut sd = vec![1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0];
    sd.extend_from_slice(&dacl);
    sd
}

struct AbsoluteDescriptor(Vec<u8>);

impl ClientMemory for AbsoluteDescriptor {
    fn read(&self, address: u64, output: &mut [u8]) -> bool {
        let Some(source) = self.0.get(address as usize..address as usize + output.len()) else {
            return false;
        };
        output.copy_from_slice(source);
        true
    }
}

fn captured_labeled_absolute_descriptor(dacl: Vec<u8>) -> Vec<u8> {
    captured_absolute_descriptor_with_label(dacl, 0x1000, 1, 0)
}

fn captured_absolute_descriptor_with_label(dacl: Vec<u8>, level: u32, policy: u32, flags: u8) -> Vec<u8> {
    // x64 absolute SD as passed by BASESRV after RtlSetDaclSecurityDescriptor reuses BnoSd.
    // The SACL holds a low-integrity SYSTEM_MANDATORY_LABEL_ACE for S-1-16-4096.
    let mut memory = AbsoluteDescriptor(vec![0; 1024]);
    memory.0[64] = 1;
    memory.0[66..68].copy_from_slice(&0x0014u16.to_le_bytes());
    memory.0[88..96].copy_from_slice(&128u64.to_le_bytes());
    memory.0[96..104].copy_from_slice(&512u64.to_le_bytes());
    memory.0[128..136].copy_from_slice(&[4, 0, 28, 0, 1, 0, 0, 0]);
    memory.0[136..156].copy_from_slice(&[
        0x11, 0, 20, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 16, 0, 0x10, 0, 0,
    ]);
    memory.0[137] = flags;
    memory.0[140..144].copy_from_slice(&policy.to_le_bytes());
    memory.0[152..156].copy_from_slice(&level.to_le_bytes());
    memory.0[512..512 + dacl.len()].copy_from_slice(&dacl);
    capture_security_descriptor_bytes(&memory, 64).expect("capture BASESRV absolute SD")
}

#[test]
fn basesrv_bno_then_restricted_assignment_preserves_explicit_three_ace_dacls() {
    let token = AccessToken::system();
    let subject = subject(&token);
    let root = assign_object_directory_root_security(
        &subject,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let bno = assign_directory_security(
        &subject,
        Some(&creator_with_dacl(basesrv_dacl(0x0000_0002))),
        Some(&root),
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .expect("BASESRV must create BaseNamedObjects with the first explicit DACL");
    let restricted = assign_directory_security(
        &subject,
        Some(&creator_with_dacl(basesrv_dacl(0x0002_000f))),
        Some(&bno),
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .expect("BASESRV must create Restricted under the exact BNO parent");
    let system = authorize_directory_open(
        &subject,
        &restricted,
        0x000f_000f,
        ProcessorMode::UserMode,
    )
    .unwrap();
    assert_eq!((system.status, system.granted_access), (0, 0x000f_000f));
}

#[test]
fn basesrv_absolute_sd_with_low_label_survives_restricted_dacl_replacement() {
    let token = AccessToken::system();
    let subject = subject(&token);
    let root = assign_object_directory_root_security(
        &subject,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let bno = assign_directory_security(
        &subject,
        Some(&captured_labeled_absolute_descriptor(basesrv_dacl(0x2))),
        Some(&root),
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .expect("label-bearing BNO directory assignment");
    let parent_create = authorize_directory_open(
        &subject,
        &bno,
        0x8, // DIRECTORY_CREATE_SUBDIRECTORY used by NtCreateDirectoryObject(Restricted)
        ProcessorMode::UserMode,
    )
    .expect("mandatory-label SACL must be projected separately from the access DACL");
    assert_eq!((parent_create.status, parent_create.granted_access), (0, 0x8));
    assign_directory_security(
        &subject,
        Some(&captured_labeled_absolute_descriptor(basesrv_dacl(0x0002_000f))),
        Some(&bno),
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .expect("Restricted directory assignment after DACL replacement");
}

#[test]
fn low_label_bno_denies_write_up_for_a_lower_integrity_subject() {
    let system = AccessToken::system();
    let root = assign_object_directory_root_security(
        &subject(&system),
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let bno = assign_directory_security(
        &subject(&system),
        Some(&captured_labeled_absolute_descriptor(basesrv_dacl(0x2))),
        Some(&root),
        ProcessorMode::UserMode,
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    let mut lower = AccessToken::user(41);
    lower.integrity_level = Some(0);
    let decision = authorize_directory_open(
        &subject(&lower), &bno, 0x8, ProcessorMode::UserMode,
    )
    .expect("valid label-bearing descriptor must produce an access decision");
    assert_eq!((decision.status, decision.granted_access), (nt_security::STATUS_ACCESS_DENIED, 0));
}

#[test]
fn directory_mandatory_policy_filters_mapped_rights_and_maximum_allowed() {
    let mut lower = AccessToken::user(41);
    lower.integrity_level = Some(0);
    for (policy, denied_right, allowed_right) in [(1, 0x8, 0x1), (2, 0x1, 0x8), (4, 0x2, 0x8)] {
        let descriptor = captured_absolute_descriptor_with_label(
            basesrv_dacl(0x2), 0x1000, policy, 0,
        );
        let blocked = authorize_directory_open(
            &subject(&lower), &descriptor, denied_right, ProcessorMode::UserMode,
        ).unwrap();
        assert_eq!((blocked.status, blocked.granted_access), (nt_security::STATUS_ACCESS_DENIED, 0));
        let allowed = authorize_directory_open(
            &subject(&lower), &descriptor, allowed_right, ProcessorMode::UserMode,
        ).unwrap();
        assert_eq!((allowed.status, allowed.granted_access), (0, allowed_right));
        let maximum = authorize_directory_open(
            &subject(&lower), &descriptor, 0x0200_0000, ProcessorMode::UserMode,
        ).unwrap();
        assert_eq!(maximum.status, 0);
        assert_eq!(maximum.granted_access & denied_right, 0);
        assert_ne!(maximum.granted_access & allowed_right, 0);
    }
}

#[test]
fn directory_mandatory_policy_honors_equal_higher_inherit_only_and_unknown_integrity() {
    let ordinary = captured_absolute_descriptor_with_label(basesrv_dacl(0x2), 0x1000, 1, 0);
    let mut token = AccessToken::user(41);
    for level in [0x1000, 0x2000] {
        token.integrity_level = Some(level);
        let result = authorize_directory_open(
            &subject(&token), &ordinary, 0x8, ProcessorMode::UserMode,
        ).unwrap();
        assert_eq!((result.status, result.granted_access), (0, 0x8));
    }
    token.integrity_level = None;
    let missing = authorize_directory_open(
        &subject(&token), &ordinary, 0x8, ProcessorMode::UserMode,
    ).unwrap();
    assert_eq!((missing.status, missing.granted_access), (nt_security::STATUS_ACCESS_DENIED, 0));

    // An inherit-only low ACE does not label this object: use Medium/NO_WRITE_UP here.
    let inherit_only = captured_absolute_descriptor_with_label(basesrv_dacl(0x2), 0x1000, 1, 0x08);
    token.integrity_level = Some(0x1000);
    let inherited = authorize_directory_open(
        &subject(&token), &inherit_only, 0x8, ProcessorMode::UserMode,
    ).unwrap();
    assert_eq!((inherited.status, inherited.granted_access), (nt_security::STATUS_ACCESS_DENIED, 0));

    let kernel = authorize_directory_open(
        &subject(&token), &ordinary, 0x8, ProcessorMode::KernelMode,
    ).unwrap();
    assert_eq!((kernel.status, kernel.granted_access), (0, 0x8));
}
