//! Crate composition proof, not native handle/CM-generation admission.

use nt_hive_core::{
    encode_image, try_encode_log_record, try_replay_log, Hive, HiveKind, HiveLogOp,
};
use nt_security::{
    assign_registry_root_security, prepare_key_creation_security,
    security_descriptor_bytes_for_access, AccessToken, CapturedSubjectContext, KeyCreationAudit,
    ProcessorMode, SecurityAssignmentAudit, TokenStore, KEY_GENERIC_MAPPING,
};

fn initial_hive() -> Hive {
    let mut tokens = TokenStore::new();
    let primary = tokens.insert(AccessToken::system());
    let mut capture = CapturedSubjectContext::capture(&mut tokens, primary, None, 0).unwrap();
    let sd = assign_registry_root_security(
        &capture.resolve(&tokens).unwrap(),
        &mut SecurityAssignmentAudit::default(),
    )
    .unwrap();
    capture.release(&mut tokens).unwrap();
    let mut hive = Hive::new(HiveKind::System);
    hive.set_key_security_descriptor(hive.root(), &sd);
    hive.finish_clean_import();
    hive
}

#[test]
fn denied_parent_never_creates_a_child_or_dirties_the_hive() {
    let mut hive = initial_hive();
    let before = encode_image(&hive);
    let mut tokens = TokenStore::new();
    let primary = tokens.insert(AccessToken::user(123));
    let mut capture = CapturedSubjectContext::capture(&mut tokens, primary, None, 0).unwrap();
    let subject = capture.resolve(&tokens).unwrap();
    let tx = hive.begin_transaction();
    let parent = tx.hive().key_security_descriptor(tx.hive().root()).unwrap();
    let mut audit = KeyCreationAudit::default();
    assert!(matches!(
        prepare_key_creation_security(
            &subject,
            parent,
            None,
            2,
            ProcessorMode::UserMode,
            &mut audit
        ),
        Err(nt_security::STATUS_ACCESS_DENIED)
    ));
    assert!(!audit.parent_access.unwrap().granted());
    tx.commit();
    capture.release(&mut tokens).unwrap();
    assert_eq!(encode_image(&hive), before);
    assert_eq!(tokens.reference_count(primary), Some(1));
}

#[test]
fn assigned_child_commit_and_single_record_recovery_have_identical_security() {
    let mut hive = initial_hive();
    let mut recovered = initial_hive();
    let mut tokens = TokenStore::new();
    let primary = tokens.insert(AccessToken::admin(123));
    let mut capture = CapturedSubjectContext::capture(&mut tokens, primary, None, 0).unwrap();
    let subject = capture.resolve(&tokens).unwrap();
    let mut tx = hive.begin_transaction();
    let root = tx.hive().root();
    let parent = tx.hive().key_security_descriptor(root).unwrap();
    let creator = [
        1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0,
    ];
    let mut audit = KeyCreationAudit::default();
    let prepared = prepare_key_creation_security(
        &subject,
        parent,
        Some(&creator),
        2,
        ProcessorMode::UserMode,
        &mut audit,
    )
    .unwrap();
    assert_eq!(prepared.granted_access, 2);
    assert_eq!(audit.assignment, SecurityAssignmentAudit::default());
    assert!(audit.handle_security.is_none());
    let record = try_encode_log_record(
        &HiveLogOp::CreateChild {
            parent: "",
            name: "Child",
            class_name: Some("test"),
            descriptor: &prepared.descriptor,
        },
        10,
    )
    .unwrap();
    let child = tx
        .try_create_child(
            root,
            "Child".into(),
            Some("test".into()),
            prepared.descriptor,
        )
        .unwrap();
    tx.commit();
    assert_eq!(try_replay_log(&mut recovered, &record, 0), Ok(10));
    assert_eq!(encode_image(&hive), encode_image(&recovered));
    let sd =
        security_descriptor_bytes_for_access(hive.key_security_descriptor(child).unwrap()).unwrap();
    assert!(!subject
        .check_access(Some(&sd), 2, &KEY_GENERIC_MAPPING, ProcessorMode::UserMode)
        .granted());
    capture.release(&mut tokens).unwrap();
}

#[test]
fn abandoning_a_prepared_and_created_child_restores_all_parent_metadata() {
    let mut hive = initial_hive();
    let before = encode_image(&hive);
    let mut tokens = TokenStore::new();
    let primary = tokens.insert(AccessToken::admin(123));
    let mut capture = CapturedSubjectContext::capture(&mut tokens, primary, None, 0).unwrap();
    {
        let subject = capture.resolve(&tokens).unwrap();
        let mut tx = hive.begin_transaction();
        let root = tx.hive().root();
        let parent = tx.hive().key_security_descriptor(root).unwrap();
        let prepared = prepare_key_creation_security(
            &subject,
            parent,
            None,
            2,
            ProcessorMode::UserMode,
            &mut KeyCreationAudit::default(),
        )
        .unwrap();
        tx.try_create_child(root, "Child".into(), None, prepared.descriptor)
            .unwrap();
        // No commit: models failure before durable/handle publication, not rollback after COMMIT.
    }
    capture.release(&mut tokens).unwrap();
    assert_eq!(encode_image(&hive), before);
    assert_eq!(hive.dirty_count(), 0);
}
