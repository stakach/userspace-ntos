use super::*;
use crate::{
    AccessToken, CapturedClientToken, SecurityImpersonationLevel, TokenType, MAXIMUM_ALLOWED,
};

fn subject(token: &AccessToken) -> CapturedSubjectTokens<'_> {
    CapturedSubjectTokens {
        primary: token,
        client: None,
        process_audit_id: 7,
    }
}

fn empty_dacl() -> alloc::vec::Vec<u8> {
    alloc::vec![
        1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0
    ]
}

fn read_dacl() -> alloc::vec::Vec<u8> {
    let mut bytes = empty_dacl();
    bytes[22] = 28;
    bytes[24] = 1;
    bytes.extend_from_slice(&[0, 0, 20, 0]);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
    bytes
}

#[test]
fn existing_target_is_checked_and_maximum_allowed_is_not_generic_all() {
    let token = AccessToken::user(42);
    let subject = subject(&token);
    let decision = authorize_key_open(
        &subject,
        &read_dacl(),
        MAXIMUM_ALLOWED | 0x300,
        ProcessorMode::UserMode,
    )
    .unwrap();
    assert!(decision.granted());
    assert_eq!(decision.granted_access, 1);
    for desired in [2, MAXIMUM_ALLOWED | 2] {
        assert_eq!(
            authorize_key_open(&subject, &read_dacl(), desired, ProcessorMode::UserMode)
                .unwrap()
                .status,
            STATUS_ACCESS_DENIED
        );
    }
    assert_eq!(
        authorize_key_open(&subject, &empty_dacl(), 1, ProcessorMode::UserMode)
            .unwrap()
            .status,
        STATUS_ACCESS_DENIED
    );
}

#[test]
fn ordinary_open_preserves_privilege_use_when_dacl_denies_remainder() {
    let mut token = AccessToken::system();
    token
        .privileges
        .iter_mut()
        .find(|p| p.name == crate::SE_SECURITY)
        .unwrap()
        .enabled = true;
    for (desired, status) in [
        (ACCESS_SYSTEM_SECURITY, 0),
        (ACCESS_SYSTEM_SECURITY | 2, STATUS_ACCESS_DENIED),
    ] {
        let decision = authorize_key_open(
            &subject(&token),
            &empty_dacl(),
            desired,
            ProcessorMode::UserMode,
        )
        .unwrap();
        assert_eq!(decision.status, status);
        assert_eq!(decision.privileges_used.as_slice(), &[crate::SE_SECURITY]);
    }
}

#[test]
fn backup_restore_grants_only_enabled_privilege_rights_and_audits_both_checks() {
    for (backup, restore) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut token = AccessToken::system();
        for (name, enabled) in [(crate::SE_BACKUP, backup), (crate::SE_RESTORE, restore)] {
            token
                .privileges
                .iter_mut()
                .find(|p| p.name == name)
                .unwrap()
                .enabled = enabled;
        }
        let audit = authorize_key_backup_restore(&subject(&token), ProcessorMode::UserMode);
        assert_eq!(
            audit.status,
            if backup || restore {
                0
            } else {
                STATUS_ACCESS_DENIED
            }
        );
        assert_eq!(
            audit.backup,
            KeyHandleSecurityAudit {
                granted: backup,
                attributes: if backup { 0x8000_0000 } else { 0 }
            }
        );
        assert_eq!(
            audit.restore,
            KeyHandleSecurityAudit {
                granted: restore,
                attributes: if restore { 0x8000_0000 } else { 0 }
            }
        );
        assert_eq!(
            audit.granted_access,
            (if backup { 0x0102_0019 } else { 0 }) | (if restore { 0x010e_0006 } else { 0 })
        );
    }
}

#[test]
fn backup_creation_bypasses_parent_dacl_but_not_descriptor_assignment() {
    let mut token = AccessToken::system();
    token
        .privileges
        .iter_mut()
        .find(|p| p.name == crate::SE_BACKUP)
        .unwrap()
        .enabled = true;
    let mut audit = KeyBackupRestoreCreationAudit::default();
    let prepared = prepare_key_backup_restore_creation_security(
        &subject(&token),
        &empty_dacl(),
        Some(&empty_dacl()),
        ProcessorMode::UserMode,
        &mut audit,
    )
    .unwrap();
    assert_eq!(prepared.granted_access, 0x0102_0019);
    assert_eq!(
        authorize_key_open(
            &subject(&token),
            &prepared.descriptor,
            1,
            ProcessorMode::UserMode
        )
        .unwrap()
        .status,
        STATUS_ACCESS_DENIED
    );
    assert!(prepare_key_backup_restore_creation_security(
        &subject(&token),
        &empty_dacl(),
        Some(&[1]),
        ProcessorMode::UserMode,
        &mut audit
    )
    .is_err());
    assert!(audit.privileges.unwrap().backup.granted);
}

#[test]
fn failed_backup_privileges_stop_before_assignment() {
    let token = AccessToken::user(42);
    let mut audit = KeyBackupRestoreCreationAudit::default();
    assert!(matches!(
        prepare_key_backup_restore_creation_security(
            &subject(&token),
            &[1],
            Some(&[1]),
            ProcessorMode::UserMode,
            &mut audit
        ),
        Err(STATUS_ACCESS_DENIED)
    ));
    assert_eq!(audit.assignment, SecurityAssignmentAudit::default());
    assert_eq!(audit.privileges.unwrap().granted_access, 0);
}

#[test]
fn backup_privileges_use_the_captured_client_not_the_primary() {
    let mut primary = AccessToken::system();
    primary
        .privileges
        .iter_mut()
        .find(|p| p.name == crate::SE_BACKUP)
        .unwrap()
        .enabled = true;
    let client = AccessToken::user(42)
        .duplicate(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            false,
        )
        .unwrap();
    let captured = CapturedSubjectTokens {
        primary: &primary,
        client: Some(CapturedClientToken {
            token: &client,
            level: SecurityImpersonationLevel::Impersonation,
        }),
        process_audit_id: 7,
    };
    assert_eq!(
        authorize_key_backup_restore(&captured, ProcessorMode::UserMode).status,
        STATUS_ACCESS_DENIED
    );
    assert!(authorize_key_open(&captured, &[], 1, ProcessorMode::UserMode).is_err());
}

#[test]
fn kernel_open_bypass_differs_from_backup_privilege_captured_level_checks() {
    let primary = AccessToken::system();
    let client = AccessToken::user(42)
        .duplicate(
            TokenType::Impersonation,
            SecurityImpersonationLevel::Impersonation,
            false,
        )
        .unwrap();
    let captured = CapturedSubjectTokens {
        primary: &primary,
        client: Some(CapturedClientToken {
            token: &client,
            level: SecurityImpersonationLevel::Identification,
        }),
        process_audit_id: 7,
    };
    let decision = authorize_key_open(
        &captured,
        &[],
        MAXIMUM_ALLOWED | 0x300,
        ProcessorMode::KernelMode,
    )
    .unwrap();
    assert_eq!(decision.granted_access, KEY_GENERIC_MAPPING.generic_all);
    assert!(decision.privileges_used.is_empty());
    assert_eq!(
        authorize_key_backup_restore(&captured, ProcessorMode::KernelMode).status,
        STATUS_ACCESS_DENIED
    );
    let audit = authorize_key_backup_restore(&subject(&primary), ProcessorMode::KernelMode);
    assert_eq!(audit.status, 0);
    assert_eq!(audit.backup.attributes, 0);
    assert_eq!(audit.restore.attributes, 0);
}
