use nt_security::{
    prepare_object_creation_grant, AccessToken, CapturedClientToken, CapturedSubjectTokens,
    ObjectCreationPrivilegeAudit, ProcessorMode, SecurityImpersonationLevel, TokenType,
    ACCESS_SYSTEM_SECURITY, DIRECTORY_GENERIC_MAPPING, GENERIC_READ, MAXIMUM_ALLOWED,
    SECTION_GENERIC_MAPPING, SE_PRIVILEGE_USED_FOR_ACCESS, STATUS_PRIVILEGE_NOT_HELD,
};

fn subject(token: &AccessToken) -> CapturedSubjectTokens<'_> {
    CapturedSubjectTokens {
        primary: token,
        client: None,
        process_audit_id: 29,
    }
}

#[test]
fn new_object_grant_maps_maximum_allowed_by_actual_object_type() {
    let token = AccessToken::user(29);
    for (mapping, expected) in [
        (&SECTION_GENERIC_MAPPING, 0xf001f),
        (&DIRECTORY_GENERIC_MAPPING, 0xf000f),
    ] {
        let mut audit = None;
        let granted = prepare_object_creation_grant(
            &subject(&token),
            MAXIMUM_ALLOWED,
            mapping,
            ProcessorMode::UserMode,
            &mut audit,
        )
        .unwrap();
        assert_eq!(granted, expected);
        assert_eq!(audit, None);
        let granted = prepare_object_creation_grant(
            &subject(&token),
            GENERIC_READ,
            mapping,
            ProcessorMode::UserMode,
            &mut audit,
        )
        .unwrap();
        assert_eq!(granted, mapping.generic_read);
    }
}

#[test]
fn security_privilege_denial_and_actual_use_are_retained_in_audit() {
    for enabled in [false, true] {
        let mut token = AccessToken::system();
        token
            .privileges
            .iter_mut()
            .find(|privilege| privilege.name == nt_security::SE_SECURITY)
            .unwrap()
            .enabled = enabled;
        let mut audit = None;
        let result = prepare_object_creation_grant(
            &subject(&token),
            MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY,
            &SECTION_GENERIC_MAPPING,
            ProcessorMode::UserMode,
            &mut audit,
        );
        assert_eq!(
            result,
            if enabled {
                Ok(0xf001f | ACCESS_SYSTEM_SECURITY)
            } else {
                Err(STATUS_PRIVILEGE_NOT_HELD)
            }
        );
        assert_eq!(
            audit,
            Some(ObjectCreationPrivilegeAudit {
                granted: enabled,
                attributes: if enabled {
                    SE_PRIVILEGE_USED_FOR_ACCESS
                } else {
                    0
                },
            })
        );
    }
}

#[test]
fn kernel_bypass_grants_without_claiming_privilege_used_and_audit_resets() {
    let token = AccessToken::user(29);
    let mut audit = Some(ObjectCreationPrivilegeAudit {
        granted: false,
        attributes: 77,
    });
    let result = prepare_object_creation_grant(
        &subject(&token),
        ACCESS_SYSTEM_SECURITY,
        &DIRECTORY_GENERIC_MAPPING,
        ProcessorMode::KernelMode,
        &mut audit,
    );
    assert_eq!(result, Ok(ACCESS_SYSTEM_SECURITY));
    assert_eq!(
        audit,
        Some(ObjectCreationPrivilegeAudit {
            granted: true,
            attributes: 0
        })
    );
    assert_eq!(
        prepare_object_creation_grant(
            &subject(&token),
            0,
            &SECTION_GENERIC_MAPPING,
            ProcessorMode::UserMode,
            &mut audit
        ),
        Ok(0)
    );
    assert_eq!(audit, None);
    assert_eq!(
        prepare_object_creation_grant(
            &subject(&token),
            ACCESS_SYSTEM_SECURITY,
            &SECTION_GENERIC_MAPPING,
            ProcessorMode::UserMode,
            &mut audit
        ),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    );
    assert_eq!(
        prepare_object_creation_grant(
            &subject(&token),
            4,
            &SECTION_GENERIC_MAPPING,
            ProcessorMode::UserMode,
            &mut audit
        ),
        Ok(4)
    );
    assert_eq!(audit, None);
}

#[test]
fn captured_low_client_level_precedes_kernel_privilege_bypass() {
    let primary = AccessToken::system();
    let client = AccessToken::system()
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
        process_audit_id: 29,
    };
    let mut audit = None;
    assert_eq!(
        prepare_object_creation_grant(
            &captured,
            ACCESS_SYSTEM_SECURITY,
            &SECTION_GENERIC_MAPPING,
            ProcessorMode::KernelMode,
            &mut audit
        ),
        Err(STATUS_PRIVILEGE_NOT_HELD)
    );
    assert_eq!(
        audit,
        Some(ObjectCreationPrivilegeAudit {
            granted: false,
            attributes: 0
        })
    );
}
