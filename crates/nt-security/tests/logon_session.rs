use nt_security::{
    AccessToken, LogonSessionRegistry, Luid, TokenStore,
    STATUS_BAD_LOGON_SESSION_STATE, STATUS_LOGON_SESSION_EXISTS,
    STATUS_NO_SUCH_LOGON_SESSION,
};

#[test]
fn srm_create_and_delete_track_real_session_state() {
    let mut sessions = LogonSessionRegistry::new();
    let tokens = TokenStore::new();
    let id = Luid::new(0x4a2b);

    assert!(!sessions.contains(id));
    assert_eq!(sessions.create(id), Ok(()));
    assert!(sessions.contains(id));
    assert_eq!(sessions.create(id), Err(STATUS_LOGON_SESSION_EXISTS));
    assert_eq!(sessions.delete(id, &tokens), Ok(()));
    assert!(!sessions.contains(id));
    assert_eq!(sessions.delete(id, &tokens), Err(STATUS_NO_SUCH_LOGON_SESSION));
}

#[test]
fn srm_delete_respects_token_references_and_builtin_sessions() {
    let mut sessions = LogonSessionRegistry::new();
    let mut tokens = TokenStore::new();
    let id = Luid::new(0x4a2c);
    sessions.create(id).unwrap();

    let mut token = AccessToken::user(0x1234);
    token.authentication_id = id;
    let token_id = tokens.insert(token);
    assert_eq!(sessions.delete(id, &tokens), Err(STATUS_BAD_LOGON_SESSION_STATE));
    assert!(sessions.contains(id));

    tokens.release(token_id).unwrap();
    assert_eq!(sessions.delete(id, &tokens), Ok(()));
    assert_eq!(sessions.delete(Luid::new(0x3e7), &tokens),
        Err(STATUS_BAD_LOGON_SESSION_STATE));
    assert_eq!(sessions.delete(Luid::new(0x3e6), &tokens),
        Err(STATUS_BAD_LOGON_SESSION_STATE));
}
