const WIN32K: &str = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const EXEC: &str = include_str!("../../../components/ntos-executive/src/exec_named_events.rs");

#[test]
fn win32k_named_event_create_preserves_root_name_and_security_descriptor() {
    let create = WIN32K
        .split("fn s_zw_create_event(")
        .nth(1)
        .expect("win32k ZwCreateEvent import")
        .split("fn s_zw_close(")
        .next()
        .unwrap();
    assert!(!create.contains("STATUS_NOT_SUPPORTED until named provider creates are brokered"));
    assert!(create.contains("create_named_event"),
        "named OBJECT_ATTRIBUTES must be captured and brokered before any create effect");
    assert!(SERVICE.contains("provider_create_named_event"),
        "executive must resolve the exact RootDirectory and creator security before publication");
}

#[test]
fn win32k_event_reference_and_close_follow_the_attached_handle_table() {
    let reference = SERVICE
        .split("W32_EVENT_OP_REFERENCE =>")
        .nth(1)
        .expect("win32k Event reference route")
        .split("W32_EVENT_OP_CLOSE =>")
        .next()
        .unwrap();
    assert!(reference.contains("resolve_win32k_event_handle_pi(handler, channel, pi)"),
        "the referenced handle belongs to the active attached process, not the original caller");
    let close = SERVICE
        .split("W32_EVENT_OP_CLOSE =>")
        .nth(1)
        .expect("win32k Event close route")
        .split("W32_EVENT_OP_DEREFERENCE =>")
        .next()
        .unwrap();
    assert!(close.contains("resolve_win32k_event_handle_pi(handler, channel, pi)"),
        "close must use the same attached process handle table as reference");
}

#[test]
fn named_event_executive_rejects_unrepresentable_unicode() {
    assert!(EXEC.contains("u8::try_from(unit).map_err(|_| BAD_NAME)?"),
        "event names must fail before publication if the object namespace cannot represent a UTF-16 unit");
    assert!(!EXEC.contains("(unit as u8)"),
        "truncation can alias a different named event");
}
