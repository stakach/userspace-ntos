use nt_hive_core::{
    compose_system_hive_overlay_secured, decode_image, encode_image, Hive, HiveKind,
};
use nt_security::{
    assign_registry_root_security, prepare_key_creation_security, AccessToken,
    CapturedSubjectTokens, KeyCreationAudit, ProcessorMode, SecurityAssignmentAudit,
};

fn subject(token: &AccessToken) -> CapturedSubjectTokens<'_> {
    CapturedSubjectTokens { primary: token, client: None, process_audit_id: 0 }
}

fn root_descriptor(token: &AccessToken) -> Vec<u8> {
    assign_registry_root_security(&subject(token), &mut SecurityAssignmentAudit::default())
        .expect("valid native root security")
}

fn inherited(parent: &[u8]) -> Vec<u8> {
    prepare_key_creation_security(
        &subject(&AccessToken::system()), parent, None, 2, ProcessorMode::KernelMode,
        &mut KeyCreationAudit::default(),
    ).expect("canonical NT container inheritance").descriptor
}

fn system() -> Hive {
    let mut hive = Hive::new(HiveKind::System);
    let select = hive.create_key("Select");
    assert!(hive.set_dword(select, "Current", 1));
    hive.create_key("ControlSet001");
    hive
}

fn imported_base() -> Hive {
    let mut base = system();
    let descriptor = root_descriptor(&AccessToken::system());
    for path in ["", "Select", "ControlSet001"] {
        let key = if path.is_empty() { base.root() } else { base.open_key(path).unwrap() };
        assert!(base.set_key_security_descriptor(key, &descriptor));
    }
    decode_image(&encode_image(&base)).expect("import persistent native descriptors")
}

#[test]
fn generated_nested_keys_receive_actual_nt_inheritance() {
    let base = imported_base();
    let mut overlay = system();
    overlay.create_key(r"ControlSet001\Services\Generated\Parameters");
    let composed = compose_system_hive_overlay_secured(&base, &overlay).unwrap();
    let mut parent = composed.open_key("ControlSet001").unwrap();
    for path in [
        r"ControlSet001\Services",
        r"ControlSet001\Services\Generated",
        r"ControlSet001\Services\Generated\Parameters",
    ] {
        let expected = inherited(composed.key_security_descriptor(parent).unwrap());
        let child = composed.open_key(path).unwrap();
        assert_eq!(composed.key_security_descriptor(child), Some(expected.as_slice()), "{path}");
        parent = child;
    }
    assert!(base.open_key(r"ControlSet001\Services").is_none());
}

#[test]
fn imported_and_explicit_security_remain_authoritative() {
    let mut base = imported_base();
    let existing = base.create_key(r"ControlSet001\Existing");
    let preserved = root_descriptor(&AccessToken::admin(123));
    assert!(base.set_key_security_descriptor(existing, &preserved));
    let mut overlay = system();
    overlay.create_key(r"ControlSet001\Existing\Generated");
    let explicit = overlay.create_key(r"ControlSet001\Explicit");
    let explicit_sd = root_descriptor(&AccessToken::admin(456));
    assert!(overlay.set_key_security_descriptor(explicit, &explicit_sd));
    overlay.create_key(r"ControlSet001\Explicit\Child");
    let composed = compose_system_hive_overlay_secured(&base, &overlay).unwrap();
    for (path, descriptor) in [
        (r"ControlSet001\Existing", preserved.as_slice()),
        (r"ControlSet001\Explicit", explicit_sd.as_slice()),
    ] {
        assert_eq!(composed.key_security_descriptor(composed.open_key(path).unwrap()), Some(descriptor));
    }
    for (path, descriptor) in [
        (r"ControlSet001\Existing\Generated", inherited(&preserved)),
        (r"ControlSet001\Explicit\Child", inherited(&explicit_sd)),
    ] {
        assert_eq!(composed.key_security_descriptor(composed.open_key(path).unwrap()), Some(descriptor.as_slice()));
    }
}

#[test]
fn absent_parent_security_fails_closed_without_mutating_inputs() {
    let base = system();
    let mut overlay = system();
    overlay.create_key(r"ControlSet001\Generated");
    let before = encode_image(&base);
    assert!(compose_system_hive_overlay_secured(&base, &overlay).is_err());
    assert_eq!(encode_image(&base), before);
}

#[test]
fn malformed_parent_security_fails_closed_without_mutating_inputs() {
    let mut base = imported_base();
    let parent = base.open_key("ControlSet001").unwrap();
    assert!(base.set_key_security_descriptor(parent, &[1, 0, 4]));
    let mut overlay = system();
    overlay.create_key(r"ControlSet001\Generated\Child");
    let before = encode_image(&base);
    assert!(compose_system_hive_overlay_secured(&base, &overlay).is_err());
    assert_eq!(encode_image(&base), before);
}

#[test]
fn malformed_explicit_security_is_not_published() {
    let base = imported_base();
    let mut overlay = system();
    let child = overlay.create_key(r"ControlSet001\Generated");
    assert!(overlay.set_key_security_descriptor(child, &[1, 0, 4]));
    assert!(compose_system_hive_overlay_secured(&base, &overlay).is_err());
}
