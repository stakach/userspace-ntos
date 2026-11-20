//! #417: symbolic link keys in the runtime (HARDWARE) registry follow CmpParseKey's rules.

use nt_config_manager::{Registry, RegistryLinkWalk, RegistryValueType};

const TARGET: &str = r"\Registry\Machine\HARDWARE\DESCRIPTION\System";

fn link_data(target: &str) -> Vec<u8> {
    target.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn registry_with_link() -> (Registry, u64, u64) {
    let mut registry = Registry::new();
    let parent = registry.create_key(r"\Registry\Machine\HARDWARE\DEVICEMAP");
    let generation = registry.generation(parent).unwrap();
    let descriptor = nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR;
    let link = registry
        .create_secured_link_checked(r"\Registry\Machine\HARDWARE\DEVICEMAP\Link", &descriptor,
            true, parent, generation, None)
        .unwrap();
    (registry, parent, link)
}

#[test]
fn a_runtime_link_is_created_once_and_holds_only_its_target() {
    let (mut registry, parent, link) = registry_with_link();
    assert!(registry.is_symbolic_link(link));
    assert!(registry.is_volatile(link));
    let generation = registry.generation(parent).unwrap();
    let descriptor = nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR;
    assert_eq!(
        registry.create_secured_link_checked(r"\Registry\Machine\HARDWARE\DEVICEMAP\Link",
            &descriptor, true, parent, generation, None),
        Err(0xC000_0035),
        "an existing key collides"
    );
    assert_eq!(
        registry.create_secured_key(r"\Registry\Machine\HARDWARE\DEVICEMAP\Link\Child", &descriptor, true),
        Err(0xC000_0022),
        "a link key has no children"
    );
    assert!(registry.link_value_allowed(link, "symboliclinkvalue", RegistryValueType::Link as u32));
    assert!(!registry.link_value_allowed(link, "SymbolicLinkValue", RegistryValueType::Sz as u32));
    assert!(!registry.link_value_allowed(link, "Other", RegistryValueType::Link as u32));
    assert!(registry.link_value_allowed(parent, "Other", RegistryValueType::Sz as u32));
}

#[test]
fn a_runtime_walk_reparses_through_a_link() {
    let (mut registry, parent, link) = registry_with_link();
    let root = registry.open_key(r"\Registry").unwrap();
    let path = r"Machine\HARDWARE\DEVICEMAP\Link";
    assert_eq!(registry.walk_following_links(root, path, false),
        Err(nt_config_manager::symbolic_link::SymbolicLinkError::NoTarget));
    assert!(registry.set_value(link, "SymbolicLinkValue", RegistryValueType::Link, link_data(TARGET)));
    assert_eq!(registry.walk_following_links(root, path, false),
        Ok(RegistryLinkWalk::Reparse(TARGET.into())));
    assert_eq!(registry.walk_following_links(parent, r"Link\Child", false),
        Ok(RegistryLinkWalk::Reparse(format!(r"{TARGET}\Child"))));
    assert_eq!(registry.walk_following_links(root, path, true), Ok(RegistryLinkWalk::Found(link)));
    assert_eq!(registry.walk_following_links(root, r"Machine\Missing", false),
        Ok(RegistryLinkWalk::NotFound { last: true }));
    assert_eq!(registry.walk_following_links(root, r"Machine\Missing\Child", false),
        Ok(RegistryLinkWalk::NotFound { last: false }));
}
