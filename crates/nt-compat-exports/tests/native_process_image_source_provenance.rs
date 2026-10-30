//! Native bridge guard: a dynamic process retains the exact Section source evidence.

const BRIDGE: &str = include_str!("../../../components/ntos-executive/src/exec_image_process_create.rs");

#[test]
fn process_owner_captures_physical_file_and_observation_before_runtime_publication() {
    let source = syn::parse_file(BRIDGE).unwrap();
    let owner = source.items.iter().find_map(|item| match item {
        syn::Item::Struct(value) if value.ident == "ProcessImageOwner" => Some(value),
        _ => None,
    }).unwrap();
    assert!(owner.fields.iter().any(|field| field.ident.as_ref().is_some_and(|name| name == "source")));
    let physical = BRIDGE.find("source.backing.file.ok_or(INVALID_IMAGE)?").unwrap();
    let captured = BRIDGE.find("ProcessImageSourceEvidence::capture(").unwrap();
    let published = BRIDGE.find("register_hosted_process_runtime_for_image(image)").unwrap();
    assert!(physical < captured && captured < published);
    assert!(BRIDGE.contains("target, pid: None, view, source, mechanism_retired: false"));
}
