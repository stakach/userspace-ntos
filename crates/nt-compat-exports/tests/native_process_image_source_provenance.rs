//! Native bridge guard: a dynamic process retains the exact Section source evidence.

const BRIDGE: &str = include_str!("../../../components/ntos-executive/src/exec_image_process_create.rs");

#[test]
fn process_owner_captures_section_file_and_registered_alias_before_runtime_publication() {
    let source = syn::parse_file(BRIDGE).unwrap();
    let owner = source.items.iter().find_map(|item| match item {
        syn::Item::Struct(value) if value.ident == "ProcessImageOwner" => Some(value),
        _ => None,
    }).unwrap();
    assert!(owner.fields.iter().any(|field| field.ident.as_ref().is_some_and(|name| name == "source")));
    let section = BRIDGE.find("source.backing.file.ok_or(INVALID_IMAGE)?").unwrap();
    let alias = BRIDGE.find("source.registered_file").unwrap();
    let captured = BRIDGE.find("ProcessImageSourceEvidence::capture_with_registered_file(").unwrap();
    let published = BRIDGE.find("register_hosted_process_runtime_for_image(image)").unwrap();
    assert!(section < alias && alias < captured && captured < published);
    assert!(BRIDGE.contains("image, section_file, registered_file, observation_target"));
    assert!(BRIDGE.contains("target, pid: None, view, source, mechanism_retired: false"));
}

#[test]
fn registered_alias_flows_from_exact_live_device_without_replacing_routed_section_file() {
    let metadata = include_str!("../../../components/ntos-executive/src/section_metadata_work.rs");
    let section = include_str!("../../../components/ntos-executive/src/exec_image_section_create.rs");
    let source = include_str!("../../../components/ntos-executive/src/native_image_sections.rs");
    for text in [metadata, section, source] { syn::parse_file(text).unwrap(); }
    assert!(metadata.contains("physical_exec_file_alias(\n                                    capture.device_id(), metadata.file"),
        "policy alias must use the captured FILE_OBJECT device and queried File identity");
    assert!(metadata.contains("observation_for_backing(file)"));
    assert!(metadata.contains("work.registered_file = physical_file"));
    assert!(metadata.contains("registered_file: work.registered_file"));
    assert!(section.contains("admission.metadata.file"));
    assert!(section.contains("admission.registered_file"));
    assert!(section.contains("GenericSectionBacking::routed(\n                            lease,\n                            file_identity,"),
        "routed Section I/O must keep the original File identity");
    assert!(source.contains("pub(crate) registered_file: Option<SectionFileIdentity>"));
}
