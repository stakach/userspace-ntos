//! An unowned synchronous routed metadata query is only valid on the inline Boot route.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/exec_section_create.rs");
const NAMES: &str = include_str!("../../../components/ntos-executive/src/exec_named_data_sections.rs");
const BROKER: &str = include_str!("../../../components/ntos-executive/src/provider_section_broker.rs");

#[test]
fn routed_section_metadata_without_a_retained_admission_is_boot_only() {
    let reserve = SOURCE.split("fn reserve_generic_data_section(").nth(1).unwrap();
    let routed = reserve.split("HandleObject::RoutedFile { file_id, device_id } => {").nth(1).unwrap()
        .split("_ => return Err(STATUS_INVALID_FILE_FOR_SECTION)").next().unwrap();
    let after_admission = routed.split("if let Some(admission) = routed_admission.take()").nth(1).unwrap();
    let fallback = after_admission.split("} else {").nth(1).unwrap()
        .split("(capture, metadata)").next().unwrap();
    assert!(fallback.contains("boot_inline_read_admitted(mount)"),
        "native routed metadata must enter a retained owner before IRP dispatch");
    assert!(fallback.find("boot_inline_read_admitted(mount)").unwrap()
        < fallback.find("routed_section_io::query_metadata").unwrap());

    assert!(NAMES.contains("section_metadata_work::submit_hosted_data"),
        "named routed Section creation must retain its metadata Reply");
    assert!(BROKER.contains("RoutedSectionAdmission"),
        "provider Section creation must transfer exact metadata into reservation");
}
