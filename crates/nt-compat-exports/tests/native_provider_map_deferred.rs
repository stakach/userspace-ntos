//! A provider kernel Section MAP must retain its Reply and pending read until
//! exact completion, instead of converting Pending into a failed font page.

use std::fs;

fn source(path: &str) -> String {
    fs::read_to_string(format!(
        "{}/../../components/ntos-executive/src/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn provider_map_has_an_owned_deferred_read_boundary() {
    let service = source("service_sec_image.rs");
    let work = source("provider_section_map_work.rs");
    let objects = source("provider_mm_section_objects.rs");
    assert!(service.contains("provider_section_map_work::submit("));
    assert!(work.contains("park_retained_service("));
    assert!(work.contains("PendingSectionPageReads"));
    assert!(work.contains("completed_irp_exact("));
    assert!(work.contains("copy_completed_irp_output_exact("));
    assert!(work.contains("acknowledge_completed_irp_strict("));
    assert!(work.contains("take_acknowledged_if("));
    assert!(objects.contains("pub(crate) unsafe fn prepare_map("));
    assert!(objects.contains("pub(crate) unsafe fn publish_map("));
    assert!(objects.contains("pub(crate) unsafe fn abort_map("));
}
