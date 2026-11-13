//! A retained provider MAP reads a bounded window, then publishes each page
//! from the acknowledged staging bytes into the unpublished map.

use std::fs;

#[test]
fn provider_map_dispatches_a_window_and_selects_each_acknowledged_page() {
    let source = fs::read_to_string(format!(
        "{}/../../components/ntos-executive/src/provider_section_map_work.rs",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();

    let body: String = source.chars().filter(|character| !character.is_whitespace()).collect();

    // Native wiring must use the crate's eight-page limit. The previous
    // one-page request made a font map wait for one completion per page.
    assert!(
        body.contains("work.file_size,(prepared.pages-work.page).min(8),"),
        "provider MAP must batch up to eight pages without reading beyond the prepared view"
    );
    // The completed window remains staged until strict ACK, and each page
    // selects its own 4 KiB slice before publication.
    assert!(body.contains("acknowledge_completed_irp_strict"));
    assert!(body.contains("take_acknowledged_if"));
    assert!(body.contains("plan.page_bytes(work.pageasu64,bytes)"));
}
