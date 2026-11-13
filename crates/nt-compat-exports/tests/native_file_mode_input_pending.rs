//! A routed FileModeInformation input page may pend before the File mutation begins.

const MODE: &str = include_str!("../../../components/ntos-executive/src/exec_file_mode.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const SECTION: &str = include_str!("../../../components/ntos-executive/src/section_pagein_work.rs");
const IMAGE: &str = include_str!("../../../components/ntos-executive/src/native_image_pagein_work.rs");

#[test]
fn routed_file_mode_input_waits_for_exact_page_completion_before_terminal_publication() {
    // The old synchronous helper converts a routed Section page-in into a resource error. Keep
    // the original FileMode call and its IOSB under an explicit Pending admission instead.
    let entry = MODE.split_once("pub(super) unsafe fn try_set_file_mode_information(")
        .expect("FileMode native entry").1;
    assert!(!entry.contains("self.capture_file_mode_input(input, length)"),
        "the native entry cannot finish input capture before routed Pending completes");
    assert!(SERVICE.contains("redrive_file_mode_input(")
        && SERVICE.contains("file_mode_input_page_completed(")
        && SERVICE.contains("submit_for_file_mode_input("),
        "native ingress must retain the original Call until exact input page completion");
    assert!(SECTION.contains("RoutedFileModeInput"),
        "Section completion must return to the exact FileMode input owner");
    assert!(IMAGE.contains("RoutedFileModeInput"),
        "image completion must return to the exact FileMode input owner");
}
