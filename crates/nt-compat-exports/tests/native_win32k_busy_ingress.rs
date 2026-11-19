//! A returned Receive frame may still own the shared win32k publication after its physical
//! lane parks. The next hosted Call must keep its original message and Reply until admission.

fn source(name: &str) -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src")
            .join(name),
    ).unwrap()
}

#[test]
fn busy_page_keeps_undelivered_win32k_call_in_its_original_owner() {
    let hosted = source("component_ingress_hosted.rs");
    let classifier = hosted.split("fn is_win32k_native_call(").nth(1).unwrap();
    let classifier = classifier.split('}').next().unwrap();
    assert!(classifier.contains("NT_NATIVE_SYSCALL_LABEL"),
        "ordinary fault ingress must remain independently deliverable");
    assert!(classifier.contains("WIN32K_SERVICE_BASE"),
        "use the same shadow-table boundary as native dispatch");
}

