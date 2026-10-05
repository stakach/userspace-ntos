#[test]
fn committed_private_faults_share_the_canonical_copy_and_lock_residency_service() {
    let root = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let handler = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    assert!(
        root.contains("service_committed_private_page_residency"),
        "root VMFault must service canonical committed private backing instead of falling through image lookup"
    );
    assert!(
        handler.contains("ensure_private_page_residency"),
        "copy and lock must share the focused private backing service"
    );
    let focused = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/exec_private_residency.rs"
    ))
    .expect("focused canonical private residency module");
    assert!(focused.contains("ResidentMappingRevalidation"));
    assert!(focused.contains("MemoryLifetime::Process"));
    assert!(focused.contains("plan_private_read_fault"));
    assert!(!focused.contains("csrss_frame_get_exact"), "numeric PI/page lookup alone does not prove preserved backing authority");
}
