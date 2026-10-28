//! Installer stall evidence follows exact process ancestry and captured service metadata.

#[test]
fn installer_ancestor_uses_captured_service_observation() {
    let source = include_str!("../../../components/ntos-executive/src/exec_installer_progress.rs");
    let resolver = source
        .split("fn live_installer_owner_for_pi(")
        .nth(1)
        .expect("installer owner resolver");
    let resolver = resolver.split("/// Called only at the exact").next().unwrap();
    assert!(resolver.contains("capture_process_identity(ancestor_pi)"));
    assert!(resolver.contains("self.hosted_process_observation_role(ancestor_pi)"));
    assert!(!resolver.contains("self.hosted_process_role(ancestor_pi)"));
}
