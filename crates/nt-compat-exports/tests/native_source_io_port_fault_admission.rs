//! A GP on a hosted driver can use a live sibling PDO's port grant even when
//! the current PDO's cached channel capabilities contain no port resource.

#[test]
fn gp_port_decode_is_attempted_before_cached_channel_capability_admission() {
    let source = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    // Both pumps pass their currently retained Reply to the fault service.
    // The sibling-grant behavior is exercised by native_source_io_port_fault_grant.
    let call = "pump_service_io_port_fault(ch, ";
    let callsites: Vec<_> = source.match_indices(call).map(|(at, _)| at).collect();
    assert_eq!(callsites.len(), 2, "IRQ and ordinary pumps must both attempt I/O decode");

    for at in callsites {
        let branch_start = source[..at]
            .rfind("if label == 3")
            .expect("port fault call must be in a GP branch");
        let admission = &source[branch_start..at];
        assert!(
            !admission.contains("ch.caps.io_port_faults"),
            "a mouse PDO with no local port cap must reach the exact live grant selector: {admission}"
        );
    }
}
