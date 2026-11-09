//! The outer service loop must run a retained CONNECT child after its File frames unwind.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn root_claims_and_runs_one_connect_child_before_other_provider_work() {
    let maintenance = SERVICE
        .split_once("crate::driver_launch::redrive_hosted_connect_forward();")
        .expect("CONNECT redrive in outer service loop")
        .1
        .split_once("crate::driver_launch::redrive_hosted_hook_forward();")
        .expect("HOOK redrive after CONNECT")
        .0;
    let claim = maintenance
        .find("claim_suspended_port_connect_pump()")
        .expect("claim exact suspended CONNECT before child work");
    let child = maintenance
        .find("drive_one_nested_file_child_step()")
        .expect("one child step after File frames unwind");
    let resume = maintenance
        .find("redrive_suspended_connect_pump(")
        .expect("resume the exact CONNECT continuation");
    assert!(claim < child && child < resume);
}

#[test]
fn unresolved_connect_parent_fences_later_provider_work() {
    let maintenance = SERVICE
        .split_once("crate::driver_launch::redrive_hosted_connect_forward();")
        .expect("CONNECT redrive in outer service loop")
        .1
        .split_once("crate::driver_launch::redrive_hosted_hook_forward();")
        .expect("HOOK redrive after CONNECT")
        .0;
    let gate = maintenance
        .find("unsettled_suspended_connect_pump()")
        .expect("unresolved parked CONNECT must fence later providers");
    let stop = maintenance[gate..]
        .find("break 'service_loop")
        .expect("unresolved parent cannot admit unrelated provider work");
    assert!(stop > 0);
}

#[test]
fn repeated_yield_without_a_child_cannot_spin_the_root_loop() {
    let maintenance = SERVICE
        .split_once("claim_suspended_port_connect_pump()")
        .expect("root must claim a parked CONNECT")
        .1
        .split_once("unsettled_suspended_connect_pump()")
        .expect("root must fence parked CONNECT before other providers")
        .0;
    assert!(maintenance.contains("consecutive_no_child_yields"));
    assert!(maintenance.contains("break 'service_loop"));
}
