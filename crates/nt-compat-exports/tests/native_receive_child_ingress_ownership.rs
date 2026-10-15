const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn outer_resume_cannot_select_a_child_after_an_unrelated_delivery_is_received() {
    let loop_start = SERVICE
        .find("'service_loop: loop {")
        .expect("hosted service loop");
    let selected_child = SERVICE[loop_start..]
        .find("let observed = crate::spawn_hosts::shared_ingress::owner::runtime::receive_child_observation(")
        .map(|offset| loop_start + offset)
        .expect("exact selected child observation");
    let current_delivery = SERVICE[..selected_child]
        .rfind("let native_ingress_request = nt_syscall_abi::NativeSyscallRequest::capture(")
        .expect("current delivery captured before admission");
    let live_ingress = SERVICE[current_delivery..selected_child]
        .rfind("// Complete durable publications and filesystem checkpoints before accepting the next")
        .map(|offset| current_delivery + offset)
        .expect("live ingress publication boundary");
    let current_owner_window = &SERVICE[live_ingress..selected_child];
    assert!(current_owner_window.contains("receive_child_is_current("));
    assert!(!current_owner_window.contains("component_resume::run_outer("),
        "outer resume may create a different Receive child while this delivery still owns its Reply and message");

    let boundary = &SERVICE[loop_start..current_delivery];
    assert!(boundary.contains("component_resume::run_outer(core::ptr::from_mut(&mut *nt_handler));"),
        "outer resume remains available before the next delivery is received");
}
