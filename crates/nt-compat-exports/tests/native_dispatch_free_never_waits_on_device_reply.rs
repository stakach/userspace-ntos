//! ExFreePool runs at DISPATCH_LEVEL on a hosted driver's IRQ lane (a DPC completing an SRB).
//! The component's device-reply lock is held by a PASSIVE lane across a root Call (for example
//! IoGetDeviceProperty). Root cannot answer that Call while it is driving the DPC, and every
//! hosted thread shares root's processor below root's priority, so a DPC that waits for that
//! lock yields forever (boot 44963863150: storahci's DPC spun in `s_ex_free_pool` while its
//! primary lane was inside IoGetDeviceProperty for the second AHCI controller).

#[path = "support/executive_call_graph.rs"]
mod executive_call_graph;

use executive_call_graph::{chain, executive_functions};

#[test]
fn a_dispatch_level_pool_free_never_waits_on_the_device_reply_lock() {
    let functions = executive_functions();
    assert!(functions.0.contains_key("component_device_reply_lock"),
        "the device-reply lock this test guards against still exists");
    for free in ["s_ex_free_pool", "s_ex_free_pool_tag"] {
        // The hosted kernel-driver export (win32k's provider pool has its own export).
        assert_eq!(chain(&functions, "driver_launch.rs", free, "component_device_reply_lock"), None,
            "{free} can run on a DPC while a PASSIVE lane holds the device-reply lock across a \
             root Call that root cannot answer until the DPC returns");
    }
}

#[test]
fn a_dpc_is_admitted_only_when_no_lane_holds_the_device_reply_lock() {
    // nt-hosted-runtime device_reply_lock proves the admission and release-wake policy; this pins
    // that the native DPC dispatch and the component guard use it.
    let functions = executive_functions();
    let calls = |file: &str, name: &str| functions.0.get(name).into_iter().flatten()
        .filter(|(f, _)| f == file)
        .flat_map(|(_, calls)| calls.iter().map(|(_, callee)| callee.clone()))
        .collect::<Vec<_>>();
    assert!(calls("hosted_irq_broker.rs", "dispatch_next_dpc").iter()
        .any(|call| call == "hosted_device_reply_dpc_may_start"),
        "no DPC starts over a device-reply holder");
    assert!(calls("hosted_device_reply_lock.rs", "dpc_may_start").iter()
        .any(|call| call == "admit_dpc_over_device_reply_lock"));
    assert!(calls("hosted_device_reply_lock.rs", "component_device_reply_lock").iter()
        .any(|call| call == "try_acquire_device_reply_lock"));
}
