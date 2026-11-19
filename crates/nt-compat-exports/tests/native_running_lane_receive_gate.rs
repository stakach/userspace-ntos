//! Boot 44594159275 exited `ingress-retained site=522`: the AddDevice CONNECT resume gate
//! (stages 40/8, 42/1, 20/259, 41/4) returned RetainedRefusal while primary lane 37 still ran
//! behind a scheduler-yielded child receive, and the root took its idle receive. The rule is
//! structural: the root's idle receive is never reached while any lane runs. Every executor
//! receive passes the running-lane gate, which drives the retained owners first.

const EXECUTOR: &[(&str, &str)] = &[
    ("admission.rs", include_str!("../../../components/ntos-executive/src/executor/admission.rs")),
    ("body.rs", include_str!("../../../components/ntos-executive/src/executor/body.rs")),
    ("exceptions.rs", include_str!("../../../components/ntos-executive/src/executor/exceptions.rs")),
    ("flow.rs", include_str!("../../../components/ntos-executive/src/executor/flow.rs")),
    ("local.rs", include_str!("../../../components/ntos-executive/src/executor/local.rs")),
    ("loop_state.rs", include_str!("../../../components/ntos-executive/src/executor/loop_state.rs")),
    ("maintenance.rs", include_str!("../../../components/ntos-executive/src/executor/maintenance.rs")),
    ("mod.rs", include_str!("../../../components/ntos-executive/src/executor/mod.rs")),
    ("native_call.rs", include_str!("../../../components/ntos-executive/src/executor/native_call.rs")),
    ("receive.rs", include_str!("../../../components/ntos-executive/src/executor/receive.rs")),
    ("syscall.rs", include_str!("../../../components/ntos-executive/src/executor/syscall.rs")),
    ("syscall_nt.rs", include_str!("../../../components/ntos-executive/src/executor/syscall_nt.rs")),
    ("syscall_tail.rs", include_str!("../../../components/ntos-executive/src/executor/syscall_tail.rs")),
    ("syscall_win32k.rs", include_str!("../../../components/ntos-executive/src/executor/syscall_win32k.rs")),
    ("vm_fault.rs", include_str!("../../../components/ntos-executive/src/executor/vm_fault.rs")),
];

/// Every direct native ingress receive in the executor is preceded, within its function, by
/// the running-lane gate. All other receives go through `receive`/`reply_receive`.
#[test]
fn every_executor_ingress_receive_passes_the_running_lane_gate() {
    let mut sites = 0;
    for (file, text) in EXECUTOR {
        for (at, _) in text.match_indices("crate::executive_ingress::") {
            let call = &text[at..];
            if !(call.starts_with("crate::executive_ingress::receive(")
                || call.starts_with("crate::executive_ingress::reply_receive("))
            {
                continue;
            }
            sites += 1;
            let function_start = text[..at].rfind("fn ").expect("enclosing function");
            let prefix = &text[function_start..at];
            assert!(prefix.contains("drive_running_lane("),
                "{file}: ingress receive at byte {at} bypasses the running-lane gate");
        }
    }
    assert_eq!(sites, 4, "enumerated executor ingress receive sites changed; review the gate");
}

#[test]
fn the_gate_drives_owners_and_never_waits_on_a_running_lane() {
    let receive = include_str!("../../../components/ntos-executive/src/executor/receive.rs");
    for entry in ["pub(super) unsafe fn receive(", "pub(super) unsafe fn reply_receive("] {
        let body = receive.split(entry).nth(1).unwrap();
        let body = body.split("\n}\n").next().unwrap();
        let gate = body.find("drive_running_lane(ingress, nt_handler, exit)?;").expect("gate");
        let prepare = body.find("root_add_device_exclusive_pending()").unwrap();
        assert!(gate < prepare, "{entry}: the gate runs before any receive preparation");
    }
    assert!(receive.contains("exit.record(b\"idle-receive-running-lane\")"));
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let gate = service.split("unsafe fn running_lane_gate(").nth(1).unwrap()
        .split("\nfn trace_running_lane_gate(").next().unwrap();
    assert!(gate.contains("drive_running_lane_before_idle_receive("));
    assert!(gate.contains("runtime::outer_boundary_ready()"));
    assert!(gate.contains("runtime::lane_receives"));
    assert!(gate.contains("redrive_flat_root_add_device_selected(handler, owner)"));
    let runtime = include_str!("../../../components/ntos-executive/src/component_ingress_runtime.rs");
    assert!(runtime.contains("if execution != IngressExecutionOwner::Idle {\n                    LANE_RECEIVES.fetch_add"));
}
