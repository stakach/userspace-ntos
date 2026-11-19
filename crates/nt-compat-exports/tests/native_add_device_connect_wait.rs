//! A retained settlement waits for the next root event; only a proven Blocked exits the loop.
//!
//! Boot 44500015316 exited with `add-device-connect-retained` and boot 44510687412 with
//! `queued-callback-receive-prepare`: in both, a hook File pump was retained waiting on its own
//! native completion behind the lazy checkpoint's physical command during flat-root AddDevice.

const EXECUTOR: [(&str, &str); 3] = [
    ("maintenance.rs", include_str!("../../../components/ntos-executive/src/executor/maintenance.rs")),
    ("flow.rs", include_str!("../../../components/ntos-executive/src/executor/flow.rs")),
    ("syscall.rs", include_str!("../../../components/ntos-executive/src/executor/syscall.rs")),
];

/// Every arm that matches `pattern`, up to the next arm at the same indentation.
fn arms<'a>(source: &'a str, pattern: &str) -> Vec<&'a str> {
    let mut found = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find(pattern) {
        let tail = &rest[at..];
        let end = tail[pattern.len()..]
            .find("ConnectPumpSettlement::")
            .map_or(tail.len(), |next| next + pattern.len());
        found.push(&tail[..end]);
        rest = &tail[pattern.len()..];
    }
    found
}

#[test]
fn every_retained_settlement_arm_waits_and_records_no_exit() {
    let mut retained_arms = 0;
    for (file, source) in EXECUTOR {
        assert!(!source.contains("ConnectPumpSettlement::Retained | ConnectPumpSettlement::Blocked"),
            "{file} folds Retained into an exit");
        assert!(!source.contains("ConnectPumpSettlement::RetryableRestore | ConnectPumpSettlement::Retained"),
            "{file} routes Retained through a queued-callback-only park");
        for arm in arms(source, "ConnectPumpSettlement::Retained =>") {
            retained_arms += 1;
            assert!(arm.contains("wait_retained_settlement("), "{file}: {arm}");
            assert!(!arm.contains("exit.record("), "{file} exits on Retained: {arm}");
        }
    }
    assert_eq!(retained_arms, 4, "every root settlement site has an explicit Retained arm");
}

#[test]
fn exit_reasons_reachable_from_settlement_are_blocked_only() {
    let maintenance = EXECUTOR[0].1;
    for arm in arms(maintenance, "ConnectPumpSettlement::Blocked =>") {
        assert!(arm.contains("add-device-connect-blocked") || arm.contains("queued-callback-unsettled"),
            "unexpected Blocked exit: {arm}");
    }
    for reason in ["add-device-connect-retained"] {
        assert!(!EXECUTOR.iter().any(|(_, source)| source.contains(reason)), "{reason} remains");
    }
    let flow = EXECUTOR[1].1;
    let wait = flow
        .split("pub(super) unsafe fn wait_retained_settlement(")
        .nth(1)
        .expect("one waiting primitive")
        .split("\nfn trace_retained_settlement_wait(")
        .next()
        .unwrap();
    // The add-device turn owns the root while it is present: never the queued-callback park.
    let add_device = wait.find("prepare_parked_add_device_receive(").unwrap();
    let queued = wait.find("queued_callback_turn_can_park(").unwrap();
    assert!(wait[..queued].contains("ingress.root_add_device_turn.is_none()"));
    assert!(queued < add_device);
    assert!(wait.contains("receive("), "the root waits for its next event");
}
