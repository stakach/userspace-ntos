//! A retained CONNECT/queued-callback owner during flat-root AddDevice waits; it is not fatal.
//!
//! Boot 44500015316 exited with `reason=add-device-connect-retained stop=0x80000011` while the
//! lazy native checkpoint's physical command was entered (`phase=committing entered=1`): a hook
//! File pump was retained waiting on its own native completion behind that command.

#[test]
fn only_a_blocked_connect_settlement_exits_the_service_loop() {
    let maintenance = include_str!("../../../components/ntos-executive/src/executor/maintenance.rs");
    assert!(!maintenance.contains("add-device-connect-retained"),
        "a retained owner is waited out, not recorded as a loop exit");
    assert!(!maintenance.contains("ConnectPumpSettlement::Retained | ConnectPumpSettlement::Blocked"));
    let waits = maintenance
        .matches("ConnectPumpSettlement::RetryableRestore | ConnectPumpSettlement::Retained =>")
        .count();
    assert_eq!(waits, 4, "every root settlement site parks the root receive");
    assert_eq!(maintenance.matches("lp.exit.record(b\"add-device-connect-blocked\")").count(), 3);
}
