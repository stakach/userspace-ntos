//! A hosted process slot and its badge are reused by later process incarnations.
//! A pending ALPC exchange from the old incarnation must retain its Reply and
//! service token without refusing the new incarnation's CSR connection.

#[test]
fn retained_alpc_admission_distinguishes_reused_badges_by_exact_caller() {
    for worker in [
        "native_alpc_connect_accept_work.rs",
        "native_alpc_send_receive_work.rs",
    ] {
        let source = match worker {
            "native_alpc_connect_accept_work.rs" => include_str!(
                "../../../components/ntos-executive/src/native_alpc_connect_accept_work.rs"
            ),
            "native_alpc_send_receive_work.rs" => include_str!(
                "../../../components/ntos-executive/src/native_alpc_send_receive_work.rs"
            ),
            _ => unreachable!(),
        };
        assert!(source.contains("owner.caller() == caller"),
            "{worker}: admission must compare process, thread, generation, badge and TCB");
        assert!(!source.contains("owner.caller().badge == caller.badge")
            && !source.contains("owner.caller().badge == badge"),
            "{worker}: a recycled badge must not block the new physical caller");
    }
}
