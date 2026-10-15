//! A retained class CONNECT must keep its exact source receiver available for first redrive.

#[test]
fn parked_connect_source_receives_nested_redrive_without_broad_worker_exemption() {
    let pump = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
    let wait = &pump[pump.find("pub(super) unsafe fn service_wait_yields(").unwrap()..];
    let wait = &wait[..wait.find("\n}").unwrap()];
    assert!(wait.contains("driver_launch::parked_hosted_connect_source_channel(ch)"));
    assert!(wait.contains("PhysicalSourceKind::DispatchWorker"));

    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let wrapper = &driver[driver.find("pub(crate) unsafe fn parked_hosted_connect_source_channel(").unwrap()..];
    let wrapper = &wrapper[..wrapper.find("\n}").unwrap()];
    assert!(wrapper.contains("hosted_connect_live::parked_source_channel(ch)"));

    let connect = include_str!("../../../components/ntos-executive/src/hosted_connect_live.rs");
    let source = &connect[connect.find("pub(super) unsafe fn parked_source_channel(").unwrap()..];
    let source = &source[..source.find("\n}").unwrap()];
    for exact_owner in [
        "runtime::channel_route(ch)",
        "runtime::dispatch(route)",
        "runtime::current_reply(route)",
        "work.source.source_pin_owned()",
        "origin.route == route",
        "origin.dispatch == dispatch",
        "origin.reply == reply",
    ] {
        assert!(source.contains(exact_owner), "missing CONNECT source owner: {exact_owner}");
    }
}
