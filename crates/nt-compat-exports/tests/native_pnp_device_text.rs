const DRIVER_LAUNCH: &str = include_str!(
    "../../../components/ntos-executive/src/driver_launch.rs"
);

fn body(start: &str, end: &str) -> &'static str {
    DRIVER_LAUNCH
        .split_once(start)
        .and_then(|(_, rest)| rest.split_once(end))
        .map(|(body, _)| body)
        .expect("native PnP function exists")
}

#[test]
fn relation_publication_captures_provider_text_before_device_action() {
    let dispatch = body("unsafe fn dispatch_hosted_bus_property(", "unsafe fn store_hosted_device_capabilities(");
    assert!(dispatch.contains("query_device_text"), "query the physical child PDO");

    let mutations = body("unsafe fn build_hosted_relation_mutations(", "unsafe fn publish_hosted_bus_relations(");
    let description = mutations.find("\"DeviceDesc\"").expect("publish DeviceDesc");
    let action = mutations.rfind("PublishDeviceAction").expect("publish device action");
    assert!(description < action, "description must be committed before notification");
    assert!(mutations.contains("child_properties"), "text must come from child query state");
}
