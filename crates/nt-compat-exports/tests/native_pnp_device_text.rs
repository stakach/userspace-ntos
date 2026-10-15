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

#[test]
fn root_pdo_backend_preserves_unhandled_device_text_result() {
    let backend = body(
        "impl DriverDispatchBackend for HostedRootBusBackend {",
        "const HOSTED_ROOT_BUS_DRIVER_PATH:",
    );
    assert!(
        backend.contains("dispatch_pnp_outcome(irp.device_id, irp.minor)"),
        "dispatch to the exact root PDO and PnP minor"
    );
    assert!(
        backend.contains("completion_or(irp.status.raw(), irp.information)"),
        "an unhandled QueryDeviceText must preserve STATUS_NOT_SUPPORTED and Information=0"
    );
    assert!(
        !backend.contains("status: nt_status::NtStatus::SUCCESS"),
        "the root backend cannot report synthetic success for every PnP minor"
    );
}

#[test]
fn accepted_bus_children_apply_required_description_policy_before_publication() {
    let queried_children = body(
        "unsafe fn store_hosted_bus_property(",
        "unsafe fn publish_hosted_bus_relations(",
    );
    assert!(
        queried_children
            .contains("plan_required_device_description_from_verified_publication("),
        "an accepted child with an unsupported or empty PDO text result needs the verified \
         PiSetDevNodeText fallback before its Enum key becomes visible"
    );
    assert!(
        queried_children.contains("\"DeviceDesc\""),
        "the required description must be part of the durable child publication"
    );
}
