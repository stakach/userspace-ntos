//! Keep VideoPort's FDO BusRelations request out of the miniport's generic PnP stub.

#[test]
fn video_port_registers_a_pnp_handler_and_routes_bus_relations() {
    let native = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let initialize = native
        .split("extern \"win64\" fn s_video_port_initialize(")
        .nth(1)
        .unwrap()
        .split("// --- the SHARED ntoskrnl export surface")
        .next()
        .unwrap();
    assert!(initialize.contains("major::IRP_MJ_PNP")
        && initialize.contains("hosted_video_port_pnp::dispatch"),
        "VideoPortInitialize must install its own PnP dispatch");
    let pnp = include_str!("../../../components/ntos-executive/src/hosted_video_port_pnp.rs");
    assert!(pnp.contains("nt_pnp_abi::BUS_RELATIONS")
        && pnp.contains("call_hosted_pe(callback")
        && pnp.contains("s_obf_reference_object(device)")
        && pnp.contains("s_io_complete_request(irp, 0)"),
        "VideoPort must enumerate real miniport children and complete an owned relation IRP");
    assert!(native.contains("HostedDeviceRelationQueryPhase::AwaitingProviderRelationAck")
        && native.contains("FSD_DISPATCH_VIDEO_RELATION_ACK")
        && native.contains("acknowledge_hosted_video_relation(allocation, generation)"),
        "the root must acknowledge an exact copied relation before publishing its children");
    assert!(pnp.contains("release_in_flight = Some(index)")
        && pnp.contains("s_obf_dereference_object(device)"),
        "the component must retain and release its counted child references");
}
