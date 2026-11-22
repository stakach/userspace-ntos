//! ReactOS class START synchronously opens its own registered interface.
//! The CREATE must use a physically independent class lane while START owns
//! the primary Reply and request bank, then retain that lane through ACK.

#[test]
fn class_start_can_dispatch_nested_interface_create() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let dispatch_start = launch
        .find("unsafe fn dispatch_irp_for_instance_exact(")
        .expect("missing native dispatch");
    let dispatch = &launch[dispatch_start..];
    let selection = &dispatch[..dispatch
        .find("let ingress_route = match class_selection.as_ref()")
        .expect("missing independent class route selection")];
    assert!(selection.contains("major::IRP_MJ_CREATE"));
    assert!(selection.contains("hosted_class_irp_lane::select_new"));
    assert!(selection.contains("hosted_class_irp_lane::owns_irp"));

    let lane = include_str!("../../../components/ntos-executive/src/hosted_class_irp_lane.rs");
    let execute = &lane[lane.find("unsafe fn execute(").expect("missing class lane executor")..];
    assert!(execute.contains("major::IRP_MJ_CREATE"));
    assert!(execute.contains("run_irp_with_bank"));
}
