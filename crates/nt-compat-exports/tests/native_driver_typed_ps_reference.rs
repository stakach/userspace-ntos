//! A typed ObReferenceObjectByHandle from a released driver must reach the
//! ProcessManager's counted Ps reference contract, not the file-only broker.

#[test]
fn hosted_driver_typed_ps_reference_routes_to_canonical_ps_handles() {
    let shared = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let reference = shared
        .split_once("extern \"win64\" fn s_ob_reference_object_by_handle(")
        .expect("generic ObReferenceObjectByHandle")
        .1
        .split_once("extern \"win64\" fn s_ob_open_object_by_pointer(")
        .expect("generic ObReferenceObjectByHandle end")
        .0;
    assert!(
        reference.contains("hosted_driver_ps_handle_reference::"),
        "typed PsProcessType/PsThreadType must route to a separate canonical Ps broker"
    );

    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_ps_handle_reference.rs");
    assert!(
        adapter.contains("reference_native_ps_handle(")
            && adapter.contains("grant_referenced_body(")
            && adapter.contains(".release(pm)"),
        "typed references must validate PM type/access, project before publication, and own rollback"
    );
    assert!(
        shared.contains("hosted_driver_ps_handle_reference::release_if_owned("),
        "ObfDereferenceObject must retire exactly the pointer reference acquired by the typed broker"
    );
}
