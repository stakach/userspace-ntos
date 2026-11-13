//! The released NPFS driver requires the generic kernel's process-session query.

#[test]
fn released_npfs_process_session_import_has_a_generic_callable_binding() {
    assert!(
        nt_compat_exports::module_export_descriptor("ntoskrnl.exe", "PsGetProcessSessionId")
            .is_some()
    );

    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let bindings = source
        .split_once("fn register_fsd_trampolines()")
        .expect("generic hosted-driver registry")
        .1
        .split_once("pub(crate) fn initialize_fsd_export_registry()")
        .expect("generic hosted-driver registry end")
        .0;
    assert!(
        bindings.contains("\"PsGetProcessSessionId\",\n        hosted_driver_process_state::ps_get_process_session_id"),
        "the generic native driver registry must bind the authenticated Ps handler"
    );
}
