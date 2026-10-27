//! BASESRV changes the security of the existing named-object directory, not a registry key.

#[test]
fn directory_security_uses_typed_handle_and_exact_namespace_identity() {
    let dispatch = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let directory = include_str!("../../../components/ntos-executive/src/exec_directory_security.rs");
    let query = dispatch
        .split_once("NativeService::NtQuerySecurityObject => unsafe {")
        .expect("security query dispatch")
        .1
        .split_once("NativeService::NtSetSecurityObject => {")
        .unwrap()
        .0;
    let set = dispatch
        .split_once("NativeService::NtSetSecurityObject => {")
        .expect("security set dispatch")
        .1
        .split_once("NativeService::NtInitializeRegistry => {")
        .unwrap()
        .0;
    for branch in [query, set] {
        let typed = branch
            .find("lookup_native_object_directory_handle(caller, args[0], 0)")
            .expect("typed directory route");
        let registry = branch.find("resolve_registry_key(args[0]").expect("registry fallback");
        assert!(typed < registry, "directory must resolve before registry fallback");
        assert!(branch.contains("nt_security::LABEL_SECURITY_INFORMATION"));
    }
    assert!(set.contains("self.set_directory_object_security("));
    assert!(query.contains("self.query_directory_object_security("));
    assert!(directory.contains("lookup_native_object_directory_handle(caller, handle, required_access)"));
    assert!(directory.contains("directory_namespace_index_for_identity(identity)?"));
    assert!(directory.contains("record.identity == identity"));
    assert!(directory.contains("record.descriptor = updated"));
}
