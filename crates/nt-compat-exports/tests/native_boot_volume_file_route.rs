//! A Boot-backed volume File must retain its exact mounted device owner for FSCTLs.

#[test]
fn native_open_and_create_use_the_same_exact_volume_policy_before_local_fallback() {
    let open = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let create = include_str!("../../../components/ntos-executive/src/exec_file_create.rs");

    for (source, name, options) in [
        (open, "nt_open_file_captured", "open_options"),
        (create, "nt_create_file_captured", "create_options"),
    ] {
        let body = source
            .split(&format!("fn {name}("))
            .nth(1)
            .unwrap_or_else(|| panic!("missing {name}"));
        let call = format!("route_absolute_open_to_kernel_file(name16, {options}, mount_route, resolved)");
        let normalized: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let call: String = call.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(normalized.contains(&call),
            "{name} must pass the retained exact target into the shared route policy");
    }
}
