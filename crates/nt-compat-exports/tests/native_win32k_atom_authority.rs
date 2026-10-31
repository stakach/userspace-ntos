//! The first win32k DriverEntry atom request runs in a root-issued System activation.
//! It has no hosted process identity, so ingress must authenticate the physical provider
//! request before selecting the executive-lifetime atom table.

#[test]
fn atom_pump_passes_exact_physical_envelope_to_the_service() {
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    let branch = pump
        .split("else if label == crate::win32k_subsystem::W32_ATOM_LABEL")
        .nth(1)
        .expect("native win32k atom ingress")
        .split("else if label == crate::win32k_subsystem::W32_MM_SECURE_LABEL")
        .next()
        .unwrap();
    for field in ["ch,", "*reply_cap,", "msg.badge,", "msg.mi,", "msg.m0,", "msg.m1,"] {
        assert!(branch.contains(field), "atom service missing authenticated {field}");
    }
    assert!(branch.contains("service_win32k_atom_request("));
}

#[test]
fn atom_table_is_reached_only_after_exact_provider_authentication() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let atom = service
        .split("pub(crate) unsafe fn service_win32k_atom_request(")
        .nth(1)
        .expect("native atom service")
        .split("\nunsafe fn delay_timer_rearm_after_park(")
        .next()
        .unwrap();
    let ingress = atom
        .find("provider_service_ingress::authenticate(")
        .expect("exact route, Reply, badge, message, and retained kernel activation");
    let physical = atom
        .find("provider_service_ingress::physical_win32k_provider(")
        .expect("current physical win32k provider identity");
    let table = atom
        .find("add_kernel_global_atom(")
        .expect("real executive-lifetime atom table");
    assert!(ingress < physical && physical < table,
        "atom payload must be served only after route and provider authentication");
    assert!(atom.contains("W32_ATOM_LABEL << 12") && atom.contains("| 2"),
        "atom ingress must validate its exact two-word protocol");
    assert!(atom.contains("channel.kernel_caller"),
        "root-issued System activation must reach the atom table without a hosted process identity");
}

#[test]
fn hosted_atom_mutation_requires_the_current_logical_dispatch() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let atom = service
        .split("pub(crate) unsafe fn service_win32k_atom_request(")
        .nth(1)
        .unwrap()
        .split("\nunsafe fn delay_timer_rearm_after_park(")
        .next()
        .unwrap();
    let current = atom.find("registry_logical_caller_is_current(channel)")
        .expect("hosted atom caller belongs to current GUI dispatch");
    let identity = atom.find("handler.validate_provider_logical_caller(caller)")
        .expect("hosted atom caller retains exact process and thread identity");
    let table = atom.find("add_kernel_global_atom(").unwrap();
    assert!(current < table && identity < table);
}

#[test]
fn early_kernel_atoms_use_the_same_table_as_runtime_calls() {
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let atom = service
        .split("pub(crate) unsafe fn service_win32k_atom_request(")
        .nth(1).unwrap()
        .split("\nunsafe fn delay_timer_rearm_after_park(").next().unwrap();
    let authenticate = atom.find("provider_service_ingress::authenticate(").unwrap();
    let physical = atom.find("provider_service_ingress::physical_win32k_provider(").unwrap();
    let bootstrap = atom.find("atom_bootstrap::add_kernel_atom(")
        .expect("root-issued win32k calls must use the early canonical atom table");
    assert!(authenticate < physical && physical < bootstrap);
    assert!(atom.contains("channel.kernel_caller.is_none()"),
        "hosted callers must not access the bootstrap table");
    let transfer = service.find("atom_bootstrap::take()")
        .expect("the original atom allocation must move into the live handler");
    let publish = service.find("register_service_delay_drain_context(&mut nt_handler, delay_queue)")
        .expect("handler publication");
    assert!(transfer < publish);
    let executive = include_str!("../../../components/ntos-executive/src/main.rs");
    assert!(executive.contains("atom_bootstrap::initialize()"),
        "atom owner must exist before provider activation");
}
