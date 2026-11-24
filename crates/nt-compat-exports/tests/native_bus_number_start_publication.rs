//! A bus-reported PCI root starts with one BusNumber descriptor and no MMIO lease.
//! Its successful StartDevice still needs an exact typed publication proof.

const MMIO: &str = include_str!("../../../components/ntos-executive/src/hosted_mmio_broker.rs");
const START: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const PNP: &str = include_str!("../../nt-pnp-manager/src/lib.rs");
const BUS: &str = include_str!("../../nt-pnp-manager/src/bus_properties.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing native path: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing native path end: {end}"))
        .0
}

#[test]
fn bus_number_plan_commits_the_exact_unleased_assignment() {
    let plan = between(
        START,
        "unsafe fn prepare_current_hosted_devnode<H>(",
        "let lease = acquire_hosted_pnp_context_lease()?;",
    );
    assert!(plan.contains("prepare_hosted_bus_pdo_bus_number_start"));
    assert!(plan.contains("resource_plan: PreparedHostedResourcePlan::BusReportedBusNumber"));

    let grant = between(
        MAIN,
        "PreparedHostedResourcePlan::BusReportedBusNumber { resources } => {",
        "PreparedHostedResourcePlan::BusOwnedRoot { resources } => {",
    );
    assert!(grant.contains("raw_resource_list: resources.raw_resources"));
    assert!(grant.contains("translated_resource_list: resources.translated_resources"));
    assert!(grant.contains("mmio_phys: 0"));

    let source = between(
        BUS,
        "pub fn prepare_bus_reported_bus_number_start(",
        "pub fn initialized_device_capabilities_x64(",
    );
    assert!(source.contains("decode_single_bus_number_resource(raw)"));
    assert!(source.contains("boot_resources_raw"));
    assert!(source.contains("boot_resources_translated"));
    assert!(source.contains("resource_requirements"));
}

#[test]
fn bus_number_only_publication_needs_typed_started_proof_before_lease_bound_maps() {
    let publication = between(
        MMIO,
        "pub(super) unsafe fn validate_publication(",
        "pub(super) unsafe fn preflight_retirement(",
    );
    let no_lease = publication
        .find("state.address_resource_count == 0 && state.pnp_context_lease.is_none()")
        .expect("unleased publication needs exact retained state");
    let bus_only = publication
        .find("devnode_has_started_bus_number_assignment")
        .expect("a committed BusNumber-only assignment must settle without an MMIO lease");
    let lease_bound = publication
        .find("pnp_owner(binding)")
        .expect("assigned MMIO requests must retain live lease authority");
    assert!(no_lease < bus_only && bus_only < lease_bound);
    assert!(publication.contains("pnp.fdo(identity.devnode_id()) != Some(binding.device_id)"));
    assert!(publication.contains("has_retained_pnp_device_rows(binding)"));
    let retained_rows = between(MMIO, "unsafe fn has_retained_pnp_device_rows(", "unsafe fn retained_pnp_state(");
    assert!(retained_rows.contains("ledger.has_pnp_device_rows("));
    assert!(retained_rows.contains("binding.projection_domain.domain_id.raw()"));
    assert!(retained_rows.contains("binding.projection_domain.cookie"));
    assert!(retained_rows.contains("binding.device_id"));

    let proof = between(
        PNP,
        "pub fn devnode_has_started_bus_number_assignment(",
        "/// Commit only a terminal driver's state query",
    );
    let identity = between(PNP, "fn started_pdo_properties(", "/// The exact started PDO has completed an empty");
    assert!(proof.contains("started_pdo_properties(identity)"));
    assert!(identity.contains("devnode.generation == identity.generation"));
    assert!(identity.contains("devnode.state == DeviceState::Started"));
    assert!(identity.contains("devnode.pending_dispatch.is_none()"));
    assert!(proof.contains("allocated_resources_raw"));
    assert!(proof.contains("allocated_resources_translated"));
    assert!(proof.contains("boot_resources_raw"));
    assert!(proof.contains("boot_resources_translated"));
    assert!(proof.contains("resource_requirements"));
    assert!(proof.contains("decode_single_bus_number_resource"));
    assert!(proof.contains("PropertyBlobState::KnownNone"));
    assert!(proof.contains("PropertyBlobState::Present"));
}
