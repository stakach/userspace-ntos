//! A bus-reported PCI root starts with one BusNumber descriptor and no MMIO lease.
//! Its successful StartDevice still needs an exact typed publication proof.

const MMIO: &str = include_str!("../../../components/ntos-executive/src/hosted_mmio_broker.rs");
const START: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const PNP: &str = include_str!("../../nt-pnp-manager/src/lib.rs");
const BUS: &str = include_str!("../../nt-pnp-manager/src/bus_properties.rs");
const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const ADMISSION: &str = include_str!("../../../components/ntos-executive/src/hosted_pnp_start.rs");

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

#[test]
fn bus_owned_root_proof_survives_grant_start_and_publication_without_enabling_maps() {
    let grant = between(MAIN, "struct HostedDevnodeGrant {", "fn hosted_pci_grant_error(");
    assert!(grant.contains("bus_owned_root_proof"));
    let bus_root = between(
        MAIN,
        "PreparedHostedResourcePlan::BusOwnedRoot { resources } => {",
        "PreparedHostedResourcePlan::Pci {",
    );
    assert!(bus_root.contains("resources.publication_proof()"));
    let proof = between(LAUNCH, "impl HostedBusOwnedRootResources {", "/// Adopt a bus-number-bearing PDO's complete");
    assert!(proof.contains("child: self.child"));
    assert!(proof.contains("provider: self.provider"));
    let start = between(ADMISSION, "let start_status = match grant_prepared_hosted_devnode_resources(", "unsafe fn canonical_start_status(");
    assert!(start.contains("grant.bus_owned_root_proof"));
    let transaction = between(LAUNCH, "struct HostedPnpTransaction {", "enum HostedFilterRequirementsDisposition");
    assert!(transaction.contains("bus_owned_root_proof"));
    let publication = between(LAUNCH, "unsafe fn finish_hosted_start_publication(", "unsafe fn finish_hosted_stop_publication(");
    assert!(publication.contains("transaction.bus_owned_root_proof"));
    assert!(publication.contains("hosted_mmio_broker::validate_publication"));
    let no_lease = between(MMIO, "if state.address_resource_count == 0 && state.pnp_context_lease.is_none() {", "let (owner, state) = pnp_owner(binding)");
    assert!(no_lease.contains("devnode_has_started_bus_owned_root_assignment"));
    assert!(no_lease.contains("has_retained_pnp_device_rows(binding)"));
    assert!(MMIO.contains("pub(super) unsafe fn map_assigned"));
}
