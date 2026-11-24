//! A successful StartDevice with an empty resource assignment has no PnP context lease.
//! Its publication must still settle, while an unexpected retained MMIO request must fence it.

const MMIO: &str = include_str!("../../../components/ntos-executive/src/hosted_mmio_broker.rs");
const START: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
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
fn empty_assignment_reaches_successful_start_publication_without_a_context_lease() {
    let admission = between(
        ADMISSION,
        "unsafe fn start_filtered_devnode(",
        "fn trace_canonical_start_failure(",
    );
    assert!(admission.contains("commit_hosted_device_resource_assignment(device_id, &[], &[])"));

    let start = between(
        START,
        "unsafe fn finish_hosted_start_publication(",
        "unsafe fn finish_hosted_stop_publication(",
    );
    assert!(start.contains("hosted_mmio_broker::validate_publication(binding)?"));

    let validation = between(
        MMIO,
        "pub(super) unsafe fn validate_publication(",
        "pub(super) unsafe fn preflight_retirement(",
    );
    let empty = validation
        .find("state.address_resource_count == 0")
        .expect("empty assigned resources need a publication path without a PnP context lease");
    let lease_bound = validation
        .find("pnp_owner(binding)")
        .expect("assigned resources still require the exact PnP context lease");
    assert!(empty < lease_bound, "empty assignment must settle before lease-bound validation");
    let retained = between(MMIO, "unsafe fn retained_pnp_state(", "unsafe fn pnp_owner(");
    assert!(
        validation[..empty].contains("retained_pnp_state(binding)")
            && retained.contains("hosted_device_binding_by_device_id(binding.device_id)")
            && retained.contains("hosted_device_resource_state_by_device_id(binding.device_id)"),
        "the empty path must authenticate the retained binding and resource state",
    );
    assert!(
        validation.contains("devnode_has_started_empty_assignment(identity)"),
        "a default empty projection is not proof of a committed empty assignment",
    );
    assert!(
        validation.contains("has_pnp_device_rows"),
        "an unexpected retained MMIO request must fence empty-resource publication",
    );
}
