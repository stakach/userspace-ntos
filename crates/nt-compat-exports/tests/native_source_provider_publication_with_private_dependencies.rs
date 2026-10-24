const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const DXG: &str = include_str!("../../../components/ntos-executive/src/hosted_dxg_registration.rs");

#[test]
fn live_primary_provider_with_private_dependencies_publishes_callable_image() {
    let publish = LAUNCH
        .split("if let Some(provider) = hosted_provider_leaf_from_path(path) {")
        .last()
        .expect("primary hosted provider publication");
    let publish = publish.split("if let Err(status) = io_manager_mut().bind_hosted_driver_identity(")
        .next().expect("publication boundary");
    assert!(publish.contains("register_hosted_provider_singleton("));
    assert!(!publish.contains("planned_images.dependencies.is_empty()"),
        "a private support DLL does not erase the primary provider image authority");

    let register = LAUNCH
        .split("unsafe fn register_hosted_provider_singleton(")
        .nth(1).expect("singleton registrar")
        .split("unsafe fn find_hosted_provider_singleton_by_cookie(")
        .next().expect("registrar boundary");
    assert!(register.contains("hosted_provider_export_gate_va()"),
        "typed internal call policy needs a callable gate even without named exports");
    assert!(!register.contains("if hosted_provider_has_export_marshal_policies(provider.as_str())"));
}

#[test]
fn dxg_resolver_creates_exact_dependency_before_deriving_its_owner() {
    let bridge = DXG.split("pub(crate) unsafe fn bridge_dxg_registration_entry(")
        .nth(1).expect("typed resolver bridge")
        .split("pub(super) unsafe fn validate_call(")
        .next().expect("bridge boundary");
    let dependency = bridge.find("ensure_hosted_provider_domain_dependency(")
        .expect("generation-bound dependency admission");
    let owner = bridge.find("hosted_provider_object_owner_for_pair(")
        .expect("derived provider object owner");
    assert!(dependency < owner,
        "owner construction requires the exact provider/dependent dependency to exist");
}

#[test]
fn published_dxg_callbacks_retire_after_dependency_quiescence() {
    let clear = LAUNCH
        .split("unsafe fn clear_hosted_provider_callback_parents_for_instance(")
        .nth(1).expect("callback-parent retirement")
        .split("unsafe fn ").next().expect("retirement boundary");
    assert!(clear.contains("HOSTED_PROVIDER_CALLBACK_PARENT_KIND_DXG"),
        "published Dxg callback ownership needs an explicit retirement policy");
    assert!(clear.contains("HostedProviderConstructionState::Published"),
        "successful DxgkInitialize must not permanently pin callback slots");

    let instance_clear = LAUNCH.split("fn clear_instance(i: usize)")
        .nth(1).expect("instance teardown");
    let quiesce = instance_clear.find("begin_hosted_provider_dependency_retirement_for_instance(")
        .expect("dependency quiescence");
    let callbacks = instance_clear.find("clear_hosted_provider_callback_parents_for_instance(")
        .expect("callback retirement");
    assert!(quiesce < callbacks,
        "callback thunks cannot retire before provider dispatch is quiescent");
}

#[test]
fn dxg_entry_resolution_retires_before_thunk_free_check() {
    let clear = LAUNCH.split("fn clear_instance(i: usize)")
        .nth(1).expect("instance teardown");
    let quiesce = clear.find("begin_hosted_provider_dependency_retirement_for_instance(")
        .expect("dependency quiescence");
    let retire = clear.find("hosted_dxg_registration::retire_for_instance(")
        .expect("exact Dxg entry thunk retirement");
    let slots = clear.find("driver_instance_thunk_slots_are_free(i)")
        .expect("slot-free gate");
    assert!(quiesce < retire && retire < slots,
        "entry thunk needs quiescence and checked release before slot-free gate");

    let retire_fn = DXG.split("pub(super) unsafe fn retire_for_instance(")
        .nth(1).expect("Dxg resolution retirement")
        .split("pub(").next().expect("retirement boundary");
    assert!(retire_fn.contains("release_instance_executable_thunk_binding("));
    assert!(retire_fn.contains("provider_instance") && retire_fn.contains("dependent_instance"),
        "both owner sides must be included in Dxg resolution retirement");
}

#[test]
fn dxg_reverse_callbacks_retain_the_validated_table_version() {
    let table = DXG.split("pub(super) unsafe fn marshal_initialization_data(")
        .nth(1).expect("Dxg DDI table marshal");
    assert!(table.contains("table.version()"));
    assert!(table.contains("provider_marshal_emit_callback_thunk_reserved("));

    let record = LAUNCH.split("struct HostedProviderCallbackRecord {")
        .nth(1).expect("callback authority record")
        .split('}').next().expect("record boundary");
    assert!(record.contains("callback_version: u32"),
        "reverse dispatch must retain the parsed DDI version");
    let dispatch = LAUNCH.split("unsafe fn service_hosted_provider_callback_with_dispatch(")
        .nth(1).expect("callback dispatcher")
        .split("unsafe fn add_provider_domain_if_callable(")
        .next().expect("callback dispatch boundary");
    assert!(dispatch.contains("DxgDdiSignature::for_offset("),
        "only source-verified lifecycle signatures may cross VSpaces");
}
