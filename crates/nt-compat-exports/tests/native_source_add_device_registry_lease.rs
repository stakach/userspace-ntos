//! AddDevice records the owned registry identity before a projection can suspend.

const PREPARATION: &str = include_str!(
    "../../../components/ntos-executive/src/hosted_add_device_continuation/preparation.rs"
);

#[test]
fn registry_identity_is_recorded_under_the_bank_before_projection_entry() {
    let start = PREPARATION.split_once("unsafe fn start_typed_add_device(")
        .expect("typed AddDevice entry").1
        .split_once("unsafe fn continue_typed_after_projection(")
        .expect("projection continuation boundary").0;
    let claim = start.find("reserve_add_device_bank(").expect("atomic bank claim");
    let allocation = start.find("allocate_hosted_registry_identity(")
        .expect("registry identity allocation");
    let record = start.find("hosted_add_device_rollback::record_registry(")
        .expect("durable rollback identity record");
    let projection = start.find("dispatch_pdo_projection_progress(")
        .expect("projection native entry");
    assert!(claim < allocation && allocation < record && record < projection,
        "the lease and rollback owner must exist before allocating and publishing identity");
    assert!(start[claim..projection].contains("hosted_add_device_rollback::abort(rollback)"),
        "a refused bank claim must release its unused rollback reservation");
}
