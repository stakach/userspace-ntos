//! An entered AddDevice owns both request pages before either can be published to a driver.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const ADD_DEVICE: &str = include_str!(
    "../../../components/ntos-executive/src/hosted_add_device_continuation.rs"
);

fn between(source: &'static str, start: &str, end: &str) -> &'static str {
    source.split_once(start).expect("native start boundary").1
        .split_once(end).expect("native end boundary").0
}

#[test]
fn add_device_claims_both_pages_atomically_in_the_file_transfer_authority() {
    let transfer = between(SOURCE, "struct ActiveHostedIrpTransfer {", "type ActiveHostedIrpTransferTicket");
    assert!(transfer.contains("secondary_shared_va: Option<u64>"),
        "one retained row must represent both possible AddDevice request pages");

    let reserve = between(ADD_DEVICE, "unsafe fn reserve_add_device_bank(", "unsafe fn retire_add_device_bank(");
    assert!(reserve.contains("secondary_shared_va: Option<u64>"));
    assert!(reserve.contains("retain_exclusive_by("),
        "claim the pair with one serialized admission, rather than two sequential leases");
    assert!(!reserve.contains("enter_active_hosted_irp_transfer("),
        "a one-page helper cannot atomically claim primary and provider pages");

    let file_entry = between(SOURCE, "unsafe fn enter_active_hosted_irp_transfer(",
        "unsafe fn active_hosted_irp_transfer_mut(");
    assert!(file_entry.contains("held.secondary_shared_va"),
        "ordinary File admission must reject either page in a retained AddDevice row");

    let transaction = between(ADD_DEVICE, "unsafe fn start_typed_add_device(",
        "unsafe fn continue_typed_after_projection(");
    let claim = transaction.find("reserve_add_device_bank(").expect("single dual-page claim");
    let create_pdo = transaction.find("dispatch_pdo_projection_progress(")
        .expect("typed native PDO projection pump");
    assert!(claim < create_pdo,
        "both pages must be claimed before PDO projection writes SH_REQ and enters its pump");
    let after_projection = between(ADD_DEVICE, "unsafe fn continue_typed_after_projection(",
        "unsafe fn prepare_add_device_transaction(");
    assert!(after_projection.contains("publish_shared_registry_identity_at("),
        "registry publication must follow the leased typed projection stage");
    assert_eq!(transaction.matches("reserve_add_device_bank(").count(), 1,
        "a second page claim after a reentrant effect is not atomic");

}

#[test]
fn terminal_phase_is_authenticated_before_releasing_the_dual_bank_claim() {
    let retirement = between(ADD_DEVICE, "unsafe fn settle_terminal(",
        "pub(crate) fn record_child_step(");
    let retire = retirement.find("transaction.banks.retire()")
        .expect("the typed terminal owner retires the exact bank ticket");
    let finish = retirement.find("self.retained.finish_terminal(key, ())")
        .expect("the retained transaction consumes its authenticated terminal");
    let authenticated_phase = retirement.find("self.retained.acknowledge_restore(key)")
        .expect("exact owner must authenticate physical restore before releasing bank claim");
    assert!(authenticated_phase < retire,
        "a failed phase transition must retain both bank claims with the terminal owner");
    assert!(retire < finish, "bank retirement refusal must retain the AddDevice transaction");
}
