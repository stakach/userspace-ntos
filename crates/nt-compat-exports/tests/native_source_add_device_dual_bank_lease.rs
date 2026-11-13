//! An entered AddDevice owns both request pages before either can be published to a driver.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const ADD_DEVICE: &str = include_str!(
    "../../../components/ntos-executive/src/hosted_add_device_continuation.rs"
);
const PREPARATION: &str = include_str!(
    "../../../components/ntos-executive/src/hosted_add_device_continuation/preparation.rs"
);
const ROLLBACK: &str = include_str!(
    "../../../components/ntos-executive/src/hosted_add_device_rollback.rs"
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

    let transaction = between(PREPARATION, "unsafe fn start_typed_add_device(",
        "unsafe fn continue_typed_after_projection(");
    let claim = transaction.find("reserve_add_device_bank(").expect("single dual-page claim");
    let create_pdo = transaction.find("dispatch_pdo_projection_progress(")
        .expect("typed native PDO projection pump");
    assert!(claim < create_pdo,
        "both pages must be claimed before PDO projection writes SH_REQ and enters its pump");
    let after_projection = between(PREPARATION, "unsafe fn continue_typed_after_projection(",
        "unsafe fn prepare_add_device_transaction(");
    assert!(after_projection.contains("publish_shared_registry_identity_at("),
        "registry publication must follow the leased typed projection stage");
    assert_eq!(transaction.matches("reserve_add_device_bank(").count(), 1,
        "a second page claim after a reentrant effect is not atomic");

}

#[test]
fn terminal_phase_is_authenticated_before_banked_rollback_settlement() {
    let terminal = between(ADD_DEVICE, "unsafe fn settle_terminal(",
        "pub(crate) fn record_child_step(");
    let finish = terminal.find("self.retained.finish_terminal(key, ())")
        .expect("the retained transaction consumes its authenticated terminal");
    let authenticated_phase = terminal.find("self.retained.acknowledge_restore(key)")
        .expect("exact owner must authenticate physical restore before transaction settlement");
    let transaction_finish = terminal.find("transaction.finish(terminal)")
        .expect("banked rollback owner settles only after authenticated terminal");
    assert!(authenticated_phase < finish && finish < transaction_finish);
    assert!(!terminal.contains("transaction.banks.retire()"),
        "the terminal path must leave the bank claim with rollback through shared cleanup");
}

#[test]
fn deferred_rollback_retains_both_bank_claims_until_shared_registry_cleanup() {
    let owner = between(ROLLBACK, "struct Owner {", "static mut OWNERS:");
    assert!(owner.contains("bank_ticket: Option<SuspendedActiveHostedIrpTransfer>"),
        "rollback owns the exact dual-page lease after preparation, including deferred drain");

    let preparation = between(PREPARATION, "unsafe fn start_typed_add_device(",
        "unsafe fn continue_typed_after_projection(");
    let claim = preparation.find("reserve_add_device_bank(").expect("dual-page claim");
    let projection = preparation.find("dispatch_pdo_projection_progress(")
        .expect("first native projection pump");
    assert!(preparation[claim..projection].contains("bank_ticket"),
        "move the claim into rollback ownership before the projection pump can yield");

    let advance = between(ROLLBACK, "unsafe fn advance_inner(",
        "pub(super) unsafe fn drain(");
    let last_clear = advance.rfind("clear_shared_registry_identity_at(")
        .expect("rollback clears both request pages");
    let retire = advance.rfind("retire_add_device_bank(")
        .expect("rollback retires exact bank ticket after shared cleanup");
    assert!(last_clear < retire,
        "deferred cleanup may not write either shared page after releasing its lease");
}

#[test]
fn successful_add_device_clears_provider_registry_before_bank_retirement() {
    let terminal = between(ADD_DEVICE, "unsafe fn settle_terminal(",
        "pub(crate) fn record_child_step(");
    assert!(!terminal.contains("transaction.banks.retire()"),
        "terminal handoff must retain the dual-page claim through transaction.finish");

    let finish = between(ADD_DEVICE, "impl AddDeviceTransaction {", "mod preparation;");
    let clear = finish.find("clear_shared_registry_identity_at(shared)")
        .expect("successful AddDevice clears provider registry page");
    let commit = finish.find("hosted_add_device_rollback::commit(")
        .expect("successful AddDevice commits rollback owner");
    assert!(clear < commit,
        "provider registry write must finish while rollback owner still holds both bank claims");

    let rollback_commit = between(ROLLBACK, "pub(super) unsafe fn commit(",
        "pub(super) unsafe fn block(");
    assert!(rollback_commit.contains("bank_ticket") && rollback_commit.contains("retire_add_device_bank"),
        "success commit must retire the exact dual-page ticket before discarding rollback owner");
}
