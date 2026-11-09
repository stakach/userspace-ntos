//! A suspended File transfer retains the physical request page across nested dispatch.

const NATIVE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn file_dispatch_claims_the_selected_request_bank_before_native_publication() {
    let body = NATIVE
        .split_once("unsafe fn dispatch_irp_for_instance_exact_inner(")
        .expect("native File entry")
        .1
        .split_once("/// Allocate the canonical File")
        .expect("native File entry boundary")
        .0;
    let selected = body.find("sh = class_selection.as_ref().map_or(sh, |selection| selection.shared);")
        .expect("exact class worker bank selected");
    let claim = body.find("let transfer_guard = match enter_active_hosted_irp_transfer(")
        .expect("retained physical bank claim");
    let projection = body.find("project_provider_device_dispatch_state(")
        .expect("provider projection");
    let restore = body.find("restore_hosted_device_resource_state(binding, sh, false)")
        .expect("resource projection");
    let request = body.find("write_volatile((sh + SH_REQ_MAJOR)")
        .expect("request header publication");
    assert!(selected < claim && claim < projection && claim < restore && claim < request);

    let enter = NATIVE
        .split_once("unsafe fn enter_active_hosted_irp_transfer(")
        .expect("native retained bank entry")
        .1
        .split_once("unsafe fn active_hosted_irp_transfer_mut(")
        .expect("native retained bank entry boundary")
        .0;
    assert!(enter.contains("retain_exclusive_by("));
    assert!(enter.contains("held.shared_va == shared_va"));
    assert!(enter.contains("NtStatus::DEVICE_BUSY"));
}
