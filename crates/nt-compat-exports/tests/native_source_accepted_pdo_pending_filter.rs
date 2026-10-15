//! A pending accepted PDO FILTER must preserve its exact provider owner until completion.

#[test]
fn pending_filter_waits_and_authentic_unchanged_input_retires_without_output_copy() {
    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let filter = &driver[driver
        .find("HostedFilterRequirementsPhase::AwaitingVideoProvider => {")
        .unwrap()..];
    let retained = &filter[filter
        .find("HostedAcceptedPdoProviderStage::Retained(retained)")
        .unwrap()..];
    let retained = &retained[..retained.find("let transaction = &mut hosted_filter_requirements_transactions_mut()[index];").unwrap()];
    assert!(retained.contains("retained.is_indeterminate()"));
    assert!(retained.contains("retained.has_rejected_terminal()"));
    assert!(
        !retained.contains("retained.identity().minor == nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS"),
        "ordinary pending FILTER is neither rejected nor indeterminate",
    );

    let completion = &driver[driver.find("unsafe fn complete_hosted_irp_with_owner(").unwrap()..];
    let completion = &completion[..completion.find("fn s_io_allocate_error_log_entry(").unwrap()];
    assert!(completion.contains("let borrowed_filter_input = completion_valid && filter_requirements && information == target.data;"));
    assert!(completion.contains("if borrowed_filter_input { 0 } else { information }"));
    assert!(
        !completion.contains("if completion_valid && filter_requirements && information == target.data {\n            write_volatile("),
        "the nested input allocation remains owned by its normal completion graph",
    );

    let accepted = include_str!("../../../crates/nt-pnp-manager/src/accepted_pdo_pnp.rs");
    let terminal = &accepted[accepted.find("fn finish_terminal(").unwrap()..];
    assert!(terminal.contains("!status.is_success() || information == 0 && payload.is_none()"));
}
