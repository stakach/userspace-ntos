use nt_hosted_runtime::{
    HostedProviderObjectOwner, HostedProviderWorkerIdentity, HostedWorkerBankLayout,
    HostedProviderExportCompletion, classify_hosted_provider_export_completion,
    select_hosted_provider_export_worker, select_hosted_cr8_bank,
};

fn owner() -> HostedProviderObjectOwner {
    HostedProviderObjectOwner::new(11, 12, 21, 22).unwrap()
}

#[test]
fn reentrant_export_requires_separate_physical_worker_and_exact_publication() {
    // Distinct routes on one shared ingress endpoint can each have generation 1.
    let primary = HostedProviderWorkerIdentity::new(100, 101, 102, 400, 103, 1).unwrap();
    let worker = HostedProviderWorkerIdentity::new(200, 201, 202, 400, 203, 1).unwrap();
    let selected = select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary, worker, true).unwrap();
    assert_eq!(selected, worker);

    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 302, primary, worker, true).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, HostedProviderObjectOwner::new(11, 13, 21, 22).unwrap(),
        301, primary, worker, true).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary, worker, false).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary, primary, true).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary,
        HostedProviderWorkerIdentity::new(200, 201, 102, 400, 203, 1).unwrap(), true).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary,
        HostedProviderWorkerIdentity::new(200, 101, 202, 400, 203, 1).unwrap(), true).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary,
        HostedProviderWorkerIdentity::new(100, 201, 202, 400, 203, 1).unwrap(), true).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary,
        HostedProviderWorkerIdentity::new(200, 201, 202, 400, 103, 1).unwrap(), true).is_none());
}

#[test]
fn incomplete_physical_worker_cannot_be_selected() {
    assert!(HostedProviderWorkerIdentity::new(0, 201, 202, 400, 203, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 0, 202, 400, 203, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 201, 0, 400, 203, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 201, 202, 0, 203, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 201, 202, 400, 0, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 201, 202, 400, 203, 0).is_none());
}

#[test]
fn worker_bank_maps_full_checked_arena_before_arg_window() {
    let bank = HostedWorkerBankLayout::new(0x49_000, 32, Some(0x69_000), 4, 0x20_0000)
        .expect("32-page provider bank and four-page ARG window fit disjointly");
    assert_eq!(bank.bank_bytes(), 0x20_000);
    assert_eq!(bank.bank_end(), 0x69_000);
    assert_eq!(bank.arg_end(), Some(0x6d_000));
    assert!(HostedWorkerBankLayout::new(0x44_000, 1, Some(0x45_000), 4, 0x20_0000).is_some());
    assert!(HostedWorkerBankLayout::new(0x44_000, 1, None, 4, 0x20_0000).is_some());
    assert!(HostedWorkerBankLayout::new(0x49_000, 32, Some(0x4a_000), 4, 0x20_0000).is_none());
    assert!(HostedWorkerBankLayout::new(0x49_000, 0, None, 4, 0x20_0000).is_none());
    assert!(HostedWorkerBankLayout::new(0x49_001, 32, None, 4, 0x20_0000).is_none());
    assert!(HostedWorkerBankLayout::new(0x49_000, u64::MAX, None, 4, 0x20_0000).is_none());
    assert!(HostedWorkerBankLayout::new(0x1f_0000, 32, None, 4, 0x20_0000).is_none());
}

#[test]
fn cr8_continuation_uses_only_authenticated_lane_local_irql_bank() {
    let primary = 0x1000;
    let worker = 0x2000;
    assert_eq!(select_hosted_cr8_bank(primary, primary, true, false), Some(primary));
    assert_eq!(select_hosted_cr8_bank(primary, worker, false, true), Some(worker));
    assert_eq!(select_hosted_cr8_bank(primary, worker, false, false), None);
    assert_eq!(select_hosted_cr8_bank(primary, worker, true, false), None);
    assert_eq!(select_hosted_cr8_bank(primary, primary, false, true), None);
    assert_eq!(select_hosted_cr8_bank(primary, worker, true, true), None);
    assert_eq!(select_hosted_cr8_bank(0, worker, false, true), None);
}

#[test]
fn provider_export_completion_retains_worker_after_guarded_failure_or_wall() {
    assert_eq!(classify_hosted_provider_export_completion(true, 0),
        HostedProviderExportCompletion::Reusable);
    assert_eq!(classify_hosted_provider_export_completion(true, 0xc000_0001u32 as i32),
        HostedProviderExportCompletion::Retain(0xc000_0001u32 as i32));
    assert_eq!(classify_hosted_provider_export_completion(false, 0),
        HostedProviderExportCompletion::Retain(0xc000_0001u32 as i32));
}
