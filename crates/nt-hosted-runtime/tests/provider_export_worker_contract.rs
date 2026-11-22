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
    let primary = HostedProviderWorkerIdentity::new(100, 10, 101, 102, 400, 103, 1).unwrap();
    let worker = HostedProviderWorkerIdentity::new(200, 20, 201, 202, 400, 203, 1).unwrap();
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
        HostedProviderWorkerIdentity::new(200, 20, 201, 102, 400, 203, 1).unwrap(), true).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary,
        HostedProviderWorkerIdentity::new(200, 10, 101, 202, 400, 203, 1).unwrap(), true).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary,
        HostedProviderWorkerIdentity::new(100, 20, 201, 202, 400, 203, 1).unwrap(), true).is_none());
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary,
        HostedProviderWorkerIdentity::new(200, 20, 201, 202, 400, 103, 1).unwrap(), true).is_none());
}

#[test]
fn local_reply_slot_may_match_across_distinct_owned_cnodes() {
    let primary = HostedProviderWorkerIdentity::new(100, 10, 101, 102, 400, 103, 1).unwrap();
    let worker = HostedProviderWorkerIdentity::new(200, 20, 101, 202, 400, 203, 1).unwrap();
    assert_eq!(
        select_hosted_provider_export_worker(owner(), 301, owner(), 301, primary, worker, true),
        Some(worker)
    );
    let aliased = HostedProviderWorkerIdentity::new(200, 10, 101, 202, 400, 203, 1).unwrap();
    assert!(select_hosted_provider_export_worker(
        owner(), 301, owner(), 301, primary, aliased, true).is_none());
    let separate_slot = HostedProviderWorkerIdentity::new(200, 10, 201, 202, 400, 203, 1).unwrap();
    assert_eq!(
        select_hosted_provider_export_worker(owner(), 301, owner(), 301, primary, separate_slot, true),
        Some(separate_slot)
    );
}

#[test]
fn incomplete_physical_worker_cannot_be_selected() {
    assert!(HostedProviderWorkerIdentity::new(0, 20, 201, 202, 400, 203, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 0, 201, 202, 400, 203, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 20, 0, 202, 400, 203, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 20, 201, 0, 400, 203, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 20, 201, 202, 0, 203, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 20, 201, 202, 400, 0, 1).is_none());
    assert!(HostedProviderWorkerIdentity::new(200, 20, 201, 202, 400, 203, 0).is_none());
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

/// Boot 44978356639 boot 2: with storahci's primary parked in StartDevice, a disk SRB
/// (IRP_MJ_INTERNAL_DEVICE_CONTROL) ran on storahci's dispatch-worker lane, and storport's
/// inlined KeRaiseIrql (`mov %cr8, %r15` at storport+0x5d35) raised #GP. Only the primary and
/// provider-export workers were authorised for CR8 emulation, so the fault walled the lane. A
/// class/ordinary worker is a full execution context: its IRQL lives in its own bank.
#[test]
fn an_ordinary_worker_lane_emulates_cr8_against_its_own_irql() {
    use nt_hosted_runtime::{hosted_instance_lane, HostedInstanceLane};
    assert_eq!(hosted_instance_lane(false, false, true, false), Some(HostedInstanceLane::Worker));
    assert_eq!(hosted_instance_lane(false, true, false, false), Some(HostedInstanceLane::Worker));
    assert_eq!(hosted_instance_lane(true, false, false, false), Some(HostedInstanceLane::Primary));
    assert_eq!(hosted_instance_lane(false, false, false, false), None, "an unauthenticated lane");
    assert_eq!(hosted_instance_lane(true, false, true, false), None, "one lane, one authority");
}

/// Boot 44985671350 boot 1: with storahci's primary parked, a disk SRB ran on its worker lane,
/// and storport's StorPortSynchronizeAccess → KeAcquireInterruptSpinLock was refused by the
/// interrupt service (`[provider-bugcheck] code=0xC4 p1=0x785 p2=3 p4=0xC0000022`): only the
/// primary's bank was accepted. Any authenticated lane of the instance may synchronise with
/// that instance's interrupt; a lane of no instance (or another's) may not.
#[test]
fn every_authenticated_lane_of_an_instance_may_synchronise_with_its_interrupt() {
    use nt_hosted_runtime::{hosted_instance_lane, HostedInstanceLane};
    assert_eq!(hosted_instance_lane(false, false, true, false), Some(HostedInstanceLane::Worker));
    assert_eq!(hosted_instance_lane(false, true, false, false), Some(HostedInstanceLane::Worker));
    assert_eq!(hosted_instance_lane(true, false, false, false), Some(HostedInstanceLane::Primary));
    // A foreign instance's lane matches none of this instance's lanes.
    assert_eq!(hosted_instance_lane(false, false, false, false), None);
}

/// Boot 44997226178 boot 1: after 5b142e2c9 admitted storahci's worker lane to the interrupt
/// service, KeAcquireInterruptSpinLock was still refused with STATUS_INVALID_DEVICE_REQUEST
/// (`[provider-bugcheck] code=0xC4 p1=0x785 p2=3 p4=0xC0000010`): the lock checked that the
/// caller had raised to the interrupt's SynchronizeIrql by reading the PRIMARY bank's IRQL,
/// while the worker (b7182adba) raises its own. The check reads the calling lane's IRQL.
#[test]
fn an_interrupt_lock_checks_the_calling_lanes_own_irql() {
    use nt_hosted_runtime::{hosted_instance_lane, hosted_lane_irql_bank, interrupt_lock_irql_matches};
    const PRIMARY_BANK: u64 = 0x1000;
    const WORKER_BANK: u64 = 0x9000;
    const SYNCHRONIZE_IRQL: u8 = 5;
    let irql_at = |bank: u64| if bank == WORKER_BANK { SYNCHRONIZE_IRQL } else { 0 };

    // storahci's worker raised to SynchronizeIrql; its parked primary is still at PASSIVE.
    let lane = hosted_instance_lane(false, false, true, false).unwrap();
    let bank = hosted_lane_irql_bank(lane, PRIMARY_BANK, WORKER_BANK);
    assert_eq!(bank, WORKER_BANK);
    assert!(interrupt_lock_irql_matches(SYNCHRONIZE_IRQL, irql_at(bank)));

    // The primary's own acquisition keeps reading the primary bank.
    let lane = hosted_instance_lane(true, false, false, false).unwrap();
    assert_eq!(hosted_lane_irql_bank(lane, PRIMARY_BANK, PRIMARY_BANK), PRIMARY_BANK);
    // A caller that did not raise, or a passive interrupt, is refused.
    assert!(!interrupt_lock_irql_matches(SYNCHRONIZE_IRQL, 0));
    assert!(!interrupt_lock_irql_matches(1, 1));
}

/// #427 audit gaps 1-3, 6, 7: an ordinary IRP admitted on a dispatch worker never got its
/// device's resource projection, so MmMapIoSpace returned NULL, port I/O faults were refused,
/// DPC resources were lost and CLAIM_PORT_RANGE compared against an empty PDO. Each lane's
/// dispatch projects the device resources into that lane's own bank, never into the parked
/// primary's.
#[test]
fn a_dispatch_projects_device_resources_into_its_own_lane_bank() {
    use nt_hosted_runtime::{hosted_instance_lane, hosted_resource_projection_bank};
    const PRIMARY_BANK: u64 = 0x1000;
    const WORKER_BANK: u64 = 0x9000;
    let worker = hosted_instance_lane(false, false, true, false).unwrap();
    assert_eq!(hosted_resource_projection_bank(worker, PRIMARY_BANK, WORKER_BANK), Some(WORKER_BANK));
    let primary = hosted_instance_lane(true, false, false, false).unwrap();
    assert_eq!(hosted_resource_projection_bank(primary, PRIMARY_BANK, PRIMARY_BANK), Some(PRIMARY_BANK));
    // A worker's projection can never target the primary bank.
    assert_eq!(hosted_resource_projection_bank(worker, PRIMARY_BANK, PRIMARY_BANK), None);
}

/// #427 audit gap 11: a driver's completion routine runs on the source-completion lane, and a
/// CR8 access or interrupt lock there was refused because that lane was not an authenticated lane
/// of its instance. Every lane a driver's code runs on is.
#[test]
fn a_completion_lane_is_an_authenticated_lane_of_its_instance() {
    use nt_hosted_runtime::{hosted_instance_lane, HostedInstanceLane};
    assert_eq!(hosted_instance_lane(false, false, false, true), Some(HostedInstanceLane::Worker));
    assert_eq!(hosted_instance_lane(false, false, true, true), None, "one lane, one authority");
}
