//! RED: a queued condrv IRP must not be retried when only another instance frees a lane.
//! The fixture executes the native admission receipt and global epoch bodies unchanged.

use std::process::Command;

#[test]
fn unrelated_instance_lane_release_does_not_advance_condrv_admission() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
    let receipt = source.split_once("/// Value-only lane-availability observation").unwrap().1
        .split_once("\nstruct Row {").unwrap().0;
    let lane_freed = source.split_once("pub(super) fn lane_freed(instance_index: usize, domain: HostedDomainIdentity) {").unwrap().1
        .split_once("\n}").unwrap().0;
    let admission_epoch = source.split_once("pub(super) fn admission_epoch() -> u64 {").unwrap().1
        .split_once("\n}").unwrap().0;
    let runtime = include_str!("../../nt-hosted-runtime/src/ordinary_irp_lane.rs");
    let lane_selection = runtime.split_once("/// Where an ordinary IRP is admitted.").unwrap().1
        .split_once("/// Where a copy, ACK or cancel control").unwrap().0;
    let queued_selection = runtime.split_once("/// An ordinary IRP that no lane admitted").unwrap().1
        .split_once("/// How far a File caller's IRP has got").unwrap().0;
    let fixture = format!("{MOCKS}\n/// Value-only lane-availability observation{receipt}\n\
        fn lane_freed(instance_index: usize, domain: HostedDomainIdentity) {{{lane_freed}\n}}\n\
        fn admission_epoch() -> u64 {{{admission_epoch}\n}}\n\
        /// Where an ordinary IRP is admitted.{lane_selection}\n\
        /// An ordinary IRP that no lane admitted{queued_selection}\n{CASES}");

    let dir = std::env::temp_dir().join(format!("nt-queued-instance-red-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("fixture.rs");
    let binary = dir.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "admission fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.status.success(), "foreign lane release retried condrv:\n{}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

const MOCKS: &str = r#"
extern crate alloc;
use std::sync::atomic::{AtomicU64, Ordering};
static LANE_EPOCH: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct HostedDomainIdentity { id: u64, cookie: u64 }
#[derive(Clone, Copy)]
struct DriverInstance { used: bool, driver_id: u64, domain: HostedDomainIdentity, file_worker_epoch: u64 }
const EMPTY: DriverInstance = DriverInstance { used: false, driver_id: 0,
    domain: HostedDomainIdentity { id: 0, cookie: 0 }, file_worker_epoch: 0 };
static mut INSTANCES: [DriverInstance; 15] = [EMPTY; 15];
static mut IDLE: [u64; 15] = [0; 15];
static mut READY: [bool; 15] = [false; 15];
static mut PRESENT: [bool; 15] = [false; 15];
unsafe fn driver_instances_mut() -> &'static mut [DriverInstance; 15] { &mut *std::ptr::addr_of_mut!(INSTANCES) }
fn instance(index: usize) -> Option<DriverInstance> { unsafe {
    driver_instances_mut().get(index).copied().filter(|row| row.used)
} }
fn instance_domain_identity(inst: DriverInstance) -> Option<HostedDomainIdentity> {
    (inst.domain.id != 0 && inst.domain.cookie != 0).then_some(inst.domain)
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Authority { instance: usize, driver_id: u64, domain: HostedDomainIdentity }
impl Authority {
    fn capture(index: usize) -> Option<Self> {
        let inst = instance(index)?;
        Some(Self { instance: index, driver_id: inst.driver_id, domain: inst.domain })
    }
    fn live(self) -> bool { Self::capture(self.instance) == Some(self) }
}
mod nt_io_manager {
    #[derive(Clone, Copy)] pub struct DriverId(pub u64);
    impl DriverId { pub fn raw(self) -> u64 { self.0 } }
}
fn instance_by_driver_id(driver: u64) -> Option<(usize, ())> {
    [6, 14].contains(&driver).then_some((driver as usize, ()))
}
mod spawn_hosts { pub mod shared_ingress { pub mod owner { pub mod runtime {
    pub unsafe fn lane_idle_epoch() -> u64 { 0 }
    pub unsafe fn lane_idle_epoch_for_domain(domain: super::super::super::super::HostedDomainIdentity)
        -> Option<u64> {
        super::super::super::super::PRESENT[domain.id as usize]
            .then_some(super::super::super::super::IDLE[domain.id as usize])
    }
    pub unsafe fn ready_for_admission(route: super::super::super::super::PeerRoute) -> Result<bool, ()> {
        Ok(super::super::super::super::READY[route.0])
    }
    pub unsafe fn primary_dispatch_parked(_: super::super::super::super::PeerRoute) -> bool { false }
}}}}
#[derive(Clone, Copy)] struct PeerRoute(usize);
mod hosted_ingress_sources { pub fn primary_route(index: usize) -> Option<super::PeerRoute> {
    Some(super::PeerRoute(index))
} }
mod hosted_class_irp_lane { pub unsafe fn ordinary_ready(_: usize) -> bool { false } }
fn setup() { unsafe {
    for index in [6, 14] {
        driver_instances_mut()[index] = DriverInstance { used: true, driver_id: index as u64,
            domain: HostedDomainIdentity { id: index as u64, cookie: 9 }, file_worker_epoch: 0 };
        IDLE[index] = 0;
        READY[index] = false;
        PRESENT[index] = true;
    }
} }
"#;

const CASES: &str = r#"
fn epoch(receipt: AdmissionReceipt) -> u64 {
    let AdmissionEpoch::Ready(epoch) = receipt.current_epoch() else { panic!("live epoch") };
    epoch
}
#[test]
fn only_the_queued_instances_lane_release_admits_a_retry() {
    setup();
    let condrv_before = AdmissionReceipt::capture(Some(nt_io_manager::DriverId(6)));
    assert_eq!(condrv_before.owner.unwrap().instance, 6);
    assert_eq!(condrv_before.owner.unwrap().domain.cookie, 9);
    assert_eq!(select_ordinary_irp_lane(false, true, false), OrdinaryIrpLane::Busy);
    let queued_create = [QueuedIrp { id: 7, driver: 6,
        refused_at: epoch(condrv_before), current_epoch: Some(epoch(condrv_before)),
        wake_without_epoch: false,
        cancel_queued: false }];
    assert!(queued_admission_candidates(&queued_create).is_empty());
    lane_freed(14, HostedDomainIdentity { id: 14, cookie: 9 });
    let condrv_after = AdmissionReceipt::capture(Some(nt_io_manager::DriverId(6)));
    assert_eq!(condrv_after.owner, condrv_before.owner);
    let queue = [QueuedIrp { current_epoch: Some(epoch(condrv_before)), ..queued_create[0] }];
    assert!(queued_admission_candidates(&queue).is_empty(),
        "instance 6 still has both lanes held; instance 14 alone freed a lane");
}

#[test]
fn queued_cancellation_remains_selectable_without_a_lane_release() {
    setup();
    let cancelled = [QueuedIrp { id: 8, driver: 6,
        refused_at: 0, current_epoch: Some(0), wake_without_epoch: false,
        cancel_queued: true }];
    assert_eq!(queued_admission_candidates(&cancelled), [8]);
}

#[test]
fn own_lane_release_selects_only_the_oldest_queued_create() {
    setup();
    let before = AdmissionReceipt::capture(Some(nt_io_manager::DriverId(6)));
    lane_freed(6, HostedDomainIdentity { id: 6, cookie: 9 });
    let queue = [
        QueuedIrp { id: 7, driver: 6, refused_at: match before.refused {
                AdmissionEpoch::Ready(epoch) => epoch, _ => panic!("live refusal") },
            current_epoch: Some(epoch(before)), wake_without_epoch: false,
            cancel_queued: false },
        QueuedIrp { id: 8, driver: 6, refused_at: match before.refused {
                AdmissionEpoch::Ready(epoch) => epoch, _ => panic!("live refusal") },
            current_epoch: Some(epoch(before)), wake_without_epoch: false,
            cancel_queued: false },
    ];
    assert_eq!(queued_admission_candidates(&queue), [7]);
}

#[test]
fn a_reused_instance_cannot_inherit_the_old_queued_authority() {
    setup();
    let before = AdmissionReceipt::capture(Some(nt_io_manager::DriverId(6)));
    unsafe { driver_instances_mut()[6].domain.cookie = 10; }
    assert_eq!(before.current_epoch(), AdmissionEpoch::Retired);
    lane_freed(6, HostedDomainIdentity { id: 6, cookie: 9 });
    assert_eq!(instance(6).unwrap().file_worker_epoch, 0);
}

#[test]
fn only_own_domain_idle_transition_wakes_a_queued_irp() {
    setup();
    let before = AdmissionReceipt::capture(Some(nt_io_manager::DriverId(6)));
    unsafe { IDLE[14] += 1; }
    assert_eq!(before.current_epoch(), before.refused);
    unsafe { IDLE[6] += 1; }
    assert_ne!(before.current_epoch(), before.refused);
}

#[test]
fn only_own_receiver_readiness_wakes_without_an_idle_event() {
    setup();
    let before = AdmissionReceipt::capture(Some(nt_io_manager::DriverId(6)));
    unsafe { READY[14] = true; }
    assert!(!before.became_ready());
    unsafe { READY[6] = true; }
    assert!(before.became_ready());
}

#[test]
fn missing_domain_registration_and_instance_replacement_are_distinct() {
    setup();
    unsafe { PRESENT[6] = false; }
    let missing = AdmissionReceipt::capture(Some(nt_io_manager::DriverId(6)));
    assert_eq!(missing.refused, AdmissionEpoch::MissingDomain);
    unsafe { PRESENT[6] = true; }
    assert_eq!(missing.current_epoch(), AdmissionEpoch::Ready(0));
    unsafe { driver_instances_mut()[6].domain.cookie = 10; }
    assert_eq!(missing.refresh().current_epoch(), AdmissionEpoch::Retired);
    assert_eq!(missing.refresh().owner, missing.owner,
        "a queued IRP never captures a replacement instance's authority");
}
"#;
