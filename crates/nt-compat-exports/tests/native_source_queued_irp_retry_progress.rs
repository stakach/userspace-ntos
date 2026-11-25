//! Execute the native queue receipt and the owned redrive prelude against staged wake changes.

use std::process::Command;

#[test]
fn queue_retries_only_after_owned_continuation_progress() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
    let queue = source.split_once("fn queue_unadmitted(id: u64, prepared: PreparedExternalFileIrp, reason: QueueReason) {")
        .unwrap().1.split_once("\n}\n\nfn queued_admissions").unwrap().0;
    let redrive = source.split_once("fn redrive_queued(id: u64) -> QueuedReadRedriveOutcome {")
        .unwrap().1.split_once("let Some(irp_id)").unwrap().0;
    let fixture = format!("{SUPPORT}\nfn queue_unadmitted(id: u64, prepared: PreparedExternalFileIrp, reason: QueueReason) {{{queue}\n}}\n\
        fn consume_redrive_prefix(id: u64) -> QueuedReadRedriveOutcome {{{redrive}\n\
        QueuedReadRedriveOutcome::Progressed\n}}\n{CASES}");
    let dir = std::env::temp_dir().join(format!("nt-queued-retry-progress-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("fixture.rs");
    let binary = dir.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&input).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "native retry fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.status.success(), "native retry progress:\n{}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

const SUPPORT: &str = r#"
#[derive(Clone, Copy, Debug, Eq, PartialEq)] enum AdmissionEpoch { Retired, MissingDomain, Ready(u64) }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct Authority { instance: usize }
static mut LIVE: bool = true;
static mut STATE: AdmissionEpoch = AdmissionEpoch::Ready(0);
impl Authority { fn live(self) -> bool { unsafe { LIVE } } }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct AdmissionReceipt {
    owner: Option<Authority>, refused: AdmissionEpoch,
}
impl AdmissionReceipt {
    fn capture(_: Option<nt_io_manager::DriverId>) -> Self {
        Self { owner: Some(Authority { instance: 6 }), refused: unsafe { STATE } }
    }
    fn current_epoch(self) -> AdmissionEpoch {
        if self.owner.is_some_and(Authority::live) { unsafe { STATE } }
        else { AdmissionEpoch::Retired }
    }
    fn refresh(self) -> Self { Self { owner: self.owner, refused: self.current_epoch() } }
}
mod nt_io_manager { #[derive(Clone, Copy)] pub struct DriverId(pub u64); }
mod component_scheduler {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum PendingSchedulerProgress { Service, Restore(u64) }
}
static mut PHASE: Option<component_scheduler::PendingSchedulerProgress> = None;
mod hosted_class_irp_lane {
    pub unsafe fn startup_retry_progress(_: usize)
        -> Option<super::component_scheduler::PendingSchedulerProgress> { super::PHASE }
}
#[derive(Clone, Copy)] enum QueueReason { OlderQueuedIrp, NoLane, RedriveNoLane }
#[derive(Clone, Copy, PartialEq, Eq)] enum Flight { QueuedDispatch }
#[derive(Clone, Copy)] struct Projection { major: u8 }
#[derive(Clone, Copy)] struct PreparedExternalFileIrp { major: u8 }
impl PreparedExternalFileIrp { fn projection(&self) -> Projection { Projection { major: self.major } } }
enum Payload { Prepared(PreparedExternalFileIrp) }
#[derive(Clone, Copy)] struct IrpId(u64);
struct Row {
    irp_id: Option<IrpId>,
    primary_driver: Option<nt_io_manager::DriverId>,
    admission_receipt: AdmissionReceipt,
    startup_probe_phase: Option<component_scheduler::PendingSchedulerProgress>,
    startup_probe_owed: bool,
    retired_probe_consumed: bool,
    missing_domain_probe_consumed: bool,
    payload: Option<Payload>, flight: Flight, blocked_status: Option<()>,
}
static mut ROW: Option<Row> = None;
fn row(_: u64) -> &'static mut Row { unsafe { (*std::ptr::addr_of_mut!(ROW)).as_mut().unwrap() } }
fn trace_initial_queue(_: u64, _: u8, _: QueueReason) {}
fn trace_irp_queue(_: usize, _: u64, _: u8) {}
fn trace_nested_pnp_create_owner(_: u64, _: u64, _: IrpId) {}
enum QueuedReadRedriveOutcome { NoWork, Progressed }
mod allocator { pub fn enter_durable() {} }
fn init() { unsafe {
    LIVE = true; STATE = AdmissionEpoch::Ready(0); PHASE = None;
    *std::ptr::addr_of_mut!(ROW) = Some(Row {
        irp_id: None,
        primary_driver: Some(nt_io_manager::DriverId(6)),
        admission_receipt: AdmissionReceipt::capture(None),
        startup_probe_phase: None, startup_probe_owed: false,
        retired_probe_consumed: false, missing_domain_probe_consumed: false,
        payload: None, flight: Flight::QueuedDispatch, blocked_status: None,
    });
} }
"#;

const CASES: &str = r#"
#[test]
fn service_to_restore_gets_one_more_drive_but_repeated_restore_does_not_spin() {
    init();
    unsafe { PHASE = Some(component_scheduler::PendingSchedulerProgress::Service); }
    queue_unadmitted(1, PreparedExternalFileIrp { major: 0 }, QueueReason::NoLane);
    assert!(row(1).startup_probe_owed);
    let _ = consume_redrive_prefix(1);
    assert!(!row(1).startup_probe_owed);
    unsafe { PHASE = Some(component_scheduler::PendingSchedulerProgress::Restore(17)); }
    queue_unadmitted(1, PreparedExternalFileIrp { major: 0 }, QueueReason::RedriveNoLane);
    assert!(row(1).startup_probe_owed, "owned Service to Restore progress needs another drive");
    let _ = consume_redrive_prefix(1);
    queue_unadmitted(1, PreparedExternalFileIrp { major: 0 }, QueueReason::RedriveNoLane);
    assert!(!row(1).startup_probe_owed, "same refused restore cannot busy spin");
}

#[test]
fn missing_domain_then_retirement_each_get_one_distinct_disposition_probe() {
    init();
    unsafe { STATE = AdmissionEpoch::MissingDomain; }
    queue_unadmitted(1, PreparedExternalFileIrp { major: 0 }, QueueReason::NoLane);
    let original = row(1).admission_receipt.owner;
    let _ = consume_redrive_prefix(1);
    assert!(row(1).missing_domain_probe_consumed);
    assert!(!row(1).retired_probe_consumed);
    queue_unadmitted(1, PreparedExternalFileIrp { major: 0 }, QueueReason::RedriveNoLane);
    assert_eq!(row(1).admission_receipt.owner, original);
    unsafe { STATE = AdmissionEpoch::Ready(0); }
    queue_unadmitted(1, PreparedExternalFileIrp { major: 0 }, QueueReason::RedriveNoLane);
    assert!(!row(1).missing_domain_probe_consumed,
        "a repaired registration starts a new missing-domain episode");
    unsafe { STATE = AdmissionEpoch::MissingDomain; }
    let _ = consume_redrive_prefix(1);
    assert!(row(1).missing_domain_probe_consumed);
    unsafe { LIVE = false; }
    let _ = consume_redrive_prefix(1);
    assert!(row(1).retired_probe_consumed);
    assert_eq!(row(1).admission_receipt.owner, original);
}
"#;
