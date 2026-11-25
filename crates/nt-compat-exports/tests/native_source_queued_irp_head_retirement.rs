//! A never-admitted queue head can retire without freeing a physical lane (#427).
//! Execute the native `keep` and `remove` bodies against two queued File rows.

use std::process::Command;

fn body<'a>(source: &'a str, signature: &str) -> &'a str {
    source.split_once(signature).unwrap_or_else(|| panic!("missing {signature}"))
        .1.split_once("\n}").expect("function boundary").0
}

fn optional_function(source: &str, signature: &str) -> String {
    source.split_once(signature).map_or(String::new(), |(_, tail)| {
        let body = tail.split_once("\n}").expect("function boundary").0;
        format!("{signature}{body}\n}}")
    })
}

#[test]
fn retiring_a_never_admitted_head_wakes_only_its_exact_successor() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");
    let keep = body(source, "fn keep(id: u64, payload: Payload) {");
    let remove = body(source, "fn remove(id: u64) -> Result<Row, nt_status::NtStatus> {");
    let ahead = body(source, "fn queued_ahead(id: u64) -> bool {");
    // On the RED baseline these helpers are absent, while the unchanged native keep/remove
    // bodies compile and demonstrate that head retirement does not wake the successor.
    let ticket = optional_function(source,
        "fn queue_head_ticket(id: u64) -> Option<QueueHeadTicket> {");
    let retired = optional_function(source,
        "fn queue_head_retired(ticket: QueueHeadTicket) {");
    let runtime = include_str!("../../nt-hosted-runtime/src/ordinary_irp_lane.rs");
    let queued_selection = runtime.split_once("/// An ordinary IRP that no lane admitted")
        .unwrap().1.split_once("/// How far a File caller's IRP has got").unwrap().0;
    let fixture = format!("{MOCKS}\nfn queued_ahead(id: u64) -> bool {{{ahead}\n}}\n\
        {ticket}\n{retired}\nfn keep(id: u64, payload: Payload) {{{keep}\n}}\n\
        fn remove(id: u64) -> Result<Row, nt_status::NtStatus> {{{remove}\n}}\n\
        /// An ordinary IRP that no lane admitted{queued_selection}\n{CASES}");
    let dir = std::env::temp_dir().join(format!("nt-queued-head-red-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("fixture.rs");
    let binary = dir.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"]).arg(&input).arg("-o").arg(&binary)
        .output().unwrap();
    assert!(compiled.status.success(), "queued head fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(result.status.success(), "queued head retirement regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
}

const MOCKS: &str = r#"
extern crate alloc;
use std::sync::atomic::{AtomicU64, Ordering};
static LANE_EPOCH: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostedDomainIdentity { id: u64, cookie: u64 }
#[derive(Clone, Copy)]
struct DriverInstance { used: bool, driver_id: u64, domain: HostedDomainIdentity, file_worker_epoch: u64 }
const EMPTY: DriverInstance = DriverInstance { used: false, driver_id: 0,
    domain: HostedDomainIdentity { id: 0, cookie: 0 }, file_worker_epoch: 0 };
static mut INSTANCES: [DriverInstance; 15] = [EMPTY; 15];
unsafe fn driver_instances_mut() -> &'static mut [DriverInstance; 15] {
    &mut *std::ptr::addr_of_mut!(INSTANCES)
}
fn instance(index: usize) -> Option<DriverInstance> { unsafe {
    driver_instances_mut().get(index).copied().filter(|row| row.used)
} }
fn instance_by_driver_id(driver: u64) -> Option<(usize, DriverInstance)> {
    unsafe { driver_instances_mut() }.iter().copied().enumerate()
        .find(|(_, row)| row.used && row.driver_id == driver)
}
fn lane_freed() { LANE_EPOCH.fetch_add(1, Ordering::AcqRel); }
fn instance_domain_identity(inst: DriverInstance) -> Option<HostedDomainIdentity> {
    (inst.domain.id != 0 && inst.domain.cookie != 0).then_some(inst.domain)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Authority { instance: usize, driver_id: u64, domain: HostedDomainIdentity }
impl Authority {
    fn capture(index: usize) -> Option<Self> {
        let inst = instance(index)?;
        Some(Self { instance: index, driver_id: inst.driver_id, domain: inst.domain })
    }
    fn live(self) -> bool { Self::capture(self.instance) == Some(self) }
}
#[derive(Clone, Copy)] struct AdmissionReceipt { owner: Option<Authority> }
#[derive(Clone, Copy)] struct QueueHeadTicket { id: u64, owner: Authority }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] enum Flight { QueuedDispatch, Idle, Blocked }
#[derive(Clone, Copy)] enum Payload { Prepared, Retained }
#[derive(Clone, Copy)] struct IrpId(u64);
impl IrpId { fn raw(self) -> u64 { self.0 } }
mod nt_io_manager { #[derive(Clone, Copy, Eq, PartialEq)] pub struct DriverId(pub u64);
    impl DriverId { pub fn raw(self) -> u64 { self.0 } } }
mod nt_status { #[derive(Clone, Copy, Debug)] pub struct NtStatus(pub i32); }
#[derive(Clone, Copy)] struct Requestor;
impl Requestor { fn release(self, _: &mut ()) -> Result<(), i32> { Ok(()) } }
struct Row {
    id: u64, requestor: Requestor, primary_driver: Option<nt_io_manager::DriverId>,
    authorities: Vec<Authority>, irp_id: Option<IrpId>, queue_not_admitted: bool,
    flight: Flight, admission_receipt: AdmissionReceipt, payload: Option<Payload>,
    blocked_status: Option<nt_status::NtStatus>, retry_after: u64,
}
static mut ROWS: Option<Vec<Row>> = None;
fn rows() -> &'static mut Vec<Row> { unsafe { (&mut *std::ptr::addr_of_mut!(ROWS)).as_mut().unwrap() } }
fn row(id: u64) -> &'static mut Row { rows().iter_mut().find(|row| row.id == id).unwrap() }
fn release_projection_owners(_: u64) -> Result<(), nt_status::NtStatus> { Ok(()) }
fn quarantine_release(_: u64, _: nt_status::NtStatus) { panic!("unexpected quarantine") }
fn with_provider_process_manager<R>(f: impl FnOnce(&mut ()) -> R) -> R { f(&mut ()) }
mod hosted_class_irp_lane { pub unsafe fn release_irp(_: usize, _: u64) {} }
mod service_sec_image { pub fn hosted_file_dispatch_returned(_: u64) {} }
fn trace_nested_pnp_create_owner(_: u64, _: u64, _: IrpId) {}
fn setup() { unsafe {
    let table = driver_instances_mut();
    table[6] = DriverInstance { used: true, driver_id: 6,
        domain: HostedDomainIdentity { id: 6, cookie: 9 }, file_worker_epoch: 0 };
    table[14] = DriverInstance { used: true, driver_id: 14,
        domain: HostedDomainIdentity { id: 14, cookie: 9 }, file_worker_epoch: 0 };
    let owner = Authority::capture(6).unwrap();
    ROWS = Some([7, 8].into_iter().map(|id| Row {
        id, requestor: Requestor, primary_driver: Some(nt_io_manager::DriverId(6)),
        authorities: vec![owner], irp_id: Some(IrpId(id)), queue_not_admitted: true,
        flight: Flight::QueuedDispatch, admission_receipt: AdmissionReceipt { owner: Some(owner) },
        payload: Some(Payload::Prepared), blocked_status: None, retry_after: 0,
    }).collect());
    LANE_EPOCH.store(1, Ordering::Release);
} }
"#;

const CASES: &str = r#"
fn successor_candidates() -> alloc::vec::Vec<u64> {
    queued_admission_candidates(&[QueuedIrp { id: 8, driver: 6, refused_at: 0,
        current_epoch: Some(instance(6).unwrap().file_worker_epoch),
        wake_without_epoch: false, cancel_queued: false }])
}
#[test]
fn cancelled_head_wakes_successor_without_a_physical_lane_release() {
    setup();
    keep(7, Payload::Retained);
    assert_eq!(row(7).flight, Flight::Idle);
    assert_eq!(row(8).flight, Flight::QueuedDispatch);
    assert_eq!(instance(6).unwrap().file_worker_epoch, 1,
        "the successor needs a distinct queue-head-retired epoch");
    assert_eq!(successor_candidates(), [8], "the successor can now be admitted");
    assert_eq!(instance(14).unwrap().file_worker_epoch, 0);
}
#[test]
fn removing_head_wakes_successor_but_nonhead_does_not() {
    setup();
    keep(8, Payload::Retained);
    assert_eq!(instance(6).unwrap().file_worker_epoch, 0,
        "a nonhead cancellation cannot wake the still-queued head");
    assert!(successor_candidates().is_empty());
    setup();
    remove(7).unwrap();
    assert_eq!(row(8).flight, Flight::QueuedDispatch);
    assert_eq!(instance(6).unwrap().file_worker_epoch, 1);
    assert_eq!(successor_candidates(), [8]);
}
#[test]
fn retired_instance_generation_does_not_gain_a_queue_wake() {
    setup();
    unsafe { driver_instances_mut()[6].domain.cookie = 10; }
    keep(7, Payload::Retained);
    assert_eq!(instance(6).unwrap().file_worker_epoch, 0);
}
"#;
