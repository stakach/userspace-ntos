//! Keep a service-less RawDeviceOK START on the real accepted PDO provider path.
//!
//! The pure PnP crate already owns direct START admission and terminal receipts. These source
//! checks guard the native PlugPlayControlStartDevice caller that currently exits at the Enum
//! Service lookup before it can use those contracts.

use std::process::Command;

fn start_control_source() -> &'static str {
    let source = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let start = source
        .find("unsafe fn pnp_control_start_device(")
        .expect("native StartDevice control caller");
    let end = source[start..]
        .find("\n    unsafe fn pnp_begin_rebalance(")
        .expect("following native PnP control method");
    &source[start..start + end]
}

#[test]
fn native_lookup_distinguishes_missing_enum_service_from_missing_key_or_broken_service() {
    let source = include_str!("../../../components/ntos-executive/src/main.rs");
    let start = source
        .find("pub(crate) unsafe fn live_config_existing_device_launch_spec(")
        .expect("native existing-device service lookup");
    let typed_start = source[start..]
        .find("pub(crate) unsafe fn live_config_existing_device_start_service(")
        .map(|offset| start + offset)
        .expect("typed existing-device service lookup");
    let end = source[start..]
        .find("\n#[derive(Clone, Copy, Default)]")
        .expect("following native launch-plan type");
    let wrapper = &source[start..typed_start];
    let lookup = &source[typed_start..start + end];

    assert!(wrapper.contains("live_config_existing_device_start_service("),
        "other callers must share the typed lookup before mapping its status");
    let opened = lookup.find("config_manager_open_system_hive_key(&enum_path)")
        .expect("open exact Enum key before classifying its Service value");
    let resolved = lookup.find("resolve_existing_device_start_service(")
        .expect("classify missing Service only after an opened Enum key");
    let query = lookup.find("config_manager_query_leased_system_hive_value(key, \"Service\")")
        .expect("query Service through the exact key lease");
    let retired = lookup.find("config_manager_retire_system_hive_key(opened.lease)")
        .expect("retire the retained Enum key lease on every outcome");
    assert!(opened < resolved && resolved < query && query < retired,
        "native lookup must use the opened-key Service contract and retire its lease");
}

#[test]
fn service_less_raw_device_reaches_direct_pdo_start_while_named_service_keeps_driver_batch() {
    let caller = start_control_source();
    let start = caller
        .find("let spec = match live_config_existing_device_start_service(")
        .expect("production Service decision");
    let end = caller[start..]
        .find("if REPLY_MAIN_SLOT.load(")
        .expect("following native Reply admission");
    let decision = &caller[start..start + end];
    let fixture = format!("{PORTS}\n{DECIDE_START}\n{decision}\n{DECIDE_END}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-raw-pdo-start-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "production Service decision must compile in the fixture:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(result.status.success(), "native raw-PDO START decision regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr));
}

#[test]
fn native_raw_start_retains_exact_provider_irp_and_terminal_lifecycle_receipt() {
    let native = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(native.contains("PreparedAcceptedPdoPnp::start_direct("),
        "native raw route must prepare a canonical accepted-PDO START IRP");
    assert!(native.contains("retire_with_receipt("),
        "the provider terminal and ACK must yield the exact I/O receipt");
    assert!(native.contains("complete_start_device_dispatch("),
        "DN_STARTED must follow only the matching PnP token and terminal I/O receipt");
}

const PORTS: &str = r#"
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const SERVICE_DEMAND_START: u32 = 3;
static PNP_START_LOOKUP_CONTEXT_TRACE_N: AtomicUsize = AtomicUsize::new(32);

mod driver_launch {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum DriverClass { Device, Other }
    #[derive(Clone, Copy)]
    pub enum DeviceState { Enumerated }
    pub fn hosted_pnp_start_diagnostic_identity(
        _: &str,
    ) -> Option<(u64, u64, u64, DeviceState, Option<bool>)> { None }
}

#[derive(Clone)]
struct DriverServiceLaunchSpec {
    class: driver_launch::DriverClass,
    devnodes: Vec<u64>,
}
#[derive(Debug, PartialEq, Eq)]
enum Outcome { NamedService, DirectPending, NoStartIrp(u32) }
mod nt_pnp_manager {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ExistingDeviceStartServiceError { MissingService, Failure(i32) }
}
use nt_pnp_manager::ExistingDeviceStartServiceError;
#[derive(Clone, Copy)]
struct Request(u64);
impl Request {
    fn sequence(self) -> u64 { self.0 }
}
#[derive(Clone, Copy)]
struct StatusRecord { status: u32, problem: u32 }
struct PnpStatus { records: [StatusRecord; 1] }
struct Handler {
    raw_device_ok: bool,
    no_irp_calls: usize,
    direct_calls: usize,
    pnp_status: PnpStatus,
}
impl Handler {
    fn new(raw_device_ok: bool) -> Self {
        Self { raw_device_ok, no_irp_calls: 0, direct_calls: 0,
            pnp_status: PnpStatus { records: [StatusRecord { status: 0, problem: 0 }] } }
    }
    fn pnp_complete_start_without_irp(&mut self, _: Request, status: u32) -> Outcome {
        self.no_irp_calls += 1;
        Outcome::NoStartIrp(status)
    }
    fn pnp_status_slot(&self, _: &str) -> Option<usize> { None }
    // The native direct path may call this seam once its retained owner exists.
    fn start_hosted_raw_pdo(&mut self, _: &str, request: Request) -> Outcome {
        if !self.raw_device_ok {
            return self.pnp_complete_start_without_irp(request, STATUS_OBJECT_NAME_NOT_FOUND);
        }
        self.direct_calls += 1;
        Outcome::DirectPending
    }
}
fn print_str(_: &[u8]) {}
fn print_u64(_: u64) {}
fn print_hex_u64(_: u64) {}
thread_local! {
    static LOOKUP: RefCell<Result<DriverServiceLaunchSpec, ExistingDeviceStartServiceError>> =
        RefCell::new(Err(ExistingDeviceStartServiceError::MissingService));
}
fn live_config_existing_device_start_service(
    _: &str, _: u32, _: bool,
) -> Result<DriverServiceLaunchSpec, ExistingDeviceStartServiceError> {
    LOOKUP.with(|value| value.borrow().clone())
}
fn live_config_existing_device_launch_spec(
    instance: &str, start: u32, trace: bool,
) -> Result<DriverServiceLaunchSpec, i32> {
    live_config_existing_device_start_service(instance, start, trace).map_err(|error| match error {
        ExistingDeviceStartServiceError::MissingService => STATUS_OBJECT_NAME_NOT_FOUND as i32,
        ExistingDeviceStartServiceError::Failure(status) => status,
    })
}
fn set_lookup(value: Result<DriverServiceLaunchSpec, ExistingDeviceStartServiceError>) {
    LOOKUP.with(|slot| *slot.borrow_mut() = value);
}
"#;

const DECIDE_START: &str = r#"
impl Handler {
    unsafe fn decide(&mut self) -> Outcome {
        let instance = String::from("ACPI\\FixedButton\\FFB0");
        let request = Request(19);
        let caller_pid = 41u64;
        let caller_generation = 9u64;
        macro_rules! no_start_irp {
            ($status:expr) => {{ return self.pnp_complete_start_without_irp(request, $status); }};
        }
"#;

const DECIDE_END: &str = r#"
        Outcome::NamedService
    }
}
"#;

const CASES: &str = r#"
#[test]
fn service_less_raw_pdo_starts_a_real_owned_request() {
    set_lookup(Err(ExistingDeviceStartServiceError::MissingService));
    let mut handler = Handler::new(true);
    assert_eq!(unsafe { handler.decide() }, Outcome::DirectPending,
        "missing Service on RawDeviceOK must enter a retained PDO START instead of a no-IRP reply");
    assert_eq!(handler.direct_calls, 1);
    assert_eq!(handler.no_irp_calls, 0);
}

#[test]
fn configured_service_keeps_the_named_function_stack() {
    set_lookup(Ok(DriverServiceLaunchSpec {
        class: driver_launch::DriverClass::Device,
        devnodes: vec![71],
    }));
    let mut handler = Handler::new(true);
    assert_eq!(unsafe { handler.decide() }, Outcome::NamedService);
    assert_eq!(handler.direct_calls, 0);
    assert_eq!(handler.no_irp_calls, 0);
}

#[test]
fn nonraw_or_other_lookup_failure_cannot_take_direct_start() {
    set_lookup(Err(ExistingDeviceStartServiceError::MissingService));
    let mut nonraw = Handler::new(false);
    assert_eq!(unsafe { nonraw.decide() },
        Outcome::NoStartIrp(STATUS_OBJECT_NAME_NOT_FOUND));
    assert_eq!(nonraw.direct_calls, 0);

    set_lookup(Err(ExistingDeviceStartServiceError::Failure(STATUS_ACCESS_DENIED as i32)));
    let mut refused = Handler::new(true);
    assert_eq!(unsafe { refused.decide() }, Outcome::NoStartIrp(STATUS_ACCESS_DENIED));
    assert_eq!(refused.direct_calls, 0);

    set_lookup(Err(ExistingDeviceStartServiceError::Failure(STATUS_OBJECT_NAME_NOT_FOUND as i32)));
    let mut missing_key = Handler::new(true);
    assert_eq!(unsafe { missing_key.decide() },
        Outcome::NoStartIrp(STATUS_OBJECT_NAME_NOT_FOUND));
    assert_eq!(missing_key.direct_calls, 0);
}
"#;
