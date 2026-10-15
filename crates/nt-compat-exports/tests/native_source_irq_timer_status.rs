//! Run the native IRQ timer operation with controlled lane, mapping and object state.

use std::process::Command;

#[test]
fn irq_timer_thunks_fail_stop_on_invalid_arguments_before_service() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let cancel = source
        .split_once("extern \"win64\" fn s_ke_cancel_timer(")
        .expect("KeCancelTimer thunk").1
        .split_once("extern \"win64\" fn s_ke_set_timer(")
        .expect("next timer thunk").0;
    let set = source
        .split_once("extern \"win64\" fn s_ke_set_timer_ex(")
        .expect("KeSetTimerEx thunk").1
        .split_once("\nextern \"win64\" fn ")
        .expect("next hosted import thunk").0;
    for thunk in [cancel, set] {
        let early_guard = thunk.split_once("return 0;").expect("invalid argument guard").0;
        assert!(early_guard.contains("hosted_irq_lane_context()")
            && early_guard.contains("hosted_irq_lane_protocol_fault("),
            "IRQ DPC invalid timer arguments must fault before returning false");
    }
}

#[test]
fn irq_timer_rejects_invalid_identity_and_objects_before_queue_mutation() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("unsafe fn service_hosted_irq_lane_timer(")
        .expect("native IRQ timer operation");
    let end = source[start..]
        .find("\npub(crate) fn service_hosted_driver_ke_set_timer(")
        .expect("next native timer service");
    let function = &source[start..start + end];
    syn::parse_str::<syn::ItemFn>(function).expect("native timer operation is a complete function");

    let fixture = format!("{MOCKS}\n{function}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-source-irq-timer-status-{}",
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
    assert!(compiled.status.success(), "IRQ timer fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).output().unwrap();
    assert!(result.status.success(), "IRQ timer validation regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr));
}

const MOCKS: &str = r#"
use core::ptr::read_unaligned;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod nt_hosted_runtime {
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum HostedIrqServiceKind { TimerCancel, TimerSet }
}
mod nt_status {
    #[derive(Clone, Copy, Debug)]
    pub struct NtStatus;
    impl NtStatus {
        pub const DEVICE_NOT_CONNECTED: Self = Self;
        pub const INVALID_DEVICE_REQUEST: Self = Self;
        pub const INVALID_PARAMETER: Self = Self;
    }
}
trait ObservedStatus { fn observed(self) -> Result<u8, ()>; }
impl ObservedStatus for u8 { fn observed(self) -> Result<u8, ()> { Ok(self) } }
impl ObservedStatus for Result<u8, nt_status::NtStatus> {
    fn observed(self) -> Result<u8, ()> { self.map_err(|_| ()) }
}

const TIMER_NOTIFICATION_OBJECT: u8 = 8;
const TIMER_SYNCHRONIZATION_OBJECT: u8 = 9;
const KDPC_SIZE: u64 = 0x40;
static INSTANCE_LIVE: AtomicBool = AtomicBool::new(true);
static DOMAIN_LIVE: AtomicBool = AtomicBool::new(true);
static TIMER_MAPPED: AtomicBool = AtomicBool::new(true);
static DPC_MAPPED: AtomicBool = AtomicBool::new(true);
static MUTATIONS: AtomicU64 = AtomicU64::new(0);
static mut TIMER: [u8; 0x40] = [0; 0x40];

#[derive(Clone, Copy)] struct DriverInstance;
#[derive(Clone, Copy)] struct DomainId(u64);
impl DomainId { fn raw(self) -> u64 { self.0 } }
#[derive(Clone, Copy)] struct Domain { domain_id: DomainId, cookie: u64 }
fn instance(_: usize) -> Option<DriverInstance> {
    INSTANCE_LIVE.load(Ordering::Relaxed).then_some(DriverInstance)
}
fn instance_domain_identity(_: DriverInstance) -> Option<Domain> {
    DOMAIN_LIVE.load(Ordering::Relaxed).then_some(Domain { domain_id: DomainId(7), cookie: 11 })
}
fn component_to_exec_va_for_instance(_: usize, _: DriverInstance, ptr: u64, size: u64) -> Option<u64> {
    match (ptr, size) {
        (0x1000, 0x40) if TIMER_MAPPED.load(Ordering::Relaxed) =>
            Some(core::ptr::addr_of!(TIMER) as u64),
        (0x2000, 0x40) if DPC_MAPPED.load(Ordering::Relaxed) => Some(0x2000),
        _ => None,
    }
}
unsafe fn apply_hosted_driver_ke_cancel_timer(_: usize, _: u64) -> u8 {
    MUTATIONS.fetch_add(1, Ordering::Relaxed);
    0 // A valid inactive timer is a successful false result.
}
unsafe fn apply_hosted_driver_ke_set_timer(_: usize, _: u64, _: u64, _: i64, _: u32, _: u64) -> u8 {
    MUTATIONS.fetch_add(1, Ordering::Relaxed);
    1
}
"#;

const CASES: &str = r#"
#[test]
fn rejects_invalid_lane_or_object_but_preserves_valid_inactive_cancel() {
    unsafe { TIMER[0] = TIMER_NOTIFICATION_OBJECT; }
    let cancel = nt_hosted_runtime::HostedIrqServiceKind::TimerCancel;
    let set = nt_hosted_runtime::HostedIrqServiceKind::TimerSet;
    let call = |kind, dpc| unsafe { service_hosted_irq_lane_timer(3, 7, 11, kind, 0x1000, -10, 0, dpc) }.observed();
    assert_eq!(call(cancel, 0), Ok(0));
    assert_eq!(MUTATIONS.load(Ordering::Relaxed), 1);

    INSTANCE_LIVE.store(false, Ordering::Relaxed);
    assert!(call(cancel, 0).is_err(), "retired instance must be an error, not inactive");
    INSTANCE_LIVE.store(true, Ordering::Relaxed);
    assert!(unsafe { service_hosted_irq_lane_timer(3, 7, 12, cancel, 0x1000, -10, 0, 0) }.observed().is_err(),
        "wrong domain cookie must be an error");
    TIMER_MAPPED.store(false, Ordering::Relaxed);
    assert!(call(cancel, 0).is_err(), "unmapped 0x40 KTIMER must be an error");
    TIMER_MAPPED.store(true, Ordering::Relaxed);
    unsafe { TIMER[0] = 0; }
    assert!(call(cancel, 0).is_err(), "invalid timer type must be an error");
    unsafe { TIMER[0] = TIMER_NOTIFICATION_OBJECT; }
    DPC_MAPPED.store(false, Ordering::Relaxed);
    assert!(call(set, 0x2000).is_err(), "unmapped same-instance DPC must be an error");
    assert_eq!(MUTATIONS.load(Ordering::Relaxed), 1, "rejected calls must not mutate timer queue");
}
"#;
