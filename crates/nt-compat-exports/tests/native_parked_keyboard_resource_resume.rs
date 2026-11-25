//! A sibling i8042prt grant must not leak into a parked keyboard StartDevice continuation.
//! Compile the native continuation's rebind and resume paths against two device assignments.

use std::process::Command;

struct FixtureDirectory(std::path::PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const OWNER: &str = include_str!(
    "../../nt-hosted-runtime/src/retained_dispatch_context.rs"
);

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing native start: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing native end: {end}"))
        .0
}

#[test]
fn parked_keyboard_reprojects_its_resource_bank_before_resuming_start() {
    let rebind = between(
        DRIVER,
        "    unsafe fn rebind_bindings(",
        "    /// Resume the receive half after an outer-loop child step.",
    );
    let resume = between(
        DRIVER,
        "    pub(super) unsafe fn resume_after_child(",
        "\n}\n\npub(super) enum HostedIrpDispatchProgress",
    );
    let fixture = format!(
        "mod retained_dispatch_context {{\n{OWNER}\n}}\n{SUPPORT}\nmod native {{\nuse super::*;\nimpl FileIrpPumpContinuation {{\n    unsafe fn rebind_bindings({rebind}\n    pub(super) unsafe fn resume_after_child({resume}\n}}\n}}\n{CASES}"
    );
    let directory = FixtureDirectory(std::env::temp_dir().join(format!(
        "nt-parked-keyboard-resource-resume-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let input = directory.0.join("fixture.rs");
    let binary = directory.0.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native keyboard continuation fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let run = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "parked keyboard resource regression:\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

const SUPPORT: &str = r#"
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

static PRIMARY_VECTOR: AtomicU32 = AtomicU32::new(0);
static PRIMARY_PORT_CAP: AtomicU64 = AtomicU64::new(0);
static WORKER_VECTOR: AtomicU32 = AtomicU32::new(0);
static WORKER_PORT_CAP: AtomicU64 = AtomicU64::new(0);
static RESUMED_VECTOR: AtomicU32 = AtomicU32::new(0);
static RESUMED_PORT_CAP: AtomicU64 = AtomicU64::new(0);
static RESUME_WORKER: AtomicBool = AtomicBool::new(false);
static RESTORE_FAIL: AtomicBool = AtomicBool::new(false);
static CHILD_RESUMES: AtomicU32 = AtomicU32::new(0);

mod nt_status {
    #[derive(Clone, Copy, Debug)]
    pub struct NtStatus;
    impl NtStatus {
        pub const DEVICE_BUSY: Self = Self;
        pub const DEVICE_NOT_CONNECTED: Self = Self;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostedDeviceBinding { vector: u32, port_cap: u64 }
#[derive(Clone, Copy)]
struct DriverInstance { exec_shared_va: u64, cnode: u64 }
struct Selection { cnode: u64 }

fn restore_hosted_device_resource_state(
    binding: HostedDeviceBinding, shared_va: u64, cnode: u64, _: bool,
) -> Result<(), nt_status::NtStatus> {
    if RESTORE_FAIL.load(Ordering::Relaxed) {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    match (shared_va, cnode) {
        (100, 1) => {
            PRIMARY_VECTOR.store(binding.vector, Ordering::Relaxed);
            PRIMARY_PORT_CAP.store(binding.port_cap, Ordering::Relaxed);
        }
        (200, 2) => {
            WORKER_VECTOR.store(binding.vector, Ordering::Relaxed);
            WORKER_PORT_CAP.store(binding.port_cap, Ordering::Relaxed);
        }
        other => panic!("unexpected lane projection: {other:?}"),
    }
    Ok(())
}
fn project_provider_device_dispatch_state(
    _: HostedDeviceBinding, _: u64, _: DriverInstance, _: u64,
) -> Result<(), nt_status::NtStatus> { panic!("ordinary keyboard must not enter provider projection") }

struct SuspendedActiveHostedIrpTransfer;
struct ActiveHostedIrpTransferGuard;
impl ActiveHostedIrpTransferGuard {
    unsafe fn resume(ticket: SuspendedActiveHostedIrpTransfer)
        -> Result<Self, (nt_status::NtStatus, SuspendedActiveHostedIrpTransfer)>
    {
        let _ = ticket;
        Ok(Self)
    }
    fn suspend(self) -> Result<SuspendedActiveHostedIrpTransfer, (nt_status::NtStatus, Self)> {
        Ok(SuspendedActiveHostedIrpTransfer)
    }
}

struct SuspendedHostedDeviceDispatchContext {
    binding: HostedDeviceBinding,
    shared_va: u64,
}
struct HostedDeviceDispatchContextGuard {
    binding: HostedDeviceBinding,
    shared_va: u64,
}
impl HostedDeviceDispatchContextGuard {
    unsafe fn resume(ticket: SuspendedHostedDeviceDispatchContext)
        -> Result<Self, (nt_status::NtStatus, SuspendedHostedDeviceDispatchContext)>
    {
        Ok(Self { binding: ticket.binding, shared_va: ticket.shared_va })
    }
    unsafe fn projection_binding(&self, shared_va: u64)
        -> Result<HostedDeviceBinding, nt_status::NtStatus>
    {
        assert_eq!(shared_va, self.shared_va);
        Ok(self.binding)
    }
    fn suspend(self) -> Result<SuspendedHostedDeviceDispatchContext,
        (nt_status::NtStatus, Self)>
    {
        Ok(SuspendedHostedDeviceDispatchContext {
            binding: self.binding,
            shared_va: self.shared_va,
        })
    }
}
impl retained_dispatch_context::RetainedContextBinding for HostedDeviceDispatchContextGuard {
    type Suspended = SuspendedHostedDeviceDispatchContext;
    type Error = nt_status::NtStatus;

    fn suspend(self) -> Result<Self::Suspended, (Self::Error, Self)> {
        self.suspend()
    }
    fn resume(ticket: Self::Suspended) -> Result<Self, (Self::Error, Self::Suspended)> {
        unsafe { Self::resume(ticket) }
    }
}
type DeviceDispatchContextOwner =
    retained_dispatch_context::RetainedContextOwner<HostedDeviceDispatchContextGuard>;

enum FileTransferOwner {
    Active(ActiveHostedIrpTransferGuard),
    Suspended(SuspendedActiveHostedIrpTransfer),
}

mod component_scheduler {
    use super::{CHILD_RESUMES, Ordering, PRIMARY_PORT_CAP, PRIMARY_VECTOR,
        RESUMED_PORT_CAP, RESUMED_VECTOR, RESUME_WORKER, WORKER_PORT_CAP, WORKER_VECTOR};

    pub enum HostedPumpRestore {
        ChildWorkReady { epoch: u64 },
        Restored(()),
    }
    pub fn resume_child_work(pump: HostedPumpRestore, _: u64)
        -> Result<HostedPumpRestore, (HostedPumpRestore, u64)>
    {
        CHILD_RESUMES.fetch_add(1, Ordering::Relaxed);
        let (vector, cap) = if RESUME_WORKER.load(Ordering::Relaxed) {
            (WORKER_VECTOR.load(Ordering::Relaxed), WORKER_PORT_CAP.load(Ordering::Relaxed))
        } else {
            (PRIMARY_VECTOR.load(Ordering::Relaxed), PRIMARY_PORT_CAP.load(Ordering::Relaxed))
        };
        RESUMED_VECTOR.store(vector, Ordering::Relaxed);
        RESUMED_PORT_CAP.store(cap, Ordering::Relaxed);
        Ok(HostedPumpRestore::Restored(()))
    }
    pub fn retry_child_work(_: HostedPumpRestore) -> HostedPumpRestore {
        RESUMED_VECTOR.store(PRIMARY_VECTOR.load(Ordering::Relaxed), Ordering::Relaxed);
        RESUMED_PORT_CAP.store(PRIMARY_PORT_CAP.load(Ordering::Relaxed), Ordering::Relaxed);
        HostedPumpRestore::Restored(())
    }
}

struct FileIrpPumpContinuation {
    pump: Option<component_scheduler::HostedPumpRestore>,
    transfer: Option<FileTransferOwner>,
    device_context: Option<DeviceDispatchContextOwner>,
    class_selection: Option<Selection>,
    dependent_inst: DriverInstance,
    d: DriverInstance,
    shared_va: u64,
    provider_binding: Option<HostedDeviceBinding>,
    child_step: Option<u64>,
    ready_for_child: bool,
}
struct HostedIrpTransportResult { vector: u32, port_cap: u64 }
enum FileIrpResumeProgress {
    Completed(HostedIrpTransportResult),
    ChildWorkYield(FileIrpPumpContinuation),
}
impl FileIrpPumpContinuation {
    fn restore_retryable(&self) -> bool { false }
    unsafe fn suspend_bindings(&mut self) {
        if let Some(owner) = self.transfer.take() {
            self.transfer = Some(match owner {
                FileTransferOwner::Active(guard) =>
                    FileTransferOwner::Suspended(guard.suspend().ok().unwrap()),
                owner => owner,
            });
        }
        if let Some(owner) = self.device_context.take() {
            self.device_context = Some(owner.suspend().unwrap_or_else(|(_, owner)| owner));
        }
    }
    fn finish(self, _: &mut [u8]) -> HostedIrpTransportResult {
        HostedIrpTransportResult {
            vector: RESUMED_VECTOR.load(Ordering::Relaxed),
            port_cap: RESUMED_PORT_CAP.load(Ordering::Relaxed),
        }
    }
}
"#;

const CASES: &str = r#"
#[test]
fn keyboard_start_uses_keyboard_vector_and_cap_after_mouse_grant() {
    RESUME_WORKER.store(false, Ordering::Relaxed);
    RESTORE_FAIL.store(false, Ordering::Relaxed);
    // The primary lane is parked inside keyboard StartDevice. The mouse assignment and its
    // worker can run meanwhile, but keyboard's receive half must see its own grant on resume.
    PRIMARY_VECTOR.store(11, Ordering::Relaxed);
    PRIMARY_PORT_CAP.store(0x60, Ordering::Relaxed);
    let keyboard = FileIrpPumpContinuation {
        pump: Some(component_scheduler::HostedPumpRestore::ChildWorkReady { epoch: 1 }),
        transfer: Some(FileTransferOwner::Suspended(SuspendedActiveHostedIrpTransfer)),
        device_context: Some(DeviceDispatchContextOwner::Suspended(
            SuspendedHostedDeviceDispatchContext {
                binding: HostedDeviceBinding { vector: 11, port_cap: 0x60 },
                shared_va: 100,
            },
        )),
        class_selection: None,
        dependent_inst: DriverInstance { exec_shared_va: 100, cnode: 1 },
        d: DriverInstance { exec_shared_va: 100, cnode: 1 },
        shared_va: 100,
        provider_binding: None,
        child_step: Some(1),
        ready_for_child: false,
    };
    // This models the observed grant-time write into i8042prt's shared primary bank.
    PRIMARY_VECTOR.store(12, Ordering::Relaxed);
    PRIMARY_PORT_CAP.store(0x64, Ordering::Relaxed);
    WORKER_VECTOR.store(12, Ordering::Relaxed);
    WORKER_PORT_CAP.store(0x64, Ordering::Relaxed);
    assert_eq!(WORKER_VECTOR.load(Ordering::Relaxed), 12);
    assert_eq!(WORKER_PORT_CAP.load(Ordering::Relaxed), 0x64);

    let progress = unsafe { keyboard.resume_after_child(&mut []) };
    let FileIrpResumeProgress::Completed(receipt) = progress.ok().expect("keyboard resume") else {
        panic!("keyboard must complete its selected child step");
    };
    assert_eq!(receipt.vector, 11, "keyboard must not observe mouse's vector 12");
    assert_eq!(receipt.port_cap, 0x60, "keyboard must not borrow mouse's port cap");
}

#[test]
fn worker_reprojects_its_own_bank_without_changing_parked_primary() {
    RESUME_WORKER.store(true, Ordering::Relaxed);
    RESTORE_FAIL.store(false, Ordering::Relaxed);
    PRIMARY_VECTOR.store(11, Ordering::Relaxed);
    PRIMARY_PORT_CAP.store(0x60, Ordering::Relaxed);
    WORKER_VECTOR.store(99, Ordering::Relaxed);
    WORKER_PORT_CAP.store(0, Ordering::Relaxed);
    let mouse = FileIrpPumpContinuation {
        pump: Some(component_scheduler::HostedPumpRestore::ChildWorkReady { epoch: 2 }),
        transfer: Some(FileTransferOwner::Suspended(SuspendedActiveHostedIrpTransfer)),
        device_context: Some(DeviceDispatchContextOwner::Suspended(
            SuspendedHostedDeviceDispatchContext {
                binding: HostedDeviceBinding { vector: 12, port_cap: 0x64 },
                shared_va: 200,
            },
        )),
        class_selection: Some(Selection { cnode: 2 }),
        dependent_inst: DriverInstance { exec_shared_va: 100, cnode: 1 },
        d: DriverInstance { exec_shared_va: 100, cnode: 1 },
        shared_va: 200,
        provider_binding: None,
        child_step: Some(2),
        ready_for_child: false,
    };
    let progress = unsafe { mouse.resume_after_child(&mut []) };
    let FileIrpResumeProgress::Completed(receipt) = progress.ok().expect("mouse resume") else {
        panic!("mouse must complete its selected child step");
    };
    assert_eq!((receipt.vector, receipt.port_cap), (12, 0x64));
    assert_eq!(PRIMARY_VECTOR.load(Ordering::Relaxed), 11);
    assert_eq!(PRIMARY_PORT_CAP.load(Ordering::Relaxed), 0x60);
}

#[test]
fn refused_reprojection_retains_child_and_exact_owners_without_retrying_pump() {
    RESUME_WORKER.store(false, Ordering::Relaxed);
    RESTORE_FAIL.store(true, Ordering::Relaxed);
    let before = CHILD_RESUMES.load(Ordering::Relaxed);
    let keyboard = FileIrpPumpContinuation {
        pump: Some(component_scheduler::HostedPumpRestore::ChildWorkReady { epoch: 3 }),
        transfer: Some(FileTransferOwner::Suspended(SuspendedActiveHostedIrpTransfer)),
        device_context: Some(DeviceDispatchContextOwner::Suspended(
            SuspendedHostedDeviceDispatchContext {
                binding: HostedDeviceBinding { vector: 11, port_cap: 0x60 },
                shared_va: 100,
            },
        )),
        class_selection: None,
        dependent_inst: DriverInstance { exec_shared_va: 100, cnode: 1 },
        d: DriverInstance { exec_shared_va: 100, cnode: 1 },
        shared_va: 100,
        provider_binding: None,
        child_step: Some(3),
        ready_for_child: false,
    };
    let retained = unsafe { keyboard.resume_after_child(&mut []) }.err()
        .expect("uncertain projection must retain the continuation");
    assert!(matches!(retained.pump,
        Some(component_scheduler::HostedPumpRestore::ChildWorkReady { .. })));
    assert_eq!(retained.child_step, Some(3));
    assert!(matches!(retained.transfer, Some(FileTransferOwner::Suspended(_))));
    assert!(matches!(retained.device_context, Some(DeviceDispatchContextOwner::Suspended(_))));
    assert_eq!(CHILD_RESUMES.load(Ordering::Relaxed), before);
}
"#;
