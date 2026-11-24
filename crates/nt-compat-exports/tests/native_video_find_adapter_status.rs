//! A successful hosted dispatch must not erase the miniport's own FindAdapter failure.
//! Compile the production answer against a completed IRP pump whose generic result mirrors
//! dispatch NTSTATUS, while the exact component bank carries the separately returned VP_STATUS.

use std::process::Command;

const NATIVE: &str = include_str!("../../../components/ntos-executive/src/hosted_video_find_adapter.rs");
const POLICY: &str = include_str!("../../nt-video-miniport/src/find_adapter.rs");
const OWNER: &str = include_str!("../../nt-hosted-runtime/src/retained_dispatch_context.rs");

struct FixtureDirectory(std::path::PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[test]
fn native_find_adapter_keeps_dispatch_and_vp_status_separate() {
    let answer = NATIVE
        .split_once("unsafe fn answer(")
        .expect("native FindAdapter answer")
        .1
        .split_once("\nfn trace(")
        .expect("native FindAdapter answer boundary")
        .0;
    let policy = POLICY.split_once("#[cfg(test)]").unwrap().0;
    let kept_impl = NATIVE
        .split_once("impl Kept {")
        .expect("native retained FindAdapter owner")
        .1
        .split_once("/// Run FindAdapter for the START IRP")
        .expect("native FindAdapter dispatch boundary")
        .0;
    let fixture = format!(
        "mod nt_video_miniport {{\n{policy}\n}}\nmod retained_dispatch_context {{\n{OWNER}\n}}\n{SUPPORT}\nmod native {{\nuse super::*;\nimpl Kept {{{kept_impl}\nunsafe fn answer({answer}\n{CASES}\n}}"
    );
    let directory = FixtureDirectory(std::env::temp_dir().join(format!(
        "nt-video-find-adapter-status-{}-{}",
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
    assert!(compiled.status.success(), "native answer fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let run = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    assert!(run.status.success(), "native FindAdapter status regression:\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr));
}

const SUPPORT: &str = r#"
use std::ptr::read_volatile;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use nt_video_miniport::{find_adapter_start, FindAdapterPump, FindAdapterStart, VP_NO_ERROR};

const SH_VIDEO_FIND_ADAPTER_CALLS: u64 = 0x9d8;
const SH_VIDEO_FIND_ADAPTER_STATUS: u64 = 0x9e0;
const SH_VIDEO_FIND_ADAPTER_AGAIN: u64 = 0x9e4;

mod nt_status {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NtStatus(pub i32);
    impl NtStatus {
        pub const UNSUCCESSFUL: Self = Self(0xc000_0001u32 as i32);
        pub const DEVICE_BUSY: Self = Self(0x8000_0011u32 as i32);
        pub const DEVICE_NOT_CONNECTED: Self = Self(0xc000_009du32 as i32);
        pub const fn raw(self) -> i32 { self.0 }
    }
}

#[derive(Clone, Copy)]
struct PumpResult { completed: bool, status: i32, result: u64 }
mod component_scheduler {
    use super::{AtomicBool, AtomicU32, AtomicU64, Ordering, PumpResult};
    pub enum HostedPumpRestore {
        Restored(PumpResult),
        Unattributed(PumpResult),
        Pending,
    }
    impl HostedPumpRestore {
        pub fn retryable_continuation(&self) -> bool { matches!(self, Self::Pending) }
    }
    pub fn retry_child_work(_: HostedPumpRestore) -> HostedPumpRestore {
        assert!(super::ACTIVE.load(Ordering::SeqCst), "context must be active before provider retry");
        assert_eq!(super::PROJECTED_BANK.load(Ordering::SeqCst),
            super::PUBLISHED_BANK.load(Ordering::SeqCst), "retry must use its assigned bank");
        super::RETRIES.fetch_add(1, Ordering::SeqCst);
        super::MAPS.fetch_add(1, Ordering::SeqCst);
        HostedPumpRestore::Restored(PumpResult { completed: true, status: 0, result: 0 })
    }
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static PUBLISHED_DEVICE: AtomicU64 = AtomicU64::new(0);
static PUBLISHED_GENERATION: AtomicU64 = AtomicU64::new(0);
static PUBLISHED_BANK: AtomicU64 = AtomicU64::new(0);
static PROJECTED_BANK: AtomicU64 = AtomicU64::new(0);
static RETRIES: AtomicU32 = AtomicU32::new(0);
static MAPS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
struct HostedDeviceBinding { device_id: u64, driver_id: u64, bank: u64 }
struct DriverInstance { driver_id: u64, cnode: u64 }
fn instance(index: usize) -> Option<DriverInstance> {
    (index == 18).then_some(DriverInstance { driver_id: 99, cnode: 1 })
}
fn restore_hosted_device_resource_state(
    binding: HostedDeviceBinding, shared_va: u64, _: u64, _: bool,
) -> Result<(), nt_status::NtStatus> {
    if !ACTIVE.load(Ordering::SeqCst) || binding.bank != shared_va {
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    PROJECTED_BANK.store(shared_va, Ordering::SeqCst);
    Ok(())
}

struct Guard { device_id: u64, generation: u64, bank: u64 }
struct Ticket { device_id: u64, generation: u64, bank: u64 }
impl Guard {
    fn projection_binding(&self, shared_va: u64)
        -> Result<HostedDeviceBinding, nt_status::NtStatus>
    {
        if !ACTIVE.load(Ordering::SeqCst)
            || self.device_id != PUBLISHED_DEVICE.load(Ordering::SeqCst)
            || self.generation != PUBLISHED_GENERATION.load(Ordering::SeqCst)
            || self.bank != shared_va
            || self.bank != PUBLISHED_BANK.load(Ordering::SeqCst)
        {
            return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        }
        Ok(HostedDeviceBinding { device_id: self.device_id, driver_id: 99, bank: self.bank })
    }
}
impl retained_dispatch_context::RetainedContextBinding for Guard {
    type Suspended = Ticket;
    type Error = nt_status::NtStatus;
    fn suspend(self) -> Result<Ticket, (Self::Error, Self)> {
        if !ACTIVE.swap(false, Ordering::SeqCst) {
            return Err((nt_status::NtStatus::DEVICE_BUSY, self));
        }
        Ok(Ticket { device_id: self.device_id, generation: self.generation, bank: self.bank })
    }
    fn resume(ticket: Ticket) -> Result<Self, (Self::Error, Ticket)> {
        if ticket.device_id != PUBLISHED_DEVICE.load(Ordering::SeqCst)
            || ticket.generation != PUBLISHED_GENERATION.load(Ordering::SeqCst)
            || ticket.bank != PUBLISHED_BANK.load(Ordering::SeqCst)
            || ACTIVE.swap(true, Ordering::SeqCst)
        {
            return Err((nt_status::NtStatus::DEVICE_NOT_CONNECTED, ticket));
        }
        Ok(Self { device_id: ticket.device_id, generation: ticket.generation, bank: ticket.bank })
    }
}
type DeviceDispatchContextOwner = retained_dispatch_context::RetainedContextOwner<Guard>;

fn context(shared_va: u64) -> DeviceDispatchContextOwner {
    ACTIVE.store(true, Ordering::SeqCst);
    PUBLISHED_DEVICE.store(0x4e, Ordering::SeqCst);
    PUBLISHED_GENERATION.store(7, Ordering::SeqCst);
    PUBLISHED_BANK.store(shared_va, Ordering::SeqCst);
    PROJECTED_BANK.store(0, Ordering::SeqCst);
    RETRIES.store(0, Ordering::SeqCst);
    MAPS.store(0, Ordering::SeqCst);
    DeviceDispatchContextOwner::active(Guard { device_id: 0x4e, generation: 7, bank: shared_va })
}

struct Kept {
    pump: component_scheduler::HostedPumpRestore,
    index: usize,
    device_id: u64,
    shared_va: u64,
    device_context: DeviceDispatchContextOwner,
}

enum HostedIrpTransportResult {
    Returned { status: nt_status::NtStatus, information: u64, file_context: u64 },
    Indeterminate { transport_status: nt_status::NtStatus },
}

mod hosted_file_owners { pub fn lane_freed() {} }
fn register_instance_ready(_: usize, _: bool) {}
fn trace(_: &[u8], _: u64, _: u32) {}
fn print_str(_: &[u8]) {}
fn print_u64(_: u64) {}
fn print_hex(_: u32) {}

fn bank(vp_status: u32) -> (Box<[u64; 320]>, u64) {
    let mut storage = Box::new([0u64; 320]);
    let shared_va = storage.as_mut_ptr() as u64;
    unsafe {
        std::ptr::write_volatile((shared_va + SH_VIDEO_FIND_ADAPTER_STATUS) as *mut u32,
            vp_status);
        std::ptr::write_volatile((shared_va + SH_VIDEO_FIND_ADAPTER_CALLS) as *mut u64, 1);
    }
    (storage, shared_va)
}
"#;

const CASES: &str = r#"
#[test]
fn completed_dispatch_reads_the_miniports_own_vp_status() {
    let (_storage, shared_va) = bank(nt_video_miniport::VP_ERROR_DEV_NOT_EXIST);
    let result = unsafe { answer(Kept {
        pump: component_scheduler::HostedPumpRestore::Restored(PumpResult {
            completed: true, status: 0, result: 0,
        }),
        index: 18, device_id: 0x4e, shared_va,
        device_context: context(shared_va),
    }) };
    match result {
        Ok(HostedIrpTransportResult::Returned { status, .. }) =>
            assert_eq!(status.0 as u32, 0xc000_009d, "the VP failure must complete StartDevice"),
        _ => panic!("completed FindAdapter must return the miniport's terminal"),
    }
}

#[test]
fn a_failed_wrapper_dispatch_precedes_any_vp_status() {
    let (_storage, shared_va) = bank(nt_video_miniport::VP_ERROR_DEV_NOT_EXIST);
    let failed = 0xc000_000du32 as i32;
    let result = unsafe { answer(Kept {
        pump: component_scheduler::HostedPumpRestore::Restored(PumpResult {
            completed: true, status: failed, result: failed as u32 as u64,
        }),
        index: 18, device_id: 0x4e, shared_va,
        device_context: context(shared_va),
    }) };
    match result {
        Ok(HostedIrpTransportResult::Returned { status, .. }) =>
            assert_eq!(status.0, failed),
        _ => panic!("failed wrapper dispatch must complete with its own error"),
    }
}

#[test]
fn unfinished_and_uncertain_pumps_do_not_consume_a_stale_bank_value() {
    let (_storage, shared_va) = bank(nt_video_miniport::VP_ERROR_DEV_NOT_EXIST);
    let pending = unsafe { answer(Kept {
        pump: component_scheduler::HostedPumpRestore::Pending,
        index: 18, device_id: 0x4e, shared_va,
        device_context: context(shared_va),
    }) };
    assert!(pending.is_err(), "a pending pump keeps its native owner");
    let uncertain = unsafe { answer(Kept {
        pump: component_scheduler::HostedPumpRestore::Restored(PumpResult {
            completed: false, status: 0, result: 0,
        }),
        index: 18, device_id: 0x4e, shared_va,
        device_context: context(shared_va),
    }) };
    assert!(matches!(uncertain,
        Ok(HostedIrpTransportResult::Indeterminate { .. })),
        "an untrustworthy return quarantines rather than using stale VP status");
}

#[test]
fn pending_find_adapter_rebinds_its_assigned_bank_before_provider_retry() {
    let (_storage, shared_va) = bank(nt_video_miniport::VP_NO_ERROR);
    let kept = unsafe { answer(Kept {
        pump: component_scheduler::HostedPumpRestore::Pending,
        index: 18, device_id: 0x4e, shared_va,
        device_context: context(shared_va),
    }) }.err().expect("pending native pump");
    assert!(!ACTIVE.load(Ordering::SeqCst));
    let before = RETRIES.load(Ordering::SeqCst);
    let result = unsafe { kept.resume() };
    assert!(matches!(result, Ok(HostedIrpTransportResult::Returned { .. })));
    assert_eq!(RETRIES.load(Ordering::SeqCst), before + 1);
    assert_eq!(MAPS.load(Ordering::SeqCst), 1);
}

#[test]
fn changed_device_or_generation_refuses_pending_resume_without_provider_replay() {
    let (_storage, shared_va) = bank(nt_video_miniport::VP_NO_ERROR);
    let kept = unsafe { answer(Kept {
        pump: component_scheduler::HostedPumpRestore::Pending,
        index: 18, device_id: 0x4e, shared_va,
        device_context: context(shared_va),
    }) }.err().expect("pending native pump");
    PUBLISHED_DEVICE.store(0x50, Ordering::SeqCst);
    let before = RETRIES.load(Ordering::SeqCst);
    let kept = unsafe { kept.resume() }.err().expect("foreign device must retain the pump");
    assert_eq!(RETRIES.load(Ordering::SeqCst), before);
    assert!(!ACTIVE.load(Ordering::SeqCst));
    PUBLISHED_DEVICE.store(0x4e, Ordering::SeqCst);
    PUBLISHED_GENERATION.store(8, Ordering::SeqCst);
    let kept = unsafe { kept.resume() }.err().expect("recycled ticket must retain the pump");
    assert_eq!(RETRIES.load(Ordering::SeqCst), before);
    PUBLISHED_GENERATION.store(7, Ordering::SeqCst);
    PUBLISHED_BANK.store(shared_va + 0x1000, Ordering::SeqCst);
    let _kept = unsafe { kept.resume() }.err().expect("another assigned bank must retain the pump");
    assert_eq!(RETRIES.load(Ordering::SeqCst), before);
    assert!(!ACTIVE.load(Ordering::SeqCst));
}
"#;
