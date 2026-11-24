//! A successful hosted dispatch must not erase the miniport's own FindAdapter failure.
//! Compile the production answer against a completed IRP pump whose generic result mirrors
//! dispatch NTSTATUS, while the exact component bank carries the separately returned VP_STATUS.

use std::process::Command;

const NATIVE: &str = include_str!("../../../components/ntos-executive/src/hosted_video_find_adapter.rs");
const POLICY: &str = include_str!("../../nt-video-miniport/src/find_adapter.rs");

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
    let fixture = format!(
        "mod nt_video_miniport {{\n{policy}\n}}\n{SUPPORT}\nunsafe fn answer({answer}\n{CASES}"
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
use nt_video_miniport::{find_adapter_start, FindAdapterPump, FindAdapterStart, VP_NO_ERROR};

const SH_VIDEO_FIND_ADAPTER_CALLS: u64 = 0x9d8;
const SH_VIDEO_FIND_ADAPTER_STATUS: u64 = 0x9e0;
const SH_VIDEO_FIND_ADAPTER_AGAIN: u64 = 0x9e4;

mod nt_status {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NtStatus(pub i32);
    impl NtStatus { pub const UNSUCCESSFUL: Self = Self(0xc000_0001u32 as i32); }
}

#[derive(Clone, Copy)]
struct PumpResult { completed: bool, status: i32, result: u64 }
mod component_scheduler {
    use super::PumpResult;
    pub enum HostedPumpRestore {
        Restored(PumpResult),
        Unattributed(PumpResult),
        Pending,
    }
}

struct Kept {
    pump: component_scheduler::HostedPumpRestore,
    index: usize,
    device_id: u64,
    shared_va: u64,
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
    }) };
    assert!(pending.is_err(), "a pending pump keeps its native owner");
    let uncertain = unsafe { answer(Kept {
        pump: component_scheduler::HostedPumpRestore::Restored(PumpResult {
            completed: false, status: 0, result: 0,
        }),
        index: 18, device_id: 0x4e, shared_va,
    }) };
    assert!(matches!(uncertain,
        Ok(HostedIrpTransportResult::Indeterminate { .. })),
        "an untrustworthy return quarantines rather than using stale VP status");
}
"#;
