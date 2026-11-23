//! Compile the production supplemental port-cap issue path against uncertain native effects.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn port_issue_retains_authority_when_native_result_is_uncertain() {
    let from = SOURCE
        .find("unsafe fn issue_hosted_io_port_cap(")
        .expect("production port issue");
    let tail = &SOURCE[from..];
    let production = &tail[..tail
        .find("\nunsafe fn claim_hosted_supplemental_port_range(")
        .expect("port issue end")];
    let fixture = format!("{SUPPORT}\n{production}\n{CASES}");
    let directory =
        std::env::temp_dir().join(format!("nt-worker-port-issue-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
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
        "worker port issue fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "worker port issue regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
#[derive(Clone, Copy)] struct DriverInstance { cnode: u64 }
mod nt_status { #[derive(Debug)] pub enum NtStatus { INVALID_PARAMETER, INSUFFICIENT_RESOURCES, INVALID_DEVICE_REQUEST } }
const CT_IO_PORT_BASE: u64 = 8;
const CT_IO_PORT_CAPACITY: u64 = 16;
static mut FAIL_ISSUE: bool = false;
static mut FAIL_DELETE: bool = false;
static mut FAIL_COPY: bool = false;
static mut COPY_CALLS: u64 = 0;
static mut ROOT_RECYCLES: u64 = 0;
static mut ROOT_DELETES: u64 = 0;
fn try_alloc_slot() -> Option<u64> { Some(90) }
fn recycle_deleted_root_slot(_: u64) { unsafe { ROOT_RECYCLES += 1; } }
fn cnode_delete_recycle_r(_: u64) -> u64 { unsafe { ROOT_DELETES += 1; } 0 }
fn issue_ioport_cap(_: u64, _: u16, _: u16) -> u64 { unsafe { FAIL_ISSUE as u64 } }
fn cnode_delete_in_cnode_r(_: u64, _: u64) -> u64 { unsafe { FAIL_DELETE as u64 } }
fn cnode_copy_at_r(_: u64, _: u64, _: u64) -> u64 {
    unsafe { COPY_CALLS += 1; FAIL_COPY as u64 }
}
"#;

const CASES: &str = r#"
fn reset() { unsafe {
    FAIL_ISSUE=false; FAIL_DELETE=false; FAIL_COPY=false;
    COPY_CALLS=0; ROOT_RECYCLES=0; ROOT_DELETES=0;
} }
#[test]
fn failed_destination_delete_refuses_copy_and_retains_root_slot() {
    reset();
    unsafe { FAIL_DELETE=true; }
    assert!(unsafe { issue_hosted_io_port_cap(DriverInstance { cnode:2 },8,0x3c0,2) }.is_err());
    unsafe { assert_eq!(COPY_CALLS,0); assert_eq!(ROOT_RECYCLES,0); assert_eq!(ROOT_DELETES,0); }
}
#[test]
fn uncertain_copy_never_recycles_the_root_cap() {
    reset();
    unsafe { FAIL_COPY=true; }
    assert!(unsafe { issue_hosted_io_port_cap(DriverInstance { cnode:2 },8,0x3c0,2) }.is_err());
    unsafe { assert_eq!(COPY_CALLS,1); assert_eq!(ROOT_RECYCLES,0); assert_eq!(ROOT_DELETES,0); }
}
#[test]
fn uncertain_issue_never_recycles_the_reserved_root_slot() {
    reset();
    unsafe { FAIL_ISSUE=true; }
    assert!(unsafe { issue_hosted_io_port_cap(DriverInstance { cnode:2 },8,0x3c0,2) }.is_err());
    unsafe { assert_eq!(COPY_CALLS,0); assert_eq!(ROOT_RECYCLES,0); assert_eq!(ROOT_DELETES,0); }
}
"#;
