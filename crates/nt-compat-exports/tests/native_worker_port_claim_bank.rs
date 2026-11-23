//! Compile VideoPort's production supplemental-range gate against separate primary/worker banks.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn supplemental_port_claim_uses_the_active_worker_bank() {
    let start = SOURCE
        .find("extern \"win64\" fn s_video_port_verify_access_ranges(")
        .expect("production VideoPortVerifyAccessRanges");
    let tail = &SOURCE[start..];
    let end = tail
        .find("\n/// `PVOID VideoPortGetDeviceBase")
        .expect("production function end");
    let production = tail[..end].replacen("extern \"win64\"", "extern \"C\"", 1);
    let fixture = format!("{SUPPORT}\n{production}\n{CASES}");
    let directory =
        std::env::temp_dir().join(format!("nt-port-claim-worker-{}", std::process::id()));
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
        "worker claim fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "worker claim regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::read_volatile;
static mut FSD_SHARED_VADDR: u64 = 0;
static mut ACTIVE_BANK: u64 = 0;
static mut PRIMARY_HAS_PORT: bool = false;
static mut WORKER_HAS_PORT: bool = false;
static mut CLAIMED: bool = false;
static mut CLAIM_CALLS: u64 = 0;
const SH_RESOURCE_PDO_OBJECT: u64 = 0;
const SH_RESOURCE_ADDRESS_KIND_PORT: u8 = 1;
const STATUS_SUCCESS: i32 = 0;
const VP_NO_ERROR: u32 = 0;
const VP_ERROR_INVALID_FUNCTION: u32 = 1;
const VP_ERROR_INVALID_PARAMETER: u32 = 2;
const VP_ERROR_DEV_NOT_EXIST: u32 = 3;
const VIDEO_ACCESS_RANGE_X64_SIZE: u64 = 16;
#[repr(C)] #[derive(Clone, Copy)] struct VideoAccessRangeX64 {
    range_start: u64, range_length: u32, range_in_io_space: bool,
}
unsafe fn hosted_resource_identity_active() -> bool { true }
unsafe fn hosted_component_resource_shared_va() -> u64 { ACTIVE_BANK }
unsafe fn component_read_video_access_range(ptr: u64) -> VideoAccessRangeX64 {
    *(ptr as *const VideoAccessRangeX64)
}
unsafe fn hosted_video_range_granted(range: VideoAccessRangeX64) -> bool {
    CLAIMED && range.range_start == 0x3c0
}
unsafe fn first_shared_address_resource(bank: u64, kind: u8) -> Option<()> {
    if kind != SH_RESOURCE_ADDRESS_KIND_PORT { return None; }
    if bank == FSD_SHARED_VADDR && PRIMARY_HAS_PORT { return Some(()); }
    if bank == ACTIVE_BANK && WORKER_HAS_PORT { return Some(()); }
    None
}
unsafe fn hosted_device_claim_port_range(pdo: u64, start: u64, length: u64) -> i32 {
    if pdo != 11 { return -1; }
    CLAIM_CALLS += 1;
    if start == 0 && length == 0 { CLAIMED = false; }
    else if start == 0x3c0 && length == 2 { CLAIMED = true; }
    else { return -1; }
    STATUS_SUCCESS
}
"#;

const CASES: &str = r#"
#[test]
fn worker_claim_ignores_primary_sibling_and_refuses_wrong_bank() {
    let mut primary = [0u64; 8];
    let mut worker = [0u64; 8];
    let range = VideoAccessRangeX64 {
        range_start:0x3c0, range_length:2, range_in_io_space:true,
    };
    worker[0] = 11;
    unsafe {
        FSD_SHARED_VADDR = primary.as_mut_ptr() as u64;
        ACTIVE_BANK = worker.as_mut_ptr() as u64;
        PRIMARY_HAS_PORT = true;
        WORKER_HAS_PORT = false;
        CLAIMED = false;
        CLAIM_CALLS = 0;
        assert_eq!(s_video_port_verify_access_ranges(0, 1, &range as *const _ as u64),
            VP_NO_ERROR, "primary sibling's range must not refuse worker A's claim");
        assert_eq!(CLAIM_CALLS, 1);
        assert_eq!(s_video_port_verify_access_ranges(0, 0, 0), VP_NO_ERROR);
        worker[0] = 0;
        assert_eq!(s_video_port_verify_access_ranges(0, 0, 0), VP_ERROR_INVALID_PARAMETER);
        worker[0] = 11;
        PRIMARY_HAS_PORT = false;
        WORKER_HAS_PORT = true;
        CLAIMED = false;
        CLAIM_CALLS = 0;
        assert_eq!(s_video_port_verify_access_ranges(0, 1, &range as *const _ as u64),
            VP_ERROR_INVALID_PARAMETER, "worker's own existing port must refuse another claim");
        assert_eq!(CLAIM_CALLS, 0);
    }
}
"#;
