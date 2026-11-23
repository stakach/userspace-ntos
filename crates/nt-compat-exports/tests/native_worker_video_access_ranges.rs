//! Compile VideoPort's production range enumeration with distinct primary and worker devices.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn section(start: &str, end: &str) -> &'static str {
    let from = SOURCE.find(start).expect("production start marker");
    let tail = &SOURCE[from..];
    &tail[..tail.find(end).expect("production end marker")]
}

#[test]
fn video_access_ranges_follow_the_active_worker_bank() {
    let pci_slot = section(
        "unsafe fn hosted_pci_device_function()",
        "\nconst HOSTED_PCI_CONFIG_OP_READ:",
    );
    let ranges = section(
        "extern \"win64\" fn s_video_port_get_access_ranges(",
        "\n/// `VP_STATUS VideoPortVerifyAccessRanges",
    )
    .replacen("extern \"win64\"", "extern \"C\"", 1);
    let fixture = format!("{SUPPORT}\n{pci_slot}\n{ranges}\n{CASES}");
    let directory =
        std::env::temp_dir().join(format!("nt-video-range-worker-{}", std::process::id()));
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
        "worker VideoPort fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "worker VideoPort regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::{read_volatile, write_unaligned};
static mut FSD_SHARED_VADDR: u64 = 0;
static mut ACTIVE_BANK: u64 = 0;
const SH_RESOURCE_ADDRESS: u64 = 0x10;
const SH_RESOURCE_INTERFACE_TYPE: u64 = 0x18;
const SH_RESOURCE_ADDRESS_KIND_PORT: u8 = 1;
const HOSTED_INTERFACE_TYPE_PCIBUS: u32 = 5;
const VIDEO_ACCESS_RANGE_X64_SIZE: u64 = 16;
const VP_NO_ERROR: u32 = 0;
const VP_ERROR_INVALID_PARAMETER: u32 = 1;
const VP_ERROR_INVALID_FUNCTION: u32 = 2;
const VP_ERROR_DEV_NOT_EXIST: u32 = 3;
const VP_ERROR_MORE_DATA: u32 = 4;
#[derive(Clone, Copy)] struct SharedAddressResource {kind:u8, raw_start:u64, len:u64}
#[repr(C)] #[derive(Clone, Copy, Default)] struct VideoAccessRangeX64 {
    range_start:u64, range_length:u32, range_in_io_space:bool,
}
impl VideoAccessRangeX64 {
    fn io(start:u64,len:u32)->Self {Self {range_start:start,range_length:len,range_in_io_space:true}}
    fn memory(start:u64,len:u32)->Self {Self {range_start:start,range_length:len,range_in_io_space:false}}
}
unsafe fn hosted_component_resource_shared_va() -> u64 { ACTIVE_BANK }
unsafe fn hosted_resource_identity_active() -> bool { true }
unsafe fn hosted_videoprt_pci_identity_matches(_:u64,_:u64)->bool { true }
unsafe fn shared_address_resource_count(_:u64)->Option<u64> { Some(1) }
unsafe fn read_shared_address_resource(bank:u64,index:u64)->Option<SharedAddressResource> {
    if index != 0 {return None;}
    if bank == FSD_SHARED_VADDR {Some(SharedAddressResource {kind:1,raw_start:0x2f8,len:2})}
    else if bank == ACTIVE_BANK {Some(SharedAddressResource {kind:1,raw_start:0x3c0,len:2})}
    else {None}
}
unsafe fn component_write_video_access_range(ptr:u64,range:VideoAccessRangeX64) {
    *(ptr as *mut VideoAccessRangeX64)=range;
}
unsafe fn component_zero_video_access_range(ptr:u64) {
    *(ptr as *mut VideoAccessRangeX64)=VideoAccessRangeX64::default();
}
"#;

const CASES: &str = r#"
#[test]
fn worker_range_and_pci_slot_win_over_parked_primary() {
    let mut primary = [0u32; 16];
    let mut worker = [0u32; 16];
    primary[(SH_RESOURCE_ADDRESS/4) as usize] = (7<<16)|2;
    worker[(SH_RESOURCE_ADDRESS/4) as usize] = (5<<16)|1;
    primary[(SH_RESOURCE_INTERFACE_TYPE/4) as usize] = HOSTED_INTERFACE_TYPE_PCIBUS;
    worker[(SH_RESOURCE_INTERFACE_TYPE/4) as usize] = HOSTED_INTERFACE_TYPE_PCIBUS;
    let mut range = VideoAccessRangeX64::default();
    let mut slot = 0u32;
    unsafe {
        FSD_SHARED_VADDR = primary.as_mut_ptr() as u64;
        ACTIVE_BANK = worker.as_mut_ptr() as u64;
        assert_eq!(s_video_port_get_access_ranges(0,0,0,1,&mut range as *mut _ as u64,
            0,0,&mut slot as *mut _ as u64), VP_NO_ERROR);
        assert_eq!(range.range_start,0x3c0, "worker must enumerate its own port range");
        assert_eq!(slot, 5 | (1<<5), "worker must report its own PCI slot");
    }
}
"#;
