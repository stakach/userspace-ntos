//! Run the native VideoPort port helpers against separate primary and worker banks.

use std::process::Command;

#[test]
fn video_port_ushort_calls_keep_worker_evidence_out_of_the_parked_primary_bank() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("extern \"win64\" fn s_video_port_read_port_ushort(")
        .expect("native VideoPort read helper");
    let end = source[start..]
        .find("\nfn hosted_video_registry_key_path(")
        .expect("native VideoPort helper boundary");
    let helpers = &source[start..start + end];
    let fixture = format!(
        "{SUPPORT}\n{}\n{CASES}",
        // The host target lacks the guest ABI and the primary bank's fixed guest VA.
        // Substitute only those two deployment details; bank selection stays native.
        helpers
            .replace("extern \"win64\" fn", "fn")
            .replace("FSD_SHARED_VADDR", "primary_bank()")
    );
    syn::parse_file(&fixture).expect("native wrappers form a complete host fixture");

    let directory =
        std::env::temp_dir().join(format!("nt-video-port-worker-bank-{}", std::process::id()));
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
    assert!(
        compiled.status.success(),
        "VideoPort fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "worker bank isolation regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::{read_volatile, write_volatile};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const SH_RESOURCE_IO_PORT_IN16_CALLS: u64 = 0;
const SH_RESOURCE_IO_PORT_OUT16_CALLS: u64 = 8;
const SH_RESOURCE_IO_PORT_LAST_IN16_PORT: u64 = 16;
const SH_RESOURCE_IO_PORT_LAST_IN16_STATUS: u64 = 24;
const SH_RESOURCE_IO_PORT_LAST_IN16_VALUE: u64 = 32;
const SH_RESOURCE_IO_PORT_LAST_OUT16_PORT: u64 = 40;
const SH_RESOURCE_IO_PORT_LAST_OUT16_STATUS: u64 = 48;
const SH_RESOURCE_IO_PORT_LAST_OUT16_VALUE: u64 = 56;
const SH_VIDEO_DISPI_SELECTED_INDEX: u64 = 64;
const SH_VIDEO_MEMORY_LEN: u64 = 72;
const SH_RESOURCE_IO_PORT_IN16_DENIED: u64 = 80;
const SH_RESOURCE_IO_PORT_OUT16_DENIED: u64 = 88;
const SH_RESOURCE_IO_PORT_IN16_FAILURES: u64 = 96;
const SH_RESOURCE_IO_PORT_OUT16_FAILURES: u64 = 104;
const VBE_DISPI_IOPORT_INDEX: u64 = 0x1ce;
const VBE_DISPI_IOPORT_DATA: u64 = 0x1cf;
const VBE_DISPI_INDEX_VIDEO_MEMORY_64K: u16 = 0x0a;

static PRIMARY: AtomicU64 = AtomicU64::new(0);
static CURRENT: AtomicU64 = AtomicU64::new(0);
static GRANT: AtomicBool = AtomicBool::new(true);

fn primary_bank() -> u64 { PRIMARY.load(Ordering::Relaxed) }
fn hosted_component_resource_shared_va() -> u64 { CURRENT.load(Ordering::Relaxed) }

unsafe fn bump_shared_io_counter(offset: u64) -> u64 {
    let ptr = (hosted_component_resource_shared_va() + offset) as *mut u64;
    let next = read_volatile(ptr) + 1;
    write_volatile(ptr, next);
    next
}

unsafe fn hosted_port_cap_for_component_io(_: u64, _: u64) -> Option<u64> {
    GRANT.load(Ordering::Relaxed).then_some(77)
}

unsafe fn hosted_video_memory_64k_units() -> Option<u16> {
    let bytes = read_volatile((hosted_component_resource_shared_va() + SH_VIDEO_MEMORY_LEN) as *const u64);
    (bytes >= 65536).then_some((bytes / 65536) as u16)
}

fn io_in16_r(cap: u64, _: u16) -> (u16, u64) {
    assert_eq!(cap, 77);
    (0xbeef, 0)
}

fn io_out16(cap: u64, _: u16, _: u16) -> u64 {
    assert_eq!(cap, 77);
    0
}

fn print_str(_: &[u8]) {}
fn print_u64(_: u64) {}
fn print_hex(_: u32) {}
"#;

const CASES: &str = r#"
#[test]
fn granted_and_denied_worker_ports_touch_only_the_worker_bank() {
    let mut primary = Box::new([0u64; 16]);
    let mut worker = Box::new([0u64; 16]);
    PRIMARY.store(primary.as_mut_ptr() as u64, Ordering::Relaxed);
    CURRENT.store(worker.as_mut_ptr() as u64, Ordering::Relaxed);
    worker[(SH_VIDEO_MEMORY_LEN / 8) as usize] = 2 * 65536;

    s_video_port_write_port_ushort(VBE_DISPI_IOPORT_INDEX, VBE_DISPI_INDEX_VIDEO_MEMORY_64K);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_OUT16_CALLS / 8) as usize], 1);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_LAST_OUT16_PORT / 8) as usize], VBE_DISPI_IOPORT_INDEX);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_LAST_OUT16_VALUE / 8) as usize], 0x0a);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_LAST_OUT16_STATUS / 8) as usize], 0);
    assert_eq!(worker[(SH_VIDEO_DISPI_SELECTED_INDEX / 8) as usize], 0x0a);
    assert_eq!(primary.as_ref(), &[0u64; 16], "a parked primary cannot receive worker evidence");

    assert_eq!(s_video_port_read_port_ushort(VBE_DISPI_IOPORT_DATA), 2);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_IN16_CALLS / 8) as usize], 1);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_LAST_IN16_PORT / 8) as usize], VBE_DISPI_IOPORT_DATA);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_LAST_IN16_STATUS / 8) as usize], 0);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_LAST_IN16_VALUE / 8) as usize], 2);
    assert_eq!(primary.as_ref(), &[0u64; 16]);

    GRANT.store(false, Ordering::Relaxed);
    assert_eq!(s_video_port_read_port_ushort(VBE_DISPI_IOPORT_DATA), 0);
    s_video_port_write_port_ushort(VBE_DISPI_IOPORT_INDEX, 7);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_IN16_DENIED / 8) as usize], 1);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_OUT16_DENIED / 8) as usize], 1);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_LAST_IN16_STATUS / 8) as usize], u64::MAX);
    assert_eq!(worker[(SH_RESOURCE_IO_PORT_LAST_OUT16_STATUS / 8) as usize], u64::MAX);
    assert_eq!(worker[(SH_VIDEO_DISPI_SELECTED_INDEX / 8) as usize], 0x0a,
        "a denied index write cannot change the selected register");
    assert_eq!(primary.as_ref(), &[0u64; 16]);
}
"#;
