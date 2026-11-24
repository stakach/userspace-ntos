//! A lower PnP admission refusal leaves the caller's IRP untouched. An entered
//! dispatch without completion is still uncertain and must not return FALSE.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

struct FixtureDirectory(std::path::PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn synchronous_forward_distinguishes_refusal_from_uncompleted_entry() {
    let forwarding = SOURCE
        .split_once("#[repr(C)]\nstruct HostedSyncForwardContext {")
        .expect("native sync-forward context")
        .1
        .split_once("\n\nunsafe fn trace_wdm_forward_call(")
        .expect("end of native sync-forward path")
        .0;
    let fixture = format!(
        "{SUPPORT}\n#[repr(C)]\nstruct HostedSyncForwardContext {{{forwarding}\n{CASES}"
    ).replace("extern \"win64\"", "extern \"C\"");
    let directory = FixtureDirectory(std::env::temp_dir().join(format!(
        "nt-sync-forward-refusal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let source = directory.0.join("fixture.rs");
    let binary = directory.0.join("fixture-tests");
    std::fs::write(&source, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native sync-forward fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr),
    );
    for (mode, expected_exit) in [("rejected", 0), ("entered", 99), ("inline", 0)] {
        let run = Command::new(&binary)
            .env("NT_SYNC_FORWARD_MODE", mode)
            .arg("--test-threads=1")
            .output()
            .unwrap();
        assert_eq!(
            run.status.code(),
            Some(expected_exit),
            "{mode} sync-forward contract:\n{}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr),
        );
    }
}

#[test]
fn lower_pnp_marks_only_accepted_zero_before_the_irp_cursor_moves() {
    let call = SOURCE
        .split_once("unsafe fn s_iof_call_driver_with_entry(")
        .expect("typed CallDriver entry")
        .1
        .split_once("extern \"win64\" fn s_iof_call_driver(")
        .expect("unchanged CallDriver ABI")
        .0;
    let filter = call
        .split_once("if forwarded_minor == nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS as u64")
        .unwrap()
        .1
        .split_once("if forwarded_minor == nt_pnp_abi::IRP_MN_START_DEVICE as u64")
        .unwrap()
        .0;
    assert!(filter.contains(
        "if accepted == 0 {\n                cancel_unbound_pnp_completion(irp);\n                if status as u32 as i32 != STATUS_SUCCESS {\n                    *entry = ForwardEntry::RejectedBeforeDispatch;"
    ));
    let start = call
        .split_once("if forwarded_minor == nt_pnp_abi::IRP_MN_START_DEVICE as u64")
        .unwrap()
        .1
        .split_once("let (_, result, handled")
        .unwrap()
        .0;
    assert!(start.contains(
        "if accepted == 0 {\n                    cancel_unbound_pnp_completion(irp);\n                    *entry = ForwardEntry::RejectedBeforeDispatch;"
    ));
    assert!(start.contains(
        "if accepted == 0 {\n                    *entry = ForwardEntry::RejectedBeforeDispatch;"
    ));
}

const SUPPORT: &str = r#"
use std::ptr::{read_unaligned, write_unaligned};
use std::sync::atomic::{AtomicBool, Ordering};

const WDM_X64_IO_STACK_LOCATION_SIZE: usize = 0x48;
const WDM_X64_IO_STACK_CONTROL_OFFSET: u64 = 0x03;
const WDM_X64_IO_STACK_COMPLETION_ROUTINE_OFFSET: u64 = 0x38;
const WDM_X64_IO_STACK_CONTEXT_OFFSET: u64 = 0x40;
const WDM_X64_IRP_CURRENT_LOCATION_OFFSET: u64 = 0x43;
const WDM_X64_IRP_IO_STATUS_STATUS_OFFSET: u64 = 0x30;
const WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET: u64 = 0x38;

mod nt_status {
    #[derive(Clone, Copy)]
    pub struct NtStatus(pub i32);
    impl NtStatus {
        pub const SUCCESS: Self = Self(0);
        pub const PENDING: Self = Self(0x103);
        pub const MORE_PROCESSING_REQUIRED: Self = Self(0xC000_0016u32 as i32);
        pub fn raw(self) -> i32 { self.0 }
    }
}
mod provider_bugcheck {
    pub fn report(_: u32, _: [u64; 4]) -> ! { std::process::exit(99) }
}
fn validate_hosted_irp_packet(irp: u64) -> Option<(u8, u8, u64)> {
    (irp != 0).then_some((3, 3, 0))
}
unsafe fn irp_next_stack_location(irp: u64) -> u64 {
    read_unaligned((irp + 0xb8) as *const u64) - WDM_X64_IO_STACK_LOCATION_SIZE as u64
}
extern "win64" fn s_io_copy_current_irp_stack_location_to_next(irp: u64) {
    unsafe {
        let current = read_unaligned((irp + 0xb8) as *const u64);
        let next = irp_next_stack_location(irp);
        std::ptr::copy_nonoverlapping(current as *const u8, next as *mut u8, 0x38);
        write_unaligned((next + WDM_X64_IO_STACK_CONTROL_OFFSET) as *mut u8, 0);
    }
}
extern "win64" fn s_ke_initialize_event(_: u64, _: u32, _: u32) {}
extern "win64" fn s_ke_set_event(_: u64, _: i32, _: u8) -> i32 { 0 }
extern "win64" fn s_ke_wait_for_single_object(_: u64, _: u32, _: u8, _: u8, _: u64) -> i32 { 0 }
extern "win64" fn s_iof_call_driver(device: u64, irp: u64) -> i32 {
    unsafe {
        let mode = std::env::var("NT_SYNC_FORWARD_MODE").unwrap();
        if mode == "inline" {
            let next = irp_next_stack_location(irp);
            let callback: extern "win64" fn(u64, u64, u64) -> i32 = std::mem::transmute(
                read_unaligned((next + WDM_X64_IO_STACK_COMPLETION_ROUTINE_OFFSET) as *const u64)
                    as usize,
            );
            let context = read_unaligned((next + WDM_X64_IO_STACK_CONTEXT_OFFSET) as *const u64);
            callback(device, irp, context);
            return 0;
        }
        // The status code alone is deliberately identical in the two no-callback cases.
        0x8000_0011u32 as i32
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ForwardEntry { RejectedBeforeDispatch, Entered }
unsafe fn s_iof_call_driver_with_entry(
    device: u64, irp: u64, entry: &mut ForwardEntry,
) -> i32 {
    if std::env::var("NT_SYNC_FORWARD_MODE").unwrap() == "rejected" {
        *entry = ForwardEntry::RejectedBeforeDispatch;
        return 0x8000_0011u32 as i32;
    }
    *entry = ForwardEntry::Entered;
    s_iof_call_driver(device, irp)
}
"#;

const CASES: &str = r#"
#[test]
fn source_irp_ownership_after_synchronous_forward() {
    let mode = std::env::var("NT_SYNC_FORWARD_MODE").unwrap();
    let mut packet = [0u64; 96];
    let irp = packet.as_mut_ptr() as u64;
    let current = irp + 0x208;
    let next = current - WDM_X64_IO_STACK_LOCATION_SIZE as u64;
    unsafe {
        write_unaligned((irp + 0xb8) as *mut u64, current);
        write_unaligned((irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *mut u8, 3);
        std::ptr::write_bytes(next as *mut u8, 0x5a, WDM_X64_IO_STACK_LOCATION_SIZE);
        std::ptr::write_bytes(current as *mut u8, 0xa5, WDM_X64_IO_STACK_LOCATION_SIZE);
        let original = std::slice::from_raw_parts(next as *const u8, WDM_X64_IO_STACK_LOCATION_SIZE)
            .to_vec();
        let returned = s_io_forward_irp_synchronously(0x1234, irp);
        if mode == "rejected" {
            assert_eq!(returned, 0, "the lower dispatch was never entered");
            assert_eq!(
                std::slice::from_raw_parts(next as *const u8, WDM_X64_IO_STACK_LOCATION_SIZE),
                original,
                "a retry must not retain a stack-local completion callback",
            );
            assert_eq!(read_unaligned((irp + 0xb8) as *const u64), current);
            assert_eq!(read_unaligned((irp + WDM_X64_IRP_CURRENT_LOCATION_OFFSET) as *const u8), 3);
        } else if mode == "inline" {
            assert_eq!(returned, 1);
        } else {
            panic!("entered-but-uncompleted must remain fail closed");
        }
    }
}
"#;
