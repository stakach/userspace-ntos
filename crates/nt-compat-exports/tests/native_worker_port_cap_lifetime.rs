//! Compile the production port-cap restore and read path with two concurrent worker banks.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn section(start: &str, end: &str) -> &'static str {
    let from = SOURCE.find(start).expect("production start marker");
    let tail = &SOURCE[from..];
    &tail[..tail.find(end).expect("production end marker")]
}

#[test]
fn physical_worker_cnode_receives_its_projected_port_cap() {
    let restore = section(
        "unsafe fn clear_hosted_io_port_caps(",
        "\nunsafe fn write_hosted_resource_state_projection(",
    );
    let projection = section(
        "unsafe fn restore_hosted_device_resource_state(",
        "\nunsafe fn project_provider_device_dispatch_state(",
    );
    let counter = section(
        "unsafe fn bump_shared_io_counter(",
        "\nunsafe fn hosted_port_cap_for_component_io(",
    );
    let cap_lookup = section(
        "unsafe fn hosted_port_cap_for_component_io(",
        "\nextern \"win64\" fn s_read_port_ushort(",
    );
    let read_port = section(
        "extern \"win64\" fn s_read_port_ushort(",
        "\nextern \"win64\" fn s_write_port_ushort(",
    )
    .replacen("extern \"win64\"", "extern \"C\"", 1);
    let fixture = format!(
        "{SUPPORT}\n{restore}\n{projection}\n{counter}\n{cap_lookup}\n{read_port}\n{CASES}"
    );
    let directory = std::env::temp_dir().join(format!("nt-port-cap-worker-{}", std::process::id()));
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
        "worker port fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "worker port regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::{read_volatile, write_volatile};
const CT_IO_PORT_BASE: u64 = 8;
const CT_IO_PORT_CAPACITY: u64 = 16;
const SH_RESOURCE_ADDRESS_KIND_PORT: u8 = 2;
const SH_RESOURCE_IO_PORT_IN16_CALLS: u64 = 0x100;
const SH_RESOURCE_IO_PORT_IN16_DENIED: u64 = 0x108;
const SH_RESOURCE_IO_PORT_IN16_FAILURES: u64 = 0x110;
const SH_RESOURCE_IO_PORT_LAST_IN16_PORT: u64 = 0x118;
const SH_RESOURCE_IO_PORT_LAST_IN16_STATUS: u64 = 0x120;
const SH_RESOURCE_IO_PORT_LAST_IN16_VALUE: u64 = 0x128;
#[derive(Clone, Copy)] struct DriverInstance { cnode: u64 }
#[derive(Clone, Copy)] struct SharedAddressResource { kind: u8, translated_start: u64, len: u64,
    broker_va_or_root_cap: u64, component_cap: u64 }
#[derive(Clone, Copy)] struct HostedDeviceResourceState { device_id: u64, driver_id: u64,
    instance: usize, resource: SharedAddressResource }
#[derive(Clone, Copy)] struct HostedDeviceBinding { device_id: u64, driver_id: u64, instance: usize }
fn hosted_state_address_resources(state: &HostedDeviceResourceState) -> &[SharedAddressResource] {
    core::slice::from_ref(&state.resource)
}
mod nt_status {
    #[derive(Debug)] pub enum NtStatus { INVALID_DEVICE_REQUEST, OBJECT_NAME_NOT_FOUND, DEVICE_BUSY }
}
static mut C_NODES: [[u64; 32]; 5] = [[0; 32]; 5];
static mut WORKER_A: u64 = 0;
static mut WORKER_B: u64 = 0;
static mut ACTIVE_BANK: u64 = 0;
static mut ACTIVE_CNODE: usize = 0;
static mut FAIL_DELETE_CNODE: u64 = 0;
static mut FAIL_COPY_CNODE: u64 = 0;
static mut PROJECTION_COUNT: u64 = 0;
static mut PENDING_CNODE: u64 = 0;
static mut RESOURCE_A: Option<SharedAddressResource> = None;
static mut RESOURCE_B: Option<SharedAddressResource> = None;
fn cnode_delete_in_cnode_r(cnode: u64, slot: u64) -> u64 {
    if unsafe { FAIL_DELETE_CNODE } == cnode { return 1; }
    unsafe { C_NODES[cnode as usize][slot as usize] = 0; }
    0
}
fn cnode_copy_at_r(cnode: u64, slot: u64, cap: u64) -> u64 {
    if unsafe { FAIL_COPY_CNODE } == cnode { return 1; }
    unsafe { C_NODES[cnode as usize][slot as usize] = cap; }
    0
}
unsafe fn hosted_device_resource_state_by_device_id(device_id: u64) -> Option<HostedDeviceResourceState> {
    let resource = match device_id { 1 => RESOURCE_A?, 2 => RESOURCE_B?, _ => return None };
    Some(HostedDeviceResourceState {device_id, driver_id:7, instance:0, resource})
}
fn instance_by_driver_id(driver_id: u64) -> Option<(usize, DriverInstance)> {
    (driver_id == 7).then_some((0, DriverInstance {cnode:1}))
}
fn hosted_io_port_cap_effect_pending(_: HostedDeviceBinding, cnode: u64) -> bool {
    unsafe { PENDING_CNODE == cnode }
}
unsafe fn write_hosted_resource_state_projection(sh: u64, state: HostedDeviceResourceState, _: bool) {
    PROJECTION_COUNT += 1;
    if sh == WORKER_A { RESOURCE_A = Some(state.resource); }
    if sh == WORKER_B { RESOURCE_B = Some(state.resource); }
}
fn print_str(_: &[u8]) {}
fn print_u64(_: u64) {}
unsafe fn hosted_component_resource_shared_va() -> u64 { ACTIVE_BANK }
unsafe fn find_shared_address_resource_by_range(
    bank: u64, kind: u8, start: u64, width: u64, _: bool,
) -> Option<SharedAddressResource> {
    let resource = if bank == WORKER_A { RESOURCE_A? }
        else if bank == WORKER_B { RESOURCE_B? } else { return None };
    (resource.kind == kind && start >= resource.translated_start
        && start.checked_add(width)? <= resource.translated_start + resource.len).then_some(resource)
}
fn io_in16_r(slot: u64, port: u16) -> (u16, u64) {
    unsafe {
        match (C_NODES[ACTIVE_CNODE][slot as usize], port) {
            (0xA, 0x3c0) => (0xAAAA, 0),
            (0xB, 0x2f8) => (0xBBBB, 0),
            _ => (0, 1),
        }
    }
}
"#;

const CASES: &str = r#"
#[test]
fn two_worker_banks_retain_their_own_live_port_caps() {
    let mut bank_a = [0u64; 64];
    let mut bank_b = [0u64; 64];
    let a = SharedAddressResource { kind: SH_RESOURCE_ADDRESS_KIND_PORT,
        translated_start: 0x3c0, len: 2, broker_va_or_root_cap: 0xA, component_cap: 8 };
    let b = SharedAddressResource { kind: SH_RESOURCE_ADDRESS_KIND_PORT,
        translated_start: 0x2f8, len: 2, broker_va_or_root_cap: 0xB, component_cap: 8 };
    unsafe {
        WORKER_A = bank_a.as_mut_ptr() as u64;
        WORKER_B = bank_b.as_mut_ptr() as u64;
        RESOURCE_A = Some(a);
        RESOURCE_B = Some(b);
        restore_hosted_device_resource_state(
            HostedDeviceBinding {device_id:1,driver_id:7,instance:0}, WORKER_A, 2, false).unwrap();
        ACTIVE_BANK = WORKER_A;
        ACTIVE_CNODE = 2;
        assert_eq!(s_read_port_ushort(0x3c0), 0xAAAA,
            "worker A's physical CNode must receive its bank's port cap");
        restore_hosted_device_resource_state(
            HostedDeviceBinding {device_id:2,driver_id:7,instance:0}, WORKER_B, 3, false).unwrap();
        ACTIVE_BANK = WORKER_B;
        ACTIVE_CNODE = 3;
        assert_eq!(s_read_port_ushort(0x2f8), 0xBBBB);
        ACTIVE_BANK = WORKER_A;
        ACTIVE_CNODE = 2;
        assert_eq!(s_read_port_ushort(0x3c0), 0xAAAA,
            "worker B's independent CNode must not change worker A's cap");
        assert_eq!(s_read_port_ushort(0x2f8), 0,
            "A's bank cannot borrow B's resource record");
    }
}
#[test]
fn primary_and_private_irq_provider_cnodes_keep_independent_caps() {
    let mut primary_bank = [0u64; 64];
    let mut irq_bank = [0u64; 64];
    let mut provider_bank = [0u64; 64];
    let a = SharedAddressResource { kind: SH_RESOURCE_ADDRESS_KIND_PORT,
        translated_start: 0x3c0, len: 2, broker_va_or_root_cap: 0xA, component_cap: 8 };
    let b = SharedAddressResource { kind: SH_RESOURCE_ADDRESS_KIND_PORT,
        translated_start: 0x2f8, len: 2, broker_va_or_root_cap: 0xB, component_cap: 8 };
    unsafe {
        WORKER_A=primary_bank.as_mut_ptr() as u64;
        WORKER_B=provider_bank.as_mut_ptr() as u64;
        RESOURCE_A=Some(a);
        RESOURCE_B=Some(b);
        restore_hosted_device_resource_state(
            HostedDeviceBinding {device_id:1,driver_id:7,instance:0},WORKER_A,1,false).unwrap();
        restore_hosted_device_resource_state(
            HostedDeviceBinding {device_id:2,driver_id:7,instance:0},WORKER_B,3,false).unwrap();
        ACTIVE_BANK=WORKER_A;
        ACTIVE_CNODE=1;
        assert_eq!(s_read_port_ushort(0x3c0),0xAAAA);
        ACTIVE_BANK=WORKER_B;
        ACTIVE_CNODE=3;
        assert_eq!(s_read_port_ushort(0x2f8),0xBBBB);
        WORKER_A=irq_bank.as_mut_ptr() as u64;
        restore_hosted_device_resource_state(
            HostedDeviceBinding {device_id:1,driver_id:7,instance:0},WORKER_A,4,false).unwrap();
        ACTIVE_BANK=WORKER_A;
        ACTIVE_CNODE=4;
        assert_eq!(s_read_port_ushort(0x3c0),0xAAAA);
        ACTIVE_CNODE=1;
        assert_eq!(s_read_port_ushort(0x3c0),0xAAAA,
            "IRQ projection must not remove primary cap");
        ACTIVE_BANK=WORKER_B;
        ACTIVE_CNODE=3;
        assert_eq!(s_read_port_ushort(0x2f8),0xBBBB,
            "IRQ projection must not remove provider cap");
    }
}
#[test]
fn failed_child_cap_delete_cannot_publish_a_new_worker_bank() {
    let mut bank = [0u64; 64];
    let resource = SharedAddressResource { kind:SH_RESOURCE_ADDRESS_KIND_PORT,
        translated_start:0x3c0,len:2,broker_va_or_root_cap:0xA,component_cap:8 };
    unsafe {
        WORKER_A=bank.as_mut_ptr() as u64;
        RESOURCE_A=Some(resource);
        FAIL_DELETE_CNODE=2;
        PROJECTION_COUNT=0;
        assert!(restore_hosted_device_resource_state(
            HostedDeviceBinding {device_id:1,driver_id:7,instance:0},WORKER_A,2,false).is_err());
        assert_eq!(PROJECTION_COUNT,0, "failed CNode delete cannot publish resource authority");
        FAIL_DELETE_CNODE=0;
    }
}
#[test]
fn failed_child_cap_copy_cannot_publish_a_new_worker_bank() {
    let mut bank = [0u64; 64];
    let resource = SharedAddressResource { kind:SH_RESOURCE_ADDRESS_KIND_PORT,
        translated_start:0x3c0,len:2,broker_va_or_root_cap:0xA,component_cap:8 };
    unsafe {
        WORKER_A=bank.as_mut_ptr() as u64;
        RESOURCE_A=Some(resource);
        FAIL_COPY_CNODE=2;
        PROJECTION_COUNT=0;
        assert!(restore_hosted_device_resource_state(
            HostedDeviceBinding {device_id:1,driver_id:7,instance:0},WORKER_A,2,false).is_err());
        assert_eq!(PROJECTION_COUNT,0, "failed CNode copy cannot publish resource authority");
        FAIL_COPY_CNODE=0;
    }
}
#[test]
fn pending_native_cap_effect_blocks_worker_bank_publication() {
    let mut bank = [0u64; 64];
    let resource = SharedAddressResource { kind:SH_RESOURCE_ADDRESS_KIND_PORT,
        translated_start:0x3c0,len:2,broker_va_or_root_cap:0xA,component_cap:8 };
    unsafe {
        WORKER_A=bank.as_mut_ptr() as u64;
        RESOURCE_A=Some(resource);
        PENDING_CNODE=2;
        PROJECTION_COUNT=0;
        assert!(restore_hosted_device_resource_state(
            HostedDeviceBinding {device_id:1,driver_id:7,instance:0},WORKER_A,2,false).is_err());
        assert_eq!(PROJECTION_COUNT,0);
        PENDING_CNODE=0;
    }
}
"#;
