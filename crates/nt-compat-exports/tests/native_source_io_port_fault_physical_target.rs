//! Compile the production GP grant selector against separate primary and physical CNodes.

use std::process::Command;

#[test]
fn sibling_port_fault_grants_the_exact_worker_or_irq_cnode() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let selector_start = source
        .find("pub(crate) unsafe fn hosted_io_port_fault_grant(")
        .expect("production port fault selector");
    let selector_len = source[selector_start..]
        .find("\n}\n")
        .expect("port fault selector end")
        + 2;
    let selector = &source[selector_start..selector_start + selector_len];
    syn::parse_str::<syn::ItemFn>(selector).expect("selector is a complete function");
    let range_start = source
        .find("fn io_port_in_range(")
        .expect("production port range predicate");
    let range_len = source[range_start..]
        .find("\n}")
        .expect("port range predicate end")
        + 2;
    let range = &source[range_start..range_start + range_len];
    let fixture = format!("{SUPPORT}\n{range}\n{selector}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-port-fault-physical-target-{}",
        std::process::id()
    ));
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
        "production port fault selector must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "physical worker/IRQ target regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::read_volatile;
use std::sync::atomic::{AtomicU64, Ordering};
const SH_RESOURCE_PDO_OBJECT: u64 = 0;
const SH_RESOURCE_ADDRESS_KIND_PORT: u8 = 1;
const CT_IO_PORT_BASE: usize = 8;

#[derive(Clone, Copy, Default)]
struct SharedAddressResource {
    kind: u8, translated_start: u64, len: u64,
    broker_va_or_root_cap: u64, component_cap: u64,
}
#[derive(Clone, Copy, Default)]
struct HostedDeviceResourceState {
    device_id: u64, driver_id: u64, instance: usize,
    projection_domain: u64, pdo_object: u64,
    address_resource_count: usize,
    address_resources: [SharedAddressResource; 1],
}
#[derive(Clone, Copy)]
struct DriverInstance { driver_id: u64, cnode: u64 }
#[derive(Clone, Copy)]
struct HostedDeviceBinding {
    device_id: u64, driver_id: u64, instance: usize,
    projection_domain: u64, pdo_object: u64, used: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostedIoPortFaultGrant { cap: u64, base: u64, len: u64 }
mod spawn_hosts { pub struct PumpChannel { pub cnode: u64, pub reply_cap: u64 } }

static WORKER_BANK: AtomicU64 = AtomicU64::new(0);
static IRQ_BANK: AtomicU64 = AtomicU64::new(0);
static PENDING_DEVICE: AtomicU64 = AtomicU64::new(0);
static mut STATES: Option<Vec<HostedDeviceResourceState>> = None;
static mut BINDINGS: Option<Vec<HostedDeviceBinding>> = None;
static mut CNODES: [[u64; 16]; 4] = [[0; 16]; 4];

fn instance_by_shared_va(_: u64) -> Option<(usize, DriverInstance)> { None }
fn hosted_irq_instance_by_shared_va(shared: u64) -> Option<(usize, DriverInstance)> {
    (IRQ_BANK.load(Ordering::Relaxed) == shared).then_some((7, DriverInstance {driver_id: 42, cnode: 1}))
}
mod hosted_class_irp_lane {
    use super::*;
    pub unsafe fn instance_for_shared(shared: u64) -> Option<(usize, DriverInstance)> {
        (WORKER_BANK.load(Ordering::Relaxed) == shared).then_some((7, DriverInstance {driver_id: 42, cnode: 1}))
    }
}
unsafe fn hosted_device_bindings() -> Option<&'static Vec<HostedDeviceBinding>> { BINDINGS.as_ref() }
fn hosted_device_binding_by_device_id(device_id: u64) -> Option<HostedDeviceBinding> {
    unsafe { BINDINGS.as_ref()?.iter().copied().find(|row| row.used && row.device_id == device_id) }
}
unsafe fn hosted_device_resource_states() -> Option<&'static Vec<HostedDeviceResourceState>> { STATES.as_ref() }
fn hosted_state_address_resources(state: &HostedDeviceResourceState) -> &[SharedAddressResource] {
    &state.address_resources[..state.address_resource_count]
}
fn physical_cnode_for_pump_channel(channel: &spawn_hosts::PumpChannel, reply_cap: u64) -> Option<u64> {
    (reply_cap != 0 && channel.reply_cap == reply_cap).then_some(channel.cnode)
}
fn copy_hosted_io_port_caps_to_cnode(cnode: u64, state: HostedDeviceResourceState) -> Result<(), ()> {
    for resource in hosted_state_address_resources(&state) {
        if resource.kind == SH_RESOURCE_ADDRESS_KIND_PORT {
            unsafe { CNODES[cnode as usize][resource.component_cap as usize] = resource.broker_va_or_root_cap; }
        }
    }
    Ok(())
}
fn hosted_io_port_cap_effect_pending(binding: HostedDeviceBinding, _: u64) -> bool {
    PENDING_DEVICE.load(Ordering::Relaxed) == binding.device_id
}
fn write_hosted_resource_state_projection(_: u64, _: HostedDeviceResourceState, _: bool) {}
"#;

const CASES: &str = r#"
fn setup() {
    PENDING_DEVICE.store(0, Ordering::Relaxed);
    unsafe {
        CNODES = [[0; 16]; 4];
        STATES = Some(vec![
            HostedDeviceResourceState {
                device_id: 1, driver_id: 42, instance: 7, projection_domain: 99,
                pdo_object: 111, address_resource_count: 1,
                address_resources: [SharedAddressResource {
                    kind: SH_RESOURCE_ADDRESS_KIND_PORT, translated_start: 0x64,
                    len: 1, broker_va_or_root_cap: 77, component_cap: CT_IO_PORT_BASE as u64,
                }],
            },
            HostedDeviceResourceState {
                device_id: 2, driver_id: 42, instance: 7, projection_domain: 99,
                pdo_object: 222, ..Default::default()
            },
        ]);
        BINDINGS = Some(vec![
            HostedDeviceBinding { device_id: 1, driver_id: 42, instance: 7,
                projection_domain: 99, pdo_object: 111, used: true },
            HostedDeviceBinding { device_id: 2, driver_id: 42, instance: 7,
                projection_domain: 99, pdo_object: 222, used: true },
        ]);
    }
}
fn assert_sibling_grant_on_physical_bank(is_irq: bool, physical_cnode: usize) {
    setup();
    let mut pdo = Box::new(222u64);
    let shared = (&mut *pdo as *mut u64) as u64;
    WORKER_BANK.store(if is_irq { 0 } else { shared }, Ordering::Relaxed);
    IRQ_BANK.store(if is_irq { shared } else { 0 }, Ordering::Relaxed);
    let channel = spawn_hosts::PumpChannel { cnode: physical_cnode as u64, reply_cap: 9 };
    let grant = unsafe { hosted_io_port_fault_grant(&channel, 9, shared, 0x64) };
    assert_eq!(grant, Some(HostedIoPortFaultGrant { cap: 77, base: 0x64, len: 1 }));
    let (physical_cap, primary_cap) = unsafe {
        (CNODES[physical_cnode][CT_IO_PORT_BASE], CNODES[1][CT_IO_PORT_BASE])
    };
    assert_eq!((physical_cap, primary_cap), (77, 0),
        "the sibling cap belongs only to the active physical lane, never its parked primary");
}
#[test]
fn dispatch_worker_sibling_fault_targets_worker_cnode() {
    assert_sibling_grant_on_physical_bank(false, 2);
}
#[test]
fn private_irq_sibling_fault_targets_irq_cnode() {
    assert_sibling_grant_on_physical_bank(true, 3);
}
#[test]
fn pending_sibling_cap_effect_denies_a_worker_fault_grant() {
    setup();
    let mut pdo = Box::new(222u64);
    let shared = (&mut *pdo as *mut u64) as u64;
    WORKER_BANK.store(shared, Ordering::Relaxed);
    IRQ_BANK.store(0, Ordering::Relaxed);
    PENDING_DEVICE.store(1, Ordering::Relaxed);
    let channel = spawn_hosts::PumpChannel { cnode: 2, reply_cap: 9 };
    assert_eq!(unsafe { hosted_io_port_fault_grant(&channel, 9, shared, 0x64) }, None,
        "an uncertain sibling cap effect cannot authorize a fault grant");
    assert_eq!(unsafe { (CNODES[2][CT_IO_PORT_BASE], CNODES[1][CT_IO_PORT_BASE]) }, (0, 0));
}
#[test]
fn unrecognized_reply_cannot_project_a_sibling_port_cap() {
    setup();
    let mut pdo = Box::new(222u64);
    let shared = (&mut *pdo as *mut u64) as u64;
    WORKER_BANK.store(shared, Ordering::Relaxed);
    IRQ_BANK.store(0, Ordering::Relaxed);
    let channel = spawn_hosts::PumpChannel { cnode: 2, reply_cap: 9 };
    assert_eq!(unsafe { hosted_io_port_fault_grant(&channel, 10, shared, 0x64) }, None);
    assert_eq!(unsafe { (CNODES[2][CT_IO_PORT_BASE], CNODES[1][CT_IO_PORT_BASE]) }, (0, 0));
}
"#;
