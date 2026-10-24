//! Exercise the actual hosted I/O-port GP grant selector with two PDOs owned by one driver.

use std::process::Command;

#[test]
fn hosted_io_port_fault_grant_retains_same_instance_controller_authority() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("pub(crate) unsafe fn hosted_io_port_fault_grant(")
        .expect("native I/O-port GP grant selector");
    let end = source[start..]
        .find("\n}\n")
        .expect("native grant selector closing brace") + 2;
    let selector = &source[start..start + end];
    syn::parse_str::<syn::ItemFn>(selector).expect("native grant selector is a complete function");
    let range_start = source
        .find("fn io_port_in_range(")
        .expect("native port range predicate");
    // Only include the pure range function, not the intervening cap-claim implementation.
    let range_len = source[range_start..]
        .find("\n}")
        .expect("port range predicate end")
        + 2;
    let range = &source[range_start..range_start + range_len];
    syn::parse_str::<syn::ItemFn>(range).expect("native port range predicate is complete");

    let fixture = format!("{PORTS}\n{range}\n{selector}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-source-io-port-fault-grant-{}",
        std::process::id()
    ));
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
        "native grant fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "same-instance controller grant regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use core::ptr::read_volatile;
use std::sync::atomic::{AtomicU64, Ordering};

const SH_RESOURCE_PDO_OBJECT: u64 = 0;
const SH_RESOURCE_ADDRESS_KIND_PORT: u8 = 1;

#[derive(Clone, Copy, Default)]
struct SharedAddressResource {
    kind: u8,
    translated_start: u64,
    len: u64,
    broker_va_or_root_cap: u64,
}

#[derive(Clone, Copy, Default)]
struct HostedDeviceResourceState {
    device_id: u64,
    driver_id: u64,
    instance: usize,
    projection_domain: u64,
    pdo_object: u64,
    address_resource_count: usize,
    address_resources: [SharedAddressResource; 2],
}

#[derive(Clone, Copy)]
struct DriverInstance { driver_id: u64 }

#[derive(Clone, Copy)]
struct HostedDeviceBinding {
    device_id: u64,
    driver_id: u64,
    instance: usize,
    projection_domain: u64,
    pdo_object: u64,
    used: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostedIoPortFaultGrant {
    cap: u64,
    base: u64,
    len: u64,
}

static mut STATES: Option<Vec<HostedDeviceResourceState>> = None;
static mut BINDINGS: Option<Vec<HostedDeviceBinding>> = None;
static ACTIVE_INSTANCE: AtomicU64 = AtomicU64::new(0);
static PROJECTED_PDO: AtomicU64 = AtomicU64::new(0);

fn instance_by_shared_va(_: u64) -> Option<(usize, DriverInstance)> {
    Some((ACTIVE_INSTANCE.load(Ordering::Relaxed) as usize, DriverInstance { driver_id: 42 }))
}

unsafe fn hosted_device_bindings() -> Option<&'static Vec<HostedDeviceBinding>> {
    BINDINGS.as_ref()
}

fn hosted_device_binding_by_device_id(device_id: u64) -> Option<HostedDeviceBinding> {
    unsafe { BINDINGS.as_ref()?.iter().copied().find(|binding| binding.used && binding.device_id == device_id) }
}

unsafe fn hosted_device_resource_states() -> Option<&'static Vec<HostedDeviceResourceState>> {
    STATES.as_ref()
}

fn hosted_state_address_resources(state: &HostedDeviceResourceState) -> &[SharedAddressResource] {
    &state.address_resources[..state.address_resource_count]
}

fn copy_hosted_io_port_caps_to_instance(_: DriverInstance, _: HostedDeviceResourceState) -> Result<(), ()> {
    Ok(())
}

fn write_hosted_resource_state_projection(_: u64, state: HostedDeviceResourceState, _: bool) {
    PROJECTED_PDO.store(state.pdo_object, Ordering::Relaxed);
}
"#;

const CASES: &str = r#"
#[test]
fn same_instance_sibling_port_is_available_without_projecting_sibling_resources() {
    let mut current_pdo = 222u64;
    let shared_va = (&mut current_pdo as *mut u64) as u64;
    let keyboard = HostedDeviceResourceState {
        device_id: 1,
        driver_id: 42,
        instance: 7,
        projection_domain: 99,
        pdo_object: 111,
        address_resource_count: 1,
        address_resources: [
            SharedAddressResource { kind: 1, translated_start: 0x64, len: 1, broker_va_or_root_cap: 77 },
            SharedAddressResource::default(),
        ],
    };
    let mouse = HostedDeviceResourceState {
        device_id: 2, driver_id: 42, instance: 7, projection_domain: 99,
        pdo_object: 222, ..Default::default()
    };
    ACTIVE_INSTANCE.store(7, Ordering::Relaxed);
    PROJECTED_PDO.store(0, Ordering::Relaxed);
    unsafe {
        STATES = Some(vec![keyboard, mouse]);
        BINDINGS = Some(vec![
            HostedDeviceBinding { device_id: 1, driver_id: 42, instance: 7, projection_domain: 99, pdo_object: 111, used: true },
            HostedDeviceBinding { device_id: 2, driver_id: 42, instance: 7, projection_domain: 99, pdo_object: 222, used: true },
        ]);
    }
    let grant = unsafe { hosted_io_port_fault_grant(shared_va, 0x64) };
    assert_eq!(grant, Some(HostedIoPortFaultGrant { cap: 77, base: 0x64, len: 1 }));
    assert_ne!(PROJECTED_PDO.load(Ordering::Relaxed), 111,
        "the mouse PDO must not publish keyboard resource identity");

    // Neither another driver instance nor a retired cap can authorize this mouse dispatch.
    ACTIVE_INSTANCE.store(8, Ordering::Relaxed);
    assert_eq!(unsafe { hosted_io_port_fault_grant(shared_va, 0x64) }, None);
    ACTIVE_INSTANCE.store(7, Ordering::Relaxed);
    unsafe { STATES.as_mut().unwrap()[0].address_resources[0].broker_va_or_root_cap = 0; }
    assert_eq!(unsafe { hosted_io_port_fault_grant(shared_va, 0x64) }, None);
    unsafe {
        STATES.as_mut().unwrap()[0].address_resources[0].broker_va_or_root_cap = 77;
        BINDINGS.as_mut().unwrap()[0].used = false;
    }
    assert_eq!(unsafe { hosted_io_port_fault_grant(shared_va, 0x64) }, None);
}
"#;
