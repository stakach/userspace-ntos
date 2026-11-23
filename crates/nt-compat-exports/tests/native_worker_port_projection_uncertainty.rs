//! Compile the production physical port-cap projection with uncertain native effects.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const LEDGER: &str =
    include_str!("../../../components/ntos-executive/src/driver_launch/hosted_port_projection.rs");

fn section(start: &str, end: &str) -> &'static str {
    let from = SOURCE.find(start).expect("production start marker");
    let tail = &SOURCE[from..];
    &tail[..tail.find(end).expect("production end marker")]
}

#[test]
fn uncertain_native_projection_never_replays_into_the_same_physical_cnode() {
    let projection = section(
        "unsafe fn clear_hosted_io_port_caps(",
        "\nunsafe fn write_hosted_resource_state_projection(",
    );
    let restore = section(
        "unsafe fn restore_hosted_device_resource_state(",
        "\nunsafe fn project_provider_device_dispatch_state(",
    );
    let fixture = format!(
        "{SUPPORT}\nmod hosted_port_projection {{\n{LEDGER}\n}}\n{projection}\n{restore}\n{CASES}"
    );
    let directory = std::env::temp_dir().join(format!(
        "nt-port-projection-uncertainty-{}",
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
        "port projection fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "port projection regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
const CT_IO_PORT_BASE: u64 = 8;
const CT_IO_PORT_CAPACITY: u64 = 16;
const SH_RESOURCE_ADDRESS_KIND_PORT: u8 = 2;
mod allocator { pub fn enter_durable() {} }
#[derive(Clone, Copy)] struct DriverInstance { cnode: u64 }
#[derive(Clone, Copy)] struct SharedAddressResource {
    kind: u8, broker_va_or_root_cap: u64, component_cap: u64,
}
#[derive(Clone, Copy)] struct HostedDeviceResourceState {
    device_id: u64, driver_id: u64, instance: usize, resource: SharedAddressResource,
    projection_domain: HostedDomainIdentity, pdo_object: u64,
}
#[derive(Clone, Copy)] struct DomainId(u64);
impl DomainId { fn raw(self) -> u64 { self.0 } }
#[derive(Clone, Copy)] struct HostedDomainIdentity { domain_id: DomainId, cookie: u64 }
#[derive(Clone, Copy)] struct HostedDeviceBinding {
    device_id: u64, driver_id: u64, instance: usize,
}
fn hosted_state_address_resources(state: &HostedDeviceResourceState) -> &[SharedAddressResource] {
    core::slice::from_ref(&state.resource)
}
mod nt_status {
    #[derive(Debug)] pub enum NtStatus {
        INVALID_DEVICE_REQUEST, OBJECT_NAME_NOT_FOUND, DEVICE_NOT_CONNECTED,
        DEVICE_BUSY, INSUFFICIENT_RESOURCES,
    }
}
static mut CNODES: [[u64; 32]; 8] = [[0; 32]; 8];
static mut PHYSICAL_GENERATION: [u64; 8] = [0, 1, 1, 1, 1, 1, 1, 1];
static mut FAIL_TARGET_CNODE: u64 = 2;
static mut DELETE_CALLS: u64 = 0;
static mut COPY_CALLS: u64 = 0;
static mut FAIL_DELETE_AFTER_EFFECT: bool = false;
static mut FAIL_COPY_AFTER_EFFECT: bool = false;
static mut PUBLISHED: u64 = 0;
fn cnode_delete_in_cnode_r(cnode: u64, slot: u64) -> u64 {
    unsafe {
        DELETE_CALLS += 1;
        CNODES[cnode as usize][slot as usize] = 0;
        if FAIL_DELETE_AFTER_EFFECT && cnode == FAIL_TARGET_CNODE {
            FAIL_DELETE_AFTER_EFFECT = false;
            return 1;
        }
    }
    0
}
fn cnode_copy_at_r(cnode: u64, slot: u64, cap: u64) -> u64 {
    unsafe {
        COPY_CALLS += 1;
        CNODES[cnode as usize][slot as usize] = cap;
        if FAIL_COPY_AFTER_EFFECT && cnode == FAIL_TARGET_CNODE {
            FAIL_COPY_AFTER_EFFECT = false;
            return 1;
        }
    }
    0
}
unsafe fn hosted_device_resource_state_by_device_id(device_id: u64) -> Option<HostedDeviceResourceState> {
    (device_id == 7 || device_id == 8).then_some(HostedDeviceResourceState {
        device_id, driver_id: 11, instance: 0, pdo_object: device_id * 10,
        projection_domain: HostedDomainIdentity {
            domain_id: DomainId(1), cookie: if device_id == 7 { 11 } else { 22 },
        },
        resource: SharedAddressResource {
            kind: SH_RESOURCE_ADDRESS_KIND_PORT,
            broker_va_or_root_cap: 0xA, component_cap: CT_IO_PORT_BASE,
        },
    })
}
fn instance_by_driver_id(driver_id: u64) -> Option<(usize, DriverInstance)> {
    (driver_id == 11).then_some((0, DriverInstance { cnode: 1 }))
}
unsafe fn hosted_port_projection_owner(cnode: u64) -> Option<hosted_port_projection::PhysicalOwner> {
    (cnode < 8 && PHYSICAL_GENERATION[cnode as usize] != 0).then(||
        hosted_port_projection::PhysicalOwner::Primary {
            instance: cnode as usize, domain_id: 1,
            cookie: PHYSICAL_GENERATION[cnode as usize], tcb: cnode,
        })
}
unsafe fn write_hosted_resource_state_projection(_: u64, _: HostedDeviceResourceState, _: bool) {
    PUBLISHED += 1;
}
fn print_str(_: &[u8]) {}
fn print_u64(_: u64) {}
fn binding() -> HostedDeviceBinding {
    HostedDeviceBinding { device_id: 7, driver_id: 11, instance: 0 }
}
fn sibling_binding() -> HostedDeviceBinding {
    HostedDeviceBinding { device_id: 8, driver_id: 11, instance: 0 }
}
unsafe fn reset() {
    CNODES = [[0; 32]; 8];
    PHYSICAL_GENERATION = [0, 1, 1, 1, 1, 1, 1, 1];
    FAIL_TARGET_CNODE = 2;
    DELETE_CALLS = 0;
    COPY_CALLS = 0;
    FAIL_DELETE_AFTER_EFFECT = false;
    FAIL_COPY_AFTER_EFFECT = false;
    PUBLISHED = 0;
}
"#;

const CASES: &str = r#"
#[test]
fn uncertain_delete_quarantines_the_exact_cnode_without_replay() {
    unsafe {
        reset();
        FAIL_TARGET_CNODE = 3;
        CNODES[3][CT_IO_PORT_BASE as usize] = 0xB;
        FAIL_DELETE_AFTER_EFFECT = true;
        assert!(restore_hosted_device_resource_state(binding(), 100, 3, false).is_err());
        assert_eq!(CNODES[3][CT_IO_PORT_BASE as usize], 0,
            "delete took effect despite the nonzero result");
        assert_eq!(PUBLISHED, 0);
        let calls = (DELETE_CALLS, COPY_CALLS);
        assert!(restore_hosted_device_resource_state(binding(), 100, 3, false).is_err());
        assert_eq!((DELETE_CALLS, COPY_CALLS), calls,
            "uncertain physical CNode delete must not be replayed");
        assert!(clear_hosted_io_port_caps(3).is_err(),
            "a DPC cleanup cannot erase an uncertain prior projection");
        assert_eq!((DELETE_CALLS, COPY_CALLS), calls);
        restore_hosted_device_resource_state(binding(), 101, 4, false).unwrap();
        assert_eq!(CNODES[4][CT_IO_PORT_BASE as usize], 0xA,
            "a distinct physical CNode remains independently usable");
    }
}
#[test]
fn uncertain_copy_retains_possible_child_cap_and_never_cleans_or_replays() {
    unsafe {
        reset();
        FAIL_COPY_AFTER_EFFECT = true;
        assert!(restore_hosted_device_resource_state(binding(), 100, 2, false).is_err());
        assert_eq!(CNODES[2][CT_IO_PORT_BASE as usize], 0xA,
            "copy may have installed the derived child cap");
        assert_eq!(DELETE_CALLS, CT_IO_PORT_CAPACITY,
            "uncertain copy must not trigger a blind cleanup pass");
        assert_eq!(PUBLISHED, 0);
        let calls = (DELETE_CALLS, COPY_CALLS);
        assert!(restore_hosted_device_resource_state(binding(), 100, 2, false).is_err());
        assert_eq!((DELETE_CALLS, COPY_CALLS), calls,
            "uncertain copy must not be overwritten by a later bank");
        assert!(clear_hosted_io_port_caps(2).is_err(),
            "a DPC cleanup cannot discard a possibly installed child cap");
        assert_eq!((DELETE_CALLS, COPY_CALLS), calls);
    }
}
#[test]
fn uncertain_old_owner_blocks_numeric_cnode_reuse_without_retirement() {
    unsafe {
        reset();
        FAIL_TARGET_CNODE = 5;
        FAIL_COPY_AFTER_EFFECT = true;
        assert!(restore_hosted_device_resource_state(binding(), 100, 5, false).is_err());
        let calls = (DELETE_CALLS, COPY_CALLS);
        // Model a new owner being assigned the same root slot without proof that the
        // previous physical CNode and its possibly installed child cap retired.
        PHYSICAL_GENERATION[5] = 2;
        CNODES[5] = [0; 32];
        assert!(restore_hosted_device_resource_state(binding(), 200, 5, false).is_err());
        assert_eq!((DELETE_CALLS, COPY_CALLS), calls,
            "a new generation cannot inherit a quarantined numeric CNode slot");
        assert_eq!(PUBLISHED, 0);
    }
}
#[test]
fn uncertain_replacement_retains_prior_and_incoming_device_generations() {
    unsafe {
        reset();
        FAIL_TARGET_CNODE = 6;
        restore_hosted_device_resource_state(binding(), 100, 6, false).unwrap();
        FAIL_DELETE_AFTER_EFFECT = true;
        assert!(restore_hosted_device_resource_state(sibling_binding(), 200, 6, false).is_err());
        assert!(hosted_port_projection::quarantines_domain(
            HostedDomainIdentity { domain_id: DomainId(1), cookie: 11 }));
        assert!(hosted_port_projection::quarantines_domain(
            HostedDomainIdentity { domain_id: DomainId(1), cookie: 22 }));
        let owner = hosted_port_projection_owner(6).unwrap();
        assert!(!hosted_port_projection::retirement_allowed(6, owner));
        assert!(!hosted_port_projection::retired(6, owner));
    }
}
#[test]
fn acknowledged_retirement_releases_a_physical_cnode_for_new_generation() {
    unsafe {
        reset();
        restore_hosted_device_resource_state(binding(), 100, 7, false).unwrap();
        let owner = hosted_port_projection_owner(7).unwrap();
        assert!(hosted_port_projection::retirement_allowed(7, owner));
        assert!(hosted_port_projection::retired(7, owner));
        PHYSICAL_GENERATION[7] = 2;
        CNODES[7] = [0; 32];
        restore_hosted_device_resource_state(binding(), 200, 7, false).unwrap();
        assert_eq!(CNODES[7][CT_IO_PORT_BASE as usize], 0xA);
    }
}
"#;
