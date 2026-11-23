//! The device resource snapshot must follow the root-owned interrupt connection, not a lane's
//! mutable CONNECT request. Compile and exercise the native refresh function with two banks.

use std::process::Command;

#[test]
fn interrupt_evidence_follows_exact_root_connection_across_lane_reuse() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("unsafe fn refresh_hosted_device_resource_state(")
        .expect("native device state refresh");
    let end = source[start..]
        .find("\nunsafe fn hosted_io_port_cap_effects_mut(")
        .expect("native refresh boundary");
    let fixture = format!("{SUPPORT}\n{}\n{CASES}", &source[start..start + end]);
    let directory = std::env::temp_dir().join(format!(
        "nt-interrupt-canonical-evidence-{}",
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
        "interrupt evidence fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "canonical interrupt evidence regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::read_volatile;

const OBJECT: usize = 0;
const ROUTINE: usize = 1;
const CONTEXT: usize = 2;
const ID: usize = 3;
const DELIVERED_VECTOR: usize = 4;
const ISR_CLAIMED: usize = 5;
const DELIVERIES: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostedDeviceBinding { device_id: u64, projection_domain: u64 }
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HostedHardwareEvidence {
    interrupt_object: u64, interrupt_routine: u64,
    interrupt_context: u64, interrupt_id: u64,
    interrupt_delivered_vector: u64, interrupt_isr_claimed: u64,
    interrupt_deliveries: u64,
}
#[derive(Clone, Copy, Debug)]
struct HostedDeviceResourceState {
    device_id: u64, projection_domain: u64, evidence: HostedHardwareEvidence,
}
#[derive(Clone, Copy)]
struct Tokens { interrupt_id: u64, service_routine_token: u64, service_context_token: u64 }
#[derive(Clone, Copy)]
struct Route { tokens: Tokens }
#[derive(Clone, Copy)]
struct HostedIrqConnection {
    binding: HostedDeviceBinding, interrupt_object: u64,
    route: Route, active: bool,
}

static mut STATES: Vec<HostedDeviceResourceState> = Vec::new();
static mut CONNECTIONS: Vec<HostedIrqConnection> = Vec::new();

unsafe fn read_hosted_device_resource_state_from_shared(
    binding: HostedDeviceBinding, sh: u64,
) -> HostedDeviceResourceState {
    let bank = sh as *const u64;
    HostedDeviceResourceState {
        device_id: binding.device_id,
        projection_domain: binding.projection_domain,
        evidence: HostedHardwareEvidence {
            interrupt_object: read_volatile(bank.add(OBJECT)),
            interrupt_routine: read_volatile(bank.add(ROUTINE)),
            interrupt_context: read_volatile(bank.add(CONTEXT)),
            interrupt_id: read_volatile(bank.add(ID)),
            interrupt_delivered_vector: read_volatile(bank.add(DELIVERED_VECTOR)),
            interrupt_isr_claimed: read_volatile(bank.add(ISR_CLAIMED)),
            interrupt_deliveries: read_volatile(bank.add(DELIVERIES)),
        },
    }
}
unsafe fn hosted_device_resource_states_mut() -> &'static mut Vec<HostedDeviceResourceState> {
    &mut *core::ptr::addr_of_mut!(STATES)
}
fn hosted_irq_connections() -> Option<&'static Vec<HostedIrqConnection>> {
    Some(unsafe { &*core::ptr::addr_of!(CONNECTIONS) })
}
fn hosted_irq_connection_active(connection: HostedIrqConnection) -> bool { connection.active }
"#;

const CASES: &str = r#"
#[test]
fn request_bytes_never_become_canonical_evidence() {
    let binding = HostedDeviceBinding { device_id: 7, projection_domain: 13 };
    let other = HostedDeviceBinding { device_id: 8, projection_domain: 13 };
    let mut first_bank = [0xaaa_u64, 0xbbb, 0xccc, 123, 55, 1, 9];
    let mut second_bank = [0xddd_u64, 0xeee, 0xfff, 456, 77, 1, 5];
    unsafe {
        refresh_hosted_device_resource_state(binding, first_bank.as_mut_ptr() as u64);
        assert_eq!(STATES[0].evidence, HostedHardwareEvidence::default(),
            "a staged CONNECT has no active root connection");
        assert_eq!(first_bank, [0xaaa, 0xbbb, 0xccc, 123, 55, 1, 9],
            "canonicalization must not erase an in-flight request");
        CONNECTIONS.push(HostedIrqConnection {
            binding: other, interrupt_object: 0x999,
            route: Route { tokens: Tokens { interrupt_id: 66,
                service_routine_token: 0x888, service_context_token: 0x777 } }, active: true,
        });
        CONNECTIONS.push(HostedIrqConnection {
            binding, interrupt_object: 0x111,
            route: Route { tokens: Tokens { interrupt_id: 99,
                service_routine_token: 0x222, service_context_token: 0x333 } }, active: true,
        });
        refresh_hosted_device_resource_state(binding, second_bank.as_mut_ptr() as u64);
        assert_eq!(STATES[0].evidence, HostedHardwareEvidence {
            interrupt_object: 0x111, interrupt_routine: 0x222,
            interrupt_context: 0x333, interrupt_id: 99,
            interrupt_delivered_vector: 0, interrupt_isr_claimed: 0,
            interrupt_deliveries: 0,
        }, "root connection must override another lane's mutable bytes");
        assert_eq!(second_bank, [0xddd, 0xeee, 0xfff, 456, 77, 1, 5]);
        CONNECTIONS[1].active = false;
        refresh_hosted_device_resource_state(binding, second_bank.as_mut_ptr() as u64);
        assert_eq!(STATES[0].evidence, HostedHardwareEvidence::default(),
            "retirement must not republish an old object into the next lane");
    }
}
"#;
