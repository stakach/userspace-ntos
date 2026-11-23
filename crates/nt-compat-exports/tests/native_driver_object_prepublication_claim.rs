//! Compile the root's pre-DriverEntry claim against physical source and object lifetimes.

use std::process::Command;

#[test]
fn prepublication_claim_uses_the_exact_primary_source_and_one_shot_object() {
    let source = include_str!(
        "../../../components/ntos-executive/src/hosted_driver_object_claim.rs"
    );
    let start = source.find("pub(super) fn service_claim(").unwrap();
    let len = source[start..].find("\n}").unwrap() + 2;
    let validator = &source[start..start + len];
    syn::parse_str::<syn::ItemFn>(validator).expect("production claim is a complete function");
    let identity_start = source.find("pub(super) fn published_identity(").unwrap();
    let identity_len = source[identity_start..].find("\n}").unwrap() + 2;
    let identity = &source[identity_start..identity_start + identity_len];
    syn::parse_str::<syn::ItemFn>(identity).expect("production publication contract is a function");
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let rebuild = &launch[launch.find("fn register_instance(dc:").unwrap()..];
    let rebuild = &rebuild[..rebuild.find("\n}\n").unwrap()];
    assert!(rebuild.contains("published_claim: u64")
        && rebuild.contains("provisional_driver_object: published_claim,")
        && rebuild.contains("driver_object: dc.drvobj,"),
        "ready-instance reconstruction must retain the exact pre-PE claim");
    let fixture = format!("{SUPPORT}\nmod production {{\nuse super::*;\n{identity}\n{validator}\n}}\nuse production::{{published_identity, service_claim}};\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-driver-object-claim-{}", std::process::id()
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
    assert!(compiled.status.success(), "production claim must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr));
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    assert!(result.status.success(), "claim contract failed:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr));
}

const SUPPORT: &str = r#"
use core::ptr::{read_unaligned, read_volatile};
use std::sync::atomic::{AtomicU64, Ordering};
const STATUS_ACCESS_DENIED: i32 = -1;
const STATUS_INVALID_PARAMETER: i32 = -2;
const STATUS_SUCCESS: i32 = 0;
const SH_DRVOBJ: u64 = 0;
const WDM_X64_IO_TYPE_DRIVER: i16 = 4;
const WDM_X64_DRIVER_OBJECT_SIZE: usize = 0x150;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Domain(u64);
#[derive(Clone, Copy)]
struct DriverInstance {
    driver_id: u64, driver_object: u64, provisional_driver_object: u64, ready: bool, used: bool,
    tcb: u64, pml4: u64, fault_ep: u64, exec_shared_va: u64, exec_pool_va: u64,
    domain: Domain,
}
mod spawn_hosts {
    use super::Domain;
    pub struct PumpChannel {
        pub tcb: u64, pub pml4: u64, pub fault_ep: u64, pub shared_va: u64,
        pub reply_cap: u64, pub domain: Domain,
    }
}
static mut INSTANCE: DriverInstance = DriverInstance {
    driver_id: 0, driver_object: 0, provisional_driver_object: 0, ready: false, used: false,
    tcb: 0, pml4: 0, fault_ep: 0, exec_shared_va: 0, exec_pool_va: 0, domain: Domain(0),
};
static ALLOCATED_OBJECT: AtomicU64 = AtomicU64::new(0);
fn current_instance() -> DriverInstance { unsafe { INSTANCE } }
fn driver_instances_mut() -> &'static mut [DriverInstance; 1] {
    unsafe { &mut *core::ptr::addr_of_mut!(INSTANCE).cast::<[DriverInstance; 1]>() }
}
fn physical_instance_for_pump_channel(ch: &spawn_hosts::PumpChannel) -> Option<(usize, DriverInstance)> {
    let inst = current_instance();
    (ch.tcb == inst.tcb && ch.pml4 == inst.pml4 && ch.fault_ep == inst.fault_ep
        && ch.domain == inst.domain).then_some((0, inst))
}
fn instance_for_pump_channel(ch: &spawn_hosts::PumpChannel, reply: u64) -> Option<(usize, DriverInstance)> {
    (reply != 0 && reply == ch.reply_cap).then_some((0, current_instance()))
}
fn hosted_pool_allocation_exec_range(_: u64, object: u64) -> Option<(u64, u64)> {
    (object == ALLOCATED_OBJECT.load(Ordering::Relaxed))
        .then_some((object, WDM_X64_DRIVER_OBJECT_SIZE as u64))
}
fn hosted_instance_pool_allocation_is_free_unlocked(_: DriverInstance, _: u64) -> Option<bool> {
    Some(false)
}
"#;

const CASES: &str = r#"
fn object() -> u64 {
    let mut bytes = Box::new([0u8; WDM_X64_DRIVER_OBJECT_SIZE]);
    bytes[0..2].copy_from_slice(&WDM_X64_IO_TYPE_DRIVER.to_le_bytes());
    bytes[2..4].copy_from_slice(&(WDM_X64_DRIVER_OBJECT_SIZE as u16).to_le_bytes());
    Box::into_raw(bytes) as u64
}
fn setup() -> (spawn_hosts::PumpChannel, u64) {
    let canonical = object();
    ALLOCATED_OBJECT.store(canonical, Ordering::Relaxed);
    let shared = Box::into_raw(Box::new(canonical)) as u64;
    let ch = spawn_hosts::PumpChannel {
        tcb: 33, pml4: 44, fault_ep: 55, shared_va: shared, reply_cap: 66, domain: Domain(77),
    };
    unsafe { INSTANCE = DriverInstance {
        driver_id: 88, driver_object: 0, provisional_driver_object: 0, ready: false, used: true,
        tcb: 33, pml4: 44, fault_ep: 55, exec_shared_va: shared,
        exec_pool_va: 0x9000, domain: Domain(77),
    }; }
    (ch, canonical)
}
#[test]
fn exact_harness_claim_is_one_shot() {
    let (ch, canonical) = setup();
    assert_eq!(service_claim(&ch, canonical, 66), STATUS_SUCCESS);
    assert_eq!(current_instance().provisional_driver_object, canonical);
    assert_eq!(service_claim(&ch, canonical, 66), STATUS_ACCESS_DENIED);
}
#[test]
fn foreign_or_rewritten_object_cannot_claim() {
    let (ch, canonical) = setup();
    let foreign = object();
    unsafe { core::ptr::write_volatile(ch.shared_va as *mut u64, foreign); }
    assert_eq!(service_claim(&ch, foreign, 66), STATUS_INVALID_PARAMETER);
    assert_eq!(service_claim(&ch, canonical, 66), STATUS_ACCESS_DENIED);
    assert_eq!(current_instance().provisional_driver_object, 0);
}
#[test]
fn wrong_physical_source_reply_and_generation_cannot_claim() {
    let (mut ch, canonical) = setup();
    assert_eq!(service_claim(&ch, canonical, 67), STATUS_ACCESS_DENIED);
    ch.tcb += 1;
    assert_eq!(service_claim(&ch, canonical, 66), STATUS_ACCESS_DENIED);
    ch.tcb -= 1;
    ch.domain = Domain(78);
    assert_eq!(service_claim(&ch, canonical, 66), STATUS_ACCESS_DENIED);
    assert_eq!(current_instance().provisional_driver_object, 0);
}
#[test]
fn retired_instance_cannot_claim() {
    let (ch, canonical) = setup();
    unsafe { INSTANCE.used = false; }
    assert_eq!(service_claim(&ch, canonical, 66), STATUS_ACCESS_DENIED);
}
#[test]
fn publication_and_ready_reconstruction_keep_only_the_claimed_object() {
    let (_, canonical) = setup();
    let foreign = object();
    assert_eq!(published_identity(0, canonical), None);
    assert_eq!(published_identity(canonical, foreign), None);
    let carried = published_identity(canonical, canonical).unwrap();
    let ready = DriverInstance {provisional_driver_object: carried,
        driver_object: canonical, ready: true, ..current_instance()};
    assert_eq!(ready.provisional_driver_object, ready.driver_object);
}
"#;
