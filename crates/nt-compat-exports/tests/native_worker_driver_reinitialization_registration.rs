//! Compile the production registration validator with primary and physical worker banks.

use std::process::Command;

#[test]
fn reinitialization_registration_accepts_an_exact_worker_generation() {
    let source =
        include_str!("../../../components/ntos-executive/src/hosted_driver_reinitialization.rs");
    let start = source
        .find("pub(super) fn validated_registration(")
        .expect("production reinitialization validator");
    let len = source[start..]
        .find("\n}\n")
        .expect("reinitialization validator end")
        + 2;
    let validator = &source[start..start + len];
    syn::parse_str::<syn::ItemFn>(validator).expect("validator is a complete function");
    let fixture = format!("{SUPPORT}\nmod production {{\nuse super::*;\n{validator}\n}}\nuse production::validated_registration;\n{CASES}");
    let directory =
        std::env::temp_dir().join(format!("nt-worker-driver-reinit-{}", std::process::id()));
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
        "production reinitialization validator must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "worker registration regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::{read_unaligned, read_volatile};
use std::sync::atomic::{AtomicU64, Ordering};

const STATUS_ACCESS_DENIED: i32 = -1;
const STATUS_INVALID_PARAMETER: i32 = -2;
const FSD_CODE_VA: u64 = 0x1000;
const SH_DRVOBJ: u64 = 0;
const WDM_X64_DRIVER_OBJECT_SIZE: usize = 0x40;
const WDM_X64_IO_TYPE_DRIVER: i16 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct DomainId(u64);
impl DomainId { fn raw(self) -> u64 { self.0 } }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostedDomainIdentity { domain_id: DomainId, cookie: u64 }
#[derive(Clone, Copy)]
struct DriverInstance {
    driver_id: u64, driver_object: u64, exec_shared_va: u64,
    image_frames: u64, exec_pool_va: u64,
}
mod spawn_hosts {
    use super::HostedDomainIdentity;
    pub struct PumpChannel {
        pub shared_va: u64,
        pub physical_domain: Option<HostedDomainIdentity>,
        pub reply_cap: u64,
    }
}
#[derive(Debug, Eq, PartialEq)]
struct DriverReinitializationIdentity {
    driver_id: u64, domain_id: u64, domain_cookie: u64,
    driver_object: u64, routine: u64, context: u64,
}

static PRIMARY_BANK: AtomicU64 = AtomicU64::new(0);
static WORKER_BANK: AtomicU64 = AtomicU64::new(0);
static CANONICAL_DRIVER: AtomicU64 = AtomicU64::new(0);
static FOREIGN_DRIVER: AtomicU64 = AtomicU64::new(0);
static ACTIVE_GENERATION: AtomicU64 = AtomicU64::new(0);

fn current_domain() -> HostedDomainIdentity {
    HostedDomainIdentity { domain_id: DomainId(7), cookie: ACTIVE_GENERATION.load(Ordering::Relaxed) }
}
fn current_instance() -> DriverInstance {
    DriverInstance { driver_id: 42, driver_object: CANONICAL_DRIVER.load(Ordering::Relaxed),
        exec_shared_va: PRIMARY_BANK.load(Ordering::Relaxed), image_frames: 2, exec_pool_va: 0x9000 }
}
fn instance(index: usize) -> Option<DriverInstance> { (index == 3).then(current_instance) }
fn instance_domain_identity(_: DriverInstance) -> Option<HostedDomainIdentity> { Some(current_domain()) }
fn instance_for_pump_channel(ch: &spawn_hosts::PumpChannel, reply_cap: u64) -> Option<(usize, DriverInstance)> {
    let bank = ch.shared_va;
    (reply_cap != 0 && reply_cap == ch.reply_cap && ch.physical_domain == Some(current_domain())
        && (bank == PRIMARY_BANK.load(Ordering::Relaxed) || bank == WORKER_BANK.load(Ordering::Relaxed)))
        .then_some((3, current_instance()))
}
fn hosted_pool_allocation_exec_range(_: u64, object: u64) -> Option<(u64, u64)> {
    (object == CANONICAL_DRIVER.load(Ordering::Relaxed)
        || object == FOREIGN_DRIVER.load(Ordering::Relaxed))
        .then_some((object, WDM_X64_DRIVER_OBJECT_SIZE as u64))
}
fn hosted_instance_pool_allocation_is_free_unlocked(_: DriverInstance, _: u64) -> Option<bool> {
    Some(false)
}
"#;

const CASES: &str = r#"
fn driver_object() -> u64 {
    let mut object = Box::new([0u8; WDM_X64_DRIVER_OBJECT_SIZE]);
    object[0..2].copy_from_slice(&WDM_X64_IO_TYPE_DRIVER.to_le_bytes());
    object[2..4].copy_from_slice(&(WDM_X64_DRIVER_OBJECT_SIZE as u16).to_le_bytes());
    Box::into_raw(object) as u64
}
fn bank(driver_object: u64) -> u64 {
    Box::into_raw(Box::new(driver_object)) as u64
}
fn setup() -> (spawn_hosts::PumpChannel, spawn_hosts::PumpChannel, u64) {
    let canonical = driver_object();
    let foreign = driver_object();
    let primary = bank(canonical);
    let worker = bank(canonical);
    CANONICAL_DRIVER.store(canonical, Ordering::Relaxed);
    FOREIGN_DRIVER.store(foreign, Ordering::Relaxed);
    PRIMARY_BANK.store(primary, Ordering::Relaxed);
    WORKER_BANK.store(worker, Ordering::Relaxed);
    ACTIVE_GENERATION.store(19, Ordering::Relaxed);
    let domain = current_domain();
    (spawn_hosts::PumpChannel {shared_va: primary, physical_domain: Some(domain), reply_cap: 88},
     spawn_hosts::PumpChannel {shared_va: worker, physical_domain: Some(domain), reply_cap: 89},
     canonical)
}
#[test]
fn exact_worker_bank_registers_the_canonical_driver() {
    let (_, worker, canonical) = setup();
    assert_eq!(validated_registration(&worker, canonical, 0x1100, 0x55, 89),
        Ok(DriverReinitializationIdentity {driver_id: 42, domain_id: 7, domain_cookie: 19,
            driver_object: canonical, routine: 0x1100, context: 0x55}));
}
#[test]
fn primary_bank_still_registers_the_canonical_driver() {
    let (primary, _, canonical) = setup();
    assert!(validated_registration(&primary, canonical, 0x1100, 0x55, 88).is_ok());
}
#[test]
fn stale_worker_generation_and_wrong_reply_are_rejected() {
    let (_, mut worker, canonical) = setup();
    assert_eq!(validated_registration(&worker, canonical, 0x1100, 0x55, 90), Err(STATUS_ACCESS_DENIED));
    worker.physical_domain = Some(HostedDomainIdentity {domain_id: DomainId(7), cookie: 18});
    assert_eq!(validated_registration(&worker, canonical, 0x1100, 0x55, 89), Err(STATUS_ACCESS_DENIED));
}
#[test]
fn foreign_driver_object_cannot_be_registered_from_a_valid_bank() {
    let (primary, _, _) = setup();
    let foreign = FOREIGN_DRIVER.load(Ordering::Relaxed);
    unsafe { core::ptr::write_volatile(primary.shared_va as *mut u64, foreign); }
    assert_eq!(validated_registration(&primary, foreign, 0x1100, 0x55, 88), Err(STATUS_ACCESS_DENIED));
}
"#;
