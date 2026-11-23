//! The production device-property service must fill the authenticated physical ARG bank.

use std::process::Command;

#[test]
fn device_property_query_preserves_the_parked_primary_arg_bank() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("    let (_projection_instance, inst, pdo_device_id) =\n        match authenticated_hosted_pdo(ch, pdo_object, active_reply_cap)")
        .expect("production property service tail");
    let end = source[start..]
        .find("\n}\n\nfn hosted_root_pdo_identity_status")
        .expect("end of production device service");
    let tail = &source[start..start + end];
    let fixture = format!(
        "{SUPPORT}\nfn production_property_query(ch: &PumpChannel, pdo_object: u64, op: u64, arg2: u64, arg3: u64, active_reply_cap: u64) -> (i32, u64, u64, u64) {{\n{tail}\n}}\n{CASES}"
    );
    syn::parse_file(&fixture).expect("production service tail remains a complete Rust function");
    let directory = std::env::temp_dir().join(format!(
        "nt-worker-device-property-query-{}",
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
        "production property service tail must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "worker property query regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use std::sync::atomic::{AtomicU64, Ordering};
const STATUS_INVALID_PARAMETER: i32 = -2;
const STATUS_ACCESS_DENIED: i32 = -1;
const HOSTED_DEVICE_ARG_DATA_OFF: u64 = 16;
mod nt_io_manager {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct HostedDomainId(pub u64);
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostedDomainIdentity { domain_id: nt_io_manager::HostedDomainId, cookie: u64 }
#[derive(Clone, Copy)] struct DriverInstance {
    hosted_domain_id: u64, hosted_domain_cookie: u64, exec_arg_va: u64,
}
struct DeviceId(u64);
impl DeviceId { fn raw(self) -> u64 { self.0 } }
struct PumpChannel {
    shared_va: u64, tcb: u64, reply_cap: u64, physical_domain: HostedDomainIdentity,
}
struct Status(i32);
impl Status { fn raw(self) -> i32 { self.0 } }
struct HostedDevicePropertyOwner {
    domain: HostedDomainIdentity, pdo_device_id: DeviceId, pdo_address: u64,
}
static PRIMARY_ARG: AtomicU64 = AtomicU64::new(0);
static WORKER_ARG: AtomicU64 = AtomicU64::new(0);
static PRIMARY_SHARED: AtomicU64 = AtomicU64::new(0);
static WORKER_SHARED: AtomicU64 = AtomicU64::new(0);
fn domain() -> HostedDomainIdentity {
    HostedDomainIdentity {domain_id: nt_io_manager::HostedDomainId(7), cookie: 19}
}
fn authenticated_hosted_pdo(ch: &PumpChannel, pdo: u64, reply: u64)
    -> Result<(usize, DriverInstance, DeviceId), Status> {
    if pdo != 0x1234 || reply != ch.reply_cap || ch.physical_domain != domain()
        || !((ch.shared_va == PRIMARY_SHARED.load(Ordering::Relaxed) && ch.tcb == 11)
            || (ch.shared_va == WORKER_SHARED.load(Ordering::Relaxed) && ch.tcb == 12))
    { return Err(Status(STATUS_ACCESS_DENIED)); }
    Ok((3, DriverInstance { hosted_domain_id: 7, hosted_domain_cookie: 19,
        exec_arg_va: PRIMARY_ARG.load(Ordering::Relaxed) }, DeviceId(33)))
}
mod hosted_provider_export_lane {
    pub unsafe fn executive_arg_for_shared(_: u64) -> Option<u64> { None }
}
mod hosted_class_irp_lane {
    use super::*;
    pub unsafe fn executive_arg_for_shared(shared: u64) -> Option<u64> {
        (shared == WORKER_SHARED.load(Ordering::Relaxed))
            .then(|| WORKER_ARG.load(Ordering::Relaxed))
    }
}
mod device_property {
    use super::*;
    pub const PROPERTY_CHUNK_BYTES: usize = 8;
    pub struct DriverPropertyTransfers;
    pub fn service(owner: HostedDevicePropertyOwner, _: u64, _: u64, _: u64,
        data: &mut [u8], _: &mut DriverPropertyTransfers) -> (i32, u64, u64, u64) {
        assert_eq!(owner.domain, domain());
        assert_eq!(owner.pdo_device_id.raw(), 33);
        assert_eq!(owner.pdo_address, 0x1234);
        data.copy_from_slice(&[0xa5; PROPERTY_CHUNK_BYTES]);
        (0, PROPERTY_CHUNK_BYTES as u64, 1, PROPERTY_CHUNK_BYTES as u64)
    }
}
"#;

const CASES: &str = r#"
fn setup() -> (PumpChannel, PumpChannel, Box<[u8; 32]>, Box<[u8; 32]>) {
    let mut primary = Box::new([0x11; 32]);
    let mut worker = Box::new([0x22; 32]);
    PRIMARY_ARG.store(primary.as_mut_ptr() as u64, Ordering::Relaxed);
    WORKER_ARG.store(worker.as_mut_ptr() as u64, Ordering::Relaxed);
    PRIMARY_SHARED.store(0x1000, Ordering::Relaxed);
    WORKER_SHARED.store(0x2000, Ordering::Relaxed);
    (PumpChannel {shared_va: 0x1000, tcb: 11, reply_cap: 81, physical_domain: domain()},
     PumpChannel {shared_va: 0x2000, tcb: 12, reply_cap: 82, physical_domain: domain()},
     primary, worker)
}
#[test]
fn exact_worker_query_fills_its_private_arg_and_preserves_primary() {
    let (_, worker_ch, primary, worker) = setup();
    assert_eq!(production_property_query(&worker_ch, 0x1234, 1, 2, 3, 82).0, 0);
    assert_eq!(&worker[16..24], &[0xa5; 8]);
    assert_eq!(&primary[..], &[0x11; 32]);
}
#[test]
fn primary_query_still_uses_primary_arg() {
    let (primary_ch, _, primary, worker) = setup();
    assert_eq!(production_property_query(&primary_ch, 0x1234, 1, 2, 3, 81).0, 0);
    assert_eq!(&primary[16..24], &[0xa5; 8]);
    assert_eq!(&worker[..], &[0x22; 32]);
}
#[test]
fn stale_reply_and_foreign_worker_tcb_are_refused_before_writing() {
    let (_, mut worker_ch, primary, worker) = setup();
    assert_eq!(production_property_query(&worker_ch, 0x1234, 1, 2, 3, 80).0,
        STATUS_ACCESS_DENIED);
    worker_ch.tcb = 99;
    assert_eq!(production_property_query(&worker_ch, 0x1234, 1, 2, 3, 82).0,
        STATUS_ACCESS_DENIED);
    assert_eq!(&primary[..], &[0x11; 32]);
    assert_eq!(&worker[..], &[0x22; 32]);
}
"#;

#[test]
fn device_property_query_client_reads_the_active_worker_arg_bank() {
    let source = include_str!("../../../components/ntos-executive/src/device_property.rs");
    let start = source
        .find("impl PropertyQueryTransport for DriverPropertyClient {")
        .expect("production property query transport");
    let end = source[start..]
        .find("\n}\n\n/// Native pointer validation")
        .expect("end of production property transport")
        + 2;
    // The real fixed VA is remapped to a test-owned primary buffer. The transport body and its
    // choice between primary and worker remain production source.
    let transport = &source[start..start + end];
    let transport = transport.replace("FSD_ARG_VADDR", "primary_arg()");
    let fixture = format!("{CLIENT_SUPPORT}\n{transport}\n{CLIENT_CASES}");
    syn::parse_file(&fixture).expect("production transport remains complete Rust");
    let directory = std::env::temp_dir().join(format!(
        "nt-worker-device-property-client-{}",
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
        "production property client transport must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "worker property client regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const CLIENT_SUPPORT: &str = r#"
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
const PROPERTY_CHUNK_BYTES: usize = 8;
const HOSTED_DEVICE_ARG_DATA_OFF: u64 = 16;
const FSD_SERVICE_DEVICE_LABEL: u64 = 0x123;
#[derive(Clone, Copy, Debug, Eq, PartialEq)] enum PropertyQueryRequest {
    Begin {pdo:u64, property:u32, capacity:u32},
    Pull {pdo:u64, token:u64, offset:usize},
    Abort {pdo:u64, token:u64},
}
#[derive(Debug)] struct PropertyQueryReply {
    status: nt_status::NtStatus, total_len:u64, token:u64, chunk_len:u64,
    data:[u8; PROPERTY_CHUNK_BYTES],
}
mod nt_status {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)] pub struct NtStatus(pub i32);
    impl NtStatus { pub const SUCCESS: Self = Self(0); }
}
trait PropertyQueryTransport {
    type Scratch;
    fn exchange(&mut self, request:PropertyQueryRequest)
        -> Result<PropertyQueryReply, nt_status::NtStatus>;
    fn allocate(&mut self, bytes:usize) -> Option<Self::Scratch>;
    fn release(&mut self, scratch:Self::Scratch);
}
struct PropertyScratch { address:u64 }
impl PropertyScratch {
    unsafe fn from_allocation(address:u64, _:usize) -> Option<Self> {
        (address != 0).then_some(Self {address})
    }
    fn address(&self) -> u64 { self.address }
}
struct DriverPropertyClient;
static PRIMARY_ARG: AtomicU64 = AtomicU64::new(0);
static WORKER_ARG: AtomicU64 = AtomicU64::new(0);
static ACTIVE_WORKER: AtomicBool = AtomicBool::new(false);
fn primary_arg() -> u64 { PRIMARY_ARG.load(Ordering::Relaxed) }
mod hosted_provider_export_lane {
    pub fn current_component_arg() -> Option<u64> { None }
}
mod hosted_class_irp_lane {
    use super::*;
    pub fn current_component_arg() -> Option<u64> {
        ACTIVE_WORKER.load(Ordering::Relaxed)
            .then(|| WORKER_ARG.load(Ordering::Relaxed))
    }
}
fn request_words(request:PropertyQueryRequest) -> (u64,u64,u64,u64) {
    match request {
        PropertyQueryRequest::Begin {pdo,property,capacity} => (1,pdo,property as u64,capacity as u64),
        _ => (0,0,0,0),
    }
}
unsafe fn call_on4(_:u64, _:u64, _:u64, _:u64, _:u64) -> (u64,u64,u64,u64,u64) {
    let arg = if ACTIVE_WORKER.load(Ordering::Relaxed) {
        WORKER_ARG.load(Ordering::Relaxed)
    } else { PRIMARY_ARG.load(Ordering::Relaxed) };
    core::ptr::write_bytes((arg + HOSTED_DEVICE_ARG_DATA_OFF) as *mut u8, 0xa5,
        PROPERTY_CHUNK_BYTES);
    (1, 0, PROPERTY_CHUNK_BYTES as u64, 77, PROPERTY_CHUNK_BYTES as u64)
}
unsafe fn copy_bytes_unchecked(dst:u64, src:u64, len:u64) {
    core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len as usize)
}
unsafe fn pool_alloc(_:u64) -> u64 { 1 }
unsafe fn pool_free(_:u64) {}
"#;

const CLIENT_CASES: &str = r#"
fn setup() -> (Box<[u8;32]>, Box<[u8;32]>) {
    let mut primary = Box::new([0x11;32]);
    let mut worker = Box::new([0x22;32]);
    PRIMARY_ARG.store(primary.as_mut_ptr() as u64, Ordering::Relaxed);
    WORKER_ARG.store(worker.as_mut_ptr() as u64, Ordering::Relaxed);
    (primary, worker)
}
#[test]
fn worker_transport_consumes_its_private_reply_and_preserves_primary() {
    let (primary, worker) = setup();
    ACTIVE_WORKER.store(true, Ordering::Relaxed);
    let reply = DriverPropertyClient.exchange(PropertyQueryRequest::Begin {
        pdo: 0x1234, property: 1, capacity: 8,
    }).unwrap();
    assert_eq!(reply.data, [0xa5;8]);
    assert_eq!(&primary[..], &[0x11;32]);
    assert_eq!(&worker[16..24], &[0xa5;8]);
}
#[test]
fn primary_transport_consumes_its_own_reply() {
    let (primary, worker) = setup();
    ACTIVE_WORKER.store(false, Ordering::Relaxed);
    let reply = DriverPropertyClient.exchange(PropertyQueryRequest::Begin {
        pdo: 0x1234, property: 1, capacity: 8,
    }).unwrap();
    assert_eq!(reply.data, [0xa5;8]);
    assert_eq!(&primary[16..24], &[0xa5;8]);
    assert_eq!(&worker[..], &[0x22;32]);
}
"#;
