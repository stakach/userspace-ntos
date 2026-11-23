//! Compile WMI REGINFO_CHUNK production paths against separate primary and worker ARG banks.

use std::process::Command;

#[test]
fn wmi_reginfo_component_stream_uses_the_active_arg_bank() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_driver_wmi.rs");
    let start = source
        .find("fn stream_reginfo_bytes(")
        .expect("production component WMI chunk stream");
    let end = source[start..]
        .find("\n}\n\n/// `ULONG IoWMIDeviceObjectToProviderId")
        .expect("end of component chunk stream")
        + 2;
    // Remap the production fixed primary VA into a test-owned allocation; the source's choice
    // of active ARG bank and all copy/call ordering remain unchanged.
    let stream = source[start..start + end].replace("FSD_ARG_VADDR", "primary_arg()");
    let fixture = format!("{COMPONENT_SUPPORT}\n{stream}\n{COMPONENT_CASES}");
    compile_and_run("nt-worker-wmi-component", &fixture);
}

#[test]
fn wmi_reginfo_root_stages_only_the_authenticated_physical_arg_bank() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_driver_wmi.rs");
    let start = source
        .find("fn service_reginfo_terminal(")
        .expect("production root WMI chunk service");
    let end = source[start..]
        .find("\n}\n\nfn authenticated_device(")
        .expect("end of root chunk service")
        + 2;
    let service = &source[start..start + end];
    let fixture = format!("{ROOT_SUPPORT}\n{service}\n{ROOT_CASES}");
    compile_and_run("nt-worker-wmi-root", &fixture);
}

fn compile_and_run(name: &str, fixture: &str) {
    syn::parse_file(fixture).expect("production WMI source slice is complete Rust");
    let directory = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
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
        "production WMI fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "WMI worker ARG regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const COMPONENT_SUPPORT: &str = r#"
use core::ptr::write_volatile;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
const FSD_ARG_BYTES: u64 = 128;
const ARG_CHUNK_LENGTH: u64 = 0;
const ARG_CHUNK_BYTES: u64 = 8;
const OP_REGINFO_CHUNK: u64 = 5;
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
unsafe fn component_device_reply_lock() {}
fn ticket_operation(op: u64, device: u64, ticket: u64, offset: u64) -> Result<u64, i32> {
    assert_eq!((op, device, ticket, offset), (OP_REGINFO_CHUNK, 0x1234, 55, 0));
    Ok(0)
}
"#;

const COMPONENT_CASES: &str = r#"
fn setup() -> (Box<[u8;128]>, Box<[u8;128]>) {
    let mut primary = Box::new([0x11;128]);
    let mut worker = Box::new([0x22;128]);
    PRIMARY_ARG.store(primary.as_mut_ptr() as u64, Ordering::Relaxed);
    WORKER_ARG.store(worker.as_mut_ptr() as u64, Ordering::Relaxed);
    (primary, worker)
}
#[test]
fn worker_chunk_publishes_to_its_private_arg_without_touching_primary() {
    let (primary, worker) = setup();
    ACTIVE_WORKER.store(true, Ordering::Relaxed);
    assert_eq!(stream_reginfo_bytes(0x1234, 55, &[0xa5;4]), Ok(()));
    assert_eq!(&worker[8..12], &[0xa5;4]);
    assert_eq!(&primary[..], &[0x11;128]);
}
#[test]
fn primary_chunk_still_publishes_to_primary_arg() {
    let (primary, worker) = setup();
    ACTIVE_WORKER.store(false, Ordering::Relaxed);
    assert_eq!(stream_reginfo_bytes(0x1234, 55, &[0xa5;4]), Ok(()));
    assert_eq!(&primary[8..12], &[0xa5;4]);
    assert_eq!(&worker[..], &[0x22;128]);
}
"#;

const ROOT_SUPPORT: &str = r#"
use core::ptr::{read_volatile, addr_of_mut};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
const STATUS_SUCCESS: i32 = 0;
const STATUS_ACCESS_DENIED: i32 = -1;
const STATUS_INVALID_HANDLE: i32 = -2;
const STATUS_INVALID_PARAMETER: i32 = -3;
const FSD_ARG_BYTES: u64 = 128;
const ARG_CHUNK_LENGTH: u64 = 0;
const ARG_CHUNK_BYTES: u64 = 8;
const OP_REGINFO_CHUNK: u64 = 5;
const OP_REGINFO_COMPLETE: u64 = 6;
#[derive(Clone, Copy)] struct DomainId(u64);
impl DomainId { fn raw(self) -> u64 { self.0 } }
#[derive(Clone, Copy)] struct Domain { domain_id: DomainId, cookie: u64 }
#[derive(Clone, Copy)] struct Instance {exec_arg_va: u64}
mod spawn_hosts {
    pub struct PumpChannel {pub shared_va:u64, pub tcb:u64, pub reply_cap:u64}
    pub mod shared_ingress {pub mod owner {pub mod runtime {
        use super::super::super::PumpChannel;
        #[derive(Clone, Copy)] pub enum PhysicalSourceKind {
            Primary, DispatchWorker {ordinal:u64},
        }
        pub struct PhysicalSource {pub kind:PhysicalSourceKind}
        pub unsafe fn channel_route(ch:&PumpChannel) -> Result<Option<u64>, ()> {
            Ok(match ch.tcb {11 => Some(1), 12 => Some(2), _ => None})
        }
        pub unsafe fn physical_source(route:u64) -> Result<PhysicalSource, ()> {
            match route {
                1 => Ok(PhysicalSource {kind:PhysicalSourceKind::Primary}),
                2 => Ok(PhysicalSource {kind:PhysicalSourceKind::DispatchWorker {ordinal:1}}),
                _ => Err(()),
            }
        }
    } } }
}
static PRIMARY_ARG: AtomicU64 = AtomicU64::new(0);
static WORKER_ARG: AtomicU64 = AtomicU64::new(0);
static PRIMARY_SHARED: AtomicU64 = AtomicU64::new(0);
static WORKER_SHARED: AtomicU64 = AtomicU64::new(0);
static ACTIVE_ROW: AtomicBool = AtomicBool::new(true);
fn instance_for_pump_channel(ch:&spawn_hosts::PumpChannel, reply:u64) -> Option<(usize,Instance)> {
    let pair = (ch.shared_va == PRIMARY_SHARED.load(Ordering::Relaxed) && ch.tcb == 11)
        || (ch.shared_va == WORKER_SHARED.load(Ordering::Relaxed) && ch.tcb == 12)
        || (ch.shared_va == PRIMARY_SHARED.load(Ordering::Relaxed) && ch.tcb == 12);
    (reply == ch.reply_cap && pair).then_some((3,Instance {
        exec_arg_va: PRIMARY_ARG.load(Ordering::Relaxed)
    }))
}
fn hosted_driver_caller(index:usize, _:Instance, badge:u64) -> Option<()> {
    (index == 3 && badge == 81).then_some(())
}
fn instance_domain_identity(_:Instance) -> Option<Domain> {
    Some(Domain {domain_id:DomainId(7),cookie:19})
}
mod hosted_provider_export_lane {
    pub unsafe fn executive_arg_for_shared(_:u64) -> Option<u64> {None}
}
mod hosted_class_irp_lane {
    use super::*;
    pub unsafe fn executive_arg_for_shared(shared:u64) -> Option<u64> {
        (ACTIVE_ROW.load(Ordering::Relaxed)
            && shared == WORKER_SHARED.load(Ordering::Relaxed))
            .then(|| WORKER_ARG.load(Ordering::Relaxed))
    }
}
#[derive(Clone, Copy)] struct Identity {domain:u64, device_object:u64}
#[derive(Clone, Copy)] struct RegInfoTicket {id:u64}
impl RegInfoTicket {
    fn for_authenticated_device(id:u64, _:Identity) -> Self {Self {id}}
}
struct Registry {staged:[u8;32], len:usize}
impl Registry {
    fn pending_reginfo_identity(&self, id:u64) -> Option<Identity> {
        (id == 55).then_some(Identity {domain:7,device_object:0x1234})
    }
    fn stage_reginfo_chunk(&mut self, ticket:RegInfoTicket, offset:u64, bytes:&[u8])
        -> Result<(),u32> {
        if ticket.id != 55 || offset != 0 || bytes.len() > self.staged.len() {
            return Err(STATUS_INVALID_PARAMETER as u32);
        }
        self.staged[..bytes.len()].copy_from_slice(bytes);
        self.len = bytes.len();
        Ok(())
    }
    fn complete_streamed_reginfo(&mut self, _:RegInfoTicket, _:u32) -> Result<(),u32> {Ok(())}
}
static mut DEVICE_REGISTRY: Registry = Registry {staged:[0;32],len:0};
"#;

const ROOT_CASES: &str = r#"
fn setup() -> (spawn_hosts::PumpChannel, spawn_hosts::PumpChannel, Box<[u8;128]>, Box<[u8;128]>) {
    let mut primary = Box::new([0x11;128]);
    let mut worker = Box::new([0x22;128]);
    primary[..4].copy_from_slice(&4u32.to_le_bytes());
    worker[..4].copy_from_slice(&4u32.to_le_bytes());
    worker[8..12].copy_from_slice(&[0xa5;4]);
    PRIMARY_ARG.store(primary.as_mut_ptr() as u64, Ordering::Relaxed);
    WORKER_ARG.store(worker.as_mut_ptr() as u64, Ordering::Relaxed);
    PRIMARY_SHARED.store(0x1000, Ordering::Relaxed);
    WORKER_SHARED.store(0x2000, Ordering::Relaxed);
    ACTIVE_ROW.store(true, Ordering::Relaxed);
    unsafe { DEVICE_REGISTRY.len = 0; DEVICE_REGISTRY.staged = [0;32]; }
    (spawn_hosts::PumpChannel {shared_va:0x1000,tcb:11,reply_cap:91},
     spawn_hosts::PumpChannel {shared_va:0x2000,tcb:12,reply_cap:92},
     primary,worker)
}
fn staged() -> Vec<u8> {
    unsafe { DEVICE_REGISTRY.staged[..DEVICE_REGISTRY.len].to_vec() }
}
#[test]
fn worker_chunk_stages_private_bytes_without_mutating_primary() {
    let (_, worker, primary_arg, _worker_arg) = setup();
    assert_eq!(service_reginfo_terminal(&worker, OP_REGINFO_CHUNK, 0x1234, 55, 0, 81, 92),
        (STATUS_SUCCESS,0));
    assert_eq!(staged(), [0xa5;4]);
    assert_eq!(&primary_arg[8..12], &[0x11;4]);
}
#[test]
fn primary_chunk_stages_its_own_bytes() {
    let (primary, _, _primary_arg, _worker_arg) = setup();
    assert_eq!(service_reginfo_terminal(&primary, OP_REGINFO_CHUNK, 0x1234, 55, 0, 81, 91),
        (STATUS_SUCCESS,0));
    assert_eq!(staged(), [0x11;4]);
}
#[test]
fn stale_reply_wrong_tcb_and_unknown_ticket_cannot_stage() {
    let (_, mut worker, _primary_arg, _worker_arg) = setup();
    assert_eq!(service_reginfo_terminal(&worker, OP_REGINFO_CHUNK, 0x1234, 55, 0, 81, 90).0,
        STATUS_ACCESS_DENIED);
    worker.tcb = 99;
    assert_eq!(service_reginfo_terminal(&worker, OP_REGINFO_CHUNK, 0x1234, 55, 0, 81, 92).0,
        STATUS_ACCESS_DENIED);
    worker.tcb = 12;
    assert_eq!(service_reginfo_terminal(&worker, OP_REGINFO_CHUNK, 0x1234, 77, 0, 81, 92).0,
        STATUS_INVALID_HANDLE);
    assert!(staged().is_empty());
}
#[test]
fn missing_worker_row_and_forged_primary_shared_cannot_stage() {
    let (primary, worker, _primary_arg, _worker_arg) = setup();
    ACTIVE_ROW.store(false, Ordering::Relaxed);
    assert_eq!(service_reginfo_terminal(&worker, OP_REGINFO_CHUNK, 0x1234, 55, 0, 81, 92).0,
        STATUS_ACCESS_DENIED);
    let forged = spawn_hosts::PumpChannel {tcb:12,reply_cap:92,..primary};
    assert_eq!(service_reginfo_terminal(&forged, OP_REGINFO_CHUNK, 0x1234, 55, 0, 81, 92).0,
        STATUS_ACCESS_DENIED);
    assert!(staged().is_empty());
}
"#;
