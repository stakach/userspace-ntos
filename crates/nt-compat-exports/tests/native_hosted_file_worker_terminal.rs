//! Compile the production WRITE terminal publisher with an authenticated worker bank.

use std::process::Command;

#[test]
fn completed_worker_file_terminals_publish_only_to_their_exact_live_bank() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_kernel_file_write.rs");
    let start = source
        .find(
            "        let (status, information) = self.terminal.expect(\"hosted WRITE terminal\");",
        )
        .expect("WRITE terminal publisher start");
    let end = source[start..]
        .find("\n    }\n}\n\npub(crate) unsafe fn redrive")
        .expect("WRITE terminal publisher end")
        + start;
    let control_source =
        include_str!("../../../components/ntos-executive/src/hosted_kernel_file_control.rs");
    let control_start = control_source
        .find(
            "        let (status, information) = self.terminal.expect(\"hosted FSCTL terminal\");",
        )
        .expect("FSCTL terminal publisher start");
    let control_end = control_source[control_start..]
        .find("\n    }\n}\n\npub(crate) unsafe fn redrive")
        .expect("FSCTL terminal publisher end")
        + control_start;
    let control = control_source[control_start..control_end]
        .replace("STATUS_OFF", "CONTROL_STATUS_OFF")
        .replace("COPIED_OFF", "CONTROL_COPIED_OFF")
        .replace("INFORMATION_OFF", "CONTROL_INFORMATION_OFF")
        .replace("COMPLETED_OFF", "CONTROL_COMPLETED_OFF");
    let read_source =
        include_str!("../../../components/ntos-executive/src/hosted_kernel_file_read_query.rs");
    let read_start = read_source.find("        match &mut self.source {\n            PacketSource::Fsd { instance, domain, channel } =>")
        .expect("READ/QUERY terminal publisher start");
    let read_end = read_source[read_start..]
        .find("\n    }\n}\n\nunsafe fn redrive_one")
        .expect("READ/QUERY terminal publisher end")
        + read_start;
    let transport =
        include_str!("../../../components/ntos-executive/src/hosted_kernel_file_transport.rs");
    let fixture = format!("{SUPPORT}\nmod hosted_kernel_file_transport {{\n{transport}\n}}\nimpl Work {{ unsafe fn terminal(&mut self, handler: *mut Handler) -> bool {{\n{}\n}} }}\nimpl ControlWork {{ unsafe fn terminal(&mut self, handler: *mut Handler) -> bool {{\n{control}\n}} }}\nimpl ReadWork {{ unsafe fn terminal(&mut self, handler: *mut Handler, status: u32, information: u64) -> bool {{\n{}\n}} }}\n{CASES}", &source[start..end], &read_source[read_start..read_end]);
    let directory =
        std::env::temp_dir().join(format!("nt-hosted-file-worker-{}", std::process::id()));
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
        "worker fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "worker terminal regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::write_unaligned;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct Domain { id: u64, generation: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct Transport { domain: Domain, endpoint: u64, vspace: u64, shared: u64 }
impl Transport { fn matches_live(self, live: Self) -> bool {
    self.domain.id != 0 && self.domain.generation != 0 && self.endpoint != 0 && self.vspace != 0 && self.shared != 0 && self == live
} }
mod nt_io_manager { pub type HostedTransportIdentity = super::Transport; }
mod nt_component_suspension { pub mod peer_registry { pub type PeerRoute = u64; } pub type LaneDispatchIdentity = u64; }
#[derive(Clone, Copy)] struct DriverInstance { domain: Domain, fault_ep: u64, pml4: u64, exec_shared_va: u64, exec_pool_va: u64, tcb: u64, driver_id: u64 }
#[derive(Clone, Copy)] struct PumpChannel { ingress_route: Option<u64>, physical_domain: Option<Domain>, fault_ep: u64, pml4: u64, shared_va: u64, tcb: u64 }
struct File { id: u64 }
impl File { fn file_id(&self) -> u64 { self.id } }
struct Params { length: u32 }
struct Completion { signaled: bool }
impl Completion { fn set_signaled(&mut self, id: u64, value: bool) -> Result<(), ()> { assert_eq!(id, 17); self.signaled=value; Ok(()) } }
struct Handler { file_completion: Completion }
impl Handler { fn dispatcher_objects(&mut self, _: Option<()>) -> Vec<()> { Vec::new() } }
struct Work { terminal: Option<(u32,u64)>, parameters: Params, domain: Transport, channel: PumpChannel,
    instance: DriverInstance, packet: u64, packet_length: u64, file: File, reply_entered: bool,
    route: u64, dispatch: u64, reply: u64, token: u64 }
struct ControlWork { terminal: Option<(u32,u64)>, domain: Transport, channel: PumpChannel,
    instance: DriverInstance, component_packet: u64, packet_length: u64, file: File,
    input: Vec<u8>, output: Vec<u8>, copied: usize, reply_entered: bool,
    route: u64, dispatch: u64, reply: u64, token: u64 }
enum PacketSource { Fsd { instance: DriverInstance, domain: Transport, channel: PumpChannel },
    Win32k { lease: u64, packet: Vec<u8> } }
#[derive(Clone,Copy)] enum Operation { Read, Directory { unused: u64 } }
struct ReadWork { source: PacketSource, packet: u64, packet_length: u64, file: File,
    output: Vec<u8>, operation: Operation, delivery_required: bool, reply_entered: bool,
    route: u64, dispatch: u64, reply: u64, token: u64 }
const STATUS_OFF: u64 = 4; const INFORMATION_OFF: u64 = 8; const COMPLETED_OFF: u64 = 0;
const HEADER_BYTES: usize = 32;
const CONTROL_STATUS_OFF: u64 = 16; const CONTROL_COPIED_OFF: u64 = 20;
const CONTROL_INFORMATION_OFF: u64 = 24; const CONTROL_COMPLETED_OFF: u64 = 12;
mod wire { pub fn publish_completion(packet: &mut [u8], output: &[u8], status: u32, info: u64) -> Result<(), ()> {
    if packet.len() < 40 || output.len() > packet.len()-40 { return Err(()); }
    packet[24..28].copy_from_slice(&1u32.to_ne_bytes());
    packet[28..32].copy_from_slice(&status.to_ne_bytes());
    packet[32..40].copy_from_slice(&info.to_ne_bytes());
    packet[40..40+output.len()].copy_from_slice(output); Ok(())
} }
mod directory_wire { pub use crate::wire::publish_completion; }
mod provider_bugcheck { pub fn report(_: u32, _: [u64;4]) -> ! { panic!("bad wire publication") } }
mod win32k_subsystem { pub fn publish_provider_pool_packet(_: u64, _: &mut Vec<u8>) -> bool { true } }
mod service_sec_image { pub fn provider_wait_select_ready(_: &mut Vec<()>) {} }
static PRIMARY_BANK: AtomicU64=AtomicU64::new(0); static WORKER_BANK: AtomicU64=AtomicU64::new(0);
static LIVE_GENERATION: AtomicU64=AtomicU64::new(1); static LIVE_ROUTE: AtomicU64=AtomicU64::new(81);
static LIVE_DISPATCH: AtomicU64=AtomicU64::new(82); static LIVE_REPLY: AtomicU64=AtomicU64::new(83);
static WAKE: AtomicBool=AtomicBool::new(false);
fn live() -> DriverInstance { DriverInstance { domain: Domain { id: 7, generation: LIVE_GENERATION.load(Ordering::Relaxed) },
    fault_ep: 43, pml4: 53, exec_shared_va: PRIMARY_BANK.load(Ordering::Relaxed), exec_pool_va: 63, tcb: 73, driver_id: 11 } }
fn instance_by_shared_va(shared: u64) -> Option<(usize, DriverInstance)> {
    (shared == PRIMARY_BANK.load(Ordering::Relaxed)).then_some((0, live()))
}
fn instance_domain_identity(inst: DriverInstance) -> Option<Domain> { Some(inst.domain) }
mod hosted_class_irp_lane {
    use super::*;
    pub unsafe fn instance_for_shared(shared: u64) -> Option<(usize, DriverInstance)> {
        (shared == WORKER_BANK.load(Ordering::Relaxed)).then_some((0, live()))
    }
    pub unsafe fn matches_channel(index: usize, inst: DriverInstance, ch: &PumpChannel) -> bool {
        index == 0 && inst.domain == ch.physical_domain.unwrap() && ch.shared_va == WORKER_BANK.load(Ordering::Relaxed)
            && ch.ingress_route == Some(LIVE_ROUTE.load(Ordering::Relaxed)) && ch.tcb == 99 && ch.pml4 == inst.pml4 && ch.fault_ep == inst.fault_ep
    }
}
mod hosted_source_completion_lane {
    use super::*;
    pub unsafe fn instance_for_shared(_: u64) -> Option<(usize, DriverInstance)> { None }
    pub unsafe fn matches_channel(_: usize, _: DriverInstance, _: &PumpChannel) -> bool { false }
}
mod hosted_provider_export_lane {
    use super::*;
    pub unsafe fn instance_for_shared(_: u64) -> Option<(usize, DriverInstance)> { None }
    pub unsafe fn matches_channel(_: usize, _: DriverInstance, _: &PumpChannel) -> bool { false }
}
pub mod runtime {
    use super::*;
    pub unsafe fn channel_route(ch: &PumpChannel) -> Result<Option<u64>, ()> {
        if ch.ingress_route == Some(LIVE_ROUTE.load(Ordering::Relaxed)) && ch.physical_domain == Some(live().domain)
            && ch.pml4 == live().pml4 && ch.fault_ep == live().fault_ep
            && ((ch.tcb == 99 && ch.shared_va == WORKER_BANK.load(Ordering::Relaxed))
                || (ch.tcb == 73 && ch.shared_va == PRIMARY_BANK.load(Ordering::Relaxed)))
        { Ok(ch.ingress_route) } else { Err(()) }
    }
    pub unsafe fn dispatch(_: u64) -> Result<u64, ()> { Ok(LIVE_DISPATCH.load(Ordering::Relaxed)) }
    pub unsafe fn current_reply(_: u64) -> Result<u64, ()> { Ok(LIVE_REPLY.load(Ordering::Relaxed)) }
    pub unsafe fn wake_service(route: u64, dispatch: u64, reply: u64, token: u64, _: i32) -> Result<(), ()> {
        assert_eq!((route, dispatch, reply, token), (81,82,83,84)); WAKE.store(true, Ordering::Relaxed); Ok(())
    }
}
mod spawn_hosts {
    pub type PumpChannel = super::PumpChannel;
    pub mod shared_ingress { pub mod owner { pub use crate::runtime; } }
}
unsafe fn hosted_instance_pool_allocation_exec_if_live(live: DriverInstance, packet: u64, len: u64) -> Option<u64> {
    (live.exec_pool_va == 63 && packet != 0 && len >= 16).then_some(packet)
}
"#;

const CASES: &str = r#"
fn make_work(packet: &mut [u8; 32], bank: u64) -> Work {
    let channel = PumpChannel { ingress_route: Some(81), physical_domain: Some(Domain { id: 7, generation: 1 }),
        fault_ep: 43, pml4: 53, shared_va: bank, tcb: 99 };
    Work { terminal: Some((0, 3)), parameters: Params { length: 4 },
        domain: Transport { domain: channel.physical_domain.unwrap(), endpoint: 43, vspace: 53, shared: bank },
        channel, instance: live(), packet: packet.as_mut_ptr() as u64, packet_length: packet.len() as u64,
        file: File { id: 17 }, reply_entered: false, route: 81, dispatch: 82, reply: 83, token: 84 }
}
fn make_channel(bank: u64) -> PumpChannel {
    PumpChannel { ingress_route: Some(81), physical_domain: Some(Domain { id: 7, generation: 1 }),
        fault_ep: 43, pml4: 53, shared_va: bank, tcb: 99 }
}
fn make_transport(channel: PumpChannel) -> Transport {
    Transport { domain: channel.physical_domain.unwrap(), endpoint: 43, vspace: 53, shared: channel.shared_va }
}
#[test] fn worker_fsctl_and_read_terminals_publish_and_wake() {
    PRIMARY_BANK.store(100, Ordering::Relaxed); WORKER_BANK.store(200, Ordering::Relaxed);
    LIVE_GENERATION.store(1, Ordering::Relaxed); LIVE_ROUTE.store(81, Ordering::Relaxed);
    LIVE_DISPATCH.store(82, Ordering::Relaxed); LIVE_REPLY.store(83, Ordering::Relaxed);
    let channel=make_channel(200);
    let mut control_packet=[0u8;64];
    let mut control=ControlWork { terminal: Some((0,2)), domain: make_transport(channel), channel,
        instance: live(), component_packet: control_packet.as_mut_ptr() as u64,
        packet_length: control_packet.len() as u64, file: File { id: 17 }, input: vec![],
        output: vec![9,8], copied: 2, reply_entered: false, route: 81, dispatch: 82, reply: 83, token: 84 };
    let mut handler=Handler { file_completion: Completion { signaled: false } };
    WAKE.store(false, Ordering::Relaxed);
    unsafe { assert!(!control.terminal(&mut handler)); }
    assert_eq!(u32::from_ne_bytes(control_packet[12..16].try_into().unwrap()), 1);
    assert_eq!(&control_packet[32..34], &[9,8]);
    assert!(handler.file_completion.signaled && control.reply_entered && WAKE.load(Ordering::Relaxed));
    let mut read_packet=[0u8;64];
    let mut read=ReadWork { source: PacketSource::Fsd { instance: live(), domain: make_transport(channel), channel },
        packet: read_packet.as_mut_ptr() as u64, packet_length: read_packet.len() as u64,
        file: File { id: 17 }, output: vec![1,2], operation: Operation::Read,
        delivery_required: false, reply_entered: false, route: 81, dispatch: 82, reply: 83, token: 84 };
    let mut handler=Handler { file_completion: Completion { signaled: false } };
    WAKE.store(false, Ordering::Relaxed);
    unsafe { assert!(!read.terminal(&mut handler,0,2)); }
    assert_eq!(u32::from_ne_bytes(read_packet[24..28].try_into().unwrap()), 1);
    assert_eq!(&read_packet[40..42], &[1,2]);
    assert!(handler.file_completion.signaled && read.reply_entered && WAKE.load(Ordering::Relaxed));
}
#[test] fn wrong_worker_bank_blocks_fsctl_and_read_publication() {
    PRIMARY_BANK.store(100, Ordering::Relaxed); WORKER_BANK.store(200, Ordering::Relaxed);
    LIVE_GENERATION.store(1, Ordering::Relaxed); LIVE_ROUTE.store(81, Ordering::Relaxed);
    LIVE_DISPATCH.store(82, Ordering::Relaxed); LIVE_REPLY.store(83, Ordering::Relaxed);
    let channel=make_channel(201);
    let mut control_packet=[0u8;64];
    let mut control=ControlWork { terminal: Some((0,2)), domain: make_transport(channel), channel,
        instance: live(), component_packet: control_packet.as_mut_ptr() as u64,
        packet_length: control_packet.len() as u64, file: File { id: 17 }, input: vec![],
        output: vec![9,8], copied: 2, reply_entered: false, route: 81, dispatch: 82, reply: 83, token: 84 };
    let mut handler=Handler { file_completion: Completion { signaled: false } };
    WAKE.store(false, Ordering::Relaxed);
    unsafe { assert!(!control.terminal(&mut handler)); }
    assert_eq!(u32::from_ne_bytes(control_packet[12..16].try_into().unwrap()), 0);
    assert!(!handler.file_completion.signaled && !control.reply_entered && !WAKE.load(Ordering::Relaxed));
    let mut read_packet=[0u8;64];
    let mut read=ReadWork { source: PacketSource::Fsd { instance: live(), domain: make_transport(channel), channel },
        packet: read_packet.as_mut_ptr() as u64, packet_length: read_packet.len() as u64,
        file: File { id: 17 }, output: vec![1,2], operation: Operation::Read,
        delivery_required: false, reply_entered: false, route: 81, dispatch: 82, reply: 83, token: 84 };
    let mut handler=Handler { file_completion: Completion { signaled: false } };
    WAKE.store(false, Ordering::Relaxed);
    unsafe { assert!(!read.terminal(&mut handler,0,2)); }
    assert_eq!(u32::from_ne_bytes(read_packet[24..28].try_into().unwrap()), 0);
    assert!(!handler.file_completion.signaled && !read.reply_entered && !WAKE.load(Ordering::Relaxed));
}
#[test] fn worker_terminal_writes_and_wakes() {
    PRIMARY_BANK.store(100, Ordering::Relaxed); WORKER_BANK.store(200, Ordering::Relaxed);
    LIVE_GENERATION.store(1, Ordering::Relaxed); LIVE_ROUTE.store(81, Ordering::Relaxed);
    LIVE_DISPATCH.store(82, Ordering::Relaxed); LIVE_REPLY.store(83, Ordering::Relaxed);
    WAKE.store(false, Ordering::Relaxed);
    let mut packet=[0u8;32]; let mut work=make_work(&mut packet, 200);
    let mut handler=Handler { file_completion: Completion { signaled: false } };
    unsafe { assert!(!work.terminal(&mut handler)); }
    assert_eq!(u32::from_ne_bytes(packet[0..4].try_into().unwrap()), 1, "worker packet not completed");
    assert!(handler.file_completion.signaled && work.reply_entered && WAKE.load(Ordering::Relaxed));
}
#[test] fn primary_terminal_remains_live() {
    PRIMARY_BANK.store(100, Ordering::Relaxed); WORKER_BANK.store(200, Ordering::Relaxed);
    LIVE_GENERATION.store(1, Ordering::Relaxed); LIVE_ROUTE.store(81, Ordering::Relaxed);
    LIVE_DISPATCH.store(82, Ordering::Relaxed); LIVE_REPLY.store(83, Ordering::Relaxed);
    WAKE.store(false, Ordering::Relaxed);
    let mut packet=[0u8;32]; let mut work=make_work(&mut packet, 100);
    work.channel.tcb=73;
    let mut handler=Handler { file_completion: Completion { signaled: false } };
    unsafe { assert!(!work.terminal(&mut handler)); }
    assert_eq!(u32::from_ne_bytes(packet[0..4].try_into().unwrap()), 1);
    assert!(handler.file_completion.signaled && work.reply_entered && WAKE.load(Ordering::Relaxed));
}
#[test] fn wrong_bank_and_retired_generation_never_publish() {
    PRIMARY_BANK.store(100, Ordering::Relaxed); WORKER_BANK.store(200, Ordering::Relaxed);
    LIVE_GENERATION.store(1, Ordering::Relaxed); LIVE_ROUTE.store(81, Ordering::Relaxed);
    LIVE_DISPATCH.store(82, Ordering::Relaxed); LIVE_REPLY.store(83, Ordering::Relaxed);
    for (bank, generation) in [(201,1),(200,2)] {
        let mut packet=[0u8;32]; let mut work=make_work(&mut packet, bank);
        LIVE_GENERATION.store(generation, Ordering::Relaxed); WAKE.store(false, Ordering::Relaxed);
        let mut handler=Handler { file_completion: Completion { signaled: false } };
        unsafe { assert!(!work.terminal(&mut handler)); }
        assert_eq!(u32::from_ne_bytes(packet[0..4].try_into().unwrap()), 0);
        assert!(!handler.file_completion.signaled && !work.reply_entered && !WAKE.load(Ordering::Relaxed));
    }
    LIVE_GENERATION.store(1, Ordering::Relaxed);
    let mut packet=[0u8;32]; let mut work=make_work(&mut packet, 200);
    LIVE_ROUTE.store(82, Ordering::Relaxed);
    let mut handler=Handler { file_completion: Completion { signaled: false } };
    unsafe { assert!(!work.terminal(&mut handler)); }
    assert_eq!(u32::from_ne_bytes(packet[0..4].try_into().unwrap()), 0);
    assert!(!handler.file_completion.signaled && !work.reply_entered);
    LIVE_ROUTE.store(81, Ordering::Relaxed);
    for (dispatch, reply) in [(87,83),(82,88)] {
        LIVE_DISPATCH.store(dispatch, Ordering::Relaxed); LIVE_REPLY.store(reply, Ordering::Relaxed);
        let mut packet=[0u8;32]; let mut work=make_work(&mut packet, 200);
        let mut handler=Handler { file_completion: Completion { signaled: false } };
        unsafe { assert!(!work.terminal(&mut handler)); }
        assert_eq!(u32::from_ne_bytes(packet[0..4].try_into().unwrap()), 0);
        assert!(!handler.file_completion.signaled && !work.reply_entered);
    }
}
"#;
