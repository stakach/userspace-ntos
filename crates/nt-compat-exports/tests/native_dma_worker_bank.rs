//! Compile the production DMA dispatch selector and lease gate with two live worker banks.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn section(start: &str, end: &str) -> &'static str {
    let from = SOURCE.find(start).expect("production start marker");
    let tail = &SOURCE[from..];
    &tail[..tail.find(end).expect("production end marker")]
}

#[test]
fn hal_get_adapter_uses_active_worker_dispatch_bank() {
    let bank_selector = section(
        "unsafe fn hosted_component_resource_shared_va()",
        "\n#[inline]\nunsafe fn hosted_raise_irql(",
    );
    let hal_get_adapter = section(
        "extern \"win64\" fn s_hal_get_adapter(",
        "\nfn project_hosted_dma_adapter(",
    )
    .replacen("extern \"win64\"", "extern \"C\"", 1);
    let fixture = format!("{HAL_SUPPORT}\n{bank_selector}\n{hal_get_adapter}\n{HAL_CASES}");
    let directory = std::env::temp_dir().join(format!("nt-dma-hal-worker-{}", std::process::id()));
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
        "HalGetAdapter fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "HalGetAdapter worker regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const HAL_SUPPORT: &str = r#"
use core::ptr::read_volatile;
static mut FSD_SHARED_VADDR: u64 = 0;
static mut CLASS_BANK: u64 = 0;
static mut PROVIDER_BANK: u64 = 0;
static mut IRQ_BANK: u64 = 0;
static mut ACTIVE_IRQ: bool = false;
const SH_ACTIVE_DEVICE_OBJECT: u64 = 0x20;
fn hosted_irq_lane_context() -> Option<()> { unsafe { ACTIVE_IRQ.then_some(()) } }
unsafe fn hosted_component_shared_va() -> u64 { IRQ_BANK }
mod hosted_provider_export_lane {
    pub fn current_component_bank() -> Option<u64> {
        unsafe { (super::PROVIDER_BANK != 0).then_some(super::PROVIDER_BANK) }
    }
}
mod hosted_class_irp_lane {
    pub fn current_component_bank() -> Option<u64> {
        unsafe { (super::CLASS_BANK != 0).then_some(super::CLASS_BANK) }
    }
}
fn project_hosted_dma_adapter(pdo: u64, _: u64, _: *mut u32) -> u64 { pdo }
"#;

const HAL_CASES: &str = r#"
#[test]
fn exact_active_worker_pdo_wins_over_primary_and_newer_sibling() {
    let mut primary = [0u64; 8];
    let mut worker_a = [0u64; 8];
    let mut worker_b = [0u64; 8];
    let mut provider = [0u64; 8];
    let mut irq = [0u64; 8];
    primary[4] = 22;
    worker_a[4] = 11;
    worker_b[4] = 33;
    provider[4] = 44;
    irq[4] = 55;
    unsafe {
        FSD_SHARED_VADDR = primary.as_mut_ptr() as u64;
        CLASS_BANK = worker_a.as_mut_ptr() as u64;
        assert_eq!(s_hal_get_adapter(1, core::ptr::null_mut()), 11);
        CLASS_BANK = worker_b.as_mut_ptr() as u64;
        assert_eq!(s_hal_get_adapter(1, core::ptr::null_mut()), 33);
        PROVIDER_BANK = provider.as_mut_ptr() as u64;
        assert_eq!(s_hal_get_adapter(1, core::ptr::null_mut()), 44);
        IRQ_BANK = irq.as_mut_ptr() as u64;
        ACTIVE_IRQ = true;
        assert_eq!(s_hal_get_adapter(1, core::ptr::null_mut()), 55);
        ACTIVE_IRQ = false;
        PROVIDER_BANK = 0;
        CLASS_BANK = 0;
        assert_eq!(s_hal_get_adapter(1, core::ptr::null_mut()), 22);
    }
}
"#;

#[test]
fn worker_dma_request_and_free_use_exact_lane_and_lease() {
    let selector = section(
        "fn current_hosted_device_dispatch_binding_for_projection(",
        "\nconst EMPTY_HOSTED_DEVICE_BINDING:",
    );
    let request = section(
        "    let description = match nt_dma_manager::Nt5DeviceDescription::from_service_words(words) {",
        "    if unsafe { hosted_dma_owner_is_quarantined(owner) } {",
    );
    let lease = section(
        "unsafe fn authenticated_hosted_dma_free_lease(",
        "\n#[allow(clippy::too_many_arguments)]\nunsafe fn free_hosted_dma_common_buffer_lease(",
    );
    let fixture = format!(
        "{SUPPORT}\n{selector}\n{lease}\nfn request(ch: &PumpChannel, pdo_object: u64, words: [u64;4], active_reply_cap: u64) -> (i32,u64,u64,u64) {{\n{request}\n    (STATUS_SUCCESS, binding.device_id, owner, 0)\n}}\n{CASES}"
    );
    let directory = std::env::temp_dir().join(format!("nt-dma-worker-bank-{}", std::process::id()));
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
        "DMA fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "DMA worker regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct Domain(u64);
type HostedDomainIdentity = Domain;
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct DeviceId(u64);
impl DeviceId { fn raw(self) -> u64 { self.0 } }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct Registration { domain: Domain, address: u64, device_id: DeviceId }
impl Registration { fn domain(self) -> Domain { self.domain } fn address(self) -> u64 { self.address } fn device_id(self) -> DeviceId { self.device_id } }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct DriverInstance { ready: bool, domain: Domain, exec_shared_va: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct HostedDeviceBinding { used: bool, instance: usize, projection_instance: usize,
    projection_domain: Domain, driver_id: u64, device_id: u64, pdo_device_id: u64, pdo_object: u64, owner: u64 }
#[derive(Clone, Copy)] struct Context { projection_shared_va: Option<u64>, instance: usize, binding: HostedDeviceBinding }
struct ContextTable { rows: Vec<Context> }
impl ContextTable { fn find_active(&self, mut predicate: impl FnMut(&Context)->bool) -> Option<&Context> {
    self.rows.iter().rev().find(|row| predicate(row))
} }
#[derive(Clone, Copy, Debug)] enum HostedProjectionBindingRejection { ContextTable, Context, DriverInstance,
    ProjectionInstance, CanonicalBinding, DriverNotReady, ProjectionDomain }
static mut HOSTED_DEVICE_DISPATCH_CONTEXTS: Option<ContextTable> = None;
static mut BINDINGS: Option<Vec<HostedDeviceBinding>> = None;
fn instance_by_driver_id(id: u64) -> Option<(usize,DriverInstance)> { (id==1).then_some((0,instance(0)?)) }
fn instance(index: usize) -> Option<DriverInstance> { (index==0).then_some(DriverInstance { ready:true, domain:Domain(7), exec_shared_va:100 }) }
fn instance_domain_identity(inst: DriverInstance) -> Option<Domain> { Some(inst.domain) }
fn hosted_device_binding_by_device_id(id: u64) -> Option<HostedDeviceBinding> {
    unsafe { BINDINGS.as_ref()?.iter().copied().find(|binding| binding.device_id==id) }
}
#[derive(Clone, Copy)] struct PumpChannel { shared_va: u64 }
mod nt_dma_manager { pub struct Nt5DeviceDescription; impl Nt5DeviceDescription {
    pub fn from_service_words(_: [u64;4]) -> Result<Self,()> { Ok(Self) }
} }
mod nt_status { #[derive(Clone, Copy, Debug)] pub enum NtStatus { INVALID_DEVICE_REQUEST, ACCESS_DENIED }
    impl NtStatus { pub fn raw(self)->i32 { match self { Self::INVALID_DEVICE_REQUEST => -2, Self::ACCESS_DENIED => -3 } } }
}
const STATUS_SUCCESS:i32=0; const STATUS_INVALID_PARAMETER:i32=-1;
const STATUS_INVALID_DEVICE_REQUEST:i32=-2; const STATUS_ACCESS_DENIED:i32=-3;
fn authenticated_hosted_pdo(ch:&PumpChannel, pdo:u64, reply:u64) -> Result<(usize,DriverInstance,DeviceId),nt_status::NtStatus> {
    if ch.shared_va==0 || reply!=8 { return Err(nt_status::NtStatus::ACCESS_DENIED); }
    Ok((0,instance(0).unwrap(),DeviceId(match pdo {11=>10,22=>20,_=>0})))
}
fn hosted_dma_owner(binding: HostedDeviceBinding) -> u64 { binding.owner }
#[derive(Clone, Copy)] struct HostedDmaAdapterLease { lease_id:u64, adapter_id:u64, owner:u64, consumer_domain:Domain,
    pdo_registration:Registration, pdo_generation:u64, grant:Option<(u64,u64,u64)> }
#[derive(Clone, Copy, Debug)] struct HostedPnpPciResourceDescriptor { dma_frame_base:u64, dma_pages:u64,
    dma_seed_va:u64, dma_va:u64, dma_len:u64, dma_logical:u64 }
struct State { pnp_context_lease:Option<u64>, interface_type:u32, dma_frame_base:u64,
    address:u32, bus_number:u32, dma_pages:u64, dma_broker_va:u64 }
const HOSTED_INTERFACE_TYPE_PCIBUS:u32=5;
static mut LEASES:Option<Vec<HostedDmaAdapterLease>>=None;
unsafe fn hosted_dma_adapter_leases_mut() -> &'static mut Vec<HostedDmaAdapterLease> { LEASES.as_mut().unwrap() }
unsafe fn hosted_dma_owner_is_quarantined(_:u64)->bool { false }
struct IoManager;
impl IoManager { fn hosted_device_pointer_registration(&self,domain:Domain,address:u64)->Option<Registration> {
    (domain==Domain(7) && address==11).then_some(Registration {domain,address,device_id:DeviceId(10)})
} }
static mut IO:IoManager=IoManager;
unsafe fn io_manager_mut()->&'static mut IoManager { &mut IO }
unsafe fn hosted_dma_pdo_generation_is_live(pdo:u64,generation:u64)->bool { pdo==10 && generation==1 }
unsafe fn hosted_device_bindings()->Option<&'static Vec<HostedDeviceBinding>> { BINDINGS.as_ref() }
unsafe fn hosted_device_resource_state_by_device_id(id:u64)->Option<State> {
    (id==1).then_some(State {pnp_context_lease:Some(9),interface_type:5,dma_frame_base:0x4000,
        address:0,bus_number:0,dma_pages:2,dma_broker_va:0x5000})
}
fn request_hosted_pnp_pci_dma_window(_:u64,_:u8,_:u8,_:u8)
    -> Result<HostedPnpPciResourceDescriptor,nt_status::NtStatus> {
    Ok(HostedPnpPciResourceDescriptor {dma_frame_base:0x4000,dma_pages:2,dma_seed_va:0x5000,
        dma_va:0x1000,dma_len:0x2000,dma_logical:0x3000})
}
"#;

const CASES: &str = r#"
fn binding(device_id:u64,pdo_device_id:u64,pdo_object:u64,owner:u64)->HostedDeviceBinding {
    HostedDeviceBinding {used:true,instance:0,projection_instance:0,projection_domain:Domain(7),
        driver_id:1,device_id,pdo_device_id,pdo_object,owner}
}
fn setup() {
    unsafe {
        let a=binding(1,10,11,101); let b=binding(2,20,22,202);
        BINDINGS=Some(vec![a,b]);
        HOSTED_DEVICE_DISPATCH_CONTEXTS=Some(ContextTable { rows:vec![
            Context {projection_shared_va:Some(200),instance:0,binding:a},
            Context {projection_shared_va:Some(300),instance:0,binding:b},
        ] });
        LEASES=Some(vec![HostedDmaAdapterLease {lease_id:55,adapter_id:44,owner:101,
            consumer_domain:Domain(7),pdo_registration:Registration {domain:Domain(7),address:11,
            device_id:DeviceId(10)},pdo_generation:1,grant:Some((0x1000,0x2000,0x3000))}]);
    }
}
#[test] fn exact_older_worker_request_wins_over_newer_sibling() {
    setup();
    assert_eq!(request(&PumpChannel {shared_va:200},11,[0;4],8), (STATUS_SUCCESS,1,101,0));
    assert_eq!(request(&PumpChannel {shared_va:300},22,[0;4],8), (STATUS_SUCCESS,2,202,0));
    assert_ne!(request(&PumpChannel {shared_va:300},11,[0;4],8).0, STATUS_SUCCESS);
    assert_ne!(request(&PumpChannel {shared_va:301},11,[0;4],8).0, STATUS_SUCCESS);
}
#[test] fn authenticated_worker_can_free_exact_lease_but_not_stale_or_wrong_owner() {
    setup();
    unsafe {
        assert!(authenticated_hosted_dma_free_lease(0,Domain(7),55,44).is_ok(),
            "worker bank must be admitted for an exact live lease");
        LEASES.as_mut().unwrap()[0].pdo_generation=2;
        assert!(authenticated_hosted_dma_free_lease(0,Domain(7),55,44).is_err());
        LEASES.as_mut().unwrap()[0].pdo_generation=1;
        BINDINGS.as_mut().unwrap()[0].owner=999;
        assert!(authenticated_hosted_dma_free_lease(0,Domain(7),55,44).is_err());
    }
}
"#;
