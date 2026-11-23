//! Compile the production pending port-cap ledger against exact owner and recovery transitions.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn section(start: &str, end: &str) -> &'static str {
    let from = SOURCE.find(start).expect("production start marker");
    let tail = &SOURCE[from..];
    &tail[..tail.find(end).expect("production end marker")]
}

#[test]
fn pending_port_effect_keeps_exact_authority_until_quiesced_reconciliation() {
    let record = section(
        "#[derive(Clone, Copy, Eq, PartialEq)]\nenum HostedIoPortNativeStep {",
        "\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\nstruct HostedIrqConnection {",
    );
    let ledger = section(
        "unsafe fn hosted_io_port_cap_effects_mut(",
        "\nunsafe fn issue_hosted_io_port_cap(",
    );
    let retirement = section(
        "unsafe fn retire_hosted_io_port_cap(",
        "\nunsafe fn revoke_hosted_device_resource_state(",
    );
    let fixture = format!("{SUPPORT}\n{record}\n{ledger}\n{retirement}\n{CASES}");
    let directory =
        std::env::temp_dir().join(format!("nt-port-effect-ledger-{}", std::process::id()));
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
        "pending port ledger compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "pending port ledger regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
#![allow(static_mut_refs)]
const CT_IO_PORT_BASE:u64=8;
const CT_IO_PORT_CAPACITY:u64=16;
const SH_RESOURCE_ADDRESS_KIND_PORT:u8=2;
#[derive(Clone,Copy,PartialEq,Eq,Debug)] struct HostedDeviceBinding {
 driver_id:u64,device_id:u64,pdo_device_id:u64,instance:usize,projection_instance:usize,
 projection_domain:u64,device_object:u64,pdo_object:u64,registry_identity_id:u64,used:bool
}
#[derive(Clone,Copy,Default)] struct SharedAddressResource { kind:u8,translated_start:u64,len:u64,broker_va_or_root_cap:u64,component_cap:u64 }
#[derive(Clone,Copy)] struct HostedDeviceResourceState {device_id:u64,projection_domain:u64,
 address_resource_count:u8,address_resources:[SharedAddressResource;4],io_port_supplemental:bool}
mod nt_status { #[derive(Debug)] pub enum NtStatus { INVALID_PARAMETER,INVALID_DEVICE_REQUEST,
    INSUFFICIENT_RESOURCES,DEVICE_BUSY,UNSUCCESSFUL } }
static mut HOSTED_IO_PORT_CAP_EFFECTS:Option<Vec<HostedIoPortCapEffect>>=None;
static mut STATES:Vec<HostedDeviceResourceState>=Vec::new();
static mut FAIL_REVOKE:bool=false;
static mut FAIL_DELETE:bool=false;
static mut REVOKES:u64=0;
static mut DELETES:u64=0;
static mut RELEASES:u64=0;
fn hosted_state_address_resources(state:&HostedDeviceResourceState)->&[SharedAddressResource] {
 &state.address_resources[..state.address_resource_count as usize]
}
fn cnode_revoke_r(_:u64)->u64 {unsafe{REVOKES+=1; FAIL_REVOKE as u64}}
fn cnode_delete_recycle_r(_:u64)->u64 {unsafe{DELETES+=1; FAIL_DELETE as u64}}
fn hosted_device_resource_states_mut()->&'static mut Vec<HostedDeviceResourceState>{unsafe{&mut STATES}}
fn hosted_resource_owner(_:HostedDeviceBinding)->u64{7}
struct Manager;
impl Manager {fn release_port(&mut self,_:u64,_:u64)->Result<(),()> {unsafe{RELEASES+=1;} Ok(())}}
static mut MANAGER:Manager=Manager;
fn hosted_resource_manager_mut()->&'static mut Manager{unsafe{&mut MANAGER}}
fn hosted_hal_status(_:())->nt_status::NtStatus{nt_status::NtStatus::UNSUCCESSFUL}
"#;

const CASES: &str = r#"
fn owner(generation:u64,used:bool)->HostedDeviceBinding { HostedDeviceBinding {
 driver_id:7,device_id:1,pdo_device_id:2,instance:0,projection_instance:0,
 projection_domain:generation,device_object:10,pdo_object:11,registry_identity_id:12,used
} }
fn effect(binding:HostedDeviceBinding,cnode:u64,cap:u64,start:u64)->HostedIoPortCapEffect {
 HostedIoPortCapEffect {binding,cnode,component_slot:8,root_cap:cap,start,length:2,
 claim_resource_id:Some(44),root_revoke:HostedIoPortNativeStep::Pending,
 root_retire:HostedIoPortNativeStep::Pending,claim_released:false}
}
fn reset() {unsafe{HOSTED_IO_PORT_CAP_EFFECTS=None;STATES.clear();FAIL_REVOKE=false;
 FAIL_DELETE=false;REVOKES=0;DELETES=0;RELEASES=0;}}
#[test]
fn mutable_publication_flag_does_not_change_exact_owner_but_generation_does() {
 reset(); let old=owner(55,true); let retired=owner(55,false); let next=owner(56,true);
 unsafe {retain_hosted_io_port_cap_effect(effect(old,2,90,0x3c0)).unwrap();}
 assert!(unsafe{hosted_io_port_cap_effect_pending(retired,3)},"used flag cannot lose retained owner");
 assert!(unsafe{hosted_io_port_cap_effect_mut(next,90)}.is_none(),"new generation cannot own old root cap");
 assert!(unsafe{retain_hosted_io_port_cap_effect(effect(next,3,91,0x3c0))}.is_err(),
    "pending physical range cannot be reused by another generation");
 assert!(unsafe{retain_hosted_io_port_cap_effect(effect(next,2,91,0x2f8))}.is_err(),
    "pending CNode slot cannot be reused by another generation");
}
#[test]
fn uncertain_revoke_is_quarantined_without_native_replay() {
 reset(); let binding=owner(55,true);
 unsafe {retain_hosted_io_port_cap_effect(effect(binding,2,90,0x3c0)).unwrap();
  let mut resources=[SharedAddressResource::default();4];
  resources[0]=SharedAddressResource{kind:SH_RESOURCE_ADDRESS_KIND_PORT,
    translated_start:0x3c0,len:2,broker_va_or_root_cap:90,component_cap:8};
  STATES.push(HostedDeviceResourceState{device_id:1,projection_domain:55,
   address_resource_count:1,address_resources:resources,io_port_supplemental:true});
  FAIL_REVOKE=true;
  assert!(reconcile_hosted_io_port_cap_effects(owner(55,false)).is_err());
  assert_eq!((REVOKES,DELETES,RELEASES),(1,0,0));
  assert!(hosted_io_port_cap_effect_pending(binding,2));
  FAIL_REVOKE=false;
  assert!(reconcile_hosted_io_port_cap_effects(owner(55,false)).is_err());
  assert_eq!((REVOKES,DELETES,RELEASES),(1,0,0),
    "a failed native revoke cannot be replayed or release the claim");
  assert!(hosted_io_port_cap_effect_pending(binding,2));
  assert_eq!(STATES[0].address_resources[0].broker_va_or_root_cap,90);
 }
}
#[test]
fn uncertain_delete_is_quarantined_after_acknowledged_revoke() {
 reset(); let binding=owner(55,true);
 unsafe {retain_hosted_io_port_cap_effect(effect(binding,2,90,0x3c0)).unwrap();
  FAIL_DELETE=true;
  assert!(reconcile_hosted_io_port_cap_effects(owner(55,false)).is_err());
  assert_eq!((REVOKES,DELETES,RELEASES),(1,1,0));
  FAIL_DELETE=false;
  assert!(reconcile_hosted_io_port_cap_effects(owner(55,false)).is_err());
  assert_eq!((REVOKES,DELETES,RELEASES),(1,1,0),
    "a failed native delete cannot be replayed or recycle a root slot");
  assert!(hosted_io_port_cap_effect_pending(binding,2));
 }
}
#[test]
fn acknowledged_reconciliation_retires_each_effect_once() {
 reset(); let binding=owner(55,true);
 unsafe {retain_hosted_io_port_cap_effect(effect(binding,2,90,0x3c0)).unwrap();
  let mut resources=[SharedAddressResource::default();4];
  resources[0]=SharedAddressResource{kind:SH_RESOURCE_ADDRESS_KIND_PORT,
    translated_start:0x3c0,len:2,broker_va_or_root_cap:90,component_cap:8};
  STATES.push(HostedDeviceResourceState{device_id:1,projection_domain:55,
    address_resource_count:1,address_resources:resources,io_port_supplemental:true});
  reconcile_hosted_io_port_cap_effects(owner(55,false)).unwrap();
  reconcile_hosted_io_port_cap_effects(owner(55,false)).unwrap();
  assert_eq!((REVOKES,DELETES,RELEASES),(1,1,1));
  assert!(!hosted_io_port_cap_effect_pending(binding,2));
  assert_eq!(STATES[0].address_resource_count,0,
    "a retired supplemental cap must remove its canonical resource row");
  assert!(!STATES[0].io_port_supplemental,
    "a retired supplemental range cannot remain advertised on a teardown retry");
  assert_eq!(STATES[0].address_resources[0].broker_va_or_root_cap,0);
 }
}
#[test]
fn canonical_retirement_never_replays_failed_native_revoke() {
 reset(); let binding=owner(55,true);
 unsafe {let mut resources=[SharedAddressResource::default();4];
  resources[0]=SharedAddressResource{kind:SH_RESOURCE_ADDRESS_KIND_PORT,
    translated_start:0x3c0,len:2,broker_va_or_root_cap:90,component_cap:8};
  STATES.push(HostedDeviceResourceState{device_id:1,projection_domain:55,
    address_resource_count:1,address_resources:resources,io_port_supplemental:false});
  FAIL_REVOKE=true;
  assert!(retire_hosted_device_port_caps(binding).is_err());
  assert_eq!((REVOKES,DELETES),(1,0));
  FAIL_REVOKE=false;
  assert!(retire_hosted_device_port_caps(binding).is_err());
  assert_eq!((REVOKES,DELETES),(1,0),
    "canonical retirement cannot replay uncertain revoke or recycle its root slot");
 }
}
#[test]
fn canonical_retirement_never_replays_failed_native_delete() {
 reset(); let binding=owner(55,true);
 unsafe {let mut resources=[SharedAddressResource::default();4];
  resources[0]=SharedAddressResource{kind:SH_RESOURCE_ADDRESS_KIND_PORT,
    translated_start:0x3c0,len:2,broker_va_or_root_cap:90,component_cap:8};
  STATES.push(HostedDeviceResourceState{device_id:1,projection_domain:55,
    address_resource_count:1,address_resources:resources,io_port_supplemental:false});
  FAIL_DELETE=true;
  assert!(retire_hosted_device_port_caps(binding).is_err());
  assert_eq!((REVOKES,DELETES),(1,1));
  FAIL_DELETE=false;
  assert!(retire_hosted_device_port_caps(binding).is_err());
  assert_eq!((REVOKES,DELETES),(1,1),
    "canonical retirement cannot replay uncertain delete or recycle its root slot");
 }
}
"#;
