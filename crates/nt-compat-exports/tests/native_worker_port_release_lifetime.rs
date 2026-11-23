//! Compile the production supplemental release branch against a failed child-cap deletion.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn failed_child_delete_keeps_the_port_claim_and_canonical_cap() {
    let from = SOURCE
        .find("unsafe fn claim_hosted_supplemental_port_range(")
        .expect("production claim");
    let tail = &SOURCE[from..];
    let production = &tail[..tail
        .find("\nmod hosted_port_projection;")
        .expect("claim end")];
    let fixture = format!("{SUPPORT}\n{production}\n{CASES}");
    let directory =
        std::env::temp_dir().join(format!("nt-worker-port-release-{}", std::process::id()));
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
        "worker port release fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "worker port release regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
#![allow(static_mut_refs)]
const SH_RESOURCE_ADDRESS_KIND_PORT: u8 = 2;
const SH_RESOURCE_ADDRESS_RECORD_CAPACITY: u64 = 4;
const CT_IO_PORT_BASE: u64 = 8;
const CT_IO_PORT_CAPACITY: u64 = 16;
#[derive(Clone, Copy, PartialEq)] struct HostedDeviceBinding { device_id:u64, driver_id:u64, instance:usize,
    pdo_object:u64, projection_domain:u64 }
#[derive(Clone, Copy, Eq, PartialEq)] enum HostedIoPortNativeStep { Pending, Acknowledged, Uncertain }
#[derive(Clone, Copy)] struct HostedIoPortCapEffect { binding:HostedDeviceBinding,cnode:u64,
 component_slot:u64,root_cap:u64,start:u64,length:u64,claim_resource_id:Option<u64>,
 root_revoke:HostedIoPortNativeStep,root_retire:HostedIoPortNativeStep,claim_released:bool }
#[derive(Clone, Copy, Default)] struct SharedAddressResource { kind:u8, resource_index:u8, share:u8,
    raw_start:u64, translated_start:u64, len:u64, broker_va_or_root_cap:u64, component_cap:u64 }
#[derive(Clone, Copy, Default)] struct Evidence { resource_io_port_len:u64,
    resource_io_port_cap:u64, resource_io_port_component_cap:u64 }
#[derive(Clone, Copy, Default)] struct HostedDeviceResourceState { device_id:u64,driver_id:u64,
    instance:usize,pdo_object:u64,projection_domain:u64,address_resources:[SharedAddressResource;4],
    address_resource_count:u8,io_port_supplemental:bool,evidence:Evidence }
mod nt_status { #[derive(Debug)] pub enum NtStatus { INVALID_DEVICE_REQUEST, ACCESS_DENIED,
    INVALID_PARAMETER, CONFLICTING_ADDRESSES, INSUFFICIENT_RESOURCES, DEVICE_BUSY, UNSUCCESSFUL } }
mod nt_cm_resources { pub const CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE:u8=1; }
static mut STATES: Option<Vec<HostedDeviceResourceState>> = None;
static mut FAIL_DELETE:bool=false;
static mut FAIL_REVOKE:bool=false;
static mut ROOT_REVOKES:u64=0;
static mut ROOT_DELETES:u64=0;
static mut CLAIM_RELEASES:u64=0;
static mut PROJECTIONS:u64=0;
static mut EFFECT:Option<HostedIoPortCapEffect>=None;
fn hosted_io_port_cap_effect_pending(_:HostedDeviceBinding,_:u64)->bool { unsafe { EFFECT.is_some() } }
fn retain_hosted_io_port_cap_effect(effect:HostedIoPortCapEffect)->Result<(),nt_status::NtStatus> {
    unsafe { assert!(EFFECT.is_none()); EFFECT=Some(effect); } Ok(())
}
fn hosted_io_port_cap_effect_mut(_:HostedDeviceBinding,cap:u64)->Option<&'static mut HostedIoPortCapEffect> {
    unsafe { let effect=EFFECT.as_mut()?; (effect.root_cap==cap).then_some(effect) }
}
fn settle_hosted_io_port_cap_effect(_:HostedDeviceBinding,_:u64) { unsafe { EFFECT=None; } }
fn hosted_device_resource_state_by_device_id(device_id:u64)->Option<HostedDeviceResourceState> {
    unsafe { STATES.as_ref()?.iter().find(|row|row.device_id==device_id).copied() }
}
fn hosted_device_resource_states_mut()->&'static mut Vec<HostedDeviceResourceState> {
    unsafe { STATES.as_mut().unwrap() }
}
fn hosted_state_address_resources(state:&HostedDeviceResourceState)->&[SharedAddressResource] {
    &state.address_resources[..state.address_resource_count as usize]
}
fn hosted_state_first_address_resource(state:&HostedDeviceResourceState,kind:u8)->Option<SharedAddressResource> {
    hosted_state_address_resources(state).iter().find(|r|r.kind==kind).copied()
}
fn hosted_supplemental_io_port_resource_id(_:u64)->Option<u64>{Some(44)}
fn hosted_resource_owner(_:HostedDeviceBinding)->u64{7}
struct Manager;
impl Manager {
    fn claim_port(&mut self,_:u64,_:u64,_:u64,_:u64)->Result<(),()> { Ok(()) }
    fn release_port(&mut self,_:u64,_:u64)->Result<(),()> {
        unsafe { CLAIM_RELEASES+=1; } Ok(())
    }
}
static mut MANAGER:Manager=Manager;
fn hosted_resource_manager_mut()->&'static mut Manager { unsafe { &mut MANAGER } }
fn hosted_hal_status(_:())->nt_status::NtStatus { nt_status::NtStatus::INVALID_DEVICE_REQUEST }
fn cnode_delete_in_cnode_r(cnode:u64,slot:u64)->u64 { unsafe {
    let effect=EFFECT.unwrap();
    assert_eq!((effect.cnode,effect.component_slot),(cnode,slot));
    FAIL_DELETE as u64
} }
fn cnode_revoke_r(cap:u64)->u64 { unsafe { assert_eq!(EFFECT.unwrap().root_cap,cap); ROOT_REVOKES+=1; FAIL_REVOKE as u64 } }
fn cnode_delete_recycle_r(cap:u64)->u64 { unsafe { assert_eq!(EFFECT.unwrap().root_cap,cap); ROOT_DELETES+=1; 0 } }
fn copy_hosted_io_port_caps_to_cnode(cnode:u64,_:HostedDeviceResourceState)->Result<(),nt_status::NtStatus>{
    assert_eq!(cnode,2,"release must target worker physical CNode"); Ok(())
}
fn write_hosted_resource_state_projection(_:u64,_:HostedDeviceResourceState,_:bool){unsafe{PROJECTIONS+=1;}}
fn issue_hosted_io_port_cap(_:HostedDeviceBinding,_:u64,_:u64,_:u64,_:u64,_:Option<u64>)
 ->Result<u64,nt_status::NtStatus>{Ok(90)}
"#;

const CASES: &str = r#"
#[test]
fn uncertain_child_delete_blocks_claim_release_and_publication() {
    let mut state=HostedDeviceResourceState {device_id:1,driver_id:7,instance:0,pdo_object:11,projection_domain:55,
        io_port_supplemental:true,..Default::default()};
    state.address_resources[0]=SharedAddressResource {kind:SH_RESOURCE_ADDRESS_KIND_PORT,
        resource_index:u8::MAX,translated_start:0x3c0,len:2,broker_va_or_root_cap:90,
        component_cap:8,..Default::default()};
    state.address_resource_count=1;
    unsafe { STATES=Some(vec![state]); EFFECT=None; FAIL_DELETE=true; FAIL_REVOKE=false;
        ROOT_REVOKES=0; ROOT_DELETES=0; CLAIM_RELEASES=0; PROJECTIONS=0; }
    let binding=HostedDeviceBinding {device_id:1,driver_id:7,instance:0,pdo_object:11,projection_domain:55};
    assert!(unsafe { claim_hosted_supplemental_port_range(binding,2,0,0,0) }.is_err());
    unsafe {
        assert_eq!(ROOT_REVOKES,0,"failed child delete cannot revoke parent cap");
        assert_eq!(ROOT_DELETES,0,"failed child delete cannot delete parent cap");
        assert_eq!(CLAIM_RELEASES,0,"failed child delete cannot release resource claim");
        assert_eq!(PROJECTIONS,0,"failed release cannot publish an empty bank");
        assert_eq!(STATES.as_ref().unwrap()[0].address_resource_count,1);
        assert_eq!(EFFECT.unwrap().root_cap,90,"uncertain child effect stays owned");
        assert!(claim_hosted_supplemental_port_range(binding,2,0,0,0).is_err(),"retry must refuse");
    }
}
#[test]
fn failed_root_revoke_keeps_claim_and_successful_release_projects_once() {
    let mut state=HostedDeviceResourceState {device_id:1,driver_id:7,instance:0,pdo_object:11,projection_domain:55,
        io_port_supplemental:true,..Default::default()};
    state.address_resources[0]=SharedAddressResource {kind:SH_RESOURCE_ADDRESS_KIND_PORT,
        resource_index:u8::MAX,translated_start:0x3c0,len:2,broker_va_or_root_cap:90,
        component_cap:8,..Default::default()};
    state.address_resource_count=1;
    let binding=HostedDeviceBinding {device_id:1,driver_id:7,instance:0,pdo_object:11,projection_domain:55};
    unsafe { STATES=Some(vec![state]); EFFECT=None; FAIL_DELETE=false; FAIL_REVOKE=true;
        ROOT_REVOKES=0; ROOT_DELETES=0; CLAIM_RELEASES=0; PROJECTIONS=0; }
    assert!(unsafe { claim_hosted_supplemental_port_range(binding,2,0,0,0) }.is_err());
    unsafe { assert_eq!(ROOT_REVOKES,1); assert_eq!(ROOT_DELETES,0);
        assert_eq!(CLAIM_RELEASES,0); assert_eq!(PROJECTIONS,0);
        assert_eq!(STATES.as_ref().unwrap()[0].address_resource_count,1);
        assert!(EFFECT.is_some()); }

    unsafe { STATES=Some(vec![state]); EFFECT=None; FAIL_DELETE=false; FAIL_REVOKE=false;
        ROOT_REVOKES=0; ROOT_DELETES=0; CLAIM_RELEASES=0; PROJECTIONS=0; }
    assert!(unsafe { claim_hosted_supplemental_port_range(binding,2,0,0,0) }.is_ok());
    unsafe { assert_eq!(ROOT_REVOKES,1); assert_eq!(ROOT_DELETES,1);
        assert_eq!(CLAIM_RELEASES,1); assert_eq!(PROJECTIONS,1);
        assert_eq!(STATES.as_ref().unwrap()[0].address_resource_count,0);
        assert!(EFFECT.is_none()); }
}
"#;
