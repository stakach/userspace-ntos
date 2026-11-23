//! Compile the production DPC projection to verify private CNode authority is cleared first.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn empty_or_invalid_dpc_resource_clears_the_private_port_cap() {
    let from = SOURCE
        .find("unsafe fn prepare_hosted_dpc_resource_projection(")
        .expect("production DPC projection");
    let tail = &SOURCE[from..];
    let production = &tail[..tail
        .find("\nunsafe fn queue_hosted_driver_dpc(")
        .expect("DPC projection end")];
    let fixture = format!("{SUPPORT}\n{production}\n{CASES}");
    let directory = std::env::temp_dir().join(format!("nt-dpc-port-cap-{}", std::process::id()));
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
        "DPC fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "DPC regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
use core::ptr::{read_volatile, write_volatile};
macro_rules! offsets { ($($name:ident),* $(,)?) => { offsets!(@inner 0; $($name),*); };
    (@inner $number:expr; ) => {};
    (@inner $number:expr; $name:ident $(,$rest:ident)*) => {
        const $name:u64=$number*8; offsets!(@inner ($number+1); $($rest),*);
    };
}
offsets!(SH_RESOURCE_PDO_OBJECT,SH_RESOURCE_MMIO_MAPPED_PHYS,SH_RESOURCE_MMIO_MAPPED_LEN,
 SH_RESOURCE_INTERRUPT_VECTOR,SH_RESOURCE_INTERRUPT_LINE,SH_RESOURCE_INTERRUPT_AFFINITY,
 SH_RESOURCE_INTERRUPT_POLICY,SH_RESOURCE_INTERFACE_TYPE,SH_RESOURCE_BUS_NUMBER,
 SH_RESOURCE_ADDRESS,SH_RESOURCE_PCI_VENDOR_DEVICE,SH_RESOURCE_PCI_CLASS_REV,SH_RESOURCE_PCI_IRQ,
 SH_VIDEO_MEMORY_PHYS,SH_VIDEO_MEMORY_LEN,SH_VIDEO_MEMORY_CALLER_VA,SH_VIDEO_MEMORY_MAPPED_VA,
 SH_RESOURCE_INTERRUPT_OBJECT,SH_RESOURCE_INTERRUPT_ROUTINE,SH_RESOURCE_INTERRUPT_CONTEXT,
 SH_RESOURCE_INTERRUPT_ID,SH_DMA_COMMON_VA,SH_DMA_COMMON_LEN,SH_DMA_COMMON_LOGICAL,
 SH_DMA_ADAPTER_ID,SH_DMA_ADAPTER_BLOB);
const HOSTED_INTERFACE_TYPE_INTERNAL:u32=0;
#[derive(Clone,Copy)] struct HostedDpcResourceIdentity { device_id:u64 }
#[derive(Clone,Copy)] struct HostedDeviceBinding { device_id:u64 }
mod nt_status { #[derive(Debug,PartialEq)] pub enum NtStatus { DEVICE_NOT_CONNECTED, INVALID_DEVICE_REQUEST } }
static mut CNODE_CAPS:[u64;4]=[0;4];
static mut FAIL_CLEAR:bool=false;
static mut RESTORES:u64=0;
unsafe fn clear_shared_address_resources(_:u64) {}
unsafe fn clear_hosted_io_port_caps(cnode:u64)->Result<(),nt_status::NtStatus> {
    if FAIL_CLEAR { return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST); }
    CNODE_CAPS[cnode as usize]=0;
    Ok(())
}
unsafe fn hosted_dpc_binding_for_resource(resource:HostedDpcResourceIdentity,_:usize)->Option<HostedDeviceBinding> {
    (resource.device_id==1).then_some(HostedDeviceBinding {device_id:1})
}
unsafe fn restore_hosted_device_resource_state(binding:HostedDeviceBinding,sh:u64,cnode:u64,_:bool)
    ->Result<(),nt_status::NtStatus> {
    clear_hosted_io_port_caps(cnode)?;
    RESTORES+=1;
    CNODE_CAPS[cnode as usize]=0xA;
    write_volatile((sh+SH_RESOURCE_PDO_OBJECT) as *mut u64,binding.device_id);
    Ok(())
}
"#;

const CASES: &str = r#"
#[test]
fn no_resource_dpc_clears_the_previous_private_cap() {
    let mut bank=[0u64;64];
    unsafe { CNODE_CAPS[2]=0xB; FAIL_CLEAR=false; RESTORES=0; }
    assert!(unsafe { prepare_hosted_dpc_resource_projection(None,0,bank.as_mut_ptr() as u64,2) }.is_ok());
    unsafe { assert_eq!(CNODE_CAPS[2],0,"empty DPC must not inherit prior port cap"); assert_eq!(RESTORES,0); }
}
#[test]
fn invalid_resource_dpc_clears_the_previous_private_cap() {
    let mut bank=[0u64;64];
    unsafe { CNODE_CAPS[2]=0xB; FAIL_CLEAR=false; RESTORES=0; }
    assert_eq!(unsafe { prepare_hosted_dpc_resource_projection(Some(HostedDpcResourceIdentity{device_id:99}),0,bank.as_mut_ptr() as u64,2) },Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED));
    unsafe { assert_eq!(CNODE_CAPS[2],0); assert_eq!(RESTORES,0); }
}
#[test]
fn failed_private_cap_clear_refuses_a_new_resource_projection() {
    let mut bank=[0u64;64];
    unsafe { CNODE_CAPS[2]=0xB; FAIL_CLEAR=true; RESTORES=0; }
    assert_eq!(unsafe { prepare_hosted_dpc_resource_projection(Some(HostedDpcResourceIdentity{device_id:1}),0,bank.as_mut_ptr() as u64,2) },Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST));
    unsafe { assert_eq!(RESTORES,0); FAIL_CLEAR=false; }
}
"#;
