//! Compile the physical CNode selector used before a hosted supplemental port claim.

use std::process::Command;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[test]
fn port_claim_cnode_requires_exact_physical_lane_and_reply() {
    let start = SOURCE
        .find("fn physical_cnode_for_pump_channel(")
        .expect("production CNode selector");
    let tail = &SOURCE[start..];
    let end = tail
        .find("\n/// A fatal autonomous service")
        .expect("production selector end");
    let fixture = format!("{SUPPORT}\n{}\n{CASES}", &tail[..end]);
    let directory = std::env::temp_dir().join(format!("nt-port-cnode-auth-{}", std::process::id()));
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
        "physical CNode fixture compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary)
        .arg("--test-threads=1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "physical CNode regression:\n{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const SUPPORT: &str = r#"
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct Domain(u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct Route(u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)] struct Source {
    tcb:u64, pml4:u64, domain:spawn_hosts::shared_ingress::owner::runtime::PhysicalDomain,
}
mod spawn_hosts {
    pub struct PumpChannel {pub ingress_route:Option<super::Route>,pub tcb:u64,
        pub pml4:u64,pub physical_domain:Option<super::Domain>}
    pub mod shared_ingress {pub mod owner {pub mod runtime {
        use crate::{Domain,Route,Source};
        #[derive(Clone,Copy,Debug,Eq,PartialEq)] pub enum PhysicalDomain {Hosted(Domain)}
        pub fn channel_route(ch:&crate::spawn_hosts::PumpChannel)->Result<Option<Route>,()> {
            Ok(ch.ingress_route)
        }
        pub fn physical_source(_:Route)->Result<Source,()> {unsafe {Ok(crate::PHYSICAL)}}
        pub fn current_reply(_:Route)->Result<u64,()> {unsafe {Ok(crate::REPLY)}}
    }}}
}
mod hosted_ingress_sources {
    use crate::{Route,Source};
    #[derive(Clone,Copy,Debug,Eq,PartialEq)] pub enum EnrollmentPhase {Published,Retired}
    #[derive(Clone,Copy)] pub struct Enrollment {pub route:Option<Route>,pub phase:EnrollmentPhase,pub cnode:u64}
    pub unsafe fn verify(_:Source)->bool {crate::VERIFIED}
    pub fn enrollment(_:Source)->Option<Enrollment> {unsafe {Some(crate::ENROLLMENT)}}
}
static mut PHYSICAL: Source=Source {tcb:7,pml4:8,
    domain:spawn_hosts::shared_ingress::owner::runtime::PhysicalDomain::Hosted(Domain(1))};
static mut REPLY:u64=10;
static mut VERIFIED:bool=true;
static mut ENROLLMENT:hosted_ingress_sources::Enrollment=hosted_ingress_sources::Enrollment {
    route:Some(Route(9)),phase:hosted_ingress_sources::EnrollmentPhase::Published,cnode:2};
"#;

const CASES: &str = r#"
#[test]
fn exact_route_tcb_domain_reply_and_enrollment_select_only_its_cnode() {
    let mut ch=spawn_hosts::PumpChannel {ingress_route:Some(Route(9)),tcb:7,pml4:8,
        physical_domain:Some(Domain(1))};
    unsafe {
        assert_eq!(physical_cnode_for_pump_channel(&ch,10),Some(2));
        ch.tcb=77;
        assert_eq!(physical_cnode_for_pump_channel(&ch,10),None);
        ch.tcb=7;
        ch.pml4=88;
        assert_eq!(physical_cnode_for_pump_channel(&ch,10),None);
        ch.pml4=8;
        ch.physical_domain=Some(Domain(2));
        assert_eq!(physical_cnode_for_pump_channel(&ch,10),None);
        ch.physical_domain=Some(Domain(1));
        assert_eq!(physical_cnode_for_pump_channel(&ch,11),None);
        ch.ingress_route=Some(Route(11));
        assert_eq!(physical_cnode_for_pump_channel(&ch,10),None);
        ch.ingress_route=Some(Route(9));
        VERIFIED=false;
        assert_eq!(physical_cnode_for_pump_channel(&ch,10),None);
        VERIFIED=true;
        ENROLLMENT.phase=hosted_ingress_sources::EnrollmentPhase::Retired;
        assert_eq!(physical_cnode_for_pump_channel(&ch,10),None);
        ENROLLMENT.phase=hosted_ingress_sources::EnrollmentPhase::Published;
        ENROLLMENT.cnode=0;
        assert_eq!(physical_cnode_for_pump_channel(&ch,10),None);
    }
}
"#;
