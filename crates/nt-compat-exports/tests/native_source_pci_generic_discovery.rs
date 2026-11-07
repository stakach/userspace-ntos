//! Exercise native PCI grant discovery before any launch plan or critical binding exists.

use std::process::Command;

#[test]
fn bar_bearing_functions_are_discovered_without_prior_driver_binding() {
    let source = include_str!("../../../components/ntos-executive/src/main.rs");
    let selection = extract(source, "unsafe fn hosted_pci_selected_for_context(", "\nfn hosted_pci_selected_from_launch_plans(");
    let eligibility = extract(source, "fn hosted_pci_resource_bar_eligible(", "\nunsafe fn claim_hosted_pci_memory_grants(");
    let discovery = extract(source, "unsafe fn discover_hosted_pci_hardware_grants_for_launch_plans(", "\n#[derive(Default)]\nstruct HostedPciWindowPublishReport");
    for function in [selection, eligibility, discovery] {
        syn::parse_str::<syn::ItemFn>(function).expect("complete native PCI function");
    }
    let harness = format!("{PORTS}\n{selection}\n{eligibility}\n{discovery}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-source-pci-generic-discovery-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native PCI discovery fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native PCI discovery regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

fn extract<'a>(source: &'a str, start: &str, next: &str) -> &'a str {
    let offset = source.find(start).expect("native PCI function");
    let end = source[offset..].find(next).expect("next native item");
    &source[offset..offset + end]
}

const PORTS: &str = r#"
extern crate alloc;
mod nt_pnp {
    #[derive(Clone)]
    pub struct Bar { pub base: u64, pub is_io: bool }
    #[derive(Clone)]
    pub struct PciDevice {
        pub bus: u8, pub dev: u8, pub func: u8,
        pub vendor: u16, pub device: u16, pub class: u32,
        pub bars: Vec<Bar>,
    }
    impl PciDevice {
        pub fn first_memory_bar(&self) -> Option<&Bar> {
            self.bars.iter().find(|bar| !bar.is_io && bar.base != 0)
        }
        pub fn first_io_bar(&self) -> Option<&Bar> {
            self.bars.iter().find(|bar| bar.is_io && bar.base != 0)
        }
    }
}
struct InlineDriverLaunchPlan;
struct CriticalBinding { service_name: Option<&'static str> }
fn hosted_pci_selected_from_launch_plans(
    _: &nt_pnp::PciDevice, _: &[nt_pnp::PciDevice], _: &[&InlineDriverLaunchPlan],
) -> bool { false }
fn config_manager_query_critical_device_binding(_: &str) -> Result<Option<CriticalBinding>, ()> {
    Ok(None)
}
struct BootInfo;
struct HostedPciBarClaimAuthority;
#[derive(Clone, Copy)]
struct BootStorageBarClaim;
struct HostedPciHardwareGrant { bus: u8, dev: u8, func: u8 }
impl HostedPciHardwareGrant {
    fn for_device(device: &nt_pnp::PciDevice, _: Vec<()>) -> Option<Self> {
        Some(Self { bus: device.bus, dev: device.dev, func: device.func })
    }
    fn matches(&self, device: &nt_pnp::PciDevice) -> bool {
        (self.bus, self.dev, self.func) == (device.bus, device.dev, device.func)
    }
}
#[derive(Default)]
struct HostedPciGrantDiscoveryReport {
    selected_devnodes: u64, existing_grants: u64, claimed_grants: u64,
    barless_devnodes: u64, claim_failures: u64,
}
unsafe fn claim_hosted_pci_memory_grants(
    _: &BootInfo, _: &mut HostedPciBarClaimAuthority,
    _: &nt_pnp::PciDevice, _: Option<BootStorageBarClaim>,
) -> Option<Vec<()>> { Some(vec![()]) }
"#;

const CASES: &str = r#"
fn device(bus: u8, dev: u8, bar_base: u64) -> nt_pnp::PciDevice {
    nt_pnp::PciDevice {
        bus, dev, func: 0, vendor: 0x1234, device: 0x5678, class: 0x010601,
        bars: if bar_base == 0 { vec![] } else {
            vec![nt_pnp::Bar { base: bar_base, is_io: false }]
        },
    }
}
#[test]
fn same_id_different_bdf_functions_receive_distinct_generic_grants() {
    let devices = [device(0, 1, 0x8100_0000), device(0, 2, 0x8200_0000), device(0, 3, 0)];
    let mut grants = Vec::new();
    let mut authority = HostedPciBarClaimAuthority;
    let report = unsafe {
        discover_hosted_pci_hardware_grants_for_launch_plans(
            &BootInfo, &mut authority, &devices, &[], None, &mut grants,
        )
    };
    assert_eq!(report.claimed_grants, 2);
    assert_eq!(report.claim_failures, 0);
    assert_eq!(grants.len(), 2);
    assert!(grants.iter().any(|grant| grant.matches(&devices[0])));
    assert!(grants.iter().any(|grant| grant.matches(&devices[1])));
    assert!(!grants.iter().any(|grant| grant.matches(&devices[2])));
}
"#;
