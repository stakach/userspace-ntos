//! Execute the native PCI resource eligibility predicate against BAR-less and assigned devices.

use std::process::Command;

#[test]
fn selected_barless_bridge_does_not_require_a_hosted_resource_window() {
    let source = include_str!("../../../components/ntos-executive/src/main.rs");
    let start = source
        .find("fn hosted_pci_resource_bar_eligible(")
        .expect("native PCI BAR eligibility predicate");
    let end = source[start..]
        .find("\nunsafe fn claim_hosted_pci_memory_grants(")
        .expect("next native function");
    let function = &source[start..start + end];
    syn::parse_str::<syn::ItemFn>(function).expect("complete native predicate");
    let harness = format!("{PORTS}\n{function}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-source-pci-bar-eligibility-{}",
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
        "native PCI eligibility fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native PCI eligibility regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
mod nt_pnp {
    pub struct Bar { pub base: u64, pub is_io: bool }
    pub struct PciDevice { pub bars: Vec<Bar> }
    impl PciDevice {
        pub fn first_memory_bar(&self) -> Option<&Bar> {
            self.bars.iter().find(|bar| !bar.is_io && bar.base != 0)
        }
        pub fn first_io_bar(&self) -> Option<&Bar> {
            self.bars.iter().find(|bar| bar.is_io && bar.base != 0)
        }
    }
}
"#;

const CASES: &str = r#"
#[test]
fn no_bar_or_only_unassigned_bars_are_ineligible() {
    assert!(!hosted_pci_resource_bar_eligible(&nt_pnp::PciDevice { bars: vec![] }));
    assert!(!hosted_pci_resource_bar_eligible(&nt_pnp::PciDevice {
        bars: vec![nt_pnp::Bar { base: 0, is_io: false }],
    }));
}
#[test]
fn assigned_mmio_or_port_bar_requires_a_window() {
    for is_io in [false, true] {
        assert!(hosted_pci_resource_bar_eligible(&nt_pnp::PciDevice {
            bars: vec![nt_pnp::Bar { base: 0x8104_0000, is_io }],
        }));
    }
}
"#;
