//! Exercise the executive's actual PCI BAR cap selection with recorded retype attempts.

use std::process::Command;

#[test]
fn boot_storage_bar_cap_is_reused_only_for_its_exact_pci_bar() {
    let source = include_str!("../../../components/ntos-executive/src/main.rs");
    let start = source
        .find("unsafe fn claim_hosted_pci_memory_grants(")
        .expect("native PCI grant selector");
    let end = source[start..]
        .find("\nunsafe fn discover_hosted_pci_hardware_grants_for_launch_plans(")
        .expect("next native function");
    let function = &source[start..start + end];
    syn::parse_str::<syn::ItemFn>(function).expect("complete native PCI grant selector");
    let harness = format!("{PORTS}\n{function}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-source-pci-bar-claim-{}",
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
        "native selector fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native PCI grant regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use std::cell::Cell;
thread_local! { static RETYPES: Cell<usize> = const { Cell::new(0) }; }
struct BootInfo;
#[derive(Clone, Copy)]
struct DeviceFrameCapRun { base: u64, pages: u64 }
#[derive(Clone, Copy)]
struct BootStorageBarClaim {
    bus: u8, dev: u8, func: u8, bar_index: u8, phys: u64, run: DeviceFrameCapRun,
}
struct HostedPciMemoryGrant {
    bar_index: u8, phys: u64, len: u64, frame_base: u64, pages: u64,
}
mod nt_pnp {
    pub struct Bar { pub index: u8, pub base: u64, pub size: u64, pub is_io: bool }
    impl Bar { pub fn is_present(&self) -> bool { self.size != 0 } }
    pub struct PciDevice { pub bus: u8, pub dev: u8, pub func: u8, pub bars: Vec<Bar> }
}
fn existing_boot_framebuffer_bar_cap_run(_: u64, _: u64) -> Option<DeviceFrameCapRun> { None }
unsafe fn claim_device_frame_caps(_: &BootInfo, _: u64, pages: u64) -> Option<DeviceFrameCapRun> {
    RETYPES.with(|count| count.set(count.get() + 1));
    Some(DeviceFrameCapRun { base: 99, pages })
}
fn device(bus: u8, base: u64) -> nt_pnp::PciDevice {
    nt_pnp::PciDevice {
        bus, dev: 2, func: 0,
        bars: vec![nt_pnp::Bar { index: 5, base, size: 0x1000, is_io: false }],
    }
}
fn storage_claim() -> BootStorageBarClaim {
    BootStorageBarClaim {
        bus: 0, dev: 2, func: 0, bar_index: 5, phys: 0x8106_1000,
        run: DeviceFrameCapRun { base: 77, pages: 1 },
    }
}
fn retypes() -> usize { RETYPES.with(Cell::get) }
fn reset() { RETYPES.with(|count| count.set(0)); }
"#;

const CASES: &str = r#"
#[test]
fn exact_boot_storage_bar_reuses_cap_without_retype() {
    reset();
    let grants = unsafe {
        claim_hosted_pci_memory_grants(&BootInfo, &device(0, 0x8106_1000), Some(storage_claim()))
    }.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].frame_base, 77);
    assert_eq!(grants[0].pages, 1);
    assert_eq!(retypes(), 0);
}
#[test]
fn different_device_or_bar_cannot_borrow_storage_cap() {
    reset();
    assert!(unsafe {
        claim_hosted_pci_memory_grants(&BootInfo, &device(1, 0x8106_1000), Some(storage_claim()))
    }.is_none());
    assert_eq!(retypes(), 0);
    reset();
    let grants = unsafe {
        claim_hosted_pci_memory_grants(&BootInfo, &device(0, 0x8106_2000), Some(storage_claim()))
    }.unwrap();
    assert_eq!(grants[0].frame_base, 99);
    assert_eq!(retypes(), 1);
}
#[test]
fn incomplete_existing_claim_fails_closed_without_second_retype() {
    reset();
    let mut claim = storage_claim();
    claim.run.pages = 0;
    assert!(unsafe {
        claim_hosted_pci_memory_grants(&BootInfo, &device(0, 0x8106_1000), Some(claim))
    }.is_none());
    assert_eq!(retypes(), 0);
}
"#;
