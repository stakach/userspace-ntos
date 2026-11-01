//! Exercise the native PCI BAR cap claim across partial retype and retry.

use std::process::Command;

#[test]
fn pci_bar_claim_records_attempted_caps_before_native_effects() {
    let source = include_str!("../../../components/ntos-executive/src/main.rs");
    let start = source
        .find("unsafe fn claim_hosted_pci_bar_frame_caps(")
        .expect("owned PCI BAR cap claim helper");
    let end = source[start..].find("\n}\n").expect("helper closing brace");
    let function = &source[start..start + end + 2];
    syn::parse_str::<syn::ItemFn>(function).expect("complete native PCI BAR claim helper");
    let grants_start = source
        .find("unsafe fn claim_hosted_pci_memory_grants(")
        .expect("native PCI BAR grant selector");
    let grants_end = source[grants_start..]
        .find("\n}\n")
        .expect("grant selector closing brace");
    let grants = &source[grants_start..grants_start + grants_end + 2];
    syn::parse_str::<syn::ItemFn>(grants).expect("complete native PCI BAR grant selector");
    let harness = format!("{PORTS}\n{function}\n{grants}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-source-pci-cap-lifetime-{}",
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
        "native PCI BAR cap claim fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native PCI BAR cap lifetime regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
use std::cell::RefCell;
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
#[derive(Default)]
struct State {
    next_slot: u64,
    fail_slot: Option<u64>,
    attempted: Vec<u64>,
    retypes: Vec<u64>,
    recycled: Vec<u64>,
}
#[derive(Clone, Copy)]
struct UntypedDesc { is_device: u8, paddr: u64, size_bits: u8 }
#[derive(Clone, Copy)]
struct UntypedRange { start: u64, end: u64 }
struct BootInfo { untyped: UntypedRange, untyped_list: [UntypedDesc; 2] }
impl BootInfo {
    fn new() -> Self { Self {
        untyped: UntypedRange { start: 20, end: 22 },
        untyped_list: [
            UntypedDesc { is_device: 1, paddr: 0x8100_0000, size_bits: 16 },
            UntypedDesc { is_device: 1, paddr: 0x8200_0000, size_bits: 16 },
        ],
    } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
struct Claim {
    bus: u8, dev: u8, func: u8, bar_index: u8, phys: u64,
    untyped: u64, run: DeviceFrameCapRun, complete: bool,
}
#[derive(Default)]
struct HostedPciBarClaimAuthority { claims: Vec<Claim> }
impl HostedPciBarClaimAuthority {
    fn allows_framebuffer_borrow(&self, _: &nt_pnp::PciDevice, _: &nt_pnp::Bar) -> bool { true }
    fn existing(&self, device: &nt_pnp::PciDevice, bar: &nt_pnp::Bar) -> Option<DeviceFrameCapRun> {
        self.claims.iter().find(|c| c.complete && c.bus == device.bus && c.dev == device.dev
            && c.func == device.func && c.bar_index == bar.index && c.phys == bar.base)
            .map(|c| c.run)
    }
    fn has_source_conflict(&self, untyped: u64, _: u64) -> bool {
        self.claims.iter().any(|c| c.untyped == untyped)
    }
    fn reserve(&mut self) -> bool { self.claims.try_reserve(1).is_ok() }
    fn record(&mut self, device: &nt_pnp::PciDevice, bar: &nt_pnp::Bar, untyped: u64, run: DeviceFrameCapRun) {
        self.claims.push(Claim { bus: device.bus, dev: device.dev, func: device.func,
            bar_index: bar.index, phys: bar.base, untyped, run, complete: false });
    }
    fn record_attempt(&mut self, slot: u64) {
        STATE.with_borrow_mut(|state| state.attempted.push(slot));
    }
    fn mark_complete(&mut self, device: &nt_pnp::PciDevice, bar: &nt_pnp::Bar) {
        let claim = self.claims.iter_mut().find(|c| c.bus == device.bus && c.dev == device.dev
            && c.func == device.func && c.bar_index == bar.index && c.phys == bar.base)
            .expect("completed BAR has an ownership record");
        claim.complete = true;
    }
}
const OBJ_X86_4K_PAGE: u64 = 1;
const PAGING_BITS: u64 = 12;
fn try_alloc_slot_run(n: u64) -> Option<u64> {
    STATE.with_borrow_mut(|state| {
        let base = state.next_slot;
        state.next_slot += n;
        Some(base)
    })
}
unsafe fn untyped_retype_from_r(_: u64, _: u64, _: u64, _: u64, slot: u64) -> u64 {
    STATE.with_borrow_mut(|state| {
        assert!(state.attempted.contains(&slot), "native effect before ownership record");
        state.retypes.push(slot);
        if state.fail_slot == Some(slot) { 1 } else { 0 }
    })
}
unsafe fn recycle_deleted_root_slot(slot: u64) {
    STATE.with_borrow_mut(|state| state.recycled.push(slot));
}
fn existing_boot_framebuffer_bar_cap_run(_: u64, _: u64) -> Option<DeviceFrameCapRun> { None }
fn print_str(_: &[u8]) {}
fn print_hex(_: u32) {}
fn print_u64(_: u64) {}
fn device(bus: u8, base: u64, size: u64) -> nt_pnp::PciDevice {
    nt_pnp::PciDevice { bus, dev: 3, func: 0,
        bars: vec![nt_pnp::Bar { index: 0, base, size, is_io: false }] }
}
fn reset(fail_slot: Option<u64>) {
    STATE.with_borrow_mut(|state| *state = State {
        next_slot: 100, fail_slot, ..State::default()
    });
}
fn state() -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    STATE.with_borrow(|state| (state.attempted.clone(), state.retypes.clone(), state.recycled.clone()))
}
"#;

const CASES: &str = r#"
#[test]
fn partial_retype_is_recorded_and_never_replayed() {
    reset(Some(101));
    let mut authority = HostedPciBarClaimAuthority::default();
    let a = device(0, 0x8100_0000, 0x3000);
    let run = unsafe { claim_hosted_pci_bar_frame_caps(&BootInfo::new(), &mut authority, &a, &a.bars[0], 3) };
    assert!(run.is_none());
    assert_eq!(state().0, vec![100, 101]);
    assert_eq!(state().1, vec![100, 101]);
    assert_eq!(state().2, vec![102]);
    assert!(unsafe { claim_hosted_pci_bar_frame_caps(&BootInfo::new(), &mut authority, &a, &a.bars[0], 3) }.is_none());
    assert_eq!(state().1, vec![100, 101], "partial source claim was replayed");
}

#[test]
fn source_conflict_cannot_be_claimed_for_another_pci_identity() {
    reset(None);
    let mut authority = HostedPciBarClaimAuthority::default();
    let a = device(0, 0x8100_0000, 0x1000);
    let b = device(1, 0x8100_0000, 0x1000);
    assert!(unsafe { claim_hosted_pci_bar_frame_caps(&BootInfo::new(), &mut authority, &a, &a.bars[0], 1) }.is_some());
    assert!(unsafe { claim_hosted_pci_bar_frame_caps(&BootInfo::new(), &mut authority, &b, &b.bars[0], 1) }.is_none());
    assert_eq!(state().1, vec![100]);
}

#[test]
fn later_bar_failure_keeps_earlier_and_uncertain_claims_owned() {
    reset(Some(101));
    let mut authority = HostedPciBarClaimAuthority::default();
    let mut a = device(0, 0x8100_0000, 0x1000);
    a.bars.push(nt_pnp::Bar {
        index: 1, base: 0x8200_0000, size: 0x1000, is_io: false,
    });
    assert!(unsafe {
        claim_hosted_pci_memory_grants(&BootInfo::new(), &mut authority, &a, None)
    }.is_none());
    assert_eq!(state().0, vec![100, 101]);
    assert_eq!(authority.claims.len(), 2, "late failure lost the prior or uncertain claim");
    assert_eq!(state().2, Vec::<u64>::new());
    assert!(unsafe {
        claim_hosted_pci_memory_grants(&BootInfo::new(), &mut authority, &a, None)
    }.is_none());
    assert_eq!(state().1, vec![100, 101], "late failure replayed native retype");
}
"#;
