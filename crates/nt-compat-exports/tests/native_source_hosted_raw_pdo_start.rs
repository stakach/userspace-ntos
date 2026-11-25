//! Execute the native direct raw-PDO START owner against controlled provider stages.

use std::process::Command;

#[test]
fn direct_raw_pdo_start_retains_exact_effect_until_terminal_or_proven_discard() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_raw_pdo_start.rs");
    syn::parse_file(source).expect("complete native direct raw-PDO START owner");
    let fixture = format!("{PORTS}\nmod production {{\n{source}\n}}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-hosted-raw-pdo-start-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native raw-PDO START owner must compile in fixture:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native raw-PDO START owner regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
extern crate self as nt_io_manager;
extern crate self as nt_pnp_manager;
extern crate self as nt_status;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

// Serial output is outside this executable owner's behavioral contract.
fn print_str(_: &[u8]) {}
fn print_u64(_: u64) {}
fn print_hex_u64(_: u64) {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrpId(u64);
impl IrpId { pub fn raw(self) -> u64 { self.0 } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PnpDispatchToken(u64);
pub struct PnpDispatchIdentity {
    pub devnode_id: u64,
    pub devnode_generation: u64,
    pub dispatch_generation: u64,
    pub canonical_irp_id: u64,
}
impl PnpDispatchToken {
    pub fn identity(&self) -> PnpDispatchIdentity {
        PnpDispatchIdentity {
            devnode_id: self.0,
            devnode_generation: 1,
            dispatch_generation: 1,
            canonical_irp_id: self.0,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartDeviceRequestIdentity(u64);
impl StartDeviceRequestIdentity { pub fn sequence(self) -> u64 { self.0 } }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartDeviceLifecycleReceipt(u64);
pub struct PnpError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtStatus(u32);
impl NtStatus {
    pub const INVALID_DEVICE_REQUEST: Self = Self(0xc0000010);
    pub fn raw(self) -> u32 { self.0 }
}

thread_local! {
    static ABORTS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
    static ABORT_FAIL: Cell<bool> = const { Cell::new(false) };
    static COMPLETIONS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
}

mod driver_launch {
    use super::*;

    #[derive(Clone, Copy)]
    pub enum Step { Awaiting, Ready, Indeterminate, NotEntered }

    pub struct HostedAcceptedPdoProviderOwner {
        pub irp: IrpId,
        pub steps: VecDeque<Step>,
        pub terminal_rejects: usize,
    }
    impl HostedAcceptedPdoProviderOwner {
        pub fn direct_provider_irp(&self) -> Option<IrpId> { Some(self.irp) }
    }

    pub enum HostedRawPdoStartDiscard {
        Retired,
        Retained(HostedAcceptedPdoProviderOwner),
    }
    pub enum HostedRawPdoStartProgress {
        Awaiting(HostedAcceptedPdoProviderOwner),
        Ready(HostedRawPdoStartTerminal),
        Indeterminate { status: NtStatus, owner: HostedAcceptedPdoProviderOwner },
        NotEntered { status: NtStatus, owner: HostedAcceptedPdoProviderOwner },
    }
    pub struct HostedRawPdoStartTerminal { pub rejects: usize }
    impl HostedRawPdoStartTerminal {
        pub fn complete(
            mut self, token: &PnpDispatchToken, pdo: u64,
        ) -> Result<(StartDeviceLifecycleReceipt, NtStatus), (PnpError, Self)> {
            if self.rejects > 0 {
                self.rejects -= 1;
                return Err((PnpError, self));
            }
            COMPLETIONS.with(|log| log.borrow_mut().push((token.0, pdo)));
            Ok((StartDeviceLifecycleReceipt(token.0), NtStatus(0)))
        }
    }

    pub fn discard_hosted_raw_pdo_start(
        _owner: HostedAcceptedPdoProviderOwner,
    ) -> HostedRawPdoStartDiscard {
        HostedRawPdoStartDiscard::Retired
    }
    pub fn advance_hosted_raw_pdo_start(
        mut owner: HostedAcceptedPdoProviderOwner,
        trace_call: u64,
        pdo: u64,
    ) -> HostedRawPdoStartProgress {
        assert_eq!(trace_call, 9);
        assert_eq!(pdo, 17);
        match owner.steps.pop_front().unwrap_or(Step::Awaiting) {
            Step::Awaiting => HostedRawPdoStartProgress::Awaiting(owner),
            Step::Ready => HostedRawPdoStartProgress::Ready(
                HostedRawPdoStartTerminal { rejects: owner.terminal_rejects }
            ),
            Step::Indeterminate => HostedRawPdoStartProgress::Indeterminate {
                status: NtStatus(0xc0000001), owner,
            },
            Step::NotEntered => HostedRawPdoStartProgress::NotEntered {
                status: NtStatus(0xc0000034), owner,
            },
        }
    }
    pub fn abort_hosted_raw_pdo_start_dispatch(
        token: &PnpDispatchToken, irp: IrpId,
    ) -> Result<(), NtStatus> {
        ABORTS.with(|log| log.borrow_mut().push((token.0, irp.0)));
        if ABORT_FAIL.with(Cell::get) { Err(NtStatus(0xc0000001)) } else { Ok(()) }
    }
}
"#;

const CASES: &str = r#"
use driver_launch::{HostedAcceptedPdoProviderOwner, Step};
use production::{OwnedHostedRawPdoStart, RawPdoStartProgress};

fn owner(steps: &[Step], terminal_rejects: usize) -> HostedAcceptedPdoProviderOwner {
    HostedAcceptedPdoProviderOwner {
        irp: IrpId(61), steps: steps.iter().copied().collect(), terminal_rejects,
    }
}
fn reset() {
    ABORTS.with(|log| log.borrow_mut().clear());
    COMPLETIONS.with(|log| log.borrow_mut().clear());
    ABORT_FAIL.with(|flag| flag.set(false));
}

#[test]
fn synchronous_terminal_commits_exact_token_and_pdo_before_success() {
    reset();
    let mut start = OwnedHostedRawPdoStart::new(
        17, owner(&[Step::Ready], 0), PnpDispatchToken(41), StartDeviceRequestIdentity(9),
    );
    assert_eq!(start.provider_irp(), 61);
    match unsafe { start.drive() } {
        RawPdoStartProgress::Complete { request, receipt, status } => {
            assert_eq!(request, Some(StartDeviceRequestIdentity(9)));
            assert_eq!(receipt, StartDeviceLifecycleReceipt(41));
            assert_eq!(status, 0);
        }
        _ => panic!("synchronous provider must produce the exact terminal receipt"),
    }
    assert!(!start.needs_completion_redrive());
    COMPLETIONS.with(|log| assert_eq!(&*log.borrow(), &[(41, 17)]));
    ABORTS.with(|log| assert!(log.borrow().is_empty()));
}

#[test]
fn pending_provider_retains_owner_until_terminal() {
    reset();
    let mut start = OwnedHostedRawPdoStart::new(
        17, owner(&[Step::Awaiting, Step::Ready], 0),
        PnpDispatchToken(41), StartDeviceRequestIdentity(9),
    );
    assert!(matches!(unsafe { start.drive() }, RawPdoStartProgress::Awaiting));
    assert!(start.needs_completion_redrive());
    COMPLETIONS.with(|log| assert!(log.borrow().is_empty()));
    assert!(matches!(unsafe { start.drive() }, RawPdoStartProgress::Complete {
        request: Some(StartDeviceRequestIdentity(9)), status: 0, ..
    }));
    COMPLETIONS.with(|log| assert_eq!(&*log.borrow(), &[(41, 17)]));
}

#[test]
fn proven_no_entry_aborts_exact_token_before_no_irp_failure() {
    reset();
    let mut start = OwnedHostedRawPdoStart::new(
        17, owner(&[Step::NotEntered], 0),
        PnpDispatchToken(41), StartDeviceRequestIdentity(9),
    );
    assert!(matches!(unsafe { start.drive() }, RawPdoStartProgress::NotEntered {
        request: Some(StartDeviceRequestIdentity(9)), status: 0xc0000034,
    }));
    assert!(!start.needs_completion_redrive());
    ABORTS.with(|log| assert_eq!(&*log.borrow(), &[(41, 61)]));
    COMPLETIONS.with(|log| assert!(log.borrow().is_empty()));
}

#[test]
fn uncertain_provider_and_rejected_ack_keep_owner_after_reply_is_consumed() {
    reset();
    let mut start = OwnedHostedRawPdoStart::new(
        17, owner(&[Step::Indeterminate, Step::Ready], 1),
        PnpDispatchToken(41), StartDeviceRequestIdentity(9),
    );
    assert!(matches!(unsafe { start.drive() }, RawPdoStartProgress::OwnershipLost {
        request: StartDeviceRequestIdentity(9), irp_id: 61, status: 0xc0000001,
    }));
    assert!(start.needs_completion_redrive());
    COMPLETIONS.with(|log| assert!(log.borrow().is_empty()));
    assert!(matches!(unsafe { start.drive() }, RawPdoStartProgress::Awaiting));
    assert!(start.needs_completion_redrive());
    COMPLETIONS.with(|log| assert!(log.borrow().is_empty()));
    assert!(matches!(unsafe { start.drive() }, RawPdoStartProgress::Complete {
        request: None, status: 0, ..
    }));
    COMPLETIONS.with(|log| assert_eq!(&*log.borrow(), &[(41, 17)]));
    assert!(!start.needs_completion_redrive());
}

#[test]
fn abort_rejection_retains_exact_token_without_second_caller_reply() {
    reset();
    ABORT_FAIL.with(|flag| flag.set(true));
    let mut start = OwnedHostedRawPdoStart::new(
        17, owner(&[Step::NotEntered, Step::NotEntered], 0),
        PnpDispatchToken(41), StartDeviceRequestIdentity(9),
    );
    assert!(matches!(unsafe { start.drive() }, RawPdoStartProgress::OwnershipLost {
        request: StartDeviceRequestIdentity(9), irp_id: 61, status: 0xc0000034,
    }));
    assert!(start.needs_completion_redrive());
    ABORT_FAIL.with(|flag| flag.set(false));
    assert!(matches!(unsafe { start.drive() }, RawPdoStartProgress::NotEntered {
        request: None, status: 0xc0000034,
    }));
    ABORTS.with(|log| assert_eq!(&*log.borrow(), &[(41, 61), (41, 61)]));
    COMPLETIONS.with(|log| assert!(log.borrow().is_empty()));
    assert!(!start.needs_completion_redrive());
}
"#;
