//! Retained direct START for a service-less raw PDO.
//!
//! The canonical provider IRP, PnP token, and caller request stay together until the
//! exact terminal receipt commits the devnode. A provider effect with an uncertain
//! outcome cannot be replayed or converted into a successful no-IRP reply.

use crate::driver_launch::{
    self, HostedAcceptedPdoProviderOwner, HostedRawPdoStartDiscard,
    HostedRawPdoStartProgress, HostedRawPdoStartTerminal,
};
use nt_pnp_manager::{PnpDispatchToken, StartDeviceLifecycleReceipt, StartDeviceRequestIdentity};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::{print_hex_u64, print_str, print_u64};

// The first few raw START admissions are enough to locate a stalled owner without
// producing a line on every completion-pump pass.
const RAW_START_TRACE_CALLS: u64 = 4;
const RAW_START_TRACE_LINE_BUDGET: u64 = 96;
static RAW_START_TRACE_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static RAW_START_TRACE_CALL_IDS: [AtomicU64; 4] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
static RAW_START_TRACE_LINES: AtomicU64 = AtomicU64::new(0);
static RAW_START_ONCE_TRACE_BITS: AtomicU64 = AtomicU64::new(0);

fn raw_start_trace_slot(call: u64) -> Option<u32> {
    if call == 0 { return None; }
    RAW_START_TRACE_CALL_IDS.iter().position(|slot| slot.load(Ordering::Relaxed) == call)
        .map(|index| index as u32)
}

pub(crate) fn trace_raw_start_admission(call: u64, instance: &str) {
    let slot = RAW_START_TRACE_ADMISSIONS.fetch_add(1, Ordering::Relaxed);
    if call == 0 || slot >= RAW_START_TRACE_CALLS { return; }
    RAW_START_TRACE_CALL_IDS[slot as usize].store(call, Ordering::Relaxed);
    if RAW_START_TRACE_LINES.fetch_add(1, Ordering::Relaxed) >= RAW_START_TRACE_LINE_BUDGET
    { return; }
    print_str(b"[raw-pdo-start] call=");
    print_u64(call);
    print_str(b" instance=");
    print_str(instance.as_bytes());
    print_str(b" phase=admission\n");
}

pub(crate) fn trace_raw_start(
    call: u64,
    pdo: u64,
    provider_irp: u64,
    phase: &[u8],
    status: Option<u32>,
    token: Option<&PnpDispatchToken>,
) {
    if raw_start_trace_slot(call).is_none()
        || RAW_START_TRACE_LINES.fetch_add(1, Ordering::Relaxed) >= RAW_START_TRACE_LINE_BUDGET
    { return; }
    print_str(b"[raw-pdo-start] call=");
    print_u64(call);
    print_str(b" pdo=");
    print_u64(pdo);
    print_str(b" provider-irp=0x");
    print_hex_u64(provider_irp);
    print_str(b" phase=");
    print_str(phase);
    if let Some(token) = token {
        let identity = token.identity();
        print_str(b" token-devnode/gen/dispatch/irp=");
        print_u64(identity.devnode_id);
        print_str(b"/");
        print_u64(identity.devnode_generation);
        print_str(b"/");
        print_u64(identity.dispatch_generation);
        print_str(b"/0x");
        print_hex_u64(identity.canonical_irp_id);
    }
    if let Some(status) = status {
        print_str(b" status=0x");
        print_hex_u64(status as u64);
    }
    print_str(b"\n");
}

/// An unchanged provider stage or rejected terminal may recur on every pump.
pub(crate) fn trace_raw_start_once(
    call: u64, pdo: u64, provider_irp: u64, outcome: u32, phase: &[u8],
) {
    let Some(slot) = raw_start_trace_slot(call) else { return; };
    if outcome >= 5 { return; }
    let bit = 1u64 << (u64::from(slot) * 5 + u64::from(outcome));
    if RAW_START_ONCE_TRACE_BITS.fetch_or(bit, Ordering::Relaxed) & bit == 0 {
        trace_raw_start(call, pdo, provider_irp, phase, None, None);
    }
}

enum Stage {
    /// Token admission failed. Only a proven discard may release this owner.
    Unentered(HostedAcceptedPdoProviderOwner),
    Provider(HostedAcceptedPdoProviderOwner),
    Terminal(HostedRawPdoStartTerminal),
}

pub(crate) enum RawPdoStartProgress {
    Awaiting,
    NotEntered {
        request: Option<StartDeviceRequestIdentity>,
        status: u32,
    },
    Complete {
        request: Option<StartDeviceRequestIdentity>,
        receipt: StartDeviceLifecycleReceipt,
        status: u32,
    },
    OwnershipLost {
        request: StartDeviceRequestIdentity,
        irp_id: u64,
        status: u32,
    },
    Released,
}

pub(crate) struct OwnedHostedRawPdoStart {
    pdo: u64,
    provider_irp: nt_io_manager::IrpId,
    token: Option<PnpDispatchToken>,
    request: Option<StartDeviceRequestIdentity>,
    trace_call: u64,
    stage: Option<Stage>,
    no_effect_status: u32,
}

impl OwnedHostedRawPdoStart {
    pub(crate) fn new(
        pdo: u64,
        owner: HostedAcceptedPdoProviderOwner,
        token: PnpDispatchToken,
        request: StartDeviceRequestIdentity,
    ) -> Self {
        let provider_irp = owner.direct_provider_irp()
            .expect("direct START owner lost its canonical IRP");
        Self { pdo, provider_irp, token: Some(token), request: Some(request),
            trace_call: request.sequence(), stage: Some(Stage::Provider(owner)), no_effect_status: 0 }
    }

    pub(crate) fn without_token(
        pdo: u64,
        owner: HostedAcceptedPdoProviderOwner,
        request: StartDeviceRequestIdentity,
        no_effect_status: u32,
    ) -> Self {
        let provider_irp = owner.direct_provider_irp()
            .expect("unentered direct START owner lost its canonical IRP");
        Self { pdo, provider_irp, token: None, request: Some(request),
            trace_call: request.sequence(), stage: Some(Stage::Unentered(owner)), no_effect_status }
    }

    pub(crate) fn provider_irp(&self) -> u64 { self.provider_irp.raw() }

    pub(crate) fn trace_identity(&self) -> (u64, u64, u64) {
        (self.trace_call, self.pdo, self.provider_irp.raw())
    }

    pub(crate) fn abandon_request(&mut self) -> Option<StartDeviceRequestIdentity> {
        self.request.take()
    }

    pub(crate) fn needs_completion_redrive(&self) -> bool {
        self.stage.is_some()
    }

    fn ownership_lost(&mut self, status: u32) -> RawPdoStartProgress {
        match self.request.take() {
            Some(request) => RawPdoStartProgress::OwnershipLost {
                request, irp_id: self.provider_irp.raw(), status,
            },
            None => RawPdoStartProgress::Awaiting,
        }
    }

    pub(crate) unsafe fn drive(&mut self) -> RawPdoStartProgress {
        let Some(stage) = self.stage.take() else { return RawPdoStartProgress::Released };
        match stage {
            Stage::Unentered(owner) => match driver_launch::discard_hosted_raw_pdo_start(owner) {
                HostedRawPdoStartDiscard::Retired => RawPdoStartProgress::NotEntered {
                    request: self.request.take(), status: self.no_effect_status,
                },
                HostedRawPdoStartDiscard::Retained(owner) => {
                    self.stage = Some(Stage::Unentered(owner));
                    self.ownership_lost(nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw() as u32)
                }
            },
            Stage::Provider(owner) => match driver_launch::advance_hosted_raw_pdo_start(
                owner, self.trace_call, self.pdo,
            ) {
                HostedRawPdoStartProgress::Awaiting(owner) => {
                    self.stage = Some(Stage::Provider(owner));
                    RawPdoStartProgress::Awaiting
                }
                HostedRawPdoStartProgress::Ready(terminal) => {
                    self.stage = Some(Stage::Terminal(terminal));
                    self.drive()
                }
                HostedRawPdoStartProgress::Indeterminate { status, owner } => {
                    self.stage = Some(Stage::Provider(owner));
                    self.ownership_lost(status.raw() as u32)
                }
                HostedRawPdoStartProgress::NotEntered { status, owner } => {
                    let token = self.token.as_ref().expect("direct START token vanished before abort");
                    if driver_launch::abort_hosted_raw_pdo_start_dispatch(token, self.provider_irp).is_ok() {
                        // Provider discard was proven; no canonical effect can arrive later.
                        drop(owner);
                        self.token = None;
                        RawPdoStartProgress::NotEntered {
                            request: self.request.take(), status: status.raw() as u32,
                        }
                    } else {
                        self.stage = Some(Stage::Provider(owner));
                        self.ownership_lost(status.raw() as u32)
                    }
                }
            },
            Stage::Terminal(terminal) => {
                let token = self.token.as_ref().expect("direct terminal lost PnP token");
                match terminal.complete(token, self.pdo) {
                    Ok((receipt, status)) => {
                        trace_raw_start(self.trace_call, self.pdo, self.provider_irp.raw(),
                            b"pnp-lifecycle-terminal", Some(status.raw() as u32), Some(token));
                        self.token = None;
                        RawPdoStartProgress::Complete {
                            request: self.request.take(), receipt, status: status.raw() as u32,
                        }
                    }
                    Err((_, terminal)) => {
                        trace_raw_start_once(self.trace_call, self.pdo,
                            self.provider_irp.raw(), 3, b"pnp-lifecycle-rejected");
                        self.stage = Some(Stage::Terminal(terminal));
                        self.ownership_lost(nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw() as u32)
                    }
                }
            }
        }
    }
}
