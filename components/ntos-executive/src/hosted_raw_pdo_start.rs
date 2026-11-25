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
            stage: Some(Stage::Provider(owner)), no_effect_status: 0 }
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
            stage: Some(Stage::Unentered(owner)), no_effect_status }
    }

    pub(crate) fn provider_irp(&self) -> u64 { self.provider_irp.raw() }

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
            Stage::Provider(owner) => match driver_launch::advance_hosted_raw_pdo_start(owner) {
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
                        self.token = None;
                        RawPdoStartProgress::Complete {
                            request: self.request.take(), receipt, status: status.raw() as u32,
                        }
                    }
                    Err((_, terminal)) => {
                        self.stage = Some(Stage::Terminal(terminal));
                        self.ownership_lost(nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw() as u32)
                    }
                }
            }
        }
    }
}
