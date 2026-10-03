//! Source dispatch receipt and origin admission, independent of forwarded payload ownership.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_progress::{
    hosted_forward_dispatch_reply_ready, HostedForwardDispatchReply,
};
use nt_io_manager::source_terminal::{OriginCallPhase, TerminalAdmission, TerminalDelivery};

pub(super) unsafe fn arm_pending(label: u64, irp: u64, token: u64) {
    if token == 0 {
        crate::provider_bugcheck::report(0xc4, [label, 3, irp, token]);
    }
    let (reply_label, status, _, _, _) = call_on4((label << 12) | 4, 3, irp, token, 0);
    if reply_label != 0 || status as u32 as i32 != STATUS_SUCCESS {
        crate::provider_bugcheck::report(0xc4, [label, 3, irp, status]);
    }
}

pub(super) struct HostedForwardOrigin {
    pub route: nt_component_suspension::peer_registry::PeerRoute,
    pub dispatch: nt_component_suspension::LaneDispatchIdentity,
    pub reply: u64,
    pub token: u64,
    pub reply_entered: bool,
    disposition: Option<HostedForwardDispatchReply>,
    phase: OriginCallPhase,
    terminal_entered: bool,
    terminal_completed: bool,
    terminal_held: bool,
    terminal_command: Option<hosted_source_completion_lane::SourceCompletionCommand>,
    lane_acknowledged: bool,
}

impl HostedForwardOrigin {
    pub(super) fn new(
        route: nt_component_suspension::peer_registry::PeerRoute,
        dispatch: nt_component_suspension::LaneDispatchIdentity,
        reply: u64,
        token: u64,
    ) -> Self {
        Self {
            route,
            dispatch,
            reply,
            token,
            reply_entered: false,
            disposition: None,
            phase: OriginCallPhase::Calling,
            terminal_entered: false,
            terminal_completed: false,
            terminal_held: false,
            terminal_command: None,
            lane_acknowledged: false,
        }
    }

    pub(super) fn pending(&self) -> bool {
        self.disposition == Some(HostedForwardDispatchReply::Pending)
    }

    pub(super) fn armed(&self) -> bool {
        self.phase == OriginCallPhase::Armed(self.token)
    }

    pub(super) fn completed(&self) -> bool {
        self.terminal_completed && self.lane_acknowledged
    }

    pub(super) fn preparation_uncertain(&self) -> bool {
        self.phase == OriginCallPhase::Indeterminate
    }

    pub(super) unsafe fn prepare_lane(
        &mut self,
        command: hosted_source_completion_lane::SourceCompletionCommand,
    ) -> hosted_source_completion_lane::SourceCompletionPreparation {
        use hosted_source_completion_lane::SourceCompletionPreparation;
        if self.phase == OriginCallPhase::Indeterminate
            || command.token != self.token
            || self
                .terminal_command
                .is_some_and(|previous| previous != command)
        {
            self.phase = OriginCallPhase::Indeterminate;
            return SourceCompletionPreparation::RetainedUncertain;
        }
        use nt_io_manager::source_irp_ledger::SourceIrpOwner;
        let prepared = match command.allocation.owner {
            SourceIrpOwner::HostedDriver(index) | SourceIrpOwner::HostedCaller(index) => {
                hosted_source_completion_lane::prepare(index, command)
            }
            SourceIrpOwner::Win32k => {
                SourceCompletionPreparation::KnownRejected(STATUS_INVALID_HANDLE as u32)
            }
        };
        if matches!(
            prepared,
            SourceCompletionPreparation::Ready | SourceCompletionPreparation::RetainedUncertain
        ) {
            self.terminal_command = Some(command);
        }
        if matches!(prepared, SourceCompletionPreparation::RetainedUncertain) {
            self.phase = OriginCallPhase::Indeterminate;
        }
        prepared
    }

    pub(super) unsafe fn release_prepared(&mut self) -> bool {
        if self.terminal_entered {
            return self.may_discard();
        }
        let Some(command) = self.terminal_command else {
            return true;
        };
        use nt_io_manager::source_irp_ledger::SourceIrpOwner;
        let released = match command.allocation.owner {
            SourceIrpOwner::HostedDriver(index) | SourceIrpOwner::HostedCaller(index) => {
                hosted_source_completion_lane::cancel_prepared(index, command)
            }
            SourceIrpOwner::Win32k => false,
        };
        if released {
            self.terminal_command = None;
        }
        released
    }

    pub(super) unsafe fn terminal_ready(
        &self,
        command: hosted_source_completion_lane::SourceCompletionCommand,
    ) -> bool {
        if self.phase == OriginCallPhase::Indeterminate {
            return false;
        }
        if self
            .terminal_command
            .is_some_and(|previous| previous != command)
        {
            return false;
        }
        if self.terminal_completed || (self.terminal_held && !self.lane_acknowledged) {
            return true;
        }
        use nt_io_manager::source_irp_ledger::SourceIrpOwner;
        match command.allocation.owner {
            SourceIrpOwner::HostedDriver(index) | SourceIrpOwner::HostedCaller(index) => {
                if self.terminal_entered {
                    self.phase != OriginCallPhase::Indeterminate
                        && !self.terminal_held
                        && hosted_source_completion_lane::continuation_ready(index, command)
                } else {
                    hosted_source_completion_lane::preparation_ready(index, command)
                }
            }
            SourceIrpOwner::Win32k => false,
        }
    }

    pub(super) fn held(&self) -> bool {
        self.terminal_held
    }

    pub(super) fn acknowledge_held_free(&mut self) {
        if self.terminal_held && self.lane_acknowledged {
            self.terminal_completed = true;
        }
    }

    pub(super) unsafe fn stopped(&self) -> bool {
        runtime::retained_service_owner_stopped(self.route, self.dispatch, self.reply, self.token)
    }

    pub(super) fn may_discard(&self) -> bool {
        self.phase != OriginCallPhase::Indeterminate
            && (!self.terminal_entered
                || ((self.terminal_held || self.terminal_completed) && self.lane_acknowledged))
    }

    pub(super) unsafe fn retire_receipt(&self) -> bool {
        if runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token) {
            runtime::acknowledge_retained_service_cancellation(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .is_ok()
        } else {
            runtime::retire_stopped_acknowledged_retained_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .is_ok()
        }
    }

    pub(super) unsafe fn reply_dispatch(
        &mut self,
        disposition: HostedForwardDispatchReply,
        source_terminal_published: bool,
    ) -> bool {
        if self.reply_entered {
            return self.disposition == Some(disposition);
        }
        if !hosted_forward_dispatch_reply_ready(disposition, source_terminal_published) {
            return false;
        }
        self.disposition = Some(disposition);
        self.reply_entered = true;
        let _ = runtime::wake_hosted_forward_service(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
            disposition,
        );
        true
    }

    /// Arrival of the exact source arm Call proves the original Reply was consumed, but does
    /// not itself prove that the source accepted an unrelated completion command.
    pub(super) unsafe fn arm(&mut self, token: u64) -> Result<(), i32> {
        if token != self.token
            || !self.pending()
            || !self.reply_entered
            || self.phase != OriginCallPhase::Calling
        {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        if !matches!(
            runtime::reconcile_retained_service_reply(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            ),
            Ok(true)
        ) {
            return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
        }
        self.phase = OriginCallPhase::Armed(self.token);
        Ok(())
    }

    pub(super) unsafe fn begin_terminal(
        &mut self,
        command: hosted_source_completion_lane::SourceCompletionCommand,
    ) -> bool {
        use nt_io_manager::source_irp_ledger::SourceIrpOwner;
        let instance = match command.allocation.owner {
            SourceIrpOwner::HostedDriver(index) | SourceIrpOwner::HostedCaller(index) => index,
            SourceIrpOwner::Win32k => return false,
        };
        if command.token != self.token {
            return false;
        }
        if let Some(previous) = self.terminal_command {
            if previous != command {
                return false;
            }
            if !self.lane_acknowledged && (self.terminal_completed || self.terminal_held) {
                self.lane_acknowledged =
                    hosted_source_completion_lane::acknowledge(instance, command);
            }
        }
        if self.terminal_completed {
            return self.lane_acknowledged;
        }
        if self.terminal_held
            || TerminalDelivery::Pending.admit(self.phase, self.token) != TerminalAdmission::Ready
        {
            return false;
        }
        let previously_entered = self.terminal_entered;
        let result = if previously_entered {
            if !hosted_source_completion_lane::continuation_ready(instance, command) {
                return false;
            }
            hosted_source_completion_lane::poll(instance, command)
        } else {
            if !matches!(
                self.prepare_lane(command),
                hosted_source_completion_lane::SourceCompletionPreparation::Ready
            ) || !hosted_source_completion_lane::ready_for_source(instance, command)
            {
                return false;
            }
            self.terminal_entered = true;
            self.terminal_command = Some(command);
            hosted_source_completion_lane::dispatch(instance, command)
        };
        match result {
            hosted_source_completion_lane::SourceCompletionDispatch::NotEntered => {
                if !previously_entered {
                    self.terminal_entered = false;
                }
                false
            }
            hosted_source_completion_lane::SourceCompletionDispatch::Suspended => false,
            hosted_source_completion_lane::SourceCompletionDispatch::Completed(
                HostedIrpUnwindOutcome::Terminal,
            ) => {
                self.terminal_completed = true;
                self.lane_acknowledged =
                    hosted_source_completion_lane::acknowledge(instance, command);
                self.lane_acknowledged
            }
            hosted_source_completion_lane::SourceCompletionDispatch::Completed(
                HostedIrpUnwindOutcome::MoreProcessingRequired,
            ) => {
                self.terminal_held = true;
                self.lane_acknowledged =
                    hosted_source_completion_lane::acknowledge(instance, command);
                false
            }
            hosted_source_completion_lane::SourceCompletionDispatch::Uncertain => {
                self.phase = OriginCallPhase::Indeterminate;
                false
            }
        }
    }
}
