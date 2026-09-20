//! Recipient-owned pump progress and its exact stopped provider-wait observation.

use crate::provider_kernel_activation::{KernelProviderCaller, KernelProviderWaitCapture};
use crate::provider_kernel_pump::{
    KernelProviderPumpAttempt, KernelProviderPumpDisposition, KernelProviderPumpFacts,
    KernelProviderPumpProgress, PumpProgressError,
};
use nt_component_suspension::{SuspensionResume, TerminalIdentity};
use nt_process::STATUS_INVALID_PARAMETER;
use nt_provider_wait::ProviderWaitRequest;

#[derive(Debug)]
enum WaitObservation {
    Captured(KernelProviderWaitCapture),
    Rejected {
        request: ProviderWaitRequest,
        status: u32,
    },
}

/// A retained physical stop, not authority to publish, resume, or release its activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProviderStoppedOutcome {
    Returned(u32),
    WaitCaptured(KernelProviderWaitCapture),
    Walled,
    CallbackSuspended,
    LpcWaitSuspended,
}

/// The native recipient retains this state alongside its physical channel and pump result.
#[derive(Debug)]
pub struct KernelProviderWaitState {
    progress: KernelProviderPumpProgress,
    wait: Option<WaitObservation>,
    active_resume: Option<KernelProviderWaitCapture>,
    delivered_return: Option<(TerminalIdentity, u32)>,
}

pub trait KernelProviderWaitRecipient {
    fn kernel_wait_state(&mut self) -> &mut KernelProviderWaitState;
}

/// A selected kernel frame must retain the same validated capture as its pump recipient.
pub trait KernelProviderWaitContinuation {
    fn kernel_wait_capture(&self) -> Option<KernelProviderWaitCapture>;
}

impl KernelProviderWaitContinuation for KernelProviderWaitCapture {
    fn kernel_wait_capture(&self) -> Option<KernelProviderWaitCapture> {
        Some(*self)
    }
}

impl KernelProviderWaitRecipient for KernelProviderWaitState {
    fn kernel_wait_state(&mut self) -> &mut KernelProviderWaitState {
        self
    }
}

impl KernelProviderWaitState {
    pub fn new(reply_cap: u64) -> Result<Self, PumpProgressError> {
        Ok(Self {
            progress: KernelProviderPumpProgress::new(reply_cap)?,
            wait: None,
            active_resume: None,
            delivered_return: None,
        })
    }

    pub fn progress(&self) -> &KernelProviderPumpProgress {
        &self.progress
    }

    /// Classify only a fully observed stop, preserving failed wait capture ownership.
    pub fn stopped_outcome(&self) -> Result<KernelProviderStoppedOutcome, u32> {
        use KernelProviderPumpDisposition as Pump;
        use KernelProviderStoppedOutcome as Stop;
        match self.progress.disposition() {
            Some(Pump::ProviderWaitSuspended) => match self.wait {
                Some(WaitObservation::Captured(capture))
                    if self
                        .progress
                        .provider_wait_observation(capture.caller().binding().reply_object)
                        == Some(capture.observation()) =>
                {
                    Ok(Stop::WaitCaptured(capture))
                }
                Some(WaitObservation::Rejected { status, .. }) => Err(status),
                _ => Err(STATUS_INVALID_PARAMETER),
            },
            Some(Pump::Returned(status)) => Ok(Stop::Returned(status)),
            Some(Pump::Walled) => Ok(Stop::Walled),
            Some(Pump::CallbackSuspended) => Ok(Stop::CallbackSuspended),
            Some(Pump::LpcWaitSuspended) => Ok(Stop::LpcWaitSuspended),
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    pub fn begin_initial(&mut self) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        self.progress.begin_initial()
    }

    pub fn begin_receive_after_yield(
        &mut self,
    ) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        self.progress.begin_receive_after_yield()
    }

    pub fn observe(
        &mut self,
        attempt: &mut KernelProviderPumpAttempt,
        facts: KernelProviderPumpFacts,
        returned_status: Option<u32>,
    ) -> Result<KernelProviderPumpDisposition, PumpProgressError> {
        self.progress.observe(attempt, facts, returned_status)
    }

    /// Preserve rejected requests too; a validation failure is not permission to reply or retry.
    pub fn retain_provider_wait(
        &mut self,
        request: ProviderWaitRequest,
        capture: Result<KernelProviderWaitCapture, u32>,
    ) -> Result<(), u32> {
        if self.wait.is_some()
            || self.progress.disposition()
                != Some(KernelProviderPumpDisposition::ProviderWaitSuspended)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        match capture {
            Ok(capture) => {
                if capture.request() != &request
                    || self
                        .progress
                        .provider_wait_observation(capture.caller().binding().reply_object)
                        != Some(capture.observation())
                {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.wait = Some(WaitObservation::Captured(capture));
                Ok(())
            }
            Err(status) => {
                self.wait = Some(WaitObservation::Rejected { request, status });
                Err(status)
            }
        }
    }

    pub fn captured_wait(&self) -> Option<KernelProviderWaitCapture> {
        match self.wait {
            Some(WaitObservation::Captured(capture)) => Some(capture),
            _ => None,
        }
    }

    /// The entered frame's origin survives IRQ receive tickets and a subsequent physical wait.
    /// It is distinct from that new stopped request until the next canonical resume is claimed.
    pub(crate) fn active_resume(&self) -> Option<KernelProviderWaitCapture> {
        self.active_resume
    }

    /// Copy the observed native return into this original recipient's terminal destination.
    /// The canonical activation must authenticate an entered local-delivery ticket first.
    /// Every refusal precedes mutation, so the native adapter can report NoEffects on error.
    pub fn deliver_terminal_return(
        &mut self,
        terminal: TerminalIdentity,
        status: u32,
    ) -> Result<(), u32> {
        let capture = self.active_resume.ok_or(STATUS_INVALID_PARAMETER)?;
        if self.progress.disposition() != Some(KernelProviderPumpDisposition::Returned(status))
            || self.wait.is_some()
            || terminal.owner() != capture.owner()
            || terminal.key() != capture.key()
            || terminal.external_token().is_some()
            || self
                .delivered_return
                .is_some_and(|delivered| delivered != (terminal, status))
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.delivered_return = Some((terminal, status));
        Ok(())
    }

    pub fn delivered_terminal_return(&self, terminal: TerminalIdentity, status: u32) -> bool {
        self.delivered_return == Some((terminal, status))
    }

    pub fn rejected_wait(&self) -> Option<(&ProviderWaitRequest, u32)> {
        match &self.wait {
            Some(WaitObservation::Rejected { request, status }) => Some((request, *status)),
            _ => None,
        }
    }

    pub(crate) fn validate_resume(
        &self,
        capture: KernelProviderWaitCapture,
    ) -> Result<(), PumpProgressError> {
        if self.captured_wait() != Some(capture) {
            return Err(PumpProgressError::NotReady);
        }
        self.progress
            .validate_provider_wait_resume(capture.observation())
    }

    pub(crate) fn prepare_resume(
        &self,
        capture: KernelProviderWaitCapture,
    ) -> Result<KernelProviderPumpAttempt, PumpProgressError> {
        self.validate_resume(capture)?;
        self.progress
            .prepare_provider_wait_resume(capture.observation())
    }

    pub(crate) fn commit_resume(
        &mut self,
        capture: KernelProviderWaitCapture,
        attempt: &KernelProviderPumpAttempt,
    ) {
        assert_eq!(self.captured_wait(), Some(capture));
        self.progress
            .commit_provider_wait_resume(capture.observation(), attempt);
        self.active_resume = Some(capture);
        self.wait = None;
    }
}

/// An authenticated lane transition and its unique pump attempt travel together.
/// Dropping this value does not reopen either the selected wait or the pump entry.
///
/// ```compile_fail
/// use nt_user_host::provider_kernel_wait::KernelProviderWaitResume;
/// fn duplicate(ticket: KernelProviderWaitResume<i32>) { let _ = ticket.clone(); }
/// ```
#[must_use = "execute and observe the claimed pump exactly once; dropping it does not permit retry"]
#[derive(Debug)]
pub struct KernelProviderWaitResume<R> {
    pub(crate) capture: KernelProviderWaitCapture,
    pub(crate) attempt: KernelProviderPumpAttempt,
    pub(crate) selection: SuspensionResume<R>,
}

impl<R> KernelProviderWaitResume<R> {
    pub fn caller(&self) -> KernelProviderCaller {
        self.capture.caller()
    }

    pub fn selection(&self) -> &SuspensionResume<R> {
        &self.selection
    }

    pub fn into_parts(
        self,
    ) -> (
        KernelProviderWaitCapture,
        KernelProviderPumpAttempt,
        SuspensionResume<R>,
    ) {
        (self.capture, self.attempt, self.selection)
    }
}
