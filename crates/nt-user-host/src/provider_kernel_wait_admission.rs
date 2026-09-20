//! Lease-backed publication of captured kernel waits and owned repeated-wait replacement.

use super::*;
use nt_kernel_exec::TimeSnapshot;
use nt_provider_wait::{
    ProviderDispatcherWaitAdmission, ProviderDispatcherWaitArbiter, ProviderDispatcherWaitBackend,
    ProviderDispatcherWaitError, ProviderDispatcherWaitPublicationError,
};

#[derive(Debug, PartialEq, Eq)]
pub enum KernelProviderWaitAdmissionError<E> {
    Authority(u32),
    Dispatcher(ProviderDispatcherWaitError<E>),
    Lane(LaneError),
}

impl<D: KernelProviderWaitRecipient> KernelProviderActivations<D> {
    fn validate_wait_publication<C: KernelProviderWaitContinuation, R, T>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        previous: Option<KernelProviderWaitCapture>,
        capture: KernelProviderWaitCapture,
        continuation: &C,
    ) -> Result<(), u32> {
        if continuation.kernel_wait_capture() != Some(capture) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.validate_wait_publication_state(caller, pm, catalog, lanes, previous, capture)
    }

    pub(super) fn validate_wait_publication_state<C: KernelProviderWaitContinuation, R, T>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        previous: Option<KernelProviderWaitCapture>,
        capture: KernelProviderWaitCapture,
    ) -> Result<(), u32> {
        self.validate(caller, pm, catalog, lanes)?;
        if capture.caller() != caller
            || lanes.external_depth(caller.dispatch.lane()) != Ok(0)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let state = self.recipient_mut(caller)?.kernel_wait_state();
        if state.captured_wait() != Some(capture)
            || state
                .progress()
                .provider_wait_observation(caller.binding.reply_object)
                != Some(capture.observation())
            || state.active_resume() != previous
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let lane = caller.dispatch.lane();
        match previous {
            None if lanes.suspension_count(lane) == Ok(0) => Ok(()),
            Some(previous)
                if previous.caller() == caller && lanes.suspension_count(lane) == Ok(1) =>
            {
                let frame = lanes
                    .top(lane)
                    .map_err(|_| STATUS_INVALID_HANDLE)?
                    .ok_or(STATUS_INVALID_HANDLE)?;
                if frame.key == previous.key()
                    && frame.owner == caller.owner()
                    && frame.continuation.kernel_wait_capture() == Some(previous)
                    && matches!(frame.phase, SuspensionPhase::Resuming { .. })
                {
                    Ok(())
                } else {
                    Err(STATUS_INVALID_HANDLE)
                }
            }
            _ => Err(STATUS_INVALID_HANDLE),
        }
    }

    /// Publish initial or repeated work only after acquiring every canonical dispatcher lease.
    /// Discovery is not authority: the retained capture and predecessor are revalidated.
    /// Success returns the replaced continuation, if any, to its retirement owner; failure
    /// returns the offered continuation without removing its predecessor. All operations are
    /// memory-local, and `now` is the outer publication pass's sampled time. No IPC or scheduling
    /// may cross these borrows. The scheduler must own stopped Reply/bank and readiness/deadlines;
    /// this transaction does not itself authorize native blocking.
    pub fn publish_wait_work<C, R: Clone, T, B>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        arbiter: &mut ProviderDispatcherWaitArbiter<B::Lease>,
        backend: &mut B,
        work: KernelProviderWaitWork,
        sequence: u64,
        now: TimeSnapshot,
        continuation: C,
        completion: impl FnOnce(i32) -> R,
    ) -> Result<
        (ProviderDispatcherWaitAdmission, Option<C>),
        (KernelProviderWaitAdmissionError<B::Error>, C),
    >
    where
        C: KernelProviderWaitContinuation,
        B: ProviderDispatcherWaitBackend,
    {
        let (previous, capture) = match work {
            KernelProviderWaitWork::Initial(capture) => (None, capture),
            KernelProviderWaitWork::Repark { previous, next } => (Some(previous), next),
        };
        if let Err(status) = self.validate_wait_publication(
            caller,
            pm,
            catalog,
            lanes,
            previous,
            capture,
            &continuation,
        ) {
            return Err((
                KernelProviderWaitAdmissionError::Authority(status),
                continuation,
            ));
        }
        let (admission, replaced) = arbiter
            .admit_owned_at(
                backend,
                capture.request(),
                caller.owner(),
                sequence,
                capture.observed_at(),
                now,
                continuation,
                |continuation| {
                    // Recheck canonical ownership after backend acquisition, before lane mutation.
                    if let Err(status) = self.validate_wait_publication(
                        caller,
                        pm,
                        catalog,
                        lanes,
                        previous,
                        capture,
                        &continuation,
                    ) {
                        return Err((
                            KernelProviderWaitAdmissionError::Authority(status),
                            continuation,
                        ));
                    }
                    let published = match previous {
                        None => lanes
                            .admit_running_owned(
                                caller.dispatch.lane(),
                                caller.binding.reply_object,
                                capture.key(),
                                sequence,
                                caller.owner(),
                                continuation,
                            )
                            .map(|()| None),
                        Some(previous) => lanes
                            .rearm_running_owned(
                                caller.dispatch.lane(),
                                caller.binding.reply_object,
                                previous.key(),
                                capture.key(),
                                sequence,
                                caller.owner(),
                                continuation,
                            )
                            .map(Some),
                    };
                    published.map_err(|(error, continuation)| {
                        (KernelProviderWaitAdmissionError::Lane(error), continuation)
                    })
                },
            )
            .map_err(|(error, continuation)| {
                let error = match error {
                    ProviderDispatcherWaitPublicationError::Wait(error) => {
                        KernelProviderWaitAdmissionError::Dispatcher(error)
                    }
                    ProviderDispatcherWaitPublicationError::Publication(error) => error,
                };
                (error, continuation)
            })?;
        let status = match admission {
            ProviderDispatcherWaitAdmission::Satisfied { status, .. } => Some(status),
            ProviderDispatcherWaitAdmission::TimedOut { .. } => {
                Some(nt_provider_wait::STATUS_TIMEOUT)
            }
            ProviderDispatcherWaitAdmission::Parked { .. } => None,
        };
        if let Some(status) = status {
            lanes
                .select(capture.key(), completion(status))
                .expect("published kernel wait must own its immediate readiness result");
        }
        Ok((admission, replaced))
    }
}
