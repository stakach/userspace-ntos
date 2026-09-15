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
    /// Admit the first captured wait only after acquiring every canonical dispatcher lease.
    /// The native scheduler must already own the stopped Reply/bank and readiness/deadlines.
    /// All supplied backend and completion operations must be memory-local; no IPC or scheduling
    /// may cross these canonical borrows. This method does not itself authorize native blocking.
    pub fn admit_dispatcher_wait<C, R: Clone, T, B>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        arbiter: &mut ProviderDispatcherWaitArbiter<B::Lease>,
        backend: &mut B,
        capture: KernelProviderWaitCapture,
        sequence: u64,
        now: TimeSnapshot,
        continuation: C,
        completion: impl FnOnce(i32) -> R,
    ) -> Result<ProviderDispatcherWaitAdmission, (KernelProviderWaitAdmissionError<B::Error>, C)>
    where
        C: KernelProviderWaitContinuation,
        B: ProviderDispatcherWaitBackend,
    {
        self.publish_dispatcher_wait(
            caller,
            pm,
            catalog,
            lanes,
            arbiter,
            backend,
            None,
            capture,
            sequence,
            now,
            continuation,
            completion,
        )
        .map(|(admission, previous)| {
            assert!(previous.is_none());
            admission
        })
    }

    /// Replace, never stack over, the exact Resuming kernel frame. Every failure returns the
    /// offered continuation and leaves its predecessor/capture owned; success returns the
    /// replaced continuation to its original retirement owner. Readiness is selected atomically.
    pub fn repark_dispatcher_wait<C, R: Clone, T, B>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        arbiter: &mut ProviderDispatcherWaitArbiter<B::Lease>,
        backend: &mut B,
        previous: KernelProviderWaitCapture,
        next: KernelProviderWaitCapture,
        sequence: u64,
        now: TimeSnapshot,
        continuation: C,
        completion: impl FnOnce(i32) -> R,
    ) -> Result<(ProviderDispatcherWaitAdmission, C), (KernelProviderWaitAdmissionError<B::Error>, C)>
    where
        C: KernelProviderWaitContinuation,
        B: ProviderDispatcherWaitBackend,
    {
        self.publish_dispatcher_wait(
            caller,
            pm,
            catalog,
            lanes,
            arbiter,
            backend,
            Some(previous),
            next,
            sequence,
            now,
            continuation,
            completion,
        )
        .map(|(admission, previous)| {
            (
                admission,
                previous.expect("repark must return its replaced continuation"),
            )
        })
    }

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

    fn publish_dispatcher_wait<C, R: Clone, T, B>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        arbiter: &mut ProviderDispatcherWaitArbiter<B::Lease>,
        backend: &mut B,
        previous: Option<KernelProviderWaitCapture>,
        capture: KernelProviderWaitCapture,
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
