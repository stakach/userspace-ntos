//! Bounded discovery of stopped requests in the original activation rows.

use super::*;
use crate::provider_kernel_pump::KernelProviderPumpDisposition;

/// A publication candidate, not permission to acquire leases or execute the provider.
/// Native admission must revalidate the retained observation and lane before publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelProviderWaitWork {
    Initial(KernelProviderWaitCapture),
    Repark {
        previous: KernelProviderWaitCapture,
        next: KernelProviderWaitCapture,
    },
}

/// A pass visits each retained activation at most once and excludes later activations.
/// There is no second queue: failed publication stays in the original recipient and frame.
pub struct KernelProviderWaitWorkCursor {
    after: u64,
    through: u64,
}

impl<D> KernelProviderActivations<D> {
    pub fn wait_work_cursor(&self) -> KernelProviderWaitWorkCursor {
        KernelProviderWaitWorkCursor {
            after: 0,
            through: self
                .rows
                .iter()
                .map(|row| row.caller.activation)
                .max()
                .unwrap_or(0),
        }
    }
}

impl<D: KernelProviderWaitRecipient> KernelProviderActivations<D> {
    /// Advance before returning a candidate or refusal. Already admitted requests are skipped
    /// only when their exact retained capture matches a sole Waiting, Selected or Cancelled
    /// frame. Readiness selection and execution belong to their own owners.
    pub fn next_wait_work<C: KernelProviderWaitContinuation, R, T>(
        &mut self,
        cursor: &mut KernelProviderWaitWorkCursor,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Option<(KernelProviderCaller, Result<KernelProviderWaitWork, u32>)> {
        loop {
            let caller = self
                .rows
                .iter()
                .filter(|row| {
                    row.completion.is_none()
                        && row.caller.activation > cursor.after
                        && row.caller.activation <= cursor.through
                })
                .map(|row| row.caller)
                .min_by_key(|caller| caller.activation);
            cursor.after = caller.map_or(cursor.through, |caller| caller.activation);
            let caller = caller?;
            match self.classify_wait_work(caller, pm, catalog, lanes) {
                Ok(None) => continue,
                Ok(Some(work)) => return Some((caller, Ok(work))),
                Err(status) => return Some((caller, Err(status))),
            }
        }
    }

    fn classify_wait_work<C: KernelProviderWaitContinuation, R, T>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<Option<KernelProviderWaitWork>, u32> {
        let (capture, previous) = {
            let state = self.recipient_mut(caller)?.kernel_wait_state();
            if let Some((_, status)) = state.rejected_wait() {
                return Err(status);
            }
            let Some(capture) = state.captured_wait() else {
                return if state.progress().disposition()
                    == Some(KernelProviderPumpDisposition::ProviderWaitSuspended)
                {
                    Err(STATUS_INVALID_HANDLE)
                } else {
                    Ok(None)
                };
            };
            if capture.caller() != caller
                || state
                    .progress()
                    .provider_wait_observation(caller.current_binding(lanes)?.reply_object)
                    != Some(capture.observation())
            {
                return Err(STATUS_INVALID_HANDLE);
            }
            (capture, state.active_resume())
        };
        self.validate_retained(caller, pm, catalog, lanes)?;
        let lane = caller.dispatch.lane();
        if lanes.external_depth(lane) != Ok(0) {
            return Err(STATUS_INVALID_HANDLE);
        }
        if lanes.phase(lane) == Ok(LanePhase::Suspended) && lanes.suspension_count(lane) == Ok(1) {
            let frame = lanes
                .top(lane)
                .map_err(|_| STATUS_INVALID_HANDLE)?
                .ok_or(STATUS_INVALID_HANDLE)?;
            if frame.key == capture.key()
                && frame.owner == caller.owner()
                && frame.continuation.kernel_wait_capture() == Some(capture)
                && matches!(
                    frame.phase,
                    SuspensionPhase::Waiting
                        | SuspensionPhase::Selected { .. }
                        | SuspensionPhase::Cancelled { .. }
                )
            {
                return Ok(None);
            }
            return Err(STATUS_INVALID_HANDLE);
        }
        self.validate_wait_publication_state(caller, pm, catalog, lanes, previous, capture)?;
        Ok(Some(match previous {
            None => KernelProviderWaitWork::Initial(capture),
            Some(previous) => KernelProviderWaitWork::Repark {
                previous,
                next: capture,
            },
        }))
    }
}
