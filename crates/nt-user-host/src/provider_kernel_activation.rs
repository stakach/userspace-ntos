//! Root-owned kernel provider activations, independent of hosted callback headers.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_component_suspension::{
    ComponentSuspensionLanes, LaneBinding, LaneDispatchIdentity, LaneHandle, LanePhase,
    RetiredTerminal, SuspensionCaller, SuspensionKey, SuspensionOwner, TerminalIdentity,
    TerminalPhase,
};
use nt_process::{
    native_handle::{NativeHandleCaller, NativeThreadProcessReference},
    ProcessManager, ThreadLifetime, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER,
};
use nt_provider_wait::{CatalogIdentity, ProviderDomainCatalog, ProviderDomainIdentity};

static NEXT_ACTIVATION: AtomicU64 = AtomicU64::new(1);

fn next_activation(counter: &AtomicU64) -> Result<u64, u32> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            if value == 0 {
                None
            } else {
                value.checked_add(1)
            }
        })
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)
}

/// Copyable routing metadata only. Admission requires the matching retained table row, live
/// provider catalog, physical dispatch and canonical ProcessManager, not possession of this copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelProviderCaller {
    activation: u64,
    catalog: CatalogIdentity,
    provider: ProviderDomainIdentity,
    dispatch: LaneDispatchIdentity,
    binding: LaneBinding,
    thread: ThreadLifetime,
}

impl KernelProviderCaller {
    pub const fn owner(self) -> SuspensionOwner {
        SuspensionOwner {
            provider_domain: self.provider.domain,
            provider_generation: self.provider.generation,
            dispatch_id: self.dispatch.epoch(),
            caller: SuspensionCaller::Kernel {
                lane: self.dispatch.lane(),
            },
        }
    }

    pub const fn binding(self) -> LaneBinding {
        self.binding
    }

    pub const fn thread(self) -> ThreadLifetime {
        self.thread
    }
}

struct Activation<D> {
    caller: KernelProviderCaller,
    native_caller: NativeHandleCaller,
    reference: NativeThreadProcessReference,
    completion: Option<Completion>,
    recipient: D,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Completion {
    TerminalPending {
        status: u32,
        terminal: TerminalIdentity,
    },
    Ready(u32),
}

/// Exact metadata for a retained, observed kernel return. Copying this receipt does not transfer
/// ownership; only acknowledgment through the originating table can release the requestor pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelProviderCompletionReceipt {
    caller: KernelProviderCaller,
    status: u32,
}

impl KernelProviderCompletionReceipt {
    pub const fn caller(self) -> KernelProviderCaller {
        self.caller
    }

    pub const fn status(self) -> u32 {
        self.status
    }
}

/// Holds both original requestor objects through dispatch, parking and uncertain completion.
/// Release is explicit and retryable; dropping this table is not reference retirement.
#[must_use = "retire all activations through their original ProcessManager"]
pub struct KernelProviderActivations<D = ()> {
    rows: Vec<Activation<D>>,
}

impl<D> KernelProviderActivations<D> {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// The adapter authenticates the kernel thread and provider-to-channel routing before entry.
    /// Capture only a running physical job issued by the shared lane machinery. Reserve storage
    /// before acquiring either Ps reference; no fallible publication follows the pair acquisition.
    /// The recipient is owned by this same row across parking and failed acknowledgment.
    /// Rejection returns it unchanged; successful publication cannot allocate after Ps capture.
    pub fn capture_with_recipient<C, R, T>(
        &mut self,
        pm: &mut ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        provider: ProviderDomainIdentity,
        lane: LaneHandle,
        native_caller: NativeHandleCaller,
        recipient: D,
    ) -> Result<KernelProviderCaller, (u32, D)> {
        let prepared = (|| {
            let catalog_identity = catalog.identity().ok_or(STATUS_INVALID_HANDLE)?;
            if !catalog.contains(provider) || lanes.phase(lane) != Ok(LanePhase::Running) {
                return Err(STATUS_INVALID_HANDLE);
            }
            let dispatch = lanes
                .active_dispatch_identity(lane)
                .map_err(|_| STATUS_INVALID_HANDLE)?
                .ok_or(STATUS_INVALID_HANDLE)?;
            // A physical dispatch cannot acquire a second logical caller, even in another domain.
            if self.rows.iter().any(|row| row.caller.dispatch == dispatch) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let binding = lanes.binding(lane).map_err(|_| STATUS_INVALID_HANDLE)?;
            self.rows
                .try_reserve(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            let activation = next_activation(&NEXT_ACTIVATION)?;
            let reference = pm.reference_native_requestor(native_caller)?;
            let caller = KernelProviderCaller {
                activation,
                catalog: catalog_identity,
                provider,
                dispatch,
                binding,
                thread: reference.thread_lifetime(),
            };
            Ok((caller, reference))
        })();
        let (caller, reference) = match prepared {
            Ok(prepared) => prepared,
            Err(status) => return Err((status, recipient)),
        };
        self.rows.push(Activation {
            caller,
            native_caller,
            reference,
            completion: None,
            recipient,
        });
        Ok(caller)
    }

    /// Routing/destination metadata only; accessing it does not authorize execution or completion.
    pub fn recipient(&self, caller: KernelProviderCaller) -> Result<&D, u32> {
        self.rows
            .iter()
            .find(|row| row.caller == caller)
            .map(|row| &row.recipient)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Update local metadata of an unfinished activation only. Do not hold this borrow across
    /// native mechanisms, replace its destination, or treat metadata as dispatch authority.
    pub fn recipient_mut(&mut self, caller: KernelProviderCaller) -> Result<&mut D, u32> {
        self.rows
            .iter_mut()
            .find(|row| row.caller == caller && row.completion.is_none())
            .map(|row| &mut row.recipient)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Validate an owned, unfinished job in either its running or suspended phase. Caller exit
    /// does not discard its native stack or Ps references; this check never authorizes execution.
    pub fn validate_retained<C, R, T>(
        &self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<(), u32> {
        let row = self
            .rows
            .iter()
            .find(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let lane = caller.dispatch.lane();
        row.reference.validate(pm)?;
        if row.completion.is_some()
            || catalog.identity() != Some(caller.catalog)
            || !catalog.contains(caller.provider)
            || !matches!(
                lanes.phase(lane),
                Ok(LanePhase::Running | LanePhase::Suspended)
            )
            || lanes.active_dispatch_identity(lane) != Ok(Some(caller.dispatch))
            || lanes.binding(lane) != Ok(caller.binding)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    /// Re-admit execution, not lifetime cleanup. A parked or completed lane cannot issue work;
    /// a resumed exact job can. Never recapture the current thread to authenticate an older job.
    pub fn validate<C, R, T>(
        &self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
    ) -> Result<(), u32> {
        self.validate_retained(caller, pm, catalog, lanes)?;
        if lanes.phase(caller.dispatch.lane()) != Ok(LanePhase::Running) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let row = self
            .rows
            .iter()
            .find(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        pm.validate_native_handle_caller(row.native_caller)
    }

    /// Record only a genuine provider return observed by the authenticated native adapter.
    /// Readiness, timeout, cancellation and a stopped pump are not evidence of return. Finish
    /// the exact physical job before publishing its result; active frames prevent completion.
    pub fn record_completion<C, R, T>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        status: u32,
    ) -> Result<KernelProviderCompletionReceipt, u32> {
        self.validate_retained(caller, pm, catalog, lanes)?;
        if lanes.phase(caller.dispatch.lane()) != Ok(LanePhase::Running) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        lanes
            .finish_dispatch(caller.dispatch.lane(), caller.binding.reply_object)
            .map_err(|_| STATUS_INVALID_HANDLE)?;
        row.completion = Some(Completion::Ready(status));
        Ok(KernelProviderCompletionReceipt { caller, status })
    }

    /// Retain an observed return from the final resumed suspension and its terminal authority
    /// together. The adapter supplies the actual return status, not the wait selection result.
    /// No new frame or external token is manufactured; nested work must finish first. Rejection
    /// returns the owned payload, leaving both activation and source suspension unchanged.
    pub fn retain_terminal_completion<C, R, T>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        key: SuspensionKey,
        payload: T,
        status: u32,
    ) -> Result<TerminalIdentity, (u32, T)> {
        if let Err(status) = self.validate_retained(caller, pm, catalog, lanes) {
            return Err((status, payload));
        }
        let lane = caller.dispatch.lane();
        if lanes.phase(lane) != Ok(LanePhase::Running)
            || lanes.suspension_count(lane) != Ok(1)
            || lanes.external_depth(lane) != Ok(0)
        {
            return Err((STATUS_INVALID_HANDLE, payload));
        }
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.caller == caller)
            .expect("validated activation disappeared before terminal retention");
        let terminal = lanes
            .retain_terminal_running(
                lane,
                caller.binding.reply_object,
                key,
                caller.owner(),
                payload,
            )
            .map_err(|(_, payload)| (STATUS_INVALID_HANDLE, payload))?;
        // All fallible validation precedes the lane transition; publication cannot allocate.
        row.completion = Some(Completion::TerminalPending { status, terminal });
        Ok(terminal)
    }

    /// Authenticate retained terminal ownership before local delivery bookkeeping. This does
    /// not authorize provider execution or receipt acknowledgment. Caller/provider exit does
    /// not invalidate cleanup, but the original Ps pair and exact physical terminal must remain.
    pub fn validate_terminal_completion<C, R, T>(
        &self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        terminal: TerminalIdentity,
    ) -> Result<(), u32> {
        let row = self
            .rows
            .iter()
            .find(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if !matches!(row.completion,
            Some(Completion::TerminalPending { terminal: retained, .. }) if retained == terminal)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        row.reference.validate(pm)?;
        let lane = caller.dispatch.lane();
        if terminal.lane() != lane
            || terminal.owner() != caller.owner()
            || terminal.external_token().is_some()
            || lanes.active_dispatch_identity(lane) != Ok(Some(caller.dispatch))
            || lanes.binding(lane) != Ok(caller.binding)
            || lanes.suspension_count(lane) != Ok(1)
            || lanes.external_depth(lane) != Ok(0)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        lanes
            .terminal(terminal, caller.binding.reply_object)
            .map_err(|_| STATUS_INVALID_HANDLE)?;
        Ok(())
    }

    /// Publish a deliverable receipt only after exact terminal retirement. Before performing
    /// local bookkeeping, the adapter must validate_terminal_completion and observe the
    /// terminal's Acknowledged phase. External mechanisms belong to the ticketed terminal
    /// stages, outside borrowed coordinator state; local_retirement reports only local
    /// bookkeeping. Its failure retains the pending status for local retry, not mechanism replay.
    pub fn finish_terminal_completion<C, R: Clone, T>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        terminal: TerminalIdentity,
        local_retirement: Result<(), u32>,
    ) -> Result<Option<(KernelProviderCompletionReceipt, RetiredTerminal<C, R, T>)>, u32> {
        self.validate_terminal_completion(caller, pm, lanes, terminal)?;
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let Some(Completion::TerminalPending { status, .. }) = row.completion else {
            unreachable!("validated pending terminal lost its completion");
        };
        if !matches!(
            lanes
                .terminal(terminal, caller.binding.reply_object)
                .map_err(|_| STATUS_INVALID_HANDLE)?
                .phase,
            TerminalPhase::Acknowledged { .. }
        ) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let Some(retired) = lanes
            .finish_terminal(terminal, caller.binding.reply_object, local_retirement)
            .map_err(|_| STATUS_INVALID_HANDLE)?
        else {
            return Ok(None);
        };
        // finish_terminal retires the last frame and makes the lane Idle. Do not call the
        // frame-free Running completion path here; the exact return is already retained.
        row.completion = Some(Completion::Ready(status));
        Ok(Some((
            KernelProviderCompletionReceipt { caller, status },
            retired,
        )))
    }

    pub fn completion(
        &self,
        caller: KernelProviderCaller,
    ) -> Result<KernelProviderCompletionReceipt, u32> {
        let status = self
            .rows
            .iter()
            .find(|row| row.caller == caller)
            .and_then(|row| match row.completion {
                Some(Completion::Ready(status)) => Some(status),
                _ => None,
            })
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok(KernelProviderCompletionReceipt { caller, status })
    }

    /// Acknowledge the exact retained result after delivery. No provider, dispatch or caller
    /// liveness is required; failure preserves both the result and the complete reference pair.
    /// Transfer its owned destination only after successful pair retirement. No fallible work
    /// follows release; failure leaves destination, result and references in the original row.
    pub fn acknowledge_completion_with_recipient(
        &mut self,
        receipt: KernelProviderCompletionReceipt,
        pm: &mut ProcessManager,
    ) -> Result<(u32, D), u32> {
        let index = self
            .rows
            .iter()
            .position(|row| {
                row.caller == receipt.caller
                    && row.completion == Some(Completion::Ready(receipt.status))
            })
            .ok_or(STATUS_INVALID_HANDLE)?;
        self.rows[index].reference.release(pm)?;
        let row = self.rows.remove(index);
        Ok((receipt.status, row.recipient))
    }

    /// Call only after native execution/reply ownership has ended or been safely cancelled. The
    /// exact record fences retries; caller exit and provider retirement do not invalidate cleanup.
    /// Failed reference release leaves the entire row available for a later retry.
    pub fn release_with_recipient(
        &mut self,
        caller: KernelProviderCaller,
        pm: &mut ProcessManager,
    ) -> Result<D, u32> {
        let index = self
            .rows
            .iter()
            .position(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if self.rows[index].completion.is_some() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.rows[index].reference.release(pm)?;
        Ok(self.rows.remove(index).recipient)
    }

    /// Includes terminal/failed-release rows, not merely jobs currently executing on a lane.
    pub fn retained_for_provider(
        &self,
        catalog: CatalogIdentity,
        provider: ProviderDomainIdentity,
    ) -> usize {
        self.rows
            .iter()
            .filter(|row| row.caller.catalog == catalog && row.caller.provider == provider)
            .count()
    }
}

impl KernelProviderActivations<()> {
    pub fn capture<C, R, T>(
        &mut self,
        pm: &mut ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        provider: ProviderDomainIdentity,
        lane: LaneHandle,
        native_caller: NativeHandleCaller,
    ) -> Result<KernelProviderCaller, u32> {
        self.capture_with_recipient(pm, catalog, lanes, provider, lane, native_caller, ())
            .map_err(|(status, ())| status)
    }

    pub fn acknowledge_completion(
        &mut self,
        receipt: KernelProviderCompletionReceipt,
        pm: &mut ProcessManager,
    ) -> Result<u32, u32> {
        self.acknowledge_completion_with_recipient(receipt, pm)
            .map(|(status, ())| status)
    }

    pub fn release(
        &mut self,
        caller: KernelProviderCaller,
        pm: &mut ProcessManager,
    ) -> Result<(), u32> {
        self.release_with_recipient(caller, pm)
    }
}

impl<D> Default for KernelProviderActivations<D> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "provider_kernel_activation_tests.rs"]
mod tests;
