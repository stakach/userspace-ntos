//! Root-owned kernel provider activations, independent of hosted callback headers.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_component_suspension::{
    ComponentSuspensionLanes, LaneBinding, LaneDispatchIdentity, LaneHandle, LanePhase,
    SuspensionCaller, SuspensionOwner,
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

struct Activation {
    caller: KernelProviderCaller,
    native_caller: NativeHandleCaller,
    reference: NativeThreadProcessReference,
}

/// Holds both original requestor objects through dispatch, parking and uncertain completion.
/// Release is explicit and retryable; dropping this table is not reference retirement.
#[must_use = "retire all activations through their original ProcessManager"]
pub struct KernelProviderActivations {
    rows: Vec<Activation>,
}

impl KernelProviderActivations {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// The adapter authenticates the kernel thread and provider-to-channel routing before entry.
    /// Capture only a running physical job issued by the shared lane machinery. Reserve storage
    /// before acquiring either Ps reference; no fallible publication follows the pair acquisition.
    pub fn capture<C, R, T>(
        &mut self,
        pm: &mut ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        provider: ProviderDomainIdentity,
        lane: LaneHandle,
        native_caller: NativeHandleCaller,
    ) -> Result<KernelProviderCaller, u32> {
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
        self.rows.push(Activation {
            caller,
            native_caller,
            reference,
        });
        Ok(caller)
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
        let row = self
            .rows
            .iter()
            .find(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let lane = caller.dispatch.lane();
        if !row.reference.is_held()
            || catalog.identity() != Some(caller.catalog)
            || !catalog.contains(caller.provider)
            || lanes.phase(lane) != Ok(LanePhase::Running)
            || lanes.active_dispatch_identity(lane) != Ok(Some(caller.dispatch))
            || lanes.binding(lane) != Ok(caller.binding)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        pm.validate_native_handle_caller(row.native_caller)
    }

    /// Call only after native execution/reply ownership has ended or been safely cancelled. The
    /// exact record fences retries; caller exit and provider retirement do not invalidate cleanup.
    /// Failed reference release leaves the entire row available for a later retry.
    pub fn release(
        &mut self,
        caller: KernelProviderCaller,
        pm: &mut ProcessManager,
    ) -> Result<(), u32> {
        let index = self
            .rows
            .iter()
            .position(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        self.rows[index].reference.release(pm)?;
        self.rows.remove(index);
        Ok(())
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

impl Default for KernelProviderActivations {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "provider_kernel_activation_tests.rs"]
mod tests;
