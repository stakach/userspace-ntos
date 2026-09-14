//! Canonical dispatcher state moved intact from bootstrap into the live executive.

use nt_kernel_exec::{EventObjectRegistry, EventStore};
use nt_provider_wait::ProviderTimerTable;

/// Event identities, state, leases and pending effects must travel together. The native adapter
/// must also move the backing namespace/index allocator without renumbering native identities.
/// Moving this aggregate does not consume signals, release leases, or acknowledge retirement.
///
/// ```compile_fail
/// use nt_user_host::dispatcher_state::DispatcherState;
/// let original = DispatcherState::new(8, 8);
/// let duplicate = original.clone();
/// ```
pub struct DispatcherState {
    pub events: EventStore,
    pub event_objects: EventObjectRegistry,
    pub provider_timers: Option<ProviderTimerTable>,
}

impl DispatcherState {
    pub fn new(event_capacity: usize, lease_capacity: usize) -> Self {
        Self {
            events: EventStore::with_capacity(event_capacity),
            event_objects: EventObjectRegistry::with_capacity(event_capacity, lease_capacity),
            provider_timers: None,
        }
    }
}

#[cfg(test)]
#[path = "dispatcher_state_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "provider_event_wait_tests.rs"]
mod provider_event_wait_tests;
