//! Serialized Event selection, independent of continuation storage and reply transport.

use crate::{
    DispatcherWaitSource, EventObjectId, EventObjectOwner, EventObjectRegistry, EventStore,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventSignalMode {
    Set,
    Pulse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnobservedEventSignalError {
    InvalidIdentity,
    InvalidBacking,
    Observed,
}

/// Perform a provider-local signal only when no references or pending effects can observe it.
/// The adapter authenticates the provider and validates the backing namespace, supplying its
/// legacy wait-reference count. Both stores must belong to the same serialized dispatcher owner;
/// neither a copied diagnostic snapshot nor a missing scheduler proves absence of observers.
pub fn signal_unobserved_provider_event(
    registry: &EventObjectRegistry,
    events: &mut EventStore,
    id: EventObjectId,
    provider: EventObjectOwner,
    local: u64,
    external_wait_references: u32,
    mode: EventSignalMode,
) -> Result<(bool, bool), UnobservedEventSignalError> {
    use UnobservedEventSignalError::*;
    if !matches!(provider, EventObjectOwner::Provider { domain, generation }
        if domain != 0 && generation != 0)
        || local == 0
    {
        return Err(InvalidIdentity);
    }
    let snapshot = registry.snapshot(id).map_err(|_| InvalidIdentity)?;
    if snapshot.owner != provider
        || snapshot.provider_local_identity != Some(local)
        || snapshot.provider_body.is_some()
        || snapshot.delete_pending
    {
        return Err(InvalidIdentity);
    }
    if [
        external_wait_references,
        snapshot.handle_leases,
        snapshot.pointer_leases,
        snapshot.native_wait_leases,
        snapshot.gui_wait_leases,
        snapshot.provider_wait_leases,
        snapshot.operation_leases,
        snapshot.signal_leases,
    ]
    .into_iter()
    .any(|count| count != 0)
    {
        return Err(Observed);
    }
    // With no observers and no callouts, a pulse need not expose its transient signaled state.
    let previous = match mode {
        EventSignalMode::Set => events.set_existing(snapshot.native_identity),
        EventSignalMode::Pulse => events.reset_existing(snapshot.native_identity),
    }
    .ok_or(InvalidBacking)?;
    Ok((previous, mode == EventSignalMode::Set))
}

/// The adapter retains the triggering Event throughout this transaction. Candidate queries must
/// report only ready waits consuming that exact Event, including complete wait-all readiness.
/// Selection consumes one whole wait transaction and durably removes its candidate from further
/// arbitration. Neither selection nor clearing may deliver replies, resume code, or admit waits.
pub trait EventSignalSelector {
    fn oldest_ready(&self, source: DispatcherWaitSource) -> Option<u64>;
    fn select(&mut self, source: DispatcherWaitSource, sequence: u64);
    fn clear(&mut self);
}

/// Arbitrate a newly signaled Event. Recompute after every consumption: a wait-all can consume
/// another synchronization object needed by a candidate from a different continuation family.
/// Delivery is the caller's responsibility after this returns, with pulse state already cleared.
pub fn select_event_signal<B: EventSignalSelector>(backend: &mut B, mode: EventSignalMode) -> u64 {
    let mut selected = 0;
    loop {
        let next = [
            DispatcherWaitSource::Native,
            DispatcherWaitSource::Gui,
            DispatcherWaitSource::Provider,
        ]
        .into_iter()
        .filter_map(|source| {
            backend
                .oldest_ready(source)
                .filter(|sequence| *sequence != 0)
                .map(|sequence| (source, sequence))
        })
        .min_by_key(|(_, sequence)| *sequence);
        let Some((source, sequence)) = next else {
            break;
        };
        backend.select(source, sequence);
        selected += 1;
    }
    if mode == EventSignalMode::Pulse {
        backend.clear();
    }
    selected
}

#[cfg(test)]
#[path = "event_signal_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "unobserved_event_signal_tests.rs"]
mod unobserved_tests;
