//! Backing-checked provider waits over the canonical Event registry and dispatcher store.

use crate::{
    EventLeaseId, EventLeaseKind, EventObjectError, EventObjectId, EventObjectOwner,
    EventObjectRegistry, EventStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderEventWaitError {
    Registry(EventObjectError),
    MissingBacking,
}

impl From<EventObjectError> for ProviderEventWaitError {
    fn from(error: EventObjectError) -> Self {
        Self::Registry(error)
    }
}

/// The adapter authenticates the live provider and validates its native namespace entry.
/// Registry and backing must share one serialized owner throughout admission and the wait.
pub fn acquire_provider_local_event_wait(
    registry: &mut EventObjectRegistry,
    events: &EventStore,
    id: EventObjectId,
    provider: EventObjectOwner,
) -> Result<EventLeaseId, ProviderEventWaitError> {
    require_backing(registry, events, id)?;
    Ok(registry.acquire_provider_local_wait(id, provider)?)
}

/// Admit a process Event through its retained projection pointer, not a raw provider address.
/// Deletion of the last process handle does not invalidate an existing pointer reference.
/// The adapter derives both owners from the authenticated live hosted dispatch.
pub fn acquire_projected_provider_event_wait(
    registry: &mut EventObjectRegistry,
    events: &EventStore,
    id: EventObjectId,
    provider: EventObjectOwner,
    client: EventObjectOwner,
) -> Result<EventLeaseId, ProviderEventWaitError> {
    let snapshot = registry.snapshot(id)?;
    if !matches!(provider, EventObjectOwner::Provider { domain, generation }
        if domain != 0 && generation != 0)
        || !matches!(client, EventObjectOwner::Process { process_id, process_generation }
            if process_id != 0 && process_generation != 0)
        || !matches!(snapshot.owner, EventObjectOwner::Process { .. })
        || !snapshot.authorizes_provider_wait(provider, client)
    {
        return Err(EventObjectError::InvalidOwner.into());
    }
    require_backing(registry, events, id)?;
    Ok(registry.acquire_wait(id, EventLeaseKind::ProviderWait)?)
}

/// Missing backing after successful admission is a caller invariant violation, not not-ready.
pub fn provider_event_wait_is_ready(
    registry: &EventObjectRegistry,
    events: &EventStore,
    lease: EventLeaseId,
) -> Result<bool, ProviderEventWaitError> {
    let id = registry.event_for_lease(lease, EventLeaseKind::ProviderWait)?;
    Ok(require_backing(registry, events, id)?.1)
}

/// Consume only an exact retained ProviderWait; notification Events remain signaled.
pub fn consume_provider_event_wait(
    registry: &EventObjectRegistry,
    events: &mut EventStore,
    lease: EventLeaseId,
) -> Result<bool, ProviderEventWaitError> {
    let id = registry.event_for_lease(lease, EventLeaseKind::ProviderWait)?;
    let (native, _) = require_backing(registry, events, id)?;
    Ok(events.consume_existing(native))
}

fn require_backing(
    registry: &EventObjectRegistry,
    events: &EventStore,
    id: EventObjectId,
) -> Result<(u64, bool), ProviderEventWaitError> {
    let native = registry.snapshot(id)?.native_identity;
    let (_, signaled) = events
        .query_existing(native)
        .ok_or(ProviderEventWaitError::MissingBacking)?;
    Ok((native, signaled))
}

#[cfg(test)]
#[path = "event_wait_tests.rs"]
mod tests;
