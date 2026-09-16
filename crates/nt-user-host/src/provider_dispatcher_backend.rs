//! Field-borrowed dispatcher access, separate from live caller authentication and scheduling.

use nt_kernel_exec::{
    EventLeaseId, EventLeaseKind, EventObjectId, EventObjectOwner, EventObjectRegistry, EventStore,
    RetiredEventObject,
};
use nt_provider_wait::{
    ProviderDispatcherWaitBackend, ProviderTimerLeaseId, ProviderTimerTable, ProviderWaitObject,
    ProviderWaitObjectType, ProviderWaitOwner, SuspensionCaller,
};

const INVALID_PARAMETER: u32 = 0xC000_000D;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderDispatcherLease {
    Event(EventLeaseId),
    Timer(ProviderTimerLeaseId),
}

/// Object-access scope, not proof of caller liveness. The execution adapter must authenticate
/// the canonical caller immediately before borrowing the stores and keep that transaction
/// serialized. Kernel access never grants projected process Events or Timer admission.
#[derive(Clone, Copy)]
pub struct ProviderDispatcherAccess {
    owner: ProviderWaitOwner,
    process: Option<EventObjectOwner>,
}

impl ProviderDispatcherAccess {
    pub fn kernel_events(owner: ProviderWaitOwner) -> Result<Self, u32> {
        if !matches!(owner.caller, SuspensionCaller::Kernel { .. }) {
            return Err(INVALID_PARAMETER);
        }
        Ok(Self {
            owner,
            process: None,
        })
    }

    pub fn hosted(owner: ProviderWaitOwner, process_id: u64) -> Result<Self, u32> {
        let client = owner.hosted_client().ok_or(INVALID_PARAMETER)?;
        if process_id == 0 || client.client_generation == 0 {
            return Err(INVALID_PARAMETER);
        }
        Ok(Self {
            owner,
            process: Some(EventObjectOwner::new(process_id, client.client_generation)),
        })
    }
}

/// Native namespace validation and final retirement. Implementations must be memory-local:
/// no IPC, scheduler entry, or reentrant driver call while dispatcher fields are borrowed.
pub trait ProviderEventBacking {
    fn is_live_event(&self, native_identity: u64) -> bool;
    fn retire_event(&mut self, events: &mut EventStore, retired: RetiredEventObject);
    fn lease_acquired(&mut self) {}
    fn lease_released(&mut self) {}
}

/// Borrows original stores only; does not own a second registry, arbiter or process manager.
/// A `None` access scope permits selection/release of existing leases but forbids admission.
pub struct ProviderDispatcherObjects<'a, B> {
    pub events: &'a mut EventStore,
    pub event_objects: &'a mut EventObjectRegistry,
    pub timers: Option<&'a mut ProviderTimerTable>,
    pub backing: B,
    pub access: Option<ProviderDispatcherAccess>,
}

impl<B> ProviderDispatcherObjects<'_, B> {
    /// Publish timer readiness at the caller's sampled time without selecting a waiter or
    /// entering a provider. Existing wait leases remain owned by the canonical arbiter.
    pub fn expire_timers(&mut self, now: nt_kernel_exec::TimeSnapshot) -> u64 {
        let Some(timers) = self.timers.as_mut() else {
            return 0;
        };
        timers.expire_due(now)
    }
}

pub fn dispatcher_lease_is_ready(
    event_objects: &EventObjectRegistry,
    events: &EventStore,
    timers: Option<&ProviderTimerTable>,
    lease: ProviderDispatcherLease,
) -> bool {
    match lease {
        ProviderDispatcherLease::Event(lease) => {
            nt_kernel_exec::provider_event_wait_is_ready(event_objects, events, lease)
                .expect("provider Event wait lost its canonical lease or backing")
        }
        ProviderDispatcherLease::Timer(lease) => timers
            .expect("provider Timer table disappeared with a live wait lease")
            .is_ready(lease)
            .expect("provider Timer wait lost its canonical lease"),
    }
}

impl<B: ProviderEventBacking> ProviderDispatcherWaitBackend for ProviderDispatcherObjects<'_, B> {
    type Lease = ProviderDispatcherLease;
    type Error = u32;

    fn acquire_dispatcher_wait(
        &mut self,
        owner: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<Self::Lease, u32> {
        let access = self.access.ok_or(INVALID_PARAMETER)?;
        if owner != access.owner || owner.provider_domain == 0 || owner.provider_generation == 0 {
            return Err(INVALID_PARAMETER);
        }
        let lease = match object.typed() {
            Some(ProviderWaitObjectType::Event) => {
                let id = EventObjectId::from_wire_parts(object.object_id, object.object_generation)
                    .ok_or(INVALID_PARAMETER)?;
                let snapshot = self
                    .event_objects
                    .snapshot(id)
                    .map_err(|_| INVALID_PARAMETER)?;
                if !self.backing.is_live_event(snapshot.native_identity) {
                    return Err(INVALID_PARAMETER);
                }
                let provider =
                    EventObjectOwner::provider(owner.provider_domain, owner.provider_generation);
                let lease = match snapshot.owner {
                    EventObjectOwner::Provider { .. } => {
                        nt_kernel_exec::acquire_provider_local_event_wait(
                            self.event_objects,
                            self.events,
                            id,
                            provider,
                        )
                    }
                    EventObjectOwner::Process { .. } => {
                        nt_kernel_exec::acquire_projected_provider_event_wait(
                            self.event_objects,
                            self.events,
                            id,
                            provider,
                            access.process.ok_or(INVALID_PARAMETER)?,
                        )
                    }
                }
                .map_err(|_| INVALID_PARAMETER)?;
                ProviderDispatcherLease::Event(lease)
            }
            Some(ProviderWaitObjectType::Timer) if access.process.is_some() => {
                ProviderDispatcherLease::Timer(
                    self.timers
                        .as_mut()
                        .ok_or(INVALID_PARAMETER)?
                        .acquire_wait(owner, object)
                        .map_err(|_| INVALID_PARAMETER)?,
                )
            }
            _ => return Err(INVALID_PARAMETER),
        };
        self.backing.lease_acquired();
        Ok(lease)
    }

    fn dispatcher_is_ready(&self, lease: Self::Lease) -> bool {
        dispatcher_lease_is_ready(
            self.event_objects,
            self.events,
            self.timers.as_deref(),
            lease,
        )
    }

    fn consume_ready_dispatcher(&mut self, lease: Self::Lease) {
        match lease {
            ProviderDispatcherLease::Event(lease) => assert!(
                nt_kernel_exec::consume_provider_event_wait(self.event_objects, self.events, lease)
                    .expect("provider Event wait lost its canonical lease or backing"),
                "provider Event wait selected an unsignalled object"
            ),
            ProviderDispatcherLease::Timer(lease) => self
                .timers
                .as_mut()
                .expect("provider Timer table disappeared with a live wait lease")
                .consume_ready(lease)
                .expect("provider Timer wait selected an unsignalled object"),
        }
    }

    fn release_dispatcher_wait(&mut self, lease: Self::Lease) {
        match lease {
            ProviderDispatcherLease::Event(lease) => {
                if let Some(retired) = self
                    .event_objects
                    .release_wait(lease, EventLeaseKind::ProviderWait)
                    .expect("provider Event wait lost its exact lease during release")
                {
                    self.backing.retire_event(self.events, retired);
                }
            }
            ProviderDispatcherLease::Timer(lease) => {
                self.timers
                    .as_mut()
                    .expect("provider Timer table disappeared with a live wait lease")
                    .release_wait(lease)
                    .expect("provider Timer wait lost its exact lease during release");
            }
        }
        self.backing.lease_released();
    }
}

#[cfg(test)]
#[path = "provider_dispatcher_backend_tests.rs"]
mod tests;
