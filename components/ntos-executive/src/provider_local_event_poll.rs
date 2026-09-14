//! A synchronous poll borrows the original stores and releases every lease before returning.

use super::*;
use crate::exec_handler::ProviderDispatcherLease;
use nt_provider_wait::{
    ProviderDispatcherWaitArbiter, ProviderDispatcherWaitBackend, ProviderWaitObject,
    ProviderWaitObjectType, ProviderWaitOwner, ProviderWaitRequest,
};

struct LocalEventPoll<'a, 'state> {
    state: &'a mut LocalEventState<'state>,
    owner: ProviderWaitOwner,
}

impl LocalEventState<'_> {
    pub(crate) fn poll(
        &mut self,
        arbiter: &ProviderDispatcherWaitArbiter<ProviderDispatcherLease>,
        request: &ProviderWaitRequest,
        owner: ProviderWaitOwner,
    ) -> Result<i32, u32> {
        if !matches!(
            owner.caller,
            nt_provider_wait::SuspensionCaller::Kernel { .. }
        ) {
            return Err(INVALID_PARAMETER);
        }
        arbiter
            .poll(&mut LocalEventPoll { state: self, owner }, request, owner)
            .map_err(|error| match error {
                nt_provider_wait::ProviderDispatcherWaitError::Backend(status) => status,
                _ => INVALID_PARAMETER,
            })
    }
}

impl ProviderDispatcherWaitBackend for LocalEventPoll<'_, '_> {
    type Lease = ProviderDispatcherLease;
    type Error = u32;

    fn acquire_dispatcher_wait(
        &mut self,
        owner: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<Self::Lease, u32> {
        if owner != self.owner || object.typed() != Some(ProviderWaitObjectType::Event) {
            return Err(INVALID_PARAMETER);
        }
        let id = EventObjectId::from_wire_parts(object.object_id, object.object_generation)
            .ok_or(INVALID_PARAMETER)?;
        let snapshot = self
            .state
            .event_objects
            .snapshot(id)
            .map_err(|_| INVALID_PARAMETER)?;
        let provider = ProviderDomainIdentity {
            domain: owner.provider_domain,
            generation: owner.provider_generation,
        };
        let local = snapshot.provider_local_identity.ok_or(INVALID_PARAMETER)?;
        let (resolved, _, _, _) = self.state.identity(provider, local)?;
        if resolved != id {
            return Err(INVALID_PARAMETER);
        }
        let lease = nt_kernel_exec::acquire_provider_local_event_wait(
            self.state.event_objects,
            self.state.events,
            id,
            EventObjectOwner::provider(provider.domain, provider.generation),
        )
        .map_err(|_| INVALID_PARAMETER)?;
        crate::service_sec_image::provider_wait_record_dispatcher_lease_acquired();
        Ok(ProviderDispatcherLease::Event(lease))
    }

    fn dispatcher_is_ready(&self, lease: Self::Lease) -> bool {
        let ProviderDispatcherLease::Event(lease) = lease else {
            panic!("local Event poll acquired a non-Event lease");
        };
        nt_kernel_exec::provider_event_wait_is_ready(
            self.state.event_objects,
            self.state.events,
            lease,
        )
        .expect("local Event poll lost its canonical lease or backing")
    }

    fn consume_ready_dispatcher(&mut self, lease: Self::Lease) {
        let ProviderDispatcherLease::Event(lease) = lease else {
            panic!("local Event poll acquired a non-Event lease");
        };
        assert!(nt_kernel_exec::consume_provider_event_wait(
            self.state.event_objects,
            self.state.events,
            lease,
        )
        .expect("local Event poll lost its canonical lease or backing"));
    }

    fn release_dispatcher_wait(&mut self, lease: Self::Lease) {
        let ProviderDispatcherLease::Event(lease) = lease else {
            panic!("local Event poll acquired a non-Event lease");
        };
        if let Some(retired) = self
            .state
            .event_objects
            .release_wait(lease, nt_kernel_exec::EventLeaseKind::ProviderWait)
            .expect("local Event poll lost its exact lease during release")
        {
            finalize_local_backing(self.state.obj_ns, self.state.events, retired);
        }
        crate::service_sec_image::provider_wait_record_dispatcher_lease_released();
    }
}
