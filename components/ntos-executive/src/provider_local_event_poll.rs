//! Synchronous kernel polls use the same canonical backend as retained hosted waits.

use super::*;
use crate::provider_dispatcher_backend::NativeEventBacking;
use nt_provider_wait::{ProviderDispatcherWaitArbiter, ProviderWaitOwner, ProviderWaitRequest};
use nt_user_host::provider_dispatcher_backend::{
    ProviderDispatcherAccess, ProviderDispatcherLease, ProviderDispatcherObjects,
};

impl LocalEventState<'_> {
    pub(crate) fn poll(
        &mut self,
        arbiter: &ProviderDispatcherWaitArbiter<ProviderDispatcherLease>,
        request: &ProviderWaitRequest,
        owner: ProviderWaitOwner,
    ) -> Result<i32, u32> {
        let access = ProviderDispatcherAccess::kernel_events(owner)?;
        let mut backend = ProviderDispatcherObjects {
            events: self.events,
            event_objects: self.event_objects,
            timers: None,
            backing: NativeEventBacking(self.obj_ns),
            access: Some(access),
        };
        arbiter
            .poll(&mut backend, request, owner)
            .map_err(|error| match error {
                nt_provider_wait::ProviderDispatcherWaitError::Backend(status) => status,
                _ => INVALID_PARAMETER,
            })
    }
}
