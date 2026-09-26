//! Native namespace adapter for field-borrowed canonical dispatcher waits.

use crate::*;
use nt_user_host::provider_dispatcher_backend::{
    dispatcher_lease_is_ready, ProviderDispatcherAccess, ProviderDispatcherLease,
    ProviderDispatcherObjects, ProviderEventBacking,
};

pub(crate) struct NativeEventBacking<'a> {
    pub objects: &'a mut [ObjEntry],
    pub file_completion: Option<&'a mut ExecFileCompletion>,
}

impl ProviderEventBacking for NativeEventBacking<'_> {
    fn is_live_event(&self, native_identity: u64) -> bool {
        usize::try_from(native_identity)
            .ok()
            .and_then(|index| self.objects.get(index))
            .is_some_and(|entry| entry.is_live() && entry.kind == OBJ_KIND_EVENT)
    }

    fn retire_event(
        &mut self,
        events: &mut nt_kernel_exec::EventStore,
        retired: nt_kernel_exec::RetiredEventObject,
    ) {
        finalize_retired_event(self.objects, events, retired);
    }

    fn acquire_file_wait(
        &mut self,
        owner: nt_provider_wait::ProviderWaitOwner,
        object: nt_provider_wait::ProviderWaitObject,
        process: Option<nt_kernel_exec::EventObjectOwner>,
    ) -> Result<u64, u32> {
        if process.is_none() {
            return Err(0xC000_000D);
        }
        crate::provider_file_wait::acquire(
            owner,
            object,
            self.file_completion.as_deref_mut().ok_or(0xC000_000Du32)?,
        )
    }

    fn file_wait_is_ready(&self, lease: u64) -> bool {
        self.file_completion.as_deref().is_some_and(|files| {
            crate::provider_file_wait::is_ready(lease, files)
        })
    }

    fn release_file_wait(&mut self, lease: u64) {
        crate::provider_file_wait::release(
            lease,
            self.file_completion.as_deref_mut().expect("File wait has no completion owner"),
        );
    }

    fn lease_acquired(&mut self) {
        crate::service_sec_image::provider_wait_record_dispatcher_lease_acquired();
    }

    fn lease_released(&mut self) {
        crate::service_sec_image::provider_wait_record_dispatcher_lease_released();
    }
}

pub(crate) fn finalize_retired_event(
    obj_ns: &mut [ObjEntry],
    events: &mut nt_kernel_exec::EventStore,
    retired: nt_kernel_exec::RetiredEventObject,
) {
    if retired.provider_local_identity.is_some() {
        crate::provider_local_event::finalize_local_backing(obj_ns, events, retired);
        return;
    }
    let Ok(index) = usize::try_from(retired.native_identity) else {
        return;
    };
    let Some(entry) = obj_ns.get(index) else {
        return;
    };
    if !entry.is_live() || entry.kind != OBJ_KIND_EVENT || entry.wait_references != 0 {
        return;
    }
    events.remove_existing(index as u64);
    obj_ns[index].unlink();
    if retired.provider_body.is_some() {
        // Only publish the existing memory-local reclaim marker; no provider IPC here.
        unsafe { crate::win32k_subsystem::mark_event_provider_reclaim_pending() };
    }
}

impl ExecNtHandler {
    pub(crate) fn dispatcher_objects(
        &mut self,
        access: Option<ProviderDispatcherAccess>,
    ) -> ProviderDispatcherObjects<'_, NativeEventBacking<'_>> {
        ProviderDispatcherObjects {
            events: &mut self.events,
            event_objects: &mut self.event_objects,
            timers: self.provider_timers.as_mut(),
            backing: NativeEventBacking {
                objects: &mut self.obj_ns,
                file_completion: Some(&mut self.file_completion),
            },
            access,
        }
    }
}

// Hosted admission still authenticates current process and provider generations on every call.
// Kernel activation transactions construct field-only objects after their own canonical check.
impl nt_provider_wait::ProviderDispatcherWaitBackend for ExecNtHandler {
    type Lease = ProviderDispatcherLease;
    type Error = u32;

    fn acquire_dispatcher_wait(
        &mut self,
        owner: nt_provider_wait::ProviderWaitOwner,
        object: nt_provider_wait::ProviderWaitObject,
    ) -> Result<Self::Lease, u32> {
        const INVALID_PARAMETER: u32 = 0xC000_000D;
        let client = owner.hosted_client().ok_or(INVALID_PARAMETER)?;
        let client_pid = self
            .pm_pid_for_pi(client.client_pi as usize)
            .ok_or(INVALID_PARAMETER)?;
        let provider = nt_provider_wait::ProviderDomainIdentity {
            domain: owner.provider_domain,
            generation: owner.provider_generation,
        };
        if !crate::win32k_provider_domain_is_current(provider)
            || self
                .hosted_process_generation(client.client_pi as usize)
                .unwrap_or(0)
                != client.client_generation
        {
            return Err(INVALID_PARAMETER);
        }
        let access = ProviderDispatcherAccess::hosted(owner, client_pid as u64)?;
        self.dispatcher_objects(Some(access))
            .acquire_dispatcher_wait(owner, object)
    }

    fn dispatcher_is_ready(&self, lease: Self::Lease) -> bool {
        if let ProviderDispatcherLease::File(token) = lease {
            return crate::provider_file_wait::is_ready(token, &self.file_completion);
        }
        dispatcher_lease_is_ready(
            &self.event_objects,
            &self.events,
            self.provider_timers.as_ref(),
            lease,
        )
    }

    fn consume_ready_dispatcher(&mut self, lease: Self::Lease) {
        self.dispatcher_objects(None)
            .consume_ready_dispatcher(lease);
    }

    fn release_dispatcher_wait(&mut self, lease: Self::Lease) {
        self.dispatcher_objects(None).release_dispatcher_wait(lease);
    }
}
