//! Native namespace adapter for field-borrowed canonical dispatcher waits.

use crate::*;
use nt_user_host::provider_dispatcher_backend::{
    dispatcher_lease_is_ready, ProviderDispatcherAccess, ProviderDispatcherLease,
    ProviderDispatcherObjects, ProviderEventBacking,
};

// The root dispatcher owns canonical sync state. Provider-side bodies never enter this table;
// its keys are local generation identities published through the authenticated broker.
static mut ROOT_PROVIDER_SYNC: Option<nt_provider_wait::ProviderLocalSyncCatalog> = None;

unsafe fn sync_catalog_mut(
    provider: nt_provider_wait::ProviderDomainIdentity,
) -> Result<&'static mut nt_provider_wait::ProviderLocalSyncCatalog, u32> {
    const INVALID_PARAMETER: u32 = 0xC000_000D;
    if !crate::win32k_provider_domain_is_current(provider) {
        return Err(INVALID_PARAMETER);
    }
    let slot = &mut *core::ptr::addr_of_mut!(ROOT_PROVIDER_SYNC);
    if slot.as_ref().is_some_and(|catalog| catalog.provider() != provider) {
        if slot.as_ref().is_none_or(|catalog| catalog.validate_domain_retirement().is_err()) {
            return Err(INVALID_PARAMETER);
        }
        // No sync object or lease survives the old provider generation.
        *slot = None;
    }
    if slot.is_none() {
        *slot = Some(nt_provider_wait::ProviderLocalSyncCatalog::new(provider)
            .map_err(|_| INVALID_PARAMETER)?);
    }
    let catalog = slot.as_mut().ok_or(INVALID_PARAMETER)?;
    if catalog.provider() != provider {
        return Err(INVALID_PARAMETER);
    }
    Ok(catalog)
}

unsafe fn sync_catalog_for_lease(
    lease: nt_provider_wait::ProviderLocalSyncLease,
) -> &'static mut nt_provider_wait::ProviderLocalSyncCatalog {
    let catalog = (&mut *core::ptr::addr_of_mut!(ROOT_PROVIDER_SYNC))
        .as_mut().expect("canonical sync catalog disappeared with a live wait lease");
    assert_eq!(catalog.snapshot_for_canonical(lease.canonical).ok().map(|snapshot| snapshot.id), Some(lease.id),
        "canonical sync lease changed physical identity");
    catalog
}

pub(crate) unsafe fn publish_sync(
    provider: nt_provider_wait::ProviderDomainIdentity,
    local_identity: u64,
    kind: nt_provider_wait::ProviderSyncKind,
) -> Result<nt_provider_wait::ProviderWaitObject, u32> {
    sync_catalog_mut(provider)?.publish(local_identity, kind)
        .map_err(|_| 0xC000_000Du32)
}

pub(crate) unsafe fn release_sync_semaphore(
    provider: nt_provider_wait::ProviderDomainIdentity,
    local_identity: u64,
    count: i32,
) -> Result<i32, u32> {
    sync_catalog_mut(provider)?.release_semaphore(local_identity, count)
        .map_err(|_| 0xC000_000Du32)
}

pub(crate) unsafe fn snapshot_sync(
    provider: nt_provider_wait::ProviderDomainIdentity,
    local_identity: u64,
    canonical: nt_provider_wait::ProviderWaitObject,
) -> Result<nt_provider_wait::ProviderLocalSyncSnapshot, u32> {
    sync_catalog_mut(provider)?.snapshot_bound(local_identity, canonical)
        .map_err(|_| 0xC000_000Du32)
}

pub(crate) unsafe fn release_sync_mutant(
    provider: nt_provider_wait::ProviderDomainIdentity,
    local_identity: u64,
    owner: nt_provider_wait::ProviderWaitOwner,
) -> Result<i32, u32> {
    sync_catalog_mut(provider)?.release_mutant(local_identity, owner)
        .map_err(|_| 0xC000_000Du32)
}

pub(crate) unsafe fn begin_retire_sync(
    provider: nt_provider_wait::ProviderDomainIdentity,
    local_identity: u64,
) -> Result<nt_provider_wait::ProviderLocalSyncRetirement, u32> {
    let catalog = sync_catalog_mut(provider)?;
    let id = catalog.snapshot_for_body(local_identity)
        .map_err(|_| 0xC000_000Du32)?.id;
    catalog.begin_retire_sync(id).map_err(|_| 0xC000_000Du32)
}

pub(crate) unsafe fn ack_retire_sync(
    provider: nt_provider_wait::ProviderDomainIdentity,
    local_identity: u64,
    canonical: nt_provider_wait::ProviderWaitObject,
) -> Result<(), u32> {
    let catalog = sync_catalog_mut(provider)?;
    let id = catalog.snapshot_for_body(local_identity)
        .map_err(|_| 0xC000_000Du32)?.id;
    catalog.ack_retirement(nt_provider_wait::ProviderLocalSyncRetirement { id, canonical })
        .map_err(|_| 0xC000_000Du32)
}

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

    fn acquire_sync_wait(
        &mut self,
        owner: nt_provider_wait::ProviderWaitOwner,
        object: nt_provider_wait::ProviderWaitObject,
    ) -> Result<nt_provider_wait::ProviderLocalSyncLease, u32> {
        let provider = nt_provider_wait::ProviderDomainIdentity {
            domain: owner.provider_domain,
            generation: owner.provider_generation,
        };
        unsafe { sync_catalog_mut(provider)?.acquire_wait(owner, object) }
            .map_err(|_| 0xC000_000Du32)
    }

    fn sync_wait_is_ready(&self, lease: nt_provider_wait::ProviderLocalSyncLease) -> bool {
        unsafe { sync_catalog_for_lease(lease).is_ready(lease) }
            .expect("canonical sync readiness lost its exact lease")
    }

    fn consume_sync_wait(&mut self, lease: nt_provider_wait::ProviderLocalSyncLease) {
        assert!(unsafe { sync_catalog_for_lease(lease).consume_ready(lease) }
            .expect("canonical sync consumption lost its exact lease"),
            "canonical sync waiter selected an unready object");
    }

    fn release_sync_wait(&mut self, lease: nt_provider_wait::ProviderLocalSyncLease) {
        unsafe { sync_catalog_for_lease(lease).release_wait(lease) }
            .expect("canonical sync wait release lost its exact lease");
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
        if let ProviderDispatcherLease::Sync(lease) = lease {
            return unsafe { sync_catalog_for_lease(lease).is_ready(lease) }
                .expect("canonical sync readiness lost its exact lease");
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
