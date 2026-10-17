//! Provider-side storage authority for embedded KMUTEX and KSEMAPHORE objects.

use super::*;
use nt_provider_wait::{ProviderLocalSyncCatalog, ProviderLocalSyncId, ProviderLocalSyncLease,
    ProviderLocalSyncRetirement, ProviderSyncKind, ProviderWaitObject, ProviderWaitOwner};

static mut LOCAL: Option<ProviderLocalSyncCatalog> = None;
const KMUTEX_BYTES: u64 = 0x38;
const KSEMAPHORE_BYTES: u64 = 0x20;

unsafe fn catalog_mut() -> Option<&'static mut ProviderLocalSyncCatalog> {
    (&mut *core::ptr::addr_of_mut!(LOCAL)).as_mut()
}

unsafe fn catalog() -> Option<&'static ProviderLocalSyncCatalog> {
    (&*core::ptr::addr_of!(LOCAL)).as_ref()
}

/// Called while the event/timer catalogs are published under the same metadata guard.
pub(super) unsafe fn initialize_under_metadata(provider: nt_provider_wait::ProviderDomainIdentity) -> bool {
    if catalog().is_some() { return false; }
    let Ok(state) = ProviderLocalSyncCatalog::new(provider) else { return false; };
    *core::ptr::addr_of_mut!(LOCAL) = Some(state);
    true
}

pub(super) unsafe fn backing_count(backing: nt_provider_wait::ProviderEventBacking) -> usize {
    catalog().map_or(usize::MAX, |catalog| catalog.backing_sync_count(backing))
}

pub(super) unsafe fn validate_backing_retirement(backing: nt_provider_wait::ProviderEventBacking) -> bool {
    catalog().is_some_and(|catalog| catalog.validate_backing_retirement(backing).is_ok())
}

fn encoded(canonical: ProviderWaitObject) -> u64 {
    ((canonical.object_type as u64) << 32) | canonical.object_generation
}

unsafe fn retire_one(retirement: ProviderLocalSyncRetirement) -> bool {
    let (status, object_id, generation, kind) = win32k_event_broker_call(
        W32_SYNC_OP_RETIRE, retirement.id.raw(), 0, 0,
    );
    if status != 0 || object_id != retirement.canonical.object_id
        || generation != retirement.canonical.object_generation
        || kind != retirement.canonical.object_type as u64
    { return false; }
    let (status, _, _, _) = win32k_event_broker_call(
        W32_SYNC_OP_ACK_RETIREMENT,
        retirement.id.raw(), retirement.canonical.object_id,
        encoded(retirement.canonical),
    );
    if status != 0 { return false; }
    let _metadata = ProviderMetadataGuard::acquire();
    catalog_mut().is_some_and(|catalog| catalog.ack_retirement(retirement).is_ok())
}

pub(super) unsafe fn retire_backing(backing: nt_provider_wait::ProviderEventBacking) -> bool {
    let retirements = {
        let _metadata = ProviderMetadataGuard::acquire();
        let Some(catalog) = catalog_mut() else { return false; };
        match catalog.begin_retire_backing(backing) {
            Ok(retirements) => retirements,
            Err(nt_provider_wait::ProviderLocalSyncError::NotFound) => return true,
            Err(_) => return false,
        }
    };
    for retirement in retirements {
        if !retire_one(retirement) { return false; }
    }
    true
}

unsafe fn retire_existing(body: u64) -> bool {
    let retirement = {
        let _metadata = ProviderMetadataGuard::acquire();
        let Some(catalog) = catalog_mut() else { return false; };
        let Ok(snapshot) = catalog.snapshot_for_body(body) else { return true; };
        match catalog.begin_retire_sync(snapshot.id) {
            Ok(retirement) => retirement,
            Err(_) => return false,
        }
    };
    retire_one(retirement)
}

unsafe fn admit_storage(body: u64, bytes: u64, kind: ProviderSyncKind) -> Option<ProviderLocalSyncId> {
    let allocation = with_provider_allocations(|allocations| {
        let allocation = allocations.containing(body, bytes).ok()?;
        catalog_mut()?.initialize_in_allocation(
            allocations, allocation.identity, body, bytes, kind,
        ).ok()
    }).flatten();
    if allocation.is_some() { return allocation; }
    let stack = (|| {
        let _metadata = ProviderMetadataGuard::acquire();
        let (activation, offset) = (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS))
            .as_ref()?.classify_event_storage(current_stack_pointer(), body, bytes).ok()?;
        catalog_mut()?.initialize_stack(
            body, activation.lane_id, u64::from(activation.lane.generation()),
            activation.dispatch_id, activation.generation, offset, kind,
        ).ok()
    })();
    if stack.is_some() { return stack; }
    let end = body.checked_add(bytes)?;
    if (body >= WIN32K_CODE_VA && end <= WIN32K_CODE_VA + WIN32K_IMAGE_BYTES)
        || crate::win32k_glue::image_loader::contains_loaded_writable_storage(body, bytes)
    {
        let _metadata = ProviderMetadataGuard::acquire();
        return catalog_mut()?.initialize_static(body, body - WIN32K_CODE_VA, kind).ok();
    }
    None
}

unsafe fn initialize_object(body: u64, bytes: u64, kind: ProviderSyncKind) -> bool {
    if body == 0 || !retire_existing(body) { return false; }
    let Some(id) = admit_storage(body, bytes, kind) else { return false; };
    let packed = match kind {
        ProviderSyncKind::Semaphore { initial_count, .. } =>
            (1u64 << 32) | u64::from(initial_count as u32),
        ProviderSyncKind::Mutant => 2u64 << 32,
    };
    let limit = match kind { ProviderSyncKind::Semaphore { limit, .. } => limit as u32 as u64,
                             ProviderSyncKind::Mutant => 0 };
    let (status, object_id, generation, _) = win32k_event_broker_call(
        W32_SYNC_OP_PUBLISH, id.raw(), packed, limit,
    );
    if status != 0 {
        let _metadata = ProviderMetadataGuard::acquire();
        if catalog_mut().is_none_or(|catalog| catalog.rollback_unpublished(id).is_err()) {
            crate::provider_bugcheck::report(0xc4, [W32_EVENT_LABEL, W32_SYNC_OP_PUBLISH, id.raw(), 4]);
        }
        return false;
    }
    let object_type = match kind {
        ProviderSyncKind::Semaphore { .. } => nt_provider_wait::ProviderWaitObjectType::Semaphore,
        ProviderSyncKind::Mutant => nt_provider_wait::ProviderWaitObjectType::Mutant,
    };
    let canonical = ProviderWaitObject::new(object_type, object_id, generation);
    let bound = {
        let _metadata = ProviderMetadataGuard::acquire();
        catalog_mut().is_some_and(|catalog| catalog.bind_canonical(id, canonical).is_ok())
    };
    if !bound { return false; }
    match kind {
        ProviderSyncKind::Semaphore { initial_count, limit } =>
            nt_kernel_exec::init_ksemaphore(body as *mut u8, initial_count, limit).is_ok(),
        ProviderSyncKind::Mutant => {
            let bytes = nt_kernel_exec::hosted_kmutex::initial_header(body);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), body as *mut u8, bytes.len());
            true
        }
    }
}

pub(super) extern "win64" fn ke_initialize_mutant(body: u64, _level: u32) {
    if !unsafe { initialize_object(body, KMUTEX_BYTES, ProviderSyncKind::Mutant) } {
        unsafe { crate::provider_bugcheck::report(0xc4, [W32_EVENT_LABEL, W32_SYNC_OP_PUBLISH, body, 1]); }
    }
}

pub(super) extern "win64" fn ke_initialize_semaphore(body: u64, count: i32, limit: i32) {
    if !unsafe { initialize_object(body, KSEMAPHORE_BYTES,
        ProviderSyncKind::Semaphore { initial_count: count, limit }) } {
        unsafe { crate::provider_bugcheck::report(0xc4, [W32_EVENT_LABEL, W32_SYNC_OP_PUBLISH, body, 2]); }
    }
}

pub(super) extern "win64" fn ke_release_mutant(body: u64, wait: u8) -> i32 {
    if wait != 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [W32_EVENT_LABEL, W32_SYNC_OP_RELEASE_MUTANT, body, 3]); }
    }
    let (id, lease) = unsafe { operation(body) };
    let (status, previous, _, _) = unsafe { win32k_event_broker_call(
        W32_SYNC_OP_RELEASE_MUTANT, id.raw(), 0, 0,
    ) };
    if status != 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [W32_EVENT_LABEL, W32_SYNC_OP_RELEASE_MUTANT, body, status as u32 as u64]); }
    }
    unsafe {
        if !refresh_header(body, id, lease.canonical) {
            crate::provider_bugcheck::report(0xc4, [W32_EVENT_LABEL, W32_SYNC_OP_QUERY, body, 1]);
        }
        release_operation(lease);
    }
    previous as u32 as i32
}

pub(super) extern "win64" fn ke_release_semaphore(body: u64, _increment: i32,
    adjustment: i32, wait: u8) -> i32 {
    if wait != 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [W32_EVENT_LABEL, W32_SYNC_OP_RELEASE_SEMAPHORE, body, 3]); }
    }
    let (id, lease) = unsafe { operation(body) };
    let (status, previous, _, _) = unsafe { win32k_event_broker_call(
        W32_SYNC_OP_RELEASE_SEMAPHORE, id.raw(), adjustment as u32 as u64, 0,
    ) };
    if status != 0 {
        unsafe { crate::provider_bugcheck::report(0xc4, [W32_EVENT_LABEL, W32_SYNC_OP_RELEASE_SEMAPHORE, body, status as u32 as u64]); }
    }
    unsafe {
        if !refresh_header(body, id, lease.canonical) {
            crate::provider_bugcheck::report(0xc4, [W32_EVENT_LABEL, W32_SYNC_OP_QUERY, body, 2]);
        }
        release_operation(lease);
    }
    previous as u32 as i32
}

unsafe fn operation(body: u64) -> (ProviderLocalSyncId, nt_provider_wait::ProviderLocalSyncOperationLease) {
    let _metadata = ProviderMetadataGuard::acquire();
    let catalog = catalog_mut().expect("provider sync catalog missing");
    let snapshot = catalog.snapshot_for_body(body).expect("sync operation lost body identity");
    let lease = catalog.acquire_operation(snapshot.id).expect("sync operation lease denied");
    (snapshot.id, lease)
}

unsafe fn release_operation(lease: nt_provider_wait::ProviderLocalSyncOperationLease) {
    let _metadata = ProviderMetadataGuard::acquire();
    catalog_mut().expect("provider sync catalog missing").release_operation(lease)
        .expect("sync operation lease lost");
}

/// Refresh the guest-visible dispatcher header from the root's selected state. The root may
/// consume a newly released count before the release broker reply reaches this component.
pub(super) unsafe fn refresh_header(
    body: u64,
    id: ProviderLocalSyncId,
    canonical: ProviderWaitObject,
) -> bool {
    let (status, state, owner_tid, owner_generation) = win32k_event_broker_call(
        W32_SYNC_OP_QUERY, id.raw(), canonical.object_id, encoded(canonical),
    );
    if status != 0 { return false; }
    let snapshot = {
        let _metadata = ProviderMetadataGuard::acquire();
        let Some(snapshot) = catalog().and_then(|catalog| catalog.snapshot_for_body(body).ok()) else {
            return false;
        };
        if snapshot.id != id || snapshot.canonical != Some(canonical) || snapshot.delete_pending {
            return false;
        }
        snapshot
    };
    let owner_thread = match snapshot.kind {
        ProviderSyncKind::Semaphore { .. } if owner_tid == 0 && owner_generation == 0 => 0,
        ProviderSyncKind::Mutant if owner_tid == 0 && owner_generation == 0 => 0,
        ProviderSyncKind::Mutant if owner_tid != 0 && owner_generation != 0 => {
            let Some(index) = thread_context_index_for_tid(owner_tid) else { return false; };
            if thread_ctx_generation(index) != owner_generation { return false; }
            let thread = thread_ctx_ethread(index);
            if thread == 0 { return false; }
            thread
        }
        _ => return false,
    };
    core::ptr::write_unaligned((body + 4) as *mut i32, state as u32 as i32);
    if matches!(snapshot.kind, ProviderSyncKind::Mutant) {
        core::ptr::write_unaligned((body + 0x28) as *mut u64, owner_thread);
    }
    true
}

pub(super) unsafe fn refresh_wait_header(body: u64, lease: ProviderLocalSyncLease) -> bool {
    refresh_header(body, lease.id, lease.canonical)
}

pub(super) unsafe fn wait_object(body: u64) -> Option<(ProviderWaitObject, ProviderLocalSyncLease)> {
    let owner: ProviderWaitOwner = current_provider_wait_owner()?;
    let mut metadata = ProviderMetadataGuard::acquire();
    let snapshot = catalog()?.snapshot_for_body(body).ok()?;
    if snapshot.delete_pending || !provider_wait_backing_active(
        &mut metadata, body,
        match snapshot.kind { ProviderSyncKind::Semaphore { .. } => KSEMAPHORE_BYTES,
                              ProviderSyncKind::Mutant => KMUTEX_BYTES },
        snapshot.storage.backing,
    ) { return None; }
    let canonical = snapshot.canonical?;
    let lease = catalog_mut()?.acquire_wait(owner, canonical).ok()?;
    Some((canonical, lease))
}

/// Caller already holds the provider metadata guard while releasing the mixed wait admission.
pub(super) unsafe fn release_wait_under_metadata(lease: ProviderLocalSyncLease) -> bool {
    catalog_mut().is_some_and(|catalog| catalog.release_wait(lease).is_ok())
}
