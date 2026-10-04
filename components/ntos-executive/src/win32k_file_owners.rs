//! Per-open win32k FILE_OBJECT ownership backed by exact routed handle and I/O identities.

use alloc::vec::Vec;
use core::ptr::{addr_of, addr_of_mut};

use nt_io_manager::{
    consumer_file_projection::ConsumerFileProjection, DeviceId, FileId, FileReference,
    HostedDomainIdentity, HostedFileIdentity, HostedFilePublicationLease, HostedFileWaitLeaseLedger,
    WDM_X64_FILE_OBJECT_EVENT_OFFSET, WDM_X64_FILE_OBJECT_EVENT_SIGNAL_STATE_OFFSET,
    WDM_X64_FILE_OBJECT_SIZE,
};
use nt_process::{
    native_handle::{NativeHandleCaller, NativeHandleScope}, HandleObject, ProcessId,
};

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Building,
    Live,
    Retiring,
}

struct Row {
    id: u64,
    owner: ProcessId,
    handle: u64,
    file_id: FileId,
    device_id: DeviceId,
    address: u64,
    allocation: Option<crate::win32k_subsystem::RootProviderPoolAllocation>,
    identity: Option<HostedFileIdentity>,
    projection: Option<ConsumerFileProjection>,
    phase: Phase,
}

static mut ROWS: Vec<Row> = Vec::new();
static mut NEXT_ID: u64 = 1;
static mut WAIT_LEASES: HostedFileWaitLeaseLedger = HostedFileWaitLeaseLedger::new();
static mut WAIT_RECEIPTS: Vec<WaitReceipt> = Vec::new();

struct WaitReceipt {
    token: u64,
    row_id: u64,
    identity: HostedFileIdentity,
    releasing: bool,
    publication: Option<HostedFilePublicationLease>,
    reference: Option<FileReference>,
}

unsafe fn wait_leases() -> &'static mut HostedFileWaitLeaseLedger {
    &mut *addr_of_mut!(WAIT_LEASES)
}

unsafe fn wait_receipts() -> &'static mut Vec<WaitReceipt> {
    &mut *addr_of_mut!(WAIT_RECEIPTS)
}

unsafe fn rows() -> &'static mut Vec<Row> {
    &mut *addr_of_mut!(ROWS)
}

unsafe fn row(id: u64) -> Option<&'static mut Row> {
    rows().iter_mut().find(|row| row.id == id)
}

unsafe fn id_for_handle(owner: ProcessId, handle: u64, file_id: FileId) -> Option<u64> {
    rows().iter().find(|row| {
        row.owner == owner && row.handle == handle && row.file_id == file_id
    }).map(|row| row.id)
}

unsafe fn id_for_address(address: u64) -> Option<u64> {
    rows().iter().find(|row| row.address == address && address != 0).map(|row| row.id)
}

pub(crate) unsafe fn quiescent() -> bool {
    rows().is_empty() && wait_receipts().is_empty()
}

/// The publication lease held by the caller fences this exact root-owned allocation.
pub(crate) unsafe fn mode_projection_address(identity: HostedFileIdentity) -> Result<Option<u64>, u32> {
    let Some(owner) = rows().iter().find(|row| row.identity == Some(identity)) else {
        return Ok(None);
    };
    if owner.phase != Phase::Live || owner.file_id != identity.file_id()
        || owner.address != identity.address()
    {
        return Err(STATUS_INVALID_HANDLE as u32);
    }
    let allocation = owner.allocation.ok_or(STATUS_INVALID_HANDLE as u32)?;
    if allocation.address() != owner.address
        || allocation.length() < WDM_X64_FILE_OBJECT_SIZE as u64
    {
        return Err(STATUS_INVALID_HANDLE as u32);
    }
    Ok(Some(allocation.address()))
}

/// Admit an embedded FILE_OBJECT Event only while the exact projection is still referenced.
/// The row pin is recorded before acquiring independently owned canonical receipts, so
/// retirement cannot recycle its address during any external I/O-manager operation.
pub(crate) unsafe fn acquire_wait_identity_for_event(
    domain: HostedDomainIdentity,
    event: u64,
) -> Result<(HostedFileIdentity, u64), i32> {
    let id = rows()
        .iter()
        .find(|row| {
            row.address != 0
                && row.address.checked_add(WDM_X64_FILE_OBJECT_EVENT_OFFSET as u64) == Some(event)
        })
        .map(|row| row.id)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let identity = wait_identity_for_row(id, false)?;
    if identity.domain() != domain {
        return Err(STATUS_INVALID_HANDLE);
    }
    wait_receipts()
        .try_reserve(1)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let token = wait_leases().acquire(id, identity).map_err(|status| status.raw())?;
    wait_receipts().push(WaitReceipt {
        token,
        row_id: id,
        identity,
        releasing: false,
        publication: None,
        reference: None,
    });

    let result = (|| -> Result<(), i32> {
        let reference = io_manager_mut()
            .retain_file_reference(identity.file_id())
            .map_err(|status| status.raw())?;
        wait_receipts()
            .iter_mut()
            .find(|receipt| receipt.token == token)
            .ok_or(STATUS_INVALID_HANDLE)?
            .reference = Some(reference);
        let publication = io_manager_mut()
            .lease_hosted_file_identity(identity)
            .map_err(|status| status.raw())?;
        wait_receipts()
            .iter_mut()
            .find(|receipt| receipt.token == token)
            .ok_or(STATUS_INVALID_HANDLE)?
            .publication = Some(publication);
        Ok(())
    })();
    if let Err(status) = result {
        if release_wait_identity(identity.domain(), token).is_err() {
            park();
        }
        return Err(status);
    }
    Ok((identity, token))
}

/// Retain the token and any unreleased receipts on uncertainty. Redrive may complete a
/// partially released token without requiring LIFO pointer-reference behavior.
pub(crate) unsafe fn release_wait_identity(domain: HostedDomainIdentity, token: u64) -> Result<(), i32> {
    let index = wait_receipts()
        .iter()
        .position(|receipt| token != 0 && receipt.token == token)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let receipt = &mut wait_receipts()[index];
    if receipt.identity.domain() != domain {
        return Err(STATUS_INVALID_HANDLE);
    }
    receipt.releasing = true;
    if let Some(reference) = receipt.reference.as_mut() {
        io_manager_mut()
            .release_file_reference(reference)
            .map_err(|status| status.raw())?;
        receipt.reference = None;
    }
    if let Some(publication) = receipt.publication.as_mut() {
        io_manager_mut()
            .release_hosted_file_publication(publication)
            .map_err(|status| status.raw())?;
        receipt.publication = None;
    }
    wait_leases()
        .release(receipt.token, receipt.row_id, receipt.identity)
        .map_err(|status| status.raw())?;
    let row_id = receipt.row_id;
    wait_receipts().swap_remove(index);
    if row(row_id).is_some_and(|owner| owner.phase == Phase::Retiring) {
        let _ = retire(row_id);
    }
    Ok(())
}

pub(crate) unsafe fn wait_identity_for_canonical(
    file_id: u64,
    binding_generation: u64,
) -> Result<HostedFileIdentity, i32> {
    let id = rows()
        .iter()
        .find(|row| {
            row.identity.is_some_and(|identity| {
                identity.file_id().raw() == file_id
                    && identity.binding_generation() == binding_generation
            })
        })
        .map(|row| row.id)
        .ok_or(STATUS_INVALID_HANDLE)?;
    wait_identity_for_row(id, true)
}

unsafe fn wait_identity_for_row(id: u64, allow_wait_lease: bool) -> Result<HostedFileIdentity, i32> {
    let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    if row.phase == Phase::Building {
        return Err(STATUS_INVALID_HANDLE);
    }
    let identity = row.identity.ok_or(STATUS_INVALID_HANDLE)?;
    let projection = row.projection.as_ref().ok_or(STATUS_INVALID_HANDLE)?;
    if (projection.pointer_reference_count() == 0
        && !(allow_wait_lease && wait_leases().has_lease(id, identity)))
        || io_manager_mut()
            .hosted_file_identity_at(identity.domain(), identity.file_id(), identity.address())
            .map_err(|status| status.raw())?
            != Some(identity)
    {
        return Err(STATUS_INVALID_HANDLE);
    }
    Ok(identity)
}

/// Keep the visible WDM Event header coherent with the canonical completion table. Wait
/// admission and selection never trust this field as authority.
pub(crate) unsafe fn sync_event_signal(file_id: u64, signaled: bool) {
    for row in rows().iter() {
        if row.address != 0
            && row.identity.is_some_and(|identity| identity.file_id().raw() == file_id)
            && row.projection.is_some()
        {
            let state = (row.address + WDM_X64_FILE_OBJECT_EVENT_SIGNAL_STATE_OFFSET as u64)
                as *const core::sync::atomic::AtomicI32;
            (*state).store(i32::from(signaled), core::sync::atomic::Ordering::Release);
        }
    }
}

unsafe fn build(id: u64) -> Result<(), i32> {
    let (file_id, device_id) = {
        let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
        (row.file_id, row.device_id)
    };
    let _ = win32k_device_consumer::ensure_projection(device_id)?;
    let allocation = crate::win32k_subsystem::allocate_root_provider_pool_allocation(WDM_X64_FILE_OBJECT_SIZE as u64)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let address = allocation.address();
    let owner = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    owner.address = address;
    owner.allocation = Some(allocation);
    let identity = win32k_device_consumer::bind_file_projection(address, file_id, device_id)?;
    row(id).ok_or(STATUS_INVALID_HANDLE)?.identity = Some(identity);
    win32k_device_consumer::write_file_projection(identity, device_id)?;
    let projection = win32k_device_consumer::create_file_projection(identity, device_id)?;
    let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    row.projection = Some(projection);
    row.phase = Phase::Live;
    Ok(())
}

/// Retire exact receipts before returning the native allocation to the provider pool.
unsafe fn retire(id: u64) -> Result<(), i32> {
    if !wait_leases().can_retire(id) {
        return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
    }
    let owner = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    if owner.phase != Phase::Retiring {
        return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
    }
    if let Some(projection) = owner.projection.as_mut() {
        if !projection.is_ready_to_retire() {
            return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
        }
        win32k_device_consumer::retire_file_owner(projection)?;
        owner.projection = None;
        owner.identity = None;
    }
    if let Some(identity) = owner.identity {
        win32k_device_consumer::retire_file_projection(identity)?;
        owner.identity = None;
    }
    if let Some(allocation) = owner.allocation {
        if allocation.address() != owner.address
            || !crate::win32k_subsystem::retire_root_provider_pool_allocation(allocation) {
            return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
        }
        owner.address = 0;
        owner.allocation = None;
    }
    let index = rows().iter().position(|row| row.id == id).ok_or(STATUS_INVALID_HANDLE)?;
    rows().swap_remove(index);
    Ok(())
}

/// Called only after the ingress has authenticated win32k's physical service lane.
pub(crate) unsafe fn reference_handle(
    caller: NativeHandleCaller,
    handle: u64,
    access: u32,
    mode: u8,
) -> (i32, u64, u32, u32) {
    let _durable = crate::allocator::enter_durable();
    let result = (|| -> Result<(u64, u32, u32), i32> {
        if mode > 1 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let (owner, file_id, device_id, grant, attributes) =
            crate::service_sec_image::with_provider_process_manager(|pm| {
                pm.validate_native_handle_caller(caller)?;
                let (file_id, device_id) = pm.lookup_native_routed_file_handle(caller, handle, 0)?;
                let target = pm.inspect_native_close_target(caller, handle)?;
                if target.object() != (HandleObject::RoutedFile { file_id, device_id }) {
                    return Err(STATUS_INVALID_HANDLE as u32);
                }
                let NativeHandleScope::Table { owner, .. } =
                    pm.decode_native_handle(caller, handle)? else {
                    return Err(STATUS_INVALID_HANDLE as u32);
                };
                let info = target.information();
                let grant = info.granted_access.ok_or(STATUS_INVALID_HANDLE as u32)?;
                Ok((owner, FileId(file_id), DeviceId(device_id), grant, info.attributes))
            }).map_err(|status| status as i32)?;
        if mode == 1 && access & !grant != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        if let Some(id) = id_for_handle(owner, handle, file_id) {
            let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
            if row.device_id != device_id || row.phase != Phase::Live {
                return Err(STATUS_INVALID_HANDLE);
            }
            let identity = row.identity.ok_or(STATUS_INVALID_HANDLE)?;
            let projection = row.projection.as_mut().ok_or(STATUS_INVALID_HANDLE)?;
            let pointer = win32k_device_consumer::reference_file_by_handle(projection, identity)?;
            return Ok((pointer, grant, attributes));
        }
        let next = (*addr_of!(NEXT_ID)).checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        rows().try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let id = *addr_of!(NEXT_ID);
        rows().push(Row {
            id, owner, handle, file_id, device_id, address: 0, allocation: None,
            identity: None, projection: None, phase: Phase::Building,
        });
        *addr_of_mut!(NEXT_ID) = next;
        if let Err(status) = build(id) {
            row(id).ok_or(STATUS_INVALID_HANDLE)?.phase = Phase::Retiring;
            let _ = retire(id);
            return Err(status);
        }
        let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
        let identity = row.identity.ok_or(STATUS_INVALID_HANDLE)?;
        let pointer = win32k_device_consumer::reference_file_by_handle(
            row.projection.as_mut().ok_or(STATUS_INVALID_HANDLE)?, identity,
        )?;
        Ok((pointer, grant, attributes))
    })();
    match result {
        Ok((pointer, grant, attributes)) => (STATUS_SUCCESS, pointer, grant, attributes),
        Err(status) => (status, 0, 0, 0),
    }
}

pub(crate) unsafe fn reference_pointer(domain: HostedDomainIdentity, address: u64) -> Result<u64, i32> {
    let id = id_for_address(address).ok_or(STATUS_INVALID_HANDLE)?;
    let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    if row.phase == Phase::Building {
        return Err(STATUS_INVALID_HANDLE);
    }
    let identity = row.identity.ok_or(STATUS_INVALID_HANDLE)?;
    if identity.domain() != domain {
        return Err(STATUS_INVALID_HANDLE);
    }
    let projection = row.projection.as_mut().ok_or(STATUS_INVALID_HANDLE)?;
    win32k_device_consumer::reference_file_by_pointer(projection, identity)?;
    Ok((projection.pointer_reference_count() as u64).saturating_add(1))
}

pub(crate) unsafe fn dereference_pointer(domain: HostedDomainIdentity, address: u64) -> Result<u64, i32> {
    let id = id_for_address(address).ok_or(STATUS_INVALID_HANDLE)?;
    let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    let identity = row.identity.ok_or(STATUS_INVALID_HANDLE)?;
    if identity.domain() != domain {
        return Err(STATUS_INVALID_HANDLE);
    }
    let projection = row.projection.as_mut().ok_or(STATUS_INVALID_HANDLE)?;
    win32k_device_consumer::dereference_file_owner(projection, identity)?;
    let count = projection.pointer_reference_count() as u64;
    if row.phase == Phase::Retiring {
        let _ = retire(id);
    }
    Ok(count.saturating_add(1))
}

pub(crate) unsafe fn related_device_address(domain: HostedDomainIdentity, address: u64) -> Result<u64, i32> {
    let id = id_for_address(address).ok_or(STATUS_INVALID_HANDLE)?;
    let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    if row.phase == Phase::Building {
        return Err(STATUS_INVALID_HANDLE);
    }
    let projection = row.projection.as_ref().ok_or(STATUS_INVALID_HANDLE)?;
    if projection.identity().domain() != domain {
        return Err(STATUS_INVALID_HANDLE);
    }
    if projection.pointer_reference_count() == 0 {
        return Err(STATUS_INVALID_HANDLE);
    }
    win32k_device_consumer::related_file_device_address(projection)
}

/// Capture a kernel FileObject independently of its possibly closed original handle.
pub(crate) unsafe fn capture_section_pointer(
    address: u64,
) -> Result<crate::driver_launch::hosted_file_capture::Capture, u32> {
    let id = id_for_address(address).ok_or(STATUS_INVALID_HANDLE as u32)?;
    let identity = wait_identity_for_row(id, false).map_err(|status| status as u32)?;
    let (file_id, device_id) = {
        let owner = row(id).ok_or(STATUS_INVALID_HANDLE as u32)?;
        if owner.identity != Some(identity) || owner.address != address {
            return Err(STATUS_INVALID_HANDLE as u32);
        }
        (owner.file_id.raw(), owner.device_id.raw())
    };
    // MmCreateSection's supplied FileObject path references the object directly;
    // the canonical backing policy still validates protection and storage rights.
    const KERNEL_FILE_DATA_ACCESS: u32 = 0x0001 | 0x0002 | 0x0020;
    crate::driver_launch::hosted_file_capture::capture_owned(
        file_id, device_id, KERNEL_FILE_DATA_ACCESS,
    )
}

/// The caller has already committed the exact typed process-table close.
pub(crate) unsafe fn handle_closed(
    owner: ProcessId,
    handle: u64,
    file_id: u64,
) -> Result<(), i32> {
    for row in rows().iter_mut().filter(|row| {
        row.owner == owner && row.handle == handle && row.file_id == FileId(file_id)
    }) {
        if row.phase == Phase::Live {
            let identity = row.identity.ok_or(STATUS_INVALID_HANDLE)?;
            row.projection.as_mut().ok_or(STATUS_INVALID_HANDLE)?
                .handle_closed(identity).map_err(|status| status.raw())?;
        }
        row.phase = Phase::Retiring;
    }
    redrive();
    Ok(())
}

pub(crate) unsafe fn redrive() {
    let mut cursor = 0;
    while let Some((token, domain)) = wait_receipts()
        .iter()
        .filter(|receipt| receipt.releasing && receipt.token > cursor)
        .map(|receipt| (receipt.token, receipt.identity.domain()))
        .min_by_key(|(token, _)| *token)
    {
        cursor = token;
        let _ = release_wait_identity(domain, token);
    }
    let mut cursor = 0;
    while let Some(id) = rows().iter().filter(|row| {
        row.phase == Phase::Retiring && row.id > cursor
    }).map(|row| row.id).min() {
        cursor = id;
        let _ = retire(id);
    }
}
