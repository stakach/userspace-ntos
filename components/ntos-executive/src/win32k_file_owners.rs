//! Per-open win32k FILE_OBJECT ownership backed by exact routed handle and I/O identities.

use alloc::vec::Vec;
use core::ptr::{addr_of, addr_of_mut};

use nt_io_manager::{
    consumer_file_projection::ConsumerFileProjection, DeviceId, FileId, HostedFileIdentity,
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
    identity: Option<HostedFileIdentity>,
    projection: Option<ConsumerFileProjection>,
    phase: Phase,
}

static mut ROWS: Vec<Row> = Vec::new();
static mut NEXT_ID: u64 = 1;

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
    rows().is_empty()
}

/// The embedded notification Event is not an independently allocated Event object. A provider
/// wait may name it only through an exact, referenced File projection.
pub(crate) unsafe fn wait_identity_for_event(event: u64) -> Result<HostedFileIdentity, i32> {
    let id = rows()
        .iter()
        .find(|row| {
            row.address.checked_add(WDM_X64_FILE_OBJECT_EVENT_OFFSET as u64) == Some(event)
                && row.address != 0
        })
        .map(|row| row.id)
        .ok_or(STATUS_INVALID_HANDLE)?;
    wait_identity_for_row(id)
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
    wait_identity_for_row(id)
}

unsafe fn wait_identity_for_row(id: u64) -> Result<HostedFileIdentity, i32> {
    let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    if row.phase == Phase::Building {
        return Err(STATUS_INVALID_HANDLE);
    }
    let identity = row.identity.ok_or(STATUS_INVALID_HANDLE)?;
    let projection = row.projection.as_ref().ok_or(STATUS_INVALID_HANDLE)?;
    if projection.pointer_reference_count() == 0
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
    let address = crate::win32k_subsystem::pool_alloc_export(WDM_X64_FILE_OBJECT_SIZE as u64);
    if address == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    row(id).ok_or(STATUS_INVALID_HANDLE)?.address = address;
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
    if owner.address != 0 {
        if !crate::win32k_subsystem::release_consumer_projection(
            owner.address, WDM_X64_FILE_OBJECT_SIZE as u64,
        ) {
            return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
        }
        owner.address = 0;
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
            id, owner, handle, file_id, device_id, address: 0,
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

pub(crate) unsafe fn reference_pointer(address: u64) -> Result<u64, i32> {
    let id = id_for_address(address).ok_or(STATUS_INVALID_HANDLE)?;
    let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    if row.phase == Phase::Building {
        return Err(STATUS_INVALID_HANDLE);
    }
    let identity = row.identity.ok_or(STATUS_INVALID_HANDLE)?;
    let projection = row.projection.as_mut().ok_or(STATUS_INVALID_HANDLE)?;
    win32k_device_consumer::reference_file_by_pointer(projection, identity)?;
    Ok((projection.pointer_reference_count() as u64).saturating_add(1))
}

pub(crate) unsafe fn dereference_pointer(address: u64) -> Result<u64, i32> {
    let id = id_for_address(address).ok_or(STATUS_INVALID_HANDLE)?;
    let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    let identity = row.identity.ok_or(STATUS_INVALID_HANDLE)?;
    let projection = row.projection.as_mut().ok_or(STATUS_INVALID_HANDLE)?;
    win32k_device_consumer::dereference_file_owner(projection, identity)?;
    let count = projection.pointer_reference_count() as u64;
    if row.phase == Phase::Retiring {
        let _ = retire(id);
    }
    Ok(count.saturating_add(1))
}

pub(crate) unsafe fn related_device_address(address: u64) -> Result<u64, i32> {
    let id = id_for_address(address).ok_or(STATUS_INVALID_HANDLE)?;
    let row = row(id).ok_or(STATUS_INVALID_HANDLE)?;
    if row.phase == Phase::Building {
        return Err(STATUS_INVALID_HANDLE);
    }
    let projection = row.projection.as_ref().ok_or(STATUS_INVALID_HANDLE)?;
    if projection.pointer_reference_count() == 0 {
        return Err(STATUS_INVALID_HANDLE);
    }
    win32k_device_consumer::related_file_device_address(projection)
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
    while let Some(id) = rows().iter().filter(|row| {
        row.phase == Phase::Retiring && row.id > cursor
    }).map(|row| row.id).min() {
        cursor = id;
        let _ = retire(id);
    }
}
