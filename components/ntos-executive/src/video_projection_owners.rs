//! Independently retained ownership of video File handles and consumer projections.

use alloc::vec::Vec;
use core::ptr::{addr_of, addr_of_mut};

use nt_io_manager::{
    consumer_file_projection::ConsumerFileProjection, FileId, HostedFileIdentity,
    WDM_X64_FILE_OBJECT_SIZE,
};
use nt_status::NtStatus;

struct Row {
    id: u64,
    handle: u64,
    file: u64,
    address: u64,
    identity: Option<HostedFileIdentity>,
    projection: Option<ConsumerFileProjection>,
    handle_closed: bool,
    retiring: bool,
    in_flight: bool,
}

#[derive(Clone, Copy)]
struct RowSnapshot {
    handle: u64,
    file: u64,
    address: u64,
    identity: Option<HostedFileIdentity>,
    handle_closed: bool,
    retiring: bool,
    in_flight: bool,
}

static mut OWNERS: Vec<Option<Row>> = Vec::new();
static mut LAST_ISSUED: u64 = 0;
static mut NEXT_RETIREMENT: usize = 0;
const RETIREMENT_BUDGET: usize = 16;

unsafe fn rows() -> &'static Vec<Option<Row>> {
    &*addr_of!(OWNERS)
}

unsafe fn rows_mut() -> &'static mut Vec<Option<Row>> {
    &mut *addr_of_mut!(OWNERS)
}

unsafe fn index_for(id: u64) -> Option<usize> {
    rows()
        .iter()
        .position(|row| row.as_ref().is_some_and(|row| row.id == id))
}

unsafe fn snapshot(index: usize) -> RowSnapshot {
    let row = rows()[index]
        .as_ref()
        .expect("in-flight video File owner must remain allocated");
    RowSnapshot {
        handle: row.handle,
        file: row.file,
        address: row.address,
        identity: row.identity,
        handle_closed: row.handle_closed,
        retiring: row.retiring,
        in_flight: row.in_flight,
    }
}

/// Establish a durable owner before opening a File or allocating its projection.
pub(super) unsafe fn reserve() -> Result<u64, NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let id = (*addr_of!(LAST_ISSUED))
        .checked_add(1)
        .ok_or(NtStatus::INSUFFICIENT_RESOURCES)?;
    let vacant = rows().iter().position(Option::is_none);
    if vacant.is_none() {
        rows_mut()
            .try_reserve(1)
            .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
    }
    let row = Some(Row {
        id,
        handle: 0,
        file: 0,
        address: 0,
        identity: None,
        projection: None,
        handle_closed: false,
        retiring: false,
        in_flight: false,
    });
    if let Some(index) = vacant {
        rows_mut()[index] = row;
    } else {
        rows_mut().push(row);
    }
    *addr_of_mut!(LAST_ISSUED) = id;
    Ok(id)
}

/// Transfer a newly opened handle into the reserved owner without allocation or callbacks.
pub(super) unsafe fn attach_open(id: u64, handle: u64, file_id: u64) -> Result<(), NtStatus> {
    let index = index_for(id).ok_or(NtStatus::INVALID_HANDLE)?;
    let row = rows_mut()[index].as_mut().unwrap();
    if handle == 0
        || file_id == 0
        || row.handle != 0
        || row.file != 0
        || row.retiring
        || row.in_flight
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    row.handle = handle;
    row.file = file_id;
    Ok(())
}

pub(super) unsafe fn prepare(
    id: u64,
    device_id: u64,
    device_address: u64,
    allocate: unsafe fn(u64) -> u64,
) -> Result<u64, NtStatus> {
    let index = index_for(id).ok_or(NtStatus::INVALID_HANDLE)?;
    let row = snapshot(index);
    if row.handle == 0
        || row.file == 0
        || row.address != 0
        || row.retiring
        || row.in_flight
        || device_id == 0
        || device_address == 0
    {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    rows_mut()[index].as_mut().unwrap().in_flight = true;
    let result = prepare_inner(index, device_id, allocate);
    let row = rows_mut()[index].as_mut().unwrap();
    row.in_flight = false;
    if row.retiring {
        return Err(NtStatus::DELETE_PENDING);
    }
    result
}

unsafe fn prepare_inner(
    index: usize,
    device_id: u64,
    allocate: unsafe fn(u64) -> u64,
) -> Result<u64, NtStatus> {
    let file = snapshot(index).file;
    let address = allocate(WDM_X64_FILE_OBJECT_SIZE as u64);
    if address == 0 {
        return Err(NtStatus::INSUFFICIENT_RESOURCES);
    }
    // Allocation ownership must survive initialization errors and reentrant route retirement.
    rows_mut()[index].as_mut().unwrap().address = address;
    if snapshot(index).retiring {
        return Err(NtStatus::DELETE_PENDING);
    }
    let identity = crate::driver_launch::win32k_device_consumer::bind_file_projection(
        address,
        FileId(file),
        nt_io_manager::DeviceId(device_id),
    )
    .map_err(NtStatus)?;
    rows_mut()[index].as_mut().unwrap().identity = Some(identity);
    crate::driver_launch::win32k_device_consumer::write_file_projection(
        identity,
        nt_io_manager::DeviceId(device_id),
    )
    .map_err(NtStatus)?;
    let projection = crate::driver_launch::win32k_device_consumer::create_file_projection(
        identity,
        nt_io_manager::DeviceId(device_id),
    )
    .map_err(NtStatus)?;
    rows_mut()[index].as_mut().unwrap().projection = Some(projection);
    Ok(address)
}

pub(super) unsafe fn pointer_reference_count(id: u64) -> Option<usize> {
    let index = index_for(id)?;
    rows()[index]
        .as_ref()?
        .projection
        .as_ref()
        .map(ConsumerFileProjection::pointer_reference_count)
}

pub(super) unsafe fn reference_by_handle(id: u64, address: u64) -> Result<u64, NtStatus> {
    let index = index_for(id).ok_or(NtStatus::INVALID_HANDLE)?;
    let row = rows_mut()[index].as_mut().unwrap();
    if row.retiring || row.handle == 0 || row.address != address {
        return Err(NtStatus::INVALID_HANDLE);
    }
    let identity = row.identity.ok_or(NtStatus::INVALID_HANDLE)?;
    let projection = row.projection.as_mut().ok_or(NtStatus::INVALID_HANDLE)?;
    let pointer = crate::driver_launch::win32k_device_consumer::reference_file_by_handle(
        projection, identity,
    )
    .map_err(NtStatus)?;
    assert_eq!(pointer, address, "video File reference changed projection address");
    Ok((projection.pointer_reference_count() as u64).saturating_add(1))
}

pub(super) unsafe fn reference_by_pointer(id: u64, address: u64) -> Result<u64, NtStatus> {
    let index = index_for(id).ok_or(NtStatus::INVALID_HANDLE)?;
    let row = rows_mut()[index].as_mut().unwrap();
    if row.retiring || row.address != address {
        return Err(NtStatus::INVALID_HANDLE);
    }
    let identity = row.identity.ok_or(NtStatus::INVALID_HANDLE)?;
    let projection = row.projection.as_mut().ok_or(NtStatus::INVALID_HANDLE)?;
    let pointer = crate::driver_launch::win32k_device_consumer::reference_file_by_pointer(
        projection, identity,
    )
    .map_err(NtStatus)?;
    assert_eq!(pointer, address, "video File reference changed projection address");
    Ok((projection.pointer_reference_count() as u64).saturating_add(1))
}

pub(super) unsafe fn dereference(id: u64, address: u64) -> Result<u64, NtStatus> {
    let index = index_for(id).ok_or(NtStatus::INVALID_HANDLE)?;
    let row = rows_mut()[index].as_mut().unwrap();
    if row.address != address {
        return Err(NtStatus::INVALID_HANDLE);
    }
    let identity = row.identity.ok_or(NtStatus::INVALID_HANDLE)?;
    let projection = row.projection.as_mut().ok_or(NtStatus::INVALID_HANDLE)?;
    crate::driver_launch::win32k_device_consumer::dereference_file_owner(projection, identity)
        .map_err(NtStatus)?;
    Ok((projection.pointer_reference_count() as u64).saturating_add(1))
}

/// Retire only after caller pointer references have drained. Failed stages retain their owners.
pub(super) unsafe fn retire(id: u64) -> bool {
    let Some(index) = index_for(id) else {
        return id != 0 && id <= *addr_of!(LAST_ISSUED);
    };
    rows_mut()[index].as_mut().unwrap().retiring = true;
    retire_one(index)
}

unsafe fn retire_one(index: usize) -> bool {
    let Some(row) = rows().get(index).and_then(Option::as_ref) else {
        return false;
    };
    if !row.retiring || row.in_flight {
        return false;
    }
    rows_mut()[index].as_mut().unwrap().in_flight = true;
    let retired = retire_inner(index);
    if retired {
        rows_mut()[index] = None;
    } else {
        rows_mut()[index].as_mut().unwrap().in_flight = false;
    }
    retired
}

unsafe fn retire_inner(index: usize) -> bool {
    let handle = snapshot(index).handle;
    if handle != 0 {
        if crate::driver_launch::close_io_handle(handle).is_err() {
            return false;
        }
        rows_mut()[index].as_mut().unwrap().handle = 0;
    }
    if !snapshot(index).handle_closed {
        if let Some(identity) = snapshot(index).identity {
            let row = rows_mut()[index].as_mut().unwrap();
            if let Some(projection) = row.projection.as_mut() {
                if projection.handle_closed(identity).is_err() {
                    return false;
                }
            }
        }
        rows_mut()[index].as_mut().unwrap().handle_closed = true;
    }
    if let Some(projection) = rows_mut()[index].as_mut().unwrap().projection.as_mut() {
        if crate::driver_launch::win32k_device_consumer::retire_file_owner(projection).is_err() {
            return false;
        }
        rows_mut()[index].as_mut().unwrap().projection = None;
        rows_mut()[index].as_mut().unwrap().identity = None;
    }
    if let Some(identity) = snapshot(index).identity {
        if crate::driver_launch::win32k_device_consumer::retire_file_projection(identity).is_err() {
            return false;
        }
        rows_mut()[index].as_mut().unwrap().identity = None;
    }
    let address = snapshot(index).address;
    if address != 0 {
        if !crate::win32k_subsystem::release_video_projection(
            address,
            WDM_X64_FILE_OBJECT_SIZE as u64,
        ) {
            return false;
        }
        rows_mut()[index].as_mut().unwrap().address = 0;
    }
    true
}

pub(super) unsafe fn pending_count() -> u64 {
    rows().iter().flatten().filter(|row| row.retiring).count() as u64
}

pub(super) unsafe fn has_pending() -> bool {
    rows().iter().flatten().any(|row| row.retiring)
}

pub(super) unsafe fn has_owners() -> bool {
    rows().iter().any(Option::is_some)
}

/// Bound maintenance work without allowing one refused retirement to starve later owners.
pub(super) unsafe fn drain() -> u64 {
    let count = rows().len();
    if count == 0 {
        return 0;
    }
    let start = *addr_of!(NEXT_RETIREMENT) % count;
    let budget = count.min(RETIREMENT_BUDGET);
    let mut retired = 0;
    for offset in 0..budget {
        retired += u64::from(retire_one((start + offset) % count));
    }
    *addr_of_mut!(NEXT_RETIREMENT) = (start + budget) % count;
    retired
}
