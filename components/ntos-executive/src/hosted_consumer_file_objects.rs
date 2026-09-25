//! Driver-local FILE_OBJECT/DEVICE_OBJECT projections for typed routed File handles.
//!
//! The canonical File and Device remain in the I/O Manager. Every address in this module is
//! owned by the authenticated consumer domain and is never used as provider dispatch authority.

use super::*;
use nt_io_manager::{
    consumer_file_projection::{consumer_file_metadata, ConsumerFileProjection}, DeviceId, FileId,
    FileReference, HostedDevicePointerRegistration, HostedDomainIdentity, HostedFileIdentity,
    HostedFilePublicationLease, HostedFileUnbindOutcome, WdmOpenDeviceProjectionInit,
    WDM_X64_DEVICE_OBJECT_SIZE, WDM_X64_DRIVER_EXTENSION_SIZE, WDM_X64_DRIVER_OBJECT_SIZE,
    WDM_X64_FILE_OBJECT_SIZE,
};
use nt_process::{native_handle::NativeHandleScope, HandleObject, ProcessId};

const ALLOCATION_COUNT: usize = 5;
const STATUS_BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Building,
    Live,
    Retiring,
}

struct Row {
    id: u64,
    domain: HostedDomainIdentity,
    owner: ProcessId,
    handle: u64,
    file_id: FileId,
    device_id: DeviceId,
    instance_index: usize,
    pool_va: u64,
    allocations: [Option<u64>; ALLOCATION_COUNT],
    device: Option<HostedDevicePointerRegistration>,
    file: Option<HostedFileIdentity>,
    projection: Option<ConsumerFileProjection>,
    phase: Phase,
}

struct Metadata {
    driver_name: Vec<u16>,
    file_name: Vec<u16>,
    driver_id: nt_io_manager::DriverId,
    device_type: u32,
    device_flags: u32,
    device_characteristics: u32,
    device_stack_size: u8,
    file_create_options: u32,
    file_opened_case_sensitive: bool,
}

static mut ROWS: Vec<Row> = Vec::new();
static mut NEXT_ROW_ID: u64 = 1;

#[must_use = "release the source File and projection lease after forwarding retires"]
pub(super) struct ForwardFileOwner {
    identity: HostedFileIdentity,
    device: HostedDevicePointerRegistration,
    reference: FileReference,
    lease: HostedFilePublicationLease,
}

impl ForwardFileOwner {
    pub(super) fn file_id(&self) -> FileId { self.identity.file_id() }
    pub(super) fn device_id(&self) -> DeviceId { self.device.device_id() }

    pub(super) fn validate(&self) -> Result<(), i32> {
        let io = io_manager_mut();
        if io.hosted_file_identity_at(
            self.identity.domain(), self.identity.file_id(), self.identity.address(),
        ).map_err(|status| status.raw())? != Some(self.identity)
            || io.hosted_device_pointer_registration(self.device.domain(), self.device.address())
                != Some(self.device)
            || io.file(self.identity.file_id())
                .is_none_or(|file| file.device_id != self.device.device_id())
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(())
    }

    pub(super) fn release(&mut self) -> Result<(), i32> {
        self.validate()?;
        let io = io_manager_mut();
        if self.reference.is_held() {
            io.release_file_reference(&mut self.reference).map_err(|status| status.raw())?;
        }
        if self.lease.is_held() {
            io.release_hosted_file_publication(&mut self.lease).map_err(|status| status.raw())?;
        }
        Ok(())
    }
}

fn rows() -> &'static mut Vec<Row> {
    // The executive serializes hosted service work. No reference crosses provider IPC.
    unsafe { &mut *core::ptr::addr_of_mut!(ROWS) }
}

fn row(id: u64) -> &'static mut Row {
    rows().iter_mut().find(|row| row.id == id).expect("consumer File owner missing")
}

fn row_for_handle(
    domain: HostedDomainIdentity,
    owner: ProcessId,
    handle: u64,
    file_id: FileId,
) -> Option<u64> {
    rows().iter().find(|row| {
        row.domain == domain && row.owner == owner && row.handle == handle && row.file_id == file_id
    }).map(|row| row.id)
}

fn row_for_pointer(domain: HostedDomainIdentity, address: u64) -> Option<u64> {
    rows().iter().find(|row| {
        row.domain == domain && row.allocations[2] == Some(address)
    }).map(|row| row.id)
}

fn copy_units(source: &[u16]) -> Result<Vec<u16>, i32> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(source.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    owned.extend_from_slice(source);
    Ok(owned)
}

fn metadata(file_id: FileId, device_id: DeviceId) -> Result<Metadata, i32> {
    let io = io_manager_mut();
    let file = consumer_file_metadata(io, file_id, device_id).map_err(|status| status.raw())?;
    let device = io.device(device_id).ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    if device.delete_pending || device.stack_size == 0 {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let driver = io.driver(device.driver_id).ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    let driver_name = copy_units(&driver.name.to_units())?;
    Ok(Metadata {
        driver_name,
        file_name: file.file_name,
        driver_id: device.driver_id,
        device_type: device.device_type.0,
        device_flags: device.flags.bits(),
        device_characteristics: device.characteristics.bits(),
        device_stack_size: device.stack_size,
        file_create_options: file.create_options,
        file_opened_case_sensitive: file.opened_case_sensitive,
    })
}

unsafe fn live_instance(id: u64) -> Result<DriverInstance, i32> {
    let owner = row(id);
    let inst = instance(owner.instance_index).ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    if instance_domain_identity(inst) != Some(owner.domain) || inst.exec_pool_va != owner.pool_va {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(inst)
}

unsafe fn allocate(id: u64, slot: usize, bytes: usize) -> Result<(u64, u64), i32> {
    let inst = live_instance(id)?;
    let length = u64::try_from(bytes).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let address = hosted_instance_pool_alloc(inst, length).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    row(id).allocations[slot] = Some(address);
    let exec = hosted_instance_pool_allocation_exec_if_live(inst, address, length)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    Ok((address, exec))
}

unsafe fn write_name(id: u64, slot: usize, units: &[u16]) -> Result<(u64, u16, u16), i32> {
    if units.is_empty() {
        return Ok((0, 0, 0));
    }
    let length = units.len().checked_mul(2).ok_or(STATUS_INVALID_PARAMETER)?;
    let maximum = length.checked_add(2).ok_or(STATUS_INVALID_PARAMETER)?;
    let length = u16::try_from(length).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let maximum = u16::try_from(maximum).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let (address, exec) = allocate(id, slot, maximum as usize)?;
    for (index, unit) in units.iter().enumerate() {
        core::ptr::write_unaligned((exec + (index * 2) as u64) as *mut u16, *unit);
    }
    core::ptr::write_unaligned((exec + length as u64) as *mut u16, 0);
    Ok((address, length, maximum))
}

unsafe fn build(id: u64, metadata: &Metadata) -> Result<(), i32> {
    let (driver, driver_exec) = allocate(
        id, 0, WDM_X64_DRIVER_OBJECT_SIZE + WDM_X64_DRIVER_EXTENSION_SIZE,
    )?;
    let (device, device_exec) = allocate(id, 1, WDM_X64_DEVICE_OBJECT_SIZE)?;
    let (file, file_exec) = allocate(id, 2, WDM_X64_FILE_OBJECT_SIZE)?;
    let (driver_name, driver_len, driver_max) = write_name(id, 3, &metadata.driver_name)?;
    let (file_name, file_len, file_max) = write_name(id, 4, &metadata.file_name)?;
    let driver_bytes = core::slice::from_raw_parts_mut(
        driver_exec as *mut u8, WDM_X64_DRIVER_OBJECT_SIZE + WDM_X64_DRIVER_EXTENSION_SIZE,
    );
    let device_bytes = core::slice::from_raw_parts_mut(device_exec as *mut u8, WDM_X64_DEVICE_OBJECT_SIZE);
    let file_bytes = core::slice::from_raw_parts_mut(file_exec as *mut u8, WDM_X64_FILE_OBJECT_SIZE);
    nt_io_manager::write_wdm_open_device_projection(
        driver_bytes,
        device_bytes,
        file_bytes,
        WdmOpenDeviceProjectionInit {
            file_object_address: file,
            driver_object: driver,
            driver_extension: driver + WDM_X64_DRIVER_OBJECT_SIZE as u64,
            driver_name_len: driver_len,
            driver_name_max_len: driver_max,
            driver_name_buffer: driver_name,
            device_object: device,
            // FsContext is an address in the provider's VSpace, not this consumer's.
            file_object_context: 0,
            device_type: metadata.device_type,
            device_flags: metadata.device_flags,
            device_characteristics: metadata.device_characteristics,
            device_stack_size: metadata.device_stack_size,
            file_create_options: metadata.file_create_options,
            file_opened_case_sensitive: metadata.file_opened_case_sensitive,
            file_name_len: file_len,
            file_name_max_len: file_max,
            file_name_buffer: file_name,
            ..Default::default()
        },
    ).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let (domain, device_id, file_id) = {
        let owner = row(id);
        (owner.domain, owner.device_id, owner.file_id)
    };
    let registration = io_manager_mut()
        .bind_hosted_device_pointer(domain, device, device_id)
        .map_err(|status| status.raw())?;
    row(id).device = Some(registration);
    let identity = io_manager_mut()
        .bind_hosted_file_identity(domain, file, file_id)
        .map_err(|status| status.raw())?;
    row(id).file = Some(identity);
    let projection = ConsumerFileProjection::new(io_manager_mut(), identity, registration)
        .map_err(|status| status.raw())?;
    row(id).projection = Some(projection);
    row(id).phase = Phase::Live;
    Ok(())
}

/// Rollback and post-close retirement share the same checked ordering. A failed step leaves the
/// row and its allocation identities intact for redrive; no address can be reused prematurely.
unsafe fn retire(id: u64) -> Result<(), i32> {
    let phase = row(id).phase;
    if phase == Phase::Live {
        return Err(STATUS_BUSY);
    }
    if row(id).projection.is_some() {
        let projection = row(id).projection.as_mut().unwrap();
        if !projection.is_ready_to_retire() {
            return Err(STATUS_BUSY);
        }
        projection.retire(io_manager_mut()).map_err(|status| status.raw())?;
        row(id).projection = None;
        row(id).file = None;
    }
    if let Some(identity) = row(id).file {
        match io_manager_mut().unbind_hosted_file_identity(identity) {
            Ok(HostedFileUnbindOutcome::Removed) => row(id).file = None,
            Ok(HostedFileUnbindOutcome::AlreadyAbsent) => return Err(STATUS_INVALID_HANDLE),
            Err(status) => return Err(status.raw()),
        }
    }
    if let Some(registration) = row(id).device {
        io_manager_mut().retire_hosted_device_pointer(registration)
            .map_err(|status| status.raw())?;
        row(id).device = None;
    }
    let inst = live_instance(id)?;
    for slot in (0..ALLOCATION_COUNT).rev() {
        if let Some(address) = row(id).allocations[slot] {
            if !free_hosted_instance_pool_allocation_exact(inst, address) {
                return Err(STATUS_BUSY);
            }
            row(id).allocations[slot] = None;
        }
    }
    let index = rows().iter().position(|owner| owner.id == id).expect("consumer File owner missing");
    rows().swap_remove(index);
    Ok(())
}

unsafe fn authenticate(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
) -> Result<(DriverInstance, HostedDomainIdentity), i32> {
    let (_, inst) = instance_for_pump_channel(ch, reply_cap).ok_or(STATUS_ACCESS_DENIED)?;
    let domain = instance_domain_identity(inst).ok_or(STATUS_ACCESS_DENIED)?;
    Ok((inst, domain))
}

/// Capture the exact source FILE_OBJECT and its registered related DEVICE_OBJECT before a
/// cross-domain forward. The source driver must still own a pointer reference to the File.
pub(super) unsafe fn capture_forward_file(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    file_address: u64,
    device_address: u64,
) -> Result<ForwardFileOwner, i32> {
    let (_, domain) = authenticate(ch, reply_cap)?;
    let id = row_for_pointer(domain, file_address).ok_or(STATUS_INVALID_HANDLE)?;
    let owner = row(id);
    let projection = owner.projection.as_ref().ok_or(STATUS_INVALID_HANDLE)?;
    if projection.pointer_reference_count() == 0
        || projection.related_device_address(io_manager_mut()).map_err(|status| status.raw())?
            != device_address
    {
        return Err(STATUS_INVALID_HANDLE);
    }
    let identity = projection.identity();
    let device = projection.device_registration();
    let io = io_manager_mut();
    let mut lease = io.lease_hosted_file_identity(identity).map_err(|status| status.raw())?;
    let reference = match io.retain_file_reference(identity.file_id()) {
        Ok(reference) => reference,
        Err(status) => {
            io.release_hosted_file_publication(&mut lease)
                .expect("captured File lease rollback");
            return Err(status.raw());
        }
    };
    Ok(ForwardFileOwner { identity, device, reference, lease })
}

/// One call is never replayed after an uncertain Reply. Repeated, distinct calls share a single
/// projection row but each acquire their own canonical FILE_OBJECT pointer reference.
pub(super) unsafe fn reference_handle(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    handle: u64,
    desired_access: u32,
    access_mode: u8,
) -> (i32, u64, u32, u32) {
    let result = (|| -> Result<(u64, u32, u32), i32> {
        let (inst, domain) = authenticate(ch, reply_cap)?;
        if access_mode > 1 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let caller = crate::provider_registry_caller::resolve(ch).map_err(|status| status as i32)?;
        let (owner, file_id, device_id, grant, attributes) =
            crate::service_sec_image::with_provider_process_manager(|pm| {
                let (file_id, device_id) = pm.lookup_native_routed_file_handle(caller, handle, 0)?;
                let target = pm.inspect_native_close_target(caller, handle)?;
                if target.object() != (HandleObject::RoutedFile { file_id, device_id }) {
                    return Err(STATUS_INVALID_HANDLE as u32);
                }
                let NativeHandleScope::Table { owner, .. } = pm.decode_native_handle(caller, handle)? else {
                    return Err(STATUS_INVALID_HANDLE as u32);
                };
                let info = target.information();
                let grant = info.granted_access.ok_or(STATUS_INVALID_HANDLE as u32)?;
                Ok((owner, FileId(file_id), DeviceId(device_id), grant, info.attributes))
            }).map_err(|status| status as i32)?;
        if access_mode == 1 && desired_access & !grant != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        let metadata = metadata(file_id, device_id)?;
        if instance_domain_identity(inst) != Some(domain)
            || io_manager_mut().driver(metadata.driver_id).is_none()
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if let Some(id) = row_for_handle(domain, owner, handle, file_id) {
            if row(id).device_id != device_id || row(id).phase != Phase::Live {
                return Err(STATUS_BUSY);
            }
            live_instance(id)?;
            let identity = row(id).file.ok_or(STATUS_INVALID_HANDLE)?;
            let pointer = row(id).projection.as_mut().unwrap()
                .reference_by_handle(io_manager_mut(), identity)
                .map_err(|status| status.raw())?;
            return Ok((pointer, grant, attributes));
        }
        let id = NEXT_ROW_ID;
        let next = id.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        rows().try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let (instance_index, _) = instance_for_pump_channel(ch, reply_cap)
            .ok_or(STATUS_ACCESS_DENIED)?;
        rows().push(Row {
            id, domain, owner, handle, file_id, device_id, instance_index,
            pool_va: inst.exec_pool_va,
            allocations: [None; ALLOCATION_COUNT], device: None, file: None,
            projection: None, phase: Phase::Building,
        });
        NEXT_ROW_ID = next;
        if let Err(status) = build(id, &metadata) {
            row(id).phase = Phase::Retiring;
            let _ = retire(id);
            return Err(status);
        }
        let identity = row(id).file.expect("built consumer projection lacks identity");
        let pointer = row(id).projection.as_mut().unwrap()
            .reference_by_handle(io_manager_mut(), identity)
            .map_err(|status| status.raw())?;
        Ok((pointer, grant, attributes))
    })();
    match result {
        Ok((pointer, grant, attributes)) => (STATUS_SUCCESS, pointer, grant, attributes),
        Err(status) => (status, 0, 0, 0),
    }
}

pub(super) unsafe fn reference_pointer(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    address: u64,
) -> (i32, u64) {
    let result = (|| -> Result<u64, i32> {
        let (_, domain) = authenticate(ch, reply_cap)?;
        let id = row_for_pointer(domain, address).ok_or(STATUS_INVALID_PARAMETER)?;
        if row(id).phase == Phase::Building {
            return Err(STATUS_INVALID_HANDLE);
        }
        let identity = row(id).file.ok_or(STATUS_INVALID_HANDLE)?;
        row(id).projection.as_mut().ok_or(STATUS_INVALID_HANDLE)?
            .reference_by_pointer(io_manager_mut(), identity).map_err(|status| status.raw())
    })();
    match result {
        Ok(pointer) => (STATUS_SUCCESS, pointer),
        Err(status) => (status, 0),
    }
}

pub(super) unsafe fn dereference_pointer(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    address: u64,
) -> i32 {
    let result = (|| -> Result<(), i32> {
        let (_, domain) = authenticate(ch, reply_cap)?;
        let id = row_for_pointer(domain, address).ok_or(STATUS_INVALID_PARAMETER)?;
        let identity = row(id).file.ok_or(STATUS_INVALID_HANDLE)?;
        row(id).projection.as_mut().ok_or(STATUS_INVALID_HANDLE)?
            .dereference(io_manager_mut(), identity).map_err(|status| status.raw())?;
        if row(id).phase == Phase::Retiring {
            let _ = retire(id);
        }
        Ok(())
    })();
    result.map_or_else(|status| status, |_| STATUS_SUCCESS)
}

/// Called only after the typed process-table close receipt is committed. A pointer reference may
/// outlive that handle; the canonical File and local allocations remain owned until dereference.
pub(crate) unsafe fn handle_closed(
    owner: ProcessId,
    handle: u64,
    file_id: u64,
) -> Result<(), i32> {
    for row in rows().iter_mut().filter(|row| {
        row.owner == owner && row.handle == handle && row.file_id == FileId(file_id)
    }) {
        if row.phase == Phase::Live {
            let identity = row.file.ok_or(STATUS_INVALID_HANDLE)?;
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
    loop {
        let Some(id) = rows().iter().filter(|row| row.phase == Phase::Retiring && row.id > cursor)
            .map(|row| row.id).min() else { break };
        cursor = id;
        let _ = retire(id);
    }
}
