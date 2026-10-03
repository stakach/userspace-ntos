//! One owned consumer DEVICE_OBJECT registration shared by exact per-File leases.

use super::*;
use nt_io_manager::{
    consumer_device_projection::{ConsumerDeviceLease, ConsumerDeviceProjection},
    DeviceId, FileId, HostedDevicePointerRegistration, HostedDomainIdentity, WdmDeviceObjectInit,
    WdmDriverObjectInit, WDM_X64_DEVICE_OBJECT_SIZE, WDM_X64_DRIVER_EXTENSION_SIZE,
    WDM_X64_DRIVER_OBJECT_SIZE,
};
const STATUS_DEVICE_BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

struct Allocation {
    address: u64,
    generation: u64,
}
struct Row {
    id: u64,
    instance_index: usize,
    domain: HostedDomainIdentity,
    pool_va: u64,
    pml4: u64,
    device: DeviceId,
    allocations: [Option<Allocation>; 3],
    projection: Option<ConsumerDeviceProjection>,
    registration: Option<HostedDevicePointerRegistration>,
    retiring: bool,
}
static mut ROWS: Vec<Row> = Vec::new();
static mut NEXT_ID: u64 = 1;

#[must_use = "release this File's shared consumer Device owner"]
pub(super) struct DeviceOwner {
    row_id: u64,
    lease: ConsumerDeviceLease,
}
impl DeviceOwner {
    pub(super) fn registration(&self) -> HostedDevicePointerRegistration {
        self.lease.registration()
    }
}

fn rows() -> &'static mut Vec<Row> {
    unsafe { &mut *core::ptr::addr_of_mut!(ROWS) }
}
fn row(id: u64) -> &'static mut Row {
    rows()
        .iter_mut()
        .find(|row| row.id == id)
        .expect("shared consumer Device missing")
}

unsafe fn live_instance(id: u64) -> Result<DriverInstance, i32> {
    let owner = row(id);
    let inst = instance(owner.instance_index).ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    if instance_domain_identity(inst) != Some(owner.domain)
        || inst.exec_pool_va != owner.pool_va
        || inst.pml4 != owner.pml4
    {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(inst)
}

unsafe fn allocate(id: u64, slot: usize, bytes: usize) -> Result<(u64, u64), i32> {
    let inst = live_instance(id)?;
    let address =
        hosted_instance_pool_alloc(inst, bytes as u64).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    // Retain the address before any subsequent lookup or write can refuse admission.
    row(id).allocations[slot] = Some(Allocation {
        address,
        generation: 0,
    });
    let _lock = hosted_instance_pool_lock(inst.exec_pool_va).ok_or(STATUS_INVALID_PARAMETER)?;
    if hosted_instance_pool_allocation_is_free_unlocked(inst, address) != Some(false) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let exec = hosted_pool_allocation_exec_va(inst.exec_pool_va, address, bytes as u64)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let generation = read_volatile((exec - 8) as *const u64);
    if generation == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    row(id).allocations[slot].as_mut().unwrap().generation = generation;
    Ok((address, exec))
}

unsafe fn build(id: u64, name: &[u16], mut init: WdmDeviceObjectInit) -> Result<(), i32> {
    let (driver, driver_exec) = allocate(
        id,
        0,
        WDM_X64_DRIVER_OBJECT_SIZE + WDM_X64_DRIVER_EXTENSION_SIZE,
    )?;
    let (device, device_exec) = allocate(id, 1, WDM_X64_DEVICE_OBJECT_SIZE)?;
    let length = name.len().checked_mul(2).ok_or(STATUS_INVALID_PARAMETER)?;
    let maximum = length.checked_add(2).ok_or(STATUS_INVALID_PARAMETER)?;
    let length = u16::try_from(length).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let maximum = u16::try_from(maximum).map_err(|_| STATUS_INVALID_PARAMETER)?;
    let (name_address, name_exec) = allocate(id, 2, maximum as usize)?;
    let driver_bytes = core::slice::from_raw_parts_mut(
        driver_exec as *mut u8,
        WDM_X64_DRIVER_OBJECT_SIZE + WDM_X64_DRIVER_EXTENSION_SIZE,
    );
    nt_io_manager::write_wdm_driver_object(
        driver_bytes,
        WdmDriverObjectInit {
            size_field: WDM_X64_DRIVER_OBJECT_SIZE as u16,
            device_object: device,
            driver_extension: driver + WDM_X64_DRIVER_OBJECT_SIZE as u64,
            ..Default::default()
        },
    )
    .map_err(|_| STATUS_INVALID_PARAMETER)?;
    driver_bytes[0x38..0x3a].copy_from_slice(&length.to_le_bytes());
    driver_bytes[0x3a..0x3c].copy_from_slice(&maximum.to_le_bytes());
    driver_bytes[0x40..0x48].copy_from_slice(&name_address.to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        core::ptr::write_unaligned((name_exec + index as u64 * 2) as *mut u16, *unit);
    }
    core::ptr::write_unaligned((name_exec + length as u64) as *mut u16, 0);
    init.driver_object = driver;
    init.size_field = WDM_X64_DEVICE_OBJECT_SIZE as u16;
    nt_io_manager::write_wdm_device_object(
        core::slice::from_raw_parts_mut(device_exec as *mut u8, WDM_X64_DEVICE_OBJECT_SIZE),
        init,
    )
    .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let registration = io_manager_mut()
        .bind_hosted_device_pointer(row(id).domain, device, row(id).device)
        .map_err(|status| status.raw())?;
    row(id).registration = Some(registration);
    row(id).projection = Some(
        ConsumerDeviceProjection::new(io_manager_mut(), registration)
            .map_err(|status| status.raw())?,
    );
    Ok(())
}

unsafe fn retire(id: u64) -> Result<(), i32> {
    if !row(id).retiring {
        return Err(STATUS_DEVICE_BUSY);
    }
    let inst = live_instance(id)?;
    if let Some(projection) = row(id).projection.as_mut() {
        if !projection.is_retired() {
            projection
                .begin_retirement(io_manager_mut())
                .map_err(|status| status.raw())?;
        }
        row(id).registration = None;
    } else if let Some(registration) = row(id).registration {
        io_manager_mut()
            .retire_hosted_device_pointer(registration)
            .map_err(|status| status.raw())?;
        row(id).registration = None;
    }
    for slot in (0..3).rev() {
        if let Some(allocation) = row(id).allocations[slot].as_ref() {
            let address = allocation.address;
            let generation = allocation.generation;
            let _lock = hosted_instance_pool_lock(inst.exec_pool_va).ok_or(STATUS_DEVICE_BUSY)?;
            let exec = hosted_pool_allocation_exec_va(inst.exec_pool_va, address, 1)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            if generation == 0
                || hosted_instance_pool_allocation_is_free_unlocked(inst, address) != Some(false)
                || read_volatile((exec - 8) as *const u64) != generation
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
            // This local allocator returns false only before either free-list store.
            if !hosted_instance_pool_free_unlocked(inst, address) {
                return Err(STATUS_DEVICE_BUSY);
            }
            row(id).allocations[slot] = None;
        }
    }
    let index = rows().iter().position(|row| row.id == id).unwrap();
    rows().swap_remove(index);
    Ok(())
}

pub(super) unsafe fn acquire_device(
    instance_index: usize,
    domain: HostedDomainIdentity,
    file: FileId,
    device: DeviceId,
    name: &[u16],
    init: WdmDeviceObjectInit,
) -> Result<DeviceOwner, i32> {
    let inst = instance(instance_index).ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    if instance_domain_identity(inst) != Some(domain) {
        return Err(STATUS_ACCESS_DENIED);
    }
    let existing = rows()
        .iter()
        .find(|row| {
            row.instance_index == instance_index && row.domain == domain && row.device == device
        })
        .map(|row| row.id);
    let id = if let Some(id) = existing {
        live_instance(id)?;
        if row(id)
            .projection
            .as_ref()
            .is_none_or(|projection| projection.is_retired())
        {
            return Err(STATUS_DEVICE_BUSY);
        }
        id
    } else {
        if let Some(address) = io_manager_mut().hosted_device_address_by_identity(domain, device) {
            let registration = io_manager_mut().hosted_device_pointer_registration(domain, address);
            print_str(b"[consumer-device-acquire-denied] stage=existing-registration domain=");
            print_hex64(domain.domain_id.0);
            print_str(b" generation=");
            print_hex64(domain.cookie);
            print_str(b" file=");
            print_hex64(file.0);
            print_str(b" device=");
            print_hex64(device.0);
            print_str(b" new-address=0x0 existing-address=");
            print_hex64(address);
            print_str(b" registration-generation=");
            print_hex64(registration.map_or(0, |value| value.generation()));
            print_str(b"\n");
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let id = NEXT_ID;
        let next = id.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        rows()
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        rows().push(Row {
            id,
            instance_index,
            domain,
            pool_va: inst.exec_pool_va,
            pml4: inst.pml4,
            device,
            allocations: [None, None, None],
            projection: None,
            registration: None,
            retiring: false,
        });
        NEXT_ID = next;
        if let Err(status) = build(id, name, init) {
            row(id).retiring = true;
            let _ = retire(id);
            return Err(status);
        }
        id
    };
    let lease = match row(id)
        .projection
        .as_mut()
        .ok_or(STATUS_DEVICE_BUSY)?
        .acquire(io_manager_mut(), file)
    {
        Ok(lease) => lease,
        Err(status) => {
            if row(id).projection.as_ref().unwrap().lease_count() == 0 {
                row(id).retiring = true;
                let _ = retire(id);
            }
            return Err(status.raw());
        }
    };
    row(id).retiring = false;
    Ok(DeviceOwner { row_id: id, lease })
}

pub(super) unsafe fn release_device(owner: &mut DeviceOwner) -> Result<(), i32> {
    live_instance(owner.row_id)?;
    let projection = row(owner.row_id)
        .projection
        .as_mut()
        .ok_or(STATUS_INVALID_HANDLE)?;
    projection
        .release(io_manager_mut(), &mut owner.lease)
        .map_err(|status| status.raw())?;
    if projection.lease_count() == 0 {
        row(owner.row_id).retiring = true;
    }
    // The exact lease is released once; physical cleanup has an independent retained journal.
    redrive();
    Ok(())
}

pub(super) unsafe fn redrive() {
    let mut after = 0;
    while let Some(id) = rows()
        .iter()
        .filter(|row| row.retiring && row.id > after)
        .map(|row| row.id)
        .min()
    {
        after = id;
        let _ = retire(id);
    }
}
