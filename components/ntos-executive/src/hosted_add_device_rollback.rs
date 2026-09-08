//! Retained ownership of an unpublished AddDevice attempt and its producer projections.
use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Preparing,
    Dispatching,
    Retiring,
    Advancing,
    ProjectionInFlight,
    Blocked,
}

#[derive(Clone, Copy)]
struct CreatedDevice {
    registration: nt_io_manager::HostedDevicePointerRegistration,
    pointer_retired: bool,
    destroyed: bool,
    projection_retired: bool,
}

struct Owner {
    id: u64,
    instance: usize,
    domain: HostedDomainIdentity,
    pdo_id: u64,
    pdo: u64,
    pdo_created: bool,
    pdo_registration: Option<nt_io_manager::HostedDevicePointerRegistration>,
    driver_id: u64,
    driver_object: u64,
    previous_head: u64,
    committed_fdo: Option<nt_io_manager::DeviceId>,
    phase: Phase,
    blocked_status: Option<nt_status::NtStatus>,
    created: Vec<CreatedDevice>,
    created_reserved: usize,
    channel: Option<DriverInstance>,
    registry_identity: HostedRegistryIdentityId,
    registry_shared: u64,
    provider_registry_shared: Option<u64>,
    power_prepared: bool,
    dispatch_context_held: bool,
}

static mut OWNERS: Vec<Owner> = Vec::new();
static mut NEXT_OWNER: u64 = 1;

#[must_use]
pub(super) struct Reservation(u64);

pub(super) struct CreatedReservation(u64);

#[derive(Default)]
pub(crate) struct Stats {
    pub live: usize,
    pub prepared: usize,
    pub retiring: usize,
    pub blocked: usize,
    pub devices: usize,
    pub retired_devices: usize,
}

pub(crate) unsafe fn stats() -> Stats {
    let mut result = Stats::default();
    for row in owners() {
        result.live += 1;
        result.prepared += usize::from(matches!(row.phase, Phase::Preparing | Phase::Dispatching));
        result.retiring += usize::from(matches!(
            row.phase,
            Phase::Retiring | Phase::Advancing | Phase::ProjectionInFlight
        ));
        result.blocked += usize::from(row.phase == Phase::Blocked);
        result.devices += row.created.len();
        result.retired_devices += row
            .created
            .iter()
            .filter(|device| device.projection_retired)
            .count();
    }
    result
}

pub(super) unsafe fn lifetime_quiesced(
    instance: usize,
    driver_id: u64,
    domain: HostedDomainIdentity,
) -> bool {
    owners()
        .iter()
        .all(|row| row.instance != instance && row.driver_id != driver_id && row.domain != domain)
}

pub(super) unsafe fn instance_quiesced(index: usize) -> bool {
    let current = instance(index);
    owners().iter().all(|row| {
        row.instance != index
            && current.is_none_or(|current| {
                row.driver_id != current.driver_id
                    && (row.domain.domain_id.raw() != current.hosted_domain_id
                        || row.domain.cookie != current.hosted_domain_cookie)
            })
    })
}

unsafe fn owners() -> &'static mut Vec<Owner> {
    &mut *core::ptr::addr_of_mut!(OWNERS)
}

unsafe fn owner(id: u64) -> &'static mut Owner {
    owners()
        .iter_mut()
        .find(|owner| owner.id == id)
        .expect("retained AddDevice owner missing")
}

pub(super) unsafe fn reserve(
    instance: usize,
    domain: HostedDomainIdentity,
    pdo_id: u64,
    driver_id: u64,
) -> Result<Reservation, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    if owners().iter().any(|owner| {
        owner.domain == domain
            || owner.pdo_id == pdo_id
            || owner.driver_id == driver_id
            || owner.dispatch_context_held
    }) {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let id = core::ptr::addr_of!(NEXT_OWNER).read();
    let next = id
        .checked_add(1)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    owners()
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    owners().push(Owner {
        id,
        instance,
        domain,
        pdo_id,
        pdo: 0,
        pdo_created: false,
        pdo_registration: None,
        driver_id,
        driver_object: 0,
        previous_head: 0,
        committed_fdo: None,
        phase: Phase::Preparing,
        blocked_status: None,
        created: Vec::new(),
        created_reserved: 0,
        channel: None,
        registry_identity: INVALID_HOSTED_REGISTRY_IDENTITY_ID,
        registry_shared: 0,
        provider_registry_shared: None,
        power_prepared: false,
        dispatch_context_held: false,
    });
    core::ptr::addr_of_mut!(NEXT_OWNER).write(next);
    Ok(Reservation(id))
}

pub(super) unsafe fn record_registry(
    reservation: &Reservation,
    identity: HostedRegistryIdentityId,
    shared: u64,
    provider_shared: Option<u64>,
) {
    let row = owner(reservation.0);
    assert!(row.phase == Phase::Preparing);
    row.registry_identity = identity;
    row.registry_shared = shared;
    row.provider_registry_shared = provider_shared;
}

pub(super) unsafe fn record_power(reservation: &Reservation) {
    owner(reservation.0).power_prepared = true;
}

pub(super) unsafe fn set_pdo(
    reservation: &Reservation,
    address: u64,
    created: bool,
    registration: Option<nt_io_manager::HostedDevicePointerRegistration>,
) {
    let row = owner(reservation.0);
    assert!(row.phase == Phase::Preparing && address != 0);
    row.pdo = address;
    row.pdo_created = created;
    row.pdo_registration = registration;
}

pub(super) unsafe fn begin_dispatch(reservation: &Reservation) {
    let instance_index = owner(reservation.0).instance;
    let channel = instance(instance_index).expect("reserved AddDevice provider missing");
    let row = owner(reservation.0);
    assert!(row.phase == Phase::Preparing && row.pdo != 0);
    assert!(
        row.domain.domain_id.raw() == channel.hosted_domain_id
            && row.domain.cookie == channel.hosted_domain_cookie
    );
    row.channel = Some(channel);
    row.phase = Phase::Dispatching;
    row.dispatch_context_held = true;
}

pub(super) unsafe fn admit_mutation(
    domain: HostedDomainIdentity,
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
) -> Result<(), nt_status::NtStatus> {
    let Some(row) = owners().iter().find(|owner| owner.domain == domain) else {
        return Ok(());
    };
    let exact = row.channel.is_some_and(|channel| {
        badge == 0
            && channel.tcb == ch.tcb
            && channel.fault_ep == ch.fault_ep
            && channel.pml4 == ch.pml4
            && channel.exec_shared_va == ch.shared_va
            && channel.reply_cap == reply_cap
    });
    if row.phase != Phase::Dispatching || !exact {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    Ok(())
}

/// CREATE calls this before acquiring the canonical device or pointer registration.
pub(super) unsafe fn reserve_created(
    domain: HostedDomainIdentity,
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
) -> Result<Option<CreatedReservation>, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    admit_mutation(domain, ch, reply_cap, badge)?;
    let Some(row) = owners().iter_mut().find(|owner| owner.domain == domain) else {
        return Ok(None);
    };
    if row.phase != Phase::Dispatching {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let pending = row
        .created_reserved
        .checked_add(1)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    row.created
        .try_reserve(pending)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    row.created_reserved = pending;
    Ok(Some(CreatedReservation(row.id)))
}

pub(super) unsafe fn cancel_created(reservation: Option<CreatedReservation>) {
    if let Some(reservation) = reservation {
        let row = owner(reservation.0);
        row.created_reserved = row
            .created_reserved
            .checked_sub(1)
            .expect("CREATE reservation missing");
    }
}

pub(super) unsafe fn record_created(
    reservation: Option<CreatedReservation>,
    registration: nt_io_manager::HostedDevicePointerRegistration,
) {
    let Some(reservation) = reservation else {
        return;
    };
    let row = owner(reservation.0);
    assert!(
        row.phase == Phase::Dispatching
            && row.domain == registration.domain()
            && row.created.len() < row.created.capacity()
            && row.created_reserved != 0
    );
    row.created_reserved -= 1;
    row.created.push(CreatedDevice {
        registration,
        pointer_retired: false,
        destroyed: false,
        projection_retired: false,
    });
}

pub(super) unsafe fn record_retired(registration: nt_io_manager::HostedDevicePointerRegistration) {
    for row in owners() {
        if let Some(device) = row
            .created
            .iter_mut()
            .find(|device| device.registration == registration)
        {
            device.pointer_retired = true;
            device.destroyed = true;
            device.projection_retired = true;
        }
    }
}

pub(super) unsafe fn completed_dispatch(
    reservation: &Reservation,
    result: &AddDeviceDispatchResult,
) {
    let row = owner(reservation.0);
    assert!(row.phase == Phase::Dispatching && row.created_reserved == 0);
    row.driver_object = result.driver_object;
    row.previous_head = result.previous_device_head;
    row.phase = Phase::Preparing;
    row.dispatch_context_held = false;
}

pub(super) unsafe fn committed_stack(reservation: &Reservation, fdo: nt_io_manager::DeviceId) {
    owner(reservation.0).committed_fdo = Some(fdo);
}

pub(super) unsafe fn commit(reservation: Reservation) {
    let index = owners()
        .iter()
        .position(|owner| owner.id == reservation.0)
        .unwrap();
    assert!(owners()[index].phase == Phase::Preparing && owners()[index].created_reserved == 0);
    owners().swap_remove(index);
}

pub(super) unsafe fn block(reservation: Reservation, status: nt_status::NtStatus) {
    block_id(reservation.0, status);
}

unsafe fn block_id(id: u64, status: nt_status::NtStatus) {
    let row = owner(id);
    row.phase = Phase::Blocked;
    row.blocked_status = Some(status);
}

pub(super) unsafe fn abort(reservation: Reservation) {
    owner(reservation.0).phase = Phase::Retiring;
    let _ = advance(reservation.0);
}

unsafe fn advance(id: u64) -> Result<(), nt_status::NtStatus> {
    if owner(id).phase != Phase::Retiring {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    owner(id).phase = Phase::Advancing;
    let result = advance_inner(id);
    if result.is_err() && owner(id).phase == Phase::Advancing {
        owner(id).phase = Phase::Retiring;
    }
    result
}

unsafe fn advance_inner(id: u64) -> Result<(), nt_status::NtStatus> {
    let (instance_index, domain) = {
        let row = owner(id);
        (row.instance, row.domain)
    };
    if !instance(instance_index).is_some_and(|current| {
        current.hosted_domain_id == domain.domain_id.raw()
            && current.hosted_domain_cookie == domain.cookie
    }) || io_manager_mut().hosted_domain_identity(domain.domain_id) != Some(domain)
    {
        block_id(id, nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    let (pdo_id, driver_id, committed) = {
        let row = owner(id);
        (row.pdo_id, row.driver_id, row.committed_fdo)
    };
    if let Some(fdo) = committed {
        if let Err(error) = hosted_pnp_manager_mut()
            .rollback_device_stack(pdo_id, fdo.raw(), driver_id)
            .map_err(hosted_pnp_status)
        {
            block_id(id, error);
            return Err(error);
        }
        owner(id).committed_fdo = None;
    }
    // Detach every owned stack member before destroying any member. Creation order need not
    // be top-of-stack order, and an upper FDO must not pin a lower FDO's cleanup indefinitely.
    for index in 0..owner(id).created.len() {
        let device = owner(id).created[index];
        if device.destroyed || device.projection_retired {
            continue;
        }
        if hosted_device_retirements_mut().iter().any(|pending| {
            pending.domain == device.registration.domain()
                && pending.device_object == device.registration.address()
                && pending.device_id == device.registration.device_id()
        }) {
            continue;
        }
        let Some(canonical) = io_manager_mut().device(device.registration.device_id()) else {
            block_id(id, nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        };
        if canonical.attached_to.is_some() {
            io_manager_mut().detach_device_from_stack(device.registration.device_id())?;
        }
    }
    for index in 0..owner(id).created.len() {
        let device = owner(id).created[index];
        if device.projection_retired {
            continue;
        }
        if hosted_device_retirements_mut().iter().any(|pending| {
            pending.domain == device.registration.domain()
                && pending.device_object == device.registration.address()
                && pending.device_id == device.registration.device_id()
        }) {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        if !device.pointer_retired {
            io_manager_mut().retire_hosted_device_pointer(device.registration)?;
            owner(id).created[index].pointer_retired = true;
        }
        if !device.destroyed {
            match io_manager_mut().destroy_device(device.registration.device_id()) {
                Ok(_) => owner(id).created[index].destroyed = true,
                Err(nt_status::NtStatus::DELETE_PENDING) => {
                    return Err(nt_status::NtStatus::DELETE_PENDING)
                }
                Err(error) => {
                    // The object-manager port may have failed after removal of the device record.
                    // A missing record on retry cannot prove that external cleanup succeeded.
                    block_id(id, error);
                    return Err(error);
                }
            }
        }
    }
    if let Some(registration) = owner(id).pdo_registration {
        if owner(id).pdo_created {
            io_manager_mut().retire_hosted_device_pointer(registration)?;
            owner(id).pdo_registration = None;
        }
    }
    let (instance, driver_object, pdo, previous_head, delete_pdo) = {
        let row = owner(id);
        (
            row.instance,
            row.driver_object,
            row.pdo,
            row.previous_head,
            row.pdo_created,
        )
    };
    if pdo != 0 {
        owner(id).phase = Phase::ProjectionInFlight;
        let result = rollback_hosted_add_device_projection(
            instance,
            driver_object,
            pdo,
            previous_head,
            delete_pdo,
        );
        if let Err(error) = result {
            // This mutating RPC has no replay receipt. Retain its owner without resending it.
            block_id(id, error);
            return Err(error);
        }
    }
    let (power_prepared, registry_identity, shared, provider_shared) = {
        let row = owner(id);
        (
            row.power_prepared,
            row.registry_identity,
            row.registry_shared,
            row.provider_registry_shared,
        )
    };
    if power_prepared {
        crate::power_manager::unregister_device(pdo_id);
    }
    if shared != 0 {
        clear_shared_registry_identity_at(shared);
    }
    if let Some(shared) = provider_shared {
        clear_shared_registry_identity_at(shared);
    }
    if registry_identity != INVALID_HOSTED_REGISTRY_IDENTITY_ID {
        release_hosted_registry_identity(registry_identity);
    }
    let index = owners().iter().position(|owner| owner.id == id).unwrap();
    owners().swap_remove(index);
    Ok(())
}

pub(super) unsafe fn drain() -> usize {
    let mut index = 0;
    let mut completed = 0;
    while index < owners().len() {
        let id = owners()[index].id;
        if owners()[index].phase == Phase::Retiring && advance(id).is_ok() {
            completed += 1;
        } else {
            index += 1;
        }
    }
    completed
}
