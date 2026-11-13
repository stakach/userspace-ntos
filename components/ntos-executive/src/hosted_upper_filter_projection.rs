//! Retained component-local projections needed before a foreign class filter enters AddDevice.
//!
//! The class driver receives its own PDO and current lower FDO pointers. These are aliases for
//! existing canonical devices, not new canonical devices. Keep their exact pool allocations and
//! pointer registrations until a separate, acknowledged stack teardown can retire them.

use super::*;
use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::HostedDevicePointerRegistration;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Reserved,
    ProjectingPdo,
    Allocating,
    ProjectingLower,
    Published,
    Configuring,
    Configured,
    Entered,
    Attached,
    Retiring,
    Blocked,
}

#[derive(Clone, Copy)]
struct Alias {
    address: u64,
    allocation: Option<SourcePoolAllocationIdentity>,
    registration: Option<HostedDevicePointerRegistration>,
    pointer_retired: bool,
    physical_retired: bool,
}

#[derive(Clone, Copy)]
struct Owner {
    id: u64,
    devnode: nt_pnp_manager::DevnodeIdentity,
    pdo: nt_io_manager::DeviceId,
    function: nt_io_manager::DeviceId,
    lower: nt_io_manager::DeviceId,
    class_driver: DriverId,
    driver_instance: usize,
    class_instance: usize,
    class_domain: HostedDomainIdentity,
    lower_domain: HostedDomainIdentity,
    lower_origin_registration: HostedDevicePointerRegistration,
    phase: Phase,
    pdo_alias: Option<Alias>,
    lower_alias: Option<Alias>,
    class_fdo: Option<Alias>,
}

static mut OWNERS: Vec<Owner> = Vec::new();
static mut NEXT_ID: u64 = 1;

/// An alias remains live through blocked and uncertain effects. Driver teardown must wait for an
/// explicit future retirement owner; absence of a completed AddDevice is not a release signal.
pub(super) fn instance_quiesced(instance_index: usize) -> bool {
    owners()
        .iter()
        .all(|row| row.driver_instance != instance_index && row.class_instance != instance_index)
}

/// The exact class FDO produced by an acknowledged AddDevice. A reverse CONNECT projection may
/// use this as its source identity, but must mint its own port-domain alias and callback route.
pub(super) unsafe fn class_fdo_registration(
    pdo_id: u64,
    class_driver_id: u64,
) -> Result<HostedDevicePointerRegistration, nt_status::NtStatus> {
    let row = *owners()
        .iter()
        .find(|row| {
            row.pdo.raw() == pdo_id
                && row.class_driver.raw() == class_driver_id
                && row.phase == Phase::Attached
        })
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let alias = row
        .class_fdo
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let registration = alias
        .registration
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let allocation = alias
        .allocation
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let inst = instance(row.class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if hosted_pnp_manager_mut().devnode_identity_for_pdo(pdo_id) != Some(row.devnode)
        || instance_domain_identity(inst) != Some(row.class_domain)
        || io_manager_mut().hosted_device_pointer_registration(row.class_domain, alias.address)
            != Some(registration)
        || hosted_device_allocations::capture_allocation(inst, alias.address)? != allocation
        || !io_manager_mut()
            .device(registration.device_id())
            .is_some_and(|device| {
                device.driver_id == row.class_driver && device.attached_to == Some(row.lower)
            })
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(registration)
}

/// Resolve the lower alias while the class AddDevice callback is active. This alias is the
/// actual target of the forwarded CONNECT; the newly created class PortDO is above it.
pub(super) unsafe fn entered_lower_registration(
    domain: HostedDomainIdentity,
    address: u64,
) -> Result<Option<(HostedDevicePointerRegistration, DriverId)>, nt_status::NtStatus> {
    let Some(row) = owners().iter().find(|row| {
        row.class_domain == domain
            && row.lower_alias.is_some_and(|alias| alias.address == address)
    }).copied() else {
        return Ok(None);
    };
    if row.phase != Phase::Entered
        || hosted_pnp_manager_mut().devnode_identity_for_pdo(row.pdo.raw()) != Some(row.devnode)
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let alias = row.lower_alias.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let registration = alias.registration.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let allocation = alias.allocation.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let inst = instance(row.class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if instance_domain_identity(inst) != Some(domain)
        || io_manager_mut().hosted_device_pointer_registration(domain, address) != Some(registration)
        || registration.device_id() != row.lower
        || hosted_device_allocations::capture_allocation(inst, address)? != allocation
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    Ok(Some((registration, row.class_driver)))
}

/// Resolve the original port-domain pointer behind an entered class-local lower alias. Reverse
/// CONNECT projection must use this exact physical domain, never infer one from a driver id.
pub(super) unsafe fn entered_lower_origin_registration(
    domain: HostedDomainIdentity,
    address: u64,
) -> Result<Option<HostedDevicePointerRegistration>, nt_status::NtStatus> {
    let Some((local, _)) = entered_lower_registration(domain, address)? else {
        return Ok(None);
    };
    let row = owners().iter().find(|row| {
        row.class_domain == domain
            && row.phase == Phase::Entered
            && row.lower_alias.is_some_and(|alias| alias.registration == Some(local))
    }).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if io_manager_mut().hosted_device_pointer_registration(
        row.lower_domain, row.lower_origin_registration.address(),
    ) != Some(row.lower_origin_registration)
        || row.lower_origin_registration.device_id() != local.device_id()
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    Ok(Some(row.lower_origin_registration))
}

fn owners() -> &'static mut Vec<Owner> {
    unsafe { &mut *core::ptr::addr_of_mut!(OWNERS) }
}

fn owner(id: u64) -> Option<&'static mut Owner> {
    owners().iter_mut().find(|row| row.id == id)
}

/// Exact aliases to pass to the class driver's AddDevice boundary. The caller must revalidate
/// immediately before that entry; this snapshot alone does not authorize attachment or dispatch.
#[derive(Clone, Copy)]
pub(super) struct PreparedUpperFilterProjection {
    pub(super) owner_id: u64,
    pub(super) pdo_object: u64,
    pub(super) lower_object: u64,
    pub(super) class_domain: HostedDomainIdentity,
    pub(super) pdo_registration: HostedDevicePointerRegistration,
    pub(super) lower_registration: HostedDevicePointerRegistration,
    pub(super) lower_type: u32,
    pub(super) lower_flags: u32,
    pub(super) lower_characteristics: u32,
    pub(super) lower_stack_size: u8,
}

/// The two class-local aliases have distinct canonical targets and must be acknowledged in
/// order. The caller owns the class dispatch page across both native projection pumps.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum AliasKind {
    Pdo,
    Lower,
}

/// Reserve one exact PnP generation before entering a native projection pump. This is pure
/// admission: the caller may release this row if bank or ledger admission fails afterward.
pub(super) unsafe fn reserve_alias_owner(
    instance_path: &str,
    claim: nt_pnp_manager::UpperFilterAttachmentClaim,
) -> Result<(u64, usize), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let pdo_id = claim.key().child().pdo_object_id();
    let function_id = claim.key().function_fdo();
    let class_driver_id = claim.driver_id();
    let lower_id = claim.lower_device();
    let pdo = nt_io_manager::DeviceId(pdo_id);
    let function = nt_io_manager::DeviceId(function_id);
    let lower = nt_io_manager::DeviceId(lower_id);
    let class_driver = DriverId(class_driver_id);
    let devnode = hosted_pnp_manager_mut()
        .devnode_identity_for_pdo(pdo_id)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if !hosted_pnp_manager_mut()
        .instance_id(devnode.devnode_id())
        .is_some_and(|current| current.eq_ignore_ascii_case(instance_path))
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    nt_pnp_manager::UpperFilterAttachmentLedger::validate_current(
        hosted_pnp_manager_mut(),
        claim.key(),
    )
    .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let (driver_instance, driver_inst) =
        instance_by_driver_id(class_driver_id).ok_or(nt_status::NtStatus::OBJECT_NAME_NOT_FOUND)?;
    let route = hosted_provider_dispatch_route_for_instance(driver_instance);
    let class_instance = route
        .map(|route| route.provider_instance)
        .unwrap_or(driver_instance);
    let class_inst = instance(class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let class_domain =
        instance_domain_identity(class_inst).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if (driver_inst.add_device == 0 && !route.is_some_and(|route| route.add_device_ready()))
        || io_manager_mut().hosted_domain_identity(class_domain.domain_id) != Some(class_domain)
        || io_manager_mut()
            .hosted_driver_address_by_identity(class_domain, class_driver)
            .is_none()
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let binding = hosted_device_binding_by_device_id(function_id)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if binding.pdo_device_id != pdo_id
        || binding.driver_id == class_driver_id
        || binding.projection_domain == class_domain
        || binding.device_object == 0
        || !io_manager_mut()
            .device(pdo)
            .is_some_and(|device| !device.delete_pending)
        || !io_manager_mut()
            .device(function)
            .is_some_and(|device| !device.delete_pending && device.attached_to == Some(pdo))
        || io_manager_mut().top_of_device_stack(pdo) != Ok(lower)
        || io_manager_mut()
            .hosted_device_address_by_identity(class_domain, pdo)
            .is_some()
        || io_manager_mut()
            .hosted_device_address_by_identity(class_domain, lower)
            .is_some()
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let (lower_domain, lower_origin_registration) = if lower == function {
        (
            binding.projection_domain,
            hosted_device_pointer_registration(
                binding.projection_domain,
                binding.device_object,
                function,
            )?,
        )
    } else {
        let prior = owners()
            .iter()
            .find(|row| {
                row.devnode == devnode
                    && row.phase == Phase::Attached
                    && row.class_fdo.is_some_and(|fdo| {
                        fdo.registration
                            .is_some_and(|registration| registration.device_id() == lower)
                    })
            })
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        (
            prior.class_domain,
            prior.class_fdo.unwrap().registration.unwrap(),
        )
    };
    if io_manager_mut()
        .hosted_device_pointer_registration(lower_domain, lower_origin_registration.address())
        != Some(lower_origin_registration)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    if owners().iter().any(|row| {
        row.devnode == devnode
            && (row.pdo == pdo || row.class_domain == class_domain)
            && row.class_driver == class_driver
    }) {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let id = unsafe { NEXT_ID };
    let next = id
        .checked_add(1)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    owners()
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    owners().push(Owner {
        id,
        devnode,
        pdo,
        function,
        lower,
        class_driver,
        driver_instance,
        class_instance,
        class_domain,
        lower_domain,
        lower_origin_registration,
        phase: Phase::Reserved,
        pdo_alias: None,
        lower_alias: None,
        class_fdo: None,
    });
    unsafe {
        NEXT_ID = next;
    }
    Ok((id, class_instance))
}

/// Release a reservation only while no native projection has entered. Once an alias pump starts,
/// its caller must keep the exact row, including an indeterminate completion without an address.
pub(super) fn release_reserved_alias_owner(owner_id: u64) -> Result<(), nt_status::NtStatus> {
    let index = owners().iter().position(|row| row.id == owner_id)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = owners()[index];
    if row.phase != Phase::Reserved || row.pdo_alias.is_some() || row.lower_alias.is_some() {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    owners().swap_remove(index);
    Ok(())
}

/// Transfer the reserved row to an impending native pump before it can allocate an alias. A
/// yielded or uncertain pump therefore cannot be released as a no-effect reservation.
pub(super) fn begin_alias_projection(
    owner_id: u64,
    kind: AliasKind,
) -> Result<(), nt_status::NtStatus> {
    let row = owner(owner_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let (expected, entered) = match kind {
        AliasKind::Pdo => (Phase::Reserved, Phase::ProjectingPdo),
        AliasKind::Lower => (Phase::Allocating, Phase::ProjectingLower),
    };
    if row.phase != expected
        || (kind == AliasKind::Pdo && row.pdo_alias.is_some())
        || (kind == AliasKind::Lower
            && (row.pdo_alias.is_none_or(|alias| alias.registration.is_none())
                || row.lower_alias.is_some()))
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    row.phase = entered;
    Ok(())
}

/// Record an acknowledged projection immediately. The owner remains durable across allocation,
/// protection and pointer registration; a failure blocks reuse of the class domain and address.
pub(super) unsafe fn accept_alias_projection(
    owner_id: u64,
    kind: AliasKind,
    address: u64,
) -> Result<(), nt_status::NtStatus> {
    let row = *owner(owner_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let expected_phase = match kind { AliasKind::Pdo => Phase::ProjectingPdo, AliasKind::Lower => Phase::ProjectingLower };
    if row.phase != expected_phase
        || address == 0
        || (kind == AliasKind::Pdo && row.pdo_alias.is_some())
        || (kind == AliasKind::Lower
            && (row.pdo_alias.is_none_or(|alias| alias.registration.is_none())
                || row.lower_alias.is_some()))
    {
        block_uncertain(owner_id);
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let device = match kind { AliasKind::Pdo => row.pdo, AliasKind::Lower => row.lower };
    let alias = Alias {
        address, allocation: None, registration: None,
        pointer_retired: false, physical_retired: false,
    };
    {
        let target = owner(owner_id).unwrap();
        target.phase = Phase::Allocating;
        match kind { AliasKind::Pdo => target.pdo_alias = Some(alias), AliasKind::Lower => target.lower_alias = Some(alias) };
    }
    let result = (|| {
        let class_inst = instance(row.class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
        if instance_domain_identity(class_inst) != Some(row.class_domain) {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let allocation = hosted_device_allocations::capture_allocation(class_inst, address)?;
        let alias = match kind { AliasKind::Pdo => owner(owner_id).unwrap().pdo_alias.as_mut().unwrap(),
                                 AliasKind::Lower => owner(owner_id).unwrap().lower_alias.as_mut().unwrap() };
        alias.allocation = Some(allocation);
        hosted_device_allocations::protect_allocation_exact(class_inst, address, Some(allocation))?;
        match register_unlinked_hosted_device_projection(class_inst, row.class_domain, address, device) {
            Ok(registration) => {
                let alias = match kind { AliasKind::Pdo => owner(owner_id).unwrap().pdo_alias.as_mut().unwrap(),
                                         AliasKind::Lower => owner(owner_id).unwrap().lower_alias.as_mut().unwrap() };
                alias.registration = Some(registration);
                Ok(())
            }
            Err(error) => {
                if let Some(registration) = error.accepted_registration() {
                    let alias = match kind { AliasKind::Pdo => owner(owner_id).unwrap().pdo_alias.as_mut().unwrap(),
                                             AliasKind::Lower => owner(owner_id).unwrap().lower_alias.as_mut().unwrap() };
                    alias.registration = Some(registration);
                }
                Err(error.status)
            }
        }
    })();
    if let Err(status) = result {
        block_uncertain(owner_id);
        return Err(status);
    }
    if kind == AliasKind::Lower { owner(owner_id).unwrap().phase = Phase::Published; }
    Ok(())
}

/// Publish the fully recorded pair after both typed projection pumps have completed.
pub(super) unsafe fn finish_prepared(
    owner_id: u64,
) -> Result<PreparedUpperFilterProjection, nt_status::NtStatus> {
    match validate_before_add_device(owner_id) {
        Ok(prepared) => Ok(prepared),
        Err(status) => { block_uncertain(owner_id); Err(status) }
    }
}

/// Recheck canonical topology, physical generations, and both exact pointer generations before
/// entering class AddDevice. A changed top is an explicit refusal, never a guessed attachment.
pub(super) unsafe fn validate_before_add_device(
    owner_id: u64,
) -> Result<PreparedUpperFilterProjection, nt_status::NtStatus> {
    let row = *owner(owner_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !matches!(row.phase, Phase::Published | Phase::Configured)
        || hosted_pnp_manager_mut().devnode_identity_for_pdo(row.pdo.raw()) != Some(row.devnode)
        || io_manager_mut().hosted_domain_identity(row.class_domain.domain_id)
            != Some(row.class_domain)
        || io_manager_mut().hosted_domain_identity(row.lower_domain.domain_id)
            != Some(row.lower_domain)
        || io_manager_mut().top_of_device_stack(row.pdo) != Ok(row.lower)
        || !io_manager_mut()
            .device(row.function)
            .is_some_and(|device| !device.delete_pending && device.attached_to == Some(row.pdo))
        || instance(row.class_instance).and_then(instance_domain_identity) != Some(row.class_domain)
        || io_manager_mut()
            .hosted_driver_address_by_identity(row.class_domain, row.class_driver)
            .is_none()
        || io_manager_mut().hosted_device_pointer_registration(
            row.lower_domain,
            row.lower_origin_registration.address(),
        ) != Some(row.lower_origin_registration)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let class_inst =
        instance(row.class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let lower_device = io_manager_mut()
        .device(row.lower)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let (lower_type, lower_flags, lower_characteristics, lower_stack_size) = (
        lower_device.device_type.0,
        lower_device.flags.bits(),
        lower_device.characteristics.bits(),
        lower_device.stack_size,
    );
    if lower_stack_size == 0 || lower_stack_size == u8::MAX {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let pdo = row
        .pdo_alias
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let lower = row
        .lower_alias
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    for (alias, device) in [(pdo, row.pdo), (lower, row.lower)] {
        let registration = alias
            .registration
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let allocation = alias
            .allocation
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        if registration.device_id() != device
            || registration.domain() != row.class_domain
            || registration.address() != alias.address
            || hosted_device_allocations::capture_allocation(class_inst, alias.address)?
                != allocation
            || io_manager_mut()
                .hosted_device_pointer_registration(row.class_domain, registration.address())
                != Some(registration)
        {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
    }
    Ok(PreparedUpperFilterProjection {
        owner_id,
        pdo_object: pdo.address,
        lower_object: lower.address,
        class_domain: row.class_domain,
        pdo_registration: pdo.registration.unwrap(),
        lower_registration: lower.registration.unwrap(),
        lower_type,
        lower_flags,
        lower_characteristics,
        lower_stack_size,
    })
}

/// Call just before the component-local alias initialization request. A lost reply may mean the
/// local chain was mutated; in that case the row is blocked and neither alias can be replayed.
pub(super) unsafe fn begin_local_chain(
    owner_id: u64,
) -> Result<PreparedUpperFilterProjection, nt_status::NtStatus> {
    let projection = validate_before_add_device(owner_id)?;
    if owner(owner_id).unwrap().phase != Phase::Published {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    owner(owner_id).unwrap().phase = Phase::Configuring;
    Ok(projection)
}

/// Accept an acknowledged component-local PDO→lower link. The caller must compare the returned
/// lower address with `pdo_object` before calling this; all other outcomes stay retained.
pub(super) unsafe fn complete_local_chain(
    owner_id: u64,
    observed_pdo: u64,
) -> Result<(), nt_status::NtStatus> {
    let row = *owner(owner_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.phase != Phase::Configuring
        || row
            .pdo_alias
            .is_none_or(|alias| alias.address != observed_pdo)
    {
        if row.phase == Phase::Configuring {
            owner(owner_id).unwrap().phase = Phase::Blocked;
        }
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    owner(owner_id).unwrap().phase = Phase::Configured;
    if let Err(status) = validate_before_add_device(owner_id) {
        block_uncertain(owner_id);
        return Err(status);
    }
    Ok(())
}

pub(super) fn block_uncertain(owner_id: u64) {
    if let Some(row) = owner(owner_id) {
        row.phase = Phase::Blocked;
    }
}

/// Transfer the prepared aliases to the impending callback. Once entered, only the eventual
/// class-stack teardown may release them, including when callback transport is indeterminate.
pub(super) unsafe fn begin_add_device(
    owner_id: u64,
) -> Result<PreparedUpperFilterProjection, nt_status::NtStatus> {
    let projection = validate_before_add_device(owner_id)?;
    if owner(owner_id).unwrap().phase != Phase::Configured {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    owner(owner_id).unwrap().phase = Phase::Entered;
    Ok(projection)
}

/// Transfer an exact IoCreateDevice registration from the AddDevice rollback owner after the
/// callback succeeded and its checked IoAttach established the expected canonical edge. The
/// caller must first prove that registration was created by this exact callback reservation.
pub(super) unsafe fn complete_add_device(
    owner_id: u64,
    class_registration: HostedDevicePointerRegistration,
) -> Result<u64, nt_status::NtStatus> {
    let row = *owner(owner_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.phase != Phase::Entered
        || class_registration.domain() != row.class_domain
        || class_registration.device_id() == row.lower
        || io_manager_mut()
            .hosted_device_pointer_registration(row.class_domain, class_registration.address())
            != Some(class_registration)
        || io_manager_mut().top_of_device_stack(row.pdo) != Ok(class_registration.device_id())
        || !io_manager_mut()
            .device(class_registration.device_id())
            .is_some_and(|device| {
                device.driver_id == row.class_driver && device.attached_to == Some(row.lower)
            })
    {
        block_uncertain(owner_id);
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let class_inst =
        instance(row.class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let allocation =
        hosted_device_allocations::capture_allocation(class_inst, class_registration.address())?;
    if !hosted_device_allocations::protects_allocation(class_inst, class_registration.address()) {
        block_uncertain(owner_id);
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    owner(owner_id).unwrap().class_fdo = Some(Alias {
        address: class_registration.address(),
        allocation: Some(allocation),
        registration: Some(class_registration),
        pointer_retired: false,
        physical_retired: false,
    });
    owner(owner_id).unwrap().phase = Phase::Attached;
    Ok(class_registration.device_id().raw())
}

/// Abort a prepared projection before AddDevice entry. Each original registration is retired
/// separately from its physical pool allocation. Any uncertain retirement leaves the row and
/// remaining ownership intact, blocking class-domain unload and address reuse.
pub(super) unsafe fn abort_prepared(owner_id: u64) -> Result<(), nt_status::NtStatus> {
    let row = *owner(owner_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.phase != Phase::Published {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let class_inst =
        instance(row.class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    for alias in [row.lower_alias, row.pdo_alias] {
        let alias = alias.ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let expected = alias
            .allocation
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let registration = alias
            .registration
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        if hosted_device_allocations::capture_allocation(class_inst, alias.address)? != expected
            || io_manager_mut().hosted_device_pointer_registration(row.class_domain, alias.address)
                != Some(registration)
        {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
    }
    owner(owner_id).unwrap().phase = Phase::Retiring;
    for is_lower in [true, false] {
        let alias = if is_lower {
            owner(owner_id).unwrap().lower_alias.unwrap()
        } else {
            owner(owner_id).unwrap().pdo_alias.unwrap()
        };
        let registration = alias.registration.unwrap();
        if let Err(status) = hosted_device_allocations::retire_canonical_pointer(io_manager_mut(), registration) {
            owner(owner_id).unwrap().phase = Phase::Blocked;
            return Err(status);
        }
        if is_lower {
            owner(owner_id)
                .unwrap()
                .lower_alias
                .as_mut()
                .unwrap()
                .pointer_retired = true;
        } else {
            owner(owner_id)
                .unwrap()
                .pdo_alias
                .as_mut()
                .unwrap()
                .pointer_retired = true;
        }
        if let Err(status) = retire_hosted_device_projection(
            class_inst,
            alias.address,
            CanonicalRetirement::Retired { registration },
            None,
        ) {
            owner(owner_id).unwrap().phase = Phase::Blocked;
            return Err(status);
        }
        if is_lower {
            owner(owner_id)
                .unwrap()
                .lower_alias
                .as_mut()
                .unwrap()
                .physical_retired = true;
        } else {
            owner(owner_id)
                .unwrap()
                .pdo_alias
                .as_mut()
                .unwrap()
                .physical_retired = true;
        }
    }
    let index = owners().iter().position(|row| row.id == owner_id).unwrap();
    owners().swap_remove(index);
    Ok(())
}
