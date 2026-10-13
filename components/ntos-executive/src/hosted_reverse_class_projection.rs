//! Retained reverse DEVICE_OBJECT aliases for a class-to-port CONNECT.
//!
//! ReactOS passes the main ClassDO and its callback to i8042prt, which can issue a synchronous
//! HOOK to the attached class PortDO. Both class objects must therefore have distinct addresses
//! in the port domain. Each address is bound to its exact canonical source device and held until
//! a separately acknowledged disconnect and source completion permits retirement.

use super::*;
use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::HostedDevicePointerRegistration;
use nt_io_manager::reverse_class_alias_projection::{
    ReverseClassAliasIdentity, ReverseClassAliasPhase, ReverseClassAliasProjection,
};

#[derive(Clone, Copy)]
struct Member {
    source: HostedDevicePointerRegistration,
    source_allocation: SourcePoolAllocationIdentity,
    alias: Option<u64>,
    alias_allocation: Option<SourcePoolAllocationIdentity>,
    alias_registration: Option<HostedDevicePointerRegistration>,
    shape: hosted_reverse_class_alias::ClassAliasShape,
}

struct Owner {
    id: u64,
    projection: ReverseClassAliasProjection,
    class_instance: usize,
    class_domain: HostedDomainIdentity,
    port_instance: usize,
    port_domain: HostedDomainIdentity,
    lower_origin: HostedDevicePointerRegistration,
    port_do: Member,
    class_do: Member,
}

impl Owner {
    fn identity(&self) -> Result<ReverseClassAliasIdentity, nt_status::NtStatus> {
        Ok(ReverseClassAliasIdentity {
            source_port_fdo: self.port_do.source,
            source_main: self.class_do.source,
            alias_port_fdo: self.port_do.alias_registration.ok_or(nt_status::NtStatus::INVALID_HANDLE)?,
            alias_main: self.class_do.alias_registration.ok_or(nt_status::NtStatus::INVALID_HANDLE)?,
        })
    }
}

static mut OWNERS: Vec<Owner> = Vec::new();
static mut NEXT_ID: u64 = 1;

fn owners() -> &'static mut Vec<Owner> {
    unsafe { &mut *core::ptr::addr_of_mut!(OWNERS) }
}

fn owner(id: u64) -> Option<&'static mut Owner> {
    owners().iter_mut().find(|row| row.id == id)
}

/// Block unload while either side can still hold a projected pointer or an uncertain pump.
pub(super) fn instance_quiesced(index: usize) -> bool {
    owners().iter().all(|row| row.class_instance != index && row.port_instance != index)
}

#[derive(Clone, Copy)]
pub(super) struct PreparedReverseClassProjection {
    pub(super) owner_id: u64,
    pub(super) port_domain_port_do: u64,
    pub(super) port_domain_class_do: u64,
    pub(super) port_do_shape: hosted_reverse_class_alias::ClassAliasShape,
    pub(super) class_do_shape: hosted_reverse_class_alias::ClassAliasShape,
    pub(super) port_do_registration: HostedDevicePointerRegistration,
    pub(super) class_do_registration: HostedDevicePointerRegistration,
}

unsafe fn source_member(
    inst: DriverInstance,
    registration: HostedDevicePointerRegistration,
) -> Result<Member, nt_status::NtStatus> {
    let domain = instance_domain_identity(inst).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if registration.domain() != domain
        || io_manager_mut().hosted_device_pointer_registration(domain, registration.address())
            != Some(registration)
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let allocation = hosted_device_allocations::capture_allocation(inst, registration.address())?;
    if !hosted_device_allocations::protects_allocation(inst, registration.address()) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let device = io_manager_mut().device(registration.device_id())
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if device.delete_pending || device.stack_size == 0 {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(Member {
        source: registration,
        source_allocation: allocation,
        alias: None,
        alias_allocation: None,
        alias_registration: None,
        shape: hosted_reverse_class_alias::ClassAliasShape {
            device_type: device.device_type.0,
            flags: device.flags.bits(),
            characteristics: device.characteristics.bits(),
            stack_size: device.stack_size,
        },
    })
}

/// Reserve both source generations before either foreign allocation. `class_port` must be the
/// PortDO created by the active class AddDevice; `class_main` comes from captured CONNECT_DATA.
/// `lower_origin` is the native port-side registration underlying the class-local lower alias.
pub(super) unsafe fn prepare(
    class_instance: usize,
    port_instance: usize,
    class_port: HostedDevicePointerRegistration,
    class_main: HostedDevicePointerRegistration,
    lower_origin: HostedDevicePointerRegistration,
) -> Result<PreparedReverseClassProjection, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let class_inst = instance(class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let port_inst = instance(port_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let class_domain = instance_domain_identity(class_inst)
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let port_domain = instance_domain_identity(port_inst)
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if class_domain == port_domain
        || class_port.domain() != class_domain || class_main.domain() != class_domain
        || lower_origin.domain() != port_domain
        || class_port.device_id() == class_main.device_id()
        || io_manager_mut().hosted_domain_identity(class_domain.domain_id) != Some(class_domain)
        || io_manager_mut().hosted_domain_identity(port_domain.domain_id) != Some(port_domain)
        || io_manager_mut().hosted_device_pointer_registration(port_domain, lower_origin.address())
            != Some(lower_origin)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    hosted_device_allocations::capture_allocation(port_inst, lower_origin.address())?;
    if !hosted_device_allocations::protects_allocation(port_inst, lower_origin.address()) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let port_do = source_member(class_inst, class_port)?;
    let class_do = source_member(class_inst, class_main)?;
    let class_driver = io_manager_mut().device(class_port.device_id())
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?.driver_id;
    if !io_manager_mut().device(class_port.device_id()).is_some_and(|device|
        device.driver_id == class_driver && device.attached_to == Some(lower_origin.device_id()))
        || !io_manager_mut().device(class_main.device_id()).is_some_and(|device|
            device.driver_id == class_driver && device.attached_to.is_none())
        || io_manager_mut().top_of_device_stack(lower_origin.device_id()) != Ok(class_port.device_id())
        || io_manager_mut().hosted_device_address_by_identity(port_domain, class_port.device_id()).is_some()
        || io_manager_mut().hosted_device_address_by_identity(port_domain, class_main.device_id()).is_some()
        || owners().iter().any(|row| row.port_do.source == class_port || row.class_do.source == class_main)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let id = unsafe { NEXT_ID };
    let next = id.checked_add(1).ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    owners().try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    // Acquire both generation-bearing references before the first port-domain allocation. The
    // owner slot is reserved first, so no fallible vector growth can strand held references.
    let projection = ReverseClassAliasProjection::new(io_manager_mut(), class_port, class_main)?;
    owners().push(Owner {
        id, projection, class_instance, class_domain, port_instance, port_domain,
        lower_origin, port_do, class_do,
    });
    unsafe { NEXT_ID = next; }
    let caller = crate::initial_system_driver_caller();
    for is_port_do in [true, false] {
        let alias = match create_hosted_pdo_projection(port_instance, caller) {
            Ok(address) => address,
            Err(status) => { block_uncertain(id); return Err(status); }
        };
        let member = if is_port_do { &mut owner(id).unwrap().port_do } else { &mut owner(id).unwrap().class_do };
        member.alias = Some(alias);
        let allocation = match hosted_device_allocations::capture_allocation(port_inst, alias) {
            Ok(allocation) => allocation,
            Err(status) => { block_uncertain(id); return Err(status); }
        };
        let member = if is_port_do { &mut owner(id).unwrap().port_do } else { &mut owner(id).unwrap().class_do };
        member.alias_allocation = Some(allocation);
        if let Err(status) = hosted_device_allocations::protect_allocation_exact(port_inst, alias, Some(allocation)) {
            block_uncertain(id);
            return Err(status);
        }
        let source = if is_port_do { class_port } else { class_main };
        match register_hosted_device_projection(port_inst, port_domain, alias, source.device_id()) {
            Ok(registration) => {
                let member = if is_port_do { &mut owner(id).unwrap().port_do } else { &mut owner(id).unwrap().class_do };
                member.alias_registration = Some(registration);
            }
            Err(error) => {
                if let Some(registration) = error.accepted_registration() {
                    let member = if is_port_do { &mut owner(id).unwrap().port_do } else { &mut owner(id).unwrap().class_do };
                    member.alias_registration = Some(registration);
                }
                block_uncertain(id);
                return Err(error.status);
            }
        }
    }
    let identity = owner(id).unwrap().identity()?;
    if let Err(status) = owner(id).unwrap().projection.stage(io_manager_mut(), identity) {
        block_uncertain(id);
        return Err(status);
    }
    match validate(id) {
        Ok(prepared) => Ok(prepared),
        Err(status) => { block_uncertain(id); Err(status) }
    }
}

/// Revalidate both source and alias physical generations plus exact canonical registrations.
pub(super) unsafe fn validate(id: u64) -> Result<PreparedReverseClassProjection, nt_status::NtStatus> {
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !matches!(row.projection.phase(), ReverseClassAliasPhase::Staged | ReverseClassAliasPhase::Entered | ReverseClassAliasPhase::Published)
        || instance(row.class_instance).and_then(instance_domain_identity) != Some(row.class_domain)
        || instance(row.port_instance).and_then(instance_domain_identity) != Some(row.port_domain)
        || io_manager_mut().hosted_device_pointer_registration(row.port_domain, row.lower_origin.address()) != Some(row.lower_origin)
        || io_manager_mut().top_of_device_stack(row.lower_origin.device_id()) != Ok(row.port_do.source.device_id())
        || !io_manager_mut().device(row.port_do.source.device_id()).is_some_and(|device|
            !device.delete_pending && device.attached_to == Some(row.lower_origin.device_id()))
        || !io_manager_mut().device(row.class_do.source.device_id()).is_some_and(|device|
            !device.delete_pending && device.attached_to.is_none())
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let class_inst = instance(row.class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let port_inst = instance(row.port_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    for member in [row.port_do, row.class_do] {
        let alias = member.alias.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        let allocation = member.alias_allocation.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        let registration = member.alias_registration.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        if hosted_device_allocations::capture_allocation(class_inst, member.source.address())? != member.source_allocation
            || io_manager_mut().hosted_device_pointer_registration(row.class_domain, member.source.address()) != Some(member.source)
            || hosted_device_allocations::capture_allocation(port_inst, alias)? != allocation
            || io_manager_mut().hosted_device_pointer_registration(row.port_domain, alias) != Some(registration)
            || registration.device_id() != member.source.device_id()
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
    }
    if row.projection.phase() == ReverseClassAliasPhase::Published {
        if row.projection.alias_for_attached_traversal(io_manager_mut())?
            != row.port_do.alias_registration.unwrap()
            || row.projection.alias_for_callback_first_argument(io_manager_mut())?
                != row.class_do.alias_registration.unwrap()
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
    }
    Ok(PreparedReverseClassProjection {
        owner_id: id,
        port_domain_port_do: row.port_do.alias.unwrap(),
        port_domain_class_do: row.class_do.alias.unwrap(),
        port_do_shape: row.port_do.shape,
        class_do_shape: row.class_do.shape,
        port_do_registration: row.port_do.alias_registration.unwrap(),
        class_do_registration: row.class_do.alias_registration.unwrap(),
    })
}

/// A lost component reply may have changed alias bytes, so no second configuration is allowed.
pub(super) unsafe fn begin_configure(id: u64) -> Result<PreparedReverseClassProjection, nt_status::NtStatus> {
    let prepared = validate(id)?;
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    row.projection.begin_publication(io_manager_mut(), row.identity()?)?;
    Ok(prepared)
}

pub(super) unsafe fn complete_configure(id: u64, observed_port_do: u64) -> Result<PreparedReverseClassProjection, nt_status::NtStatus> {
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.projection.phase() != ReverseClassAliasPhase::Entered || row.port_do.alias != Some(observed_port_do) {
        block_uncertain(id);
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let identity = row.identity()?;
    if let Err(status) = row.projection.complete_publication(io_manager_mut(), identity) {
        block_uncertain(id);
        return Err(status);
    }
    match validate(id) {
        Ok(prepared) => Ok(prepared),
        Err(status) => { block_uncertain(id); Err(status) }
    }
}

pub(super) fn block_uncertain(id: u64) {
    if let Some(row) = owner(id) {
        let _ = match row.projection.phase() {
            ReverseClassAliasPhase::Prepared | ReverseClassAliasPhase::Staged => row.projection.block_prepublication(),
            ReverseClassAliasPhase::Entered => row.projection.block_uncertain(),
            _ => Ok(()),
        };
    }
}
