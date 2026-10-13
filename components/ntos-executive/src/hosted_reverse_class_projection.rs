//! Retained reverse DEVICE_OBJECT aliases for a class-to-port CONNECT.
//!
//! ReactOS passes the main ClassDO and its callback to i8042prt, which can issue a synchronous
//! HOOK to the attached class PortDO. Both class objects must therefore have distinct addresses
//! in the port domain. Each address is bound to its exact canonical source device and held until
//! a separately acknowledged disconnect and source completion permits retirement.

use super::*;
use nt_io_manager::reverse_class_alias_projection::{
    ReverseClassAliasIdentity, ReverseClassAliasPhase, ReverseClassAliasProjection,
};
use nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity;
use nt_io_manager::HostedDevicePointerRegistration;

#[derive(Clone, Copy)]
struct Member {
    source: HostedDevicePointerRegistration,
    source_allocation: SourcePoolAllocationIdentity,
    alias: Option<u64>,
    alias_allocation: Option<SourcePoolAllocationIdentity>,
    alias_registration: Option<HostedDevicePointerRegistration>,
    pointer_retired: bool,
    physical_retired: bool,
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
    provider_entered: bool,
    retirement_blocked: bool,
}

impl Owner {
    fn identity(&self) -> Result<ReverseClassAliasIdentity, nt_status::NtStatus> {
        Ok(ReverseClassAliasIdentity {
            source_port_fdo: self.port_do.source,
            source_main: self.class_do.source,
            alias_port_fdo: self
                .port_do
                .alias_registration
                .ok_or(nt_status::NtStatus::INVALID_HANDLE)?,
            alias_main: self
                .class_do
                .alias_registration
                .ok_or(nt_status::NtStatus::INVALID_HANDLE)?,
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
    owners()
        .iter()
        .all(|row| row.class_instance != index && row.port_instance != index)
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
    let device = io_manager_mut()
        .device(registration.device_id())
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
        pointer_retired: false,
        physical_retired: false,
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
    let class_domain =
        instance_domain_identity(class_inst).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let port_domain =
        instance_domain_identity(port_inst).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if class_domain == port_domain
        || class_port.domain() != class_domain
        || class_main.domain() != class_domain
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
    let class_driver = io_manager_mut()
        .device(class_port.device_id())
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?
        .driver_id;
    if !io_manager_mut()
        .device(class_port.device_id())
        .is_some_and(|device| {
            device.driver_id == class_driver && device.attached_to == Some(lower_origin.device_id())
        })
        || !io_manager_mut()
            .device(class_main.device_id())
            .is_some_and(|device| device.driver_id == class_driver && device.attached_to.is_none())
        || io_manager_mut().top_of_device_stack(lower_origin.device_id())
            != Ok(class_port.device_id())
        || io_manager_mut()
            .hosted_device_address_by_identity(port_domain, class_port.device_id())
            .is_some()
        || io_manager_mut()
            .hosted_device_address_by_identity(port_domain, class_main.device_id())
            .is_some()
        || owners()
            .iter()
            .any(|row| row.port_do.source == class_port || row.class_do.source == class_main)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let id = unsafe { NEXT_ID };
    let next = id
        .checked_add(1)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    owners()
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    // Acquire both generation-bearing references before the first port-domain allocation. The
    // owner slot is reserved first, so no fallible vector growth can strand held references.
    let projection = ReverseClassAliasProjection::new(io_manager_mut(), class_port, class_main)?;
    owners().push(Owner {
        id,
        projection,
        class_instance,
        class_domain,
        port_instance,
        port_domain,
        lower_origin,
        port_do,
        class_do,
        provider_entered: false,
        retirement_blocked: false,
    });
    unsafe {
        NEXT_ID = next;
    }
    let caller = crate::initial_system_driver_caller();
    for is_port_do in [true, false] {
        let alias = match create_hosted_pdo_projection(port_instance, caller) {
            Ok(address) => address,
            Err(status) => {
                block_uncertain(id);
                return Err(status);
            }
        };
        let member = if is_port_do {
            &mut owner(id).unwrap().port_do
        } else {
            &mut owner(id).unwrap().class_do
        };
        member.alias = Some(alias);
        let allocation = match hosted_device_allocations::capture_allocation(port_inst, alias) {
            Ok(allocation) => allocation,
            Err(status) => {
                block_uncertain(id);
                return Err(status);
            }
        };
        let member = if is_port_do {
            &mut owner(id).unwrap().port_do
        } else {
            &mut owner(id).unwrap().class_do
        };
        member.alias_allocation = Some(allocation);
        if let Err(status) =
            hosted_device_allocations::protect_allocation_exact(port_inst, alias, Some(allocation))
        {
            block_uncertain(id);
            return Err(status);
        }
        let source = if is_port_do { class_port } else { class_main };
        match register_hosted_device_projection(port_inst, port_domain, alias, source.device_id()) {
            Ok(registration) => {
                let member = if is_port_do {
                    &mut owner(id).unwrap().port_do
                } else {
                    &mut owner(id).unwrap().class_do
                };
                member.alias_registration = Some(registration);
            }
            Err(error) => {
                if let Some(registration) = error.accepted_registration() {
                    let member = if is_port_do {
                        &mut owner(id).unwrap().port_do
                    } else {
                        &mut owner(id).unwrap().class_do
                    };
                    member.alias_registration = Some(registration);
                }
                block_uncertain(id);
                return Err(error.status);
            }
        }
    }
    let identity = owner(id).unwrap().identity()?;
    if let Err(status) = owner(id)
        .unwrap()
        .projection
        .stage(io_manager_mut(), identity)
    {
        block_uncertain(id);
        return Err(status);
    }
    match validate(id) {
        Ok(prepared) => Ok(prepared),
        Err(status) => {
            block_uncertain(id);
            Err(status)
        }
    }
}

/// Revalidate both source and alias physical generations plus exact canonical registrations.
pub(super) unsafe fn validate(
    id: u64,
) -> Result<PreparedReverseClassProjection, nt_status::NtStatus> {
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !matches!(
        row.projection.phase(),
        ReverseClassAliasPhase::Staged
            | ReverseClassAliasPhase::Entered
            | ReverseClassAliasPhase::Published
    ) || instance(row.class_instance).and_then(instance_domain_identity)
        != Some(row.class_domain)
        || instance(row.port_instance).and_then(instance_domain_identity) != Some(row.port_domain)
        || io_manager_mut()
            .hosted_device_pointer_registration(row.port_domain, row.lower_origin.address())
            != Some(row.lower_origin)
        || io_manager_mut().top_of_device_stack(row.lower_origin.device_id())
            != Ok(row.port_do.source.device_id())
        || !io_manager_mut()
            .device(row.port_do.source.device_id())
            .is_some_and(|device| {
                !device.delete_pending && device.attached_to == Some(row.lower_origin.device_id())
            })
        || !io_manager_mut()
            .device(row.class_do.source.device_id())
            .is_some_and(|device| !device.delete_pending && device.attached_to.is_none())
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let class_inst =
        instance(row.class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let port_inst = instance(row.port_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    for member in [row.port_do, row.class_do] {
        let alias = member.alias.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        let allocation = member
            .alias_allocation
            .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        let registration = member
            .alias_registration
            .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        if hosted_device_allocations::capture_allocation(class_inst, member.source.address())?
            != member.source_allocation
            || io_manager_mut()
                .hosted_device_pointer_registration(row.class_domain, member.source.address())
                != Some(member.source)
            || hosted_device_allocations::capture_allocation(port_inst, alias)? != allocation
            || io_manager_mut().hosted_device_pointer_registration(row.port_domain, alias)
                != Some(registration)
            || registration.device_id() != member.source.device_id()
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
    }
    if row.projection.phase() == ReverseClassAliasPhase::Published {
        if row
            .projection
            .alias_for_attached_traversal(io_manager_mut())?
            != row.port_do.alias_registration.unwrap()
            || row
                .projection
                .alias_for_callback_first_argument(io_manager_mut())?
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
pub(super) unsafe fn begin_configure(
    id: u64,
) -> Result<PreparedReverseClassProjection, nt_status::NtStatus> {
    let prepared = validate(id)?;
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    row.projection
        .begin_publication(io_manager_mut(), row.identity()?)?;
    Ok(prepared)
}

/// Configure both retained aliases in their exact port instance. The publication transition is
/// recorded before the component can modify either header, and only the matching address ACK
/// permits completion. Every ambiguous outcome leaves the owner blocked with both aliases held.
pub(super) unsafe fn dispatch_configure(
    prepared: PreparedReverseClassProjection,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> Result<PreparedReverseClassProjection, nt_status::NtStatus> {
    let id = prepared.owner_id;
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let index = row.port_instance;
    let port_domain = row.port_domain;
    let inst = instance(index).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if inst.fault_ep == 0
        || inst.pml4 == 0
        || inst.reply_cap == 0
        || instance_domain_identity(inst) != Some(port_domain)
    {
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    let exec_code_va = ExecVaWindow::try_for_instance(index)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?
        .code_va;
    let current = begin_configure(id)?;
    if current.port_domain_port_do != prepared.port_domain_port_do
        || current.port_domain_class_do != prepared.port_domain_class_do
        || current.port_do_registration != prepared.port_do_registration
        || current.class_do_registration != prepared.class_do_registration
        || current.port_do_shape.device_type != prepared.port_do_shape.device_type
        || current.port_do_shape.flags != prepared.port_do_shape.flags
        || current.port_do_shape.characteristics != prepared.port_do_shape.characteristics
        || current.port_do_shape.stack_size != prepared.port_do_shape.stack_size
        || current.class_do_shape.device_type != prepared.class_do_shape.device_type
        || current.class_do_shape.flags != prepared.class_do_shape.flags
        || current.class_do_shape.characteristics != prepared.class_do_shape.characteristics
        || current.class_do_shape.stack_size != prepared.class_do_shape.stack_size
    {
        block_uncertain(id);
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let sh = inst.exec_shared_va;
    let type_flags = |shape: hosted_reverse_class_alias::ClassAliasShape| {
        u64::from(shape.device_type) | (u64::from(shape.flags) << 32)
    };
    let characteristics_stack = |shape: hosted_reverse_class_alias::ClassAliasShape| {
        u64::from(shape.characteristics) | (u64::from(shape.stack_size) << 32)
    };
    write_volatile((sh + SH_DRVOBJ) as *mut u64, 0);
    write_volatile(
        (sh + SH_REQ_MAJOR) as *mut u64,
        FSD_DISPATCH_REVERSE_CLASS_ALIAS,
    );
    write_volatile(
        (sh + SH_REQ_MINOR) as *mut u64,
        characteristics_stack(current.port_do_shape),
    );
    write_volatile(
        (sh + SH_REQ_CONTROL_ID) as *mut u64,
        characteristics_stack(current.class_do_shape),
    );
    write_volatile(
        (sh + SH_REQ_FSCTL) as *mut u64,
        current.port_domain_class_do,
    );
    write_volatile(
        (sh + SH_REQ_INLEN) as *mut u64,
        type_flags(current.port_do_shape),
    );
    write_volatile(
        (sh + SH_REQ_OUTLEN) as *mut u64,
        type_flags(current.class_do_shape),
    );
    write_volatile(
        (sh + SH_REQ_FILEID) as *mut u64,
        current.port_domain_port_do,
    );
    write_volatile((sh + SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((sh + SH_REQ_INFO) as *mut u64, 0);

    let channel = crate::spawn_hosts::PumpChannel {
        fault_ep: inst.fault_ep,
        pml4: inst.pml4,
        physical_domain: Some(port_domain),
        ingress_route: hosted_ingress_sources::primary_route(index),
        code_va: 0,
        image_frames: 0,
        exec_code_va,
        root_image_rights: 3,
        root_image_map_owner: inst.map_cap_bank.owner,
        shared_va: sh,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 256,
        trace_faults: false,
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: inst.tcb,
        reply_cap: inst.reply_cap,
        client_pi: 0,
        client_generation: 0,
        logical_caller: None,
        kernel_caller: None,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    let result = component_scheduler::hosted_component_pump_with_caller(&channel, caller);
    if !result.completed {
        register_instance_ready(index, false);
        block_uncertain(id);
        return Err(nt_status::NtStatus::UNSUCCESSFUL);
    }
    if result.status != 0
        || read_volatile((sh + SH_REQ_INFO) as *const u64) != current.port_domain_port_do
    {
        block_uncertain(id);
        return Err(if result.status == 0 {
            nt_status::NtStatus::INVALID_DEVICE_REQUEST
        } else {
            nt_status::NtStatus(result.status)
        });
    }
    complete_configure(id, current.port_domain_port_do)
}

pub(super) unsafe fn complete_configure(
    id: u64,
    observed_port_do: u64,
) -> Result<PreparedReverseClassProjection, nt_status::NtStatus> {
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.projection.phase() != ReverseClassAliasPhase::Entered
        || row.port_do.alias != Some(observed_port_do)
    {
        block_uncertain(id);
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let identity = row.identity()?;
    if let Err(status) = row
        .projection
        .complete_publication(io_manager_mut(), identity)
    {
        block_uncertain(id);
        return Err(status);
    }
    match validate(id) {
        Ok(prepared) => Ok(prepared),
        Err(status) => {
            block_uncertain(id);
            Err(status)
        }
    }
}

pub(super) fn block_uncertain(id: u64) {
    if let Some(row) = owner(id) {
        let _ = match row.projection.phase() {
            ReverseClassAliasPhase::Prepared | ReverseClassAliasPhase::Staged => {
                row.projection.block_prepublication()
            }
            ReverseClassAliasPhase::Entered | ReverseClassAliasPhase::Published => {
                row.projection.block_uncertain()
            }
            _ => Ok(()),
        };
    }
}

/// Record the CONNECT boundary before the port driver can observe either alias. After this
/// transition an AddDevice error or a transport failure is not permission to retire the aliases.
pub(super) unsafe fn begin_provider_entry(
    id: u64,
) -> Result<PreparedReverseClassProjection, nt_status::NtStatus> {
    let prepared = validate(id)?;
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.provider_entered
        || row.retirement_blocked
        || row.projection.phase() != ReverseClassAliasPhase::Published
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    row.provider_entered = true;
    Ok(prepared)
}

/// Exact port FDO behind a published reverse class alias. The source HOOK IRP is allocated in
/// this physical domain and its device-extension buffer belongs to this original port object.
pub(super) unsafe fn port_source_for_hook(
    id: u64,
) -> Result<HostedDevicePointerRegistration, nt_status::NtStatus> {
    let prepared = validate(id)?;
    let row = owner(prepared.owner_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if !row.provider_entered
        || row.retirement_blocked
        || row.projection.phase() != ReverseClassAliasPhase::Published
    {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    Ok(row.lower_origin)
}

/// A fully published projection may be aborted only before the provider entry. An incomplete
/// or uncertain allocation remains owned; its effect cannot be reconstructed from a reply.
pub(super) unsafe fn abort_before_provider_entry(id: u64) -> Result<(), nt_status::NtStatus> {
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.provider_entered {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    retire_acknowledged_aliases(id)
}

unsafe fn retire_acknowledged_aliases(id: u64) -> Result<(), nt_status::NtStatus> {
    let row = owner(id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.retirement_blocked || row.projection.phase() != ReverseClassAliasPhase::Published {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let port_inst = instance(row.port_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if instance_domain_identity(port_inst) != Some(row.port_domain)
        || io_manager_mut().hosted_domain_identity(row.port_domain.domain_id)
            != Some(row.port_domain)
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    // Check both complete generations before retiring either one. In particular, a newly bound
    // pointer at an old address must never be accepted as this owner's registration.
    for member in [row.port_do, row.class_do] {
        let address = member.alias.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        let allocation = member
            .alias_allocation
            .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        let registration = member
            .alias_registration
            .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        if member.pointer_retired
            || member.physical_retired
            || hosted_device_allocations::capture_allocation(port_inst, address)? != allocation
            || io_manager_mut().hosted_device_pointer_registration(row.port_domain, address)
                != Some(registration)
            || registration.device_id() != member.source.device_id()
        {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
    }
    row.projection.begin_retirement()?;
    // From here, every failure retains this row. An uncertain native free may have modified
    // bytes or allocator state, so this operation is deliberately not retryable.
    for is_port_do in [true, false] {
        let row = owner(id).unwrap();
        let member = if is_port_do {
            row.port_do
        } else {
            row.class_do
        };
        let registration = member.alias_registration.unwrap();
        let address = member.alias.unwrap();
        if let Err(status) = io_manager_mut().retire_hosted_device_pointer(registration) {
            owner(id).unwrap().retirement_blocked = true;
            return Err(status);
        }
        {
            let row = owner(id).unwrap();
            let member = if is_port_do {
                &mut row.port_do
            } else {
                &mut row.class_do
            };
            member.pointer_retired = true;
        }
        if let Err(status) = retire_hosted_device_projection(
            port_inst,
            address,
            CanonicalRetirement::Retired { registration },
            None,
        ) {
            owner(id).unwrap().retirement_blocked = true;
            return Err(status);
        }
        {
            let row = owner(id).unwrap();
            let member = if is_port_do {
                &mut row.port_do
            } else {
                &mut row.class_do
            };
            member.physical_retired = true;
        }
    }
    let row = owner(id).unwrap();
    if let Err(status) = row.projection.finish_retirement(io_manager_mut()) {
        row.retirement_blocked = true;
        return Err(status);
    }
    let index = owners().iter().position(|row| row.id == id).unwrap();
    owners().swap_remove(index);
    Ok(())
}
