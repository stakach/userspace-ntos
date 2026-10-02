//! Durable caller mappings of exact assigned PCI memory resources.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_target::HostedForwardTarget;
use nt_video_miniport::caller_aperture::{
    ApertureIdentity, AperturePhase, AperturePlan, ApertureTransaction, MapEffect,
};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Authority {
    caller: runtime::PhysicalDomain,
    context: nt_pnp_context::ContextLeaseIdentity,
    device: nt_io_manager::HostedDevicePointerRegistration,
}
#[derive(Clone, Copy, Default)]
struct OwnedCap {
    cap: u64,
    created: bool,
    mapped: bool,
}
struct Mapping {
    transaction: ApertureTransaction<Authority>,
    context: Option<nt_pnp_context::ContextLease>,
    device: Option<HostedForwardTarget>,
    vspace: OwnedCap,
    frames: Vec<OwnedCap>,
    tables: Vec<OwnedCap>,
    in_flight: bool,
    stage: &'static [u8],
}
static mut MAPPINGS: Vec<alloc::boxed::Box<Mapping>> = Vec::new();

pub(super) unsafe fn blocks_device_retirement(device: u64) -> bool {
    (&*core::ptr::addr_of!(MAPPINGS)).iter().any(|row| {
        row.transaction.phase() != AperturePhase::Retired
            && row.transaction.plan().identity().device == device
    })
}
pub(super) unsafe fn blocks_domain_retirement(domain: runtime::PhysicalDomain) -> bool {
    (&*core::ptr::addr_of!(MAPPINGS)).iter().any(|row| {
        row.transaction.phase() != AperturePhase::Retired
            && row.transaction.plan().identity().caller_authority.caller == domain
    })
}

fn native_error(error: u64) -> nt_status::NtStatus {
    if error == 10 {
        nt_status::NtStatus::INSUFFICIENT_RESOURCES
    } else {
        nt_status::NtStatus::UNSUCCESSFUL
    }
}

/// Observe captured completion bytes without issuing I/O or altering the source IRP result.
pub(super) unsafe fn observe_terminal(
    target: &HostedForwardTarget,
    code: u32,
    status: u32,
    output: &[u8],
) {
    if status != 0 || code != nt_video_miniport::IOCTL_VIDEO_QUERY_CURRENT_MODE {
        return;
    }
    if !read_volatile(core::ptr::addr_of!(DRIVER_IO_MANAGER_INIT)) { return; }
    let io = (&*core::ptr::addr_of!(DRIVER_IO_MANAGER)).assume_init_ref();
    if target.validate(io).is_err()
        || io.device(target.device_id()).is_none_or(|device| device.delete_pending) {
        return;
    }
    let Some(state) = hosted_device_resource_state_by_device_id(target.device_id().raw()) else {
        return;
    };
    let scanout = crate::FB_BAR_PADDR.load(Ordering::Acquire);
    let pages = crate::FB_BAR_FRAME_COUNT.load(Ordering::Acquire);
    if scanout == 0 || pages == 0 || state.video_memory_phys != scanout
        || state.video_memory_len == 0 || state.video_memory_len > pages * 0x1000
        || state.video_memory_caller_va != crate::win32k_subsystem::WIN32K_FB_VA
        || io.hosted_domain_identity(state.projection_domain.domain_id) != Some(state.projection_domain)
        || !hosted_state_address_resources(&state).iter().any(|resource| {
            resource.kind == SH_RESOURCE_ADDRESS_KIND_MEMORY
                && resource.translated_start == scanout && resource.len == state.video_memory_len
        }) {
        return;
    }
    if let Ok(mode) = nt_video_miniport::parse_video_mode_information(output) {
        let offset = crate::FB_SCANOUT_BAR_OFFSET.load(Ordering::Acquire);
        let Some(available) = state.video_memory_len.checked_sub(offset) else { return; };
        let Some(bytes) = mode.framebuffer_bytes() else { return; };
        if bytes == 0 || bytes > available { return; }
        let _ = crate::publish_active_framebuffer_mode(mode);
    }
}

/// No caller-visible address is returned before every page has an acknowledged mapping.
pub(super) unsafe fn prepare(
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    target: &HostedForwardTarget,
    code: u32,
    input: &[u8],
    output_capacity: u32,
) -> Result<(), nt_status::NtStatus> {
    if code == nt_video_miniport::IOCTL_VIDEO_UNMAP_VIDEO_MEMORY {
        return Err(nt_status::NtStatus::NOT_SUPPORTED);
    }
    if code != nt_video_miniport::IOCTL_VIDEO_MAP_VIDEO_MEMORY {
        return Ok(());
    }
    if input.len() < nt_video_miniport::VIDEO_MEMORY_SIZE_X64 {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    if output_capacity < nt_video_miniport::VIDEO_MEMORY_INFORMATION_SIZE_X64 as u32 {
        return Err(nt_status::NtStatus::BUFFER_TOO_SMALL);
    }
    let incoming = u64::from_le_bytes(input[..8].try_into().unwrap());
    if incoming != 0 {
        return Err(nt_status::NtStatus::NOT_SUPPORTED);
    }
    if runtime::dispatch(route).ok() != Some(dispatch)
        || runtime::current_reply(route).ok() != Some(reply)
        || !matches!(
            runtime::retained_service_reply_not_entered(route, dispatch, reply, token),
            Ok(true)
        )
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let caller =
        runtime::physical_source(route).map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    target.validate(io_manager_mut())?;
    let state = hosted_device_resource_state_by_device_id(target.device_id().raw())
        .ok_or(nt_status::NtStatus::NOT_SUPPORTED)?;
    if state.interface_type != HOSTED_INTERFACE_TYPE_PCIBUS
        || state.video_memory_len == 0
        || state.video_memory_caller_va == 0
    {
        return Err(nt_status::NtStatus::NOT_SUPPORTED);
    }
    let context = state
        .pnp_context_lease
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let bus =
        u8::try_from(state.bus_number).map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let dev = u8::try_from(state.address >> 16)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let func = u8::try_from(state.address & 0xffff)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let resource = hosted_state_address_resources(&state)
        .iter()
        .find(|resource| {
            resource.kind == SH_RESOURCE_ADDRESS_KIND_MEMORY
                && resource.translated_start == state.video_memory_phys
                && resource.len == state.video_memory_len
        })
        .copied()
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let binding = hosted_device_binding_by_device_id(target.device_id().raw())
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if binding.projection_domain != state.projection_domain {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let resource_id = hosted_mmio_resource_id(binding.device_id, resource.resource_index)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let assignment = hosted_resource_manager_mut()
        .query_resources(hosted_resource_owner(binding))
        .into_iter()
        .find(|assignment| {
            assignment.resource_id == resource_id
                && assignment.kind == nt_hal_abi::RES_KIND_MEMORY
                && assignment.translated_start == resource.translated_start
                && assignment.length == resource.len
        })
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if assignment.arg1 & nt_hal_abi::RIGHT_READ == 0 {
        return Err(nt_status::NtStatus::ACCESS_DENIED);
    }
    let (_, window) = crate::hosted_pnp_pci_window_by_lease(context, bus, dev, func)?;
    let backing = window
        .memory_window(resource.resource_index)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if backing.phys != resource.translated_start
        || backing.len != resource.len
        || backing.frame_base == 0
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let (domain, generation) = match caller.domain {
        runtime::PhysicalDomain::Provider { domain, .. } => (domain.domain, domain.generation),
        runtime::PhysicalDomain::Hosted(domain) => (domain.domain_id.raw(), domain.cookie),
    };
    let plan = AperturePlan::new(
        ApertureIdentity {
            context: context.context().get(),
            context_lease: context.token(),
            device: target.device_id().raw(),
            resource_index: resource.resource_index,
            bus,
            device_number: dev,
            function: func,
            caller_domain: domain,
            caller_generation: generation,
            caller_authority: Authority {
                caller: caller.domain,
                context,
                device: target.registration(),
            },
            caller_vspace: caller.pml4,
            physical: backing.phys,
            length: backing.len,
            virtual_base: state.video_memory_caller_va,
            backing_pages: backing.pages,
            writable: assignment.arg1 & nt_hal_abi::RIGHT_WRITE != 0
                && resource.flags & nt_cm_resources::CM_RESOURCE_MEMORY_READ_ONLY == 0,
        },
        incoming,
    )
    .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    for row in &*core::ptr::addr_of!(MAPPINGS) {
        if row.transaction.phase() == AperturePhase::Retired {
            continue;
        }
        let old = row.transaction.plan();
        if old.matches(plan.identity()) {
            return if row.transaction.publishable() {
                Ok(())
            } else {
                Err(nt_status::NtStatus::DEVICE_BUSY)
            };
        }
        let old = old.identity();
        let new = plan.identity();
        if old.caller_authority.caller == new.caller_authority.caller
            && old.caller_vspace == new.caller_vspace
            && old.virtual_base < new.virtual_base + plan.pages() * 0x1000
            && new.virtual_base < old.virtual_base + row.transaction.plan().pages() * 0x1000
        {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
    }
    let _durable = crate::allocator::enter_durable();
    let pages =
        usize::try_from(plan.pages()).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let first_table = plan.identity().virtual_base & !0x1fffff;
    let last_table = (plan.identity().virtual_base + plan.pages() * 0x1000 - 1) & !0x1fffff;
    let table_count = usize::try_from((last_table - first_table) / 0x200000 + 1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(pages)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    frames.resize(pages, OwnedCap::default());
    let mut tables = Vec::new();
    tables
        .try_reserve_exact(table_count)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    tables.resize(table_count, OwnedCap::default());
    let records = &mut *core::ptr::addr_of_mut!(MAPPINGS);
    records
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    records.push(alloc::boxed::Box::new(Mapping {
        transaction: ApertureTransaction::new(plan),
        context: None,
        device: None,
        vspace: OwnedCap::default(),
        frames,
        tables,
        in_flight: false,
        stage: b"retain-context",
    }));
    // Box addresses are stable; never borrow the reallocatable registry across native effects.
    let row = &mut **records.last_mut().unwrap() as *mut Mapping;
    let result = build(
        row,
        context,
        target.registration(),
        caller.pml4,
        backing.frame_base,
        first_table,
    );
    if let Err(status) = result {
        print_str(b"[video-caller-aperture] failed stage=");
        print_str((*row).stage);
        print_str(b" status=0x");
        print_hex(status.raw() as u32);
        print_str(b"\n");
        let _ = rollback(row);
        return Err(status);
    }
    Ok(())
}

unsafe fn build(
    row: *mut Mapping,
    context: nt_pnp_context::ContextLeaseIdentity,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    pml4: u64,
    frame_base: u64,
    first_table: u64,
) -> Result<(), nt_status::NtStatus> {
    (*row).context = Some(crate::retain_hosted_pnp_context_lease(context)?);
    (*row).stage = b"retain-device";
    (*row).device = Some(HostedForwardTarget::capture(
        io_manager_mut(),
        registration.domain(),
        registration.address(),
    )?);
    if (*row)
        .device
        .as_ref()
        .map(HostedForwardTarget::registration)
        != Some(registration)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let cap = try_alloc_slot().ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    (*row).stage = b"retain-vspace";
    (*row).vspace.cap = cap;
    (*row).in_flight = true;
    let error = copy_cap_into_r(pml4, cap);
    (*row).in_flight = false;
    if error != 0 {
        return Err(native_error(error));
    }
    (*row).vspace.created = true;
    for index in 0..(*row).tables.len() {
        (*row).stage = b"allocate-table";
        let cap = try_alloc_slot().ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        (&mut (*row).tables)[index].cap = cap;
        (*row).in_flight = true;
        let error = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, cap);
        (*row).in_flight = false;
        if error != 0 {
            return Err(native_error(error));
        }
        (&mut (*row).tables)[index].created = true;
        (*row).stage = b"map-table";
        (*row).in_flight = true;
        let error = paging_struct_map_r(
            cap,
            LBL_X86_PAGE_TABLE_MAP,
            first_table + index as u64 * 0x200000,
            (*row).vspace.cap,
        );
        (*row).in_flight = false;
        if error != 0 {
            return Err(native_error(error));
        }
        (&mut (*row).tables)[index].mapped = true;
    }
    for index in 0..(*row).frames.len() {
        (*row).stage = b"retain-frame";
        let cap = try_alloc_slot().ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        (&mut (*row).frames)[index].cap = cap;
        (*row).in_flight = true;
        let error = copy_cap_into_r(frame_base + index as u64, cap);
        (*row).in_flight = false;
        if error != 0 {
            return Err(native_error(error));
        }
        (&mut (*row).frames)[index].created = true;
        (*row)
            .transaction
            .record_map_capability(index as u64)
            .expect("owned aperture map cap");
        (*row)
            .transaction
            .begin_map()
            .expect("aperture map effect claim");
        let (_, va) = (*row).transaction.plan().page(index as u64).unwrap();
        let rights = if (*row).transaction.plan().identity().writable {
            RW_NX
        } else {
            RO_NX
        };
        (*row).stage = b"map-frame";
        let error = page_map_r(cap, va, rights, (*row).vspace.cap);
        (*row)
            .transaction
            .acknowledge_map(if error == 0 {
                MapEffect::Mapped
            } else {
                MapEffect::NoEffect
            })
            .expect("aperture map acknowledgement");
        if error != 0 {
            return Err(native_error(error));
        }
        (&mut (*row).frames)[index].mapped = true;
    }
    (*row)
        .transaction
        .commit()
        .expect("complete aperture mapping");
    let identity = (*row).transaction.plan().identity();
    print_str(b"[video-caller-aperture] committed resource=");
    print_u64(identity.resource_index as u64);
    print_str(b" device=0x");
    print_hex64(identity.device);
    print_str(b" caller=0x");
    print_hex64(identity.caller_domain);
    print_str(b" generation=");
    print_u64(identity.caller_generation);
    print_str(b" pages=");
    print_u64((*row).transaction.plan().pages());
    print_str(b" bytes=");
    print_u64(identity.length);
    print_str(b" va=0x");
    print_hex64(identity.virtual_base);
    print_str(b" writable=");
    print_u64(identity.writable as u64);
    print_str(b"\n");
    Ok(())
}

unsafe fn retire_cap(cap: &mut OwnedCap) -> bool {
    if cap.cap == 0 {
        return true;
    }
    if cap.created {
        if cnode_delete_recycle_r(cap.cap) != 0 {
            return false;
        }
    } else {
        recycle_deleted_root_slot(cap.cap);
    }
    *cap = OwnedCap::default();
    true
}
unsafe fn rollback(row: *mut Mapping) -> bool {
    if (*row).in_flight || (*row).transaction.phase() == AperturePhase::MapInFlight {
        return false;
    }
    if (*row).transaction.phase() == AperturePhase::Preparing {
        (*row)
            .transaction
            .abort_before_map()
            .expect("known aperture failure");
    }
    if (*row).transaction.phase() != AperturePhase::RollbackRequired {
        return false;
    }
    for cap in (*row).frames.iter_mut().rev() {
        if cap.mapped {
            if page_unmap_r(cap.cap) != 0 {
                return false;
            }
            cap.mapped = false;
        }
        if !retire_cap(cap) {
            return false;
        }
    }
    for cap in (*row).tables.iter_mut().rev() {
        if !retire_cap(cap) {
            return false;
        }
    }
    if !retire_cap(&mut (*row).vspace) {
        return false;
    }
    if let Some(target) = (*row).device.as_mut() {
        if target.release(io_manager_mut()).is_err() {
            return false;
        }
        (*row).device = None;
    }
    if let Some(context) = (*row).context.as_ref() {
        if crate::release_hosted_pnp_context_lease(context.identity()).is_err() {
            return false;
        }
        (*row).context = None;
    }
    (*row)
        .transaction
        .rollback_complete()
        .expect("exact aperture rollback");
    true
}
