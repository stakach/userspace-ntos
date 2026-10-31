//! Durable caller alias for a hosted video provider's page-granular pool primary.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::hosted_forward_target::HostedForwardTarget;
use nt_video_miniport::caller_pool_map::{BackingSelection, PoolMapIdentity, PoolMapPhase, PoolMapPlan, PoolMapTransaction};

const PRESENT_DIRTY_RECT: u32 = 0x0023_2480;
const PAGE_TABLE_BYTES: u64 = 0x20_0000;

#[derive(Clone, Copy, Default)]
struct Cap {
    slot: u64,
    owned: bool,
    mapped: bool,
}

struct Mapping {
    transaction: PoolMapTransaction,
    caller: runtime::PhysicalDomain,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    provider: HostedDomainIdentity,
    target: Option<HostedForwardTarget>,
    pin: Option<BackingPin>,
    vspace: Cap,
    tables: Vec<Cap>,
    frames: Vec<Cap>,
    in_flight: bool,
    unmap_token: Option<u64>,
    stage: &'static [u8],
}

enum BackingPin {
    Pool(hosted_device_allocations::VideoPoolPin),
    Projection(hosted_contiguous_ram_broker::VideoProjectionPin),
}

impl BackingPin {
    unsafe fn release(&mut self) -> bool {
        match self {
            Self::Pool(pin) => hosted_device_allocations::release_video_pool_pin(pin).is_ok(),
            Self::Projection(pin) => hosted_contiguous_ram_broker::release_video_projection_pin(pin),
        }
    }

    fn quarantine(&self) {
        if let Self::Pool(pin) = self {
            let _ = hosted_device_allocations::quarantine_video_pool_pin(pin);
        }
        // A projected frame source remains retained by the broker's video pin until a
        // confirmed alias revoke. The uncertain Mapping itself keeps that pin alive.
    }
}

static mut MAPPINGS: Vec<alloc::boxed::Box<Mapping>> = Vec::new();
static MAP_TRACE_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static MAP_REJECT_TRACE_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub(super) unsafe fn blocks_device_retirement(device: u64) -> bool {
    (&*core::ptr::addr_of!(MAPPINGS)).iter().any(|row| {
        row.transaction.phase() != PoolMapPhase::Retired
            && row.registration.device_id().raw() == device
    })
}

pub(super) unsafe fn blocks_domain_retirement(domain: runtime::PhysicalDomain) -> bool {
    (&*core::ptr::addr_of!(MAPPINGS)).iter().any(|row| {
        row.transaction.phase() != PoolMapPhase::Retired
            && (row.caller == domain
                || matches!(domain, runtime::PhysicalDomain::Hosted(identity)
                    if identity == row.provider))
    })
}

pub(super) unsafe fn occupies_caller_range(
    caller: runtime::PhysicalDomain, start: u64, end: u64,
) -> bool {
    (&*core::ptr::addr_of!(MAPPINGS)).iter().any(|row| {
        if row.transaction.phase() == PoolMapPhase::Retired || row.caller != caller { return false; }
        let plan = row.transaction.plan();
        let old_start = plan.identity().alias_page;
        let old_end = old_start + plan.pages() * 0x1000;
        start < old_end && old_start < end
    })
}

fn native_error(error: u64) -> nt_status::NtStatus {
    if error == 10 { nt_status::NtStatus::INSUFFICIENT_RESOURCES }
    else { nt_status::NtStatus::UNSUCCESSFUL }
}

fn reject(stage: &'static [u8]) -> bool {
    if MAP_REJECT_TRACE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 4 {
        unsafe {
        print_str(b"[video-pool-map] rejected stage=");
        print_str(stage);
        print_str(b"\n");
        }
    }
    false
}

fn reject_before_alias(mut pin: BackingPin, stage: &'static [u8]) -> bool {
    if !unsafe { pin.release() } {
        pin.quarantine();
        return reject(b"pre-alias-pin-release");
    }
    reject(stage)
}

fn caller_key(caller: runtime::PhysicalDomain) -> (u64, u64) {
    match caller {
        runtime::PhysicalDomain::Provider { domain, .. } => (domain.domain, domain.generation),
        runtime::PhysicalDomain::Hosted(domain) => (domain.domain_id.raw(), domain.cookie),
    }
}

unsafe fn live_source(
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
) -> Result<runtime::PhysicalSource, nt_status::NtStatus> {
    if runtime::dispatch(route).ok() != Some(dispatch)
        || runtime::current_reply(route).ok() != Some(reply)
        || !matches!(runtime::retained_service_reply_not_entered(route, dispatch, reply, token), Ok(true))
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    runtime::physical_source(route).map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

fn has_assigned_video_bar(target: &HostedForwardTarget) -> bool {
    unsafe {
        hosted_device_resource_state_by_device_id(target.device_id().raw())
            .is_some_and(|state| state.interface_type == HOSTED_INTERFACE_TYPE_PCIBUS
                && state.video_memory_len != 0 && state.video_memory_caller_va != 0)
    }
}

/// Return true when this source transaction belongs to the pool-backed video bridge.
pub(super) unsafe fn prepare(
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    target: &HostedForwardTarget,
    code: u32,
    input: &mut [u8],
    output_capacity: u32,
) -> Result<bool, nt_status::NtStatus> {
    if code != nt_video_miniport::IOCTL_VIDEO_MAP_VIDEO_MEMORY
        && code != nt_video_miniport::IOCTL_VIDEO_UNMAP_VIDEO_MEMORY
        && code != PRESENT_DIRTY_RECT
    { return Ok(false); }
    if code == nt_video_miniport::IOCTL_VIDEO_MAP_VIDEO_MEMORY && has_assigned_video_bar(target) {
        return Ok(false);
    }
    let caller = live_source(route, dispatch, reply, token)?;
    target.validate(io_manager_mut())?;
    match code {
        nt_video_miniport::IOCTL_VIDEO_MAP_VIDEO_MEMORY => {
            if input.len() < nt_video_miniport::VIDEO_MEMORY_SIZE_X64
                || output_capacity < nt_video_miniport::VIDEO_MEMORY_INFORMATION_SIZE_X64 as u32
            { return Err(nt_status::NtStatus::BUFFER_TOO_SMALL); }
            if u64::from_le_bytes(input[..8].try_into().unwrap()) != 0 {
                return Err(nt_status::NtStatus::NOT_SUPPORTED);
            }
            Ok(true)
        }
        nt_video_miniport::IOCTL_VIDEO_UNMAP_VIDEO_MEMORY => {
            if input.len() < nt_video_miniport::VIDEO_MEMORY_SIZE_X64 {
                return Err(nt_status::NtStatus::BUFFER_TOO_SMALL);
            }
            let alias = u64::from_le_bytes(input[..8].try_into().unwrap());
            let row = (&mut *core::ptr::addr_of_mut!(MAPPINGS)).iter_mut().find(|row| {
                let plan = row.transaction.plan();
                row.transaction.phase() == PoolMapPhase::Published
                    && row.registration == target.registration()
                    && row.caller == caller.domain
                    && plan.identity().caller_vspace == caller.pml4
                    && plan.alias_pointer() == alias
            }).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
            row.transaction.claim_unmap().map_err(|_| nt_status::NtStatus::DEVICE_BUSY)?;
            row.unmap_token = Some(token);
            if revoke_alias(row).is_err() {
                row.transaction.quarantine();
                return Err(nt_status::NtStatus::DEVICE_BUSY);
            }
            row.transaction.revoke_alias().map_err(|_| nt_status::NtStatus::DEVICE_BUSY)?;
            let pin = row.pin.as_mut().ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
            if matches!(pin, BackingPin::Pool(_)) {
                // The provider may free pool-owned shadow storage inside UNMAP.
                if !pin.release() {
                    row.transaction.quarantine();
                    return Err(nt_status::NtStatus::DEVICE_BUSY);
                }
                row.pin = None;
            }
            // A projected contiguous source can be accessed during provider UNMAP;
            // its broker pin stays held until that exact completion is captured.
            row.transaction.release_pin().map_err(|_| nt_status::NtStatus::DEVICE_BUSY)?;
            input[..8].copy_from_slice(&row.transaction.plan().identity().provider_pointer.to_le_bytes());
            row.transaction.begin_provider_unmap().map_err(|_| nt_status::NtStatus::DEVICE_BUSY)?;
            Ok(true)
        }
        PRESENT_DIRTY_RECT => {
            let (source, bytes) = nt_video_miniport::dirty_rect::dirty_rect_source(input)
                .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
            let provider = (&*core::ptr::addr_of!(MAPPINGS)).iter().find_map(|row| {
                if row.transaction.phase() != PoolMapPhase::Published
                    || row.registration != target.registration()
                    || row.caller != caller.domain
                    || row.transaction.plan().identity().caller_vspace != caller.pml4
                { return None; }
                row.transaction.plan().translate_alias_range(source, bytes)
            }).ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
            nt_video_miniport::dirty_rect::rewrite_dirty_rect_source(input, provider)
                .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Complete a provider UNMAP once its true terminal has been captured.
pub(super) unsafe fn complete_unmap(token: u64, status: u32) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(MAPPINGS)).iter_mut().find(|row| {
        row.unmap_token == Some(token) && row.transaction.phase() == PoolMapPhase::ProviderUnmapInFlight
    }) else { return false; };
    if status != 0 {
        row.transaction.quarantine();
        return true;
    }
    if let Some(pin @ BackingPin::Projection(_)) = row.pin.as_mut() {
        if !pin.release() {
            row.transaction.quarantine();
            return false;
        }
        row.pin = None;
    }
    if let Some(target) = row.target.as_mut() {
        if target.release(io_manager_mut()).is_err() {
            row.transaction.quarantine();
            return false;
        }
        row.target = None;
    }
    if row.transaction.ack_provider_unmap().is_err() { return false; }
    true
}

/// Publish the real provider's shadow buffer only after its exact allocation is pinned and every
/// caller page alias has been acknowledged. A false result retains the source Work owner.
pub(super) unsafe fn publish_map(
    route: nt_component_suspension::peer_registry::PeerRoute,
    target: &HostedForwardTarget,
    information: u64,
    output: &mut [u8],
) -> bool {
    let trace = MAP_TRACE_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 4;
    if information < nt_video_miniport::VIDEO_MEMORY_INFORMATION_SIZE_X64 as u64
        || output.len() < nt_video_miniport::VIDEO_MEMORY_INFORMATION_SIZE_X64
    {
        if trace {
            print_str(b"[video-pool-map] terminal information="); print_u64(information);
            print_str(b" output-bytes="); print_u64(output.len() as u64); print_str(b"\n");
        }
        return reject(b"short-terminal");
    }
    let video_ram = u64::from_le_bytes(output[0..8].try_into().unwrap());
    let video_ram_length = u32::from_le_bytes(output[8..12].try_into().unwrap()) as u64;
    let framebuffer = u64::from_le_bytes(output[16..24].try_into().unwrap());
    let framebuffer_length = u32::from_le_bytes(output[24..28].try_into().unwrap()) as u64;
    if trace {
        print_str(b"[video-pool-map] terminal information="); print_u64(information);
        print_str(b" output-bytes="); print_u64(output.len() as u64);
        print_str(b" ram=0x"); print_hex64(video_ram);
        print_str(b" ram-bytes="); print_u64(video_ram_length);
        print_str(b" fb=0x"); print_hex64(framebuffer);
        print_str(b" fb-bytes="); print_u64(framebuffer_length);
        print_str(b"\n");
    }
    if video_ram == 0 || video_ram != framebuffer
        || video_ram_length == 0 || video_ram_length != framebuffer_length
        || target.validate(io_manager_mut()).is_err()
    { return reject(b"malformed-or-stale-target"); }
    let Ok(caller) = runtime::physical_source(route) else { return reject(b"caller-source"); };
    let Ok((instance_index, inst, _)) = hosted_dispatch_instance_for_device_id(target.device_id().raw())
    else { return reject(b"provider-route"); };
    let Some(provider) = instance_domain_identity(inst) else { return reject(b"provider-generation"); };
    let pool_pin = hosted_device_allocations::pin_video_pool_range(
        inst, framebuffer, framebuffer_length,
    );
    let projection_pin = hosted_contiguous_ram_broker::pin_video_projection(
        instance_index, inst, framebuffer, framebuffer_length,
    );
    let (pin, backing_base, backing_frames, frame_base, allocation_base,
        allocation_capacity, allocation_generation) =
        match BackingSelection::from_pins(pool_pin.is_ok(), projection_pin.is_some()) {
            BackingSelection::Pool => {
                let pin = pool_pin.expect("exact pool pin selected");
                let allocation = pin.allocation();
                (BackingPin::Pool(pin), FSD_POOL_VADDR, FSD_POOL_FRAMES,
                    inst.pool_frame_base, allocation.component_address,
                    allocation.capacity, allocation.pool_generation)
            }
            BackingSelection::Projection => {
                // A busy or uncertain pool owner cannot establish absence. It must not
                // silently select a second physical owner with the same numeric VA.
                if !matches!(pool_pin, Err(status) if status == nt_status::NtStatus::INVALID_PARAMETER) {
                    let mut pin = projection_pin.expect("exact projection pin selected");
                    let _ = hosted_contiguous_ram_broker::release_video_projection_pin(&mut pin);
                    return reject(b"pool-owner-not-excluded");
                }
                let pin = projection_pin.expect("exact projection pin selected");
                let base = pin.provider_page_base;
                let pages = pin.pages;
                let frames = pin.frame_slot_base;
                let generation = pin.generation;
                (BackingPin::Projection(pin), base, pages,
                    frames, base, pages * 0x1000, generation)
            }
            BackingSelection::Missing => {
                if trace {
                    if let Err(status) = pool_pin {
                        print_str(b"[video-pool-map] pool-pin status=0x");
                        print_hex(status.raw() as u32); print_str(b"\n");
                    }
                }
                return reject(b"no-physical-backing-owner");
            }
            BackingSelection::Ambiguous => {
                let mut pool = pool_pin.expect("ambiguous pool pin");
                let mut projection = projection_pin.expect("ambiguous projection pin");
                let _ = hosted_device_allocations::release_video_pool_pin(&mut pool);
                let _ = hosted_contiguous_ram_broker::release_video_projection_pin(&mut projection);
                return reject(b"ambiguous-physical-backing-owners");
            }
        };
    let offset = framebuffer & 0xfff;
    let Some(pages) = offset.checked_add(framebuffer_length)
        .and_then(|bytes| bytes.checked_add(0xfff)).map(|bytes| bytes / 0x1000)
    else {
        return reject_before_alias(pin, b"page-count-overflow");
    };
    let Some(rounded) = pages.checked_add(511).map(|pages| pages / 512 * PAGE_TABLE_BYTES)
    else {
        return reject_before_alias(pin, b"table-count-overflow");
    };
    let mut alias = crate::win32k_subsystem::WIN32K_VIDEO_POOL_ALIAS_VA;
    let limit = crate::win32k_subsystem::WIN32K_FTYP_VADDR;
    let chosen = loop {
        let Some(end) = alias.checked_add(rounded) else { break None; };
        if end > limit { break None; }
        if !occupies_caller_range(caller.domain, alias, end)
            && !super::hosted_video_caller_aperture::occupies_caller_range(
                caller.domain, alias, end,
            )
        { break Some(alias); }
        let Some(next) = alias.checked_add(PAGE_TABLE_BYTES) else { break None; };
        alias = next;
    };
    let Some(alias_page) = chosen else {
        return reject_before_alias(pin, b"alias-space");
    };
    let (caller_domain, caller_generation) = caller_key(caller.domain);
    let Ok(plan) = PoolMapPlan::new(PoolMapIdentity {
        device: target.device_id().raw(),
        provider_domain: provider.domain_id.raw(), provider_generation: provider.cookie,
        pool_base: backing_base, pool_frames: backing_frames,
        pool_frame_base: frame_base,
        allocation_base, allocation_capacity, allocation_generation,
        provider_pointer: framebuffer, length: framebuffer_length,
        caller_domain, caller_generation, caller_vspace: caller.pml4,
        alias_page, alias_limit: limit,
    }) else {
        return reject_before_alias(pin, b"pool-plan");
    };
    let Ok(mut target_hold) = HostedForwardTarget::capture(
        io_manager_mut(), target.registration().domain(), target.registration().address(),
    ) else {
        return reject_before_alias(pin, b"target-retain");
    };
    let _durable = crate::allocator::enter_durable();
    let Ok(frame_count) = usize::try_from(plan.pages()) else {
        let _ = target_hold.release(io_manager_mut());
        return reject_before_alias(pin, b"frame-count-overflow");
    };
    let table_count = ((plan.pages() + 511) / 512) as usize;
    let mut frames = Vec::new();
    let mut tables = Vec::new();
    if frames.try_reserve_exact(frame_count).is_err()
        || tables.try_reserve_exact(table_count).is_err()
        || (&mut *core::ptr::addr_of_mut!(MAPPINGS)).try_reserve(1).is_err()
    {
        let _ = target_hold.release(io_manager_mut());
        return reject_before_alias(pin, b"native-owner-reserve");
    }
    frames.resize(frame_count, Cap::default());
    tables.resize(table_count, Cap::default());
    let row = alloc::boxed::Box::new(Mapping {
        transaction: PoolMapTransaction::new(plan),
        caller: caller.domain, registration: target.registration(), provider,
        target: Some(target_hold), pin: Some(pin),
        vspace: Cap::default(), frames, tables,
        in_flight: false, unmap_token: None, stage: b"retain-vspace",
    });
    let rows = &mut *core::ptr::addr_of_mut!(MAPPINGS);
    rows.push(row);
    let row = &mut **rows.last_mut().unwrap();
    if build_alias(row).is_err() {
        print_str(b"[video-pool-map] failed stage=");
        print_str(row.stage);
        print_str(b" device=");
        print_u64(target.device_id().raw());
        print_str(b"\n");
        row.transaction.quarantine();
        if let Some(pin) = row.pin.as_ref() {
            pin.quarantine();
        }
        return false;
    }
    let alias_pointer = row.transaction.plan().alias_pointer();
    output[0..8].copy_from_slice(&alias_pointer.to_le_bytes());
    output[16..24].copy_from_slice(&alias_pointer.to_le_bytes());
    row.transaction.publish().expect("complete video pool map");
    print_str(b"[video-pool-map] published provider=0x");
    print_hex64(framebuffer);
    print_str(b" caller=0x");
    print_hex64(alias_pointer);
    print_str(b" bytes=");
    print_u64(framebuffer_length);
    print_str(b" pages=");
    print_u64(plan.pages());
    print_str(b"\n");
    true
}

unsafe fn build_alias(row: &mut Mapping) -> Result<(), nt_status::NtStatus> {
    row.transaction.pin_allocation().map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
    let plan = row.transaction.plan();
    let cap = try_alloc_slot().ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    row.vspace.slot = cap;
    row.in_flight = true;
    let error = copy_cap_into_r(plan.identity().caller_vspace, cap);
    row.in_flight = false;
    if error != 0 { return Err(native_error(error)); }
    row.vspace.owned = true;
    for (index, table) in row.tables.iter_mut().enumerate() {
        row.stage = b"allocate-table";
        let cap = try_alloc_slot().ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        table.slot = cap;
        row.in_flight = true;
        let error = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, cap);
        row.in_flight = false;
        if error != 0 { return Err(native_error(error)); }
        table.owned = true;
        row.stage = b"map-table";
        row.in_flight = true;
        let error = paging_struct_map_r(
            cap, LBL_X86_PAGE_TABLE_MAP,
            plan.identity().alias_page + index as u64 * PAGE_TABLE_BYTES,
            row.vspace.slot,
        );
        row.in_flight = false;
        if error != 0 { return Err(native_error(error)); }
        table.mapped = true;
    }
    for (index, frame) in row.frames.iter_mut().enumerate() {
        row.stage = b"retain-frame";
        let cap = try_alloc_slot().ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        frame.slot = cap;
        row.in_flight = true;
        let error = copy_cap_into_r(plan.frame_slot(index as u64).unwrap(), cap);
        row.in_flight = false;
        if error != 0 { return Err(native_error(error)); }
        frame.owned = true;
        row.transaction.own_frame_cap(index as u64)
            .map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
        row.transaction.begin_map(index as u64)
            .map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
        row.stage = b"map-frame";
        row.in_flight = true;
        let error = page_map_r(cap, plan.page_va(index as u64).unwrap(), RW_NX, row.vspace.slot);
        row.in_flight = false;
        if error != 0 { return Err(native_error(error)); }
        frame.mapped = true;
        row.transaction.ack_map(index as u64)
            .map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
    }
    row.transaction.commit().map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)
}

unsafe fn retire_cap(cap: &mut Cap) -> Result<(), nt_status::NtStatus> {
    if cap.slot == 0 { return Ok(()); }
    if cap.mapped {
        if page_unmap_r(cap.slot) != 0 { return Err(nt_status::NtStatus::DEVICE_BUSY); }
        cap.mapped = false;
    }
    if cap.owned {
        if cnode_delete_recycle_r(cap.slot) != 0 { return Err(nt_status::NtStatus::DEVICE_BUSY); }
    } else {
        recycle_deleted_root_slot(cap.slot);
    }
    *cap = Cap::default();
    Ok(())
}

unsafe fn revoke_alias(row: &mut Mapping) -> Result<(), nt_status::NtStatus> {
    if row.in_flight { return Err(nt_status::NtStatus::DEVICE_BUSY); }
    for frame in row.frames.iter_mut().rev() { retire_cap(frame)?; }
    for table in row.tables.iter_mut().rev() {
        // A page table capability is deleted only after every frame beneath it is unmapped.
        table.mapped = false;
        retire_cap(table)?;
    }
    retire_cap(&mut row.vspace)?;
    Ok(())
}
