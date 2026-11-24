//! Generation-owned scanout alias for a hosted display provider's GOP handoff.

use super::*;
use nt_pnp_context::resource_mapping::MappingCache;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase { Mapping, Ready, Uncertain, Retired }

#[derive(Clone, Copy, Eq, PartialEq)]
enum LegacyPortCap { Unissued, Issuing(u64), Ready(u64), Uncertain(u64) }

struct Projection {
    instance: usize,
    domain: HostedDomainIdentity,
    pml4: u64,
    bar: nt_hosted_runtime::GopPciBarAuthority,
    provider_publication: u64,
    inventory_generation: u64,
    request_phys: u64,
    request_len: u64,
    component_va: u64,
    owner: Option<crate::hosted_pnp_context::HostedPnpContextOwner>,
    legacy_port_cap: LegacyPortCap,
    phase: Phase,
}

static mut PROJECTIONS: Vec<Projection> = Vec::new();

fn request_owner(
    instance: usize,
    domain: HostedDomainIdentity,
    bar: nt_hosted_runtime::GopPciBarAuthority,
    publication: u64,
    inventory_generation: u64,
) -> nt_hosted_runtime::MmioRequestOwner {
    nt_hosted_runtime::MmioRequestOwner {
        domain_id: domain.domain_id.raw(),
        domain_cookie: domain.cookie,
        authority: nt_hosted_runtime::MmioRequestAuthority::Gop {
            instance,
            bar,
            publication,
            inventory_generation,
        },
    }
}

/// Called only from the GOP service branch after its exact message arity has been checked.
pub(super) unsafe fn map_scanout(
    channel: &crate::spawn_hosts::PumpChannel,
    caller_badge: u64,
    reply_cap: u64,
    phys: u64,
    len: u64,
    cache: u64,
) -> u64 {
    let _durable = crate::allocator::enter_durable();
    macro_rules! reject {
        ($stage:literal) => {{
            print_str(b"[gop-bar] reject stage=");
            print_str($stage);
            print_str(b"\n");
            return 0;
        }};
    }
    print_str(b"[gop-bar] request phys=0x");
    print_hex64(phys);
    print_str(b" len=");
    print_u64(len);
    print_str(b" cache=");
    print_u64(cache);
    print_str(b"\n");
    if cache != nt_hal_abi::MM_NON_CACHED as u64 { reject!(b"cache"); }
    let Some((instance_index, inst)) = instance_for_pump_channel(channel, reply_cap) else {
        reject!(b"pump-instance");
    };
    if hosted_driver_caller(instance_index, inst, caller_badge).is_none() {
        reject!(b"physical-caller");
    }
    let Some(domain) = instance_domain_identity(inst) else { reject!(b"domain"); };
    let (provider_instance, publication) = if let Some((worker_provider, worker_owner, cookie)) =
        hosted_provider_export_lane::authority_for_channel(channel) {
        if worker_provider != instance_index
            || !worker_owner.provider_matches(domain.domain_id.raw(), domain.cookie)
        { reject!(b"worker-owner"); }
        if !hosted_dxg_registration::scanout_provider_authority(
            worker_provider, domain, cookie) { reject!(b"dxg-provider"); }
        (worker_provider, cookie)
    } else if let Some(authority) = hosted_dxg_registration::scanout_dependent_authority(
        instance_index, domain) {
        authority
    } else { reject!(b"dxg-dependent"); };
    let Some((_, singleton)) = find_hosted_provider_singleton_by_cookie(publication) else {
        reject!(b"singleton");
    };
    if singleton.instance != provider_instance { reject!(b"provider-instance"); }

    let bar_start = crate::FB_BAR_PADDR.load(Ordering::Acquire);
    let bar_frames = crate::FB_BAR_FRAME_COUNT.load(Ordering::Acquire);
    let frame_base = crate::FB_BAR_FRAME_BASE.load(Ordering::Acquire);
    let scanout_offset = crate::FB_SCANOUT_BAR_OFFSET.load(Ordering::Acquire);
    let scanout_bytes = crate::FB_SIZE_BYTES.load(Ordering::Acquire);
    let Some(scanout_start) = bar_start.checked_add(scanout_offset) else {
        reject!(b"scanout-overflow");
    };
    let Some(pci_bar) = crate::hosted_pci_topology::unique_hosted_gop_display_bar(
        scanout_start, scanout_bytes) else { reject!(b"pci-bar"); };
    if frame_base == 0 || pci_bar.base != bar_start || pci_bar.frames != bar_frames {
        reject!(b"bar-caps");
    }
    let Some(authority) = nt_hosted_runtime::GopPciBarAuthority::new(
        pci_bar.bus, pci_bar.device, pci_bar.function, pci_bar.bar_index,
        bar_start, bar_frames, scanout_start, scanout_bytes,
        pci_bar.inventory_generation, domain.domain_id.raw(), domain.cookie, publication,
    ) else { reject!(b"bar-authority"); };
    let Some(span) = authority.project(phys, len, pci_bar.inventory_generation,
        domain.domain_id.raw(), domain.cookie, publication) else {
        reject!(b"scanout-extent");
    };
    let mmio_owner = request_owner(
        instance_index, domain, authority, publication, pci_bar.inventory_generation,
    );

    let rows = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
    if let Some(existing) = rows.iter().find(|row| row.instance == instance_index
        && row.domain == domain && row.pml4 == inst.pml4
        && row.provider_publication == publication && row.phase != Phase::Retired) {
        if existing.phase != Phase::Ready
            || existing.inventory_generation != pci_bar.inventory_generation
            || existing.request_phys != phys || existing.request_len != len {
            reject!(b"existing-generation");
        }
        let Ok(receipt) = hosted_mmio_broker::prepare_gop(mmio_owner, phys, len, cache as u32)
        else { reject!(b"request-receipt"); };
        let Some(va) = existing.component_va.checked_add(span.page_offset()) else {
            hosted_mmio_broker::cancel_gop(receipt);
            reject!(b"existing-va");
        };
        if hosted_mmio_broker::complete_gop(receipt, mmio_owner, va).is_err() {
            hosted_mmio_broker::uncertain_gop(receipt);
            reject!(b"existing-receipt");
        }
        return va;
    }

    let Ok(pages) = usize::try_from(span.frame_count()) else { reject!(b"pages"); };
    if rows.try_reserve(1).is_err() { reject!(b"row-capacity"); }
    let Some(bytes) = span.frame_count().checked_mul(0x1000) else {
        reject!(b"map-bytes");
    };
    let Ok(receipt) = hosted_mmio_broker::prepare_gop(mmio_owner, phys, len, cache as u32)
    else { reject!(b"request-receipt"); };
    let mut owner = crate::hosted_pnp_context::HostedPnpContextOwner::new();
    if !owner.reserve_alias_caps(pages) {
        hosted_mmio_broker::cancel_gop(receipt);
        reject!(b"alias-capacity");
    }
    let Some(component_va) = crate::hosted_pnp_context::reserve_hosted_pnp_component_span(
        &mut owner, bytes) else {
        match crate::hosted_pnp_context::try_retire_hosted_pnp_context_owner(owner) {
            Ok(()) => hosted_mmio_broker::cancel_gop(receipt),
            Err(owner) => {
                // Even a failed reservation may have allocated a VA or cap slot. Keep the
                // owner and request until native effects are conclusively reconciled.
                rows.push(Projection {
                    instance: instance_index, domain, pml4: inst.pml4, bar: authority,
                    provider_publication: publication,
                    inventory_generation: pci_bar.inventory_generation,
                    request_phys: phys, request_len: len, component_va: 0,
                    owner: Some(owner), phase: Phase::Uncertain,
                    legacy_port_cap: LegacyPortCap::Unissued,
                });
                hosted_mmio_broker::uncertain_gop(receipt);
            }
        }
        reject!(b"component-va");
    };
    print_str(b"[gop-bar] admitted instance=");
    print_u64(instance_index as u64);
    print_str(b" frames=");
    print_u64(span.frame_count());
    print_str(b" va=0x");
    print_hex64(component_va);
    print_str(b"\n");
    rows.push(Projection {
        instance: instance_index, domain, pml4: inst.pml4, bar: authority,
        provider_publication: publication,
        inventory_generation: pci_bar.inventory_generation, request_phys: phys,
        request_len: len, component_va, owner: Some(owner), phase: Phase::Mapping,
        legacy_port_cap: LegacyPortCap::Unissued,
    });
    let index = rows.len() - 1;
    macro_rules! uncertain {
        () => {{
            rows[index].phase = Phase::Uncertain;
            hosted_mmio_broker::uncertain_gop(receipt);
            return 0;
        }};
    }
    for page in 0..span.frame_count() {
        let Some(bar_page) = span.first_bar_frame().checked_add(page) else {
            uncertain!();
        };
        let Some(source_cap) = frame_base.checked_add(bar_page) else {
            uncertain!();
        };
        let Some(expected_phys) = bar_start.checked_add(bar_page * 0x1000) else {
            uncertain!();
        };
        if hosted_resource_mapping::checked_frame_address(source_cap) != Ok(expected_phys) {
            uncertain!();
        }
        let Some(target_va) = component_va.checked_add(page * 0x1000) else {
            uncertain!();
        };
        if !ensure_paging(target_va, inst.pml4, domain) {
            uncertain!();
        }
        let (cap, copied) = copy_cap_r(source_cap);
        if cap == 0 || copied != 0 {
            if cap != 0 { rows[index].owner.as_mut().unwrap().adopt_alias_cap(cap, false); }
            uncertain!();
        }
        // Adopt before PageMap; a nonzero error after entry leaves the effect uncertain.
        rows[index].owner.as_mut().unwrap().adopt_alias_cap(cap, true);
        if page_map_r(cap, target_va,
            hosted_resource_mapping::page_map_rights(RW_NX, MappingCache::Uncached), inst.pml4) != 0 {
            uncertain!();
        }
    }
    rows[index].phase = Phase::Ready;
    let Some(va) = component_va.checked_add(span.page_offset()) else { uncertain!(); };
    if hosted_mmio_broker::complete_gop(receipt, mmio_owner, va).is_err() {
        uncertain!();
    }
    va
}

/// Retire one map call, not the generation-owned GOP projection shared by duplicate calls.
pub(super) unsafe fn unmap_scanout(
    channel: &crate::spawn_hosts::PumpChannel,
    caller_badge: u64,
    reply_cap: u64,
    base: u64,
    length: u64,
) -> Result<(), nt_status::NtStatus> {
    let (instance_index, inst) = instance_for_pump_channel(channel, reply_cap)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    hosted_driver_pump_caller_tcb(channel, reply_cap, caller_badge)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let domain = instance_domain_identity(inst)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let row = (&*core::ptr::addr_of!(PROJECTIONS)).iter().find(|row| {
        row.instance == instance_index
            && row.domain == domain
            && row.pml4 == inst.pml4
            && row.phase == Phase::Ready
            && row.request_len == length
            && row.bar.project(
                row.request_phys, row.request_len, row.inventory_generation,
                domain.domain_id.raw(), domain.cookie, row.provider_publication,
            ).and_then(|span| row.component_va.checked_add(span.page_offset())) == Some(base)
    }).ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let owner = request_owner(
        instance_index, domain, row.bar,
        row.provider_publication, row.inventory_generation,
    );
    hosted_mmio_broker::unmap_gop(owner, base, length)
}

/// The only legacy VGA port needed by the released miniport after GOP handoff is input
/// status 1. Fault servicing uses the real port capability and the same retained pump Reply.
pub(super) unsafe fn legacy_vga_port_fault_grant(
    channel: &crate::spawn_hosts::PumpChannel,
    active_reply_cap: u64,
    port: u16,
    read: bool,
    width_bits: u8,
) -> Option<HostedIoPortFaultGrant> {
    let _durable = crate::allocator::enter_durable();
    if !read || width_bits != 8 || port != 0x3da { return None; }
    let (instance_index, inst) = instance_for_pump_channel(channel, active_reply_cap)?;
    let domain = instance_domain_identity(inst)?;
    let (_, publication) = hosted_dxg_registration::scanout_dependent_authority(
        instance_index, domain)?;
    let rows = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
    let row = rows.iter_mut().find(|row| row.instance == instance_index
        && row.domain == domain && row.pml4 == inst.pml4
        && row.provider_publication == publication && row.phase == Phase::Ready)?;
    let scanout_start = crate::FB_BAR_PADDR.load(Ordering::Acquire)
        .checked_add(crate::FB_SCANOUT_BAR_OFFSET.load(Ordering::Acquire))?;
    let scanout_bytes = crate::FB_SIZE_BYTES.load(Ordering::Acquire);
    let pci_bar = crate::hosted_pci_topology::unique_hosted_gop_display_bar(
        scanout_start, scanout_bytes)?;
    if pci_bar.inventory_generation != row.inventory_generation
        || pci_bar.base != crate::FB_BAR_PADDR.load(Ordering::Acquire)
        || pci_bar.frames != crate::FB_BAR_FRAME_COUNT.load(Ordering::Acquire)
    { return None; }
    let bar = nt_hosted_runtime::GopPciBarAuthority::new(
        pci_bar.bus, pci_bar.device, pci_bar.function, pci_bar.bar_index,
        pci_bar.base, pci_bar.frames, scanout_start, scanout_bytes,
        pci_bar.inventory_generation, domain.domain_id.raw(), domain.cookie, publication,
    )?;
    let mut command = [0u8; 2];
    crate::pnp::read_pci_config(nt_pnp::PciConfigAccess {
        bus: pci_bar.bus, device: pci_bar.device, function: pci_bar.function,
        offset: 4, length: 2,
    }, &mut command).ok()?;
    let authority = nt_hosted_runtime::GopLegacyVgaPortAuthority::new(
        bar, pci_bar.class, u16::from_le_bytes(command), true)?;
    if !authority.admit_read8(port, pci_bar.inventory_generation,
        domain.domain_id.raw(), domain.cookie, publication) { return None; }
    let cap = match row.legacy_port_cap {
        LegacyPortCap::Ready(cap) => cap,
        LegacyPortCap::Issuing(_) | LegacyPortCap::Uncertain(_) => return None,
        LegacyPortCap::Unissued => {
            let slot = try_alloc_slot()?;
            row.legacy_port_cap = LegacyPortCap::Issuing(slot);
            if crate::issue_ioport_cap(slot, port, port) != 0 {
                row.legacy_port_cap = LegacyPortCap::Uncertain(slot);
                return None;
            }
            row.legacy_port_cap = LegacyPortCap::Ready(slot);
            slot
        }
    };
    Some(HostedIoPortFaultGrant { cap, base: port as u64, len: 1 })
}

/// The owner is released with its exact hosted instance; failed seL4 cleanup stays in this
/// generation row rather than recycling caps or VA slots.
pub(super) unsafe fn retire_instance(instance_index: usize, domain: HostedDomainIdentity,
    pml4: u64) -> Result<(), nt_status::NtStatus> {
    let rows = &mut *core::ptr::addr_of_mut!(PROJECTIONS);
    for row in rows.iter_mut().filter(|row| row.instance == instance_index
        && row.domain == domain && row.pml4 == pml4 && row.phase != Phase::Retired) {
        hosted_mmio_broker::retire_gop_owner(request_owner(
            instance_index, domain, row.bar,
            row.provider_publication, row.inventory_generation,
        ))?;
        if let LegacyPortCap::Issuing(cap) | LegacyPortCap::Ready(cap)
            | LegacyPortCap::Uncertain(cap) = row.legacy_port_cap {
            if crate::cnode_revoke_r(cap) != 0 || crate::cnode_delete_recycle_r(cap) != 0 {
                row.phase = Phase::Uncertain;
                return Err(nt_status::NtStatus::UNSUCCESSFUL);
            }
            row.legacy_port_cap = LegacyPortCap::Unissued;
        }
        let Some(owner) = row.owner.take() else { return Err(nt_status::NtStatus::UNSUCCESSFUL); };
        if let Err(owner) = crate::hosted_pnp_context::try_retire_hosted_pnp_context_owner(owner) {
            row.owner = Some(owner);
            row.phase = Phase::Uncertain;
            return Err(nt_status::NtStatus::UNSUCCESSFUL);
        }
        row.phase = Phase::Retired;
    }
    Ok(())
}
