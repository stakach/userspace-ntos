//! Root-owned receipts for hosted driver MMIO requests.
//!
//! A component VA is a projection, not proof that a particular MmMapIoSpace call owns it.
//! Keep each request and its resource-manager mapping until its matching unmap completes.

use super::*;

#[path = "hosted_mmio_publication_policy.rs"]
mod hosted_mmio_publication_policy;
#[path = "hosted_pool_owned_mmio.rs"]
pub(super) mod hosted_pool_owned_mmio;
use hosted_pool_owned_mmio::{map_owned_pool, unmap_owned_pool};

static mut REQUESTS: Option<nt_hosted_runtime::MmioRequestLedger> = None;

unsafe fn requests_mut() -> &'static mut nt_hosted_runtime::MmioRequestLedger {
    let slot = &mut *core::ptr::addr_of_mut!(REQUESTS);
    if slot.is_none() {
        *slot = Some(nt_hosted_runtime::MmioRequestLedger::new());
    }
    slot.as_mut().unwrap()
}

pub(super) unsafe fn has_retained_pnp_device_rows(binding: HostedDeviceBinding) -> bool {
    (*core::ptr::addr_of!(REQUESTS)).as_ref().is_some_and(|ledger| {
        ledger.has_pnp_device_rows(
            binding.projection_domain.domain_id.raw(),
            binding.projection_domain.cookie,
            binding.device_id,
        )
    })
}

unsafe fn retained_pnp_state(binding: HostedDeviceBinding) -> Option<HostedDeviceResourceState> {
    if hosted_device_binding_by_device_id(binding.device_id) != Some(binding) {
        return None;
    }
    let state = hosted_device_resource_state_by_device_id(binding.device_id)?;
    if state.driver_id != binding.driver_id
        || state.instance != binding.instance
        || state.projection_domain != binding.projection_domain
        || state.pdo_object != binding.pdo_object
    {
        return None;
    }
    Some(state)
}

unsafe fn pnp_owner(
    binding: HostedDeviceBinding,
) -> Option<(nt_hosted_runtime::MmioRequestOwner, HostedDeviceResourceState)> {
    let state = retained_pnp_state(binding)?;
    let lease = state.pnp_context_lease?;
    if !crate::hosted_pnp_context_lease_is_live(lease) {
        return None;
    }
    Some((nt_hosted_runtime::MmioRequestOwner {
        domain_id: binding.projection_domain.domain_id.raw(),
        domain_cookie: binding.projection_domain.cookie,
        authority: nt_hosted_runtime::MmioRequestAuthority::Pnp {
            device_id: binding.device_id,
            context_lease: lease,
        },
    }, state))
}

fn mapped_memory_resource(
    state: HostedDeviceResourceState,
    phys: u64,
    length: u64,
) -> Option<SharedAddressResource> {
    state.address_resources.get(..usize::from(state.address_resource_count))?
        .iter()
        .copied()
        .find(|resource| {
            resource.kind == SH_RESOURCE_ADDRESS_KIND_MEMORY
                && resource.va != 0
                && resource.map_len <= resource.len
                && range_within_grant(resource.translated_start, resource.map_len, phys, length)
        })
}

/// The caller has already proved its physical transport and exact device binding.
pub(super) unsafe fn map_assigned(
    binding: HostedDeviceBinding,
    phys: u64,
    length: u64,
    cache: u32,
) -> Result<u64, nt_status::NtStatus> {
    let (owner, state) = pnp_owner(binding).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let resource = mapped_memory_resource(state, phys, length)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    // The existing native BAR projection is strong UC. WC requires a proven per-CPU PAT and
    // retirement of conflicting kernel aliases; WB cannot be returned for this UC projection.
    if cache != nt_hal_abi::MM_NON_CACHED {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let resource_id = hosted_mmio_resource_id(binding.device_id, resource.resource_index)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let va = resource.va.checked_add(phys - resource.translated_start)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let request = nt_hosted_runtime::MmioRequest {
        owner,
        physical_start: phys,
        length,
        cache,
    };
    let receipt = requests_mut().prepare(request)
        .map_err(|_| nt_status::NtStatus::DEVICE_BUSY)?;
    let mapped = match hosted_resource_manager_mut().map_io_space(
        hosted_resource_owner(binding), phys, length, cache,
    ) {
        Ok(mapped) => mapped,
        Err(error) => {
            let _ = requests_mut().cancel_prepared(receipt);
            return Err(hosted_hal_status(error));
        }
    };
    if mapped.resource_id != resource_id
        || mapped.translated_start != phys
        || mapped.length != length
    {
        if hosted_resource_manager_mut()
            .unmap_io_space(hosted_resource_owner(binding), mapped.mapping_id)
            .is_ok()
        {
            let _ = requests_mut().cancel_prepared(receipt);
        } else {
            let _ = requests_mut().mark_map_uncertain(receipt);
        }
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    if requests_mut().complete(
        receipt,
        va,
        nt_hosted_runtime::MmioRequestBacking::Assigned {
            resource_id,
            mapping_id: mapped.mapping_id,
        },
    ).is_err() {
        let _ = requests_mut().mark_map_uncertain(receipt);
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(va)
}

/// A void MmUnmapIoSpace refuses stale or foreign requests without touching another receipt.
pub(super) unsafe fn unmap_assigned(
    binding: HostedDeviceBinding,
    base: u64,
    length: u64,
) -> Result<(), nt_status::NtStatus> {
    let (owner, _) = pnp_owner(binding).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let (receipt, backing) = requests_mut().begin_unmap(owner, base, length)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let nt_hosted_runtime::MmioRequestBacking::Assigned { mapping_id, .. } = backing else {
        let _ = requests_mut().mark_unmap_uncertain(receipt);
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    match hosted_resource_manager_mut().unmap_io_space(hosted_resource_owner(binding), mapping_id) {
        Ok(()) => requests_mut().acknowledge_unmap(receipt)
            .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST),
        Err(error) => {
            let _ = requests_mut().mark_unmap_uncertain(receipt);
            Err(hosted_hal_status(error))
        }
    }
}

/// Common effect path for the primary physical pump and the authenticated IRQ arena.
pub(super) unsafe fn request_for_binding(
    binding: HostedDeviceBinding,
    operation: u64,
    address: u64,
    length: u64,
    cache: u64,
) -> (i32, u64) {
    let result = match operation {
        1 if cache <= u32::MAX as u64 => {
            map_assigned(binding, address, length, cache as u32)
        }
        2 if cache == 0 => unmap_assigned(binding, address, length).map(|_| 0),
        _ => Err(nt_status::NtStatus::INVALID_PARAMETER),
    };
    match result {
        Ok(value) => (nt_status::NtStatus::SUCCESS.raw(), value),
        Err(status) => (status.raw(), 0),
    }
}

fn trace_assigned_map_miss(
    stage: &[u8],
    instance: usize,
    shared_va: u64,
    address: u64,
    length: u64,
    device_id: u64,
) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 32 && !n.is_power_of_two() { return; }
    print_str(b"[assigned-mmio-route] n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b" instance=");
    print_u64(instance as u64);
    print_str(b" shared=0x");
    print_hex_u64(shared_va);
    print_str(b" phys=0x");
    print_hex_u64(address);
    print_str(b" len=");
    print_u64(length);
    print_str(b" device=");
    print_u64(device_id);
    print_str(b"\n");
}

pub(crate) fn service_hosted_driver_mmio_request(
    channel: &crate::spawn_hosts::PumpChannel,
    caller_badge: u64,
    active_reply_cap: u64,
    operation: u64,
    address: u64,
    length: u64,
    cache: u64,
) -> (i32, u64) {
    let refused = (nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw(), 0);
    let Some((instance_index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return refused;
    };
    if hosted_driver_pump_caller_tcb(channel, active_reply_cap, caller_badge).is_none() {
        return refused;
    }
    if length == 0 || address.checked_add(length).is_none() {
        return (nt_status::NtStatus::INVALID_PARAMETER.raw(), 0);
    }
    match current_hosted_device_dispatch_binding_for_projection(instance_index, channel.shared_va) {
        Ok(binding) => {
            if operation == 2 {
                let result = unsafe { request_for_binding(binding, operation, address, length, cache) };
                if result.0 == nt_status::NtStatus::SUCCESS.raw() {
                    return result;
                }
                // A GOP projection may coexist with an unrelated PnP binding in this process.
                // Its unmap still needs the exact provider publication and projection receipt.
            } else if operation == 1 {
                match unsafe { pnp_owner(binding) } {
                    Some((_, state)) if mapped_memory_resource(state, address, length).is_some() =>
                        return unsafe { request_for_binding(binding, operation, address, length, cache) },
                    Some(_) => trace_assigned_map_miss(b"resource", instance_index,
                        channel.shared_va, address, length, binding.device_id),
                    None => trace_assigned_map_miss(b"owner", instance_index,
                        channel.shared_va, address, length, binding.device_id),
                }
            } else {
                return unsafe { request_for_binding(binding, operation, address, length, cache) };
            }
        }
        Err(rejection) if operation == 1 =>
            trace_assigned_map_miss(rejection.name(), instance_index,
                channel.shared_va, address, length, 0),
        Err(_) => {},
    }
    // A driver may pass MmGetPhysicalAddress of its own live NonPagedPool allocation, even
    // while a PnP FDO binding is active. Borrow its existing WB VA with a separate receipt.
    match operation {
        1 if cache <= u32::MAX as u64 =>
            match unsafe { map_owned_pool(instance_index, inst, address, length, cache as u32) } {
                Ok(Some(va)) => return (nt_status::NtStatus::SUCCESS.raw(), va),
                Ok(None) => {},
                Err(status) => return (status.raw(), 0),
            },
        2 if cache == 0 =>
            match unsafe { unmap_owned_pool(instance_index, inst, address, length) } {
                Ok(true) => return (nt_status::NtStatus::SUCCESS.raw(), 0),
                Ok(false) => {},
                Err(status) => return (status.raw(), 0),
            },
        _ => {},
    }
    // A registered GOP provider may have no PnP FDO. Its publication and PCI inventory are
    // checked inside the projection service, then each successful call enters this ledger.
    match operation {
        1 if cache <= u32::MAX as u64 => {
            let va = hosted_driver_gop::service_hosted_driver_gop_map(
                channel, caller_badge, active_reply_cap, address, length, cache,
            );
            if va == 0 { refused } else { (nt_status::NtStatus::SUCCESS.raw(), va) }
        }
        2 if cache == 0 => match hosted_driver_gop::service_hosted_driver_gop_unmap(
            channel, caller_badge, active_reply_cap, address, length,
        ) {
            Ok(()) => (nt_status::NtStatus::SUCCESS.raw(), 0),
            Err(status) => (status.raw(), 0),
        },
        _ => (nt_status::NtStatus::INVALID_PARAMETER.raw(), 0),
    }
}

/// StartDevice reads only the exact binding's receipts, never the driver's mutable last-map bank.
pub(super) unsafe fn validate_publication(
    binding: HostedDeviceBinding,
    bus_owned_root_proof: Option<driver_launch::HostedBusOwnedRootPublicationProof>,
) -> Result<(), nt_status::NtStatus> {
    let state = retained_pnp_state(binding).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if state.address_resource_count == 0 && state.pnp_context_lease.is_none() {
        let pnp = hosted_pnp_manager_mut();
        let identity = pnp.devnode_identity_for_pdo(binding.pdo_device_id)
            .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
        if pnp.fdo(identity.devnode_id()) != Some(binding.device_id)
            || !(pnp.devnode_has_started_empty_assignment(identity)
                || pnp.devnode_has_started_bus_number_assignment(identity)
                || (bus_owned_root_proof.is_some_and(|proof| {
                    driver_launch::bus_owned_root_publication_proof_is_current(binding, proof)
                }) && pnp.devnode_has_started_bus_owned_root_assignment(identity)))
        {
            return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        }
        if has_retained_pnp_device_rows(binding) {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        return Ok(());
    }
    let (owner, state) = pnp_owner(binding).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let resources = state.address_resources
        .get(..usize::from(state.address_resource_count))
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    hosted_mmio_publication_policy::validate_receipts(
        resources,
        (*core::ptr::addr_of!(REQUESTS)).as_ref(),
        owner,
        |mapping_id| hosted_resource_manager_mut().mapping_info(mapping_id),
        |resource_index| hosted_mmio_resource_id(binding.device_id, resource_index),
    )
}

/// Drain ready per-call IDs before resource-page/cap retirement. An uncertain effect fences the
/// owner; it may never be replayed or silently dropped by the later revoke-owner operation.
pub(super) unsafe fn preflight_retirement(
    binding: HostedDeviceBinding,
) -> Result<(), nt_status::NtStatus> {
    let owner = match pnp_owner(binding) {
        Some((owner, _)) => owner,
        None => {
            let retained = (*core::ptr::addr_of!(REQUESTS)).as_ref().is_some_and(|ledger| {
                ledger.has_pnp_device_rows(
                    binding.projection_domain.domain_id.raw(),
                    binding.projection_domain.cookie,
                    binding.device_id,
                )
            });
            return if retained {
                Err(nt_status::NtStatus::DEVICE_BUSY)
            } else {
                Ok(())
            };
        }
    };
    if let Some(ledger) = (*core::ptr::addr_of!(REQUESTS)).as_ref() {
        if ledger.owner_rows(owner).any(|(_, _, _, phase)| {
            phase != nt_hosted_runtime::MmioRequestPhase::Ready
        }) {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
    }
    Ok(())
}

pub(super) unsafe fn retire_binding(
    binding: HostedDeviceBinding,
) -> Result<(), nt_status::NtStatus> {
    preflight_retirement(binding)?;
    let Some((owner, _)) = pnp_owner(binding) else { return Ok(()); };
    loop {
        let next = (*core::ptr::addr_of!(REQUESTS)).as_ref()
            .and_then(|ledger| ledger.owner_rows(owner)
                .find_map(|(request, va, _, _)| va.map(|va| (va, request.length))));
        let Some((base, length)) = next else {
            requests_mut().retire_completed_pnp_owner(owner);
            return Ok(());
        };
        unmap_assigned(binding, base, length)?;
    }
}

pub(super) unsafe fn prepare_gop(
    owner: nt_hosted_runtime::MmioRequestOwner,
    phys: u64,
    length: u64,
    cache: u32,
) -> Result<nt_hosted_runtime::MmioRequestReceipt, nt_status::NtStatus> {
    if cache != nt_hal_abi::MM_NON_CACHED {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    requests_mut().prepare(nt_hosted_runtime::MmioRequest {
        owner,
        physical_start: phys,
        length,
        cache,
    }).map_err(|_| nt_status::NtStatus::DEVICE_BUSY)
}

pub(super) unsafe fn complete_gop(
    receipt: nt_hosted_runtime::MmioRequestReceipt,
    owner: nt_hosted_runtime::MmioRequestOwner,
    va: u64,
) -> Result<(), nt_status::NtStatus> {
    let nt_hosted_runtime::MmioRequestAuthority::Gop {
        publication, inventory_generation, ..
    } = owner.authority else {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    requests_mut().complete(
        receipt,
        va,
        nt_hosted_runtime::MmioRequestBacking::Gop {
            publication,
            inventory_generation,
        },
    ).map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(super) unsafe fn cancel_gop(receipt: nt_hosted_runtime::MmioRequestReceipt) {
    let _ = requests_mut().cancel_prepared(receipt);
}

pub(super) unsafe fn uncertain_gop(receipt: nt_hosted_runtime::MmioRequestReceipt) {
    let _ = requests_mut().mark_map_uncertain(receipt);
}

pub(super) unsafe fn unmap_gop(
    owner: nt_hosted_runtime::MmioRequestOwner,
    base: u64,
    length: u64,
) -> Result<(), nt_status::NtStatus> {
    let (receipt, backing) = requests_mut().begin_unmap(owner, base, length)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if !matches!(backing, nt_hosted_runtime::MmioRequestBacking::Gop { .. }) {
        let _ = requests_mut().mark_unmap_uncertain(receipt);
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    // The GOP page projection is generation-owned and remains until provider retirement.
    requests_mut().acknowledge_unmap(receipt)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(super) unsafe fn retire_gop_owner(
    owner: nt_hosted_runtime::MmioRequestOwner,
) -> Result<(), nt_status::NtStatus> {
    if let Some(ledger) = (*core::ptr::addr_of!(REQUESTS)).as_ref() {
        if ledger.owner_rows(owner).any(|(_, _, _, phase)| {
            phase != nt_hosted_runtime::MmioRequestPhase::Ready
        }) {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
    }
    loop {
        let next = (*core::ptr::addr_of!(REQUESTS)).as_ref()
            .and_then(|ledger| ledger.owner_rows(owner)
                .find_map(|(request, va, _, _)| va.map(|va| (va, request.length))));
        let Some((base, length)) = next else { return Ok(()); };
        unmap_gop(owner, base, length)?;
    }
}
