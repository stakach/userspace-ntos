//! Repair only a live, granted device resource leaf using its original retained cap.

use super::*;
use nt_pnp_context::resource_mapping::{MappingDomain, MappingPhase};

pub(crate) unsafe fn service_fault(
    channel: &crate::spawn_hosts::PumpChannel,
    address: u64,
    fsr: u64,
) -> Option<bool> {
    if !crate::hosted_pnp_context::is_component_resource_address(address) {
        return None;
    }
    match authenticated_pump_channel_domain(channel) {
        Some(crate::spawn_hosts::shared_ingress::owner::runtime::PhysicalDomain::Provider {
            ..
        }) => return None,
        Some(crate::spawn_hosts::shared_ingress::owner::runtime::PhysicalDomain::Hosted(_)) => {}
        None => return Some(false),
    }
    let Some((instance, inst)) = physical_instance_for_pump_channel(channel) else {
        return Some(false);
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return Some(false);
    };
    if fsr & 0x11 != 0 || !read_volatile(core::ptr::addr_of!(DRIVER_IO_MANAGER_INIT)) {
        return Some(false);
    }
    let page = address & !0xfff;
    let selected = hosted_resource_mapping::table().iter().find_map(|row| {
        let key = row.key();
        if row.phase() != MappingPhase::Mapped
            || key.pml4 != channel.pml4
            || key.virtual_page != page
            || key.domain
                != (MappingDomain {
                    id: domain.domain_id.raw(),
                    cookie: domain.cookie,
                })
            || key.attributes != 0
            || (fsr & 2 != 0 && key.rights & 1 == 0)
        {
            return None;
        }
        row.owners().find_map(|(receipt, owner)| {
            if owner.instance != instance {
                return None;
            }
            let state = hosted_device_resource_state_by_device_id(owner.device_id)?;
            if state.pnp_context_lease != Some(owner.context_lease)
                || !crate::hosted_pnp_context::hosted_pnp_context_lease_is_live(owner.context_lease)
            {
                return None;
            }
            let binding = hosted_device_binding_by_device_id(owner.device_id)?;
            if binding.instance != instance && binding.projection_instance != instance {
                return None;
            }
            if state.driver_id != binding.driver_id
                || state.instance != binding.instance
                || state.projection_domain != binding.projection_domain
                || state.pdo_object != binding.pdo_object
            {
                return None;
            }
            let io = (&*core::ptr::addr_of!(DRIVER_IO_MANAGER)).assume_init_ref();
            if io
                .device(nt_io_manager::DeviceId(owner.device_id))
                .is_none_or(|device| device.delete_pending)
            {
                return None;
            }
            let resource = hosted_state_address_resources(&state)
                .iter()
                .find(|resource| {
                    resource.kind == SH_RESOURCE_ADDRESS_KIND_MEMORY
                        && address
                            .checked_sub(resource.va)
                            .is_some_and(|offset| offset < resource.map_len)
                })?;
            let offset = address.checked_sub(resource.va)?;
            let physical = resource.translated_start.checked_add(offset)?;
            if physical & !0xfff != key.physical_page {
                return None;
            }
            let (source_cap, expected) =
                crate::hosted_pnp_context::hosted_pnp_mapping_page(owner.context_lease, page)
                    .ok()?;
            if expected != Some(key.physical_page)
                || hosted_resource_mapping::checked_frame_address(source_cap).ok()?
                    != key.physical_page
                || hosted_resource_mapping::checked_frame_address(row.cap()?).ok()?
                    != key.physical_page
            {
                return None;
            }
            let resource_id = hosted_mmio_resource_id(owner.device_id, resource.resource_index)?;
            let grants =
                hosted_resource_manager_mut().query_resources(hosted_resource_owner(binding));
            let grant = grants.iter().find(|grant| {
                grant.kind == nt_hal_abi::RES_KIND_MEMORY
                    && grant.resource_id == resource_id
                    && grant.translated_start == resource.translated_start
                    && grant.length == resource.len
                    && grant.arg0 == nt_hal_abi::MM_NON_CACHED as u64
            })?;
            let rights = grant.arg1;
            let expected = if rights & nt_hal_abi::RIGHT_WRITE != 0 {
                RW_NX
            } else {
                RO_NX
            };
            if rights & nt_hal_abi::RIGHT_READ == 0 || expected != key.rights {
                return None;
            }
            Some((receipt, key))
        })
    });
    let Some((receipt, key)) = selected else {
        return Some(false);
    };
    let Some((cap, effect)) = hosted_resource_mapping::begin_remap(receipt) else {
        return Some(false);
    };
    let error = page_map_r(cap, key.virtual_page, key.rights, key.pml4);
    Some(hosted_resource_mapping::finish_remap(effect, error))
}
