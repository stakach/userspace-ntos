//! Validate and select one live root-owned interrupt grant for a hosted driver.
use super::*;

fn hosted_interrupt_grant_scope(
    binding: HostedDeviceBinding,
) -> nt_hosted_runtime::InterruptGrantScope {
    nt_hosted_runtime::InterruptGrantScope {
        driver_id: binding.driver_id,
        instance: binding.instance,
        projection_instance: binding.projection_instance,
        domain_id: binding.projection_domain.domain_id.raw(),
        domain_cookie: binding.projection_domain.cookie,
    }
}

unsafe fn validate_hosted_interrupt_assignment(
    binding: HostedDeviceBinding,
    state: HostedDeviceResourceState,
) -> Result<(), nt_status::NtStatus> {
    let lease = state
        .pnp_context_lease
        .filter(|lease| crate::hosted_pnp_context_lease_is_live(*lease))
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let claim = state
        .interrupt_claim
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let physical = crate::validate_physical_interrupt_claim(claim)?;
    let assigned_vector = state.evidence.interrupt_vector;
    if assigned_vector == 0
        || state.interrupt_irql == 0
        || physical.gsi != state.interrupt_line
        || physical.vector != assigned_vector
        || physical.level_sensitive == state.interrupt_latched
        || physical.active_low != state.interrupt_active_low
        || physical.shared != state.interrupt_shared
        || state.pnp_context_lease != Some(lease)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let resource_id = hosted_interrupt_resource_id(binding.device_id)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let assigned = hosted_resource_manager_mut()
        .query_resources(hosted_resource_owner(binding))
        .into_iter()
        .any(|resource| {
            let (descriptor_vector, irql, affinity, mode) = resource.interrupt_fields();
            resource.kind == nt_hal_abi::RES_KIND_INTERRUPT
                && resource.resource_id == resource_id
                && resource.raw_start == state.interrupt_line as u64
                && resource.translated_start == assigned_vector as u64
                && descriptor_vector == assigned_vector
                && irql == state.interrupt_irql
                && affinity as u64 == state.interrupt_affinity
                && mode
                    == if state.interrupt_latched {
                        nt_hal_abi::INT_MODE_LATCHED
                    } else {
                        nt_hal_abi::INT_MODE_LEVEL_SENSITIVE
                    }
                && (resource.share == nt_hal_abi::SHARE_SHARED) == state.interrupt_shared
        });
    if !assigned {
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    Ok(())
}

/// The active callback proves the driver domain; its mutable bank does not choose an IRQ.
/// Only authenticated live candidates participate in uniqueness selection.
pub(super) unsafe fn select_hosted_interrupt_grant(
    active: HostedDeviceBinding,
    vector: u32,
    pdo_object: u64,
) -> Result<(HostedDeviceBinding, HostedDeviceResourceState), nt_status::NtStatus> {
    let scope = hosted_interrupt_grant_scope(active);
    let device_id = nt_hosted_runtime::select_interrupt_grant(
        nt_hosted_runtime::InterruptGrantRequest {
            scope,
            pdo_object,
            vector,
        },
        hosted_device_bindings()
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?
            .iter()
            .copied()
            .filter_map(|binding| {
                if !binding.used || binding.device_id == 0 {
                    return None;
                }
                let state = retained_hosted_device_resource_state(binding).ok()?;
                validate_hosted_interrupt_assignment(binding, state).ok()?;
                Some(nt_hosted_runtime::InterruptGrant {
                    scope: hosted_interrupt_grant_scope(binding),
                    device_id: binding.device_id,
                    pdo_object: binding.pdo_object,
                    vector: state.evidence.interrupt_vector,
                })
            }),
    )
    .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let binding = hosted_device_binding_by_device_id(device_id)
        .filter(|binding| hosted_interrupt_grant_scope(*binding) == scope)
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let state = retained_hosted_device_resource_state(binding)?;
    validate_hosted_interrupt_assignment(binding, state)?;
    Ok((binding, state))
}
