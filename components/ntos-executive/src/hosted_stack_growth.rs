//! Caller-owned stack guard growth through canonical VAD and commitment policy.

use super::*;
use nt_thread_start::stack_vad::{
    prepare_guard_growth_into, StackGeometry, StackGrowthPolicy, StackVadError, StackVadOutcome,
};

fn plan_error(error: StackVadError) -> u32 {
    match error {
        StackVadError::Vm(status) => status,
        StackVadError::CommitLimit => nt_memory_manager::STATUS_COMMITMENT_LIMIT,
        _ => nt_address_space::STATUS_ACCESS_VIOLATION,
    }
}

pub(crate) unsafe fn service_hosted_stack_growth(
    handler: &mut ExecNtHandler,
    pi: usize,
    badge: u64,
    fault_address: u64,
    pml4: u64,
    scratch_base: u64,
    access: nt_address_space::FaultAccess,
) -> Result<Option<StackVadOutcome>, u32> {
    use nt_address_space::{VmExtentState, PAGE_GUARD, PAGE_SIZE};

    let page = fault_address & !(PAGE_SIZE - 1);
    let Some((allocation_base, stack_base, _)) =
        handler.hosted_thread_user_stack_for_badge(badge, pi)
    else {
        return Ok(None);
    };
    if page < allocation_base || page >= stack_base {
        return Ok(None);
    }
    let Some(map) = process_vm_region_map_mut(pi)
        .map(|map| map as *mut nt_address_space::VmRegionMap<VM_REGION_CAPACITY>)
    else {
        return Ok(None);
    };
    let Some(extent) = (&*map).extent_at(page) else {
        return Ok(None);
    };
    if extent.allocation_base != allocation_base || extent.type_ != nt_address_space::MEM_PRIVATE {
        return Ok(None);
    }
    if extent.state != VmExtentState::Committed {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }
    let protection = (&*map)
        .protection_at(page)
        .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?;
    if protection & PAGE_GUARD == 0 {
        return Ok(None);
    }
    if nt_address_space::private_guard_page_fault_plan(protection, access).is_none() {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }

    let runtime = handler
        .admit_hosted_thread_ingress(badge)
        .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
    if runtime.pi != pi {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let lifetime = handler
        .pm
        .thread_lifetime(u32::try_from(runtime.tid).map_err(|_| nt_process::STATUS_INVALID_HANDLE)?)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let process = handler
        .capture_process_identity(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let ctx = handler
        .loop_ctx
        .and_then(|ctx| ctx.for_process(pi))
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let target = (&*ctx.procs)
        .get(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if pml4 == 0 || target.pml4 != pml4 || target.scratch_base != scratch_base {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let teb = handler
        .hosted_thread_teb_for_badge(badge)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let peb = handler
        .pm
        .query_process_basic(lifetime.process_id(), u64::MAX)?
        .peb_base_address;
    if peb == 0 {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let mut tib = [0u8; 16];
    let mut flags = [0u8; 4];
    handler
        .process_memory_read_status(pi, teb + 8, &mut tib)
        .map_err(|_| nt_address_space::copy::STATUS_GUARD_PAGE_VIOLATION)?;
    handler
        .process_memory_read_status(pi, peb + 0xbc, &mut flags)
        .map_err(|_| nt_address_space::copy::STATUS_GUARD_PAGE_VIOLATION)?;
    if u64::from_le_bytes(tib[..8].try_into().unwrap()) != stack_base {
        return Err(nt_address_space::STATUS_ACCESS_VIOLATION);
    }
    let geometry = StackGeometry {
        allocation_base,
        stack_base,
        stack_limit: u64::from_le_bytes(tib[8..].try_into().unwrap()),
        guard_base: Some(page),
    };
    let policy = StackGrowthPolicy {
        extension_disabled: u32::from_le_bytes(flags) & 0x0001_0000 != 0,
        protection: protection & !PAGE_GUARD,
    };
    let before = *map;
    let mut candidate = before;
    let changes = prepare_guard_growth_into(
        &before,
        &mut candidate,
        geometry,
        fault_address,
        policy,
        u64::MAX,
    )
    .map_err(plan_error)?
    .changes();

    // Any eviction or page-table allocation precedes the serialized commitment plan.
    if let Some(new_page) = changes.commit_base {
        handler.ensure_process_working_set_admission(pi, new_page, scratch_base)?;
        ensure_process_user_page_table(handler, pi, new_page, pml4)?;
    }
    if handler.pm.thread_lifetime(lifetime.thread_id()) != Some(lifetime)
        || handler.capture_process_identity(pi) != Some(process)
        || *map != before
    {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let charge = match handler.prepare_process_commit_charge(
        lifetime.process_id(),
        pi,
        changes.commit_bytes,
    ) {
        Ok(charge) => Some(charge),
        Err(status) if status == nt_memory_manager::STATUS_COMMITMENT_LIMIT => None,
        Err(status) => return Err(status),
    };
    let plan = prepare_guard_growth_into(
        &before,
        &mut candidate,
        geometry,
        fault_address,
        policy,
        if charge.is_some() { u64::MAX } else { 0 },
    )
    .map_err(plan_error)?;
    let changes = plan.changes();
    if let Some(new_page) = changes.commit_base {
        vm_map_private_page(
            handler,
            pi,
            new_page,
            plan.candidate()
                .protection_at(new_page)
                .ok_or(nt_address_space::STATUS_ACCESS_VIOLATION)?,
            pml4,
            scratch_base,
        )?;
    }
    if let Some(charge) = charge {
        handler.commit_process_commit_charge(charge);
    }
    // A later refusal retains the acknowledged frame/charge; the caller parks the fault.
    // It must not restart this transaction or discard native ownership on an uncertain effect.
    if csrss_frame_get_exact(pi as u64, page).0 == 0 {
        vm_map_private_page(handler, pi, page, protection, pml4, scratch_base)?;
    }
    vm_reprotect_private_page(pi, process, page, protection, changes.protection, pml4)?;
    plan.apply_exact(&mut *map).map_err(plan_error)?;
    handler
        .process_memory_write_checked(pi, teb + 0x10, &changes.geometry.stack_limit.to_le_bytes())
        .map_err(|failure| match failure {
            nt_address_space::copy::MemoryCopyFailure::UserFault(_) => {
                nt_address_space::copy::STATUS_GUARD_PAGE_VIOLATION
            }
            nt_address_space::copy::MemoryCopyFailure::Retry(status) => status,
        })?;
    Ok(Some(changes.outcome))
}
