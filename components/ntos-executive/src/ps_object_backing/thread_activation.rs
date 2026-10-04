//! Exact dormant ETHREAD alias admission and activation publication.

use super::*;

/// Close old-body grant admission before removing its provider aliases.
///
/// # Safety
/// `plan` was just returned by PM prepare_thread_activation under exclusive caller ownership,
/// before binding any new handle. No NT operation, provider entry or pump may intervene. This
/// fresh plan proves Initialized-thread reference policy; Terminated threads are also rechecked.
pub(crate) unsafe fn prepare_thread_reactivation(
    pm: &ProcessManager,
    plan: &nt_process::ThreadActivationPlan,
    scratch_base: u64,
) -> Result<(), u32> {
    let lifetime = plan.expected_lifetime();
    if pm.thread_lifetime(plan.thread_id()) != Some(lifetime) {
        return Err(INVALID);
    }
    match pm.thread(plan.thread_id()).ok_or(INVALID)?.state {
        nt_process::ThreadState::Initialized => {}
        nt_process::ThreadState::Terminated if pm.can_reclaim_thread(plan.thread_id()) => {}
        _ => return Err(INVALID),
    }
    let Some(body) = pm.thread_kernel_object(plan.thread_id()) else {
        return Ok(());
    };
    let borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.validate(pm)?;
    let Some(index) = arena.existing(BodyId::Thread(plan.thread_id())) else {
        // A published pointer without its exact owner cannot prove old aliases were drained.
        // Only the genuinely absent-body path above admits first initialization without a row.
        return Err(INVALID);
    };
    let row = &mut arena.rows[index];
    if row.page.descriptor().address != body
        || row.current_thread_lifetime != Some(lifetime)
        || !row.page.is_initialized()
        || row
            .page
            .live_alias(MappingTarget::Executive(arena.root))
            .is_none()
        || !match row.phase {
            BodyPhase::Published => true,
            BodyPhase::Reactivating { lifetime: held } => held == lifetime,
            _ => false,
        }
    {
        return Err(INVALID);
    }
    row.phase = BodyPhase::Reactivating { lifetime };
    let mut io = Io {
        paging: &mut arena.paging,
        providers: &mut arena.providers,
        root: arena.root,
        scratch_base,
        address: row.page.descriptor().address,
        borrow: &borrow,
    };
    row.page.retire_non_root_aliases(&mut io)
}

/// Commit PM activation and refresh its stable body without an intervening provider entry.
///
/// # Safety
/// The target TCB remains suspended. Every old-activation execution/request reference is drained;
/// the alias owner separately proves that even failed non-root mapping candidates are gone.
pub(crate) unsafe fn commit_thread_activation(
    pm: &mut ProcessManager,
    plan: nt_process::ThreadActivationPlan,
    handle: nt_process::HandleReservation,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let arena = (&mut *core::ptr::addr_of_mut!(ARENA))
        .as_mut()
        .ok_or(INVALID)?;
    arena.validate(pm)?;
    let Some(index) = arena.existing(BodyId::Thread(plan.thread_id())) else {
        if pm
            .thread_kernel_object(plan.thread_id())
            .is_some_and(contains_address)
        {
            return Err(INVALID);
        }
        return pm.commit_thread_activation_with_handle(plan, handle);
    };
    let row = &mut arena.rows[index];
    let body = row.page.descriptor().address;
    if !matches!(
        row.phase,
        BodyPhase::Prepared | BodyPhase::Published | BodyPhase::Reactivating { .. }
    ) || matches!(row.phase, BodyPhase::Reactivating { lifetime } if lifetime != plan.expected_lifetime())
        || !row.page.is_initialized()
        || row.current_thread_lifetime != Some(plan.expected_lifetime())
        || pm.thread_kernel_object(plan.thread_id())
            != match row.phase {
                BodyPhase::Prepared => None,
                BodyPhase::Published | BodyPhase::Reactivating { .. } => Some(body),
                BodyPhase::Retiring { .. } => return Err(INVALID),
            }
        || row
            .page
            .live_alias(MappingTarget::Executive(arena.root))
            .is_none()
        || !row.page.non_root_aliases_drained()
    {
        record_thread_activation_guard_failure(pm, &plan, row, arena.root, "body-guard");
        return Err(INVALID);
    }
    let Initialization::Thread { mut fields, .. } = row.page.descriptor().initialization else {
        record_thread_activation_guard_failure(pm, &plan, row, arena.root, "body-type");
        return Err(INVALID);
    };
    if pm.process_kernel_object(plan.process_id()) != Some(fields.process_body.0) {
        record_thread_activation_guard_failure(pm, &plan, row, arena.root, "process-body");
        return Err(INVALID);
    }
    fields.teb = GuestAddr(plan.teb_base());
    fields.system_thread = pm.thread(plan.thread_id()).ok_or(INVALID)?.is_system_thread;
    let bytes = core::slice::from_raw_parts_mut(body as *mut u8, abi::ETHREAD_BODY_BYTES);
    if abi::validate_thread_activation(bytes, fields).is_err() {
        record_thread_activation_guard_failure(pm, &plan, row, arena.root, "body-bytes");
        return Err(INVALID);
    }
    match row.phase {
        BodyPhase::Prepared => {
            pm.commit_thread_activation_with_handle_and_object(plan, handle, body)?;
        }
        BodyPhase::Published | BodyPhase::Reactivating { .. } => {
            pm.commit_thread_activation_with_handle(plan, handle)?
        }
        BodyPhase::Retiring { .. } => unreachable!(),
    }
    // Both owners remain exclusively borrowed. No allocation, syscall or provider byte write can
    // invalidate the preflight between PM generation publication and these bounded field writes.
    abi::refresh_thread_activation(bytes, fields).expect("exclusive prevalidated ETHREAD refresh");
    row.current_thread_lifetime = pm.thread_lifetime(plan.thread_id());
    row.phase = BodyPhase::Published;
    Ok(())
}

fn record_thread_activation_guard_failure(
    pm: &ProcessManager,
    plan: &nt_process::ThreadActivationPlan,
    row: &Row,
    root: Root,
    reason: &str,
) {
    use core::fmt::Write;
    let mut record = nt_printf::record::RecordBuffer::<512>::new();
    let expected = plan.expected_lifetime();
    let phase = match row.phase {
        BodyPhase::Prepared => "prepared",
        BodyPhase::Published => "published",
        BodyPhase::Reactivating { .. } => "reactivating",
        BodyPhase::Retiring { .. } => "retiring",
    };
    let body = row.page.descriptor().address;
    let pm_body = pm.thread_kernel_object(plan.thread_id());
    let body_matches = match row.phase {
        BodyPhase::Prepared => pm_body.is_none(),
        BodyPhase::Published | BodyPhase::Reactivating { .. } => pm_body == Some(body),
        BodyPhase::Retiring { .. } => false,
    };
    let process_body_matches = match row.page.descriptor().initialization {
        Initialization::Thread { fields, .. } => {
            pm.process_kernel_object(plan.process_id()) == Some(fields.process_body.0)
        }
        _ => false,
    };
    let _ = writeln!(record,
        "[thread-activation-guard] pid={} tid={} expected-generation={} cached-generation={} phase={} reason={} initialized={} lifetime-equal={} pm-lifetime-equal={} pm-body-equal={} root-alias={} nonroot-drained={} process-body-equal={} body=0x{:016x}",
        expected.process_id(), expected.thread_id(), expected.generation(),
        row.current_thread_lifetime.map_or(0, |lifetime| lifetime.generation()), phase, reason,
        row.page.is_initialized() as u8, (row.current_thread_lifetime == Some(expected)) as u8,
        (pm.thread_lifetime(plan.thread_id()) == Some(expected)) as u8, body_matches as u8,
        row.page.live_alias(MappingTarget::Executive(root)).is_some() as u8,
        row.page.non_root_aliases_drained() as u8, process_body_matches as u8, body);
    sel4_rt::print_record(if record.overflowed() {
        b"[thread-activation-guard] record-truncated\n"
    } else {
        record.bytes()
    });
}
