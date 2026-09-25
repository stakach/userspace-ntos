//! Bind a hosted CREATE's local security graph to its canonical IRP and retained requestor.

use super::*;
use nt_io_abi::IrpId;
use nt_security::SubjectClientIdentity;

const STATUS_INVALID_HANDLE_LOCAL: i32 = 0xc000_0008u32 as i32;
const STATUS_INVALID_PARAMETER_LOCAL: i32 = 0xc000_000du32 as i32;

pub(super) unsafe fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp: u64,
    security_context: u64,
) -> (i32, u64, u64) {
    let Some((source_index, source)) = instance_for_pump_channel(channel, reply_cap) else {
        return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
    };
    if hosted_driver_pump_caller_tcb(channel, reply_cap, caller_badge).is_none()
        || source_irp == 0
        || security_context == 0
        || read_volatile((source.exec_shared_va + SH_ACTIVE_IRP) as *const u64) != source_irp
    {
        return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
    }
    let transfer_id = read_volatile((source.exec_shared_va + SH_REQ_CONTROL_ID) as *const u64);
    let (thread, canonical_irp) = {
        let Some(active) = active_hosted_irp_transfer_mut(channel.shared_va, transfer_id) else {
            return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
        };
        let Some(thread) = active.requestor_thread else {
            return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
        };
        if active.source_instance != source_index
            || active.create_subject.is_some()
            || active.file_create.is_none_or(|(_, domain)| Some(domain) != instance_domain_identity(source))
        {
            return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
        }
        (thread, IrpId(active.transfer_id))
    };
    if canonical_irp.is_null() || canonical_irp.generation() == 0 {
        return (STATUS_INVALID_PARAMETER_LOCAL, 0, 0);
    }
    let Some(exec_irp) = hosted_instance_pool_allocation_exec_if_live(
        source, source_irp, WDM_X64_IRP_SIZE as u64,
    ) else {
        return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
    };
    let stack_count = read_unaligned((exec_irp + WDM_X64_IRP_STACK_COUNT_OFFSET) as *const u8);
    let Some(total) = (WDM_X64_IRP_SIZE as u64).checked_add(
        (stack_count as u64).saturating_mul(WDM_X64_IO_STACK_LOCATION_SIZE as u64),
    ) else {
        return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
    };
    let Some(exec_irp) = hosted_instance_pool_allocation_exec_if_live(source, source_irp, total)
    else {
        return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
    };
    let iosl = read_volatile((source.exec_shared_va + SH_ACTIVE_IOSL) as *const u64);
    if stack_count == 0
        || iosl < source_irp + WDM_X64_IRP_SIZE as u64
        || iosl.checked_add(WDM_X64_IO_STACK_LOCATION_SIZE as u64)
            .is_none_or(|end| end > source_irp + total)
    {
        return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
    }
    let exec_iosl = exec_irp + (iosl - source_irp);
    if read_unaligned((exec_iosl + 8) as *const u64) != security_context {
        return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
    }
    if !hosted_source_create_security::live_context(source, security_context) {
        return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
    }
    let create_access = match hosted_source_create_security::capture_create_access(
        source,
        security_context,
    ) {
        Ok(captured) => captured,
        Err(status) => return (status as i32, 0, 0),
    };
    let captured = crate::with_provider_security_managers(|pm, tokens| {
        if !pm.validate_thread_lifetime(thread) {
            return Err(STATUS_INVALID_HANDLE_LOCAL as u32);
        }
        let primary = pm.process_primary_token(thread.process_id())
            .ok_or(STATUS_INVALID_HANDLE_LOCAL as u32)?;
        let client = pm.thread_impersonation(thread.thread_id()).map(|context| {
            SubjectClientIdentity { token: context.token, level: context.level }
        });
        hosted_source_create_security::capture(
            source,
            canonical_irp.raw(),
            u64::from(canonical_irp.generation()),
            security_context,
            primary,
            client,
            u64::from(thread.process_id()),
            create_access,
            tokens,
        )
    });
    match captured {
        Ok(identity) => {
            let active = active_hosted_irp_transfer_mut(channel.shared_va, transfer_id)
                .filter(|active| active.source_instance == source_index
                    && active.requestor_thread == Some(thread)
                    && active.create_subject.is_none());
            let Some(active) = active else {
                assert!(hosted_source_create_security::mark_terminal(source, identity));
                crate::with_provider_security_managers(|_, tokens| {
                    hosted_source_create_security::release(source, identity, tokens)
                }).expect("unentered CREATE subject must release");
                return (STATUS_INVALID_HANDLE_LOCAL, 0, 0);
            };
            active.create_subject = Some(identity);
            (STATUS_SUCCESS, identity.ticket.id(), identity.ticket.generation())
        }
        Err(status) => (status as i32, 0, 0),
    }
}

#[derive(Clone, Copy)]
pub(super) enum SourceCreateCompletion {
    Returned(nt_status::NtStatus),
    AcknowledgedTerminal,
    Indeterminate,
}

pub(super) fn finish(
    source: DriverInstance,
    identity: hosted_source_create_security::SourceSecurityIdentity,
    completion: SourceCreateCompletion,
) {
    let changed = match completion {
        SourceCreateCompletion::Indeterminate =>
            hosted_source_create_security::mark_indeterminate(source, identity),
        SourceCreateCompletion::Returned(nt_status::NtStatus::PENDING) =>
            hosted_source_create_security::mark_pending(source, identity),
        SourceCreateCompletion::Returned(_) | SourceCreateCompletion::AcknowledgedTerminal =>
            hosted_source_create_security::mark_terminal(source, identity),
    };
    assert!(changed, "canonical CREATE subject lost before provider return");
    if matches!(completion, SourceCreateCompletion::Returned(value) if value != nt_status::NtStatus::PENDING)
        || matches!(completion, SourceCreateCompletion::AcknowledgedTerminal) {
        let _ = unsafe { retire_terminal_step(source, identity) };
    }
}

struct CleanupGuard {
    source: DriverInstance,
    identity: hosted_source_create_security::SourceSecurityIdentity,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        hosted_source_create_security::end_terminal_cleanup(self.source, self.identity);
    }
}

/// Retry only cleanup of a genuinely terminal outer CREATE. A failed pool free keeps its exact
/// RetiringTokenProjection receipt in the source row; no provider dispatch or bind is replayed.
unsafe fn retire_terminal_step(
    source: DriverInstance,
    identity: hosted_source_create_security::SourceSecurityIdentity,
) -> Result<(), i32> {
    if !hosted_source_create_security::begin_terminal_cleanup(source, identity) {
        return Err(nt_status::NtStatus::DEVICE_BUSY.raw());
    }
    let _guard = CleanupGuard { source, identity };
    hosted_create_security_graph::retry_preentry_for_source(source, identity)?;
    for _ in 0..64 {
        if let Some(retiring) =
            hosted_source_create_security::take_retiring_projection(source, identity)
        {
            match driver_hosted_token_projection::free_retired(retiring) {
                Ok(()) => continue,
                Err((status, retiring)) => {
                    hosted_source_create_security::retain_retiring_projection(
                        source, identity, retiring,
                    );
                    return Err(status);
                }
            }
        }
        let next = driver_hosted_token_projection::next_bound_for_source(
            source, identity.ticket, identity.key,
        )?;
        let Some((provider, address)) = next else {
            return crate::with_provider_security_managers(|_, tokens| {
                hosted_source_create_security::release(source, identity, tokens)
            }).map_err(|status| status as i32);
        };
        let retiring = crate::with_provider_security_managers(|_, tokens| {
            hosted_source_create_security::retire_projection_binding(
                source, provider, identity, address, tokens,
            ).map_err(|status| status as u32)
        }).map_err(|status| status as i32)?;
        match driver_hosted_token_projection::free_retired(retiring) {
            Ok(()) => {},
            Err((status, retiring)) => {
                hosted_source_create_security::retain_retiring_projection(
                    source, identity, retiring,
                );
                return Err(status);
            }
        }
    }
    Err(nt_status::NtStatus::DEVICE_BUSY.raw())
}

static TERMINAL_REDRIVE_CURSOR: AtomicU64 = AtomicU64::new(0);

pub(super) unsafe fn redrive_terminal() {
    let count = hosted_source_create_security::row_count();
    if count == 0 {
        return;
    }
    let start = TERMINAL_REDRIVE_CURSOR.fetch_add(1, Ordering::Relaxed) as usize % count;
    for offset in 0..count {
        let index = (start + offset) % count;
        if let Some((source, identity)) = hosted_source_create_security::terminal_at(index) {
            let _ = retire_terminal_step(source, identity);
            return;
        }
    }
}
