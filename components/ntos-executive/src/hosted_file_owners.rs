//! Native File IRP ownership across provider IPC and completion delivery.

use super::*;
use nt_io_manager::detached_file_irp::{
    ExternalFileIrpBuffers, ExternalFileIrpCancelPhase, ExternalFileIrpCancelReturn,
    ExternalFileIrpCompletionInvocation, ExternalFileIrpCompletionReturn,
    ExternalFileIrpCopyReturn, ExternalFileIrpRequest, ExternalFileIrpResult,
    ExternalFileIrpReturn, ExternalFileIrpTerminal, PreparedExternalFileIrp,
    RetainedExternalFileIrp,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flight {
    Preparing,
    Dispatch,
    Copy,
    Cancel,
    Acknowledge,
    Idle,
    Blocked,
}

enum Payload {
    Prepared(PreparedExternalFileIrp),
    Returned(ExternalFileIrpReturn),
    Retained(RetainedExternalFileIrp),
    Completion(ExternalFileIrpCompletionInvocation),
    Acknowledgement(ExternalFileIrpCompletionReturn),
    Copy(ExternalFileIrpCopyReturn),
    Cancel(ExternalFileIrpCancelReturn),
    Terminal(ExternalFileIrpTerminal),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Authority {
    instance: usize,
    driver_id: u64,
    domain: HostedDomainIdentity,
    tcb: u64,
    pml4: u64,
    fault_ep: u64,
    shared_va: u64,
}

impl Authority {
    fn capture(index: usize) -> Option<Self> {
        let current = instance(index)?;
        Some(Self {
            instance: index,
            driver_id: current.driver_id,
            domain: instance_domain_identity(current)?,
            tcb: current.tcb,
            pml4: current.pml4,
            fault_ep: current.fault_ep,
            shared_va: current.exec_shared_va,
        })
    }

    fn live(self) -> bool {
        Self::capture(self.instance) == Some(self)
    }
}

struct Row {
    id: u64,
    irp_id: Option<IrpId>,
    primary_device: Option<nt_io_manager::DeviceId>,
    primary_driver: Option<nt_io_manager::DriverId>,
    stack: Vec<(nt_io_manager::DeviceId, nt_io_manager::DriverId)>,
    authorities: Vec<Authority>,
    completion_storage: Option<(usize, usize)>,
    flight: Flight,
    payload: Option<Payload>,
    blocked_status: Option<nt_status::NtStatus>,
    completion: Option<nt_io_manager::CompletedIrp>,
    retry_after: u64,
    work_ready: bool,
}

static mut ROWS: Vec<Row> = Vec::new();
static mut NEXT_ID: u64 = 1;
static mut NEXT_DRAIN_ID: u64 = 1;
static RETRY_READY: AtomicU64 = AtomicU64::new(0);

/// Current retained owners, not cumulative outcomes or proof of provider readiness.
#[derive(Clone, Copy, Default)]
pub(crate) struct Stats {
    pub live: usize,
    pub preparing: usize,
    pub dispatching: usize,
    pub copying: usize,
    pub cancelling: usize,
    pub acknowledging: usize,
    pub idle: usize,
    pub blocked: usize,
    pub pending: usize,
    pub indeterminate: usize,
    pub completions: usize,
    pub copy_returns: usize,
    pub ack_returns: usize,
    pub retry_deadlines: usize,
    pub retained_errors: usize,
}

pub(super) fn stats() -> Stats {
    let mut stats = Stats::default();
    // Observe only: do not resolve completions, change deadlines, or invoke a provider.
    for row in unsafe { &*core::ptr::addr_of!(ROWS) } {
        stats.live += 1;
        match row.flight {
            Flight::Preparing => stats.preparing += 1,
            Flight::Dispatch => stats.dispatching += 1,
            Flight::Copy => stats.copying += 1,
            Flight::Cancel => stats.cancelling += 1,
            Flight::Acknowledge => stats.acknowledging += 1,
            Flight::Idle => stats.idle += 1,
            Flight::Blocked => stats.blocked += 1,
        }
        match row.payload.as_ref() {
            Some(Payload::Retained(owner)) if owner.is_indeterminate() => {
                stats.indeterminate += 1;
            }
            Some(Payload::Retained(_)) => stats.pending += 1,
            Some(Payload::Copy(_)) => stats.copy_returns += 1,
            Some(Payload::Acknowledgement(_)) => stats.ack_returns += 1,
            _ => {}
        }
        stats.completions += usize::from(row.completion.is_some());
        stats.retry_deadlines += usize::from(row.flight == Flight::Idle && row.retry_after != 0);
        stats.retained_errors += usize::from(row.blocked_status.is_some());
    }
    stats
}

fn rows() -> &'static mut Vec<Row> {
    // All access is serialized by the executive. References never cross an external call.
    unsafe { &mut *core::ptr::addr_of_mut!(ROWS) }
}

fn row(id: u64) -> &'static mut Row {
    rows()
        .iter_mut()
        .find(|row| row.id == id)
        .expect("File IRP owner missing")
}

fn find(irp_id: IrpId) -> Option<u64> {
    rows()
        .iter()
        .find(|row| row.irp_id == Some(irp_id))
        .map(|row| row.id)
}

fn remove(id: u64) {
    let index = rows()
        .iter()
        .position(|row| row.id == id)
        .expect("File IRP owner missing");
    rows().swap_remove(index);
}

fn reserve() -> Result<u64, nt_status::NtStatus> {
    let id = unsafe { NEXT_ID };
    let next = id
        .checked_add(1)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    rows()
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    unsafe { NEXT_ID = next };
    rows().push(Row {
        id,
        irp_id: None,
        primary_device: None,
        primary_driver: None,
        stack: Vec::new(),
        authorities: Vec::new(),
        completion_storage: None,
        flight: Flight::Preparing,
        payload: None,
        blocked_status: None,
        completion: None,
        retry_after: 0,
        work_ready: false,
    });
    Ok(id)
}

fn add_authority(authorities: &mut Vec<Authority>, authority: Authority) {
    if !authorities.iter().any(|current| *current == authority) {
        // Capacity for the dependent and physical provider of every stack entry was reserved.
        assert!(authorities.len() < authorities.capacity());
        authorities.push(authority);
    }
}

fn capture_route(id: u64, prepared: &PreparedExternalFileIrp) -> Result<(), nt_status::NtStatus> {
    row(id).irp_id = Some(prepared.irp_id());
    row(id).primary_device = Some(prepared.route().device_id());
    row(id).primary_driver = Some(prepared.route().driver_id());
    let mut stack = Vec::new();
    {
        let irp = io_manager_mut()
            .irp(prepared.irp_id())
            .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        stack
            .try_reserve_exact(irp.stack.len())
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        stack.extend(
            irp.stack
                .iter()
                .map(|entry| (entry.device_id, entry.driver_id)),
        );
    }
    let mut authorities = Vec::new();
    let capacity = stack
        .len()
        .checked_mul(2)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    authorities
        .try_reserve_exact(capacity)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    for (_, driver_id) in &stack {
        let Some((index, _)) = instance_by_driver_id(driver_id.raw()) else {
            continue;
        };
        let dependent =
            Authority::capture(index).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
        add_authority(&mut authorities, dependent);
        if let Some(route) = unsafe { hosted_provider_dispatch_route_for_instance(index) } {
            let provider = Authority::capture(route.provider_instance)
                .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
            if dependent.domain != route.dependent_domain
                || provider.domain != route.provider_domain
            {
                return Err(nt_status::NtStatus::INVALID_PARAMETER);
            }
            add_authority(&mut authorities, provider);
        }
    }
    if !authorities
        .iter()
        .any(|authority| authority.driver_id == prepared.route().driver_id().raw())
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    row(id).stack = stack;
    row(id).authorities = authorities;
    let (dependent, _) = instance_by_driver_id(prepared.route().driver_id().raw())
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    row(id).completion_storage = Some((dependent, hosted_completion_storage_instance(dependent)));
    Ok(())
}

fn live_route(id: u64) -> bool {
    !row(id).authorities.is_empty()
        && row(id).authorities.iter().all(|authority| authority.live())
        && row(id)
            .completion_storage
            .is_some_and(|(dependent, physical)| {
                hosted_completion_storage_instance(dependent) == physical
            })
}

fn block(id: u64, payload: Payload, status: nt_status::NtStatus) {
    let row = row(id);
    row.payload = Some(payload);
    row.flight = Flight::Blocked;
    row.blocked_status = Some(status);
}

fn keep(id: u64, payload: Payload) {
    let row = row(id);
    row.payload = Some(payload);
    row.flight = Flight::Idle;
    row.blocked_status = None;
    row.retry_after = 0;
}

fn retry_later(id: u64, payload: Payload, status: nt_status::NtStatus) {
    keep(id, payload);
    row(id).blocked_status = Some(status);
    row(id).retry_after = monotonic_time_100ns().saturating_add(1_000_000);
}

fn discard(id: u64, prepared: PreparedExternalFileIrp) {
    match io_manager_mut().discard_prepared_external_file_irp(prepared) {
        Ok(_) => remove(id),
        Err(rejection) => {
            let (status, owner) = rejection.into_parts();
            block(id, Payload::Prepared(owner), status);
        }
    }
}

pub(super) enum DispatchResult {
    Returned {
        status: nt_status::NtStatus,
        information: u64,
        file_context: Option<u64>,
        buffers: ExternalFileIrpBuffers,
    },
    Outstanding {
        irp_id: IrpId,
    },
}

pub(super) fn dispatch(
    request: ExternalFileIrpRequest,
    input: &[u8],
    initial_output: &[u8],
) -> Result<DispatchResult, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let copy = |source: &[u8]| -> Result<Vec<u8>, nt_status::NtStatus> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(source.len())
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        bytes.extend_from_slice(source);
        Ok(bytes)
    };
    let buffers = ExternalFileIrpBuffers::new(copy(input)?, copy(initial_output)?);
    let id = reserve()?;
    let prepared = match io_manager_mut().prepare_external_file_irp_owned(request, buffers) {
        Ok(prepared) => prepared,
        Err(status) => {
            remove(id);
            return Err(status);
        }
    };
    if let Err(status) = capture_route(id, &prepared) {
        discard(id, prepared);
        return Err(status);
    }
    let irp_id = prepared.irp_id();
    let invocation = match io_manager_mut().begin_prepared_external_file_irp(prepared) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            let (status, prepared) = rejection.into_parts();
            discard(id, prepared);
            return Err(status);
        }
    };
    row(id).flight = Flight::Dispatch;
    let returned = hosted_file_dispatch::invoke(invocation);
    let result = match io_manager_mut().finish_external_file_irp(returned) {
        Ok(result) => result,
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            block(id, Payload::Returned(returned), status);
            return Ok(DispatchResult::Outstanding { irp_id });
        }
    };
    match result {
        ExternalFileIrpResult::NotEntered { status, prepared } => {
            discard(id, prepared);
            Err(status)
        }
        ExternalFileIrpResult::Returned(terminal) => {
            let completion = *terminal.completion();
            match io_manager_mut().retire_external_file_irp_terminal(terminal) {
                Ok((receipt, buffers)) => {
                    assert!(io_manager_mut().accepts_external_file_irp_receipt(&receipt));
                    remove(id);
                    Ok(DispatchResult::Returned {
                        status: completion.status,
                        information: completion.information,
                        file_context: completion.file_context,
                        buffers,
                    })
                }
                Err(rejection) => {
                    let (status, terminal) = rejection.into_parts();
                    block(id, Payload::Terminal(terminal), status);
                    Ok(DispatchResult::Outstanding { irp_id })
                }
            }
        }
        ExternalFileIrpResult::Pending(retained) => {
            keep(id, Payload::Retained(retained));
            Ok(DispatchResult::Outstanding { irp_id })
        }
        ExternalFileIrpResult::Indeterminate {
            transport_status,
            retained,
        } => {
            keep(id, Payload::Retained(retained));
            row(id).blocked_status = Some(transport_status);
            Ok(DispatchResult::Outstanding { irp_id })
        }
    }
}

pub(super) fn contains(irp_id: IrpId) -> bool {
    find(irp_id).is_some()
}

fn ensure_completion(id: u64) -> Result<(), nt_status::NtStatus> {
    if row(id).flight != Flight::Idle {
        return Err(row(id)
            .blocked_status
            .unwrap_or(nt_status::NtStatus::DEVICE_BUSY));
    }
    let payload = row(id)
        .payload
        .take()
        .expect("idle File owner missing payload");
    match payload {
        Payload::Retained(retained) => {
            match io_manager_mut().prepare_external_file_irp_completion(retained) {
                Ok(completion) => {
                    row(id).completion = Some(*completion.completion());
                    keep(id, Payload::Completion(completion));
                    Ok(())
                }
                Err(rejection) => {
                    let (status, retained) = rejection.into_parts();
                    // Observing a pending IRP must not erase its cancellation backoff.
                    row(id).payload = Some(Payload::Retained(retained));
                    Err(status)
                }
            }
        }
        payload @ (Payload::Completion(_) | Payload::Copy(_) | Payload::Acknowledgement(_)) => {
            row(id).payload = Some(payload);
            Ok(())
        }
        other => {
            block(id, other, nt_status::NtStatus::INVALID_PARAMETER);
            Err(nt_status::NtStatus::INVALID_PARAMETER)
        }
    }
}

pub(super) fn completion(
    irp_id: IrpId,
) -> Result<nt_io_manager::CompletedIrp, nt_status::NtStatus> {
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    ensure_completion(id)?;
    row(id)
        .completion
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)
}

fn copy_chunk(id: u64) -> Result<(), nt_status::NtStatus> {
    if monotonic_time_100ns() < row(id).retry_after {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    if !live_route(id) {
        row(id).flight = Flight::Blocked;
        row(id).blocked_status = Some(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    let payload = row(id)
        .payload
        .take()
        .expect("File completion owner missing");
    let invocation = match payload {
        Payload::Completion(completion) => {
            match io_manager_mut().begin_external_file_irp_copy(completion, 4096) {
                Ok(invocation) => invocation,
                Err(rejection) => {
                    let (status, completion) = rejection.into_parts();
                    keep(id, Payload::Completion(completion));
                    return Err(status);
                }
            }
        }
        Payload::Copy(returned) => returned.retry(),
        other => {
            keep(id, other);
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
    };
    row(id).flight = Flight::Copy;
    let returned = hosted_file_dispatch::copy(invocation);
    match io_manager_mut().finish_external_file_irp_copy(returned) {
        Ok(completion) => {
            keep(id, Payload::Completion(completion));
            Ok(())
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            retry_later(id, Payload::Copy(returned), status);
            Err(status)
        }
    }
}

pub(super) fn copy_output(
    irp_id: IrpId,
    offset: u64,
    output: &mut [u8],
) -> Result<usize, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    ensure_completion(id)?;
    let offset = usize::try_from(offset).map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
    loop {
        match row(id).payload.as_ref() {
            Some(Payload::Completion(completion)) => {
                if offset > completion.capture_len() {
                    return Err(nt_status::NtStatus::INVALID_PARAMETER);
                }
                let length = output.len().min(completion.capture_len() - offset);
                let end = offset + length;
                if end <= completion.captured_len() || length == 0 {
                    output[..length].copy_from_slice(&completion.buffers().output()[offset..end]);
                    return Ok(length);
                }
            }
            Some(Payload::Copy(_)) => {}
            _ => return Err(nt_status::NtStatus::DEVICE_BUSY),
        }
        copy_chunk(id)?;
    }
}

pub(super) fn acknowledge(irp_id: IrpId) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let id = find(irp_id).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    ensure_completion(id)?;
    if monotonic_time_100ns() < row(id).retry_after {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    let abandoned = io_manager_mut()
        .detached_file_irp_intent(ClientId(IO_MANAGER_COMPONENT_ID), irp_id)?
        .abandoned;
    if abandoned {
        match row(id).payload.take() {
            Some(Payload::Copy(returned)) => {
                keep(id, Payload::Completion(returned.into_completion()))
            }
            other => row(id).payload = other,
        }
    }
    loop {
        let needs_copy = match row(id).payload.as_ref() {
            Some(Payload::Completion(completion)) => !abandoned && !completion.capture_complete(),
            Some(Payload::Copy(_)) => true,
            Some(Payload::Acknowledgement(_)) => false,
            _ => return Err(nt_status::NtStatus::DEVICE_BUSY),
        };
        if !needs_copy {
            break;
        }
        copy_chunk(id)?;
    }
    let payload = row(id).payload.take().expect("File ACK owner missing");
    let invocation = match payload {
        Payload::Completion(completion) => {
            match io_manager_mut().begin_external_file_irp_acknowledgement(completion) {
                Ok(invocation) => invocation,
                Err(rejection) => {
                    let (status, completion) = rejection.into_parts();
                    keep(id, Payload::Completion(completion));
                    return Err(status);
                }
            }
        }
        Payload::Acknowledgement(returned) => {
            match io_manager_mut().finish_external_file_irp_completion(returned) {
                Ok((receipt, _)) => {
                    assert!(receipt.backend_acknowledged());
                    remove(id);
                    return Ok(());
                }
                Err(rejection) => {
                    let (status, returned) = rejection.into_parts();
                    match returned.retry() {
                        Ok(invocation) => invocation,
                        Err(returned) => {
                            block(id, Payload::Acknowledgement(returned), status);
                            return Err(status);
                        }
                    }
                }
            }
        }
        other => {
            keep(id, other);
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
    };
    row(id).flight = Flight::Acknowledge;
    if !live_route(id) {
        let status = nt_status::NtStatus::DEVICE_NOT_CONNECTED;
        let returned = invocation.acknowledged(
            nt_io_manager::detached_file_irp::ExternalFileIrpAcknowledgement::NotEntered { status },
        );
        block(id, Payload::Acknowledgement(returned), status);
        return Err(status);
    }
    let returned = hosted_file_dispatch::acknowledge(invocation);
    match io_manager_mut().finish_external_file_irp_completion(returned) {
        Ok((receipt, _)) => {
            assert!(receipt.backend_acknowledged());
            assert!(io_manager_mut().accepts_external_file_irp_receipt(&receipt));
            remove(id);
            Ok(())
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            retry_later(id, Payload::Acknowledgement(returned), status);
            Err(status)
        }
    }
}

fn cancel_queued(id: u64) -> bool {
    if row(id).flight != Flight::Idle {
        return false;
    }
    if !live_route(id) {
        row(id).flight = Flight::Blocked;
        row(id).blocked_status = Some(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
        return false;
    }
    let payload = row(id).payload.take().expect("File cancel owner missing");
    let retained = match payload {
        Payload::Retained(retained) => retained,
        other => {
            keep(id, other);
            return false;
        }
    };
    let invocation = match io_manager_mut().begin_external_file_irp_cancel(retained) {
        Ok(invocation) => invocation,
        Err(rejection) => {
            let (status, retained) = rejection.into_parts();
            retry_later(id, Payload::Retained(retained), status);
            return false;
        }
    };
    row(id).flight = Flight::Cancel;
    let returned = hosted_file_dispatch::cancel(invocation);
    match io_manager_mut().finish_external_file_irp_cancel(returned) {
        Ok(result) => {
            let (retained, outcome) = result.into_parts();
            keep(id, Payload::Retained(retained));
            if matches!(
                outcome,
                nt_io_manager::detached_file_irp::ExternalFileIrpCancelOutcome::NotEntered { .. }
                    | nt_io_manager::detached_file_irp::ExternalFileIrpCancelOutcome::Rejected { .. }
            ) {
                row(id).retry_after = monotonic_time_100ns().saturating_add(1_000_000);
            }
            true
        }
        Err(rejection) => {
            let (status, returned) = rejection.into_parts();
            block(id, Payload::Cancel(returned), status);
            false
        }
    }
}

pub(super) fn drain() -> usize {
    let _durable = crate::allocator::enter_durable();
    let mut selected = [0u64; 32];
    let now = monotonic_time_100ns();
    RETRY_READY.store(0, Ordering::Relaxed);
    for entry in rows().iter_mut() {
        entry.work_ready = false;
        if entry.flight != Flight::Idle {
            continue;
        }
        let Some(irp_id) = entry.irp_id else { continue };
        let Ok(intent) =
            io_manager_mut().detached_file_irp_intent(ClientId(IO_MANAGER_COMPONENT_ID), irp_id)
        else {
            continue;
        };
        entry.work_ready = intent.cancel == ExternalFileIrpCancelPhase::Queued
            && matches!(entry.payload, Some(Payload::Retained(_)))
            || intent.abandoned && io_manager_mut().completed_irp(irp_id).is_some();
        if !entry.work_ready
            && entry.retry_after != 0
            && entry.retry_after <= now
            && matches!(
                entry.payload,
                Some(Payload::Copy(_) | Payload::Acknowledgement(_))
            )
        {
            // Transfer a due retry to its delivery owner once, rather than rearming
            // an overdue timer while that owner is waiting for the outer loop.
            entry.retry_after = 0;
            crate::service_sec_image::FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
        }
        if entry.work_ready && entry.retry_after == 0 {
            entry.retry_after = now;
        }
    }
    let cursor = unsafe { NEXT_DRAIN_ID };
    let selection = nt_kernel_exec::select_cyclic_ids(
        rows()
            .iter()
            .filter(|row| row.work_ready && row.flight == Flight::Idle && row.retry_after <= now)
            .map(|row| row.id),
        cursor,
        &mut selected,
    );
    let count = selection.count;
    unsafe { NEXT_DRAIN_ID = selection.next_cursor };
    let mut progress = 0;
    for id in &selected[..count] {
        let Some(irp_id) = rows()
            .iter()
            .find(|row| row.id == *id)
            .and_then(|row| row.irp_id)
        else {
            continue;
        };
        let Ok(intent) =
            io_manager_mut().detached_file_irp_intent(ClientId(IO_MANAGER_COMPONENT_ID), irp_id)
        else {
            continue;
        };
        if intent.abandoned && io_manager_mut().completed_irp(irp_id).is_some() {
            progress += usize::from(acknowledge(irp_id).is_ok());
        } else if intent.cancel == ExternalFileIrpCancelPhase::Queued {
            progress += usize::from(cancel_queued(*id));
        }
    }
    progress
}

pub(super) fn retry_deadline() -> Option<u64> {
    if RETRY_READY.load(Ordering::Relaxed) != 0 {
        return None;
    }
    rows()
        .iter()
        .filter(|row| row.flight == Flight::Idle && row.retry_after != 0)
        .map(|row| row.retry_after)
        .min()
}

pub(super) fn retry_wake_due(now: u64) -> u64 {
    if retry_deadline().is_some_and(|deadline| now >= deadline) {
        return u64::from(RETRY_READY.swap(1, Ordering::Relaxed) == 0);
    }
    0
}

pub(super) fn device_quiesced(device_id: u64) -> bool {
    rows().iter().all(|row| {
        row.primary_device
            .is_none_or(|device| device.raw() != device_id)
            && row
                .stack
                .iter()
                .all(|(device, _)| device.raw() != device_id)
    })
}

pub(super) fn instance_quiesced(index: usize) -> bool {
    let driver = instance(index).map(|instance| instance.driver_id);
    rows().iter().all(|row| {
        row.authorities
            .iter()
            .all(|authority| authority.instance != index)
            && row
                .primary_driver
                .map(|id| id.raw())
                .is_none_or(|id| Some(id) != driver)
            && row.stack.iter().all(|(_, id)| Some(id.raw()) != driver)
    })
}

pub(super) fn domain_quiesced(domain: HostedDomainIdentity) -> bool {
    rows().iter().all(|row| {
        row.authorities
            .iter()
            .all(|authority| authority.domain != domain)
    })
}

pub(super) fn lifetime_quiesced(
    index: usize,
    driver_id: u64,
    domain: HostedDomainIdentity,
) -> bool {
    instance_quiesced(index)
        && domain_quiesced(domain)
        && rows().iter().all(|row| {
            row.primary_driver.is_none_or(|id| id.raw() != driver_id)
                && row
                    .stack
                    .iter()
                    .all(|(_, driver)| driver.raw() != driver_id)
        })
}
