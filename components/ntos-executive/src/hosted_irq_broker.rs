//! Root-owned driver for the private hosted-interrupt arena.
//!
//! The sibling component TCB never owns cross-lane authority. Root retains the physical interrupt,
//! connection rundown, and `KINTERRUPT::ActualLock` leases while this module drives the lane's
//! typed Dispatch/Service stack to an exact outer completion.

use super::*;

const STATUS_POSSIBLE_DEADLOCK: i32 = 0xC000_0194u32 as i32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HostedIrqRootDispatchOutcome {
    Completed(nt_hosted_runtime::HostedIrqArenaResult),
    DeferredBusy,
}

#[derive(Clone, Copy)]
struct HostedIrqLaneView {
    identity: nt_hosted_runtime::HostedIrqLaneIdentity,
    channel: crate::spawn_hosts::PumpChannel,
    badge: u64,
    arena_va: u64,
}

impl HostedIrqLaneView {
    unsafe fn arena(self) -> &'static nt_hosted_runtime::HostedIrqArena {
        &*(self.arena_va as *const nt_hosted_runtime::HostedIrqArena)
    }
}

struct HostedIrqRootSession {
    lane: HostedIrqLaneView,
    transaction: nt_hosted_runtime::HostedIrqTransaction,
    outer_lock: InterruptActualLockLease,
    service_locks: Vec<InterruptActualLockLease>,
}

fn arena_status(error: nt_hosted_runtime::HostedIrqArenaError) -> nt_status::NtStatus {
    match error {
        nt_hosted_runtime::HostedIrqArenaError::Busy => nt_status::NtStatus::DEVICE_BUSY,
        nt_hosted_runtime::HostedIrqArenaError::Poisoned
        | nt_hosted_runtime::HostedIrqArenaError::Shutdown => nt_status::NtStatus::UNSUCCESSFUL,
        _ => nt_status::NtStatus::INVALID_DEVICE_REQUEST,
    }
}

fn service_result(status: i32, value: Option<u64>) -> nt_hosted_runtime::HostedIrqArenaResult {
    let mut result = nt_hosted_runtime::HostedIrqArenaResult {
        status,
        faulted: false,
        value_count: 0,
        values: [0; nt_hosted_runtime::HOSTED_IRQ_ARENA_RESULT_CAP],
    };
    if let Some(value) = value {
        result.value_count = 1;
        result.values[0] = value;
    }
    result
}

fn fatal_service_result(status: i32) -> nt_hosted_runtime::HostedIrqArenaResult {
    nt_hosted_runtime::HostedIrqArenaResult {
        status,
        faulted: true,
        value_count: 0,
        values: [0; nt_hosted_runtime::HOSTED_IRQ_ARENA_RESULT_CAP],
    }
}

unsafe fn lane_view(
    connection: HostedIrqConnection,
) -> Result<HostedIrqLaneView, nt_status::NtStatus> {
    let lane = hosted_irq_lanes()
        .and_then(|lanes| {
            lanes.iter().find(|lane| {
                lane.projection_instance == connection.binding.projection_instance
                    && lane.domain == connection.binding.projection_domain
                    && lane.identity.lane_generation == connection.lane_generation
                    && lane.state == HostedIrqLaneState::Ready
            })
        })
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    if lane.exec_arena_va == 0 || !lane.arena.iter().all(|leaf| leaf.exec_mapped) {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let inst = instance(lane.projection_instance)
        .filter(|inst| instance_domain_identity(*inst) == Some(lane.domain))
        .ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let channel = hosted_irq_lane_channel(lane, inst)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    Ok(HostedIrqLaneView {
        identity: lane.identity,
        channel,
        badge: lane.badge,
        arena_va: lane.exec_arena_va,
    })
}

unsafe fn connection_for_service(
    lane: HostedIrqLaneView,
    command: nt_hosted_runtime::HostedIrqServiceCommand,
) -> Result<HostedIrqConnection, nt_status::NtStatus> {
    let connection = hosted_irq_connections()
        .and_then(|connections| {
            connections.iter().copied().find(|connection| {
                hosted_irq_connection_active(*connection)
                    && connection.grant == command.grant
                    && connection.binding.projection_domain.domain_id.raw()
                        == lane.identity.domain_id
                    && connection.binding.projection_domain.cookie == lane.identity.domain_cookie
                    && connection.lane_generation == lane.identity.lane_generation
            })
        })
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    validate_hosted_irq_actual_lock(connection)?;
    Ok(connection)
}

impl HostedIrqRootSession {
    unsafe fn record_fault(
        &self,
        token: nt_hosted_runtime::HostedIrqArenaToken,
        kind: nt_hosted_runtime::HostedIrqFaultKind,
        code: u64,
        instruction_pointer: u64,
        address: u64,
        parameters: [u64; 4],
    ) {
        let _ = self.lane.arena().control.record_first_fault(
            self.lane.identity,
            nt_hosted_runtime::HostedIrqFaultRecord {
                kind,
                transaction: token.transaction,
                sequence: token.sequence,
                depth: token.depth,
                direction: token.direction,
                code,
                instruction_pointer,
                address,
                parameters,
            },
        );
        if let Some(lane) = hosted_irq_lanes_mut()
            .iter_mut()
            .find(|lane| lane.identity == self.lane.identity)
        {
            lane.state = HostedIrqLaneState::Quarantined;
        }
    }

    unsafe fn exchange(
        &self,
        reply: nt_hosted_runtime::HostedIrqArenaToken,
    ) -> Result<crate::spawn_hosts::HostedIrqExchangeMessage, nt_status::NtStatus> {
        let result = crate::spawn_hosts::component_hosted_irq_exchange(
            &self.lane.channel,
            crate::spawn_hosts::HostedIrqExchangeAction::ReplyToken {
                identity: self.lane.identity,
                token: reply,
            },
            self.lane.badge,
            FSD_IRQ_LANE_COMPLETION_LABEL,
        );
        if result.reply_cap != self.lane.channel.reply_cap
            || result.message == crate::spawn_hosts::HostedIrqExchangeMessage::Wall
        {
            self.record_fault(
                reply,
                nt_hosted_runtime::HostedIrqFaultKind::Transport,
                result.wall_label,
                result.wall_ip,
                result.wall_addr,
                [
                    result.wall_flags,
                    result.wall_exception,
                    result.wall_code,
                    result.faults.saturating_add(result.demand),
                ],
            );
            return Err(nt_status::NtStatus::UNSUCCESSFUL);
        }
        Ok(result.message)
    }

    unsafe fn actual_lock_service(
        &mut self,
        command: nt_hosted_runtime::HostedIrqServiceCommand,
    ) -> nt_hosted_runtime::HostedIrqArenaResult {
        if command.target_domain_id != self.lane.identity.domain_id
            || command.target_domain_cookie != self.lane.identity.domain_cookie
        {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        }
        let connection = match connection_for_service(self.lane, command) {
            Ok(connection) => connection,
            Err(status) => return fatal_service_result(status.raw()),
        };
        if command.service_id != connection.actual_lock.lock_token {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        }
        match command.kind {
            nt_hosted_runtime::HostedIrqServiceKind::AcquireActualLock => {
                if self.outer_lock.identity == connection.actual_lock
                    || self
                        .service_locks
                        .iter()
                        .any(|lease| lease.identity == connection.actual_lock)
                {
                    return fatal_service_result(STATUS_POSSIBLE_DEADLOCK);
                }
                match hosted_irq_actual_locks_mut()
                    .acquire(connection.actual_lock, connection.rundown.identity())
                {
                    Ok(lease) => {
                        if self.service_locks.try_reserve(1).is_err() {
                            let _ = hosted_irq_actual_locks_mut().release(lease);
                            return fatal_service_result(STATUS_INSUFFICIENT_RESOURCES);
                        }
                        self.service_locks.push(lease);
                        service_result(STATUS_SUCCESS, Some(lease.sequence))
                    }
                    Err(InterruptActualLockError::Busy) => {
                        fatal_service_result(STATUS_POSSIBLE_DEADLOCK)
                    }
                    Err(error) => {
                        fatal_service_result(hosted_irq_actual_lock_status(error).raw())
                    }
                }
            }
            nt_hosted_runtime::HostedIrqServiceKind::ReleaseActualLock => {
                let sequence = command.arguments[0];
                let Some(index) = self.service_locks.iter().position(|lease| {
                    lease.identity == connection.actual_lock
                        && lease.owner == connection.rundown.identity()
                        && lease.sequence == sequence
                }) else {
                    return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
                };
                let lease = self.service_locks[index];
                match hosted_irq_actual_locks_mut().release(lease) {
                    Ok(()) => {
                        self.service_locks.remove(index);
                        service_result(STATUS_SUCCESS, None)
                    }
                    Err(error) => {
                        fatal_service_result(hosted_irq_actual_lock_status(error).raw())
                    }
                }
            }
            _ => fatal_service_result(STATUS_INVALID_DEVICE_REQUEST),
        }
    }

    unsafe fn queue_dpc_service(
        &mut self,
        command: nt_hosted_runtime::HostedIrqServiceCommand,
    ) -> nt_hosted_runtime::HostedIrqArenaResult {
        if command.target_domain_id != self.lane.identity.domain_id
            || command.target_domain_cookie != self.lane.identity.domain_cookie
            || command.argument_count != 4
            || command.arguments[0] == 0
        {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        }
        let connection = match connection_for_service(self.lane, command) {
            Ok(connection) => connection,
            Err(status) => return fatal_service_result(status.raw()),
        };
        let instance_index = connection.binding.projection_instance;
        let Some(inst) = instance(instance_index) else {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        };
        if instance_domain_identity(inst) != Some(connection.binding.projection_domain) {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        }
        let Some(exec_dpc) = component_to_exec_va_for_instance(
            instance_index,
            inst,
            command.service_id,
            KDPC_SIZE,
        ) else {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        };
        let routine = command.arguments[0];
        let deferred_context = command.arguments[1];
        let image_frames = if inst.image_frames == 0 {
            FSD_IMAGE_FRAMES
        } else {
            inst.image_frames
        };
        let routine_is_executable = image_frames
            .checked_mul(0x1000)
            .and_then(|image_bytes| {
                let window = ExecVaWindow::try_for_instance(instance_index)?;
                translate_component_range(
                    routine,
                    1,
                    FSD_CODE_VA,
                    image_bytes,
                    window.code_va,
                )
            })
            .is_some();
        if !routine_is_executable
            || read_unaligned((exec_dpc + KDPC_DEFERRED_ROUTINE_OFFSET) as *const u64) != routine
            || read_unaligned((exec_dpc + KDPC_DEFERRED_CONTEXT_OFFSET) as *const u64)
                != deferred_context
        {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        }
        let Some(owner) = HostedDpcOwner::new(
            connection.binding.projection_domain.domain_id.raw(),
            connection.binding.projection_domain.cookie,
        ) else {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        };
        let queue = match hosted_dpcs_mut().register_and_queue(
            owner,
            command.service_id,
            routine,
            deferred_context,
            command.arguments[2],
            command.arguments[3],
        ) {
            Ok(queue) => queue,
            Err(error) => return fatal_service_result(hosted_dpc_status(error).raw()),
        };
        let (inserted, identity) = match queue {
            HostedDpcQueueResult::Queued(identity) => (true, identity),
            HostedDpcQueueResult::AlreadyQueued(identity) => (false, identity),
        };
        let projected_queued = read_unaligned((exec_dpc + KDPC_QUEUED_OFFSET) as *const u8) != 0;
        if projected_queued != !inserted {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        }
        if inserted {
            write_unaligned((exec_dpc + KDPC_SYSTEM_ARGUMENT1_OFFSET) as *mut u64, command.arguments[2]);
            write_unaligned((exec_dpc + KDPC_SYSTEM_ARGUMENT2_OFFSET) as *mut u64, command.arguments[3]);
            write_unaligned((exec_dpc + KDPC_QUEUED_OFFSET) as *mut u8, 1);
        }
        let mut result = service_result(STATUS_SUCCESS, Some(inserted as u64));
        result.value_count = 2;
        result.values[1] = identity.generation;
        result
    }

    unsafe fn execute_service(
        &mut self,
        command: nt_hosted_runtime::HostedIrqServiceCommand,
    ) -> nt_hosted_runtime::HostedIrqArenaResult {
        match command.kind {
            nt_hosted_runtime::HostedIrqServiceKind::AcquireActualLock
            | nt_hosted_runtime::HostedIrqServiceKind::ReleaseActualLock => {
                self.actual_lock_service(command)
            }
            nt_hosted_runtime::HostedIrqServiceKind::QueueDpc => {
                self.queue_dpc_service(command)
            }
            nt_hosted_runtime::HostedIrqServiceKind::ProviderImport
            | nt_hosted_runtime::HostedIrqServiceKind::ProviderCallbackRequest => {
                service_result(STATUS_NOT_SUPPORTED, None)
            }
        }
    }

    unsafe fn service_and_resume(
        &mut self,
        parent: nt_hosted_runtime::HostedIrqArenaToken,
        service: nt_hosted_runtime::HostedIrqArenaToken,
    ) -> Result<crate::spawn_hosts::HostedIrqExchangeMessage, nt_status::NtStatus> {
        if service.direction != nt_hosted_runtime::HostedIrqLaneDirection::Service
            || service.transaction != self.transaction.transaction
            || service.depth != parent.depth
        {
            self.record_fault(
                service,
                nt_hosted_runtime::HostedIrqFaultKind::Protocol,
                0x5352_5644,
                0,
                0,
                parent.transport_words(),
            );
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let arena = self.lane.arena();
        let command = arena.service[service.depth as usize]
            .root_begin(&arena.control, self.lane.identity, service)
            .map_err(arena_status)?;
        let result = self.execute_service(command);
        if result.faulted {
            self.record_fault(
                service,
                nt_hosted_runtime::HostedIrqFaultKind::ServiceFault,
                result.status as u32 as u64,
                0,
                command.service_id,
                command.arguments[..4].try_into().unwrap_or([0; 4]),
            );
        }
        arena.service[service.depth as usize]
            .root_complete(&arena.control, self.lane.identity, service, result)
            .map_err(arena_status)?;
        self.exchange(service)
    }

    unsafe fn drive_dispatch(
        &mut self,
        dispatch: nt_hosted_runtime::HostedIrqArenaToken,
    ) -> Result<nt_hosted_runtime::HostedIrqArenaResult, nt_status::NtStatus> {
        let mut message = self.exchange(dispatch)?;
        loop {
            let token = match message {
                crate::spawn_hosts::HostedIrqExchangeMessage::Token(token) => token,
                crate::spawn_hosts::HostedIrqExchangeMessage::Ready
                | crate::spawn_hosts::HostedIrqExchangeMessage::Wall => {
                    self.record_fault(
                        dispatch,
                        nt_hosted_runtime::HostedIrqFaultKind::Protocol,
                        0x4452_5645,
                        0,
                        0,
                        [0; 4],
                    );
                    return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
                }
            };
            if token == dispatch {
                let arena = self.lane.arena();
                let result = arena.dispatch[dispatch.depth as usize]
                    .root_completion(self.lane.identity, dispatch)
                    .map_err(arena_status)?;
                arena.dispatch[dispatch.depth as usize]
                    .root_acknowledge(&arena.control, self.lane.identity, dispatch)
                    .map_err(arena_status)?;
                return Ok(result);
            }
            if token.direction != nt_hosted_runtime::HostedIrqLaneDirection::Service {
                self.record_fault(
                    token,
                    nt_hosted_runtime::HostedIrqFaultKind::Protocol,
                    0x4453_544b,
                    0,
                    0,
                    dispatch.transport_words(),
                );
                return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            }
            message = self.service_and_resume(dispatch, token)?;
        }
    }

    unsafe fn release_service_locks(&mut self) -> Result<(), nt_status::NtStatus> {
        let mut first_error = None;
        while let Some(lease) = self.service_locks.pop() {
            if let Err(error) = hosted_irq_actual_locks_mut().release(lease) {
                if first_error.is_none() {
                    first_error = Some(hosted_irq_actual_lock_status(error));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

pub(super) unsafe fn dispatch_interrupt(
    connection: HostedIrqConnection,
) -> Result<HostedIrqRootDispatchOutcome, nt_status::NtStatus> {
    validate_hosted_irq_actual_lock(connection)?;
    let lane = lane_view(connection)?;
    let outer_lock = match hosted_irq_actual_locks_mut()
        .acquire(connection.actual_lock, connection.rundown.identity())
    {
        Ok(lease) => lease,
        Err(InterruptActualLockError::Busy) => {
            return Ok(HostedIrqRootDispatchOutcome::DeferredBusy)
        }
        Err(error) => return Err(hosted_irq_actual_lock_status(error)),
    };
    let arena = lane.arena();
    let transaction = match arena.control.root_begin_transaction(
        lane.identity,
        nt_hosted_runtime::HostedIrqTransactionClass::Interrupt,
    ) {
        Ok(transaction) => transaction,
        Err(nt_hosted_runtime::HostedIrqArenaError::Busy) => {
            hosted_irq_actual_locks_mut()
                .release(outer_lock)
                .map_err(hosted_irq_actual_lock_status)?;
            return Ok(HostedIrqRootDispatchOutcome::DeferredBusy);
        }
        Err(error) => {
            hosted_irq_actual_locks_mut()
                .release(outer_lock)
                .map_err(hosted_irq_actual_lock_status)?;
            return Err(arena_status(error));
        }
    };
    let command = nt_hosted_runtime::HostedIrqDispatchCommand {
        kind: nt_hosted_runtime::HostedIrqDispatchKind::InterruptService,
        work_id: connection.route.tokens.interrupt_id,
        routine: connection.route.tokens.service_routine_token,
        object: connection.interrupt_object,
        context: connection.route.tokens.service_context_token,
        entry_irql: connection.route.tokens.irql,
        synchronize_irql: connection.route.tokens.synchronize_irql,
        grant: connection.grant,
        argument_count: 0,
        arguments: [0; nt_hosted_runtime::HOSTED_IRQ_ARENA_ARGUMENT_CAP],
    };
    let dispatch = match arena.dispatch[0].root_publish(
        &arena.control,
        lane.identity,
        transaction,
        0,
        command,
    ) {
        Ok(token) => token,
        Err(error) => {
            let _ = arena.control.root_finish_transaction(lane.identity, transaction);
            hosted_irq_actual_locks_mut()
                .release(outer_lock)
                .map_err(hosted_irq_actual_lock_status)?;
            return Err(arena_status(error));
        }
    };
    let mut session = HostedIrqRootSession {
        lane,
        transaction,
        outer_lock,
        service_locks: Vec::new(),
    };
    let result = session.drive_dispatch(dispatch);
    let dispatch_faulted = result
        .as_ref()
        .is_ok_and(|result| result.faulted || result.status != STATUS_SUCCESS);
    if dispatch_faulted {
        let status = result.as_ref().map(|result| result.status).unwrap_or(0);
        session.record_fault(
            dispatch,
            nt_hosted_runtime::HostedIrqFaultKind::WorkerFault,
            status as u32 as u64,
            0,
            connection.route.tokens.service_routine_token,
            [connection.interrupt_object, connection.grant.grant_id, 0, 0],
        );
    }
    let leaked_service_lock = !session.service_locks.is_empty();
    let service_release = session.release_service_locks();
    if leaked_service_lock {
        session.record_fault(
            dispatch,
            nt_hosted_runtime::HostedIrqFaultKind::ServiceFault,
            0x4c4b_4c4b,
            0,
            0,
            [0; 4],
        );
    }
    let finish = arena
        .control
        .root_finish_transaction(lane.identity, transaction)
        .map_err(arena_status);
    let outer_release = hosted_irq_actual_locks_mut()
        .release(session.outer_lock)
        .map_err(hosted_irq_actual_lock_status);
    let result = result?;
    service_release?;
    finish?;
    outer_release?;
    if leaked_service_lock || dispatch_faulted {
        return Err(nt_status::NtStatus::UNSUCCESSFUL);
    }
    Ok(HostedIrqRootDispatchOutcome::Completed(result))
}
