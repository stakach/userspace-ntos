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

struct HostedIrqActiveLane {
    lane: HostedIrqLaneView,
    transaction: nt_hosted_runtime::HostedIrqTransaction,
    owns_transaction: bool,
    parked_services: Vec<nt_hosted_runtime::HostedIrqArenaToken>,
}

#[derive(Clone, Copy)]
struct HostedIrqPreparedTarget {
    lane_index: usize,
    depth: u8,
    owns_transaction: bool,
}

struct HostedIrqRootSession {
    lanes: Vec<HostedIrqActiveLane>,
    call_frames: Vec<nt_hosted_runtime::HostedIrqCallFrame>,
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
    lane_view_for_domain(
        connection.binding.projection_instance,
        connection.binding.projection_domain,
        connection.lane_generation,
    )
}

unsafe fn lane_view_for_domain(
    projection_instance: usize,
    domain: HostedDomainIdentity,
    lane_generation: u64,
) -> Result<HostedIrqLaneView, nt_status::NtStatus> {
    let lane = hosted_irq_lanes()
        .and_then(|lanes| {
            lanes.iter().find(|lane| {
                lane.projection_instance == projection_instance
                    && lane.domain == domain
                    && lane.identity.lane_generation == lane_generation
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

unsafe fn lane_has_connection_grant(
    lane: HostedIrqLaneView,
    grant: nt_hosted_runtime::HostedIrqGrantIdentity,
) -> bool {
    hosted_irq_connections().is_some_and(|connections| {
        connections.iter().copied().any(|connection| {
            hosted_irq_connection_active(connection)
                && connection.grant == grant
                && connection.binding.projection_domain.domain_id.raw()
                    == lane.identity.domain_id
                && connection.binding.projection_domain.cookie == lane.identity.domain_cookie
                && connection.lane_generation == lane.identity.lane_generation
        })
    })
}

unsafe fn provider_import_authority(
    source_lane: HostedIrqLaneView,
    command: nt_hosted_runtime::HostedIrqServiceCommand,
) -> Result<
    (
        HostedProviderDomainDependency,
        HostedIrqLaneView,
        HostedProviderDependencyDispatchLease,
    ),
    nt_status::NtStatus,
> {
    let dependency = hosted_provider_domain_dependencies()
        .and_then(|dependencies| {
            dependencies.iter().copied().find(|dependency| {
                hosted_provider_domain_dependency_is_live(*dependency)
                    && dependency.dependent_domain.domain_id.raw()
                        == source_lane.identity.domain_id
                    && dependency.dependent_domain.cookie == source_lane.identity.domain_cookie
                    && dependency.dependent_lane_generation
                        == source_lane.identity.lane_generation
                    && dependency.provider_domain.domain_id.raw() == command.target_domain_id
                    && dependency.provider_domain.cookie == command.target_domain_cookie
                    && dependency.provider_publication_cookie == command.authority_cookie
            })
        })
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if command.grant != dependency.dependent_grant
        && !lane_has_connection_grant(source_lane, command.grant)
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let (_, singleton) = find_hosted_provider_singleton_by_cookie(command.authority_cookie)
        .ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    if singleton.instance != dependency.provider_instance
        || singleton.owner_domain != dependency.provider_domain
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let policy = loaded_pe_export_rva_marshal_policy(
        singleton.provider.as_str(),
        singleton.exec_va,
        singleton.image_len,
        command.service_id,
    )
    .or_else(|| hosted_provider_internal_rva_marshal_policy(singleton, command.service_id))
    .ok_or(nt_status::NtStatus::NOT_SUPPORTED)?;
    let _ = policy;
    match plan_hosted_provider_import_binding(
        Some(hosted_provider_domain_descriptor(singleton)),
        command.service_id,
    ) {
        Ok(HostedProviderImportBinding::ProviderDomainCall(_)) => {}
        Ok(HostedProviderImportBinding::PrivateDependencyRequired) => {
            return Err(nt_status::NtStatus::DEVICE_NOT_READY)
        }
        Err(_) => return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
    }
    let target_lane = lane_view_for_domain(
        dependency.provider_instance,
        dependency.provider_domain,
        dependency.provider_lane_generation,
    )?;
    let lease = acquire_hosted_provider_dependency_dispatch_lease(
        dependency.provider_instance,
        dependency.dependent_instance,
        dependency.provider_publication_cookie,
    )
    .ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    Ok((dependency, target_lane, lease))
}

unsafe fn provider_callback_authority(
    source_lane: HostedIrqLaneView,
    command: nt_hosted_runtime::HostedIrqServiceCommand,
) -> Result<
    (
        HostedProviderCallbackRecord,
        HostedProviderDomainDependency,
        HostedIrqLaneView,
        HostedProviderDependencyDispatchLease,
    ),
    nt_status::NtStatus,
> {
    let record = hosted_provider_callback_record(command.service_id)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let dependency = hosted_provider_domain_dependency_for_pair(
        record.provider_instance,
        record.dependent_instance,
    )
    .ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    if record.provider_domain.domain_id.raw() != source_lane.identity.domain_id
        || record.provider_domain.cookie != source_lane.identity.domain_cookie
        || dependency.provider_lane_generation != source_lane.identity.lane_generation
        || command.grant != dependency.provider_grant
        || command.target_domain_id != record.dependent_domain.domain_id.raw()
        || command.target_domain_cookie != record.dependent_domain.cookie
        || command.authority_cookie != record.provider_publication_cookie
        || dependency.provider_publication_cookie != record.provider_publication_cookie
    {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let target_lane = lane_view_for_domain(
        dependency.dependent_instance,
        dependency.dependent_domain,
        dependency.dependent_lane_generation,
    )?;
    let lease = acquire_hosted_provider_dependency_dispatch_lease(
        dependency.provider_instance,
        dependency.dependent_instance,
        dependency.provider_publication_cookie,
    )
    .ok_or(nt_status::NtStatus::DEVICE_NOT_READY)?;
    Ok((record, dependency, target_lane, lease))
}

impl HostedIrqRootSession {
    fn lane(&self, lane_index: usize) -> Result<HostedIrqLaneView, nt_status::NtStatus> {
        self.lanes
            .get(lane_index)
            .map(|state| state.lane)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)
    }

    fn push_call_frame(
        &mut self,
        source_lane_index: usize,
        service: nt_hosted_runtime::HostedIrqArenaToken,
        target_lane_index: usize,
        dispatch: nt_hosted_runtime::HostedIrqArenaToken,
    ) -> Result<nt_hosted_runtime::HostedIrqCallFrame, nt_status::NtStatus> {
        let source = self.lane(source_lane_index)?;
        let target = self.lane(target_lane_index)?;
        if self.lanes[source_lane_index].parked_services.last() != Some(&service) {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let frame = nt_hosted_runtime::HostedIrqCallFrame {
            source: source.identity,
            service,
            target: target.identity,
            dispatch,
        };
        nt_hosted_runtime::validate_hosted_irq_call_push(&self.call_frames, frame)
            .map_err(|_| nt_status::NtStatus(STATUS_POSSIBLE_DEADLOCK))?;
        if let Some(parent) = self
            .call_frames
            .iter()
            .rev()
            .find(|candidate| candidate.source == target.identity)
        {
            if self.lanes[target_lane_index].parked_services.last() != Some(&parent.service) {
                return Err(nt_status::NtStatus(STATUS_POSSIBLE_DEADLOCK));
            }
        } else if dispatch.depth != 0 {
            return Err(nt_status::NtStatus(STATUS_POSSIBLE_DEADLOCK));
        }
        self.call_frames
            .try_reserve(1)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        self.call_frames.push(frame);
        Ok(frame)
    }

    fn pop_call_frame(
        &mut self,
        frame: nt_hosted_runtime::HostedIrqCallFrame,
    ) -> Result<(), nt_status::NtStatus> {
        nt_hosted_runtime::validate_hosted_irq_call_pop(&self.call_frames, frame)
            .map_err(|_| nt_status::NtStatus(STATUS_POSSIBLE_DEADLOCK))?;
        self.call_frames.pop();
        Ok(())
    }

    fn active_lane_index(
        &self,
        identity: nt_hosted_runtime::HostedIrqLaneIdentity,
    ) -> Option<usize> {
        self.lanes
            .iter()
            .position(|candidate| candidate.lane.identity == identity)
    }

    unsafe fn prepare_target_lane(
        &mut self,
        target: HostedIrqLaneView,
    ) -> Result<HostedIrqPreparedTarget, nt_status::NtStatus> {
        if let Some(lane_index) = self.active_lane_index(target.identity) {
            let parent = self
                .call_frames
                .iter()
                .rev()
                .find(|candidate| candidate.source == target.identity)
                .ok_or(nt_status::NtStatus(STATUS_POSSIBLE_DEADLOCK))?;
            if self.lanes[lane_index].parked_services.last() != Some(&parent.service) {
                return Err(nt_status::NtStatus(STATUS_POSSIBLE_DEADLOCK));
            }
            let depth = parent
                .service
                .depth
                .checked_add(1)
                .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
            if depth as usize >= nt_hosted_runtime::HOSTED_IRQ_ARENA_DEPTH {
                return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
            }
            return Ok(HostedIrqPreparedTarget {
                lane_index,
                depth,
                owns_transaction: false,
            });
        }

        self.lanes
            .try_reserve(1)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        let class = self
            .lanes
            .first()
            .map(|lane| lane.transaction.class)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let transaction = target
            .arena()
            .control
            .root_begin_transaction(target.identity, class)
            .map_err(arena_status)?;
        let lane_index = self.lanes.len();
        self.lanes.push(HostedIrqActiveLane {
            lane: target,
            transaction,
            owns_transaction: true,
            parked_services: Vec::new(),
        });
        Ok(HostedIrqPreparedTarget {
            lane_index,
            depth: 0,
            owns_transaction: true,
        })
    }

    unsafe fn target_marshal_window(
        &self,
        target: HostedIrqPreparedTarget,
    ) -> Result<HostedProviderMarshalWindowSource, nt_status::NtStatus> {
        let lane = self.lane(target.lane_index)?;
        let transaction = self.lanes[target.lane_index].transaction;
        let offset = nt_hosted_runtime::HostedIrqArenaLayout::dispatch_marshal_offset(
            target.depth as usize,
        )
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let exec_base = lane.arena().dispatch[target.depth as usize]
            .root_idle_marshal_ptr(&lane.arena().control, lane.identity, transaction)
            .map_err(arena_status)? as u64;
        if lane.arena_va.checked_add(offset) != Some(exec_base) {
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let component_base = FSD_WORKER_VADDR
            .checked_add(FSD_IRQ_LANE_ARENA_OFFSET)
            .and_then(|base| base.checked_add(offset))
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        let window = HostedProviderMarshalWindow::new(
            component_base,
            exec_base,
            nt_hosted_runtime::HOSTED_IRQ_ARENA_MARSHAL_BYTES as u64,
        )
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        Ok(HostedProviderMarshalWindowSource::exact(window))
    }

    unsafe fn finish_target_lane(
        &mut self,
        target: HostedIrqPreparedTarget,
    ) -> Result<(), nt_status::NtStatus> {
        if !target.owns_transaction {
            return Ok(());
        }
        if target.lane_index + 1 != self.lanes.len()
            || !self.lanes[target.lane_index].parked_services.is_empty()
            || self.call_frames.iter().any(|frame| {
                frame.source == self.lanes[target.lane_index].lane.identity
                    || frame.target == self.lanes[target.lane_index].lane.identity
            })
        {
            return Err(nt_status::NtStatus(STATUS_POSSIBLE_DEADLOCK));
        }
        let lane = &self.lanes[target.lane_index];
        lane.lane
            .arena()
            .control
            .root_finish_transaction(lane.lane.identity, lane.transaction)
            .map_err(arena_status)?;
        self.lanes.pop();
        Ok(())
    }

    unsafe fn record_fault(
        &self,
        lane_index: usize,
        token: nt_hosted_runtime::HostedIrqArenaToken,
        kind: nt_hosted_runtime::HostedIrqFaultKind,
        code: u64,
        instruction_pointer: u64,
        address: u64,
        parameters: [u64; 4],
    ) {
        let Ok(lane) = self.lane(lane_index) else {
            return;
        };
        let _ = lane.arena().control.record_first_fault(
            lane.identity,
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
            .find(|candidate| candidate.identity == lane.identity)
        {
            lane.state = HostedIrqLaneState::Quarantined;
        }
    }

    unsafe fn exchange(
        &self,
        lane_index: usize,
        reply: nt_hosted_runtime::HostedIrqArenaToken,
    ) -> Result<crate::spawn_hosts::HostedIrqExchangeMessage, nt_status::NtStatus> {
        let lane = self.lane(lane_index)?;
        let result = crate::spawn_hosts::component_hosted_irq_exchange(
            &lane.channel,
            crate::spawn_hosts::HostedIrqExchangeAction::ReplyToken {
                identity: lane.identity,
                token: reply,
            },
            lane.badge,
            FSD_IRQ_LANE_COMPLETION_LABEL,
        );
        if result.reply_cap != lane.channel.reply_cap
            || result.message == crate::spawn_hosts::HostedIrqExchangeMessage::Wall
        {
            self.record_fault(
                lane_index,
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
        lane_index: usize,
        command: nt_hosted_runtime::HostedIrqServiceCommand,
    ) -> nt_hosted_runtime::HostedIrqArenaResult {
        let Ok(lane) = self.lane(lane_index) else {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        };
        if command.target_domain_id != lane.identity.domain_id
            || command.target_domain_cookie != lane.identity.domain_cookie
        {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        }
        let connection = match connection_for_service(lane, command) {
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
                let Some(lease) = self.service_locks.last().copied().filter(|lease| {
                    lease.identity == connection.actual_lock
                        && lease.owner == connection.rundown.identity()
                        && lease.sequence == sequence
                }) else {
                    return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
                };
                match hosted_irq_actual_locks_mut().release(lease) {
                    Ok(()) => {
                        self.service_locks.pop();
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
        lane_index: usize,
        command: nt_hosted_runtime::HostedIrqServiceCommand,
    ) -> nt_hosted_runtime::HostedIrqArenaResult {
        let Ok(lane) = self.lane(lane_index) else {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        };
        if command.target_domain_id != lane.identity.domain_id
            || command.target_domain_cookie != lane.identity.domain_cookie
            || command.argument_count != 4
            || command.arguments[0] == 0
        {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        }
        let connection = match connection_for_service(lane, command) {
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
        lane_index: usize,
        command: nt_hosted_runtime::HostedIrqServiceCommand,
    ) -> nt_hosted_runtime::HostedIrqArenaResult {
        let Ok(lane) = self.lane(lane_index) else {
            return fatal_service_result(STATUS_INVALID_DEVICE_REQUEST);
        };
        match command.kind {
            nt_hosted_runtime::HostedIrqServiceKind::AcquireActualLock
            | nt_hosted_runtime::HostedIrqServiceKind::ReleaseActualLock => {
                self.actual_lock_service(lane_index, command)
            }
            nt_hosted_runtime::HostedIrqServiceKind::QueueDpc => {
                self.queue_dpc_service(lane_index, command)
            }
            nt_hosted_runtime::HostedIrqServiceKind::ProviderImport => {
                match provider_import_authority(lane, command) {
                    Ok(_authority) => service_result(STATUS_NOT_SUPPORTED, None),
                    Err(status) => fatal_service_result(status.raw()),
                }
            }
            nt_hosted_runtime::HostedIrqServiceKind::ProviderCallbackRequest => {
                match provider_callback_authority(lane, command) {
                    Ok(_authority) => service_result(STATUS_NOT_SUPPORTED, None),
                    Err(status) => fatal_service_result(status.raw()),
                }
            }
        }
    }

    unsafe fn service_and_resume(
        &mut self,
        lane_index: usize,
        parent: nt_hosted_runtime::HostedIrqArenaToken,
        service: nt_hosted_runtime::HostedIrqArenaToken,
    ) -> Result<crate::spawn_hosts::HostedIrqExchangeMessage, nt_status::NtStatus> {
        let lane = self.lane(lane_index)?;
        let transaction = self
            .lanes
            .get(lane_index)
            .map(|state| state.transaction)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        if service.direction != nt_hosted_runtime::HostedIrqLaneDirection::Service
            || service.transaction != transaction.transaction
            || service.depth != parent.depth
        {
            self.record_fault(
                lane_index,
                service,
                nt_hosted_runtime::HostedIrqFaultKind::Protocol,
                0x5352_5644,
                0,
                0,
                parent.transport_words(),
            );
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        let arena = lane.arena();
        let command = arena.service[service.depth as usize]
            .root_begin(&arena.control, lane.identity, service)
            .map_err(arena_status)?;
        self.lanes
            .get_mut(lane_index)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?
            .parked_services
            .try_reserve(1)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        self.lanes[lane_index].parked_services.push(service);
        let result = self.execute_service(lane_index, command);
        let parked = self.lanes[lane_index].parked_services.pop();
        if parked != Some(service) {
            self.record_fault(
                lane_index,
                service,
                nt_hosted_runtime::HostedIrqFaultKind::Protocol,
                0x5352_4c46,
                0,
                0,
                parent.transport_words(),
            );
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
        if result.faulted {
            self.record_fault(
                lane_index,
                service,
                nt_hosted_runtime::HostedIrqFaultKind::ServiceFault,
                result.status as u32 as u64,
                0,
                command.service_id,
                command.arguments[..4].try_into().unwrap_or([0; 4]),
            );
        }
        arena.service[service.depth as usize]
            .root_complete(&arena.control, lane.identity, service, result)
            .map_err(arena_status)?;
        self.exchange(lane_index, service)
    }

    unsafe fn drive_dispatch(
        &mut self,
        lane_index: usize,
        dispatch: nt_hosted_runtime::HostedIrqArenaToken,
    ) -> Result<nt_hosted_runtime::HostedIrqArenaResult, nt_status::NtStatus> {
        let lane = self.lane(lane_index)?;
        let mut message = self.exchange(lane_index, dispatch)?;
        loop {
            let token = match message {
                crate::spawn_hosts::HostedIrqExchangeMessage::Token(token) => token,
                crate::spawn_hosts::HostedIrqExchangeMessage::Ready
                | crate::spawn_hosts::HostedIrqExchangeMessage::Wall => {
                    self.record_fault(
                        lane_index,
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
                let arena = lane.arena();
                let result = arena.dispatch[dispatch.depth as usize]
                    .root_completion(lane.identity, dispatch)
                    .map_err(arena_status)?;
                arena.dispatch[dispatch.depth as usize]
                    .root_acknowledge(&arena.control, lane.identity, dispatch)
                    .map_err(arena_status)?;
                return Ok(result);
            }
            if token.direction != nt_hosted_runtime::HostedIrqLaneDirection::Service {
                self.record_fault(
                    lane_index,
                    token,
                    nt_hosted_runtime::HostedIrqFaultKind::Protocol,
                    0x4453_544b,
                    0,
                    0,
                    dispatch.transport_words(),
                );
                return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
            }
            message = self.service_and_resume(lane_index, dispatch, token)?;
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
    let mut lanes = Vec::new();
    lanes
        .try_reserve_exact(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
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
    lanes.push(HostedIrqActiveLane {
        lane,
        transaction,
        owns_transaction: false,
        parked_services: Vec::new(),
    });
    let mut session = HostedIrqRootSession {
        lanes,
        call_frames: Vec::new(),
        outer_lock,
        service_locks: Vec::new(),
    };
    let result = session.drive_dispatch(0, dispatch);
    let dispatch_faulted = result
        .as_ref()
        .is_ok_and(|result| result.faulted || result.status != STATUS_SUCCESS);
    if dispatch_faulted {
        let status = result.as_ref().map(|result| result.status).unwrap_or(0);
        session.record_fault(
            0,
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
            0,
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
