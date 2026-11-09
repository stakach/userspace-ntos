//! Bounded IRQ/DPC scheduling between receive slices of a retained component invocation.

use super::*;

static DEPTH: AtomicU64 = AtomicU64::new(0);
static YIELDS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum StartupKind { Source, Class }

fn trace_worker_startup_pump(
    kind: StartupKind,
    ordinal: Option<u64>,
    stage: u64,
    result: Option<&crate::spawn_hosts::PumpResult>,
) {
    let Some(ordinal) = ordinal else { return };
    static SOURCE_COUNT: AtomicU64 = AtomicU64::new(0);
    static CLASS_COUNT: AtomicU64 = AtomicU64::new(0);
    let count = match kind { StartupKind::Source => &SOURCE_COUNT, StartupKind::Class => &CLASS_COUNT };
    if count.fetch_add(1, Ordering::Relaxed) >= 48 { return; }
    let prefix: &[u8] = match kind {
        StartupKind::Source => b"[source-startup-pump] ordinal/stage/completed/status/flags/wall-label/receipt=",
        StartupKind::Class => b"[class-startup-pump] ordinal/stage/completed/status/flags/wall-label/receipt=",
    };
    print_str(prefix);
    print_u64(ordinal); print_str(b"/");
    print_u64(stage); print_str(b"/");
    if let Some(result) = result {
        let flags = u32::from(result.scheduler_yielded)
            | (u32::from(result.receive_yield().is_some()) << 1)
            | (u32::from(result.service_wait_yield.is_some()) << 2)
            | (u32::from(result.callback_suspended) << 3)
            | (u32::from(result.provider_wait_suspended) << 4)
            | (u32::from(result.lpc_wait_suspended) << 5);
        print_u64(u64::from(result.completed)); print_str(b"/");
        print_hex(result.status as u32); print_str(b"/");
        print_hex(flags); print_str(b"/");
        print_u64(result.wall_label); print_str(b"/");
        print_u64(u64::from(result.startup_stack_receipt.is_some()));
    } else {
        print_str(b"pending");
    }
    print_str(b"\n");
}

pub(super) fn is_active() -> bool {
    DEPTH.load(Ordering::Acquire) != 0
}

/// The retained physical route owns this TCB cap. A failed request means the worker is no
/// longer runnable; the subsequent exact receive remains responsible for any completion.
fn handoff_exact_component_once(tcb: u64) -> bool {
    sel4_rt::tcb_yield_to(tcb) == 0
}

/// Keeps PASSIVE work and projection retirement outside the entire component invocation.
/// IRQ isolation comes from the dedicated broker arenas, not a copy of an active request bank.
pub(crate) struct ComponentSchedulerScope {
    depth: u64,
}

impl ComponentSchedulerScope {
    pub(crate) fn enter() -> Self {
        Self {
            depth: DEPTH.fetch_add(1, Ordering::AcqRel) + 1,
        }
    }

    /// Caller has retained the exact yielded invocation before any scheduler effect. A kernel
    /// caller must also have claimed its canonical receive attempt and released coordinator borrows.
    pub(crate) unsafe fn service_irq_yield(
        &self, shared_va: u64,
    ) -> scsi_srb_scheduler_service::SchedulerServiceSample {
        use scsi_srb_scheduler_service::{SchedulerServiceClock, SchedulerServicePhase};
        let mut clock = SchedulerServiceClock::new(crate::disk_census_ticks());
        let _message = crate::ipc_message::SavedMessageBuffer::capture();
        let _durable = crate::allocator::enter_durable();
        let mut parent = crate::spawn_hosts::shared_ingress::owner::runtime::nested::park_current()
            .expect("IRQ scheduling must preserve its exact parent invocation");
        let yield_number = YIELDS.fetch_add(1, Ordering::Relaxed) + 1;
        clock.transition(SchedulerServicePhase::TimerWork, crate::disk_census_ticks());
        crate::dispatcher_bootstrap::request_receive_checkpoint();
        let timer_work = crate::dispatcher_bootstrap::service_hosted_timer_work();
        clock.transition(SchedulerServicePhase::IrqDrain, crate::disk_census_ticks());
        let irq_lines = drain_pending_hosted_irqs_snapshot();
        crate::arm_hosted_irq_retry_before_nested_receive();
        clock.transition(SchedulerServicePhase::DpcDrain, crate::disk_census_ticks());
        let dpcs = drain_hosted_driver_dpcs();
        clock.transition(SchedulerServicePhase::ReceivePrepare, crate::disk_census_ticks());
        // Nested exchanges may reconcile earlier requests before these effects publish new demand.
        crate::dispatcher_bootstrap::request_receive_checkpoint();
        crate::dispatcher_bootstrap::prepare_receive()
            .expect("bootstrap timer admission failed before retained receive");
        if yield_number <= 16 {
            // Report canonical demand after the actual receive checkpoint.
            let deadline = crate::dispatcher_bootstrap::next_deadline(crate::nt_time_snapshot());
            print_str(b"[component-scheduler] receive continuation bank=0x");
            print_hex64(shared_va);
            print_str(b" yield=");
            print_u64(yield_number);
            print_str(b" timer-work=");
            print_u64(timer_work);
            print_str(b" irq-lines=");
            print_u64(irq_lines);
            print_str(b" dpcs=");
            print_u64(dpcs);
            match deadline {
                Ok(Some((target, source))) => {
                    print_str(b" bootstrap-deadline=");
                    print_u64(target);
                    print_str(b" source=");
                    print_u64(source);
                }
                Ok(None) => print_str(b" bootstrap-deadline=none"),
                Err(status) => {
                    print_str(b" bootstrap-deadline-status=0x");
                    print_hex64(status as u64);
                }
            }
            print_str(b"\n");
        }
        clock.transition(SchedulerServicePhase::ParentRestore, crate::disk_census_ticks());
        crate::spawn_hosts::shared_ingress::owner::runtime::nested::restore(&mut parent)
            .expect("IRQ scheduling must restore its retained parent invocation");
        clock.finish(crate::disk_census_ticks(), timer_work, irq_lines, dpcs)
    }
}

impl Drop for ComponentSchedulerScope {
    fn drop(&mut self) {
        let previous = DEPTH.fetch_sub(1, Ordering::AcqRel);
        assert_eq!(
            previous, self.depth,
            "component scheduler scope order violated"
        );
    }
}

/// A child step is already consumed when this row exists. It preserves every stage that may
/// refuse before the original receive, including the one-use inner restore receipt.
#[must_use = "retain this exact File pump continuation until receive or quarantine"]
pub(super) struct PendingChildWorkRestore {
    mode: PendingReceiveMode,
    result: crate::spawn_hosts::PumpResult,
    channel: crate::spawn_hosts::PumpChannel,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    caller: Option<nt_process::native_handle::NativeHandleCaller>,
    inner_ticket: Option<crate::spawn_hosts::shared_ingress::owner::runtime::nested::NestedRestoreTicket>,
    inner_restored: bool,
    inner_receipt: Option<crate::spawn_hosts::shared_ingress::owner::runtime::nested::ChildWorkParentRestored>,
    parent: Option<crate::spawn_hosts::shared_ingress::owner::runtime::nested::ParkedParentHandle>,
    outer_restored: bool,
    retryable: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingReceiveMode {
    ChildWork,
    NestedRestore,
    /// The child receive has already run; only its retained scheduler receive may resume.
    SchedulerYield,
}

impl PendingChildWorkRestore {
    pub(super) const fn retryable(&self) -> bool { self.retryable }
}

/// A component result remains owned by its physical parent on restore refusal. The retained
/// ticket is a selector only; `runtime::nested` continues to own the stopped TCB and Reply.
pub(super) enum HostedPumpRestore {
    Restored(crate::spawn_hosts::PumpResult),
    Unattributed(crate::spawn_hosts::PumpResult),
    /// The outer caller owns the stopped pump result and move-only outer physical parent while
    /// root executes one retained child. Neither parent is restored on this stack.
    ChildWorkReady {
        result: crate::spawn_hosts::PumpResult,
        parent: Option<crate::spawn_hosts::shared_ingress::owner::runtime::nested::ParkedParentHandle>,
        /// Admission refreshed the canonical Reply on this local channel. The caller's input
        /// channel is stale and cannot authorize a receive continuation.
        channel: crate::spawn_hosts::PumpChannel,
        dispatch: nt_component_suspension::LaneDispatchIdentity,
        caller: Option<nt_process::native_handle::NativeHandleCaller>,
    },
    /// A failed SEH settlement fences child entry and keeps both physical parents retained.
    ChildWorkQuarantined {
        result: crate::spawn_hosts::PumpResult,
        parent: Option<crate::spawn_hosts::shared_ingress::owner::runtime::nested::ParkedParentHandle>,
        channel: crate::spawn_hosts::PumpChannel,
        caller: Option<nt_process::native_handle::NativeHandleCaller>,
    },
    ChildWorkPending(PendingChildWorkRestore),
    Retained {
        result: crate::spawn_hosts::PumpResult,
        key: nt_component_suspension::NestedRestoreResultKey,
        ticket: crate::spawn_hosts::shared_ingress::owner::runtime::nested::NestedRestoreTicket,
        retryable: bool,
    },
}

/// Read-only witness of the physical source held by a typed child-work continuation.
/// The scheduler authenticates the live route, dispatch and Reply again before native receive.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ChildWorkPhysicalIdentity {
    pub(super) route: nt_component_suspension::peer_registry::PeerRoute,
    pub(super) dispatch: nt_component_suspension::LaneDispatchIdentity,
    pub(super) reply_cap: u64,
    pub(super) tcb: u64,
    pub(super) pml4: u64,
    pub(super) shared_va: u64,
}

impl HostedPumpRestore {
    pub(super) fn child_work_identity(&self) -> Option<ChildWorkPhysicalIdentity> {
        let (channel, dispatch, reply_cap) = match self {
            Self::ChildWorkReady { result, channel, dispatch, .. } =>
                (channel, *dispatch, result.reply_cap),
            Self::ChildWorkPending(pending) =>
                (&pending.channel, pending.dispatch, pending.result.reply_cap),
            _ => return None,
        };
        if reply_cap == 0 || channel.reply_cap != reply_cap { return None; }
        Some(ChildWorkPhysicalIdentity {
            route: channel.ingress_route?, dispatch, reply_cap,
            tcb: channel.tcb, pml4: channel.pml4, shared_va: channel.shared_va,
        })
    }

    fn legacy(self) -> crate::spawn_hosts::PumpResult {
        match self {
            Self::Restored(result) => result,
            Self::Retained { .. } | Self::Unattributed(_)
            | Self::ChildWorkReady { .. } | Self::ChildWorkQuarantined { .. }
            | Self::ChildWorkPending(_) =>
                panic!("restore nested hosted parent"),
        }
    }
}

pub(super) unsafe fn hosted_component_pump(
    channel: &crate::spawn_hosts::PumpChannel,
) -> crate::spawn_hosts::PumpResult {
    hosted_component_pump_inner(channel, None, None).legacy()
}

pub(super) unsafe fn hosted_component_pump_with_caller(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> crate::spawn_hosts::PumpResult {
    hosted_component_pump_inner(channel, Some(caller), None).legacy()
}

pub(super) unsafe fn hosted_component_pump_with_caller_retained(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> HostedPumpRestore {
    hosted_component_pump_inner(channel, Some(caller), None)
}

pub(super) unsafe fn hosted_component_pump_observed(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: Option<nt_process::native_handle::NativeHandleCaller>,
    owner: &scsi_srb_pump_owner::ScsiSrbPumpOwnerClaim<'_, SCSI_SRB_PUMP_OWNER_SLOTS>,
) -> crate::spawn_hosts::PumpResult {
    hosted_component_pump_inner(channel, caller, Some(owner)).legacy()
}

/// Preserve the observed SCSI timeline while returning a typed suspended child-work result.
/// The File owner must retain the move-only parent and post-admission channel before any child
/// effect; the legacy observer remains for callers that cannot transfer this continuation.
pub(super) unsafe fn hosted_component_pump_observed_retained(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: Option<nt_process::native_handle::NativeHandleCaller>,
    owner: &scsi_srb_pump_owner::ScsiSrbPumpOwnerClaim<'_, SCSI_SRB_PUMP_OWNER_SLOTS>,
) -> HostedPumpRestore {
    hosted_component_pump_inner(channel, caller, Some(owner))
}

/// Only a caller that retains its native invocation and exact physical parent may request an
/// intentional child handoff. The copied channel carries that authority through shared receive.
unsafe fn owned_child_work_channel(
    original: &crate::spawn_hosts::PumpChannel,
) -> Option<crate::spawn_hosts::PumpChannel> {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let route = runtime::channel_route(original).ok()??;
    let source = runtime::physical_source(route).ok()?;
    if !matches!(source.domain, runtime::PhysicalDomain::Hosted(_))
        || !matches!(source.kind,
            runtime::PhysicalSourceKind::Primary
            | runtime::PhysicalSourceKind::DispatchWorker { .. })
        || source.tcb != original.tcb || source.pml4 != original.pml4
    {
        return None;
    }
    let reply = runtime::current_reply(route).ok()?;
    if reply == 0 { return None; }
    let mut channel = *original;
    channel.reply_cap = reply;
    channel.child_work_capable = true;
    Some(channel)
}

pub(super) unsafe fn hosted_component_pump_with_caller_child_work(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> HostedPumpRestore {
    crate::driver_launch::trace_port_connect_handoff_probe(10, channel, 0);
    let Some(channel) = owned_child_work_channel(channel) else {
        crate::driver_launch::trace_port_connect_handoff_probe(11, channel, 0);
        return HostedPumpRestore::Unattributed(crate::spawn_hosts::PumpResult::refused(
            nt_process::STATUS_INVALID_HANDLE as i32, channel.reply_cap));
    };
    crate::driver_launch::trace_port_connect_handoff_probe(12, &channel, 1);
    hosted_component_pump_inner(&channel, Some(caller), None)
}

pub(super) unsafe fn hosted_component_pump_observed_child_work(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: Option<nt_process::native_handle::NativeHandleCaller>,
    owner: &scsi_srb_pump_owner::ScsiSrbPumpOwnerClaim<'_, SCSI_SRB_PUMP_OWNER_SLOTS>,
) -> HostedPumpRestore {
    if caller.is_none() {
        return HostedPumpRestore::Unattributed(crate::spawn_hosts::PumpResult::refused(
            nt_process::STATUS_INVALID_HANDLE as i32, channel.reply_cap));
    }
    let Some(channel) = owned_child_work_channel(channel) else {
        return HostedPumpRestore::Unattributed(crate::spawn_hosts::PumpResult::refused(
            nt_process::STATUS_INVALID_HANDLE as i32, channel.reply_cap));
    };
    hosted_component_pump_inner(&channel, caller, Some(owner))
}

/// AddDevice has a move-only rollback/registry transaction and a retained PnP batch cursor.
/// Its caller must store every typed outcome before the root runs the selected child.
pub(super) unsafe fn hosted_component_pump_with_caller_add_device_child_work(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> HostedPumpRestore {
    let Some(channel) = owned_child_work_channel(channel) else {
        return HostedPumpRestore::Unattributed(crate::spawn_hosts::PumpResult::refused(
            nt_process::STATUS_INVALID_HANDLE as i32, channel.reply_cap));
    };
    hosted_component_pump_inner(&channel, Some(caller), None)
}

unsafe fn hosted_component_pump_inner(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: Option<nt_process::native_handle::NativeHandleCaller>,
    observed_owner: Option<&scsi_srb_pump_owner::ScsiSrbPumpOwnerClaim<'_, SCSI_SRB_PUMP_OWNER_SLOTS>>,
) -> HostedPumpRestore {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let mut channel = *channel;
    let mut timeline = observed_owner.map(|owner|
        scsi_srb_pump_owner::ScsiSrbPumpTimeline::new(owner, crate::disk_census_ticks()));
    let route = runtime::channel_route(&channel).expect("physical hosted ingress identity");
    let mut parent = if channel.initial == crate::spawn_hosts::InitialAction::ReplyRequest {
        crate::driver_launch::trace_port_connect_handoff_probe(20, &channel, 0);
        let parent = runtime::nested::park_current().expect("retain nested hosted parent");
        crate::driver_launch::trace_port_connect_handoff_probe(21, &channel, u64::from(parent.is_some()));
        let route = route.expect("hosted dispatch requires enrolled source");
        crate::driver_launch::trace_port_connect_handoff_probe(22, &channel, route.endpoint());
        runtime::admit(route).expect("admit exact hosted dispatch Call");
        crate::driver_launch::trace_port_connect_handoff_probe(23, &channel, route.endpoint());
        channel.reply_cap = runtime::current_reply(route).expect("admitted canonical Reply");
        crate::driver_launch::trace_port_connect_handoff_probe(24, &channel, channel.reply_cap);
        crate::driver_launch::trace_port_connect_pump_boundary(
            0, &channel, channel.reply_cap, 0,
        );
        parent
    } else {
        None
    };
    if let Some(timeline) = timeline.as_mut() {
        timeline.transition(scsi_srb_pump_owner::ScsiSrbPumpStage::Setup,
            crate::disk_census_ticks());
    }
    let channel = &mut channel;
    let _registry_caller = caller.map(|caller| {
        crate::provider_registry_caller::Scope::enter(channel, caller)
            .expect("root-issued provider registry caller must match the executing job")
    });
    crate::driver_launch::driver_thread_projection::enter(channel, caller)
        .expect("driver execution requires its exact retained thread projection");
    let scope = ComponentSchedulerScope::enter();
    let startup_ordinal =
        crate::driver_launch::hosted_source_completion_lane::startup_expected(channel)
            .map(|words| words[0]);
    let class_startup_ordinal =
        crate::driver_launch::hosted_class_irp_lane::startup_expected(channel)
            .map(|words| words[0]);
    trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 0, None);
    trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 0, None);
    if let Some(timeline) = timeline.as_mut() {
        timeline.transition(scsi_srb_pump_owner::ScsiSrbPumpStage::ProviderPump,
            crate::disk_census_ticks());
    }
    crate::driver_launch::trace_port_connect_handoff_probe(25, channel, channel.reply_cap);
    let mut result = crate::spawn_hosts::component_pump(channel);
    crate::driver_launch::trace_port_connect_handoff_probe(26, channel, result.reply_cap);
    let result_flags = u64::from(result.completed)
        | (u64::from(result.scheduler_yielded) << 1)
        | (u64::from(matches!(result.nested_child_work,
            Some(crate::spawn_hosts::NestedChildWorkState::Ready(_)))) << 2)
        | (u64::from(matches!(result.nested_child_work,
            Some(crate::spawn_hosts::NestedChildWorkState::Quarantined(_)))) << 3)
        | (u64::from(result.nested_restore_yield.is_some()) << 4)
        | (u64::from(result.nested_restore_quarantined.is_some()) << 5)
        | (u64::from(result.wall_label != 0) << 6)
        | (u64::from(result.provider_wait_suspended) << 7)
        | (u64::from(result.lpc_wait_suspended) << 8);
    crate::driver_launch::trace_port_connect_handoff_probe(27, channel, result_flags);
    trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 1, Some(&result));
    trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 1, Some(&result));
    while result.scheduler_yielded {
        if let Some(timeline) = timeline.as_mut() {
            timeline.transition(scsi_srb_pump_owner::ScsiSrbPumpStage::SchedulerService,
                crate::disk_census_ticks());
        }
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 2, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 2, Some(&result));
        let service_sample = scope.service_irq_yield(channel.shared_va);
        if let Some(owner) = observed_owner {
            owner.record_scheduler_service(service_sample);
        }
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 3, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 3, Some(&result));
        if route.is_some() {
            let _ = handoff_exact_component_once(channel.tcb);
        }
        if let Some(route) = route {
            channel.reply_cap = runtime::current_reply(route).expect("retained canonical Reply");
        }
        if let Some(timeline) = timeline.as_mut() {
            timeline.transition(scsi_srb_pump_owner::ScsiSrbPumpStage::ReceiveContinuation,
                crate::disk_census_ticks());
        }
        result = crate::spawn_hosts::component_pump_continue_receive_after_scheduler_service(
            channel, &result)
            .expect("hosted IRQ yield must retain its exact receive continuation");
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 4, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 4, Some(&result));
    }
    match result.nested_child_work {
        Some(crate::spawn_hosts::NestedChildWorkState::Ready(yielded)) => {
            let dispatch = match route.and_then(|route| runtime::dispatch(route).ok()) {
                Some(dispatch) => dispatch,
                None => {
                    result.nested_child_work = Some(
                        crate::spawn_hosts::NestedChildWorkState::Quarantined(yielded));
                    fence_nested_child_parent(yielded.parent);
                    return HostedPumpRestore::ChildWorkQuarantined {
                        result, parent, channel: *channel, caller,
                    };
                }
            };
            let canonical_reply = match route.and_then(|route| runtime::current_reply(route).ok()) {
                Some(reply) if reply != 0 && reply == result.reply_cap => reply,
                _ => {
                    // The component may adopt a new shared Call while receiving. An unmatched
                    // snapshot cannot authorize the resumed receive or another child entry.
                    result.nested_child_work = Some(
                        crate::spawn_hosts::NestedChildWorkState::Quarantined(yielded));
                    fence_nested_child_parent(yielded.parent);
                    return HostedPumpRestore::ChildWorkQuarantined {
                        result, parent, channel: *channel, caller,
                    };
                }
            };
            channel.reply_cap = canonical_reply;
            crate::driver_launch::trace_port_connect_handoff_probe(50, channel, canonical_reply);
            return HostedPumpRestore::ChildWorkReady {
                result, parent, channel: *channel, dispatch, caller,
            };
        }
        Some(crate::spawn_hosts::NestedChildWorkState::Quarantined(yielded)) => {
            fence_nested_child_parent(yielded.parent);
            crate::driver_launch::trace_port_connect_handoff_probe(51, channel, result.reply_cap);
            return HostedPumpRestore::ChildWorkQuarantined { result, parent, channel: *channel, caller };
        }
        None => {}
    }
    if channel.child_work_capable
        && (result.nested_restore_yield.is_some() || result.nested_restore_quarantined.is_some())
    {
        let Some(route) = route else {
            return HostedPumpRestore::ChildWorkQuarantined {
                result, parent, channel: *channel, caller,
            };
        };
        let Ok(dispatch) = runtime::dispatch(route) else {
            return HostedPumpRestore::ChildWorkQuarantined {
                result, parent, channel: *channel, caller,
            };
        };
        let exact_reply = runtime::current_reply(route).ok() == Some(result.reply_cap);
        if exact_reply { channel.reply_cap = result.reply_cap; }
        let inner_ticket = result.nested_restore_yield.or(result.nested_restore_quarantined);
        crate::driver_launch::trace_port_connect_handoff_probe(52, channel, u64::from(exact_reply));
        return HostedPumpRestore::ChildWorkPending(PendingChildWorkRestore {
            mode: PendingReceiveMode::NestedRestore,
            result, channel: *channel, dispatch, caller, inner_ticket,
            inner_restored: false, inner_receipt: None,
            outer_restored: parent.is_none(), parent,
            retryable: exact_reply && result.nested_restore_yield.is_some(),
        });
    }
    if result.completed {
        if let Some(timeline) = timeline.as_mut() {
            timeline.transition(scsi_srb_pump_owner::ScsiSrbPumpStage::Completion,
                crate::disk_census_ticks());
        }
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 5, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 5, Some(&result));
        authenticate_component_completion(channel, &result)
            .expect("authenticate hosted final completion Call");
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 6, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 6, Some(&result));
    }
    trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 7, Some(&result));
    trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 7, Some(&result));
    if let Some(timeline) = timeline.as_mut() {
        timeline.transition(scsi_srb_pump_owner::ScsiSrbPumpStage::Restore,
            crate::disk_census_ticks());
    }
    let restore_key = parent.as_ref().and_then(|handle| runtime::nested::result_key(handle));
    let restore_ticket = parent.as_ref().map(|handle| handle.ticket());
    if runtime::nested::restore(&mut parent).is_err() {
        crate::driver_launch::trace_port_connect_handoff_probe(54, channel, 0);
        // An impossible missing key is still a retained refusal. The physical row remains
        // discoverable in `runtime::nested`; never return an entered result as completed.
        let (Some(key), Some(ticket)) = (restore_key, restore_ticket) else {
            return HostedPumpRestore::Unattributed(result)
        };
        return HostedPumpRestore::Retained {
            result,
            key,
            ticket,
            retryable: runtime::nested::pending_ticket(ticket),
        };
    }
    trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 8, Some(&result));
    trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 8, Some(&result));
    crate::driver_launch::trace_port_connect_handoff_probe(53, channel, result.reply_cap);
    if let Some(timeline) = timeline {
        timeline.finish(crate::disk_census_ticks());
    }
    HostedPumpRestore::Restored(result)
}

/// Shared completion contract for uninterrupted and resumed receive slices. A failed exact
/// authentication leaves the caller responsible for retaining the entered result.
unsafe fn authenticate_component_completion(
    channel: &crate::spawn_hosts::PumpChannel,
    result: &crate::spawn_hosts::PumpResult,
) -> Result<(), crate::spawn_hosts::shared_ingress::owner::runtime::Error> {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let route = runtime::channel_route(channel)?.ok_or(runtime::Error::PhysicalIdentity)?;
    let dispatch = runtime::dispatch(route)?;
    if let Some(words) = result.startup_stack_receipt {
        if !(crate::driver_launch::hosted_source_completion_lane::validate_startup_ready(
            channel, words
        ) || crate::driver_launch::hosted_class_irp_lane::validate_startup_ready(
            channel, words
        ) || crate::driver_launch::hosted_provider_export_lane::validate_startup_ready(
            channel, words
        )) {
            return Err(runtime::Error::PhysicalIdentity);
        }
        let reply = runtime::current_reply(route)?;
        runtime::complete_protocol(route, dispatch, reply, channel.dispatch_label, &words)
    } else {
        runtime::complete(route, dispatch, result.reply_cap, channel.dispatch_label)
    }
}

unsafe fn fence_nested_child_parent(
    ticket: Option<crate::spawn_hosts::shared_ingress::owner::runtime::nested::NestedRestoreTicket>,
) {
    if let Some(ticket) = ticket {
        let _ = crate::spawn_hosts::shared_ingress::owner::runtime::nested::quarantine_child_work_parent(ticket);
    }
}

/// Consume the one child-step certificate exactly once. The File owner retains any returned
/// pending state; a wrong pump state returns both original owners without entering an effect.
fn trace_connect_child_quarantine(reason: u64) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if !crate::driver_launch::hosted_connect_pending_reply_published()
        || COUNT.fetch_add(1, Ordering::Relaxed) >= 8 { return; }
    print_str(b"[connect-child-quarantine] reason=");
    print_u64(reason); print_str(b"\n");
}

pub(super) unsafe fn resume_child_work(
    pump: HostedPumpRestore,
    step: crate::service_sec_image::NestedChildStep,
) -> Result<HostedPumpRestore, (HostedPumpRestore, crate::service_sec_image::NestedChildStep)> {
    let HostedPumpRestore::ChildWorkReady { result, parent, channel, dispatch, caller } = pump else {
        return Err((pump, step));
    };
    if matches!(step.into_decision(), crate::service_sec_image::NestedChildStepDecision::Quarantine) {
        trace_connect_child_quarantine(1);
        if let Some(crate::spawn_hosts::NestedChildWorkState::Ready(yielded)) = result.nested_child_work {
            if let Some(ticket) = yielded.parent {
                let _ = crate::spawn_hosts::shared_ingress::owner::runtime::nested::quarantine_child_work_parent(ticket);
            }
        }
        return Ok(HostedPumpRestore::ChildWorkQuarantined { result, parent, channel, caller });
    }
    let inner_ticket = match result.nested_child_work {
        Some(crate::spawn_hosts::NestedChildWorkState::Ready(yielded)) => yielded.parent,
        _ => {
            trace_connect_child_quarantine(2);
            return Ok(HostedPumpRestore::ChildWorkQuarantined { result, parent, channel, caller });
        }
    };
    Ok(resume_pending_child_work(PendingChildWorkRestore {
        mode: PendingReceiveMode::ChildWork,
        result, channel, dispatch, caller, inner_ticket,
        inner_restored: inner_ticket.is_none(), inner_receipt: None,
        outer_restored: parent.is_none(), parent, retryable: true,
    }))
}

/// Retry only a certified no-effects refusal. The consumed child step is never run again.
pub(super) unsafe fn retry_child_work(pump: HostedPumpRestore) -> HostedPumpRestore {
    match pump {
        HostedPumpRestore::ChildWorkPending(pending) if pending.retryable =>
            resume_pending_child_work(pending),
        other => other,
    }
}

/// Retry only the exact no-effects outer restore ticket. The original pump result remains
/// owned here; no ReplyRequest or receive is replayed on a failed physical restoration.
pub(super) unsafe fn retry_retained_add_device_restore(
    pump: HostedPumpRestore,
) -> HostedPumpRestore {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    match pump {
        HostedPumpRestore::Retained { result, key, ticket, retryable }
            if retryable && key.scope() == ticket.identity() =>
        {
            trace_connect_retained_restore(0);
            if runtime::nested::restore_pending_ticket(ticket).is_ok() {
                trace_connect_retained_restore(1);
                HostedPumpRestore::Restored(result)
            } else {
                trace_connect_retained_restore(2);
                HostedPumpRestore::Retained {
                    result, key, ticket,
                    retryable: runtime::nested::pending_ticket(ticket),
                }
            }
        }
        other => other,
    }
}

fn trace_connect_retained_restore(stage: u64) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if !crate::driver_launch::hosted_connect_pending_reply_published()
        || COUNT.fetch_add(1, Ordering::Relaxed) >= 16 { return; }
    print_str(b"[connect-retained-restore] stage=");
    print_u64(stage);
    print_str(b"\n");
}

// Nonretryable child restore exits. Reasons 1..8 are pre/at receive;
// 9..14 are uncertain results after the receive was entered.
fn trace_connect_child_restore(reason: u64, pending: &PendingChildWorkRestore) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if !crate::driver_launch::hosted_connect_pending_reply_published()
        || COUNT.fetch_add(1, Ordering::Relaxed) >= 32 { return; }
    print_str(b"[connect-child-restore] reason/mode/inner/outer/retry/result-reply/channel-reply=");
    print_u64(reason); print_str(b"/");
    print_u64(u64::from(matches!(pending.mode, PendingReceiveMode::NestedRestore)));
    print_str(b"/"); print_u64(u64::from(pending.inner_restored));
    print_str(b"/"); print_u64(u64::from(pending.outer_restored));
    print_str(b"/"); print_u64(u64::from(pending.retryable));
    print_str(b"/"); print_hex64(pending.result.reply_cap);
    print_str(b"/"); print_hex64(pending.channel.reply_cap);
    print_str(b"\n");
}

fn trace_connect_child_result(stage: u64, result: &crate::spawn_hosts::PumpResult) {
    static COUNT: AtomicU64 = AtomicU64::new(0);
    if !crate::driver_launch::hosted_connect_pending_reply_published()
        || COUNT.fetch_add(1, Ordering::Relaxed) >= 48 { return; }
    print_str(b"[connect-child-result] stage/reply/flags/label=");
    print_u64(stage); print_str(b"/");
    print_u64(result.reply_cap); print_str(b"/");
    let flags = u64::from(result.scheduler_yielded)
        | (u64::from(result.provider_wait_suspended) << 1)
        | (u64::from(result.completed) << 2)
        | (u64::from(result.nested_child_work.is_some()) << 3)
        | (u64::from(result.nested_restore_yield.is_some()) << 4)
        | (u64::from(result.nested_restore_quarantined.is_some()) << 5);
    print_u64(flags); print_str(b"/");
    print_u64(result.wall_label); print_str(b"\n");
}

unsafe fn resume_pending_child_work(mut pending: PendingChildWorkRestore) -> HostedPumpRestore {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    trace_connect_child_restore(20, &pending);
    let route = match runtime::channel_route(&pending.channel) {
        Ok(Some(route)) if runtime::dispatch(route).ok() == Some(pending.dispatch) => route,
        _ => {
            pending.retryable = false;
            trace_connect_child_restore(1, &pending);
            return HostedPumpRestore::ChildWorkPending(pending);
        }
    };
    if !pending.inner_restored {
        let Some(ticket) = pending.inner_ticket else {
            pending.retryable = false;
            trace_connect_child_restore(2, &pending);
            return HostedPumpRestore::ChildWorkPending(pending);
        };
        let restored = match pending.mode {
            PendingReceiveMode::ChildWork =>
                runtime::nested::restore_child_work_parent(ticket).map(Some),
            PendingReceiveMode::NestedRestore =>
                runtime::nested::restore_pending_ticket(ticket).map(|_| None),
            PendingReceiveMode::SchedulerYield => {
                pending.retryable = false;
                trace_connect_child_restore(2, &pending);
                return HostedPumpRestore::ChildWorkPending(pending);
            }
        };
        match restored {
            Ok(receipt) => { pending.inner_receipt = receipt; pending.inner_restored = true; }
            Err(_) => {
                pending.retryable = runtime::nested::pending_ticket(ticket);
                if !pending.retryable { trace_connect_child_restore(3, &pending); }
                return HostedPumpRestore::ChildWorkPending(pending);
            }
        }
    }
    if !pending.outer_restored {
        let ticket = pending.parent.as_ref().map(|parent| parent.ticket());
        let mut parent = pending.parent.take();
        if runtime::nested::restore_or_retain(&mut parent).is_err() {
            pending.parent = parent;
            pending.retryable = ticket.is_some_and(|ticket| unsafe {
                runtime::nested::pending_ticket(ticket)
            });
            if !pending.retryable { trace_connect_child_restore(4, &pending); }
            return HostedPumpRestore::ChildWorkPending(pending);
        }
        pending.outer_restored = true;
    }
    if runtime::current_reply(route).ok() != Some(pending.result.reply_cap) {
        pending.retryable = false;
        trace_connect_child_restore(5, &pending);
        return HostedPumpRestore::ChildWorkPending(pending);
    }
    pending.channel.reply_cap = pending.result.reply_cap;
    if let Some(caller) = pending.caller {
        if crate::provider_registry_caller::resolve_retained(
            route, pending.dispatch, pending.channel.pml4,
        ).ok() != Some(caller) {
            pending.retryable = false;
            trace_connect_child_restore(6, &pending);
            return HostedPumpRestore::ChildWorkPending(pending);
        }
    }
    if crate::driver_launch::driver_thread_projection::enter(&pending.channel, pending.caller).is_err() {
        pending.retryable = false;
        trace_connect_child_restore(7, &pending);
        return HostedPumpRestore::ChildWorkPending(pending);
    }
    let scope = ComponentSchedulerScope::enter();
    trace_connect_child_restore(21, &pending);
    let receive = match pending.mode {
        PendingReceiveMode::ChildWork =>
            crate::spawn_hosts::component_pump_continue_nested_child_work_receive(
                &pending.channel, &pending.result, pending.inner_receipt.take(),
            ),
        PendingReceiveMode::NestedRestore =>
            crate::spawn_hosts::component_pump_continue_nested_restore_receive(
                &pending.channel, &pending.result,
            ).map_err(|status| (status, None)),
        PendingReceiveMode::SchedulerYield => Ok(pending.result),
    };
    trace_connect_child_restore(22, &pending);
    let mut result = match receive {
        Ok(result) => result,
        Err((status, receipt)) => {
            pending.inner_receipt = receipt;
            pending.retryable = status == nt_process::STATUS_INSUFFICIENT_RESOURCES;
            if !pending.retryable { trace_connect_child_restore(8, &pending); }
            return HostedPumpRestore::ChildWorkPending(pending);
        }
    };
    trace_connect_child_result(0, &result);
    let mut channel = pending.channel;
    if result.scheduler_yielded {
        trace_connect_child_result(1, &result);
        scope.service_irq_yield(channel.shared_va);
        trace_connect_child_result(2, &result);
        let _ = handoff_exact_component_once(channel.tcb);
        let reply = match runtime::current_reply(route) {
            Ok(reply) if reply != 0 => reply,
            _ => return retain_uncertain_receive(pending, result, channel, 9),
        };
        channel.reply_cap = reply;
        trace_connect_child_result(3, &result);
        result = match crate::spawn_hosts::component_pump_continue_receive_after_scheduler_service(
            &channel, &result,
        ) {
            Ok(result) => result,
            Err(_) => return retain_uncertain_receive(pending, result, channel, 10),
        };
        trace_connect_child_result(4, &result);
    }
    if result.scheduler_yielded {
        // The receive already happened. Give the retained root owner another turn rather
        // than servicing renewed timer demand forever inside the parked AddDevice parent.
        if result.reply_cap == 0
            || runtime::current_reply(route).ok() != Some(result.reply_cap)
            || runtime::dispatch(route).ok() != Some(pending.dispatch)
        {
            return retain_uncertain_receive(pending, result, channel, 15);
        }
        channel.reply_cap = result.reply_cap;
        pending.mode = PendingReceiveMode::SchedulerYield;
        pending.result = result;
        pending.channel = channel;
        pending.retryable = true;
        return HostedPumpRestore::ChildWorkPending(pending);
    }
    if let Some(crate::spawn_hosts::NestedChildWorkState::Ready(_)) = result.nested_child_work {
        if runtime::dispatch(route).ok() != Some(pending.dispatch) {
            return retain_uncertain_receive(pending, result, channel, 11);
        }
        let reply = match runtime::current_reply(route) {
            Ok(reply) if reply != 0 && reply == result.reply_cap => reply,
            _ => return retain_uncertain_receive(pending, result, channel, 12),
        };
        channel.reply_cap = reply;
        return HostedPumpRestore::ChildWorkReady {
            result, parent: None, channel, dispatch: pending.dispatch, caller: pending.caller,
        };
    }
    if result.nested_child_work.is_some() {
        return retain_uncertain_receive(pending, result, channel, 13);
    }
    if result.nested_restore_yield.is_some() || result.nested_restore_quarantined.is_some() {
        let exact_reply = runtime::current_reply(route).ok() == Some(result.reply_cap)
            && runtime::dispatch(route).ok() == Some(pending.dispatch);
        if exact_reply { channel.reply_cap = result.reply_cap; }
        pending.mode = PendingReceiveMode::NestedRestore;
        pending.inner_ticket = result.nested_restore_yield.or(result.nested_restore_quarantined);
        pending.inner_restored = false;
        pending.inner_receipt = None;
        pending.outer_restored = true;
        pending.parent = None;
        pending.retryable = exact_reply && result.nested_restore_yield.is_some();
        pending.result = result;
        pending.channel = channel;
        return HostedPumpRestore::ChildWorkPending(pending);
    }
    if result.completed {
        // The generic authenticator reads the current dispatch. A resumed slice must also
        // prove that it is still completing the dispatch it originally retained.
        if runtime::dispatch(route).ok() != Some(pending.dispatch)
            || runtime::current_reply(route).ok() != Some(result.reply_cap)
            || authenticate_component_completion(&channel, &result).is_err()
        {
            return retain_uncertain_receive(pending, result, channel, 14);
        }
    }
    HostedPumpRestore::Restored(result)
}

/// Preserve the exact dispatch generation and latest Reply after an entered receive refused.
/// This state is never retryable because effects may already have occurred.
unsafe fn retain_uncertain_receive(
    mut pending: PendingChildWorkRestore,
    result: crate::spawn_hosts::PumpResult,
    channel: crate::spawn_hosts::PumpChannel,
    reason: u64,
) -> HostedPumpRestore {
    if let Some(crate::spawn_hosts::NestedChildWorkState::Quarantined(yielded)) = result.nested_child_work {
        if let Some(ticket) = yielded.parent {
            let _ = crate::spawn_hosts::shared_ingress::owner::runtime::nested::quarantine_child_work_parent(ticket);
        }
    }
    pending.result = result;
    pending.channel = channel;
    pending.retryable = false;
    trace_connect_child_restore(reason, &pending);
    HostedPumpRestore::ChildWorkPending(pending)
}
