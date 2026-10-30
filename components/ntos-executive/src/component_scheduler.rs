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
            | (u32::from(result.receive_yield.is_some()) << 1)
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
    pub(crate) unsafe fn service_irq_yield(&self, shared_va: u64) {
        let _message = crate::ipc_message::SavedMessageBuffer::capture();
        let _durable = crate::allocator::enter_durable();
        let mut parent = crate::spawn_hosts::shared_ingress::owner::runtime::nested::park_current()
            .expect("IRQ scheduling must preserve its exact parent invocation");
        let yield_number = YIELDS.fetch_add(1, Ordering::Relaxed) + 1;
        crate::dispatcher_bootstrap::request_receive_checkpoint();
        let timer_work = crate::dispatcher_bootstrap::service_hosted_timer_work();
        let irq_lines = drain_pending_hosted_irqs_snapshot();
        let dpcs = drain_hosted_driver_dpcs();
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
        crate::spawn_hosts::shared_ingress::owner::runtime::nested::restore(&mut parent)
            .expect("IRQ scheduling must restore its retained parent invocation");
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

pub(super) unsafe fn hosted_component_pump(
    channel: &crate::spawn_hosts::PumpChannel,
) -> crate::spawn_hosts::PumpResult {
    hosted_component_pump_inner(channel, None)
}

pub(super) unsafe fn hosted_component_pump_with_caller(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> crate::spawn_hosts::PumpResult {
    hosted_component_pump_inner(channel, Some(caller))
}

unsafe fn hosted_component_pump_inner(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: Option<nt_process::native_handle::NativeHandleCaller>,
) -> crate::spawn_hosts::PumpResult {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let mut channel = *channel;
    let route = runtime::channel_route(&channel).expect("physical hosted ingress identity");
    let mut parent = if channel.initial == crate::spawn_hosts::InitialAction::ReplyRequest {
        let parent = runtime::nested::park_current().expect("retain nested hosted parent");
        let route = route.expect("hosted dispatch requires enrolled source");
        runtime::admit(route).expect("admit exact hosted dispatch Call");
        channel.reply_cap = runtime::current_reply(route).expect("admitted canonical Reply");
        crate::driver_launch::trace_port_connect_pump_boundary(
            0, &channel, channel.reply_cap, 0,
        );
        parent
    } else {
        None
    };
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
    let mut result = crate::spawn_hosts::component_pump(channel);
    trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 1, Some(&result));
    trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 1, Some(&result));
    while result.scheduler_yielded {
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 2, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 2, Some(&result));
        scope.service_irq_yield(channel.shared_va);
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 3, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 3, Some(&result));
        if let Some(route) = route {
            channel.reply_cap = runtime::current_reply(route).expect("retained canonical Reply");
        }
        result = crate::spawn_hosts::component_pump_continue_receive_after_scheduler_service(
            channel, &result)
            .expect("hosted IRQ yield must retain its exact receive continuation");
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 4, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 4, Some(&result));
    }
    if result.completed {
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 5, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 5, Some(&result));
        let route = route.expect("hosted completion requires enrolled source");
        let dispatch = runtime::dispatch(route).expect("retained hosted dispatch epoch");
        if let Some(words) = result.startup_stack_receipt {
            assert!(
                crate::driver_launch::hosted_source_completion_lane::validate_startup_ready(
                    channel, words
                ) || crate::driver_launch::hosted_class_irp_lane::validate_startup_ready(
                    channel, words
                ) || crate::driver_launch::hosted_provider_export_lane::validate_startup_ready(
                    channel, words
                ),
                "authenticate exact retained hosted worker READY"
            );
            let reply = runtime::current_reply(route).expect("current canonical startup Reply");
            runtime::complete_protocol(route, dispatch, reply, channel.dispatch_label, &words)
                .expect("settle exact hosted worker startup protocol");
        } else {
            runtime::complete(route, dispatch, result.reply_cap, channel.dispatch_label)
                .expect("authenticate hosted final completion Call");
        }
        trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 6, Some(&result));
        trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 6, Some(&result));
    }
    trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 7, Some(&result));
    trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 7, Some(&result));
    runtime::nested::restore(&mut parent).expect("restore nested hosted parent");
    trace_worker_startup_pump(StartupKind::Source, startup_ordinal, 8, Some(&result));
    trace_worker_startup_pump(StartupKind::Class, class_startup_ordinal, 8, Some(&result));
    result
}
