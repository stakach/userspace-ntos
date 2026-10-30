//! Shared receiver routing for a currently entered component invocation.

use super::shared_ingress::owner::runtime;
use super::*;
use nt_component_suspension::peer_registry::PeerRoute;

// Counts only entered receive scopes and observed IRQ notifications. Periodic census reads these
// atomics without walking the hosted ingress table or changing receive ownership.
static ACTIVE_IRP_RECEIVES: AtomicU64 = AtomicU64::new(0);
static ACTIVE_SYSCALL_RECEIVES: AtomicU64 = AtomicU64::new(0);
static ACTIVE_RETAINED_SEH_RECEIVES: AtomicU64 = AtomicU64::new(0);
static IRQ_IRP_RECEIVES: AtomicU64 = AtomicU64::new(0);
static IRQ_SYSCALL_RECEIVES: AtomicU64 = AtomicU64::new(0);
static IRQ_RETAINED_SEH_RECEIVES: AtomicU64 = AtomicU64::new(0);

struct ReceiveCensusScope {
    kind: ReqKind,
    retained_seh: bool,
}

impl ReceiveCensusScope {
    fn enter(kind: ReqKind, retained_seh: bool) -> Self {
        match kind {
            ReqKind::Irp => { ACTIVE_IRP_RECEIVES.fetch_add(1, Ordering::Relaxed); }
            ReqKind::Syscall => { ACTIVE_SYSCALL_RECEIVES.fetch_add(1, Ordering::Relaxed); }
        }
        if retained_seh {
            ACTIVE_RETAINED_SEH_RECEIVES.fetch_add(1, Ordering::Relaxed);
        }
        Self { kind, retained_seh }
    }
}

impl Drop for ReceiveCensusScope {
    fn drop(&mut self) {
        match self.kind {
            ReqKind::Irp => { ACTIVE_IRP_RECEIVES.fetch_sub(1, Ordering::Relaxed); }
            ReqKind::Syscall => { ACTIVE_SYSCALL_RECEIVES.fetch_sub(1, Ordering::Relaxed); }
        }
        if self.retained_seh {
            ACTIVE_RETAINED_SEH_RECEIVES.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

pub(super) fn receive_census() -> (u64, u64, u64, u64, u64, u64) {
    (
        ACTIVE_IRP_RECEIVES.load(Ordering::Relaxed),
        ACTIVE_SYSCALL_RECEIVES.load(Ordering::Relaxed),
        ACTIVE_RETAINED_SEH_RECEIVES.load(Ordering::Relaxed),
        IRQ_IRP_RECEIVES.load(Ordering::Relaxed),
        IRQ_SYSCALL_RECEIVES.load(Ordering::Relaxed),
        IRQ_RETAINED_SEH_RECEIVES.load(Ordering::Relaxed),
    )
}

/// Run the established bounded IRQ/DPC scheduler while the exact dispatch remains parked.
/// The scheduler owns its nested execution hold and restores it before this receiver can wait;
/// neither this checkpoint nor its caller sends or replays the retained Reply.
unsafe fn service_inline_irq_checkpoint(
    ch: &PumpChannel,
    route: PeerRoute,
) -> Result<(), runtime::Error> {
    if runtime::channel_route(ch)? != Some(route)
        || !matches!(runtime::receive_owner(route)?, nt_component_suspension::IngressExecutionOwner::Dispatch(_))
    {
        return Err(runtime::Error::PhysicalIdentity);
    }
    let dispatch = runtime::dispatch(route)?;
    let reply = runtime::current_reply(route)?;
    let scope = crate::driver_launch::ComponentSchedulerScope::enter();
    scope.service_irq_yield(ch.shared_va);
    if runtime::channel_route(ch)? != Some(route)
        || runtime::dispatch(route)? != dispatch
        || runtime::current_reply(route)? != reply
        || !matches!(runtime::receive_owner(route)?, nt_component_suspension::IngressExecutionOwner::Dispatch(current) if current == dispatch)
    {
        return Err(runtime::Error::PhysicalIdentity);
    }
    Ok(())
}

/// A physical IRQ bit is independent of the ordinary request kind and kernel-yield capability.
unsafe fn inline_irq_work_pending() -> bool {
    crate::driver_launch::hosted_irq_work_pending()
        || crate::driver_launch::hosted_driver_dpc_activation_pending()
        || crate::dispatcher_bootstrap::timer_work_pending()
}

pub(super) unsafe fn receive(
    ch: &PumpChannel, route: PeerRoute, retained_seh: bool, serviced_scheduler_yield: bool,
) -> PumpMessage {
    let _census_scope = ReceiveCensusScope::enter(ch.caps.kind, retained_seh);
    // A retained exception walk and an ordinary syscall channel without kernel IRQ yield cannot
    // return a scheduler continuation. Give already-latched work one isolated pass here instead.
    let inline_irq_checkpoint =
        retained_seh || (ch.caps.kind == ReqKind::Syscall && !ch.caps.kernel_irq_yield);
    let mut irq_checkpoint = inline_irq_checkpoint && inline_irq_work_pending();
    let mut timer_probe_consumed = false;
    loop {
        if !retained_seh {
            match crate::win32k_glue::prepare_receive_yield(ch) {
                Ok(Some(yielded)) => return PumpMessage::hosted_receive_yield(yielded),
                Ok(None) => {}
                Err(error) => {
                    crate::print_str(b"[receive-yield-failure] propagated-error=");
                    crate::print_str(match error {
                        runtime::Error::PhysicalIdentity => b"physical",
                        runtime::Error::Admission => b"admission",
                        runtime::Error::Capacity => b"capacity",
                        runtime::Error::Receive => b"receive",
                        _ => b"other",
                    });
                    crate::print_str(b"\n");
                    panic!("receive-yield preparation retains exact ingress ownership");
                }
            }
            match crate::win32k_glue::prepare_service_wait_yield(ch) {
                Ok(Some(yielded)) => return PumpMessage::hosted_service_wait_yield(yielded),
                Ok(None) => {}
                Err(_) => panic!("service-wait yield lost its exact physical ownership"),
            }
        }
        // A native SYSTEM fold may finish its second physical slot while this IRP Receive
        // retains the parent Call. Release its exact CM checkpoint and reserve before a
        // dependent registry writer retries; the generic outer finalizer cannot run here.
        if crate::writable_fs::system_wal_fold_ack_pending() {
            let mut parent = match runtime::nested::park_current() {
                Ok(parent) => parent,
                Err(_) => return PumpMessage::transport_wall(),
            };
            let progressed = crate::writable_fs::redrive_retained_system_wal_fold_after_native_completion();
            if runtime::nested::restore(&mut parent).is_err() {
                return PumpMessage::transport_wall();
            }
            if progressed { continue; }
        }
        let progressed = crate::registry_mutation_work::redrive_provider();
        // A retained CM mutation can use all sixteen steps and still have a local terminal
        // phase to run. Take another fair, bounded pass before entering a blocking Receive.
        // A stalled or ineligible owner returns false, so it cannot spin this pump.
        if progressed && crate::registry_mutation_work::wake_due(crate::monotonic_time_100ns()) != 0 {
            continue;
        }
        if crate::service_sec_image::nested_hosted_file_work_ready() {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            let mut parent = match runtime::nested::park_current() {
                Ok(parent) => parent,
                Err(_) => return PumpMessage::transport_wall(),
            };
            let progressed = crate::service_sec_image::redrive_nested_hosted_file_work();
            if runtime::nested::restore(&mut parent).is_err() {
                return PumpMessage::transport_wall();
            }
            if progressed { continue; }
        }
        match runtime::resume_acknowledged_retained_services() {
            Ok(true) => continue,
            Ok(false) => {}
            Err(_) => {
                crate::print_str(b"[pump-ingress] retained-service resume failed\n");
                return PumpMessage::transport_wall();
            }
        }
        if runtime::resume_service(route).is_err() {
            crate::print_str(b"[pump-ingress] route resume failed\n");
            return PumpMessage::transport_wall();
        }
        let next = match runtime::next_message(route) {
            Ok(next) => next,
            Err(_) => {
                crate::print_str(b"[pump-ingress] next-message failed\n");
                return PumpMessage::transport_wall();
            }
        };
        if let Some((reply, message)) = next {
            let completion = message.info() >> 12 == ch.dispatch_label;
            if !completion && runtime::adopt(route, reply).is_err() {
                crate::print_str(b"[pump-ingress] Call adoption failed\n");
                return PumpMessage::transport_wall();
            }
            let mut message = PumpMessage::from_received(message);
            if !completion {
                message.shared_reply = Some(reply);
            }
            return message;
        }
        // The registry journal has moved the mounted volume into its own transaction.
        // Leave autonomous Calls in the retained receiver until that owner releases it.
        if !crate::writable_fs::registry_journal::owns_volume() {
            match runtime::next_autonomous() {
                Ok(Some(sender)) => {
                    service_autonomous(sender)
                        .expect("autonomous failure retains its own source and parent scope");
                    continue;
                }
                Ok(None) => {}
                Err(_) => {
                    crate::print_str(b"[pump-ingress] autonomous selection failed\n");
                    return PumpMessage::transport_wall();
                }
            }
        }
        let timer_checkpoint = !retained_seh
            && (ch.caps.kind == ReqKind::Irp || ch.caps.kernel_irq_yield)
            && crate::dispatcher_bootstrap::timer_work_pending();
        if timer_checkpoint && timer_probe_consumed {
            return PumpMessage::scheduler_yield();
        }
        // A pending timer still gets its scheduler pass, but first give a newly arrived Call
        // one nonblocking physical receive through the exact retained ingress owner. Otherwise
        // continuously republished timer demand can starve a worker's READY Call forever.
        timer_probe_consumed = timer_checkpoint;
        if inline_irq_checkpoint && irq_checkpoint {
            if service_inline_irq_checkpoint(ch, route).is_err() {
                crate::print_str(b"[pump-ingress] inline IRQ checkpoint lost its route\n");
                return PumpMessage::transport_wall();
            }
            // Deferred IRQ bits may remain set. This pass belongs to the observed arrival only;
            // inspect new Calls before waiting, then await another notification to retry.
            irq_checkpoint = false;
            continue;
        }
        let execution = match runtime::receive_owner(route) {
            Ok(execution) => execution,
            Err(_) => {
                crate::print_str(b"[pump-ingress] receive owner failed\n");
                return PumpMessage::transport_wall();
            }
        };
        let arrival = runtime::receive(execution, ch.tcb,
            serviced_scheduler_yield || !timer_checkpoint);
        match arrival {
            Ok(runtime::Arrival::Hosted) => {}
            Ok(runtime::Arrival::Call { .. }) => {
                // The coordinator retains unrelated Calls for their exact source. Inspect only
                // this invocation's stored arrival on the next pass.
            }
            Ok(runtime::Arrival::Notification(message)) => {
                // The shared ingress has already proven NoCall with a free Reply. An empty
                // nonblocking probe has no sender and must not count as watchdog progress.
                if timer_checkpoint && message.badge() == 0 && message.info() == 0 {
                    return PumpMessage::scheduler_yield();
                }
                crate::census_tick_static(crate::monotonic_time_100ns());
                let (event, _, irq) = pump_handle_executive_event_badge(message.badge());
                if irq {
                    match ch.caps.kind {
                        ReqKind::Irp => { IRQ_IRP_RECEIVES.fetch_add(1, Ordering::Relaxed); }
                        ReqKind::Syscall => { IRQ_SYSCALL_RECEIVES.fetch_add(1, Ordering::Relaxed); }
                    }
                    if retained_seh {
                        IRQ_RETAINED_SEH_RECEIVES.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if !event {
                    continue;
                }
                if pump_deadman_tripped() {
                    return PumpMessage::deadman_wall();
                }
                if inline_irq_checkpoint && (irq || inline_irq_work_pending()) {
                    irq_checkpoint = true;
                }
                if !inline_irq_checkpoint && pump_scheduler_work_pending(ch, irq) {
                    return PumpMessage::scheduler_yield();
                }
            }
            Err(_) => {
                crate::print_str(b"[pump-ingress] physical receive failed\n");
                return PumpMessage::transport_wall();
            }
        }
    }
}

pub(super) unsafe fn autonomous(ch: &PumpChannel) -> bool {
    matches!(runtime::channel_route(ch).and_then(|route| route.ok_or(runtime::Error::UnknownPeer))
        .and_then(|route| runtime::physical_source(route)),
        Ok(source) if matches!(source.kind, runtime::PhysicalSourceKind::SystemThread { .. }))
}

/// Persistent dispatch workers retain their invocation across a service wait; unlike autonomous
/// threads, the service ACK cannot finish their enclosing dispatch.
pub(super) unsafe fn service_wait_yields(ch: &PumpChannel) -> bool {
    if autonomous(ch) { return true; }
    if ch.caps.kind != ReqKind::Irp { return false; }
    // The class HOOK worker runs inside an earlier AddDevice/CONNECT pump. Keep receiving on
    // this exact worker while its lower source is redriven; returning a provider-wait slice to
    // ordinary IRP dispatch would misclassify the live continuation as a transport wall.
    if crate::driver_launch::hosted_class_irp_lane::is_channel(ch) { return false; }
    // The exact class source has already parked its CONNECT Call. Its retained owner must
    // redrive the port provider before this receiver can deliver the first service Reply.
    if crate::driver_launch::parked_hosted_connect_source_channel(ch) { return false; }
    matches!(runtime::channel_route(ch).and_then(|route| route.ok_or(runtime::Error::UnknownPeer))
        .and_then(|route| runtime::physical_source(route)),
        Ok(source) if matches!(source.domain, runtime::PhysicalDomain::Hosted(_))
            && matches!(source.kind, runtime::PhysicalSourceKind::DispatchWorker { .. }))
}

pub(super) unsafe fn service_autonomous(route: PeerRoute) -> Result<(), runtime::Error> {
    let mut parent = runtime::nested::park_current()?;
    let serviced = (|| {
        runtime::resume_service(route)?;
        runtime::admit(route)?;
        let channel = crate::driver_launch::autonomous_pump_channel(route)
            .ok_or(runtime::Error::PhysicalIdentity)?;
        let message = runtime::stored_current_message(route)?;
        let mut reply = channel.reply_cap;
        let mut seh = hosted_seh_pump::SehLease::claim(&channel, reply, true)
            .ok_or(runtime::Error::PhysicalIdentity)?;
        let outcome = component_pump_loop(
            &channel,
            PumpMessage::from_received(message),
            &mut reply,
            nt_user_host::component_pump::ComponentPumpAccounting::new(false),
            &mut seh.pump,
        );
        let suspended = outcome.callback_suspended
            || outcome.provider_wait_suspended
            || outcome.lpc_wait_suspended;
        if !seh.finish(&channel, reply, suspended) {
            return Err(runtime::Error::PhysicalIdentity);
        }
        // An autonomous thread does not speak the dispatch-worker completion protocol. Only
        // the acknowledged service Reply can complete its invocation and return this lane idle.
        if outcome.completed
            && crate::service_sec_image::component_execution_lane_is_idle(route.identity().lane)
            || outcome.provider_wait_suspended
        {
            Ok(())
        } else {
            pump_wall_state_diag(&channel, outcome);
            Err(runtime::Error::Protocol)
        }
    })();
    if serviced.is_err() {
        autonomous_failure_diag(route, b"terminate/drain");
        if !crate::driver_launch::terminate_failed_autonomous_service(route) {
            autonomous_failure_diag(route, b"uncertain; parent retained");
            return Err(runtime::Error::Retirement);
        }
    }
    if let Err(error) = runtime::nested::restore(&mut parent) {
        autonomous_failure_diag(route, b"parent restoration retained");
        return Err(error);
    }
    Ok(())
}

unsafe fn autonomous_failure_diag(route: PeerRoute, stage: &[u8]) {
    crate::print_str(b"[autonomous-ingress] ");
    crate::print_str(stage);
    crate::print_str(b" badge=");
    crate::print_u64(route.badge());
    crate::print_str(b" tcb=");
    crate::print_u64(route.identity().executor);
    crate::print_str(b"\n");
}

pub(super) unsafe fn reply(ch: &PumpChannel, reply: u64, info: u64, words: [u64; 4]) -> bool {
    reply_with_info(ch, reply, info, words, false)
}

pub(super) unsafe fn reply_seh(ch: &PumpChannel, reply: u64, info: u64, words: [u64; 4]) -> bool {
    if nt_unwind::seh_transport::SehCommand::parse(info, words).is_none() {
        crate::print_str(b"[fsd-seh] malformed command reply\n");
        PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    reply_with_info(ch, reply, info, words, true)
}

unsafe fn reply_with_info(ch: &PumpChannel, reply: u64, info: u64, words: [u64; 4], labeled: bool) -> bool {
    // Capture the entire IPC bank before any
    // binding probe can overwrite MR4+, then pass an owned payload to the retained reply owner.
    if info & 0xf80 != 0 || (info >> 12 != 0 && !labeled) || (info & 0x7f) > 120 {
        if labeled { crate::print_str(b"[fsd-seh] reply info refused\n"); }
        PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let captured = crate::ipc_message::capture_received(0, info, words);
    let len = (info & 0x7f) as usize;
    let mut payload = [0u64; 120];
    for (index, word) in payload[..len].iter_mut().enumerate() {
        *word = captured.word(index).expect("validated Reply length");
    }
    match runtime::channel_route(ch) {
        Ok(Some(route)) => {
            let result = runtime::reply_with_info(route, reply, info, &payload[..len]);
            if labeled && result.is_err() { crate::print_str(b"[fsd-seh] retained reply refused\n"); }
            result.is_ok()
        }
        Ok(None) | Err(_) => {
            if labeled { crate::print_str(b"[fsd-seh] reply route refused\n"); }
            PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

pub(super) unsafe fn authenticated_badge(ch: &PumpChannel, badge: u64) -> bool {
    matches!(runtime::channel_route(ch), Ok(Some(route)) if route.badge() == badge)
}
