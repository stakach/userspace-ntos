//! Shared receiver routing for a currently entered component invocation.

use super::shared_ingress::owner::runtime;
use super::*;
use nt_component_suspension::peer_registry::PeerRoute;

pub(super) unsafe fn receive(ch: &PumpChannel, route: PeerRoute, retained_seh: bool) -> PumpMessage {
    loop {
        crate::registry_mutation_work::redrive_provider();
        if crate::driver_launch::nested_hosted_driver_create_ready()
            || crate::driver_launch::nested_hosted_query_path_ready() {
            let _message = crate::ipc_message::SavedMessageBuffer::capture();
            let parent = match runtime::nested::park_current() {
                Ok(parent) => parent,
                Err(_) => return PumpMessage::transport_wall(),
            };
            let progressed = crate::service_sec_image::redrive_nested_hosted_file_work();
            if runtime::nested::restore(parent).is_err() {
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
        if !retained_seh && (ch.caps.kind == ReqKind::Irp || ch.caps.kernel_irq_yield)
            && crate::dispatcher_bootstrap::timer_work_pending()
        {
            return PumpMessage::scheduler_yield();
        }
        let execution = match runtime::receive_owner(route) {
            Ok(execution) => execution,
            Err(_) => {
                crate::print_str(b"[pump-ingress] receive owner failed\n");
                return PumpMessage::transport_wall();
            }
        };
        match runtime::receive(execution, ch.tcb, true) {
            Ok(runtime::Arrival::Hosted) => {}
            Ok(runtime::Arrival::Call { .. }) => {
                // The coordinator retains unrelated Calls for their exact source. Inspect only
                // this invocation's stored arrival on the next pass.
            }
            Ok(runtime::Arrival::Notification(message)) => {
                let (event, _, irq) = pump_handle_executive_event_badge(message.badge());
                if !event {
                    continue;
                }
                if pump_deadman_tripped() {
                    return PumpMessage::deadman_wall();
                }
                if !retained_seh && pump_scheduler_work_pending(ch, irq) {
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

pub(super) unsafe fn service_autonomous(route: PeerRoute) -> Result<(), runtime::Error> {
    let parent = runtime::nested::park_current()?;
    let serviced = (|| {
        runtime::resume_service(route)?;
        runtime::admit(route)?;
        let channel = crate::driver_launch::autonomous_pump_channel(route)
            .ok_or(runtime::Error::PhysicalIdentity)?;
        let message = runtime::stored_current_message(route)?;
        let mut reply = channel.reply_cap;
        let outcome = component_pump_loop(
            &channel,
            PumpMessage::from_received(message),
            &mut reply,
            nt_user_host::component_pump::ComponentPumpAccounting::new(false),
        );
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
    if let Err(error) = runtime::nested::restore(parent) {
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
