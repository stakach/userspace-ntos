//! Shared receiver routing for a currently entered component invocation.

use super::shared_ingress::owner::runtime;
use super::*;
use nt_component_suspension::peer_registry::PeerRoute;

pub(super) unsafe fn receive(ch: &PumpChannel, route: PeerRoute) -> PumpMessage {
    loop {
        if runtime::resume_service(route).is_err() {
            return PumpMessage::transport_wall();
        }
        let next = match runtime::next_message(route) {
            Ok(next) => next,
            Err(_) => return PumpMessage::transport_wall(),
        };
        if let Some((reply, message)) = next {
            let completion = message.info() >> 12 == ch.dispatch_label;
            if !completion && runtime::adopt(route, reply).is_err() {
                return PumpMessage::transport_wall();
            }
            let mut message = PumpMessage::from_received(message);
            if !completion {
                message.shared_reply = Some(reply);
            }
            return message;
        }
        match runtime::next_autonomous() {
            Ok(Some(sender)) => {
                service_autonomous(sender)
                    .expect("autonomous failure retains its own source and parent scope");
                continue;
            }
            Ok(None) => {}
            Err(_) => return PumpMessage::transport_wall(),
        }
        if (ch.caps.kind == ReqKind::Irp || ch.caps.kernel_irq_yield)
            && crate::dispatcher_bootstrap::timer_work_pending()
        {
            return PumpMessage::scheduler_yield();
        }
        let execution = match runtime::receive_owner(route) {
            Ok(execution) => execution,
            Err(_) => return PumpMessage::transport_wall(),
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
                if pump_scheduler_work_pending(ch, irq) {
                    return PumpMessage::scheduler_yield();
                }
            }
            Err(_) => return PumpMessage::transport_wall(),
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
    // Replies are label-zero, capability-free payloads. Capture the entire IPC bank before any
    // binding probe can overwrite MR4+, then pass an owned payload to the retained reply owner.
    if info > 120 {
        PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let captured = crate::ipc_message::capture_received(0, info, words);
    let len = info as usize;
    let mut payload = [0u64; 120];
    for (index, word) in payload[..len].iter_mut().enumerate() {
        *word = captured.word(index).expect("validated Reply length");
    }
    match runtime::channel_route(ch) {
        Ok(Some(route)) => runtime::reply(route, reply, &payload[..len]).is_ok(),
        Ok(None) | Err(_) => {
            PUMP_REPLY_ERRORS.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

pub(super) unsafe fn authenticated_badge(ch: &PumpChannel, badge: u64) -> bool {
    matches!(runtime::channel_route(ch), Ok(Some(route)) if route.badge() == badge)
}
