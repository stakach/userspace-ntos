//! Reply evidence for private component pump receives.

use super::{PumpChannel, ReqKind};
use nt_component_suspension::{
    classify_received_call, require_free_reply, ReplyBindingObservation,
};

fn peer(channel: &PumpChannel, reply: u64, badge: u64) -> Option<u64> {
    match channel.caps.kind {
        ReqKind::Irp => crate::driver_launch::hosted_driver_pump_caller_tcb(channel, reply, badge),
        ReqKind::Syscall => {
            // Each win32k physical lane has a private endpoint and an unbadged peer. A newly
            // spawned lane also pumps its ready Call before joining the eligible lane registry;
            // the spawning scope retains these exact capabilities throughout that exchange.
            (channel.physical_domain.is_none()
                && badge == 0
                && channel.tcb != 0
                && channel.fault_ep != 0
                && reply != 0
                && reply == channel.reply_cap)
                .then_some(channel.tcb)
        }
    }
}

unsafe fn query(
    tcb: u64,
    reply: u64,
) -> Result<ReplyBindingObservation, sel4_rt::reply_binding::Error> {
    use sel4_rt::reply_binding::Binding;
    sel4_rt::reply_binding::query(tcb, reply).map(|binding| match binding {
        Binding::Free => ReplyBindingObservation::Free,
        Binding::Offered => ReplyBindingObservation::Offered,
        Binding::BoundToTarget => ReplyBindingObservation::BoundToTarget,
        Binding::BoundElsewhere => ReplyBindingObservation::BoundElsewhere,
    })
}

pub(super) unsafe fn before_receive(channel: &PumpChannel, reply: u64) {
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    let tcb = peer(channel, reply, 0).expect("component receive has no live channel peer");
    require_free_reply(query(tcb, reply)).expect("component receive would reuse an owned Reply");
}

pub(super) unsafe fn received_call(channel: &PumpChannel, reply: u64, badge: u64) -> bool {
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    let tcb = peer(channel, reply, 0).expect("component receive lost its channel peer");
    // Unknown ownership cannot become an empty poll or a wall that suspends the wrong main TCB.
    // Stop before any further receive/reply; the kernel still retains the original binding.
    classify_received_call(
        tcb,
        |target| query(target, reply),
        || peer(channel, reply, badge),
    )
    .expect("component Reply does not authenticate its received caller")
}
