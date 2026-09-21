//! Receive-only adapter for shared ingress with exact execution-owner admission.
//! Private pumps remain in use until native routing and ReplyRecv ownership are wired.

#[path = "component_ingress_owner.rs"]
pub(crate) mod owner;

use core::convert::Infallible;
use nt_component_suspension::peer_registry::{PeerRegistry, PeerRoute};
use nt_component_suspension::{
    classify_received_call, require_free_reply, ComponentSuspensionLanes, IngressExecutionOwner,
    IngressReceiveDisposition, IngressReceiver, ReceiveProbeError, ReceivedMessage,
    ReservedReceiveError, ReservedReceivePhase,
};
use nt_component_suspension::{IngressReplyPool, ReplyPoolError};

pub(crate) enum ReceiveError {
    Probe(ReceiveProbeError<sel4_rt::reply_binding::Error>),
    Ownership(ReservedReceiveError<Infallible>),
    Capture(ReservedReceiveError<Infallible>, ReceivedMessage),
    Retain(ReplyPoolError<sel4_rt::reply_binding::Error>),
    Admit(nt_component_suspension::ReplyAdmissionError<sel4_rt::reply_binding::Error>),
}

/// Retain a classified Call using a separately owned replacement Reply. The resolver validates
/// the route's exact domain generation and physical lifetime independently of registry metadata.
/// Both pools and their capabilities must
/// remain exclusive; queries cannot reenter root scheduling or mutate ownership in another domain.
pub(crate) unsafe fn retain<C, R, T>(
    owner: &mut IngressReceiver<ReceivedMessage>,
    replacements: &mut IngressReplyPool<ReceivedMessage>,
    lanes: &ComponentSuspensionLanes<C, R, T>,
    peers: &mut PeerRegistry,
    probe_tcb: u64,
    resolve_caller: impl FnOnce(PeerRoute) -> Option<u64>,
) -> Result<(), ReceiveError> {
    if owner.phase() != Some(ReservedReceivePhase::Held) {
        return Err(ReceiveError::Ownership(ReservedReceiveError::InvalidPhase));
    }
    let badge = owner.message().expect("held shared receive").badge();
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let route = peers
        .resolve(badge)
        .or_else(|| peers.resolve_retiring(badge))
        .ok_or(ReceiveError::Probe(ReceiveProbeError::UnknownCaller))?;
    if route.endpoint() != owner.endpoint()
        || resolve_caller(route) != Some(route.identity().executor)
    {
        return Err(ReceiveError::Probe(ReceiveProbeError::UnknownCaller));
    }
    replacements
        .retain(
            owner,
            lanes,
            peers,
            badge,
            |reply| super::query_component_reply_binding(probe_tcb, reply),
            |tcb, reply| super::query_component_reply_binding(tcb, reply),
        )
        .map_err(ReceiveError::Retain)
}

/// The caller owns the endpoint and Reply exclusively, validates the live probe TCB, and
/// excludes Replies retained by all other domains. No event handler or root scheduler may
/// reenter this owner across the syscall. This is not combined reply-and-receive.
pub(crate) unsafe fn receive<C, R, T>(
    owner: &mut IngressReceiver<ReceivedMessage>,
    lanes: &ComponentSuspensionLanes<C, R, T>,
    execution: IngressExecutionOwner,
    probe_tcb: u64,
    blocking: bool,
) -> Result<(), ReceiveError> {
    let endpoint = owner.endpoint();
    let reply = owner.reply();
    {
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        require_free_reply(super::query_component_reply_binding(probe_tcb, reply))
            .map_err(ReceiveError::Probe)?;
    }
    owner
        .begin_receive_for_owner(lanes, execution)
        .map_err(ReceiveError::Ownership)?;
    let badge: u64;
    let info: u64;
    let m0: u64;
    let m1: u64;
    let m2: u64;
    let m3: u64;
    let syscall = if blocking {
        crate::SYS_RECV
    } else {
        crate::SYS_NB_RECV
    };
    core::arch::asm!(
        "syscall",
        in("rdx") syscall as u64,
        inout("rdi") endpoint => badge,
        lateout("rsi") info,
        lateout("r10") m0,
        lateout("r8") m1,
        lateout("r9") m2,
        lateout("r15") m3,
        in("r12") reply,
        in("r13") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    // Own the entire IPC bank before binding queries or notification processing reuse it.
    let message = crate::ipc_message::capture_received(badge, info, [m0, m1, m2, m3]);
    owner
        .capture(message)
        .map_err(|(error, message)| ReceiveError::Capture(error, message))
}

/// Resolve only after complete capture. The resolver must authenticate badge, endpoint,
/// canonical physical domain generation and live TCB; registry badge lookup alone is not enough.
/// Query failure leaves the owner captured and charged. NoCall returns its full snapshot for
/// separate notification/Send handling, never silently discarding it as an empty receive.
pub(crate) unsafe fn classify(
    owner: &mut IngressReceiver<ReceivedMessage>,
    probe_tcb: u64,
    resolve_caller: impl FnOnce(u64) -> Option<u64>,
) -> Result<Option<ReceivedMessage>, ReceiveError> {
    if owner.phase() != Some(ReservedReceivePhase::Captured) {
        return Err(ReceiveError::Ownership(ReservedReceiveError::InvalidPhase));
    }
    let badge = owner.message().expect("captured shared receive").badge();
    let reply = owner.reply();
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let call = classify_received_call(
        probe_tcb,
        |tcb| super::query_component_reply_binding(tcb, reply),
        || resolve_caller(badge),
    )
    .map_err(ReceiveError::Probe)?;
    owner
        .resolve(if call {
            IngressReceiveDisposition::Call
        } else {
            IngressReceiveDisposition::NoCall
        })
        .map_err(ReceiveError::Ownership)
}
