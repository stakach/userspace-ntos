//! Retained native ALPC CreatePort service exchange.
//!
//! The checked request, invisible process handle, and original Reply are
//! installed here before the first ring submission. A timeout observes an
//! in-flight SQE; it never authorizes replay or frame reuse.

use crate::native_alpc_create::PendingCreatePort;
use crate::root_reply_park::RootReplyPark;
use crate::*;

const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;
const STATUS_DEVICE_NOT_READY: u32 = 0xC000_00A3;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

#[derive(Clone, Copy)]
enum Flight {
    Ready,
    Create(u64),
    CloseReady,
    Close(u64, nt_alpc_abi::AlpcCloseCreatedPortRequest),
    CloseFailed,
    InvalidTerminal,
    ReplyIndeterminate,
}

struct OwnedCreate {
    call: PendingCreatePort,
    flight: Flight,
}

static mut OWNED_CREATE: Option<OwnedCreate> = None;

fn after_create_completion(result: Result<(), u32>, call: &PendingCreatePort) -> Flight {
    if result.is_ok() || call.cleanup_request().is_some() || call.reply_status().is_some() {
        Flight::CloseReady
    } else {
        // An exact but malformed terminal CQE was consumed. It cannot be
        // interpreted as failure before effect or resubmitted under this token.
        Flight::InvalidTerminal
    }
}

/// Return only after the original Reply has been transferred to this owner.
/// A pre-effect failure is returned to the normal syscall reply path.
pub(crate) unsafe fn begin(
    handler: &mut ExecNtHandler,
    args: [u64; 3],
) -> Result<(), u32> {
    let slot = &mut *core::ptr::addr_of_mut!(OWNED_CREATE);
    if slot.is_some() {
        return Err(STATUS_DEVICE_BUSY);
    }
    if lpc_client().is_none() {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    let prepared = handler.prepare_native_alpc_create_port(args)?;
    let reply_cap = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let park = RootReplyPark::prepare().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let call = handler.reserve_native_alpc_create_port(prepared, reply_cap)?;
    *slot = Some(OwnedCreate { call, flight: Flight::Ready });
    park.commit();
    Ok(())
}

/// One checked ring observation. The channel borrow ends before any caller
/// memory copyout or Reply effect can enter another executive service.
enum RingStep {
    Idle,
    CreateNoEffect(i32),
    CreateExact(u64, i32, u64),
    CreateUncertain(u64),
    CloseNoEffect,
    CloseExact(nt_alpc_abi::AlpcCloseCreatedPortRequest, i32),
    CloseUncertain(u64, nt_alpc_abi::AlpcCloseCreatedPortRequest),
}

fn close_identity(request: nt_alpc_abi::AlpcCloseCreatedPortRequest)
    -> Option<nt_process::native_alpc_port::AlpcPortIdentity>
{
    Some(nt_process::native_alpc_port::AlpcPortIdentity {
        service_handle: request.handle,
        kind: nt_process::native_alpc_port::AlpcPortKind::Created,
        owner_process: u32::try_from(request.owner_process).ok()?,
        owner_generation: request.owner_generation,
        invocation_hi: request.invocation_hi,
        invocation_lo: request.invocation_lo,
    })
}

unsafe fn retire_acknowledged(
    slot: &mut Option<OwnedCreate>, handler: &mut ExecNtHandler,
) {
    let owner = slot.take().expect("ALPC create Reply owner disappeared");
    let cap = owner.call.reply_cap();
    let thread_id = owner.call.thread_id();
    assert!(owner.call.finish_after_reply(true).is_ok(),
        "acknowledged ALPC Reply must be terminal");
    thread_wait_state_clear_tid_ready(handler, thread_id);
    release_reply_pool_cap(cap);
}

/// Advance one exact SQE or CQE per service-loop pass. A Reply send is attempted
/// once; an uncertain result is retained and may only be reconciled without
/// another send.
pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    let slot = &mut *core::ptr::addr_of_mut!(OWNED_CREATE);
    let Some(owner) = slot.as_mut() else { return };
    if matches!(owner.flight, Flight::ReplyIndeterminate) {
        let cap = owner.call.reply_cap();
        if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap)
            && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(cap), Ok(true))
        {
            retire_acknowledged(slot, handler);
        }
        return;
    }
    if matches!(owner.flight, Flight::CloseFailed | Flight::InvalidTerminal) {
        return;
    }
    let step = {
        let Some(client) = lpc_client() else { return };
        let channel = &mut client.backend_mut().0;
        // A retained receive may own the shared ring's exact in-flight SQE.
        // Busy transport is not a CreatePort no-effect failure; wait for its
        // CQE before starting this owner's first or cleanup SQE.
        if matches!(owner.flight, Flight::Ready | Flight::CloseReady)
            && channel.completion_inbox.active_request().is_some()
        { return; }
        match owner.flight {
            Flight::Ready => {
                let request_id = channel.next_id;
                if owner.call.begin(request_id).is_err() {
                    owner.flight = Flight::InvalidTerminal;
                    return;
                }
                let mut reply = [];
                match channel.raw_owned(nt_alpc_abi::opcode::ALPC_OP_CREATE_PORT,
                    owner.call.request(), &mut reply) {
                    RingCallOutcome::NoEffect(status) => RingStep::CreateNoEffect(status),
                    RingCallOutcome::Completed(status, _, _, handle, _) =>
                        RingStep::CreateExact(request_id, status, handle),
                    RingCallOutcome::Indeterminate { request_id: observed } => {
                        assert_eq!(observed, request_id, "ALPC create ring identity changed");
                        RingStep::CreateUncertain(request_id)
                    }
                }
            }
            Flight::Create(request_id) => {
                let mut reply = [];
                match channel.poll_owned(request_id, &mut reply) {
                    Some((status, _, _, handle, _)) =>
                        RingStep::CreateExact(request_id, status, handle),
                    None => RingStep::Idle,
                }
            }
            Flight::CloseReady => {
                if let Some(request) = owner.call.cleanup_request() {
                    let request_id = channel.next_id;
                    let mut reply = [];
                    match channel.raw_owned(nt_alpc_abi::opcode::ALPC_OP_CLOSE_CREATED_PORT,
                        bytemuck::bytes_of(&request), &mut reply) {
                        RingCallOutcome::NoEffect(_) => RingStep::CloseNoEffect,
                        RingCallOutcome::Completed(status, _, _, _, _) =>
                            RingStep::CloseExact(request, status),
                        RingCallOutcome::Indeterminate { request_id: observed } => {
                            assert_eq!(observed, request_id, "ALPC close ring identity changed");
                            RingStep::CloseUncertain(request_id, request)
                        }
                    }
                } else { RingStep::Idle }
            }
            Flight::Close(request_id, request) => {
                let mut reply = [];
                match channel.poll_owned(request_id, &mut reply) {
                    Some((status, _, _, _, _)) => RingStep::CloseExact(request, status),
                    None => RingStep::Idle,
                }
            }
            Flight::CloseFailed | Flight::InvalidTerminal | Flight::ReplyIndeterminate =>
                RingStep::Idle,
        }
    };
    match step {
        RingStep::Idle | RingStep::CloseNoEffect => {}
        RingStep::CreateNoEffect(status) => {
            owner.flight = if owner.call.no_effect(&mut handler.pm, status).is_ok() {
                Flight::CloseReady
            } else { Flight::InvalidTerminal };
        }
        RingStep::CreateExact(request_id, status, handle) => {
            let result = owner.call.complete(&mut handler.pm, request_id, status, handle);
            owner.flight = after_create_completion(result, &owner.call);
        }
        RingStep::CreateUncertain(request_id) => owner.flight = Flight::Create(request_id),
        RingStep::CloseExact(request, status) => {
            owner.flight = match close_identity(request)
                .and_then(|identity| owner.call.cleanup_complete(identity, status).ok()) {
                Some(()) => Flight::CloseReady,
                None => Flight::CloseFailed,
            };
        }
        RingStep::CloseUncertain(request_id, request) =>
            owner.flight = Flight::Close(request_id, request),
    }
    if !matches!(owner.flight, Flight::CloseReady) { return }
    if owner.call.cleanup_request().is_some() { return }
    if owner.call.reply_status().is_none() && owner.call.copyout(handler).is_err() {
        return;
    }
    let Some(status) = owner.call.reply_status() else { return };
    if owner.call.begin_reply().is_err() {
        owner.flight = Flight::InvalidTerminal;
        return;
    }
    let cap = owner.call.reply_cap();
    if reply_parked_syscall(cap, status as u64) {
        retire_acknowledged(slot, handler);
    } else if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap)
        && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(cap), Ok(true))
    {
        retire_acknowledged(slot, handler);
    } else {
        owner.flight = Flight::ReplyIndeterminate;
    }
}
