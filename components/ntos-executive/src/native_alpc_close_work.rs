//! Exact NtClose owner for process-published native ALPC ports.
//! The process slot and original Reply survive every uncertain service result.

use crate::root_reply_park::RootReplyPark;
use crate::*;

const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;
const STATUS_DEVICE_NOT_READY: u32 = 0xC000_00A3;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

#[derive(Clone, Copy)]
enum Flight { Ready, Submitted(u64), ReplyReady, ReplyIndeterminate, InvalidTerminal }

struct OwnedClose {
    close: nt_process::native_alpc_port::NativeAlpcPortClose,
    request: nt_alpc_abi::AlpcCloseCreatedPortRequest,
    thread: u64,
    reply_cap: u64,
    flight: Flight,
    status: i32,
    reply_attempted: bool,
}

static mut OWNED_CLOSE: Option<OwnedClose> = None;

pub(crate) fn recognizes(handler: &ExecNtHandler, value: u64) -> bool {
    let Ok(caller) = handler.native_handle_caller(nt_syscall::ProcessorMode::UserMode) else {
        return false;
    };
    let Some(generation) = handler.hosted_process_generation(handler.pi) else { return false };
    handler.pm.lookup_native_alpc_port(caller, value, generation).is_ok()
}

/// Park the original Reply only after the exact process slot is hidden.
pub(crate) unsafe fn begin(handler: &mut ExecNtHandler, value: u64) -> Result<(), u32> {
    if lpc_client().is_none() { return Err(STATUS_DEVICE_NOT_READY); }
    if !handler.current_native_call_transport { return Err(STATUS_INVALID_HANDLE); }
    let slot = &mut *core::ptr::addr_of_mut!(OWNED_CLOSE);
    if slot.is_some() { return Err(STATUS_DEVICE_BUSY); }
    let pi = handler.pi;
    let badge = handler.current_badge;
    if handler.hosted_thread_pi_for_badge(badge) != Some(pi) { return Err(STATUS_INVALID_HANDLE); }
    let thread = handler.hosted_thread_tid_for_badge(badge)
        .filter(|tid| *tid != 0 && *tid == handler.current_tid).ok_or(STATUS_INVALID_HANDLE)?;
    handler.hosted_thread_tcb_for_badge(badge)
        .filter(|tcb| *tcb != 0).ok_or(STATUS_INVALID_HANDLE)?;
    let generation = handler.hosted_process_generation(pi)
        .filter(|generation| *generation != 0).ok_or(STATUS_INVALID_HANDLE)?;
    let caller = handler.native_handle_caller(nt_syscall::ProcessorMode::UserMode)?;
    let park = RootReplyPark::prepare().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let reply_cap = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let close = handler.pm.begin_native_alpc_port_close(caller, value, generation)
        .map_err(|error| match error {
            nt_process::native_handle::NativeCloseError::Status(status) => status,
            nt_process::native_handle::NativeCloseError::BugCheck { .. } => STATUS_INVALID_HANDLE,
        })?;
    let identity = close.identity();
    let request = nt_alpc_abi::AlpcCloseCreatedPortRequest {
        abi_size: core::mem::size_of::<nt_alpc_abi::AlpcCloseCreatedPortRequest>() as u16,
        handle: identity.service_handle,
        owner_process: identity.owner_process as u64,
        owner_thread: thread,
        owner_generation: identity.owner_generation,
        invocation_hi: identity.invocation_hi,
        invocation_lo: identity.invocation_lo,
        ..Default::default()
    };
    *slot = Some(OwnedClose { close, request, thread, reply_cap,
        flight: Flight::Ready, status: 0, reply_attempted: false });
    park.commit();
    Ok(())
}

enum Step { Idle, NoEffect(i32), Exact(i32), Uncertain(u64) }

unsafe fn retire(handler: &mut ExecNtHandler) {
    let owner = (&mut *core::ptr::addr_of_mut!(OWNED_CLOSE)).take()
        .expect("ALPC close Reply owner disappeared");
    thread_wait_state_clear_tid_ready(handler, owner.thread);
    release_reply_pool_cap(owner.reply_cap);
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    let slot = &mut *core::ptr::addr_of_mut!(OWNED_CLOSE);
    let Some(owner) = slot.as_mut() else { return };
    if matches!(owner.flight, Flight::ReplyIndeterminate) {
        let cap = owner.reply_cap;
        if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap)
            && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(cap), Ok(true))
        { retire(handler); }
        return;
    }
    if matches!(owner.flight, Flight::InvalidTerminal) { return; }
    let step = {
        let Some(client) = lpc_client() else { return };
        let channel = &mut client.backend_mut().0;
        match owner.flight {
            Flight::Ready if channel.completion_inbox.active_request().is_some() => Step::Idle,
            Flight::Ready => {
                let opcode = match owner.close.identity().kind {
                    nt_process::native_alpc_port::AlpcPortKind::Created =>
                        nt_alpc_abi::opcode::ALPC_OP_CLOSE_CREATED_PORT,
                    nt_process::native_alpc_port::AlpcPortKind::Later =>
                        nt_alpc_abi::opcode::ALPC_OP_CLOSE_LATER_PORT,
                };
                match channel.raw_owned(opcode, bytemuck::bytes_of(&owner.request), &mut []) {
                    RingCallOutcome::NoEffect(status) => Step::NoEffect(status),
                    RingCallOutcome::Completed(status, _, _, _, _) => Step::Exact(status),
                    RingCallOutcome::Indeterminate { request_id } => Step::Uncertain(request_id),
                }
            }
            Flight::Submitted(request_id) => match channel.poll_owned(request_id, &mut []) {
                Some((status, _, _, _, _)) => Step::Exact(status),
                None => Step::Idle,
            },
            Flight::ReplyReady | Flight::ReplyIndeterminate | Flight::InvalidTerminal => Step::Idle,
        }
    };
    match step {
        Step::Idle => {}
        Step::Uncertain(request_id) => owner.flight = Flight::Submitted(request_id),
        Step::NoEffect(0) => owner.flight = Flight::InvalidTerminal,
        Step::NoEffect(status) | Step::Exact(status) => {
            owner.flight = if owner.close.reconcile(&mut handler.pm, Some(status))
                == Ok(Some(status)) {
                if status == 0 && owner.close.identity().kind
                    == nt_process::native_alpc_port::AlpcPortKind::Created {
                    handler.native_alpc_secured_ports.retire(owner.close.identity().service_handle);
                }
                owner.status = status;
                Flight::ReplyReady
            } else { Flight::InvalidTerminal };
        }
    }
    if matches!(owner.flight, Flight::ReplyReady) {
        if owner.reply_attempted { owner.flight = Flight::InvalidTerminal; return; }
        owner.reply_attempted = true;
        let cap = owner.reply_cap;
        if reply_parked_syscall(cap, owner.status as u64)
            || (spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap)
                && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(cap), Ok(true)))
        { retire(handler); } else { owner.flight = Flight::ReplyIndeterminate; }
    }
}
