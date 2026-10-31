//! Retained native NtAlpcSendWaitReceivePort calls over the checked ALPC service.
//!
//! Each entry owns its original Reply, copied request, physical caller, and
//! output until an exact terminal CQE, service-record ACK, and Reply delivery.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_alpc_native_later::{NativeCaller, ReceiveTarget, RetainedLater, TerminalLater};
use nt_alpc_native_later::redrive_selection::{select_redrive_owner, RedriveOwner, RedrivePhase};
use nt_alpc_native_later::reply_commit::ReplyCommitGate;

use crate::root_reply_park::RootReplyPark;
use crate::*;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_DEVICE_NOT_READY: u32 = 0xC000_00A3;
const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_PENDING: i32 = 0x0000_0103;
const MAX_OWNERS: usize = 64;

static NEXT_INVOCATION: AtomicU64 = AtomicU64::new(1);
static DIAG_LSASS_PENDING: AtomicU64 = AtomicU64::new(0);
static mut OWNERS: Vec<OwnedReceive> = Vec::new();
static mut NEXT_OWNER: usize = 0;

#[derive(Clone, Copy)]
enum Flight {
    Ready,
    Submitted(u64),
    AckReady,
    AckSubmitted(u64),
    ReplyReady,
    ReplyIndeterminate,
    InvalidTerminal,
}

struct OwnedReceive {
    pi: usize,
    target: ReceiveTarget,
    retained: RetainedLater,
    output: Vec<u8>,
    ack: nt_alpc_abi::AlpcAcknowledgeSendReceiveRequest,
    flight: Flight,
    reply_status: i32,
    copyout_done: bool,
    submitted_once: bool,
    reply_commit: ReplyCommitGate,
    trace_scm: bool,
    logged_pending: bool,
}

impl OwnedReceive {
    fn caller(&self) -> NativeCaller { self.retained.caller() }

    fn exact_caller_live(&self, handler: &ExecNtHandler) -> bool {
        let caller = self.caller();
        handler.pm_pid_for_pi(self.pi).map(u64::from) == Some(caller.process)
            && handler.hosted_process_generation(self.pi) == Some(caller.generation)
            && handler.hosted_thread_pi_for_badge(caller.badge) == Some(self.pi)
            && handler.hosted_thread_tid_for_badge(caller.badge) == Some(caller.thread)
            && handler.hosted_thread_tcb_for_badge(caller.badge) == Some(caller.tcb)
    }

    unsafe fn copyout(&mut self, handler: &mut ExecNtHandler) {
        if self.copyout_done { return; }
        self.copyout_done = true;
        if self.reply_status != 0 { return; }
        if !self.exact_caller_live(handler) {
            self.reply_status = STATUS_INVALID_HANDLE as i32;
            return;
        }
        let Some(terminal) = self.retained.terminal() else {
            self.flight = Flight::InvalidTerminal;
            return;
        };
        let count = terminal.information as usize;
        if count > terminal.output.len() {
            self.flight = Flight::InvalidTerminal;
            return;
        }
        let attr_len = if let Some((_, allocated)) = self.target.attributes {
            if count < 8 {
                self.flight = Flight::InvalidTerminal;
                return;
            }
            let seen_allocated = u32::from_le_bytes(terminal.output[..4].try_into().unwrap());
            let valid = u32::from_le_bytes(terminal.output[4..8].try_into().unwrap());
            if seen_allocated != allocated || valid & !allocated != 0 {
                self.flight = Flight::InvalidTerminal;
                return;
            }
            if valid == 0 { 8 } else if valid == 0x2000_0000 { 40 } else {
                self.flight = Flight::InvalidTerminal;
                return;
            }
        } else { 0 };
        let message_len = count.saturating_sub(attr_len);
        if count < attr_len + core::mem::size_of::<nt_alpc_abi::PortMessage>()
            || message_len > self.target.capacity
        {
            self.flight = Flight::InvalidTerminal;
            return;
        }
        if self.target.attributes.is_some_and(|(pointer, _)|
            handler.process_memory_write_status(self.pi, pointer,
                &terminal.output[..attr_len]).is_err())
            || handler.process_memory_write_status(self.pi, self.target.message,
                &terminal.output[attr_len..count]).is_err()
            || handler.process_memory_write_status(self.pi, self.target.size_pointer,
                &(message_len as u64).to_le_bytes()).is_err()
        {
            self.reply_status = STATUS_ACCESS_VIOLATION as i32;
        }
    }
}

/// Return only after ownership of the original Reply was installed. Every
/// unsupported shape is rejected before a port-service effect or Reply park.
pub(crate) unsafe fn begin(handler: &mut ExecNtHandler, args: [u64; 8]) -> Result<(), u32> {
    if lpc_client().is_none() { return Err(STATUS_DEVICE_NOT_READY); }
    if !handler.current_native_call_transport { return Err(STATUS_INVALID_PARAMETER); }
    let pi = handler.pi;
    let badge = handler.current_badge;
    if handler.hosted_thread_pi_for_badge(badge) != Some(pi) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let process = handler.pm_pid_for_pi(pi).ok_or(STATUS_INVALID_HANDLE)? as u64;
    let thread = handler.hosted_thread_tid_for_badge(badge)
        .filter(|tid| *tid != 0 && *tid == handler.current_tid)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let generation = handler.hosted_process_generation(pi)
        .filter(|generation| *generation != 0).ok_or(STATUS_INVALID_HANDLE)?;
    let tcb = handler.hosted_thread_tcb_for_badge(badge)
        .filter(|tcb| *tcb != 0).ok_or(STATUS_INVALID_HANDLE)?;
    let caller = NativeCaller { process, thread, generation, badge, tcb };
    let handler_ptr: *mut ExecNtHandler = handler;
    let mut captured = nt_alpc_native_later::capture_send_wait_receive(
        args,
        |address, out| (*handler_ptr).xas_read(address, out),
        |address, len| (*handler_ptr).probe_user_output(address, len),
    )?;
    if captured.timeout.is_some() || captured.receive.is_none() {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let target_capacity = captured.receive.as_ref().ok_or(STATUS_NOT_SUPPORTED)?.capacity;
    if target_capacity > REP_DATA_LEN { return Err(STATUS_NOT_SUPPORTED); }
    let handle_caller = handler.native_handle_caller(nt_syscall::ProcessorMode::UserMode)?;
    let port = handler.pm.lookup_native_alpc_port(handle_caller, captured.port, generation)?;
    if u64::from(port.owner_process) != process { return Err(STATUS_INVALID_HANDLE); }
    let trace_scm = handler.hosted_process_image(pi).is_some_and(|image| {
        image.generation == generation
            && image.process_name.eq_ignore_ascii_case("services.exe")
    });
    let native_port = captured.port;
    let sequence = NEXT_INVOCATION.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
        |next| next.checked_add(1)).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    if trace_scm {
        print_str(b"[scm-alpc] begin tid="); print_u64(thread);
        print_str(b" invocation="); print_u64(sequence);
        print_str(b" port="); print_hex_u64(native_port);
        print_str(b" service-port="); print_hex_u64(port.service_handle);
        print_str(b" flags="); print_hex(captured.flags);
        if let Some(message) = captured.send_message.as_deref() {
            print_str(b" send-len="); print_u64(message.len() as u64);
            if message.len() >= 40 {
                print_str(b" type="); print_hex(u16::from_le_bytes([message[4], message[5]]) as u32);
                print_str(b" message-id="); print_hex(u32::from_le_bytes(message[24..28].try_into().unwrap()));
                if message.len() >= 52 {
                    print_str(b" api-number="); print_hex(u32::from_le_bytes(message[48..52].try_into().unwrap()));
                }
            }
        }
        print_str(b"\n");
    }
    captured.port = port.service_handle;
    let token = (generation, sequence);
    let reply_commit = ReplyCommitGate::new(captured.flags, token);
    let (request, target) = captured.into_checked_wire_and_receive(caller, token)?;
    if request.len() > REP_DATA_LEN { return Err(STATUS_NOT_SUPPORTED); }
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    if owners.len() >= MAX_OWNERS
        || owners.iter().any(|owner| owner.caller() == caller)
    { return Err(STATUS_DEVICE_BUSY); }
    owners.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let mut output = Vec::new();
    let output_capacity = target.capacity.checked_add(if target.attributes.is_some() { 40 } else { 0 })
        .filter(|capacity| *capacity <= REP_DATA_LEN).ok_or(STATUS_NOT_SUPPORTED)?;
    output.try_reserve_exact(output_capacity).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    output.resize(output_capacity, 0);
    let park = RootReplyPark::prepare().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let reply_cap = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let retained = RetainedLater::new(caller, token, reply_cap, request)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let ack = nt_alpc_abi::AlpcAcknowledgeSendReceiveRequest {
        abi_size: core::mem::size_of::<nt_alpc_abi::AlpcAcknowledgeSendReceiveRequest>() as u16,
        invocation: nt_alpc_abi::AlpcCheckedInvocation {
            owner_process: process, owner_thread: thread, owner_generation: generation,
            invocation_hi: token.0, invocation_lo: token.1,
        },
        ..Default::default()
    };
    owners.push(OwnedReceive { pi, target, retained, output, ack,
        flight: Flight::Ready, reply_status: 0, copyout_done: false,
        submitted_once: false, reply_commit, trace_scm, logged_pending: false });
    park.commit();
    Ok(())
}

enum RingStep {
    Idle,
    NoEffect(u64, i32),
    Exact(u64, i32, u64, u64, u64),
    Uncertain(u64),
    AckNoEffect,
    AckExact(i32),
    AckUncertain(u64),
}

fn selected_owner(owners: &[OwnedReceive], active: Option<u64>, cursor: usize) -> Option<usize> {
    select_redrive_owner(owners.len(), active, cursor, |index| {
        let owner = &owners[index];
        let phase = match owner.flight {
            Flight::Ready => RedrivePhase::Ready,
            Flight::Submitted(id) => RedrivePhase::Submitted(id),
            Flight::AckReady => RedrivePhase::AckReady,
            Flight::AckSubmitted(id) => RedrivePhase::AckSubmitted(id),
            Flight::ReplyReady => RedrivePhase::ReplyReady,
            Flight::ReplyIndeterminate => RedrivePhase::ReplyIndeterminate,
            Flight::InvalidTerminal => RedrivePhase::InvalidTerminal,
        };
        RedriveOwner { phase, submitted_once: owner.submitted_once,
            token_sequence: owner.retained.token().1 }
    })
}

unsafe fn retire(owner: OwnedReceive, handler: &mut ExecNtHandler) {
    let cap = owner.retained.reply_cap();
    let thread = owner.caller().thread;
    assert!(owner.retained.finish_after_reply(true).is_ok(),
        "acknowledged native ALPC Reply must be terminal");
    thread_wait_state_clear_tid_ready(handler, thread);
    release_reply_pool_cap(cap);
}

/// Advance one exact CQE or SQE per service-loop pass. The service terminal
/// record is ACKed before user memory copyout or the one physical Reply attempt.
pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) -> Option<(u64, u64)> {
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    if owners.is_empty() { return None; }
    let active = match lpc_client() {
        Some(client) => client.backend_mut().0.completion_inbox.active_request(),
        None => return None,
    };
    let cursor = *core::ptr::addr_of!(NEXT_OWNER);
    let Some(index) = selected_owner(owners, active, cursor) else { return None };
    *core::ptr::addr_of_mut!(NEXT_OWNER) = cursor.wrapping_add(1);
    let mut owner = owners.swap_remove(index);
    if matches!(owner.flight, Flight::ReplyIndeterminate) {
        let cap = owner.retained.reply_cap();
        if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap)
            && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(cap), Ok(true))
        { retire(owner, handler); } else { owners.push(owner); }
        return None;
    }
    let mut reply_committed = None;
    let step = {
        let Some(client) = lpc_client() else { owners.push(owner); return None };
        let channel = &mut client.backend_mut().0;
        match owner.flight {
            Flight::Ready => {
                let request_id = channel.next_id;
                if owner.retained.begin(request_id).is_err() {
                    owner.flight = Flight::InvalidTerminal;
                    RingStep::Idle
                } else {
                    owner.submitted_once = true;
                    owner.output.fill(0);
                    match channel.raw_owned(nt_alpc_abi::opcode::ALPC_OP_SEND_RECEIVE,
                        owner.retained.request(), &mut owner.output) {
                        RingCallOutcome::NoEffect(status) => RingStep::NoEffect(request_id, status),
                        RingCallOutcome::Completed(status, _, info, detail0, detail1) =>
                            RingStep::Exact(request_id, status, info, detail0, detail1),
                        RingCallOutcome::Indeterminate { request_id: observed } => {
                            assert_eq!(observed, request_id);
                            RingStep::Uncertain(request_id)
                        }
                    }
                }
            }
            Flight::Submitted(request_id) => match channel.poll_owned(request_id, &mut owner.output) {
                Some((status, _, info, detail0, detail1)) =>
                    RingStep::Exact(request_id, status, info, detail0, detail1),
                None => RingStep::Idle,
            },
            Flight::AckReady => {
                let request_id = channel.next_id;
                match channel.raw_owned(nt_alpc_abi::opcode::ALPC_OP_ACK_SEND_RECEIVE,
                    bytemuck::bytes_of(&owner.ack), &mut []) {
                    RingCallOutcome::NoEffect(_) => RingStep::AckNoEffect,
                    RingCallOutcome::Completed(status, _, _, _, _) => RingStep::AckExact(status),
                    RingCallOutcome::Indeterminate { request_id: observed } => {
                        assert_eq!(observed, request_id);
                        RingStep::AckUncertain(request_id)
                    }
                }
            }
            Flight::AckSubmitted(request_id) => match channel.poll_owned(request_id, &mut []) {
                Some((status, _, _, _, _)) => RingStep::AckExact(status),
                None => RingStep::Idle,
            },
            Flight::ReplyReady | Flight::ReplyIndeterminate | Flight::InvalidTerminal => RingStep::Idle,
        }
    };
    match step {
        RingStep::Idle | RingStep::AckNoEffect => {}
        RingStep::NoEffect(request_id, status) => {
            owner.flight = if owner.retained.no_effect(request_id, owner.caller(), status).is_ok()
                { Flight::ReplyReady } else { Flight::InvalidTerminal };
            owner.reply_status = status;
        }
        RingStep::Exact(request_id, status, info, detail0, detail1) => {
            let caller = owner.caller();
            if owner.trace_scm && (status != STATUS_PENDING || !owner.logged_pending) {
                print_str(b"[scm-alpc] terminal tid="); print_u64(caller.thread);
                print_str(b" invocation="); print_u64(owner.retained.token().1);
                print_str(b" status="); print_hex(status as u32);
                print_str(b" info="); print_hex_u64(info);
                print_str(b" detail0="); print_hex_u64(detail0);
                print_str(b" detail1="); print_hex_u64(detail1);
                print_str(b"\n");
                if status == STATUS_PENDING { owner.logged_pending = true; }
            }
            if owner.pi == 10
                && (status != STATUS_PENDING
                    || DIAG_LSASS_PENDING.fetch_add(1, Ordering::Relaxed) < 16) {
                print_str(b"[alpc-receive-diag] lsass tid="); print_u64(caller.thread);
                print_str(b" status="); print_hex(status as u32);
                print_str(b" info="); print_hex_u64(info);
                print_str(b" d0="); print_hex_u64(detail0);
                print_str(b" d1="); print_hex_u64(detail1);
                print_str(b"\n");
            }
            if status == STATUS_PENDING {
                owner.flight = if owner.retained.continue_pending(request_id, caller).is_ok() {
                    reply_committed = owner.reply_commit.service_exact(status);
                    Flight::Ready
                } else { Flight::InvalidTerminal };
            } else if let Ok(info) = u32::try_from(info) {
                if info as usize > owner.output.len() {
                    owner.flight = Flight::InvalidTerminal;
                } else {
                    let mut output = core::mem::take(&mut owner.output);
                    output.truncate(info as usize);
                    owner.flight = if owner.retained.complete(request_id, caller,
                        TerminalLater::service(status, info, detail0, detail1, output)).is_ok()
                    {
                        reply_committed = owner.reply_commit.service_exact(status);
                        Flight::AckReady
                    } else { Flight::InvalidTerminal };
                    owner.reply_status = status;
                }
            } else { owner.flight = Flight::InvalidTerminal; }
        }
        RingStep::Uncertain(request_id) => owner.flight = Flight::Submitted(request_id),
        RingStep::AckExact(status) => {
            reply_committed = owner.reply_commit.ack_exact(status);
            owner.flight = if status == 0 { Flight::ReplyReady } else { Flight::InvalidTerminal };
        }
        RingStep::AckUncertain(request_id) => owner.flight = Flight::AckSubmitted(request_id),
    }
    if matches!(owner.flight, Flight::ReplyReady) {
        owner.copyout(handler);
        if matches!(owner.flight, Flight::ReplyReady) {
            if owner.retained.begin_reply().is_err() {
                owner.flight = Flight::InvalidTerminal;
            } else {
                let cap = owner.retained.reply_cap();
                if reply_parked_syscall(cap, owner.reply_status as u64)
                    || (spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap)
                        && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(cap), Ok(true)))
                { retire(owner, handler); return reply_committed; }
                owner.flight = Flight::ReplyIndeterminate;
            }
        }
    }
    owners.push(owner);
    reply_committed
}

/// A retained kernel LPC request can publish into the same PortCore inbox as a parked native
/// ALPC listener. Visit each owned receive through its existing exact ring/ACK state machine
/// before the executive blocks on a fresh ingress. Two passes allow a ready receive and its
/// terminal ACK to complete without waiting for an unrelated syscall or timer tick.
pub(crate) unsafe fn redrive_after_lpc_publish(handler: &mut ExecNtHandler) -> bool {
    let count = (&*core::ptr::addr_of!(OWNERS)).len().min(MAX_OWNERS);
    let mut reply_committed = false;
    for _ in 0..count.saturating_mul(2) {
        reply_committed |= redrive(handler).is_some();
    }
    reply_committed
}
