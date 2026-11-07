//! Retained native ConnectPort and AcceptConnectPort service exchanges.
//!
//! The original Reply, physical caller, copied message, invisible process
//! handle, and exact checked token survive pending/uncertain service effects.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_alpc_native_later::{CapturedAcceptConnect, CapturedConnectPort, NativeCaller,
    RetainedLater, TerminalLater};
use nt_process::native_alpc_port::NativeAlpcPortPublication;

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
const PORT_MESSAGE_SIZE: usize = core::mem::size_of::<nt_alpc_abi::PortMessage>();

static NEXT_INVOCATION: AtomicU64 = AtomicU64::new(1);
static DIAG_SERVICE_PENDING: AtomicU64 = AtomicU64::new(0);
static mut OWNERS: Vec<OwnedLater> = Vec::new();
static mut NEXT_OWNER: usize = 0;

enum Kind {
    Connect(CapturedConnectPort),
    Accept(CapturedAcceptConnect),
}

#[derive(Clone, Copy)]
enum Flight {
    Ready,
    Submitted(u64),
    KernelAcceptReady,
    KernelAcceptSubmitted(u64),
    ReverseConnectReady,
    ReverseConnectSubmitted(u64),
    TerminalReady,
    CloseReady,
    CloseSubmitted(u64),
    AckReady,
    AckSubmitted(u64),
    ReplyReady,
    ReplyIndeterminate,
    InvalidTerminal,
}

struct OwnedLater {
    pi: usize,
    kind: Kind,
    retained: RetainedLater,
    publication: Option<NativeAlpcPortPublication>,
    output: Vec<u8>,
    ack: nt_alpc_abi::AlpcAcknowledgeSendReceiveRequest,
    close: Option<nt_alpc_abi::AlpcCloseCreatedPortRequest>,
    flight: Flight,
    reply_status: i32,
    submitted_once: bool,
    kernel_listen: Option<u64>,
    kernel_connection_id: Option<u64>,
    kernel_client_handle: Option<u64>,
    srm_reserved: bool,
    kernel_cached: bool,
    reverse_request: Option<Vec<u8>>,
    reverse_failure: Option<i32>,
}

impl OwnedLater {
    fn caller(&self) -> NativeCaller { self.retained.caller() }
    fn opcode(&self) -> u16 {
        match &self.kind {
            Kind::Connect(_) => nt_alpc_abi::opcode::ALPC_OP_CONNECT_PORT,
            Kind::Accept(_) => nt_alpc_abi::opcode::ALPC_OP_ACCEPT_CONNECT,
        }
    }
    fn ack_opcode(&self) -> u16 {
        match &self.kind {
            Kind::Connect(_) => nt_alpc_abi::opcode::ALPC_OP_ACK_CONNECT_PORT,
            Kind::Accept(_) => nt_alpc_abi::opcode::ALPC_OP_ACK_ACCEPT_CONNECT,
        }
    }
    fn exact_caller_live(&self, handler: &ExecNtHandler) -> bool {
        let caller = self.caller();
        handler.pm_pid_for_pi(self.pi).map(u64::from) == Some(caller.process)
            && handler.hosted_process_generation(self.pi) == Some(caller.generation)
            && handler.hosted_thread_pi_for_badge(caller.badge) == Some(self.pi)
            && handler.hosted_thread_tid_for_badge(caller.badge) == Some(caller.thread)
            && handler.hosted_thread_tcb_for_badge(caller.badge) == Some(caller.tcb)
    }
    fn close_request(&self, handle: u64) -> nt_alpc_abi::AlpcCloseCreatedPortRequest {
        let caller = self.caller();
        let token = self.retained.token();
        nt_alpc_abi::AlpcCloseCreatedPortRequest {
            abi_size: core::mem::size_of::<nt_alpc_abi::AlpcCloseCreatedPortRequest>() as u16,
            handle, owner_process: caller.process, owner_thread: caller.thread,
            owner_generation: caller.generation, invocation_hi: token.0,
            invocation_lo: token.1, ..Default::default()
        }
    }
    unsafe fn abort_publication(&mut self, handler: &mut ExecNtHandler) -> bool {
        let Some(publication) = self.publication.as_mut() else { return true };
        match publication.abort(&mut handler.pm) {
            Ok(Some(identity)) => {
                self.close = Some(self.close_request(identity.service_handle));
                true
            }
            Ok(None) => true,
            Err(_) => false,
        }
    }
    unsafe fn process_terminal(&mut self, handler: &mut ExecNtHandler) {
        let Some(result) = self.retained.terminal() else {
            self.flight = Flight::InvalidTerminal;
            return;
        };
        self.reply_status = result.status;
        if result.status != 0 {
            self.flight = if self.abort_publication(handler) { Flight::AckReady }
                else { Flight::InvalidTerminal };
            return;
        }
        if !self.exact_caller_live(handler) {
            self.reply_status = STATUS_INVALID_HANDLE as i32;
            self.flight = if self.abort_publication(handler) {
                if self.close.is_some() { Flight::CloseReady } else { Flight::AckReady }
            } else { Flight::InvalidTerminal };
            return;
        }
        let handle = result.detail0;
        if self.kernel_client_handle.is_some_and(|expected| expected != handle) {
            self.flight = Flight::InvalidTerminal;
            return;
        }
        let needs_port = !matches!(&self.kind, Kind::Accept(CapturedAcceptConnect { accept: false, .. }));
        if needs_port && handle == 0 {
            self.flight = Flight::InvalidTerminal;
            return;
        }
        if let Some(status) = self.reverse_failure {
            self.reply_status = status;
            self.flight = if self.abort_publication(handler) {
                self.close = Some(self.close_request(handle));
                Flight::CloseReady
            } else { Flight::InvalidTerminal };
            return;
        }
        if let Some(publication) = self.publication.as_mut() {
            if publication.bind(&mut handler.pm, handle).is_err() {
                self.flight = if self.abort_publication(handler) {
                    self.close = Some(self.close_request(handle));
                    Flight::CloseReady
                } else { Flight::InvalidTerminal };
                return;
            }
        }
        if let (Some(connection_id), Kind::Connect(captured)) =
            (self.kernel_connection_id, &self.kind)
        {
            if !handler.cache_lpc_connection_for_pi(connection_id, handle, self.pi,
                &captured.name)
            {
                self.reply_status = STATUS_INVALID_HANDLE as i32;
                self.flight = if self.abort_publication(handler) {
                    self.close = Some(self.close_request(handle));
                    Flight::CloseReady
                } else { Flight::InvalidTerminal };
                return;
            }
            self.kernel_cached = true;
        }
        let copied = match &self.kind {
            Kind::Connect(captured) => {
                let response_len = result.information as usize;
                if response_len > result.output.len() { false } else if let Some((message, capacity, size)) = captured.message_target {
                    if response_len > capacity.saturating_sub(PORT_MESSAGE_SIZE)
                        || response_len > u16::MAX as usize - PORT_MESSAGE_SIZE
                    { false } else if let Some(original) = captured.message.as_ref() {
                        let mut header = [0u8; PORT_MESSAGE_SIZE];
                        header.copy_from_slice(&original[..PORT_MESSAGE_SIZE]);
                        header[0..2].copy_from_slice(&(response_len as u16).to_le_bytes());
                        header[2..4].copy_from_slice(&((PORT_MESSAGE_SIZE + response_len) as u16).to_le_bytes());
                        handler.process_memory_write_status(self.pi, message, &header).is_ok()
                            && (response_len == 0 || message.checked_add(PORT_MESSAGE_SIZE as u64)
                                .is_some_and(|payload_address|
                                    handler.process_memory_write_status(self.pi,
                                        payload_address, &result.output[..response_len]).is_ok()))
                            && handler.process_memory_write_status(self.pi, size,
                                &((PORT_MESSAGE_SIZE + response_len) as u64).to_le_bytes()).is_ok()
                    } else { false }
                } else { response_len == 0 }
            }
            Kind::Accept(_) => result.information == 0,
        };
        let output_address = match &self.kind {
            Kind::Connect(captured) => captured.output,
            Kind::Accept(captured) => captured.output,
        };
        let visible_handle = self.publication.as_ref().map_or(0, |publication| publication.value());
        if !copied || handler.process_memory_write_status(self.pi, output_address,
            &visible_handle.to_le_bytes()).is_err()
            || self.publication.as_mut().is_some_and(|publication|
                publication.publish(&mut handler.pm).is_err())
        {
            if self.kernel_cached {
                handler.discard_lpc_connection_for_pi(handle, self.pi);
                self.kernel_cached = false;
            }
            self.reply_status = STATUS_ACCESS_VIOLATION as i32;
            self.flight = if self.abort_publication(handler) {
                if self.close.is_some() { Flight::CloseReady } else { Flight::AckReady }
            } else { Flight::InvalidTerminal };
        } else {
            self.flight = Flight::AckReady;
        }
    }
}

unsafe fn caller(handler: &ExecNtHandler) -> Result<NativeCaller, u32> {
    if !handler.current_native_call_transport { return Err(STATUS_INVALID_PARAMETER); }
    let pi = handler.pi;
    let badge = handler.current_badge;
    if handler.hosted_thread_pi_for_badge(badge) != Some(pi) { return Err(STATUS_INVALID_HANDLE); }
    let process = handler.pm_pid_for_pi(pi).ok_or(STATUS_INVALID_HANDLE)? as u64;
    let thread = handler.hosted_thread_tid_for_badge(badge)
        .filter(|tid| *tid != 0 && *tid == handler.current_tid).ok_or(STATUS_INVALID_HANDLE)?;
    let generation = handler.hosted_process_generation(pi)
        .filter(|generation| *generation != 0).ok_or(STATUS_INVALID_HANDLE)?;
    let tcb = handler.hosted_thread_tcb_for_badge(badge)
        .filter(|tcb| *tcb != 0).ok_or(STATUS_INVALID_HANDLE)?;
    Ok(NativeCaller { process, thread, generation, badge, tcb })
}

unsafe fn begin_owned(handler: &mut ExecNtHandler, caller: NativeCaller,
    kind: Kind, authorized_listen: Option<u64>, kernel_listen: Option<u64>) -> Result<(), u32> {
    let pi = handler.pi;
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    if owners.len() >= MAX_OWNERS || owners.iter().any(|owner| owner.caller() == caller) {
        return Err(STATUS_DEVICE_BUSY);
    }
    owners.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let sequence = NEXT_INVOCATION.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
        |next| next.checked_add(1)).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let token = (caller.generation, sequence);
    let request = match &kind {
        Kind::Connect(captured) => match authorized_listen {
            Some(listen) => captured.checked_wire_authorized(caller, token, listen)?,
            None => captured.checked_wire(caller, token)?,
        },
        Kind::Accept(captured) => captured.checked_wire(caller, token)?,
    };
    let reverse_request = if kernel_listen.is_some() {
        let name: Vec<u16> = "\\SeLsaCommandPort".encode_utf16().collect();
        let header_len = core::mem::size_of::<nt_lpc_abi::LpcKernelConnectNamedRequest>();
        let reverse = nt_lpc_abi::LpcKernelConnectNamedRequest {
            abi_size: header_len as u16,
            name_offset: header_len as u32,
            name_len_bytes: (name.len() * 2) as u32,
            server_process: caller.process,
            ..Default::default()
        };
        let mut wire = Vec::new();
        wire.try_reserve_exact(header_len + name.len() * 2)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        wire.extend_from_slice(bytemuck::bytes_of(&reverse));
        for unit in name { wire.extend_from_slice(&unit.to_le_bytes()); }
        Some(wire)
    } else { None };
    if request.len() > REP_DATA_LEN { return Err(STATUS_NOT_SUPPORTED); }
    let mut output = Vec::new();
    output.try_reserve_exact(REP_DATA_LEN).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    output.resize(REP_DATA_LEN, 0);
    let park = RootReplyPark::prepare().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let reply_cap = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let retained = RetainedLater::new(caller, token, reply_cap, request)
        .map_err(|_| STATUS_INVALID_PARAMETER)?;
    let handle_caller = handler.native_handle_caller(nt_syscall::ProcessorMode::UserMode)?;
    let publication = match &kind {
        Kind::Connect(_) | Kind::Accept(CapturedAcceptConnect { accept: true, .. }) =>
            Some(handler.pm.reserve_native_alpc_later_port_handle(handle_caller,
                caller.generation, token)?),
        Kind::Accept(_) => None,
    };
    let ack = nt_alpc_abi::AlpcAcknowledgeSendReceiveRequest {
        abi_size: core::mem::size_of::<nt_alpc_abi::AlpcAcknowledgeSendReceiveRequest>() as u16,
        invocation: nt_alpc_abi::AlpcCheckedInvocation {
            owner_process: caller.process, owner_thread: caller.thread,
            owner_generation: caller.generation, invocation_hi: token.0,
            invocation_lo: token.1,
        }, ..Default::default()
    };
    if kernel_listen.is_some() {
        crate::native_srm_command_work::reserve()?;
    }
    owners.push(OwnedLater { pi, kind, retained, publication, output, ack, close: None,
        flight: Flight::Ready, reply_status: 0, submitted_once: false,
        kernel_listen, kernel_connection_id: None, kernel_client_handle: None,
        srm_reserved: kernel_listen.is_some(), kernel_cached: false,
        reverse_request, reverse_failure: None });
    park.commit();
    Ok(())
}

pub(crate) unsafe fn begin_connect(handler: &mut ExecNtHandler,
    args: [u64; 11]) -> Result<(), u32> {
    if lpc_client().is_none() { return Err(STATUS_DEVICE_NOT_READY); }
    let caller = caller(handler)?;
    let handler_ptr: *mut ExecNtHandler = handler;
    let captured = nt_alpc_native_later::capture_connect_port(args,
        |address, out| {
            // The port name can live in an unresident, dynamically mapped SEC_IMAGE view.
            let pi = (*handler_ptr).pi;
            (*handler_ptr).process_memory_read_status(pi, address, out).is_ok()
        },
        |address, len| (*handler_ptr).probe_user_output(address, len))?;
    if handler.pi == 9 {
        print_str(b"[alpc-connect-diag] pi=9 tid="); print_u64(caller.thread);
        print_str(b" name=");
        for unit in captured.name.iter().take(64) {
            let byte = u8::try_from(*unit).unwrap_or(b'?');
            print_str(&[byte]);
        }
        print_str(b"\n");
    }
    if captured.timeout.is_some() || captured.send_attributes.is_some()
    { return Err(STATUS_NOT_SUPPORTED); }
    // A required server SID is an authorization condition on the exact
    // published listen object. Check its owner's primary token before any
    // connect is submitted, then bind admission to its service handle below.
    if let Some(server_sid) = captured.server_sid.as_deref() {
        let required = nt_security::Sid::from_native_bytes(server_sid)?;
        let port = handler.native_alpc_secured_ports.find(&captured.name)
            .ok_or(nt_security::STATUS_SERVER_SID_MISMATCH)?;
        let token = handler.pm.process_primary_token(port.owner_process)
            .and_then(|id| handler.token_store.get(id))
            .ok_or(nt_security::STATUS_SERVER_SID_MISMATCH)?;
        if token.user != required {
            return Err(nt_security::STATUS_SERVER_SID_MISMATCH);
        }
    }
    let authorized_listen = if let Some(port) = handler.native_alpc_secured_ports.find(&captured.name) {
        let process = u32::try_from(caller.process).map_err(|_| STATUS_INVALID_HANDLE)?;
        let thread = u32::try_from(caller.thread).map_err(|_| STATUS_INVALID_HANDLE)?;
        let primary = handler.pm.process_primary_token(process)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let client = handler.pm.thread_impersonation(thread)
            .map(|context| nt_security::SubjectClientIdentity {
                token: context.token, level: context.level,
            });
        let listen = port.listen_handle;
        let mut subject = nt_security::CapturedSubjectContext::capture(
            &mut handler.token_store, primary, client, caller.process)?;
        let decision = subject.resolve(&handler.token_store).and_then(|tokens|
            nt_security::authorize_port_connect(&tokens, &port.descriptor,
                nt_security::ProcessorMode::UserMode));
        subject.release(&mut handler.token_store)?;
        let decision = decision?;
        if !decision.granted() { return Err(decision.status); }
        Some(listen)
    } else { None };
    let registered = SRM_COMMAND_PORT_OBJECT_HANDLE.load(Ordering::Relaxed);
    let kernel_listen = (registered != 0
        && handler.lpc_port_handle_for_name16(&captured.name) == Some(registered))
        .then_some(registered);
    begin_owned(handler, caller, Kind::Connect(captured), authorized_listen, kernel_listen)
}

pub(crate) unsafe fn begin_accept(handler: &mut ExecNtHandler,
    args: [u64; 9]) -> Result<(), u32> {
    if handler.pi == 10 { print_str(b"[alpc-accept-diag] lsass ingress\n"); }
    if lpc_client().is_none() { return Err(STATUS_DEVICE_NOT_READY); }
    let caller = caller(handler)?;
    let mut connection_id = [0u8; 4];
    let id_address = args[6].checked_add(24).ok_or(STATUS_INVALID_PARAMETER)?;
    if !handler.xas_read(id_address, &mut connection_id) { return Err(STATUS_ACCESS_VIOLATION); }
    let handler_ptr: *mut ExecNtHandler = handler;
    let mut captured = nt_alpc_native_later::capture_accept_connect(args,
        u32::from_le_bytes(connection_id),
        |address, out| (*handler_ptr).xas_read(address, out),
        |address, len| (*handler_ptr).probe_user_output(address, len))?;
    if handler.pi == 10 { print_str(b"[alpc-accept-diag] captured id="); print_hex(captured.connection_id); print_str(b"\n"); }
    let handle_caller = handler.native_handle_caller(nt_syscall::ProcessorMode::UserMode)?;
    let listen = handler.pm.lookup_native_alpc_port(handle_caller,
        captured.listen_port, caller.generation)?;
    if u64::from(listen.owner_process) != caller.process { return Err(STATUS_INVALID_HANDLE); }
    captured.listen_port = listen.service_handle;
    begin_owned(handler, caller, Kind::Accept(captured), None, None)
}

enum Step {
    Idle,
    NoEffect(u64, i32),
    Exact(u64, i32, u64, u64, u64),
    Uncertain(u64),
    KernelAcceptNoEffect(i32),
    KernelAcceptExact(i32, u64, u64),
    KernelAcceptUncertain(u64),
    ReverseConnectNoEffect(i32),
    ReverseConnectExact(i32, u64, u64),
    ReverseConnectUncertain(u64),
    CloseNoEffect,
    CloseExact(i32),
    CloseUncertain(u64),
    AckNoEffect,
    AckExact(i32),
    AckUncertain(u64),
}

fn selected(owners: &[OwnedLater], active: Option<u64>, cursor: usize) -> Option<usize> {
    if let Some(id) = active {
        return owners.iter().position(|owner| matches!(owner.flight,
            Flight::Submitted(request) | Flight::KernelAcceptSubmitted(request)
                | Flight::ReverseConnectSubmitted(request)
                | Flight::CloseSubmitted(request)
                | Flight::AckSubmitted(request) if request == id));
    }
    if let Some((index, _)) = owners.iter().enumerate()
        .filter(|(_, owner)| !owner.submitted_once && matches!(owner.flight, Flight::Ready))
        .min_by_key(|(_, owner)| owner.retained.token().1)
    { return Some(index); }
    if owners.is_empty() { return None; }
    (0..owners.len()).map(|offset| (cursor + offset) % owners.len())
        .find(|index| !matches!(owners[*index].flight, Flight::InvalidTerminal))
}

unsafe fn retire(owner: OwnedLater, handler: &mut ExecNtHandler) {
    if owner.srm_reserved {
        crate::native_srm_command_work::cancel_reservation();
    }
    let cap = owner.retained.reply_cap();
    let thread = owner.caller().thread;
    assert!(owner.retained.finish_after_reply(true).is_ok());
    thread_wait_state_clear_tid_ready(handler, thread);
    release_reply_pool_cap(cap);
}

pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    if owners.is_empty() { return; }
    let active = match lpc_client() {
        Some(client) => client.backend_mut().0.completion_inbox.active_request(),
        None => return,
    };
    let cursor = *core::ptr::addr_of!(NEXT_OWNER);
    let Some(index) = selected(owners, active, cursor) else { return };
    *core::ptr::addr_of_mut!(NEXT_OWNER) = cursor.wrapping_add(1);
    let mut owner = owners.swap_remove(index);
    if matches!(owner.flight, Flight::ReplyIndeterminate) {
        let cap = owner.retained.reply_cap();
        if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap)
            && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(cap), Ok(true))
        { retire(owner, handler); } else { owners.push(owner); }
        return;
    }
    if matches!(owner.flight, Flight::TerminalReady) {
        owner.process_terminal(handler);
        owners.push(owner);
        return;
    }
    let step = {
        let Some(client) = lpc_client() else { owners.push(owner); return };
        let channel = &mut client.backend_mut().0;
        if channel.completion_inbox.active_request().is_some()
            && matches!(owner.flight, Flight::Ready | Flight::KernelAcceptReady
                | Flight::ReverseConnectReady
                | Flight::CloseReady | Flight::AckReady)
        { owners.push(owner); return; }
        match owner.flight {
            Flight::Ready => {
                let id = channel.next_id;
                if owner.retained.begin(id).is_err() {
                    owner.flight = Flight::InvalidTerminal;
                    Step::Idle
                } else {
                    owner.submitted_once = true;
                    owner.output.fill(0);
                    match channel.raw_owned(owner.opcode(), owner.retained.request(), &mut owner.output) {
                        RingCallOutcome::NoEffect(status) => Step::NoEffect(id, status),
                        RingCallOutcome::Completed(status, _, info, d0, d1) =>
                            Step::Exact(id, status, info, d0, d1),
                        RingCallOutcome::Indeterminate { request_id } => {
                            assert_eq!(request_id, id); Step::Uncertain(id)
                        }
                    }
                }
            }
            Flight::Submitted(id) => match channel.poll_owned(id, &mut owner.output) {
                Some((status, _, info, d0, d1)) => Step::Exact(id, status, info, d0, d1),
                None => Step::Idle,
            },
            Flight::KernelAcceptReady => {
                let Some(listen_port) = owner.kernel_listen else {
                    owner.flight = Flight::InvalidTerminal; owners.push(owner); return;
                };
                let Some(connection_id) = owner.kernel_connection_id else {
                    owner.flight = Flight::InvalidTerminal; owners.push(owner); return;
                };
                let caller = owner.caller();
                let request = nt_lpc_abi::LpcKernelAcceptConnectRequest {
                    abi_size: core::mem::size_of::<nt_lpc_abi::LpcKernelAcceptConnectRequest>() as u16,
                    listen_port, connection_id, client_process: caller.process,
                    client_thread: caller.thread, ..Default::default()
                };
                let id = channel.next_id;
                match channel.raw_owned(nt_lpc_abi::opcode::LPC_OP_KERNEL_ACCEPT_CONNECT,
                    bytemuck::bytes_of(&request), &mut []) {
                    RingCallOutcome::NoEffect(status) => Step::KernelAcceptNoEffect(status),
                    RingCallOutcome::Completed(status, _, _, d0, d1) =>
                        Step::KernelAcceptExact(status, d0, d1),
                    RingCallOutcome::Indeterminate { request_id } => {
                        assert_eq!(request_id, id); Step::KernelAcceptUncertain(id)
                    }
                }
            }
            Flight::KernelAcceptSubmitted(id) => match channel.poll_owned(id, &mut []) {
                Some((status, _, _, d0, d1)) => Step::KernelAcceptExact(status, d0, d1),
                None => Step::Idle,
            },
            Flight::ReverseConnectReady => {
                if !owner.exact_caller_live(handler) {
                    owner.reverse_failure = Some(STATUS_INVALID_HANDLE as i32);
                    owner.flight = Flight::Ready;
                    owners.push(owner);
                    return;
                }
                let Some(request) = owner.reverse_request.as_deref() else {
                    owner.flight = Flight::InvalidTerminal; owners.push(owner); return;
                };
                let id = channel.next_id;
                match channel.raw_owned(nt_lpc_abi::opcode::LPC_OP_KERNEL_CONNECT_NAMED,
                    request, &mut []) {
                    RingCallOutcome::NoEffect(status) => Step::ReverseConnectNoEffect(status),
                    RingCallOutcome::Completed(status, _, _, d0, d1) =>
                        Step::ReverseConnectExact(status, d0, d1),
                    RingCallOutcome::Indeterminate { request_id } => {
                        assert_eq!(request_id, id); Step::ReverseConnectUncertain(id)
                    }
                }
            }
            Flight::ReverseConnectSubmitted(id) => match channel.poll_owned(id, &mut []) {
                Some((status, _, _, d0, d1)) => Step::ReverseConnectExact(status, d0, d1),
                None => Step::Idle,
            },
            Flight::CloseReady => {
                let Some(request) = owner.close else { owner.flight = Flight::InvalidTerminal;
                    owners.push(owner); return };
                let id = channel.next_id;
                match channel.raw_owned(nt_alpc_abi::opcode::ALPC_OP_CLOSE_LATER_PORT,
                    bytemuck::bytes_of(&request), &mut []) {
                    RingCallOutcome::NoEffect(_) => Step::CloseNoEffect,
                    RingCallOutcome::Completed(status, _, _, _, _) => Step::CloseExact(status),
                    RingCallOutcome::Indeterminate { request_id } => {
                        assert_eq!(request_id, id); Step::CloseUncertain(id)
                    }
                }
            }
            Flight::CloseSubmitted(id) => match channel.poll_owned(id, &mut []) {
                Some((status, _, _, _, _)) => Step::CloseExact(status),
                None => Step::Idle,
            },
            Flight::AckReady => {
                let id = channel.next_id;
                match channel.raw_owned(owner.ack_opcode(), bytemuck::bytes_of(&owner.ack), &mut []) {
                    RingCallOutcome::NoEffect(_) => Step::AckNoEffect,
                    RingCallOutcome::Completed(status, _, _, _, _) => Step::AckExact(status),
                    RingCallOutcome::Indeterminate { request_id } => {
                        assert_eq!(request_id, id); Step::AckUncertain(id)
                    }
                }
            }
            Flight::AckSubmitted(id) => match channel.poll_owned(id, &mut []) {
                Some((status, _, _, _, _)) => Step::AckExact(status),
                None => Step::Idle,
            },
            Flight::ReplyReady | Flight::ReplyIndeterminate | Flight::InvalidTerminal
                | Flight::TerminalReady => Step::Idle,
        }
    };
    match step {
        Step::Idle | Step::CloseNoEffect | Step::AckNoEffect => {}
        Step::NoEffect(id, status) => {
            owner.flight = if owner.retained.no_effect(id, owner.caller(), status).is_ok()
                && owner.abort_publication(handler) { Flight::ReplyReady }
                else { Flight::InvalidTerminal };
            owner.reply_status = status;
        }
        Step::Exact(id, status, info, d0, d1) => {
            let caller = owner.caller();
            if owner.pi == 9 && caller.thread > 300
                && (status != STATUS_PENDING
                    || DIAG_SERVICE_PENDING.fetch_add(1, Ordering::Relaxed) < 16) {
                print_str(b"[alpc-connect-diag] terminal tid="); print_u64(caller.thread);
                print_str(b" status="); print_hex(status as u32);
                print_str(b" info="); print_hex_u64(info);
                print_str(b" d0="); print_hex_u64(d0);
                print_str(b" d1="); print_hex_u64(d1);
                print_str(b"\n");
            }
            if status == STATUS_PENDING && matches!(&owner.kind, Kind::Connect(_)) {
                owner.flight = if owner.retained.continue_pending(id, caller).is_ok() {
                    if owner.kernel_listen.is_some() {
                        if d1 == 0 || owner.kernel_connection_id.is_some_and(|seen| seen != d1) {
                            Flight::InvalidTerminal
                        } else {
                            owner.kernel_connection_id = Some(d1);
                            Flight::KernelAcceptReady
                        }
                    } else { Flight::Ready }
                } else { Flight::InvalidTerminal };
            } else if let Ok(info) = u32::try_from(info) {
                if info as usize > owner.output.len() { owner.flight = Flight::InvalidTerminal; }
                else {
                    let mut output = core::mem::take(&mut owner.output);
                    output.truncate(info as usize);
                    owner.flight = if owner.retained.complete(id, caller,
                        TerminalLater::service(status, info, d0, d1, output)).is_ok()
                    { Flight::TerminalReady } else { Flight::InvalidTerminal };
                }
            } else { owner.flight = Flight::InvalidTerminal; }
        }
        Step::Uncertain(id) => owner.flight = Flight::Submitted(id),
        Step::KernelAcceptNoEffect(_) => owner.flight = Flight::KernelAcceptReady,
        Step::KernelAcceptExact(status, client_handle, server_handle) => {
            owner.flight = if status == STATUS_PENDING {
                Flight::KernelAcceptReady
            } else if status == 0 && client_handle != 0 && server_handle != 0 {
                let caller = owner.caller();
                crate::native_srm_command_work::register(owner.pi, caller.process,
                    caller.generation, owner.kernel_connection_id.unwrap(), server_handle);
                owner.srm_reserved = false;
                owner.kernel_client_handle = Some(client_handle);
                Flight::ReverseConnectReady
            } else {
                Flight::InvalidTerminal
            };
        }
        Step::KernelAcceptUncertain(id) => owner.flight = Flight::KernelAcceptSubmitted(id),
        Step::ReverseConnectNoEffect(status) => {
            owner.reverse_failure = Some(status);
            owner.flight = Flight::Ready;
        }
        Step::ReverseConnectExact(status, handle, connection_id) => {
            owner.flight = if status == STATUS_PENDING && handle == 0 && connection_id != 0
                && handler.stage_lpc_connection_views(connection_id, 0, 0,
                    SyscallUserMemory::CurrentProcess, None, None).is_ok()
            {
                LSASS_SRM_CONNECTED.store(1, Ordering::Relaxed);
                Flight::Ready
            } else if status != 0 && status != STATUS_PENDING && handle == 0
                && connection_id == 0
            {
                owner.reverse_failure = Some(status);
                Flight::Ready
            } else { Flight::InvalidTerminal };
        }
        Step::ReverseConnectUncertain(id) => owner.flight = Flight::ReverseConnectSubmitted(id),
        Step::CloseExact(status) => {
            owner.flight = if status == 0 { Flight::AckReady } else { Flight::InvalidTerminal };
        }
        Step::CloseUncertain(id) => owner.flight = Flight::CloseSubmitted(id),
        Step::AckExact(status) => {
            owner.flight = if status == 0 { Flight::ReplyReady } else { Flight::InvalidTerminal };
        }
        Step::AckUncertain(id) => owner.flight = Flight::AckSubmitted(id),
    }
    if matches!(owner.flight, Flight::InvalidTerminal) && owner.srm_reserved {
        crate::native_srm_command_work::cancel_reservation();
        owner.srm_reserved = false;
    }
    if matches!(owner.flight, Flight::ReplyReady) {
        if owner.retained.begin_reply().is_err() { owner.flight = Flight::InvalidTerminal; }
        else {
            let cap = owner.retained.reply_cap();
            if reply_parked_syscall(cap, owner.reply_status as u64)
                || (spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap)
                    && matches!(spawn_hosts::shared_ingress::owner::runtime::finish_acknowledged_hosted_reply(cap), Ok(true)))
            { retire(owner, handler); return; }
            owner.flight = Flight::ReplyIndeterminate;
        }
    }
    owners.push(owner);
}
