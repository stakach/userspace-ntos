//! Kernel ownership of native ALPC requests sent to `\SeRmCommandPort`.
//!
//! The accepted server communication endpoint is held independently of the
//! LSASS connect syscall. Broker receive, SRM state transition, and broker
//! reply are distinct effects; an uncertain ring submission is polled by its
//! original request ID and is never submitted again.

use core::mem::size_of;

use nt_lpc_abi::{opcode, LpcClosePortRequest, LpcDataMessageMetadata, LpcMessageRequest,
    LpcReceiveRequest, PORT_MESSAGE_MAX_LEN};
use nt_security::{LogonSessionRegistry, TokenStore};
use nt_srm_message::{decode_request, write_reply_fields, RequestReply};

use crate::*;

const MAX_OWNERS: usize = 8;
const RECEIVE_CAPACITY: usize = PORT_MESSAGE_MAX_LEN + size_of::<LpcDataMessageMetadata>();
const REPLY_CAPACITY: usize = size_of::<LpcMessageRequest>() + PORT_MESSAGE_MAX_LEN;
const STATUS_PENDING: i32 = 0x103;
const STATUS_DEVICE_BUSY: i32 = 0x8000_0011u32 as i32;

#[derive(Clone, Copy)]
enum Flight {
    ReadyReceive,
    ReceiveSubmitted(u64),
    ReplyReady,
    ReplySubmitted(u64),
    CloseReady,
    CloseSubmitted(u64),
    Fault,
}

struct Owner {
    process_index: usize,
    process: u64,
    generation: u64,
    connection_id: u64,
    server_handle: u64,
    receive_request: LpcReceiveRequest,
    receive: [u8; RECEIVE_CAPACITY],
    reply_request: [u8; REPLY_CAPACITY],
    reply_request_len: usize,
    close_request: LpcClosePortRequest,
    flight: Flight,
    fault_reported: bool,
}

static mut OWNERS: [Option<Owner>; MAX_OWNERS] = [const { None }; MAX_OWNERS];
static mut RESERVED: usize = 0;
static mut NEXT_OWNER: usize = 0;
static mut SESSIONS: Option<LogonSessionRegistry> = None;

/// Reserve capacity before the kernel accept effect can create a server endpoint.
pub(crate) unsafe fn reserve() -> Result<(), u32> {
    let owners = &*core::ptr::addr_of!(OWNERS);
    let reserved = &mut *core::ptr::addr_of_mut!(RESERVED);
    if owners.iter().filter(|owner| owner.is_some()).count() + *reserved >= MAX_OWNERS {
        return Err(nt_security::STATUS_ALLOTTED_SPACE_EXCEEDED);
    }
    *reserved += 1;
    Ok(())
}

pub(crate) unsafe fn cancel_reservation() {
    let reserved = &mut *core::ptr::addr_of_mut!(RESERVED);
    assert!(*reserved != 0);
    *reserved -= 1;
}

/// Transfer the exact accepted endpoint from the connect continuation.
pub(crate) unsafe fn register(
    process_index: usize,
    process: u64,
    generation: u64,
    connection_id: u64,
    server_handle: u64,
) {
    assert!(process != 0 && generation != 0 && connection_id != 0 && server_handle != 0);
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    let reserved = &mut *core::ptr::addr_of_mut!(RESERVED);
    assert!(*reserved != 0);
    assert!(!owners.iter().flatten().any(|owner| owner.connection_id == connection_id));
    let slot = owners.iter_mut().find(|owner| owner.is_none())
        .expect("reserved SRM endpoint slot disappeared");
    *slot = Some(Owner {
        process_index, process, generation, connection_id, server_handle,
        receive_request: LpcReceiveRequest {
            abi_size: size_of::<LpcReceiveRequest>() as u16,
            port_handle: server_handle, ..Default::default()
        },
        receive: [0; RECEIVE_CAPACITY],
        reply_request: [0; REPLY_CAPACITY], reply_request_len: 0,
        close_request: LpcClosePortRequest {
            abi_size: size_of::<LpcClosePortRequest>() as u16,
            port_handle: server_handle, ..Default::default()
        },
        flight: Flight::ReadyReceive, fault_reported: false,
    });
    *reserved -= 1;
}

/// The same domain transition is used by native ALPC and legacy LPC adapters.
pub(crate) unsafe fn apply_request(result: RequestReply, tokens: &TokenStore) -> u32 {
    if result.result_status != 0 {
        return result.result_status;
    }
    let sessions = (&mut *core::ptr::addr_of_mut!(SESSIONS))
        .get_or_insert_with(LogonSessionRegistry::new);
    match (result.api_number, result.luid) {
        (nt_srm_message::RM_AUDIT_SET_COMMAND, _) => 0,
        (nt_srm_message::RM_CREATE_LOGON_SESSION, Some(id)) =>
            sessions.create(luid(id)).err().unwrap_or(0),
        (nt_srm_message::RM_DELETE_LOGON_SESSION, Some(id)) =>
            sessions.delete(luid(id), tokens).err().unwrap_or(0),
        _ => nt_srm_message::STATUS_INVALID_PARAMETER,
    }
}

fn luid(value: u64) -> nt_security::Luid {
    nt_security::Luid { low: value as u32, high: (value >> 32) as u32 as i32 }
}

impl Owner {
    fn capture_request(&mut self, handler: &mut ExecNtHandler, information: u64,
        detail0: u64, detail1: u64) -> bool {
        let Ok(count) = usize::try_from(information) else { return false };
        let metadata_len = size_of::<LpcDataMessageMetadata>();
        if count < metadata_len + nt_lpc_abi::PORT_MESSAGE_HEADER_LEN
            || count > self.receive.len()
            || detail1 as u16 != nt_lpc_abi::msg_type::LPC_REQUEST
        { return false; }
        let message_len = count - metadata_len;
        let Ok(meta) = bytemuck::try_pod_read_unaligned::<LpcDataMessageMetadata>(
            &self.receive[message_len..count]) else { return false };
        if usize::from(meta.abi_size) != metadata_len || meta._reserved != 0
            || meta._reserved2 != 0 || meta.connection_id != self.connection_id
            || meta.client_process != self.process || meta.port_context != detail0
            || meta.client_thread == 0
        { return false; }
        let message = &self.receive[..message_len];
        if nt_lpc_abi::port_message_total_length(message[..4].try_into().unwrap())
            != Some(message_len)
        { return false; }
        if message[4..6] != nt_lpc_abi::msg_type::LPC_REQUEST.to_le_bytes()
            || u64::from_le_bytes(message[8..16].try_into().unwrap()) != meta.client_process
            // The connection's opening thread can differ from the request's sending thread.
            || u64::from_le_bytes(message[16..24].try_into().unwrap()) == 0
            || u32::from_le_bytes(message[24..28].try_into().unwrap()) == 0
        { return false; }
        if message_len < nt_srm_message::REPLY_FIELDS_END { return false; }
        let Ok(mut command) = decode_request(message, PORT_MESSAGE_MAX_LEN) else {
            return false;
        };
        let header_len = size_of::<LpcMessageRequest>();
        let request = LpcMessageRequest {
            abi_size: header_len as u16,
            port_handle: self.server_handle,
            msg_offset: header_len as u32,
            msg_len_bytes: message_len as u32,
            ..Default::default()
        };
        self.reply_request[..header_len].copy_from_slice(bytemuck::bytes_of(&request));
        self.reply_request[header_len..header_len + message_len].copy_from_slice(message);
        command.result_status = unsafe { apply_request(command, &handler.token_store) };
        print_str(b"[srm-native] command="); print_u64(command.api_number as u64);
        print_str(b" conn="); print_u64(self.connection_id);
        print_str(b" status="); print_hex(command.result_status);
        print_str(b"\n");
        if write_reply_fields(&mut self.reply_request[header_len..header_len + message_len], command).is_err() {
            return false;
        }
        self.reply_request_len = header_len + message_len;
        true
    }
}

/// Progress one owner only when the shared broker ring can accept its exact
/// operation. Pending receives carry no effect; an indeterminate submission
/// always keeps its buffer and request identity until the matching CQE arrives.
pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    let Some(client) = lpc_client() else { return };
    let channel = &mut client.backend_mut().0;
    let active = channel.completion_inbox.active_request();
    let index = if let Some(id) = active {
        owners.iter().position(|slot| slot.as_ref().is_some_and(|owner|
            matches!(owner.flight, Flight::ReceiveSubmitted(seen)
                | Flight::ReplySubmitted(seen) | Flight::CloseSubmitted(seen) if seen == id)))
    } else {
        let cursor = *core::ptr::addr_of!(NEXT_OWNER);
        (0..MAX_OWNERS).map(|offset| (cursor + offset) % MAX_OWNERS)
            .find(|index| owners[*index].as_ref().is_some_and(|owner|
                !matches!(owner.flight, Flight::Fault)))
    };
    let Some(index) = index else { return };
    *core::ptr::addr_of_mut!(NEXT_OWNER) = (index + 1) % MAX_OWNERS;
    let owner = owners[index].as_mut().unwrap();
    if matches!(owner.flight, Flight::CloseReady) && owner.server_handle == 0 {
        owners[index] = None;
        return;
    }
    let stale = handler.hosted_process_generation(owner.process_index) != Some(owner.generation)
        || handler.pm_pid_for_pi(owner.process_index).map(u64::from) != Some(owner.process)
    ;
    if stale && matches!(owner.flight, Flight::ReadyReceive) {
        owner.flight = Flight::CloseReady;
    }
    match owner.flight {
        Flight::ReadyReceive => {
            let result = channel.raw_owned(opcode::LPC_OP_REPLY_WAIT_RECEIVE,
                bytemuck::bytes_of(&owner.receive_request), &mut owner.receive);
            settle_receive(owner, handler, result);
        }
        Flight::ReceiveSubmitted(id) => {
            if let Some((status, _flags, information, detail0, detail1)) =
                channel.poll_owned(id, &mut owner.receive)
            {
                if stale { owner.flight = Flight::CloseReady; }
                else { settle_receive(owner, handler, RingCallOutcome::Completed(status, 0,
                    information, detail0, detail1)); }
            }
        }
        Flight::ReplyReady => {
            let result = channel.raw_owned(opcode::LPC_OP_REPLY_PORT,
                &owner.reply_request[..owner.reply_request_len], &mut []);
            settle_reply(owner, result);
        }
        Flight::ReplySubmitted(id) => {
            if let Some((status, _, information, detail0, detail1)) =
                channel.poll_owned(id, &mut [])
            { settle_reply(owner, RingCallOutcome::Completed(status, 0,
                information, detail0, detail1)); }
        }
        Flight::CloseReady => {
            let result = channel.raw_owned(opcode::LPC_OP_CLOSE_PORT,
                bytemuck::bytes_of(&owner.close_request), &mut []);
            settle_close(owner, result);
        }
        Flight::CloseSubmitted(id) => {
            if let Some((status, _, information, detail0, detail1)) =
                channel.poll_owned(id, &mut [])
            { settle_close(owner, RingCallOutcome::Completed(status, 0,
                information, detail0, detail1)); }
        }
        Flight::Fault => {}
    }
    if matches!(owner.flight, Flight::Fault) && !owner.fault_reported {
        print_str(b"[srm-native] retained fault conn=");
        print_u64(owner.connection_id);
        print_str(b"\n");
        owner.fault_reported = true;
    }
}

fn settle_receive(owner: &mut Owner, handler: &mut ExecNtHandler, result: RingCallOutcome) {
    match result {
        RingCallOutcome::NoEffect(status) if status == STATUS_DEVICE_BUSY => {}
        RingCallOutcome::NoEffect(_) => owner.flight = Flight::Fault,
        RingCallOutcome::Indeterminate { request_id } =>
            owner.flight = Flight::ReceiveSubmitted(request_id),
        RingCallOutcome::Completed(STATUS_PENDING, _, _, _, _) =>
            owner.flight = Flight::ReadyReceive,
        RingCallOutcome::Completed(0, _, information, detail0, detail1) => {
            owner.flight = if owner.capture_request(handler, information, detail0, detail1) {
                Flight::ReplyReady
            } else { Flight::Fault };
        }
        RingCallOutcome::Completed(_, _, _, _, _) => owner.flight = Flight::CloseReady,
    }
}

fn settle_reply(owner: &mut Owner, result: RingCallOutcome) {
    match result {
        RingCallOutcome::NoEffect(status) if status == STATUS_DEVICE_BUSY => {}
        RingCallOutcome::NoEffect(_) => owner.flight = Flight::Fault,
        RingCallOutcome::Indeterminate { request_id } =>
            owner.flight = Flight::ReplySubmitted(request_id),
        RingCallOutcome::Completed(0, _, _, _, _) => {
            owner.reply_request_len = 0;
            owner.flight = Flight::ReadyReceive;
        }
        RingCallOutcome::Completed(_, _, _, _, _) => owner.flight = Flight::Fault,
    }
}

fn settle_close(owner: &mut Owner, result: RingCallOutcome) {
    match result {
        RingCallOutcome::NoEffect(status) if status == STATUS_DEVICE_BUSY => {}
        RingCallOutcome::NoEffect(_) => owner.flight = Flight::Fault,
        RingCallOutcome::Indeterminate { request_id } =>
            owner.flight = Flight::CloseSubmitted(request_id),
        RingCallOutcome::Completed(0, _, _, _, _) => {
            owner.server_handle = 0;
            owner.flight = Flight::CloseReady;
        }
        RingCallOutcome::Completed(_, _, _, _, _) => owner.flight = Flight::Fault,
    }
}
