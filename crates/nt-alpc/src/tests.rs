//! Host tests for the ALPC adapter — the ALPC surface over the core, and the
//! load-bearing **LPC↔ALPC bridge** (both directions) over ONE shared core.

use super::*;

use nt_alpc_abi::{
    msg_attr_flag, msg_type, opcode as aop, port_flag, AlpcAcceptConnectRequest,
    AlpcCloseCreatedPortRequest, AlpcConnectPortRequest, AlpcContextAttr, AlpcCreatePortRequest,
    AlpcCreatePortSectionRequest,
    AlpcCreateSectionViewRequest, AlpcDataViewAttr, AlpcHandleRequest, AlpcSendReceiveRequest,
    AlpcViewIoRequest, PortMessage,
};
use nt_lpc_client::{Backend, LpcClient};
use nt_lpc_server::{AcceptPolicy, ConnState, Server};
use nt_port_core::PortApi;

// --- encode helpers (build the fixed-layout wire buffers) ------------------

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn bytes<T: Pod>(v: &T) -> Vec<u8> {
    bytemuck::bytes_of(v).to_vec()
}

fn push_utf16(buf: &mut Vec<u8>, s: &[u16]) {
    for &u in s {
        buf.extend_from_slice(&u.to_le_bytes());
    }
}

/// A framed PORT_MESSAGE (40-byte header + payload).
fn port_message(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let hdr = PortMessage {
        data_length: payload.len() as u16,
        total_length: (40 + payload.len()) as u16,
        msg_type,
        ..Default::default()
    };
    let mut b = bytes(&hdr);
    b.extend_from_slice(payload);
    b
}

fn enc_create_port(name: &[u16], flags: u32) -> Vec<u8> {
    let hdr = size_of::<AlpcCreatePortRequest>() as u32;
    let req = AlpcCreatePortRequest {
        abi_size: hdr as u16,
        port_flags: flags,
        max_message_length: 0x1000,
        name_offset: hdr,
        name_len_bytes: (name.len() * 2) as u32,
        ..Default::default()
    };
    let mut b = bytes(&req);
    push_utf16(&mut b, name);
    b
}

fn enc_checked_create_port(
    name: &[u16],
    owner: nt_port_core::ClientId,
    token: (u64, u64),
) -> Vec<u8> {
    let hdr = size_of::<nt_alpc_abi::AlpcCreatePortCheckedRequest>() as u32;
    let req = nt_alpc_abi::AlpcCreatePortCheckedRequest {
        create: AlpcCreatePortRequest {
            abi_size: hdr as u16,
            max_message_length: 0x1000,
            name_offset: hdr,
            name_len_bytes: (name.len() * 2) as u32,
            ..Default::default()
        },
        owner_process: owner.process,
        owner_thread: owner.thread,
        owner_generation: 1,
        invocation_hi: token.0,
        invocation_lo: token.1,
    };
    let mut b = bytes(&req);
    push_utf16(&mut b, name);
    b
}

#[test]
fn checked_connect_cannot_queue_to_a_protected_port_without_an_access_decision() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId { process: 7, thread: 11 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let name = utf16("\\SmApiPort");
    let header_size = size_of::<nt_alpc_abi::AlpcCreatePortSecuredRequest>();
    let descriptor = [1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        20, 0, 0, 0, 2, 0, 8, 0, 0, 0, 0, 0];
    let request = nt_alpc_abi::AlpcCreatePortSecuredRequest {
        owned: nt_alpc_abi::AlpcCreatePortOwnedRequest {
            checked: nt_alpc_abi::AlpcCreatePortCheckedRequest {
                create: AlpcCreatePortRequest {
                    abi_size: header_size as u16,
                    max_message_length: 0x1000,
                    name_offset: header_size as u32,
                    name_len_bytes: (name.len() * 2) as u32,
                    ..Default::default()
                },
                owner_process: owner.process,
                owner_thread: owner.thread,
                owner_generation: 1,
                invocation_hi: 3,
                invocation_lo: 90,
            },
            attributes: AlpcPortAttributes { max_message_length: 0x1000, ..Default::default() },
        },
        security_offset: (header_size + name.len() * 2) as u32,
        security_len_bytes: descriptor.len() as u32,
    };
    let mut wire = bytes(&request);
    push_utf16(&mut wire, &name);
    wire.extend_from_slice(&descriptor);
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &wire, &mut []);
    assert_eq!(created.status, SUCCESS);
    let connect = enc_checked_connect(&name, client, (3, 91),
        &port_message(msg_type::CONNECTION_REQUEST, b"hello"));
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT,
        &connect, &mut []).status, nt_status::NtStatus::ACCESS_DENIED.0);
    assert!(matches!(core.receive(created.detail0).unwrap(), ReceiveOutcome::WouldBlock));

    let old_size = size_of::<nt_alpc_abi::AlpcConnectPortCheckedRequest>();
    let new_size = size_of::<nt_alpc_abi::AlpcConnectPortAuthorizedRequest>();
    let mut checked: nt_alpc_abi::AlpcConnectPortCheckedRequest =
        bytemuck::pod_read_unaligned(&connect[..old_size]);
    checked.connect.abi_size = new_size as u16;
    checked.connect.name_offset += (new_size - old_size) as u32;
    checked.connect.message_offset += (new_size - old_size) as u32;
    let authorized = nt_alpc_abi::AlpcConnectPortAuthorizedRequest {
        checked,
        target_listen_handle: created.detail0,
        access_granted: 1,
        ..Default::default()
    };
    let mut granted_wire = bytes(&authorized);
    granted_wire.extend_from_slice(&connect[old_size..]);
    let pending = alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT,
        &granted_wire, &mut []);
    assert_eq!(pending.status, nt_status::NtStatus::PENDING.0);
    assert!(matches!(core.receive(created.detail0).unwrap(),
        ReceiveOutcome::ConnectionRequest { .. }));
}

fn enc_create_lookup(owner: nt_port_core::ClientId, token: (u64, u64)) -> Vec<u8> {
    bytes(&nt_alpc_abi::AlpcLookupCreatePortRequest {
        abi_size: size_of::<nt_alpc_abi::AlpcLookupCreatePortRequest>() as u16,
        owner_process: owner.process,
        owner_thread: owner.thread,
        owner_generation: 1,
        invocation_hi: token.0,
        invocation_lo: token.1,
        ..Default::default()
    })
}

fn enc_checked_receive(
    port: u64,
    owner: nt_port_core::ClientId,
    token: (u64, u64),
) -> Vec<u8> {
    bytes(&nt_alpc_abi::AlpcSendReceiveCheckedRequest {
        send_receive: AlpcSendReceiveRequest {
            abi_size: size_of::<nt_alpc_abi::AlpcSendReceiveCheckedRequest>() as u16,
            port_handle: port,
            ..Default::default()
        },
        invocation: nt_alpc_abi::AlpcCheckedInvocation {
            owner_process: owner.process,
            owner_thread: owner.thread,
            owner_generation: 1,
            invocation_hi: token.0,
            invocation_lo: token.1,
        },
    })
}

fn enc_ack_receive(owner: nt_port_core::ClientId, token: (u64, u64)) -> Vec<u8> {
    bytes(&nt_alpc_abi::AlpcAcknowledgeSendReceiveRequest {
        abi_size: size_of::<nt_alpc_abi::AlpcAcknowledgeSendReceiveRequest>() as u16,
        invocation: nt_alpc_abi::AlpcCheckedInvocation {
            owner_process: owner.process,
            owner_thread: owner.thread,
            owner_generation: 1,
            invocation_hi: token.0,
            invocation_lo: token.1,
        },
        ..Default::default()
    })
}

fn enc_checked_connect(name: &[u16], owner: nt_port_core::ClientId,
    token: (u64, u64), message: &[u8]) -> Vec<u8> {
    let base = size_of::<nt_alpc_abi::AlpcConnectPortCheckedRequest>();
    let header = nt_alpc_abi::AlpcConnectPortCheckedRequest {
        connect: AlpcConnectPortRequest {
            abi_size: base as u16,
            name_offset: base as u32,
            name_len_bytes: (name.len() * 2) as u32,
            message_offset: (base + name.len() * 2) as u32,
            message_len_bytes: message.len() as u32,
            ..Default::default()
        },
        invocation: nt_alpc_abi::AlpcCheckedInvocation {
            owner_process: owner.process, owner_thread: owner.thread, owner_generation: 1,
            invocation_hi: token.0, invocation_lo: token.1,
        },
        ..Default::default()
    };
    let mut wire = bytes(&header);
    push_utf16(&mut wire, name);
    wire.extend_from_slice(message);
    wire
}

fn enc_checked_accept(listen: u64, connection_id: u64,
    owner: nt_port_core::ClientId, token: (u64, u64)) -> Vec<u8> {
    bytes(&nt_alpc_abi::AlpcAcceptConnectCheckedRequest {
        accept: AlpcAcceptConnectRequest {
            abi_size: size_of::<nt_alpc_abi::AlpcAcceptConnectCheckedRequest>() as u16,
            accept: 1, connection_id, ..Default::default()
        },
        invocation: nt_alpc_abi::AlpcCheckedInvocation {
            owner_process: owner.process, owner_thread: owner.thread, owner_generation: 1,
            invocation_hi: token.0, invocation_lo: token.1,
        },
        listen_port: listen,
        message_offset: 0,
        message_len_bytes: 0,
    })
}

#[test]
fn checked_connect_copies_only_native_port_message_payload_and_never_reconnects_token() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let server = nt_port_core::ClientId { process: 7, thread: 11 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let name = utf16("\\SmApiPort");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, server, (3, 40)), &mut []);
    assert_eq!(created.status, SUCCESS);
    let wire = enc_checked_connect(&name, client, (3, 41),
        &port_message(msg_type::CONNECTION_REQUEST, b"hello"));
    let first = alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &wire, &mut []);
    assert_eq!(first.status, nt_status::NtStatus::PENDING.0);
    assert_ne!(first.detail1, 0);
    assert_eq!(core.connection_info(first.detail1), Some(&b"hello"[..]));
    assert_eq!(core.connection_client_id(first.detail1), Some(client));
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &wire, &mut []), first);
    let mut changed = wire.clone();
    *changed.last_mut().unwrap() = b'!';
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT,
        &changed, &mut []).status, nt_status::NtStatus::INVALID_PARAMETER.0);
    let mut output = [0u8; 128];
    let received = alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(created.detail0, server, (3, 42)), &mut output);
    assert_eq!(received.status, SUCCESS);
    assert_eq!(&output[40..45], b"hello");
}

#[test]
fn libernt_sync_connect_preserves_qos_through_pending_accept_and_exact_replay() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let server = nt_port_core::ClientId { process: 7, thread: 11 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let name = utf16("\\SmApiPort");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, server, (3, 85)), &mut []);
    assert_eq!(created.status, SUCCESS);
    let mut wire = enc_checked_connect(&name, client, (3, 86),
        &port_message(msg_type::CONNECTION_REQUEST, b"SB!!"));
    let mut header: nt_alpc_abi::AlpcConnectPortCheckedRequest =
        bytemuck::pod_read_unaligned(&wire[..size_of::<nt_alpc_abi::AlpcConnectPortCheckedRequest>()]);
    header.connect.connect_flags = 0x0002_0000;
    header.has_port_attributes = 1;
    header.port_attributes = nt_alpc_abi::AlpcPortAttributes {
        max_message_length: 512,
        security_qos: nt_alpc_abi::SecurityQualityOfService {
            length: 12, impersonation_level: 1, context_tracking_mode: 1,
            effective_only: 1, ..Default::default()
        },
        ..Default::default()
    };
    wire[..size_of::<nt_alpc_abi::AlpcConnectPortCheckedRequest>()]
        .copy_from_slice(bytemuck::bytes_of(&header));
    let pending = alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &wire, &mut []);
    assert_eq!(pending.status, nt_status::NtStatus::PENDING.0);
    assert_eq!(core.connection_security(pending.detail1), Some(nt_port_core::ConnectionSecurity {
        impersonation_level: 1, dynamic_tracking: true, effective_only: true,
    }));
    assert_eq!(core.connection_limits(pending.detail1).unwrap().max_message, 512);
    let mut altered = wire.clone();
    let mut altered_header = header;
    altered_header.port_attributes.security_qos.impersonation_level = 2;
    altered[..size_of::<nt_alpc_abi::AlpcConnectPortCheckedRequest>()]
        .copy_from_slice(bytemuck::bytes_of(&altered_header));
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &altered, &mut []).status,
        nt_status::NtStatus::INVALID_PARAMETER.0);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &wire, &mut []), pending);
    let mut received = [0u8; 128];
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(created.detail0, server, (3, 87)), &mut received).status, SUCCESS);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACCEPT_CONNECT,
        &enc_checked_accept(created.detail0, pending.detail1, server, (3, 88)),
        &mut []).status, SUCCESS);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &wire, &mut []).status,
        SUCCESS);
}

#[test]
fn checked_accept_requires_a_matching_owned_receive_receipt_even_after_ack() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let server = nt_port_core::ClientId { process: 7, thread: 11 };
    let other = nt_port_core::ClientId { process: 9, thread: 13 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let name = utf16("\\SmApiPort");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, server, (3, 50)), &mut []);
    assert_eq!(created.status, SUCCESS);
    let connection_id = match core.connect_with_client_id(&name, PortApi::Alpc, 0,
        b"hello", client).unwrap() {
        nt_port_core::ConnectOutcome::Pending { connection_id } => connection_id,
        _ => panic!("manual accept requires a pending connection"),
    };
    let accept = enc_checked_accept(created.detail0, connection_id, server, (3, 53));
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACCEPT_CONNECT,
        &accept, &mut []).status, nt_status::NtStatus::INVALID_PARAMETER.0);
    let mut output = [0u8; 128];
    let received = alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(created.detail0, server, (3, 51)), &mut output);
    assert_eq!(received.status, SUCCESS);
    assert_eq!(received.detail0, connection_id);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACK_SEND_RECEIVE,
        &enc_ack_receive(server, (3, 51)), &mut []).status, SUCCESS);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACCEPT_CONNECT,
        &enc_checked_accept(created.detail0, connection_id, other, (3, 52)),
        &mut []).status, nt_status::NtStatus::ACCESS_DENIED.0);
    let first = alpc.dispatch(&mut core, aop::ALPC_OP_ACCEPT_CONNECT, &accept, &mut []);
    assert_eq!(first.status, SUCCESS);
    assert_ne!(first.detail0, 0);
    assert_ne!(first.detail1, 0);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACCEPT_CONNECT, &accept, &mut []), first);
}

#[test]
fn checked_accept_commits_copied_response_and_connect_poll_returns_exact_bytes() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let server = nt_port_core::ClientId { process: 7, thread: 11 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let name = utf16("\\SmApiPort");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, server, (3, 60)), &mut []);
    assert_eq!(created.status, SUCCESS);
    let connect = enc_checked_connect(&name, client, (3, 61),
        &port_message(msg_type::CONNECTION_REQUEST, b"hello"));
    let pending = alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &connect, &mut []);
    assert_eq!(pending.status, nt_status::NtStatus::PENDING.0);
    let mut received_message = [0u8; 128];
    let received = alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(created.detail0, server, (3, 62)), &mut received_message);
    assert_eq!(received.status, SUCCESS);
    assert_eq!(received.detail0, pending.detail1);
    let mut response = received_message[..42].to_vec();
    response[0..2].copy_from_slice(&2u16.to_le_bytes());
    response[2..4].copy_from_slice(&42u16.to_le_bytes());
    response[40..42].copy_from_slice(b"OK");
    let mut accept = enc_checked_accept(created.detail0, pending.detail1, server, (3, 63));
    let mut header: nt_alpc_abi::AlpcAcceptConnectCheckedRequest =
        bytemuck::pod_read_unaligned(&accept);
    header.message_offset = accept.len() as u32;
    header.message_len_bytes = response.len() as u32;
    accept.copy_from_slice(bytemuck::bytes_of(&header));
    accept.extend_from_slice(&response);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACCEPT_CONNECT,
        &accept, &mut []).status, SUCCESS);
    let mut connector_output = [0u8; 128];
    let connected = alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT,
        &connect, &mut connector_output);
    assert_eq!(connected.status, SUCCESS);
    assert_eq!(connected.information, 2);
    assert_eq!(&connector_output[..2], b"OK");
    assert_eq!(core.connection_response_info(pending.detail1), Some(&b"OK"[..]));
}

#[test]
fn checked_later_ports_close_by_exact_token_then_ack_without_replay() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let server = nt_port_core::ClientId { process: 7, thread: 11 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let name = utf16("\\SmApiPort");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, server, (3, 70)), &mut []);
    let connect = enc_checked_connect(&name, client, (3, 71),
        &port_message(msg_type::CONNECTION_REQUEST, b"hello"));
    let pending = alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &connect, &mut []);
    let mut received = [0u8; 128];
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(created.detail0, server, (3, 72)), &mut received).status, SUCCESS);
    let accept = enc_checked_accept(created.detail0, pending.detail1, server, (3, 73));
    let accepted = alpc.dispatch(&mut core, aop::ALPC_OP_ACCEPT_CONNECT, &accept, &mut []);
    assert_eq!(accepted.status, SUCCESS);
    let connected = alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &connect, &mut []);
    assert_eq!(connected.status, SUCCESS);
    let close = |owner: nt_port_core::ClientId, token: (u64, u64), handle: u64| {
        bytes(&AlpcCloseCreatedPortRequest {
            abi_size: size_of::<AlpcCloseCreatedPortRequest>() as u16,
            handle, owner_process: owner.process, owner_thread: owner.thread,
            owner_generation: 1, invocation_hi: token.0, invocation_lo: token.1,
            ..Default::default()
        })
    };
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CLOSE_LATER_PORT,
        &close(client, (3, 73), accepted.detail0), &mut []).status,
        nt_status::NtStatus::OBJECT_NAME_COLLISION.0);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACK_ACCEPT_CONNECT,
        &enc_ack_receive(server, (3, 73)), &mut []).status, SUCCESS);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACK_CONNECT_PORT,
        &enc_ack_receive(client, (3, 71)), &mut []).status, SUCCESS);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CLOSE_LATER_PORT,
        &close(server, (3, 73), accepted.detail0), &mut []).status, SUCCESS);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CLOSE_LATER_PORT,
        &close(client, (3, 71), connected.detail0), &mut []).status, SUCCESS);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACCEPT_CONNECT,
        &accept, &mut []).status, nt_status::NtStatus::OBJECT_NAME_COLLISION.0);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT,
        &connect, &mut []).status, nt_status::NtStatus::OBJECT_NAME_COLLISION.0);
}

#[test]
fn checked_receive_terminal_ack_retires_output_without_permitting_token_replay() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId { process: 7, thread: 11 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let name = utf16("\\SmApiPort");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, owner, (3, 20)), &mut []);
    assert_eq!(created.status, SUCCESS);
    let request = enc_checked_receive(created.detail0, owner, (3, 21));
    let mut output = [0u8; 128];
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &request, &mut output).status, nt_status::NtStatus::PENDING.0);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACK_SEND_RECEIVE,
        &enc_ack_receive(owner, (3, 21)), &mut []).status,
        nt_status::NtStatus::INVALID_PARAMETER.0);
    core.connect_with_client_id(&name, PortApi::Alpc, 0, b"hello", client).unwrap();
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &request, &mut output).status, SUCCESS);
    let mut foreign = enc_ack_receive(client, (3, 21));
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACK_SEND_RECEIVE,
        &foreign, &mut []).status, nt_status::NtStatus::OBJECT_NAME_COLLISION.0);
    foreign = enc_ack_receive(owner, (3, 21));
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACK_SEND_RECEIVE,
        &foreign, &mut []).status, SUCCESS);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &request, &mut output).status, nt_status::NtStatus::OBJECT_NAME_COLLISION.0);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(created.detail0, owner, (3, 22)), &mut output).status,
        nt_status::NtStatus::PENDING.0);
}

#[test]
fn checked_receive_keeps_oversized_data_queued_for_a_larger_buffer() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId { process: 7, thread: 11 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let name = utf16("\\SmApiPort");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, owner, (3, 30)), &mut []);
    assert_eq!(created.status, SUCCESS);
    let connection_id = match core.connect_with_client_id(&name, PortApi::Alpc, 0,
        &[], client).unwrap() {
        nt_port_core::ConnectOutcome::Pending { connection_id } => connection_id,
        _ => panic!("manual accept requires a pending connection"),
    };
    let server = core.accept(connection_id, true, 0).unwrap();
    let (client_handle, _) = core.complete(connection_id).unwrap();
    let message = port_message(msg_type::REQUEST, b"payload");
    core.send_message(client_handle, &message, nt_port_core::MessageAttrs::default()).unwrap();

    let mut short = [0u8; 40];
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(server, owner, (3, 31)), &mut short).status,
        nt_status::NtStatus::BUFFER_TOO_SMALL.0);
    let mut full = [0u8; 128];
    let received = alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(server, owner, (3, 32)), &mut full);
    assert_eq!(received.status, SUCCESS);
    assert_eq!(received.information as usize, message.len());
    assert_eq!(&full[..message.len()], message);
}

#[test]
fn checked_receive_on_owned_listen_port_parks_only_its_owner() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId {
        process: 7,
        thread: 11,
    };
    let intruder = nt_port_core::ClientId {
        process: 8,
        thread: 12,
    };
    let name = utf16("\\SmApiPort");
    let created = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, owner, (3, 9)),
        &mut [],
    );
    assert_eq!(created.status, SUCCESS);

    let owned = enc_checked_receive(created.detail0, owner, (3, 10));
    let first = alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &owned, &mut []);
    assert_eq!(first.status, nt_status::NtStatus::PENDING.0);
    assert_eq!(
        alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &owned, &mut []),
        first
    );
    let foreign = enc_checked_receive(created.detail0, intruder, (3, 11));
    assert_eq!(
        alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &foreign, &mut [])
            .status,
        nt_status::NtStatus::ACCESS_DENIED.0
    );
}

#[test]
fn checked_connection_receive_delivers_a_native_port_message_for_accept() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId { process: 7, thread: 11 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let name = utf16("\\SmApiPort");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, owner, (3, 12)), &mut []);
    assert_eq!(created.status, SUCCESS);
    let connection = core.connect_with_client_id(&name, PortApi::Alpc, 0,
        b"hello", client).unwrap();
    let connection_id = match connection {
        nt_port_core::ConnectOutcome::Pending { connection_id } => connection_id,
        _ => panic!("new connection must wait for acceptance"),
    };
    let mut output = [0u8; 128];
    let received = alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(created.detail0, owner, (3, 13)), &mut output);
    assert_eq!(received.status, SUCCESS);
    assert_eq!(received.detail0, connection_id);
    assert_eq!(received.information, 45);
    let header: PortMessage = bytemuck::pod_read_unaligned(&output[..40]);
    assert_eq!(header.msg_type, msg_type::CONNECTION_REQUEST);
    assert_eq!(header.message_id, connection_id as u32);
    assert_eq!(header.client_process, client.process);
    assert_eq!(header.client_thread, client.thread);
    assert_eq!(&output[40..45], b"hello");
}

#[test]
fn checked_connection_receive_with_context_output_keeps_message_and_empty_valid_mask() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId { process: 7, thread: 11 };
    let name = utf16("\\SmApiPortAttrs");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, owner, (3, 20)), &mut []);
    assert_eq!(created.status, SUCCESS);
    assert!(matches!(core.connect_with_client_id(&name, PortApi::Alpc, 0,
        b"hello", nt_port_core::ClientId { process: 8, thread: 12 }).unwrap(),
        nt_port_core::ConnectOutcome::Pending { .. }));
    let mut request = enc_checked_receive(created.detail0, owner, (3, 21));
    request[4..8].copy_from_slice(&nt_alpc_abi::send_flag::RECV_ATTRIBUTES.to_le_bytes());
    request[24..28].copy_from_slice(&nt_alpc_abi::msg_attr_flag::CONTEXT.to_le_bytes());
    let mut output = [0u8; 128];
    let received = alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &request, &mut output);
    assert_eq!(received.status, SUCCESS);
    assert_eq!(received.information, 53);
    assert_eq!(u32::from_le_bytes(output[0..4].try_into().unwrap()),
        nt_alpc_abi::msg_attr_flag::CONTEXT);
    assert_eq!(u32::from_le_bytes(output[4..8].try_into().unwrap()), 0);
    let header: PortMessage = bytemuck::pod_read_unaligned(&output[8..48]);
    assert_eq!(header.msg_type, msg_type::CONNECTION_REQUEST);
    assert_eq!(&output[48..53], b"hello");
}

#[test]
fn checked_smss_reply_and_receive_routes_exact_delivered_request_once() {
    use nt_port_core::{ClientId, MessageAttrs, MessageIdentity};
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let server = ClientId { process: 7, thread: 11 };
    let identity = MessageIdentity {
        client: ClientId { process: 8, thread: 12 }, message_id: 91,
    };
    let name = utf16("\\SmApiPortReply");
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, server, (3, 80)), &mut []);
    assert_eq!(created.status, SUCCESS);
    let listen = created.detail0;
    let kernel = core.retain_connection_port(listen).unwrap();
    let mut request = port_message(msg_type::REQUEST, b"hi");
    request[8..16].copy_from_slice(&identity.client.process.to_le_bytes());
    request[16..24].copy_from_slice(&identity.client.thread.to_le_bytes());
    request[24..28].copy_from_slice(&identity.message_id.to_le_bytes());
    core.send_kernel_request_message(kernel, &request, MessageAttrs::default(), identity).unwrap();
    let mut received = [0u8; 128];
    let first = alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE,
        &enc_checked_receive(listen, server, (3, 81)), &mut received);
    assert_eq!(first.status, SUCCESS);
    assert_eq!(&received[..request.len()], &request);
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_ACK_SEND_RECEIVE,
        &enc_ack_receive(server, (3, 81)), &mut []).status, SUCCESS);

    // SMSS keeps the received header and uses ALPC_MSGFLG_REPLY_MESSAGE.
    let mut response = port_message(msg_type::REQUEST, b"OK");
    response[8..16].copy_from_slice(&identity.client.process.to_le_bytes());
    response[16..24].copy_from_slice(&identity.client.thread.to_le_bytes());
    response[24..28].copy_from_slice(&identity.message_id.to_le_bytes());
    let mut wire = enc_checked_receive(listen, server, (3, 82));
    let mut header: nt_alpc_abi::AlpcSendReceiveCheckedRequest =
        bytemuck::pod_read_unaligned(&wire);
    header.send_receive.flags = nt_alpc_abi::send_flag::RECV_ATTRIBUTES
        | nt_alpc_abi::send_flag::REPLY_MESSAGE;
    header.send_receive.valid_attributes = msg_attr_flag::CONTEXT;
    header.send_receive.message_offset = wire.len() as u32;
    header.send_receive.message_len_bytes = response.len() as u32;
    wire.copy_from_slice(bytemuck::bytes_of(&header));
    wire.extend_from_slice(&response);
    let mut output = [0u8; 128];
    let pending = alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &wire, &mut output);
    assert_eq!(pending.status, nt_status::NtStatus::PENDING.0);
    let delivered = core.receive_reply_message(kernel, identity).unwrap().unwrap().bytes;
    assert_eq!(&delivered[8..], &response[8..], "identity and payload survive reply routing");
    assert_eq!(u16::from_le_bytes(delivered[4..6].try_into().unwrap()), msg_type::REPLY,
        "ALPC reply delivery must normalize the reused SMSS request header");
    // A pending poll of the same token must not replay the already sent reply.
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &wire, &mut output).status,
        nt_status::NtStatus::PENDING.0);
    assert_eq!(core.receive_reply_message(kernel, identity).unwrap(), None);
}

fn enc_owned_create_port(
    name: &[u16],
    owner: nt_port_core::ClientId,
    token: (u64, u64),
    attributes: nt_alpc_abi::AlpcPortAttributes,
) -> Vec<u8> {
    let mut request = enc_checked_create_port(name, owner, token);
    let name_bytes = request.split_off(size_of::<nt_alpc_abi::AlpcCreatePortCheckedRequest>());
    let header = (size_of::<nt_alpc_abi::AlpcCreatePortCheckedRequest>()
        + size_of::<nt_alpc_abi::AlpcPortAttributes>()) as u16;
    request[0..2].copy_from_slice(&header.to_le_bytes());
    request[12..16].copy_from_slice(&(header as u32).to_le_bytes());
    request[8..12].copy_from_slice(&(attributes.max_message_length as u32).to_le_bytes());
    request[4..8].copy_from_slice(&attributes.flags.to_le_bytes());
    request.extend_from_slice(bytemuck::bytes_of(&attributes));
    request.extend_from_slice(&name_bytes);
    request
}

#[test]
fn owned_create_carries_smss_pool_and_security_qos_without_losing_replay_identity() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId {
        process: 7,
        thread: 11,
    };
    let name = utf16("\\SmApiPort");
    let attributes = nt_alpc_abi::AlpcPortAttributes {
        max_message_length: 512,
        max_pool_usage: 8192,
        security_qos: nt_alpc_abi::SecurityQualityOfService {
            length: 12,
            impersonation_level: 1,
            context_tracking_mode: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let request = enc_owned_create_port(&name, owner, (7, 8), attributes);
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &request, &mut []);
    assert_eq!(created.status, SUCCESS);
    assert_eq!(
        core.handle_info(created.detail0)
            .unwrap()
            .limits
            .max_pool_usage,
        8192
    );
    assert_eq!(
        alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &request, &mut []),
        created
    );
    let mut changed = attributes;
    changed.max_pool_usage = 4096;
    let changed_request = enc_owned_create_port(&name, owner, (7, 8), changed);
    assert_eq!(
        alpc.dispatch(
            &mut core,
            aop::ALPC_OP_CREATE_PORT,
            &changed_request,
            &mut []
        )
        .status,
        nt_status::NtStatus::INVALID_PARAMETER.0
    );
    let mut changed_qos = attributes;
    changed_qos.security_qos.impersonation_level = 2;
    let changed_request = enc_owned_create_port(&name, owner, (7, 8), changed_qos);
    assert_eq!(
        alpc.dispatch(
            &mut core,
            aop::ALPC_OP_CREATE_PORT,
            &changed_request,
            &mut []
        )
        .status,
        nt_status::NtStatus::INVALID_PARAMETER.0
    );
}

#[test]
fn checked_csrss_port_flags_allow_lpc_clients_only_when_requested() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId { process: 7, thread: 11 };
    let client = nt_port_core::ClientId { process: 8, thread: 12 };
    let flags = port_flag::ALLOW_LPC_REQUESTS | port_flag::ALLOW_IMPERSONATION;
    let name = utf16("\\Windows\\ApiPort");
    let attributes = nt_alpc_abi::AlpcPortAttributes {
        flags,
        max_message_length: 512,
        max_pool_usage: 16 * 4096,
        security_qos: nt_alpc_abi::SecurityQualityOfService {
            length: 12,
            impersonation_level: 2,
            context_tracking_mode: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_owned_create_port(&name, owner, (7, 80), attributes), &mut []);
    assert_eq!(created.status, SUCCESS);
    assert!(matches!(core.connect_with_client_id(&name, PortApi::Lpc, 0,
        b"csr-client", client), Ok(nt_port_core::ConnectOutcome::Pending { .. })));

    let restricted_name = utf16("\\Windows\\AlpcOnly");
    let restricted = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT,
        &enc_owned_create_port(&restricted_name, owner, (7, 81),
            nt_alpc_abi::AlpcPortAttributes {
                flags: port_flag::ALLOW_IMPERSONATION,
                max_message_length: 512,
                ..Default::default()
            }), &mut []);
    assert_eq!(restricted.status, SUCCESS);
    assert!(core.connect_with_client_id(&restricted_name, PortApi::Lpc, 0,
        b"csr-client", client).is_err());
}

#[test]
fn owned_create_rejects_unrepresented_limits_before_creating_a_port() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId {
        process: 7,
        thread: 11,
    };
    let name = utf16("\\SmApiPort");
    let attributes = nt_alpc_abi::AlpcPortAttributes {
        max_message_length: 512,
        max_pool_usage: u32::MAX as u64 + 1,
        ..Default::default()
    };
    let request = enc_owned_create_port(&name, owner, (7, 9), attributes);
    assert_eq!(
        alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &request, &mut [])
            .status,
        nt_status::NtStatus::INVALID_PARAMETER.0
    );
    assert!(core.port_api(&name).is_none());
}

#[test]
fn checked_create_reconciles_only_exact_owner_token_and_request() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId {
        process: 7,
        thread: 11,
    };
    let intruder = nt_port_core::ClientId {
        process: 8,
        thread: 12,
    };
    let name = utf16("\\SmApiPort");
    let request = enc_checked_create_port(&name, owner, (3, 9));
    let first = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &request, &mut []);
    assert_eq!(first.status, SUCCESS);
    assert_eq!(core.handle_info(first.detail0).unwrap().server_id, owner);
    let again = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &request, &mut []);
    assert_eq!(again, first);
    let found = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_LOOKUP_CREATE_PORT,
        &enc_create_lookup(owner, (3, 9)),
        &mut [],
    );
    assert_eq!(found, first);
    let wrong_owner = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_LOOKUP_CREATE_PORT,
        &enc_create_lookup(intruder, (3, 9)),
        &mut [],
    );
    assert_eq!(
        wrong_owner.status,
        nt_status::NtStatus::OBJECT_NAME_COLLISION.0
    );
    let mut wrong_generation = enc_create_lookup(owner, (3, 9));
    wrong_generation[24..32].copy_from_slice(&2u64.to_le_bytes());
    let wrong_generation = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_LOOKUP_CREATE_PORT,
        &wrong_generation,
        &mut [],
    );
    assert_eq!(
        wrong_generation.status,
        nt_status::NtStatus::OBJECT_NAME_COLLISION.0
    );
    let changed_name = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&utf16("\\Other"), owner, (3, 9)),
        &mut [],
    );
    assert_eq!(
        changed_name.status,
        nt_status::NtStatus::INVALID_PARAMETER.0
    );
    let different_owner = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, intruder, (3, 10)),
        &mut [],
    );
    assert_eq!(
        different_owner.status,
        nt_status::NtStatus::OBJECT_NAME_COLLISION.0
    );
    let same_owner_new_token = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, owner, (3, 11)),
        &mut [],
    );
    assert_eq!(
        same_owner_new_token.status,
        nt_status::NtStatus::OBJECT_NAME_COLLISION.0
    );
}

#[test]
fn checked_created_port_close_requires_exact_owner_token_and_handle() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId { process: 7, thread: 11 };
    let name = utf16("\\SmApiPortClose");
    let create = enc_checked_create_port(&name, owner, (3, 9));
    let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &create, &mut []);
    assert_eq!(created.status, SUCCESS);
    let exact = AlpcCloseCreatedPortRequest {
        abi_size: size_of::<AlpcCloseCreatedPortRequest>() as u16,
        handle: created.detail0,
        owner_process: owner.process,
        owner_thread: owner.thread,
        owner_generation: 1,
        invocation_hi: 3,
        invocation_lo: 9,
        ..Default::default()
    };
    for changed in [
        AlpcCloseCreatedPortRequest { owner_process: 8, ..exact },
        AlpcCloseCreatedPortRequest { owner_generation: 2, ..exact },
        AlpcCloseCreatedPortRequest { invocation_lo: 10, ..exact },
        AlpcCloseCreatedPortRequest { handle: created.detail0 + 1, ..exact },
    ] {
        assert_ne!(alpc.dispatch(&mut core, aop::ALPC_OP_CLOSE_CREATED_PORT,
            &bytes(&changed), &mut []).status, SUCCESS);
        assert!(core.handle_info(created.detail0).is_some());
    }
    // A process handle can be closed by a sibling thread. The creation token,
    // process incarnation and exact service handle remain the authority.
    let sibling = AlpcCloseCreatedPortRequest { owner_thread: 12, ..exact };
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CLOSE_CREATED_PORT,
        &bytes(&sibling), &mut []).status, SUCCESS);
    assert!(core.handle_info(created.detail0).is_none());
    assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CLOSE_CREATED_PORT,
        &bytes(&exact), &mut []).status, SUCCESS);
    // Closed state is authoritative for both reconciliation routes, even if
    // a later service allocation were ever to reuse this numeric handle.
    let lookup = alpc.dispatch(&mut core, aop::ALPC_OP_LOOKUP_CREATE_PORT,
        &enc_create_lookup(owner, (3, 9)), &mut []);
    assert_eq!(lookup.status, nt_status::NtStatus::INVALID_PORT_HANDLE.0);
    assert_eq!(lookup.detail0, 0);
    let replay = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &create, &mut []);
    assert_eq!(replay.status, nt_status::NtStatus::INVALID_PORT_HANDLE.0);
    assert_eq!(replay.detail0, 0);
}

#[test]
fn closed_checked_create_records_are_bounded_without_token_replay() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId { process: 7, thread: 11 };
    let name = utf16("\\SmReopenPort");
    let mut oldest = Vec::new();
    for sequence in 1..=200u64 {
        let wire = enc_checked_create_port(&name, owner, (3, sequence));
        if sequence == 1 { oldest = wire.clone(); }
        let created = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &wire, &mut []);
        assert_eq!(created.status, SUCCESS);
        let close = AlpcCloseCreatedPortRequest {
            abi_size: size_of::<AlpcCloseCreatedPortRequest>() as u16,
            handle: created.detail0,
            owner_process: owner.process,
            owner_thread: owner.thread,
            owner_generation: 1,
            invocation_hi: 3,
            invocation_lo: sequence,
            ..Default::default()
        };
        assert_eq!(alpc.dispatch(&mut core, aop::ALPC_OP_CLOSE_CREATED_PORT,
            &bytes(&close), &mut []).status, SUCCESS);
    }
    assert!(alpc.create_results.len() <= 128);
    assert!(alpc.create_results.iter().all(|record| record.closed
        && record.name.is_empty() && record.security_descriptor.is_none()));
    assert_ne!(alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &oldest, &mut []).status,
        SUCCESS);
}

#[test]
fn checked_create_refuses_zero_token_and_does_not_recreate_closed_result() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let owner = nt_port_core::ClientId {
        process: 7,
        thread: 11,
    };
    let name = utf16("\\SmApiPort");
    let invalid = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_CREATE_PORT,
        &enc_checked_create_port(&name, owner, (0, 0)),
        &mut [],
    );
    assert_eq!(invalid.status, nt_status::NtStatus::INVALID_PARAMETER.0);
    let mut truncated = enc_checked_create_port(&name, owner, (1, 2));
    truncated.truncate(size_of::<AlpcCreatePortRequest>());
    let invalid = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &truncated, &mut []);
    assert_eq!(invalid.status, nt_status::NtStatus::INVALID_PARAMETER.0);
    let mut zero_generation = enc_checked_create_port(&name, owner, (1, 2));
    // generation sits after the 24-byte prefix and the two 64-bit IDs.
    zero_generation[40..48].fill(0);
    let invalid = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_CREATE_PORT,
        &zero_generation,
        &mut [],
    );
    assert_eq!(invalid.status, nt_status::NtStatus::INVALID_PARAMETER.0);
    let request = enc_checked_create_port(&name, owner, (1, 2));
    let first = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &request, &mut []);
    assert_eq!(first.status, SUCCESS);
    core.close_port_checked(first.detail0).unwrap();
    let replay = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &request, &mut []);
    assert_eq!(replay.status, nt_status::NtStatus::INVALID_HANDLE.0);
    let found = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_LOOKUP_CREATE_PORT,
        &enc_create_lookup(owner, (1, 2)),
        &mut [],
    );
    assert_eq!(found.status, nt_status::NtStatus::INVALID_HANDLE.0);
    let missing = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_LOOKUP_CREATE_PORT,
        &enc_create_lookup(owner, (1, 3)),
        &mut [],
    );
    assert_eq!(missing.status, nt_status::NtStatus::OBJECT_NAME_NOT_FOUND.0);
}

fn enc_connect(name: &[u16], subsystem: u32, msg: &[u8]) -> Vec<u8> {
    let hdr = size_of::<AlpcConnectPortRequest>() as u32;
    let name_bytes = (name.len() * 2) as u32;
    let req = AlpcConnectPortRequest {
        abi_size: hdr as u16,
        subsystem_type: subsystem,
        name_offset: hdr,
        name_len_bytes: name_bytes,
        message_offset: hdr + name_bytes,
        message_len_bytes: msg.len() as u32,
        ..Default::default()
    };
    let mut b = bytes(&req);
    push_utf16(&mut b, name);
    b.extend_from_slice(msg);
    b
}

fn enc_accept(conn_id: u64, accept: bool, ctx: u64) -> Vec<u8> {
    bytes(&AlpcAcceptConnectRequest {
        abi_size: size_of::<AlpcAcceptConnectRequest>() as u16,
        accept: u16::from(accept),
        connection_id: conn_id,
        port_context: ctx,
        ..Default::default()
    })
}

fn enc_send_receive(port: u64, send: Option<&[u8]>, valid: u32, attrs: &[u8]) -> Vec<u8> {
    let hdr = size_of::<AlpcSendReceiveRequest>() as u32;
    let msg = send.unwrap_or(&[]);
    let req = AlpcSendReceiveRequest {
        abi_size: hdr as u16,
        port_handle: port,
        message_offset: hdr,
        message_len_bytes: msg.len() as u32,
        valid_attributes: valid,
        attr_offset: hdr + msg.len() as u32,
        attr_len_bytes: attrs.len() as u32,
        ..Default::default()
    };
    let mut b = bytes(&req);
    b.extend_from_slice(msg);
    b.extend_from_slice(attrs);
    b
}

fn enc_handle_req(handle: u64) -> Vec<u8> {
    bytes(&AlpcHandleRequest {
        abi_size: size_of::<AlpcHandleRequest>() as u16,
        handle,
        ..Default::default()
    })
}

/// Serialize a VIEW + CONTEXT attribute blob (order: VIEW then CONTEXT).
fn enc_attrs_view_context(section: u64, view_base: u64, view_size: u64, ctx: u64) -> Vec<u8> {
    let mut b = bytes(&AlpcDataViewAttr {
        section_handle: section,
        view_base,
        view_size,
        ..Default::default()
    });
    b.extend_from_slice(&bytes(&AlpcContextAttr {
        port_context: ctx,
        ..Default::default()
    }));
    b
}

fn enc_attrs_context(ctx: u64) -> Vec<u8> {
    bytes(&AlpcContextAttr {
        port_context: ctx,
        ..Default::default()
    })
}

const SUCCESS: i32 = 0;

// --- ALPC-only surface tests ----------------------------------------------

#[test]
fn alpc_ping() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    assert_eq!(
        alpc.dispatch(&mut core, aop::ALPC_OP_PING, &[], &mut [])
            .status,
        SUCCESS
    );
}

#[test]
fn alpc_create_and_connect_auto_accept() {
    let mut core = PortCore::new(); // AutoAccept
    let mut alpc = AlpcServer::new();
    let name = utf16("\\RPC Control\\Endpoint");
    let cp = enc_create_port(&name, port_flag::NONE);
    let r = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &cp, &mut []);
    assert_eq!(r.status, SUCCESS);
    assert_ne!(r.detail0, 0);
    // A connect auto-completes.
    let cn = enc_connect(
        &name,
        0,
        &port_message(msg_type::CONNECTION_REQUEST, b"hello"),
    );
    let r = alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &cn, &mut []);
    assert_eq!(r.status, SUCCESS);
    assert_ne!(r.detail0, 0, "client comm-port handle");
}

#[test]
fn unchecked_service_rejects_checked_later_requests_before_effects() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let mut out = [0u8; 64];
    let connect = nt_alpc_abi::AlpcConnectPortCheckedRequest {
        connect: AlpcConnectPortRequest {
            abi_size: size_of::<nt_alpc_abi::AlpcConnectPortCheckedRequest>() as u16,
            ..Default::default()
        },
        ..Default::default()
    };
    let accept = nt_alpc_abi::AlpcAcceptConnectCheckedRequest {
        accept: AlpcAcceptConnectRequest {
            abi_size: size_of::<nt_alpc_abi::AlpcAcceptConnectCheckedRequest>() as u16,
            ..Default::default()
        },
        ..Default::default()
    };
    let send = nt_alpc_abi::AlpcSendReceiveCheckedRequest {
        send_receive: AlpcSendReceiveRequest {
            abi_size: size_of::<nt_alpc_abi::AlpcSendReceiveCheckedRequest>() as u16,
            ..Default::default()
        },
        ..Default::default()
    };
    for (opcode, request) in [
        (aop::ALPC_OP_CONNECT_PORT, bytes(&connect)),
        (aop::ALPC_OP_ACCEPT_CONNECT, bytes(&accept)),
        (aop::ALPC_OP_SEND_RECEIVE, bytes(&send)),
    ] {
        let reply = alpc.dispatch(&mut core, opcode, &request, &mut out);
        assert_eq!(reply.status, NtStatus::INVALID_PARAMETER.0);
    }
}

#[test]
fn alpc_malformed_does_not_panic() {
    let mut core = PortCore::new();
    let mut alpc = AlpcServer::new();
    let r = alpc.dispatch(&mut core, aop::ALPC_OP_CREATE_PORT, &[0u8; 3], &mut []);
    assert_ne!(r.status, SUCCESS);
}

#[test]
fn alpc_port_section_and_view() {
    let mut alpc = AlpcServer::new();
    // Create a section on a (nominal) port handle.
    let cs = bytes(&AlpcCreatePortSectionRequest {
        abi_size: size_of::<AlpcCreatePortSectionRequest>() as u16,
        port_handle: 0x1000,
        section_size: 0x4000,
        ..Default::default()
    });
    let r = alpc.dispatch(
        &mut PortCore::new(),
        aop::ALPC_OP_CREATE_PORT_SECTION,
        &cs,
        &mut [],
    );
    assert_eq!(r.status, SUCCESS);
    let section = r.detail0;
    assert_ne!(section, 0);
    assert_eq!(r.information, 0x4000, "ActualSectionSize");
    assert_eq!(alpc.section_count(), 1);
    assert!(alpc.has_section_for(0x1000));

    // Map a view of it.
    let cv = bytes(&AlpcCreateSectionViewRequest {
        abi_size: size_of::<AlpcCreateSectionViewRequest>() as u16,
        port_handle: 0x1000,
        alpc_section_handle: section,
        view_size: 0x2000,
        ..Default::default()
    });
    let r = alpc.dispatch(
        &mut PortCore::new(),
        aop::ALPC_OP_CREATE_SECTION_VIEW,
        &cv,
        &mut [],
    );
    assert_eq!(r.status, SUCCESS);
    assert_ne!(r.detail0, 0, "ViewBase");
    assert_eq!(alpc.view_count(), 1);

    // Teardown ops (delete view, delete section) are idempotent no-error.
    let dv = enc_handle_req(r.detail0);
    assert_eq!(
        alpc.dispatch(
            &mut PortCore::new(),
            aop::ALPC_OP_DELETE_SECTION_VIEW,
            &dv,
            &mut []
        )
        .status,
        SUCCESS
    );
    assert_eq!(alpc.view_count(), 0);
    let ds = enc_handle_req(section);
    assert_eq!(
        alpc.dispatch(
            &mut PortCore::new(),
            aop::ALPC_OP_DELETE_PORT_SECTION,
            &ds,
            &mut []
        )
        .status,
        SUCCESS
    );
    assert_eq!(alpc.section_count(), 0);

    // A view against an unknown section is rejected.
    let bad = bytes(&AlpcCreateSectionViewRequest {
        abi_size: size_of::<AlpcCreateSectionViewRequest>() as u16,
        port_handle: 0x1000,
        alpc_section_handle: 0xDEAD,
        view_size: 0x1000,
        ..Default::default()
    });
    let r = alpc.dispatch(
        &mut PortCore::new(),
        aop::ALPC_OP_CREATE_SECTION_VIEW,
        &bad,
        &mut [],
    );
    assert_ne!(r.status, SUCCESS);
}

/// Step 2: two views of ONE section alias the same backing store — a write
/// through view A is observed by a read through view B (real shared memory, not a
/// copy). The `PortCore` is irrelevant here (sections are ALPC-only), so a fresh
/// one is fine per dispatch; the sections/views live on `alpc`.
#[test]
fn section_view_shared_memory_not_a_copy() {
    let mut alpc = AlpcServer::new();

    // Create a 16 KiB section on a nominal port.
    let cs = bytes(&AlpcCreatePortSectionRequest {
        abi_size: size_of::<AlpcCreatePortSectionRequest>() as u16,
        port_handle: 0x1000,
        section_size: 0x4000,
        ..Default::default()
    });
    let section = alpc
        .dispatch(
            &mut PortCore::new(),
            aop::ALPC_OP_CREATE_PORT_SECTION,
            &cs,
            &mut [],
        )
        .detail0;
    assert_ne!(section, 0);

    // TWO views of the SAME section — one per endpoint.
    let mk_view = |alpc: &mut AlpcServer| {
        let cv = bytes(&AlpcCreateSectionViewRequest {
            abi_size: size_of::<AlpcCreateSectionViewRequest>() as u16,
            port_handle: 0x1000,
            alpc_section_handle: section,
            view_size: 0x4000,
            ..Default::default()
        });
        alpc.dispatch(
            &mut PortCore::new(),
            aop::ALPC_OP_CREATE_SECTION_VIEW,
            &cv,
            &mut [],
        )
        .detail0
    };
    let view_a = mk_view(&mut alpc);
    let view_b = mk_view(&mut alpc);
    assert_ne!(view_a, view_b, "distinct view bases");

    // Endpoint A writes a big pattern through view A.
    let big: Vec<u8> = (0..0x2000u32).map(|i| (i * 7 + 3) as u8).collect();
    let mut w = bytes(&AlpcViewIoRequest {
        abi_size: size_of::<AlpcViewIoRequest>() as u16,
        view_base: view_a,
        view_offset: 0,
        data_offset: size_of::<AlpcViewIoRequest>() as u32,
        data_len_bytes: big.len() as u32,
        ..Default::default()
    });
    w.extend_from_slice(&big);
    let r = alpc.dispatch(
        &mut PortCore::new(),
        aop::ALPC_OP_WRITE_SECTION_VIEW,
        &w,
        &mut [],
    );
    assert_eq!(r.status, SUCCESS);
    assert_eq!(r.information, big.len() as u32);

    // Endpoint B reads through view B — sees A's write (same backing, no copy).
    let rd = bytes(&AlpcViewIoRequest {
        abi_size: size_of::<AlpcViewIoRequest>() as u16,
        view_base: view_b,
        view_offset: 0,
        data_len_bytes: big.len() as u32,
        ..Default::default()
    });
    let mut out = alloc::vec![0u8; big.len()];
    let r = alpc.dispatch(
        &mut PortCore::new(),
        aop::ALPC_OP_READ_SECTION_VIEW,
        &rd,
        &mut out,
    );
    assert_eq!(r.status, SUCCESS);
    assert_eq!(r.information as usize, big.len());
    assert_eq!(
        out, big,
        "view B observes view A's write — shared, not copied"
    );

    // A second write through B is observed through A at a different offset.
    let tail = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let mut w2 = bytes(&AlpcViewIoRequest {
        abi_size: size_of::<AlpcViewIoRequest>() as u16,
        view_base: view_b,
        view_offset: 0x2000,
        data_offset: size_of::<AlpcViewIoRequest>() as u32,
        data_len_bytes: tail.len() as u32,
        ..Default::default()
    });
    w2.extend_from_slice(&tail);
    assert_eq!(
        alpc.dispatch(
            &mut PortCore::new(),
            aop::ALPC_OP_WRITE_SECTION_VIEW,
            &w2,
            &mut []
        )
        .status,
        SUCCESS
    );
    let rd2 = bytes(&AlpcViewIoRequest {
        abi_size: size_of::<AlpcViewIoRequest>() as u16,
        view_base: view_a,
        view_offset: 0x2000,
        data_len_bytes: tail.len() as u32,
        ..Default::default()
    });
    let mut out2 = [0u8; 4];
    alpc.dispatch(
        &mut PortCore::new(),
        aop::ALPC_OP_READ_SECTION_VIEW,
        &rd2,
        &mut out2,
    );
    assert_eq!(out2, tail);

    // A write past the view bounds is rejected (no OOB).
    let oob = bytes(&AlpcViewIoRequest {
        abi_size: size_of::<AlpcViewIoRequest>() as u16,
        view_base: view_a,
        view_offset: 0x3FFF,
        data_offset: size_of::<AlpcViewIoRequest>() as u32,
        data_len_bytes: 0x10,
        ..Default::default()
    });
    assert_ne!(
        alpc.dispatch(
            &mut PortCore::new(),
            aop::ALPC_OP_WRITE_SECTION_VIEW,
            &oob,
            &mut []
        )
        .status,
        SUCCESS
    );
}

#[test]
fn large_port_section_is_sparse_until_written() {
    let mut alpc = AlpcServer::new();

    let cs = bytes(&AlpcCreatePortSectionRequest {
        abi_size: size_of::<AlpcCreatePortSectionRequest>() as u16,
        port_handle: 0x1000,
        section_size: 0x80000,
        ..Default::default()
    });
    let section = alpc
        .dispatch(
            &mut PortCore::new(),
            aop::ALPC_OP_CREATE_PORT_SECTION,
            &cs,
            &mut [],
        )
        .detail0;
    assert_ne!(section, 0);
    assert_eq!(alpc.sections[0].backing.allocated_pages(), 0);

    let mk_view = |alpc: &mut AlpcServer| {
        let cv = bytes(&AlpcCreateSectionViewRequest {
            abi_size: size_of::<AlpcCreateSectionViewRequest>() as u16,
            port_handle: 0x1000,
            alpc_section_handle: section,
            view_size: 0x80000,
            ..Default::default()
        });
        alpc.dispatch(
            &mut PortCore::new(),
            aop::ALPC_OP_CREATE_SECTION_VIEW,
            &cv,
            &mut [],
        )
        .detail0
    };
    let view_a = mk_view(&mut alpc);
    let view_b = mk_view(&mut alpc);

    let rd = bytes(&AlpcViewIoRequest {
        abi_size: size_of::<AlpcViewIoRequest>() as u16,
        view_base: view_b,
        view_offset: 0x70000,
        data_len_bytes: 16,
        ..Default::default()
    });
    let mut zeroes = [0xccu8; 16];
    let r = alpc.dispatch(
        &mut PortCore::new(),
        aop::ALPC_OP_READ_SECTION_VIEW,
        &rd,
        &mut zeroes,
    );
    assert_eq!(r.status, SUCCESS);
    assert_eq!(zeroes, [0u8; 16]);
    assert_eq!(
        alpc.sections[0].backing.allocated_pages(),
        0,
        "zero reads must not commit sparse pages"
    );

    let payload = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut wr = bytes(&AlpcViewIoRequest {
        abi_size: size_of::<AlpcViewIoRequest>() as u16,
        view_base: view_a,
        view_offset: 0x0ffe,
        data_offset: size_of::<AlpcViewIoRequest>() as u32,
        data_len_bytes: payload.len() as u32,
        ..Default::default()
    });
    wr.extend_from_slice(&payload);
    let r = alpc.dispatch(
        &mut PortCore::new(),
        aop::ALPC_OP_WRITE_SECTION_VIEW,
        &wr,
        &mut [],
    );
    assert_eq!(r.status, SUCCESS);
    assert_eq!(
        alpc.sections[0].backing.allocated_pages(),
        2,
        "a write crossing one page boundary commits only touched pages"
    );

    let rd_written = bytes(&AlpcViewIoRequest {
        abi_size: size_of::<AlpcViewIoRequest>() as u16,
        view_base: view_b,
        view_offset: 0x0ffe,
        data_len_bytes: payload.len() as u32,
        ..Default::default()
    });
    let mut out = [0u8; 8];
    let r = alpc.dispatch(
        &mut PortCore::new(),
        aop::ALPC_OP_READ_SECTION_VIEW,
        &rd_written,
        &mut out,
    );
    assert_eq!(r.status, SUCCESS);
    assert_eq!(out, payload);
}

// --- attribute (de)serialization + degradation ----------------------------

#[test]
fn attr_roundtrip_and_projection() {
    let blob = enc_attrs_view_context(0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD);
    let valid = msg_attr_flag::VIEW | msg_attr_flag::CONTEXT;
    let attrs = parse_attrs(valid, &blob);
    assert_eq!(attrs.context, Some(0xDDDD));
    assert_eq!(attrs.view.map(|v| v.section_handle), Some(0xAAAA));
    // Projects back to the same valid mask.
    assert_eq!(project_valid_attributes(&attrs), valid);
    // A view present => degrades crossing to LPC.
    assert!(degrades_to_lpc(&attrs));
    // Context-only does NOT degrade (it bridges).
    let ctx_only = parse_attrs(msg_attr_flag::CONTEXT, &enc_attrs_context(0x9));
    assert!(!degrades_to_lpc(&ctx_only));
    assert_eq!(project_valid_attributes(&ctx_only), msg_attr_flag::CONTEXT);
}

/// Step 3: a full `ALPC_MESSAGE_ATTRIBUTES` buffer (header + structs) round-trips
/// through serialize → parse, and `AllocatedAttributes` masks `ValidAttributes`.
#[test]
fn message_attributes_full_serialize_parse() {
    let attrs = MessageAttrs {
        context: Some(0xDEAD),
        view: Some(nt_port_core::DataView {
            section_handle: 0x11,
            view_base: 0x5000_0000,
            view_size: 0x2000,
        }),
        ..Default::default()
    };
    // Caller allocates CONTEXT + VIEW → both are valid.
    let allocated = msg_attr_flag::CONTEXT | msg_attr_flag::VIEW;
    let (valid, blob) = serialize_attrs(allocated, &attrs);
    assert_eq!(valid, allocated);
    let (pvalid, parsed, consumed) = parse_message_attributes(&blob);
    assert_eq!(pvalid, allocated);
    assert_eq!(parsed.context, Some(0xDEAD));
    assert_eq!(parsed.view.map(|v| v.view_base), Some(0x5000_0000));
    assert_eq!(consumed, blob.len());

    // AllocatedAttributes masks: allocate only CONTEXT → VIEW is dropped from valid.
    let (valid2, blob2) = serialize_attrs(msg_attr_flag::CONTEXT, &attrs);
    assert_eq!(valid2, msg_attr_flag::CONTEXT);
    let (_, parsed2, _) = parse_message_attributes(&blob2);
    assert_eq!(parsed2.context, Some(0xDEAD));
    assert!(
        parsed2.view.is_none(),
        "un-allocated VIEW is not serialized"
    );
}

/// Step 3: the receive out-param path serializes ALPC_MESSAGE_ATTRIBUTES at the
/// front of the reply buffer (behind the RECV_ATTRIBUTES flag), body after — and
/// the bridge degradation (an LPC-originated message → ValidAttributes 0) still
/// holds with the full parse.
#[test]
fn receive_out_param_attributes_and_bridge_degradation() {
    let mut lpc = Server::new();
    lpc.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let name = utf16("\\AttrPort");

    // ALPC host port + an ALPC client rendezvous (both ALPC → attrs flow).
    let listen = alpc
        .dispatch(
            lpc.core_mut(),
            aop::ALPC_OP_CREATE_PORT,
            &enc_create_port(&name, port_flag::NONE),
            &mut [],
        )
        .detail0;
    let cn = enc_connect(&name, 0, &port_message(msg_type::CONNECTION_REQUEST, b"c"));
    let conn_id = alpc
        .dispatch(lpc.core_mut(), aop::ALPC_OP_CONNECT_PORT, &cn, &mut [])
        .detail1;
    let mut out = [0u8; 256];
    alpc.dispatch(
        lpc.core_mut(),
        aop::ALPC_OP_RECEIVE,
        &enc_send_receive(listen, None, 0, &[]),
        &mut out,
    );
    let ac = alpc.dispatch(
        lpc.core_mut(),
        aop::ALPC_OP_ACCEPT_CONNECT,
        &enc_accept(conn_id, true, 0),
        &mut [],
    );
    let (server_h, client_h) = (ac.detail0, ac.detail1);

    // ALPC client sends a message carrying CONTEXT + VIEW.
    let body = port_message(msg_type::REQUEST, b"payload");
    let attrs = enc_attrs_view_context(0xABC, 0x6000_0000, 0x1000, 0x1234);
    let valid = msg_attr_flag::VIEW | msg_attr_flag::CONTEXT;
    let sr = enc_send_receive(client_h, Some(&body), valid, &attrs);
    alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_SEND_RECEIVE, &sr, &mut out);

    // Host receives WITH the RECV_ATTRIBUTES flag + AllocatedAttributes = VIEW|CONTEXT.
    let rr = recv_with_attrs(server_h, valid);
    let mut rout = [0u8; 256];
    let r = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_SEND_RECEIVE, &rr, &mut rout);
    assert_eq!(r.status, SUCCESS);
    assert_eq!(
        r.detail0 as u32, valid,
        "ValidAttributes = allocated & present"
    );
    // Parse the front ALPC_MESSAGE_ATTRIBUTES; the body follows.
    let (pvalid, parsed, consumed) = parse_message_attributes(&rout[..r.information as usize]);
    assert_eq!(pvalid, valid);
    assert_eq!(parsed.context, Some(0x1234));
    assert_eq!(parsed.view.map(|v| v.view_base), Some(0x6000_0000));
    assert_eq!(
        &rout[consumed..r.information as usize],
        &body[..],
        "body after the attrs"
    );

    // --- bridge: an LPC client to the same host degrades to ValidAttributes 0.
    let name2 = utf16("\\AttrBridge");
    let listen2 = alpc
        .dispatch(
            lpc.core_mut(),
            aop::ALPC_OP_CREATE_PORT,
            &enc_create_port(&name2, port_flag::LPC_MODE),
            &mut [],
        )
        .detail0;
    let lconn = {
        let mut c = LpcClient::new(LpcDirect {
            server: &mut lpc,
            out: [0; 512],
        });
        c.connect_port(&name2, 2, b"SB").unwrap().connection_id
    };
    alpc.dispatch(
        lpc.core_mut(),
        aop::ALPC_OP_RECEIVE,
        &enc_send_receive(listen2, None, 0, &[]),
        &mut out,
    );
    let ac2 = alpc.dispatch(
        lpc.core_mut(),
        aop::ALPC_OP_ACCEPT_CONNECT,
        &enc_accept(lconn, true, 0),
        &mut [],
    );
    let (bserver_h, bclient_h) = (ac2.detail0, ac2.detail1);
    // LPC client sends (no attributes).
    lpc.core_mut()
        .send_message(
            bclient_h,
            &port_message(msg_type::REQUEST, b"lp"),
            MessageAttrs::default(),
        )
        .unwrap();
    // ALPC host receives WITH RECV_ATTRIBUTES + all allocated → still ValidAttributes 0.
    let rr2 = recv_with_attrs(bserver_h, 0xF800_0000);
    let mut rout2 = [0u8; 256];
    let r2 = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_SEND_RECEIVE, &rr2, &mut rout2);
    assert_eq!(r2.detail0, 0, "LPC-originated message → no ALPC attributes");
    let (pv2, _, consumed2) = parse_message_attributes(&rout2[..r2.information as usize]);
    assert_eq!(pv2, 0);
    assert_eq!(
        consumed2,
        size_of::<nt_alpc_abi::AlpcMessageAttributes>(),
        "header only, no structs"
    );
}

/// Build a send/receive request with the RECV_ATTRIBUTES flag set and `allocated`
/// as the receiver's AllocatedAttributes mask.
fn recv_with_attrs(port: u64, allocated: u32) -> Vec<u8> {
    bytes(&AlpcSendReceiveRequest {
        abi_size: size_of::<AlpcSendReceiveRequest>() as u16,
        flags: nt_alpc_abi::send_flag::RECV_ATTRIBUTES,
        port_handle: port,
        valid_attributes: allocated,
        ..Default::default()
    })
}

#[test]
fn exact_alpc_connections_do_not_share_receive_or_disconnect_state() {
    let mut core = PortCore::new();
    core.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let name = utf16("\\AlpcExact");
    let listen = alpc
        .dispatch(
            &mut core,
            aop::ALPC_OP_CREATE_PORT,
            &enc_create_port(&name, port_flag::NONE),
            &mut [],
        )
        .detail0;
    let mut clients = [0u64; 2];
    let mut servers = [0u64; 2];

    for index in 0..2 {
        let connect = alpc.dispatch(
            &mut core,
            aop::ALPC_OP_CONNECT_PORT,
            &enc_connect(
                &name,
                0,
                &port_message(msg_type::CONNECTION_REQUEST, b"connect"),
            ),
            &mut [],
        );
        assert_eq!(connect.status, NtStatus::PENDING.raw());
        let connection_id = connect.detail1;
        let mut out = [0u8; 128];
        let received = alpc.dispatch(
            &mut core,
            aop::ALPC_OP_RECEIVE,
            &enc_send_receive(listen, None, 0, &[]),
            &mut out,
        );
        assert_eq!(received.detail0, connection_id);
        let accepted = alpc.dispatch(
            &mut core,
            aop::ALPC_OP_ACCEPT_CONNECT,
            &enc_accept(connection_id, true, index as u64),
            &mut [],
        );
        assert_eq!(accepted.status, SUCCESS);
        servers[index] = accepted.detail0;
        clients[index] = accepted.detail1;
    }

    let first = port_message(msg_type::REQUEST, b"first");
    let second = port_message(msg_type::REQUEST, b"second");
    for (client, message) in [(clients[0], &first), (clients[1], &second)] {
        let send = enc_send_receive(client, Some(message), 0, &[]);
        assert_eq!(
            alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &send, &mut [])
                .status,
            NtStatus::PENDING.raw()
        );
    }

    let mut out = [0u8; 128];
    let receive_second = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_RECEIVE,
        &enc_send_receive(servers[1], None, 0, &[]),
        &mut out,
    );
    assert_eq!(&out[..receive_second.information as usize], &second);
    let receive_first = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_RECEIVE,
        &enc_send_receive(servers[0], None, 0, &[]),
        &mut out,
    );
    assert_eq!(&out[..receive_first.information as usize], &first);

    let listen_send = enc_send_receive(listen, Some(&first), 0, &[]);
    assert_eq!(
        alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &listen_send, &mut out)
            .status,
        NtStatus::INVALID_PORT_HANDLE.raw()
    );
    assert_eq!(
        alpc.dispatch(
            &mut core,
            aop::ALPC_OP_DISCONNECT_PORT,
            &enc_handle_req(clients[0]),
            &mut [],
        )
        .status,
        SUCCESS
    );
    let stale_send = enc_send_receive(servers[0], Some(&first), 0, &[]);
    assert_eq!(
        alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &stale_send, &mut [])
            .status,
        NtStatus::INVALID_PORT_HANDLE.raw()
    );

    let live_reply = port_message(msg_type::REPLY, b"live");
    let live_send = enc_send_receive(servers[1], Some(&live_reply), 0, &[]);
    assert_eq!(
        alpc.dispatch(&mut core, aop::ALPC_OP_SEND_RECEIVE, &live_send, &mut [])
            .status,
        NtStatus::PENDING.raw()
    );
    let live_receive = alpc.dispatch(
        &mut core,
        aop::ALPC_OP_RECEIVE,
        &enc_send_receive(clients[1], None, 0, &[]),
        &mut out,
    );
    assert_eq!(
        &out[..live_receive.information as usize],
        &live_reply,
        "disconnecting one connection must not affect its sibling"
    );

    let lpc_listen = core.create_port(&utf16("\\Classic"), PortApi::Lpc);
    let lpc_connection = match core
        .connect(&utf16("\\Classic"), PortApi::Lpc, 0, &[])
        .unwrap()
    {
        ConnectOutcome::Pending { connection_id } => connection_id,
        _ => unreachable!(),
    };
    core.receive(lpc_listen).unwrap();
    let lpc_server = core.accept(lpc_connection, true, 0).unwrap();
    let lpc_client = core.complete(lpc_connection).unwrap().0;
    assert_eq!(
        alpc.dispatch(
            &mut core,
            aop::ALPC_OP_DISCONNECT_PORT,
            &enc_handle_req(lpc_client),
            &mut [],
        )
        .status,
        NtStatus::INVALID_PORT_HANDLE.raw(),
        "the ALPC adapter must not disconnect a classic-LPC endpoint"
    );
    core.send_message(lpc_client, b"still-connected", MessageAttrs::default())
        .unwrap();
    assert_eq!(
        core.receive_message(lpc_server).unwrap().unwrap().bytes,
        b"still-connected"
    );
}

// --- LPC direct backend for driving the classic-LPC adapter in the test ----

struct LpcDirect<'a> {
    server: &'a mut Server,
    out: [u8; 512],
}
impl Backend for LpcDirect<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> nt_lpc_abi::LpcReply {
        let r = self.server.dispatch(opcode, in_buf, &mut self.out);
        let n = (r.information as usize)
            .min(out_buf.len())
            .min(self.out.len());
        out_buf[..n].copy_from_slice(&self.out[..n]);
        r
    }
}

// ===========================================================================
// THE BRIDGE — an LPC client and an ALPC host (and vice-versa) over ONE core.
// ===========================================================================

/// Direction 1: a classic-LPC client connects to an ALPC host, over one shared
/// core, and a message crosses each way with the documented attribute
/// degradation.
#[test]
fn bridge_lpc_client_to_alpc_host() {
    // ONE shared core, held by the LPC adapter; the ALPC adapter borrows it.
    let mut lpc = Server::new();
    lpc.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let name = utf16("\\Bridge1");

    // ALPC host creates the port (LPC_MODE = classic-LPC-compatible).
    let listen = {
        let cp = enc_create_port(&name, port_flag::LPC_MODE);
        let r = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_CREATE_PORT, &cp, &mut []);
        assert_eq!(r.status, SUCCESS);
        r.detail0
    };

    // LPC client connects with an SB_CONNECTION_INFO-style blob → pending.
    let conn_id = {
        let mut c = LpcClient::new(LpcDirect {
            server: &mut lpc,
            out: [0; 512],
        });
        let r = c.connect_port(&name, 2, b"SB_CONNECTION_INFO").unwrap();
        assert!(r.pending, "manual policy leaves the LPC connect pending");
        r.connection_id
    };
    // The ALPC host sees the LPC connection-info blob byte-for-byte (bridge
    // connection-info passthrough) + the subsystem type.
    assert_eq!(
        lpc.core_mut().connection_info(conn_id),
        Some(&b"SB_CONNECTION_INFO"[..])
    );
    assert_eq!(lpc.core_mut().connection_subsystem_type(conn_id), Some(2));

    // ALPC host receives the connection request via SendWaitReceivePort.
    {
        let sr = enc_send_receive(listen, None, 0, &[]);
        let mut out = [0u8; 256];
        let r = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_RECEIVE, &sr, &mut out);
        assert_eq!(r.status, SUCCESS);
        assert_eq!(r.detail0, conn_id, "connection id");
        assert_eq!(r.detail1 as u16, msg_type::CONNECTION_REQUEST);
    }

    // ALPC accept (folds complete) → both comm-port handles.
    let (server_h, client_h) = {
        let ac = enc_accept(conn_id, true, 0xC0FFEE);
        let r = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_ACCEPT_CONNECT, &ac, &mut []);
        assert_eq!(r.status, SUCCESS);
        (r.detail0, r.detail1)
    };
    assert_ne!(server_h, 0);
    assert_ne!(client_h, 0);
    assert_eq!(
        lpc.core_mut().connection_state(conn_id),
        Some(ConnState::Connected)
    );
    // The connection is a genuine cross-API pair: LPC client ↔ ALPC server.
    assert_eq!(
        lpc.core_mut().connection_apis(conn_id),
        Some((PortApi::Lpc, PortApi::Alpc))
    );

    // --- LPC client → ALPC host: no attributes (LPC → ALPC degrades to empty).
    let req = port_message(msg_type::REQUEST, b"ping");
    lpc.core_mut()
        .send_message(client_h, &req, MessageAttrs::default())
        .unwrap();
    {
        let sr = enc_send_receive(server_h, None, 0, &[]);
        let mut out = [0u8; 256];
        let r = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_SEND_RECEIVE, &sr, &mut out);
        assert_eq!(r.status, SUCCESS);
        assert_eq!(&out[..r.information as usize], &req[..]);
        assert_eq!(
            r.detail0, 0,
            "an LPC-originated message must present ValidAttributes == 0 to ALPC"
        );
    }

    // --- ALPC host → LPC client: carries VIEW + CONTEXT; the LPC client sees
    //     only the PORT_MESSAGE body (VIEW dropped; CONTEXT bridges).
    let reply = port_message(msg_type::REPLY, b"pong");
    let attrs = enc_attrs_view_context(0x1234, 0x5000_0000, 0x2000, 0xCAFE);
    let valid = msg_attr_flag::VIEW | msg_attr_flag::CONTEXT;
    {
        let sr = enc_send_receive(server_h, Some(&reply), valid, &attrs);
        let mut out = [0u8; 256];
        // Send half enqueues the reply; the receive half parks (nothing inbound).
        let _ = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_SEND_RECEIVE, &sr, &mut out);
    }
    // LPC client receives via its (direct) data plane — attributes are dropped.
    let got = lpc.core_mut().receive_message(client_h).unwrap().unwrap();
    assert_eq!(got.bytes, reply, "the PORT_MESSAGE body crosses intact");
    assert!(got.attrs.context.is_some(), "CONTEXT is carried (bridges)");
    assert!(
        degrades_to_lpc(&got.attrs),
        "the VIEW attribute does not bridge → the message degrades crossing to LPC"
    );
}

/// Direction 2: an ALPC client connects to a classic-LPC host, over one shared
/// core, with a message each way.
#[test]
fn bridge_alpc_client_to_lpc_host() {
    let mut lpc = Server::new();
    lpc.set_accept_policy(AcceptPolicy::Manual);
    let mut alpc = AlpcServer::new();
    let name = utf16("\\Bridge2");

    // LPC host creates the port.
    let listen = {
        let mut c = LpcClient::new(LpcDirect {
            server: &mut lpc,
            out: [0; 512],
        });
        c.create_port(&name, 0x88, 0x148, 0).unwrap()
    };

    // ALPC client connects, carrying a connect PORT_MESSAGE payload → pending.
    let connect_payload = port_message(msg_type::CONNECTION_REQUEST, b"ALPC_CONNECT_BLOB");
    let conn_id = {
        let cn = enc_connect(&name, 0, &connect_payload);
        let r = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_CONNECT_PORT, &cn, &mut []);
        assert_eq!(r.status, NtStatus::PENDING.raw());
        r.detail1
    };
    // The LPC host sees the ALPC connect payload as its connection-info blob.
    assert_eq!(
        lpc.core_mut().connection_info(conn_id),
        Some(&connect_payload[..])
    );

    // LPC host receives, accepts, completes (separate ops, the classic path).
    let (server_h, client_h) = {
        let mut c = LpcClient::new(LpcDirect {
            server: &mut lpc,
            out: [0; 512],
        });
        let rc = c.reply_wait_receive(listen).unwrap();
        assert_eq!(rc.connection_id, conn_id);
        assert_eq!(rc.msg_type, msg_type::CONNECTION_REQUEST);
        let sh = c.accept_connect(conn_id, true, 0).unwrap();
        let ch = c.complete_connect(conn_id).unwrap().handle;
        (sh, ch)
    };
    assert_ne!(server_h, 0);
    assert_ne!(client_h, 0);
    assert_eq!(
        lpc.core_mut().connection_apis(conn_id),
        Some((PortApi::Alpc, PortApi::Lpc))
    );
    let _ = listen;

    // --- ALPC client → LPC host: carries CONTEXT (bridges); LPC host reads body.
    let req = port_message(msg_type::REQUEST, b"hi");
    {
        let sr = enc_send_receive(
            client_h,
            Some(&req),
            msg_attr_flag::CONTEXT,
            &enc_attrs_context(0xABCD),
        );
        let mut out = [0u8; 256];
        let _ = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_SEND_RECEIVE, &sr, &mut out);
    }
    let got = lpc.core_mut().receive_message(server_h).unwrap().unwrap();
    assert_eq!(got.bytes, req);
    assert_eq!(
        got.attrs.context,
        Some(0xABCD),
        "CONTEXT carried across the bridge"
    );

    // --- LPC host → ALPC client: no attributes; the ALPC client sees empty valid.
    let reply = port_message(msg_type::REPLY, b"yo");
    lpc.core_mut()
        .send_message(server_h, &reply, MessageAttrs::default())
        .unwrap();
    {
        let sr = enc_send_receive(client_h, None, 0, &[]);
        let mut out = [0u8; 256];
        let r = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_SEND_RECEIVE, &sr, &mut out);
        assert_eq!(r.status, SUCCESS);
        assert_eq!(&out[..r.information as usize], &reply[..]);
        assert_eq!(r.detail0, 0, "LPC host reply presents no ALPC attributes");
    }
}
