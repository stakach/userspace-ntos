//! Live ALPC + LPC↔ALPC bridge self-test, driven over the REAL SURT ring against
//! the unified port-service component (ONE `PortCore` + both adapters).
//!
//! This is the integration proof: no real binary uses ALPC yet, so the running
//! kernel exercises (a) a pure ALPC client↔host rendezvous + message plane and
//! (b) the LPC↔ALPC bridge — an LPC client connecting to an ALPC host over the
//! SAME core, with a message each way asserting the documented degradation
//! policy — all as counted specs. Everything is driven raw on the shared channel
//! (`RingChannel::raw`), building the fixed-layout LPC/ALPC request buffers.

use crate::{check, print_str, RingChannel};

use bytemuck::Pod;
use nt_alpc_abi::{
    msg_attr_flag, opcode as aop, port_flag, AlpcAcceptConnectRequest, AlpcConnectPortRequest,
    AlpcContextAttr, AlpcCreatePortRequest, AlpcDataViewAttr, AlpcSendReceiveRequest, PortMessage,
};
use nt_lpc_abi::{opcode as lop, LpcConnectPortRequest, LpcMessageRequest, LpcReceiveRequest};

const CONNECTION_REQUEST: u16 = 10;
const REQUEST: u16 = 1;
const REPLY: u16 = 2;
const STATUS_PENDING: i32 = 0x0000_0103;
const STATUS_SUCCESS: i32 = 0;

fn utf16(s: &str) -> alloc::vec::Vec<u16> {
    s.encode_utf16().collect()
}

fn bytes<T: Pod>(v: &T) -> alloc::vec::Vec<u8> {
    bytemuck::bytes_of(v).to_vec()
}

fn push_utf16(buf: &mut alloc::vec::Vec<u8>, s: &[u16]) {
    for &u in s {
        buf.extend_from_slice(&u.to_le_bytes());
    }
}

fn port_message(msg_type: u16, payload: &[u8]) -> alloc::vec::Vec<u8> {
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

/// Run the live ALPC + bridge self-test on the shared port-service ring.
pub fn run(chan: &mut RingChannel<'_>, passed: &mut u64) {
    print_str(b"[ntos-exec] live ALPC + LPC->ALPC bridge self-test over the shared port core\n");
    let mut out = [0u8; 256];

    // ================= A. pure ALPC client <-> ALPC host =================
    // Create an ALPC port.
    let name = utf16("\\AlpcLive");
    let cp = {
        let hdr = core::mem::size_of::<AlpcCreatePortRequest>() as u32;
        let req = AlpcCreatePortRequest {
            abi_size: hdr as u16,
            port_flags: port_flag::LPC_MODE,
            max_message_length: 0x1000,
            name_offset: hdr,
            name_len_bytes: (name.len() * 2) as u32,
            ..Default::default()
        };
        let mut b = bytes(&req);
        push_utf16(&mut b, &name);
        b
    };
    let (status, _f, _i, listen, _d1) = chan.raw(aop::ALPC_OP_CREATE_PORT, &cp, &mut out);
    check(b"exec_alpc_create_port", status == STATUS_SUCCESS && listen != 0, passed);

    // ALPC client connects (Manual -> Pending), ALPC host receives + accepts (folds complete).
    let (server_h, client_h, connect_ok) = alpc_rendezvous(chan, &name, listen, &mut out);
    check(b"exec_alpc_connect_rendezvous", connect_ok, passed);

    // Client -> host message carrying CONTEXT: ALPC->ALPC preserves the attribute.
    let msg = port_message(REQUEST, b"alpc-ping");
    alpc_send(chan, client_h, &msg, msg_attr_flag::CONTEXT, &bytes(&AlpcContextAttr {
        port_context: 0xC0DE,
        ..Default::default()
    }), &mut out);
    let (rs, _f, ri, valid, mtype) = alpc_recv(chan, server_h, &mut out);
    let ctx_ok = rs == STATUS_SUCCESS
        && &out[..ri as usize] == &msg[..]
        && (valid as u32) & msg_attr_flag::CONTEXT != 0
        && mtype as u16 == REQUEST;
    check(b"exec_alpc_message_context_preserved", ctx_ok, passed);

    // ================= B. LPC client <-> ALPC host (the BRIDGE) =================
    let bname = utf16("\\BridgeLive");
    let blisten = {
        let hdr = core::mem::size_of::<AlpcCreatePortRequest>() as u32;
        let req = AlpcCreatePortRequest {
            abi_size: hdr as u16,
            port_flags: port_flag::LPC_MODE,
            max_message_length: 0x1000,
            name_offset: hdr,
            name_len_bytes: (bname.len() * 2) as u32,
            ..Default::default()
        };
        let mut b = bytes(&req);
        push_utf16(&mut b, &bname);
        let (s, _f, _i, h, _d) = chan.raw(aop::ALPC_OP_CREATE_PORT, &b, &mut out);
        if s == STATUS_SUCCESS {
            h
        } else {
            0
        }
    };

    // LPC client connects to the ALPC host's port (classic LPC connect, same core).
    let lpc_conn_id = {
        let hdr = core::mem::size_of::<LpcConnectPortRequest>() as u32;
        let nb = (bname.len() * 2) as u32;
        let req = LpcConnectPortRequest {
            abi_size: hdr as u16,
            flags: 0,
            subsystem_type: 2,
            name_offset: hdr,
            name_len_bytes: nb,
            conninfo_offset: hdr + nb,
            conninfo_len_bytes: 6,
        };
        let mut b = bytes(&req);
        push_utf16(&mut b, &bname);
        b.extend_from_slice(b"SBINFO");
        let (s, _f, _i, _d0, cid) = chan.raw(lop::LPC_OP_CONNECT_PORT, &b, &mut out);
        if s == STATUS_PENDING {
            cid
        } else {
            0
        }
    };

    // ALPC host receives the (LPC-originated) connection request + accepts it.
    let (bserver_h, bclient_h) = {
        let (rs, _f, _i, rconn, rtype) = alpc_recv(chan, blisten, &mut out);
        let recv_ok = rs == STATUS_SUCCESS && rconn == lpc_conn_id && rtype as u16 == CONNECTION_REQUEST;
        let ac = AlpcAcceptConnectRequest {
            abi_size: core::mem::size_of::<AlpcAcceptConnectRequest>() as u16,
            accept: 1,
            _reserved: 0,
            connection_id: lpc_conn_id,
            port_context: 0xBEEF,
        };
        let (as_, _f, _i, sh, ch) = chan.raw(aop::ALPC_OP_ACCEPT_CONNECT, &bytes(&ac), &mut out);
        let ok = recv_ok && as_ == STATUS_SUCCESS && sh != 0 && ch != 0;
        check(b"exec_bridge_lpc_to_alpc_connect", ok && lpc_conn_id != 0 && blisten != 0, passed);
        (sh, ch)
    };

    // LPC client sends "ping" (NO attributes) via the classic-LPC message plane;
    // the ALPC host must see it with ValidAttributes == 0 (LPC->ALPC degradation).
    let lmsg = port_message(REQUEST, b"lpc-ping");
    lpc_send(chan, bclient_h, &lmsg, &mut out);
    let (rs, _f, ri, valid, _mt) = alpc_recv(chan, bserver_h, &mut out);
    let degrade_ok = rs == STATUS_SUCCESS && &out[..ri as usize] == &lmsg[..] && valid == 0;
    check(b"exec_bridge_lpc_msg_degrades_to_empty", degrade_ok, passed);

    // ALPC host replies carrying VIEW + CONTEXT; the LPC client sees ONLY the
    // PORT_MESSAGE body (the VIEW attribute does not bridge — it is dropped).
    let rmsg = port_message(REPLY, b"alpc-pong");
    let mut attrs = bytes(&AlpcDataViewAttr {
        section_handle: 0x1234,
        view_base: 0x5000_0000,
        view_size: 0x2000,
        ..Default::default()
    });
    attrs.extend_from_slice(&bytes(&AlpcContextAttr {
        port_context: 0xCAFE,
        ..Default::default()
    }));
    alpc_send(chan, bserver_h, &rmsg, msg_attr_flag::VIEW | msg_attr_flag::CONTEXT, &attrs, &mut out);
    // LPC client receives via the classic-LPC receive (no attribute surface).
    let (ls, _f, li, ldetail0, _lmt) = lpc_recv(chan, bclient_h, &mut out);
    let reply_ok = ls == STATUS_SUCCESS && &out[..li as usize] == &rmsg[..] && ldetail0 == 0;
    check(b"exec_bridge_alpc_reply_body_only", reply_ok, passed);
}

// --- ALPC drive helpers ----------------------------------------------------

fn alpc_rendezvous(
    chan: &mut RingChannel<'_>,
    name: &[u16],
    listen: u64,
    out: &mut [u8],
) -> (u64, u64, bool) {
    // Connect (Manual -> Pending).
    let hdr = core::mem::size_of::<AlpcConnectPortRequest>() as u32;
    let nb = (name.len() * 2) as u32;
    let connect_msg = port_message(CONNECTION_REQUEST, b"ALPC_CONNECT");
    let req = AlpcConnectPortRequest {
        abi_size: hdr as u16,
        subsystem_type: 0,
        name_offset: hdr,
        name_len_bytes: nb,
        message_offset: hdr + nb,
        message_len_bytes: connect_msg.len() as u32,
        ..Default::default()
    };
    let mut b = bytes(&req);
    push_utf16(&mut b, name);
    b.extend_from_slice(&connect_msg);
    let (cs, _f, _i, _d0, conn_id) = chan.raw(aop::ALPC_OP_CONNECT_PORT, &b, out);
    if cs != STATUS_PENDING || conn_id == 0 {
        return (0, 0, false);
    }
    // Host receives the connection request.
    let (rs, _f, _i, rconn, rtype) = alpc_recv(chan, listen, out);
    if rs != STATUS_SUCCESS || rconn != conn_id || rtype as u16 != CONNECTION_REQUEST {
        return (0, 0, false);
    }
    // Host accepts (folds complete) -> server + client comm handles.
    let ac = AlpcAcceptConnectRequest {
        abi_size: core::mem::size_of::<AlpcAcceptConnectRequest>() as u16,
        accept: 1,
        _reserved: 0,
        connection_id: conn_id,
        port_context: 0xC0FFEE,
    };
    let (as_, _f, _i, sh, ch) = chan.raw(aop::ALPC_OP_ACCEPT_CONNECT, &bytes(&ac), out);
    (sh, ch, as_ == STATUS_SUCCESS && sh != 0 && ch != 0)
}

fn alpc_send(
    chan: &mut RingChannel<'_>,
    port: u64,
    msg: &[u8],
    valid: u32,
    attrs: &[u8],
    out: &mut [u8],
) {
    let hdr = core::mem::size_of::<AlpcSendReceiveRequest>() as u32;
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
    // Send half enqueues; the receive half parks (nothing inbound) — that's fine.
    let _ = chan.raw(aop::ALPC_OP_SEND_RECEIVE, &b, out);
}

fn alpc_recv(chan: &mut RingChannel<'_>, port: u64, out: &mut [u8]) -> (i32, u32, u64, u64, u64) {
    let hdr = core::mem::size_of::<AlpcSendReceiveRequest>() as u32;
    let req = AlpcSendReceiveRequest {
        abi_size: hdr as u16,
        port_handle: port,
        message_offset: hdr,
        message_len_bytes: 0,
        ..Default::default()
    };
    chan.raw(aop::ALPC_OP_RECEIVE, &bytes(&req), out)
}

// --- LPC drive helpers (classic-LPC message plane, no attributes) ----------

fn lpc_send(chan: &mut RingChannel<'_>, port: u64, msg: &[u8], out: &mut [u8]) {
    let hdr = core::mem::size_of::<LpcMessageRequest>() as u32;
    let req = LpcMessageRequest {
        abi_size: hdr as u16,
        _reserved: 0,
        _reserved2: 0,
        port_handle: port,
        msg_offset: hdr,
        msg_len_bytes: msg.len() as u32,
    };
    let mut b = bytes(&req);
    b.extend_from_slice(msg);
    let _ = chan.raw(lop::LPC_OP_REPLY_PORT, &b, out);
}

fn lpc_recv(chan: &mut RingChannel<'_>, port: u64, out: &mut [u8]) -> (i32, u32, u64, u64, u64) {
    let req = LpcReceiveRequest {
        abi_size: core::mem::size_of::<LpcReceiveRequest>() as u16,
        _reserved: 0,
        _reserved2: 0,
        port_handle: port,
        reply_msg_offset: 0,
        reply_msg_len_bytes: 0,
    };
    chan.raw(lop::LPC_OP_REPLY_WAIT_RECEIVE, &bytes(&req), out)
}
