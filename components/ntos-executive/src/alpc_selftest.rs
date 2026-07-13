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
    msg_attr_flag, opcode as aop, port_flag, send_flag, AlpcAcceptConnectRequest,
    AlpcConnectPortRequest, AlpcContextAttr, AlpcCreatePortRequest, AlpcCreatePortSectionRequest,
    AlpcCreateSectionViewRequest, AlpcDataViewAttr, AlpcMessageAttributes, AlpcSendReceiveRequest,
    AlpcViewIoRequest, PortMessage,
};
use nt_alpc::PeerDirect;
use nt_lpc_abi::{opcode as lop, LpcConnectPortRequest, LpcMessageRequest, LpcReceiveRequest};
use nt_port_core::MessageAttrs;

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

    // Step 2: REAL cross-endpoint shared memory via a port section + two views.
    // Endpoint A (client) writes big data into its view; endpoint B (server) reads
    // it back through ITS view of the same section — proving the data travelled
    // through shared memory, NOT the (tiny) PORT_MESSAGE body.
    check(
        b"exec_alpc_section_view_shared",
        section_view_shared(chan, listen, client_h, server_h, &mut out),
        passed,
    );

    // Step 3: a full ALPC_MESSAGE_ATTRIBUTES round-trip — the receive out-param
    // path serializes the header + CONTEXT + VIEW structs; the receiver parses
    // ValidAttributes + both structs back.
    check(
        b"exec_alpc_message_attributes_roundtrip",
        message_attributes_roundtrip(chan, client_h, server_h),
        passed,
    );

    // Step 4: peer-direct data plane — the broker (port-service ring) completes
    // the connect, then endpoint↔endpoint messages are delivered DIRECTLY against
    // the executive-local cache with the broker OFF the per-message path.
    check(b"exec_alpc_peer_direct", peer_direct(chan, &mut out), passed);

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

    // ================= C. item (a): NtAlpc* SSN registration + routing =================
    ssn_registration(chan, passed);
}

/// ALPC last-mile item (a): the executive registers the Win7 `NtAlpc*` SSNs (extracted from
/// references/ntdll.dll) in its fault dispatcher via `alpc_ssn_to_opcode`, routing an ALPC syscall
/// to the unified port-service ALPC adapter. No hosted ALPC binary exists (the live ReactOS
/// processes issue NO NtAlpc*, and the Win7 ALPC SSNs collide with the live ReactOS SSN space — so
/// the live route is gated by ALPC-process identity, dormant at boot). These two counted specs prove
/// the SSN→opcode registration is correct AND that a recognized NtAlpc* SSN routes end-to-end to the
/// ALPC adapter over the SAME ring the live route would use — the syscall path, minus only the seL4
/// fault delivery (identical to the proven live smss/csrss hosted-syscall path).
fn ssn_registration(chan: &mut RingChannel<'_>, passed: &mut u64) {
    use crate::{
        alpc_ssn_to_opcode, SSN_NT_ALPC_ACCEPT_CONNECT_PORT, SSN_NT_ALPC_CONNECT_PORT,
        SSN_NT_ALPC_CREATE_PORT, SSN_NT_ALPC_CREATE_PORT_SECTION, SSN_NT_ALPC_CREATE_SECTION_VIEW,
        SSN_NT_ALPC_DISCONNECT_PORT, SSN_NT_ALPC_SEND_WAIT_RECEIVE_PORT,
    };

    // (1) The SSN→opcode table matches the ntdll-extracted SSNs, and a non-ALPC SSN is rejected.
    let table_ok = alpc_ssn_to_opcode(SSN_NT_ALPC_CREATE_PORT) == Some(aop::ALPC_OP_CREATE_PORT)
        && alpc_ssn_to_opcode(SSN_NT_ALPC_CONNECT_PORT) == Some(aop::ALPC_OP_CONNECT_PORT)
        && alpc_ssn_to_opcode(SSN_NT_ALPC_ACCEPT_CONNECT_PORT) == Some(aop::ALPC_OP_ACCEPT_CONNECT)
        && alpc_ssn_to_opcode(SSN_NT_ALPC_SEND_WAIT_RECEIVE_PORT) == Some(aop::ALPC_OP_SEND_RECEIVE)
        && alpc_ssn_to_opcode(SSN_NT_ALPC_DISCONNECT_PORT) == Some(aop::ALPC_OP_DISCONNECT_PORT)
        && alpc_ssn_to_opcode(SSN_NT_ALPC_CREATE_PORT_SECTION)
            == Some(aop::ALPC_OP_CREATE_PORT_SECTION)
        && alpc_ssn_to_opcode(SSN_NT_ALPC_CREATE_SECTION_VIEW)
            == Some(aop::ALPC_OP_CREATE_SECTION_VIEW)
        && alpc_ssn_to_opcode(0x1234).is_none();
    check(b"exec_alpc_ssn_registered", table_ok, passed);

    // (2) Route an NtAlpcCreatePort SSN through the recognizer → the adapter creates a real port.
    let mut out = [0u8; 256];
    let name = utf16("\\AlpcSsnRoute");
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
    let op = alpc_ssn_to_opcode(SSN_NT_ALPC_CREATE_PORT);
    let routed_ok = match op {
        Some(op) => {
            let (status, _f, _i, listen, _d) = chan.raw(op, &b, &mut out);
            status == STATUS_SUCCESS && listen != 0
        }
        None => false,
    };
    check(b"exec_alpc_ssn_routes_to_adapter", routed_ok, passed);
}

/// Step 2 driver: a port section shared by two views. Endpoint A writes big data
/// through view A; endpoint B reads it back through view B (same backing store).
/// The PORT_MESSAGE that signals it carries only a DATA_VIEW_ATTR + a tiny body.
fn section_view_shared(
    chan: &mut RingChannel<'_>,
    listen: u64,
    client_h: u64,
    server_h: u64,
    out: &mut [u8],
) -> bool {
    const SIZE: u64 = 0x4000;
    const BIG: usize = 2048;

    // Create the port section (real shared backing store) on the listen port.
    let cs = AlpcCreatePortSectionRequest {
        abi_size: core::mem::size_of::<AlpcCreatePortSectionRequest>() as u16,
        port_handle: listen,
        section_size: SIZE,
        ..Default::default()
    };
    let (s, _f, sz, section, _d) = chan.raw(aop::ALPC_OP_CREATE_PORT_SECTION, &bytes(&cs), out);
    if s != STATUS_SUCCESS || section == 0 || sz as u64 != SIZE {
        return false;
    }

    // Two views of the SAME section — one per endpoint.
    let mut mk_view = |chan: &mut RingChannel<'_>, out: &mut [u8]| -> u64 {
        let cv = AlpcCreateSectionViewRequest {
            abi_size: core::mem::size_of::<AlpcCreateSectionViewRequest>() as u16,
            port_handle: listen,
            alpc_section_handle: section,
            view_size: SIZE,
            ..Default::default()
        };
        let (s, _f, _i, vb, _d) = chan.raw(aop::ALPC_OP_CREATE_SECTION_VIEW, &bytes(&cv), out);
        if s == STATUS_SUCCESS {
            vb
        } else {
            0
        }
    };
    let view_a = mk_view(chan, out);
    let view_b = mk_view(chan, out);
    if view_a == 0 || view_b == 0 || view_a == view_b {
        return false;
    }

    // Endpoint A writes a big pattern THROUGH view A into the shared section.
    let big: alloc::vec::Vec<u8> = (0..BIG).map(|i| (i as u32 * 5 + 1) as u8).collect();
    let hdr = core::mem::size_of::<AlpcViewIoRequest>() as u32;
    let mut w = bytes(&AlpcViewIoRequest {
        abi_size: hdr as u16,
        view_base: view_a,
        view_offset: 0,
        data_offset: hdr,
        data_len_bytes: BIG as u32,
        ..Default::default()
    });
    w.extend_from_slice(&big);
    let (ws, _f, wn, _d0, _d1) = chan.raw(aop::ALPC_OP_WRITE_SECTION_VIEW, &w, out);
    if ws != STATUS_SUCCESS || wn as usize != BIG {
        return false;
    }

    // Endpoint A sends a small PORT_MESSAGE carrying a DATA_VIEW_ATTR referencing
    // the view — NO big body (the data rides the shared section, not the message).
    let signal = port_message(REQUEST, b"view-ready");
    let view_attr = bytes(&AlpcDataViewAttr {
        section_handle: section,
        view_base: view_a,
        view_size: BIG as u64,
        ..Default::default()
    });
    alpc_send(chan, client_h, &signal, msg_attr_flag::VIEW, &view_attr, out);

    // Endpoint B receives the signal (VIEW attribute present) ...
    let (rs, _f, ri, valid, _mt) = alpc_recv(chan, server_h, out);
    if rs != STATUS_SUCCESS
        || &out[..ri as usize] != &signal[..]
        || (valid as u32) & msg_attr_flag::VIEW == 0
    {
        return false;
    }
    // ... then reads the big data back THROUGH view B — the shared-memory proof.
    let rd = AlpcViewIoRequest {
        abi_size: hdr as u16,
        view_base: view_b,
        view_offset: 0,
        data_len_bytes: BIG as u32,
        ..Default::default()
    };
    let mut readback = [0u8; BIG];
    let (rrs, _f, rn, _d0, _d1) = chan.raw(aop::ALPC_OP_READ_SECTION_VIEW, &bytes(&rd), &mut readback);
    // Real cross-endpoint shared memory: view B sees view A's write, byte-for-byte,
    // while the message body stayed small (10 bytes, not 2048).
    rrs == STATUS_SUCCESS && rn as usize == BIG && readback[..] == big[..] && signal.len() < BIG
}

/// Step 3 driver: an ALPC message carries CONTEXT + VIEW; the receiver reads them
/// back as a full ALPC_MESSAGE_ATTRIBUTES (header + structs, body after).
fn message_attributes_roundtrip(chan: &mut RingChannel<'_>, client_h: u64, server_h: u64) -> bool {
    let ctx: u64 = 0xFEED_FACE;
    let view_base: u64 = 0x7000_0000;
    let allocated = msg_attr_flag::CONTEXT | msg_attr_flag::VIEW;

    // Client sends body + (VIEW, CONTEXT) attributes (serialized order: VIEW,CONTEXT).
    let body = port_message(REQUEST, b"attr-body");
    let mut attrs = bytes(&AlpcDataViewAttr {
        section_handle: 0x99,
        view_base,
        view_size: 0x1000,
        ..Default::default()
    });
    attrs.extend_from_slice(&bytes(&AlpcContextAttr {
        port_context: ctx,
        ..Default::default()
    }));
    let mut out = [0u8; 256];
    alpc_send(chan, client_h, &body, allocated, &attrs, &mut out);

    // Receiver requests the full attribute out-param (RECV_ATTRIBUTES + allocated).
    let hdr = core::mem::size_of::<AlpcSendReceiveRequest>() as u32;
    let req = AlpcSendReceiveRequest {
        abi_size: hdr as u16,
        flags: send_flag::RECV_ATTRIBUTES,
        port_handle: server_h,
        message_offset: hdr,
        message_len_bytes: 0,
        valid_attributes: allocated,
        ..Default::default()
    };
    let (rs, _f, ri, valid, _mt) = chan.raw(aop::ALPC_OP_SEND_RECEIVE, &bytes(&req), &mut out);
    if rs != STATUS_SUCCESS || valid as u32 != allocated {
        return false;
    }
    let total = ri as usize;
    // Parse: [AlpcMessageAttributes header][VIEW attr][CONTEXT attr][body].
    let mah = core::mem::size_of::<AlpcMessageAttributes>();
    let dva = core::mem::size_of::<AlpcDataViewAttr>();
    let cta = core::mem::size_of::<AlpcContextAttr>();
    if total < mah + dva + cta {
        return false;
    }
    let header: AlpcMessageAttributes = read_pod(&out[..mah]);
    let got_view: AlpcDataViewAttr = read_pod(&out[mah..mah + dva]);
    let got_ctx: AlpcContextAttr = read_pod(&out[mah + dva..mah + dva + cta]);
    let body_off = mah + dva + cta;
    header.valid_attributes == allocated
        && got_view.view_base == view_base
        && got_ctx.port_context == ctx
        && &out[body_off..total] == &body[..]
}

/// Step 4 driver: the broker (ring) completes a connect; then a message is
/// delivered peer-direct (executive-local) with the ring untouched per-message.
fn peer_direct(chan: &mut RingChannel<'_>, out: &mut [u8]) -> bool {
    // Broker a fresh connection over the ring.
    let name = utf16("\\AlpcDirect");
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
    let (s, _f, _i, listen, _d) = chan.raw(aop::ALPC_OP_CREATE_PORT, &cp, out);
    if s != STATUS_SUCCESS || listen == 0 {
        return false;
    }
    let (server_h, client_h, ok) = alpc_rendezvous(chan, &name, listen, out);
    if !ok {
        return false;
    }

    // Register the broker-completed connection for peer-direct delivery.
    let mut pd = PeerDirect::new();
    pd.register(client_h, server_h);

    // Snapshot the ring op counter — peer-direct delivery must not advance it.
    let ring_before = chan.next_id;

    // Deliver a message client → server DIRECTLY (no ring), carrying CONTEXT.
    if pd
        .send(
            client_h,
            b"direct-payload",
            MessageAttrs {
                context: Some(0x00AB_CDEF),
                ..Default::default()
            },
        )
        .is_err()
    {
        return false;
    }
    let got = match pd.recv(server_h) {
        Ok(Some(m)) => m,
        _ => return false,
    };
    // And a reply server → client, also peer-direct.
    if pd.send(server_h, b"direct-reply", MessageAttrs::default()).is_err() {
        return false;
    }
    let reply_ok = matches!(pd.recv(client_h), Ok(Some(m)) if m.bytes == b"direct-reply");

    let ring_after = chan.next_id;

    // The broker was NOT on the message path: the ring counter is unchanged across
    // both peer-direct sends/receives.
    got.bytes == b"direct-payload"
        && got.attrs.context == Some(0x00AB_CDEF)
        && reply_ok
        && ring_after == ring_before
}

fn read_pod<T: Pod + Default>(buf: &[u8]) -> T {
    let mut v = T::default();
    bytemuck::bytes_of_mut(&mut v).copy_from_slice(&buf[..core::mem::size_of::<T>()]);
    v
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
