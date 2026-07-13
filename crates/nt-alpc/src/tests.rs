//! Host tests for the ALPC adapter — the ALPC surface over the core, and the
//! load-bearing **LPC↔ALPC bridge** (both directions) over ONE shared core.

use super::*;

use nt_alpc_abi::{
    msg_attr_flag, msg_type, opcode as aop, port_flag, AlpcAcceptConnectRequest,
    AlpcConnectPortRequest, AlpcContextAttr, AlpcCreatePortRequest, AlpcCreatePortSectionRequest,
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
        alpc.dispatch(&mut core, aop::ALPC_OP_PING, &[], &mut []).status,
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
    let cn = enc_connect(&name, 0, &port_message(msg_type::CONNECTION_REQUEST, b"hello"));
    let r = alpc.dispatch(&mut core, aop::ALPC_OP_CONNECT_PORT, &cn, &mut []);
    assert_eq!(r.status, SUCCESS);
    assert_ne!(r.detail0, 0, "client comm-port handle");
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
        alpc.dispatch(&mut PortCore::new(), aop::ALPC_OP_DELETE_SECTION_VIEW, &dv, &mut [])
            .status,
        SUCCESS
    );
    assert_eq!(alpc.view_count(), 0);
    let ds = enc_handle_req(section);
    assert_eq!(
        alpc.dispatch(&mut PortCore::new(), aop::ALPC_OP_DELETE_PORT_SECTION, &ds, &mut [])
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
        .dispatch(&mut PortCore::new(), aop::ALPC_OP_CREATE_PORT_SECTION, &cs, &mut [])
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
        alpc.dispatch(&mut PortCore::new(), aop::ALPC_OP_CREATE_SECTION_VIEW, &cv, &mut [])
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
    let r = alpc.dispatch(&mut PortCore::new(), aop::ALPC_OP_WRITE_SECTION_VIEW, &w, &mut []);
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
    let r = alpc.dispatch(&mut PortCore::new(), aop::ALPC_OP_READ_SECTION_VIEW, &rd, &mut out);
    assert_eq!(r.status, SUCCESS);
    assert_eq!(r.information as usize, big.len());
    assert_eq!(out, big, "view B observes view A's write — shared, not copied");

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
        alpc.dispatch(&mut PortCore::new(), aop::ALPC_OP_WRITE_SECTION_VIEW, &w2, &mut []).status,
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
    alpc.dispatch(&mut PortCore::new(), aop::ALPC_OP_READ_SECTION_VIEW, &rd2, &mut out2);
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
        alpc.dispatch(&mut PortCore::new(), aop::ALPC_OP_WRITE_SECTION_VIEW, &oob, &mut []).status,
        SUCCESS
    );
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

// --- LPC direct backend for driving the classic-LPC adapter in the test ----

struct LpcDirect<'a> {
    server: &'a mut Server,
    out: [u8; 512],
}
impl Backend for LpcDirect<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> nt_lpc_abi::LpcReply {
        let r = self.server.dispatch(opcode, in_buf, &mut self.out);
        let n = (r.information as usize).min(out_buf.len()).min(self.out.len());
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
        let (ch, _) = c.complete_connect(conn_id).unwrap();
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
        let sr = enc_send_receive(client_h, Some(&req), msg_attr_flag::CONTEXT, &enc_attrs_context(0xABCD));
        let mut out = [0u8; 256];
        let _ = alpc.dispatch(lpc.core_mut(), aop::ALPC_OP_SEND_RECEIVE, &sr, &mut out);
    }
    let got = lpc.core_mut().receive_message(server_h).unwrap().unwrap();
    assert_eq!(got.bytes, req);
    assert_eq!(got.attrs.context, Some(0xABCD), "CONTEXT carried across the bridge");

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
