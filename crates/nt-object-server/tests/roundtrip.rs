//! End-to-end service round-trips: the real client stub encodes requests, an
//! in-process `DirectBackend` hands them to the server's dispatcher, and the
//! client decodes the replies — the whole wire path, host-side, no SURT.

use nt_object_abi::ObReply;
use nt_object_client::{Backend, ObjectClient};
use nt_object_manager::ClientKind;
use nt_object_server::Server;
use nt_status::NtStatus;
use nt_types::{AccessMask, AccessMode, ClientId};

/// An in-process backend: dispatch straight to the server for a fixed client.
struct Direct<'a> {
    server: &'a mut Server,
    client: ClientId,
}

impl Backend for Direct<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> ObReply {
        self.server.dispatch(self.client, opcode, in_buf, out_buf)
    }
}

fn client(server: &mut Server, cid: ClientId) -> ObjectClient<Direct<'_>> {
    ObjectClient::new(Direct {
        server,
        client: cid,
    })
}

#[test]
fn full_service_roundtrip() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::NativeUser, AccessMode::UserMode);
    let mut c = client(&mut server, cid);

    assert!(c.ping().is_success());

    // create \Device\Test0 (a directory), then look it up + open it
    let id = c.create_directory("\\Device\\Test0", true).unwrap();
    assert_eq!(c.lookup("\\Device\\Test0", true).unwrap(), id);
    let h = c
        .open("\\Device\\Test0", AccessMask::GENERIC_READ, None, true)
        .unwrap();

    // \??\Link -> \Device\Test0 : lookup + query resolve through the link
    c.create_symbolic_link("\\??\\Link", "\\Device\\Test0", true)
        .unwrap();
    assert_eq!(c.lookup("\\??\\Link", true).unwrap(), id);
    let target = c.query_symbolic_link("\\??\\Link", true).unwrap();
    let expected: Vec<u16> = "\\Device\\Test0".encode_utf16().collect();
    assert_eq!(target, expected);

    c.close_handle(h).unwrap();
    // closing again is a stale handle
    assert_eq!(c.close_handle(h).unwrap_err(), NtStatus::INVALID_HANDLE);
}

#[test]
fn service_denies_over_request() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::NativeUser, AccessMode::UserMode);
    let mut c = client(&mut server, cid);
    // \Device is a directory; request a right outside DIRECTORY valid access.
    let bogus = AccessMask::from_bits_retain(0x0800);
    assert_eq!(
        c.open("\\Device", bogus, None, true).unwrap_err(),
        NtStatus::ACCESS_DENIED
    );
}

#[test]
fn service_lookup_errors_map_through() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::NativeUser, AccessMode::UserMode);
    let mut c = client(&mut server, cid);
    assert_eq!(
        c.lookup("\\Device\\Missing", true).unwrap_err(),
        NtStatus::OBJECT_NAME_NOT_FOUND
    );
    assert_eq!(
        c.lookup("\\NoDir\\X", true).unwrap_err(),
        NtStatus::OBJECT_PATH_NOT_FOUND
    );
}

#[test]
fn client_death_closes_handles_permanent_survives() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::NativeUser, AccessMode::UserMode);

    let handle = {
        let mut c = client(&mut server, cid);
        c.create_directory("\\Device\\D0", true).unwrap();
        c.open("\\Device\\D0", AccessMask::GENERIC_READ, None, true)
            .unwrap()
    };

    // Client death closes its handles.
    server.disconnect(cid).unwrap();

    // A new client: the permanent directory survives, but the old handle is gone.
    let cid2 = server.connect(ClientKind::NativeUser, AccessMode::UserMode);
    let mut c2 = client(&mut server, cid2);
    assert!(c2.lookup("\\Device\\D0", true).is_ok());
    assert!(c2.close_handle(handle).is_err());
}
