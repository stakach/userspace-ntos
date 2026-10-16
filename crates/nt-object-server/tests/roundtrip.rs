//! End-to-end service round-trips: the real client stub encodes requests, an
//! in-process `DirectBackend` hands them to the server's dispatcher, and the
//! client decodes the replies — the whole wire path, host-side, no SURT.

use nt_object_abi::ObReply;
use nt_object_client::{Backend, ObjectClient};
use nt_object_manager::ClientKind;
use nt_object_server::Server;
use nt_status::NtStatus;
use nt_types::{AccessMask, AccessMode, ClientId};

#[path = "roundtrip/file_target_tests.rs"]
mod file_target_tests;

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
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
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

    c.create_symbolic_link("\\KnownDlls\\KnownDllPath", "C:\\Windows\\system32", true)
        .unwrap();
    let target = c
        .query_symbolic_link("\\KnownDlls\\KnownDllPath", true)
        .unwrap();
    let expected: Vec<u16> = "C:\\Windows\\system32".encode_utf16().collect();
    assert_eq!(target, expected);

    let volume = c
        .create_device("\\Device\\Volume0", 0x494f, 17, true)
        .unwrap();
    c.create_symbolic_link("\\??\\C:", "\\Device\\Volume0", true)
        .unwrap();
    let aliased: Vec<u16> = "\\??\\c:\\Folder\\Leaf".encode_utf16().collect();
    let suffix: Vec<u16> = "\\Folder\\Leaf".encode_utf16().collect();
    assert_eq!(
        c.resolve_file_target(&aliased, true).unwrap(),
        nt_object_client::FilePathTarget {
            device_object: volume,
            remaining_name: suffix,
        }
    );

    c.delete_object("\\??\\Link", true).unwrap();
    assert_eq!(
        c.lookup("\\??\\Link", true).unwrap_err(),
        NtStatus::OBJECT_NAME_NOT_FOUND
    );

    c.close_handle(h).unwrap();
    // closing again is a stale handle
    assert_eq!(c.close_handle(h).unwrap_err(), NtStatus::INVALID_HANDLE);
}

#[test]
fn session_zero_link_openif_returns_the_existing_canonical_identity() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut c = client(&mut server, cid);
    let path = "\\Sessions\\0\\BaseNamedObjects";
    let target = "\\BaseNamedObjects";
    let (existing, existing_before) = c
        .create_or_open_symbolic_link(path, target, true, true, true)
        .unwrap();
    assert!(existing_before);
    assert_ne!(existing.0, 0);
    assert_eq!(c.query_symbolic_link(path, true).unwrap(), target.encode_utf16().collect::<Vec<_>>());
    assert_eq!(
        c.create_or_open_symbolic_link(path, target, true, false, true),
        Err(NtStatus::OBJECT_NAME_COLLISION)
    );
    assert_eq!(
        c.create_or_open_symbolic_link(path, "\\Different", true, true, true),
        Err(NtStatus::OBJECT_NAME_COLLISION)
    );
    assert_eq!(
        c.create_or_open_symbolic_link("\\Sessions\\0", target, true, true, true),
        Err(NtStatus::OBJECT_TYPE_MISMATCH)
    );
    let (again, opened_existing) = c
        .create_or_open_symbolic_link(path, target, true, true, true)
        .unwrap();
    assert!(opened_existing);
    assert_eq!(again, existing);
    let (folded, folded_existing) = c
        .create_or_open_symbolic_link("\\sessions\\0\\basenamedobjects", target, true, true, true)
        .unwrap();
    assert!(folded_existing);
    assert_eq!(folded, existing);
}

#[test]
fn created_session_owns_exact_numbered_windows_namespace_until_retired() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut c = client(&mut server, cid);
    assert_eq!(c.lookup("\\Sessions\\37", true), Err(NtStatus::OBJECT_NAME_NOT_FOUND));

    let owned = c.create_session_namespace(37).unwrap();
    assert_eq!(c.lookup("\\Sessions\\37", true).unwrap(), owned.session);
    assert_eq!(c.lookup("\\Sessions\\37\\Windows", true).unwrap(), owned.windows);
    assert_eq!(c.create_session_namespace(37), Err(NtStatus::OBJECT_NAME_COLLISION));
    assert_eq!(c.lookup("\\Sessions\\38", true), Err(NtStatus::OBJECT_NAME_NOT_FOUND));
    let stale = nt_object_client::SessionNamespace {
        session: nt_types::ObjectId(owned.session.0 + 1),
        windows: owned.windows,
    };
    assert_eq!(c.retire_session_namespace_exact(37, stale), Err(NtStatus::INVALID_HANDLE));
    assert_eq!(c.lookup("\\Sessions\\37\\Windows", true).unwrap(), owned.windows);

    let child = c.create_directory("\\Sessions\\37\\Windows\\WindowStations", false).unwrap();
    assert_eq!(c.lookup("\\Sessions\\37\\Windows\\WindowStations", true).unwrap(), child);
    assert_eq!(c.retire_session_namespace_exact(37, owned), Err(NtStatus::DIRECTORY_NOT_EMPTY));
    c.delete_object("\\Sessions\\37\\Windows\\WindowStations", true).unwrap();
    c.retire_session_namespace_exact(37, owned).unwrap();
    assert_eq!(c.lookup("\\Sessions\\37", true), Err(NtStatus::OBJECT_NAME_NOT_FOUND));
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
fn service_creates_and_references_file_handles() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let mut c = client(&mut server, cid);

    let dev = c.create_device("\\Device\\Io0", 0x494f, 10, true).unwrap();
    let (file, handle) = c
        .create_file_handle(0x494f, 99, dev, AccessMask::GENERIC_READ)
        .unwrap();
    assert_eq!(
        c.reference_file_handle(handle, AccessMask::GENERIC_READ)
            .unwrap(),
        file
    );
    assert_eq!(
        c.reference_file_handle(handle, AccessMask::GENERIC_WRITE)
            .unwrap_err(),
        NtStatus::ACCESS_DENIED
    );
    c.close_handle(handle).unwrap();
    assert_eq!(
        c.reference_file_handle(handle, AccessMask::GENERIC_READ)
            .unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
}

#[test]
fn persistent_reference_keeps_file_alive_after_handle_close() {
    let mut server = Server::new().unwrap();
    let cid = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let (file, reference) = {
        let mut c = client(&mut server, cid);
        let dev = c.create_device("\\Device\\Ref0", 0x494f, 10, true).unwrap();
        let (file, handle) = c
            .create_file_handle(0x494f, 99, dev, AccessMask::GENERIC_READ)
            .unwrap();
        let (referenced, reference) = c
            .reference_handle(handle, None, AccessMask::GENERIC_READ)
            .unwrap();
        assert_eq!(referenced, file);
        c.close_handle(handle).unwrap();
        (file, reference)
    };

    assert!(server.object_manager().reference_by_id(file).is_ok());
    client(&mut server, cid)
        .dereference_object(reference)
        .unwrap();
    assert_eq!(
        server.object_manager().reference_by_id(file).unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
}

#[test]
fn persistent_reference_is_client_scoped_and_disconnect_releases_it() {
    let mut server = Server::new().unwrap();
    let owner = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    let other = server.connect(ClientKind::NativeUser, AccessMode::UserMode);
    let (file, reference) = {
        let mut c = client(&mut server, owner);
        let dev = c.create_device("\\Device\\Ref1", 0x494f, 10, true).unwrap();
        let (file, handle) = c
            .create_file_handle(0x494f, 99, dev, AccessMask::GENERIC_READ)
            .unwrap();
        let (_, reference) = c
            .reference_handle(handle, None, AccessMask::empty())
            .unwrap();
        c.close_handle(handle).unwrap();
        (file, reference)
    };
    assert_eq!(
        client(&mut server, other)
            .dereference_object(reference)
            .unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
    server.disconnect(owner).unwrap();
    assert_eq!(
        server.object_manager().reference_by_id(file).unwrap_err(),
        NtStatus::INVALID_HANDLE
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
