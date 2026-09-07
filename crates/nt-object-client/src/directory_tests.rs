use super::*;
use nt_object_manager::ClientKind;
use nt_object_server::Server;
use nt_types::{rights, AccessMode, ClientId};

struct Direct {
    server: Server,
    client: ClientId,
}

impl Backend for Direct {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> ObReply {
        self.server.dispatch(self.client, opcode, input, output)
    }
}

fn setup() -> ObjectClient<Direct> {
    let mut server = Server::new().unwrap();
    let client = server.connect(ClientKind::ExecutiveService, AccessMode::KernelMode);
    ObjectClient::new(Direct { server, client })
}

#[test]
fn directory_roundtrip_uses_same_namespace_and_real_close() {
    let mut client = setup();
    let name = UnicodeString::from_str("\\Device\\DirectoryWire");
    let first = client
        .create_directory_handle(
            None,
            &name,
            rights::directory::ALL_ACCESS,
            ObjAttrFlags::KERNEL_HANDLE,
        )
        .unwrap();
    assert!(first.created);
    assert_eq!(first.status, NtStatus::SUCCESS);
    let existing = client
        .create_directory_handle(None, &name, rights::directory::QUERY, ObjAttrFlags::OPEN_IF)
        .unwrap();
    assert!(!existing.created);
    assert_eq!(existing.status, NtStatus(0x4000_0000));
    let (first_id, first_ref) = client
        .reference_handle(first.handle, None, AccessMask::empty())
        .unwrap();
    let (second_id, second_ref) = client
        .reference_handle(existing.handle, None, AccessMask::empty())
        .unwrap();
    assert_eq!(first_id, second_id);
    assert_eq!(
        client.lookup("\\Device\\DirectoryWire", true).unwrap(),
        first_id
    );
    client.dereference_object(first_ref).unwrap();
    client.dereference_object(second_ref).unwrap();
    client.close_handle(first.handle).unwrap();
    assert!(client.lookup("\\Device\\DirectoryWire", true).is_ok());
    client.close_handle(existing.handle).unwrap();
    assert_eq!(
        client.lookup("\\Device\\DirectoryWire", true),
        Err(NtStatus::OBJECT_NAME_NOT_FOUND)
    );
    assert_eq!(
        client.close_handle(existing.handle),
        Err(NtStatus::INVALID_HANDLE)
    );
}

#[test]
fn relative_counted_unicode_query_and_restart_roundtrip() {
    let mut client = setup();
    let root = client
        .create_directory_handle(
            None,
            &UnicodeString::from_str("\\Device\\WireParent"),
            rights::directory::ALL_ACCESS,
            ObjAttrFlags::empty(),
        )
        .unwrap()
        .handle;
    let child = client
        .create_directory_handle(
            Some(root),
            &UnicodeString::from_units(&[0x4e2d, 0xd800]),
            rights::directory::QUERY,
            ObjAttrFlags::empty(),
        )
        .unwrap()
        .handle;
    let mut out = [0xa5; 128];
    let result = client
        .query_directory(root, 99, true, false, 0x2000, &mut out)
        .unwrap();
    assert_eq!(result.status, NtStatus::SUCCESS);
    assert_eq!(result.context, 1);
    assert_eq!(result.written, 90);
    assert_eq!(u64::from_le_bytes(out[8..16].try_into().unwrap()), 0x2040);
    assert_eq!(&out[64..70], &[0x2d, 0x4e, 0, 0xd8, 0, 0]);
    let end = client
        .query_directory(root, result.context, false, false, 0, &mut [])
        .unwrap();
    assert_eq!(end.status, NtStatus(0x8000_001a_u32 as i32));
    assert_eq!(end.context, 1);
    let mut tiny = [0x55; 8];
    let small = client
        .query_directory(root, 0, true, true, 0, &mut tiny)
        .unwrap();
    assert_eq!(small.status, NtStatus::BUFFER_TOO_SMALL);
    assert_eq!(small.return_length, 90);
    assert_eq!(tiny, [0x55; 8]);
    client.close_handle(child).unwrap();
    client.close_handle(root).unwrap();
}

#[test]
fn malformed_packets_are_rejected_without_output_or_handle_effects() {
    let mut client = setup();
    let req = ObDirectoryHandleRequest {
        abi_size: size_of::<ObDirectoryHandleRequest>() as u16,
        name_offset: 0,
        name_len_bytes: 2,
        ..Default::default()
    };
    let result = client.backend.call(
        opcode::OB_OP_CREATE_DIRECTORY_HANDLE,
        bytemuck::bytes_of(&req),
        &mut [],
    );
    assert_eq!(result.status, NtStatus::INVALID_PARAMETER.0);
    let root = client
        .open_directory_handle(
            None,
            &UnicodeString::from_str("\\Device"),
            rights::directory::QUERY,
            ObjAttrFlags::empty(),
        )
        .unwrap();
    let mut req = ObQueryDirectoryRequest {
        abi_size: size_of::<ObQueryDirectoryRequest>() as u16,
        handle: root.0,
        buffer_length: 64,
        restart_scan: 2,
        ..Default::default()
    };
    let mut output = [0xaa; 64];
    let result = client.backend.call(
        opcode::OB_OP_QUERY_DIRECTORY,
        bytemuck::bytes_of(&req),
        &mut output,
    );
    assert_eq!(result.status, NtStatus::INVALID_PARAMETER.0);
    assert_eq!(output, [0xaa; 64]);
    req.restart_scan = 1;
    req.buffer_length = 65;
    let result = client.backend.call(
        opcode::OB_OP_QUERY_DIRECTORY,
        bytemuck::bytes_of(&req),
        &mut output,
    );
    assert_eq!(result.status, NtStatus::INVALID_PARAMETER.0);
    assert_eq!(output, [0xaa; 64]);
    req.buffer_length = 64;
    req.output_base = u64::MAX;
    let result = client.backend.call(
        opcode::OB_OP_QUERY_DIRECTORY,
        bytemuck::bytes_of(&req),
        &mut output,
    );
    assert_eq!(result.status, NtStatus::INVALID_PARAMETER.0);
    assert_eq!(output, [0xaa; 64]);
}

#[test]
fn permission_and_relative_scope_errors_cross_wire_without_fake_handles() {
    let mut client = setup();
    assert_eq!(
        client.create_directory_handle(
            Some(HandleValue(0)),
            &UnicodeString::new(),
            rights::directory::QUERY,
            ObjAttrFlags::empty()
        ),
        Err(NtStatus::INVALID_HANDLE)
    );
    let root = client
        .open_directory_handle(
            None,
            &UnicodeString::from_str("\\Device"),
            rights::directory::TRAVERSE,
            ObjAttrFlags::empty(),
        )
        .unwrap();
    assert_eq!(
        client.query_directory(root, 0, true, false, 0, &mut [0; 64]),
        Err(NtStatus::ACCESS_DENIED)
    );
    client.close_handle(root).unwrap();
    assert_eq!(
        client.create_directory_handle(
            Some(root),
            &UnicodeString::from_str("Child"),
            rights::directory::QUERY,
            ObjAttrFlags::empty()
        ),
        Err(NtStatus::INVALID_HANDLE)
    );
    assert_eq!(
        client.open_directory_handle(
            None,
            &UnicodeString::from_str("Device"),
            rights::directory::QUERY,
            ObjAttrFlags::empty()
        ),
        Err(nt_object_manager::directory::OBJECT_PATH_SYNTAX_BAD)
    );
}

#[test]
fn malformed_query_reply_cannot_fabricate_context_or_lengths() {
    struct Broken;
    impl Backend for Broken {
        fn call(&mut self, _: u16, _: &[u8], _: &mut [u8]) -> ObReply {
            ObReply {
                status: NtStatus::BUFFER_TOO_SMALL.0,
                ..Default::default()
            }
        }
    }
    let mut client = ObjectClient::new(Broken);
    assert_eq!(
        client.query_directory(HandleValue(1), 17, false, true, 0, &mut [0; 8]),
        Err(NtStatus::INVALID_PARAMETER)
    );
}

struct ReplyBackend(ObReply);

impl Backend for ReplyBackend {
    fn call(&mut self, _: u16, _: &[u8], _: &mut [u8]) -> ObReply {
        self.0
    }
}

#[test]
fn inconsistent_success_lengths_and_cursor_claims_are_rejected() {
    // status, context, written, return length, single-entry request
    for (status, next, written, returned, single) in [
        (NtStatus::SUCCESS, 18, 0, 32, false),
        (NtStatus::SUCCESS, 18, 64, 32, false),
        (NtStatus::SUCCESS, 18, 88, 90, false),
        (NtStatus::SUCCESS, 16, 88, 88, false),
        (NtStatus::SUCCESS, 17, 32, 32, false),
        (NtStatus::SUCCESS, 20, 88, 88, false),
        (NtStatus::SUCCESS, 19, 128, 128, true),
        (NtStatus(0x105), 18, 88, 88, true),
        (NtStatus(0x105), 17, 0, 32, false),
        (NtStatus(0x105), 17, 64, 64, false),
    ] {
        let mut client = ObjectClient::new(ReplyBackend(ObReply {
            status: status.0,
            information: written,
            detail0: next,
            detail1: returned,
        }));
        assert_eq!(
            client.query_directory(HandleValue(1), 17, false, single, 0, &mut [0; 128]),
            Err(NtStatus::INVALID_PARAMETER),
            "{status:?}/{next}/{written}/{returned}/{single}"
        );
    }
}

#[test]
fn coherent_success_and_restart_cursor_metadata_are_accepted() {
    for (status, next, written, restart, single) in [
        (NtStatus::SUCCESS, 18, 88, false, true),
        (NtStatus::SUCCESS, 19, 128, false, false),
        (NtStatus(0x105), 18, 88, false, false),
        (NtStatus::SUCCESS, 1, 88, true, true),
        (NtStatus(0x105), 0, 32, true, false),
    ] {
        let mut client = ObjectClient::new(ReplyBackend(ObReply {
            status: status.0,
            information: written,
            detail0: next,
            detail1: u64::from(written),
        }));
        let result = client
            .query_directory(HandleValue(1), 17, restart, single, 0, &mut [0; 128])
            .unwrap();
        assert_eq!(u64::from(result.context), next);
        assert_eq!(result.written, written);
    }
}

#[test]
fn warning_and_zero_capacity_metadata_preserve_nt5_context_rules() {
    let no_more = NtStatus(0x8000_001a_u32 as i32);
    // status, length, next context, written, return length, single, accepted
    for (status, length, next, written, returned, single, accepted) in [
        (no_more, 0, 17, 0, 32, false, true),
        (no_more, 32, 17, 32, 32, false, true),
        (no_more, 32, 0, 32, 32, false, false),
        (no_more, 32, 17, 0, 32, false, false),
        (no_more, 32, 17, 32, 64, false, false),
        (NtStatus::BUFFER_TOO_SMALL, 8, 17, 0, 88, true, true),
        (NtStatus::BUFFER_TOO_SMALL, 8, 0, 0, 88, true, false),
        (NtStatus::BUFFER_TOO_SMALL, 8, 17, 0, 88, false, false),
        (NtStatus::BUFFER_TOO_SMALL, 0, 17, 0, 32, true, false),
        (NtStatus(0x105), 0, 0, 0, 32, false, true),
        (NtStatus(0x105), 0, 17, 0, 32, false, false),
    ] {
        let mut client = ObjectClient::new(ReplyBackend(ObReply {
            status: status.0,
            information: written,
            detail0: next,
            detail1: returned,
        }));
        let mut output = vec![0; length];
        let result = client.query_directory(HandleValue(1), 17, true, single, 0, &mut output);
        assert_eq!(
            result.is_ok(),
            accepted,
            "{status:?}/{length}/{next}/{written}/{returned}/{single}"
        );
    }
}
