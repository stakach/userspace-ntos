//! End-to-end I/O service round-trips: the real client stub encodes requests, an
//! in-process `Direct` backend hands them to the server's dispatcher (driving a
//! real I/O Manager + mock driver), and the client decodes the replies — the
//! whole wire path, host-side, no SURT.

use nt_io_abi::{ioctl, opcodes::client as op, IoReply};
use nt_io_client::{Backend, IoClient};
use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceType, IoManager, MockDriverBackend, MockObjectPort,
};
use nt_io_server::IoServer;
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, NtPath};

fn npath(s: &str) -> NtPath {
    NtPath::parse_str(s).unwrap()
}

/// In-process backend: dispatch straight to the server for a fixed client.
struct Direct<'a> {
    server: &'a mut IoServer<MockObjectPort>,
    client: ClientId,
}

impl Backend for Direct<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> IoReply {
        self.server.dispatch(self.client, opcode, in_buf, out_buf)
    }
}

fn setup() -> (IoServer<MockObjectPort>, ClientId) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io
        .create_driver(&npath("\\Driver\\Test"), Box::new(MockDriverBackend::new()))
        .unwrap();
    io.create_device(
        driver,
        Some(&npath("\\Device\\Test0")),
        DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(),
        DeviceFlags::BUFFERED_IO,
        0,
    )
    .unwrap();
    io.create_symbolic_link(&npath("\\??\\Test0"), &npath("\\Device\\Test0"))
        .unwrap();
    let mut server = IoServer::new(io);
    let client = server.connect();
    (server, client)
}

#[test]
fn full_io_roundtrip() {
    let (mut server, client) = setup();
    let mut c = IoClient::new(Direct {
        server: &mut server,
        client,
    });

    assert!(c.ping().is_success());

    // Open by the DOS-devices symlink.
    let h = c
        .open(
            "\\??\\Test0",
            AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE,
            0,
            0,
            0,
        )
        .unwrap();

    // Write then read loopback (through the mock driver + real handle validation).
    assert_eq!(c.write(h, 0, b"hello").unwrap(), 5);
    let mut out = [0u8; 8];
    let n = c.read(h, 0, &mut out).unwrap();
    assert_eq!(&out[..n as usize], b"hello");

    // Echoing IOCTL.
    let code = ioctl::ctl_code(0x22, 0x800, ioctl::METHOD_BUFFERED, ioctl::FILE_ANY_ACCESS);
    let mut io_out = [0u8; 8];
    let n = c.device_control(h, code, b"ping", &mut io_out).unwrap();
    assert_eq!(&io_out[..n as usize], b"ping");

    // Cleanup + close; a read afterwards fails on the (now invalid) handle.
    c.cleanup(h).unwrap();
    c.close(h).unwrap();
    assert_eq!(
        c.read(h, 0, &mut out).unwrap_err(),
        NtStatus::INVALID_HANDLE
    );
}

#[test]
fn malformed_requests_do_not_panic() {
    let (mut server, client) = setup();
    // Truncated open request.
    let r = server.dispatch(client, op::IO_OP_OPEN, &[0u8; 3], &mut []);
    assert_eq!(r.status, NtStatus::INVALID_PARAMETER.raw());
    // Unknown opcode.
    let r = server.dispatch(client, 0x30ff, &[], &mut []);
    assert_eq!(r.status, NtStatus::NOT_IMPLEMENTED.raw());
    // Open of a nonexistent device path.
    let mut c = IoClient::new(Direct {
        server: &mut server,
        client,
    });
    assert_eq!(
        c.open("\\Device\\Missing", AccessMask::GENERIC_READ, 0, 0, 0)
            .unwrap_err(),
        NtStatus::OBJECT_NAME_NOT_FOUND
    );
}

#[test]
fn write_on_read_only_handle_denied() {
    let (mut server, client) = setup();
    let mut c = IoClient::new(Direct {
        server: &mut server,
        client,
    });
    let h = c
        .open("\\Device\\Test0", AccessMask::GENERIC_READ, 0, 0, 0)
        .unwrap();
    assert_eq!(c.write(h, 0, b"nope").unwrap_err(), NtStatus::ACCESS_DENIED);
}

#[test]
fn disconnect_closes_client_files() {
    let (mut server, client) = setup();
    let _h = {
        let mut c = IoClient::new(Direct {
            server: &mut server,
            client,
        });
        c.open("\\Device\\Test0", AccessMask::GENERIC_READ, 0, 0, 0)
            .unwrap()
    };
    assert_eq!(server.io_mut().file_count(), 1);
    server.disconnect(client).unwrap();
    assert_eq!(server.io_mut().file_count(), 0);
}
