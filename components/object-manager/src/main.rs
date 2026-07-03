//! `ntos-object-manager` — the NT Object Manager as a seL4 component.
//!
//! A standalone root task the rust-micro kernel boots. It provides a heap
//! (global allocator), creates the Object Manager service (`nt-object-server`),
//! and exercises it through the real client stub (`nt-object-client`) over an
//! in-process backend — the *whole* NT object stack running bare-metal on seL4.
//! Each step prints `PASS`/`FAIL`, then the kernel-exit sentinel.
//!
//! (The service dispatch runs here driven by the client in-process; a
//! cross-address-space SURT/endpoint transport between isolated client and
//! server components is the next hardening step.)

#![no_std]
#![no_main]

extern crate alloc;

mod allocator;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use alloc::vec::Vec;
use sel4_rt::{print_str, print_u64, yield_now, BootInfo};

use nt_object_abi::ObReply;
use nt_object_client::{Backend, ObjectClient};
use nt_object_manager::ClientKind;
use nt_object_server::Server;
use nt_types::{AccessMask, AccessMode, ClientId, ObjectId};

/// In-process backend: dispatch straight to the server for a fixed client.
struct Direct<'a> {
    server: &'a mut Server,
    client: ClientId,
}

impl Backend for Direct<'_> {
    fn call(&mut self, opcode: u16, in_buf: &[u8], out_buf: &mut [u8]) -> ObReply {
        self.server.dispatch(self.client, opcode, in_buf, out_buf)
    }
}

static PASSED: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);

fn check(name: &[u8], ok: bool) {
    if ok {
        print_str(b"  PASS ");
        PASSED.fetch_add(1, Ordering::Relaxed);
    } else {
        print_str(b"  FAIL ");
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
    print_str(name);
    print_str(b"\n");
}

fn run() {
    let mut server = match Server::new() {
        Ok(s) => s,
        Err(_) => {
            check(b"server_bootstrap", false);
            return;
        }
    };
    check(b"server_bootstrap", true);

    let cid = server.connect(ClientKind::NativeUser, AccessMode::UserMode);
    let mut c = ObjectClient::new(Direct {
        server: &mut server,
        client: cid,
    });

    check(b"ping", c.ping().is_success());

    let created = c.create_directory("\\Device\\Test0", true);
    check(b"create_directory", created.is_ok());
    let id = created.unwrap_or(ObjectId::NULL);

    check(b"lookup", c.lookup("\\Device\\Test0", true) == Ok(id));

    let handle = c.open("\\Device\\Test0", AccessMask::GENERIC_READ, None, true);
    check(b"open", handle.is_ok());

    check(
        b"create_symbolic_link",
        c.create_symbolic_link("\\??\\Link", "\\Device\\Test0", true)
            .is_ok(),
    );
    check(
        b"lookup_via_symlink",
        c.lookup("\\??\\Link", true) == Ok(id),
    );

    let expected: Vec<u16> = "\\Device\\Test0".encode_utf16().collect();
    let target = c.query_symbolic_link("\\??\\Link", true);
    check(
        b"query_symbolic_link",
        matches!(&target, Ok(t) if t.as_slice() == expected.as_slice()),
    );

    if let Ok(h) = handle {
        check(b"close_handle", c.close_handle(h).is_ok());
    }
}

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(_bootinfo: *const BootInfo) -> ! {
    print_str(b"[ntos-om] NT Object Manager on rust-micro (in-process service dispatch)\n");
    run();
    print_str(b"[ntos-om summary: ");
    print_u64(PASSED.load(Ordering::Relaxed) as u64);
    print_str(b" passed, ");
    print_u64(FAILED.load(Ordering::Relaxed) as u64);
    print_str(b" failed]\n");
    // The kernel's serial exit hook watches for this exact sentinel to qemu_exit.
    print_str(b"[microtest done]\n");
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sel4_rt::debug_put_char(b'!');
    loop {
        yield_now();
    }
}
