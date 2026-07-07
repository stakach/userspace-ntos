//! The I/O Manager as an isolated service, driven by SURT.
//!
//! Mirrors the `io-manager` component's server: it embeds an in-process Object
//! Manager (library mode) + a mock driver, sets up `\Driver\Test` / `\Device\Test0`
//! / `\??\Test0`, then consumes I/O requests off its submission ring, dispatches
//! each through `nt_io_server::IoServer::dispatch`, and produces `IoReply`s onto its
//! completion ring (writing read/IOCTL output into the shared reply frame). Its own
//! VSpace maps its ring frames at the shared vaddrs (a separate VSpace per service).

use crate::*;

use alloc::boxed::Box;

use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceType, IoManager, MockDriverBackend,
    ObjectManagerLibraryPort,
};
use nt_io_server::IoServer;
use nt_object_manager::ComponentId;
use nt_types::NtPath;
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

fn npath(s: &str) -> NtPath {
    NtPath::parse_str(s).unwrap_or_default()
}

fn park() -> ! {
    loop {
        yield_now();
    }
}

#[no_mangle]
#[link_section = ".text.io_server_entry"]
pub unsafe extern "C" fn io_server_entry() -> ! {
    let mut submissions = match Consumer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let mut completions = match Producer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let wait_requests = Sel4Notify::new(&ENV, CT_N_SUB);
    let signal_completion = Sel4Notify::new(&ENV, CT_N_COMP);

    // I/O Manager over an in-process Object Manager + a mock driver; register a
    // driver + device + DOS-devices symlink.
    let port = match ObjectManagerLibraryPort::new(ComponentId(1)) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let mut io = IoManager::new(port);
    let driver = match io.create_driver(&npath("\\Driver\\Test"), Box::new(MockDriverBackend::new()))
    {
        Ok(d) => d,
        Err(_) => park(),
    };
    if io
        .create_device(
            driver,
            Some(&npath("\\Device\\Test0")),
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .is_err()
    {
        park();
    }
    if io
        .create_symbolic_link(&npath("\\??\\Test0"), &npath("\\Device\\Test0"))
        .is_err()
    {
        park();
    }

    let mut server = IoServer::new(io);
    let client = server.connect();

    let _ = drain_blocking(&mut submissions, &wait_requests, |sqe: &SurtSqe| {
        // SAFETY: single request in flight; the ring push/pop orders the client's
        // write to the request frame before this read.
        let in_buf = unsafe {
            core::slice::from_raw_parts((REQ_DATA_VADDR + sqe.offset) as *const u8, sqe.len as usize)
        };
        let out_buf =
            unsafe { core::slice::from_raw_parts_mut(REP_DATA_VADDR as *mut u8, REP_DATA_LEN) };
        let reply = server.dispatch(client, sqe.opcode, in_buf, out_buf);
        let cqe = SurtCqe {
            request_id: sqe.request_id,
            status: reply.status,
            flags: reply.flags,
            information: reply.information,
            detail0: reply.detail0,
            detail1: reply.detail1,
            ..Default::default()
        };
        while completions.try_push(cqe).is_err() {
            yield_now();
        }
        let _ = completions.notify_consumer(&signal_completion);
        true // serve forever
    });
    park()
}
