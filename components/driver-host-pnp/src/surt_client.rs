//! The isolated cross-VSpace client.
//!
//! A genuinely isolated seL4 component (its own CSpace + VSpace, spawned by the
//! driver-host root task) that opens the KMDF child's device interface by class
//! GUID and issues an IOCTL — entirely over a SURT ring. It has NO access to the
//! WDF runtime, the Configuration Manager, or the device object; every device
//! touch is a ring request the server (the root task) mediates. This is the real
//! isolation boundary: the client shares only the read-only image, its private
//! stack, the two ring frames + two data frames, and four caps (PML4 + two
//! notifications + a result endpoint).
//!
//! Alloc-free: the shared image `.bss` (which holds the root task's global bump
//! allocator) is mapped read-only here, so the client must never allocate. It uses
//! fixed stack values + volatile reads/writes of the shared frames only.

use crate::*;

use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

fn park() -> ! {
    loop {
        yield_now();
    }
}

fn check_client(name: &[u8], ok: bool, passed: &mut u64) {
    print_str(if ok {
        b"    [surt-client] PASS "
    } else {
        b"    [surt-client] FAIL "
    });
    print_str(name);
    print_str(b"\n");
    if ok {
        *passed += 1;
    }
}

/// The client's entry point (a spawned TCB starts here in its own VSpace).
///
/// # Safety
/// Entered by the kernel with the SURT rings + data frames mapped at the shared
/// vaddrs and the four caps seeded into the component's CNode.
#[no_mangle]
#[link_section = ".text.client_entry"]
pub unsafe extern "C" fn client_entry() -> ! {
    let mut sq = match Producer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let mut cq = match Consumer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let signal_request = Sel4Notify::new(&ENV, CT_N_SUB);
    let wait_completion = Sel4Notify::new(&ENV, CT_N_COMP);

    let mut passed = 0u64;

    // 1. OP_OPEN — enumerate the interface class by GUID and resolve it to a handle.
    let guid = KMDF_IFACE_GUID.as_bytes();
    let dst = REQ_DATA_VADDR as *mut u8;
    for (i, b) in guid.iter().enumerate() {
        core::ptr::write_volatile(dst.add(i), *b);
    }
    let open = SurtSqe {
        opcode: OP_OPEN,
        len: guid.len() as u32,
        request_id: 1,
        offset: 0,
        ..Default::default()
    };
    while sq.try_push(open).is_err() {
        yield_now();
    }
    let _ = sq.notify_consumer(&signal_request);

    let mut open_status = -1i32;
    let mut fdo = 0u64;
    let mut link_len = 0u64;
    let _ = drain_blocking(&mut cq, &wait_completion, |cqe: &SurtCqe| {
        if cqe.request_id == 1 {
            open_status = cqe.status;
            fdo = cqe.detail0;
            link_len = cqe.information;
            false
        } else {
            true
        }
    });
    // The reply frame holds the interface's symbolic link; it must start with "\??\".
    let link_ok = open_status == STATUS_SUCCESS
        && fdo != 0
        && link_len > 4
        && core::ptr::read_volatile(REP_DATA_VADDR as *const u8) == b'\\';
    check_client(b"surt_client_open_interface", link_ok, &mut passed);

    // 2. OP_IOCTL(PING) through the opened handle — the driver's EvtIoDeviceControl.
    core::ptr::write_unaligned(REQ_DATA_VADDR as *mut u32, KMDF_IOCTL_PING);
    let ioctl = SurtSqe {
        opcode: OP_IOCTL,
        len: 4,
        request_id: 2,
        user_data: fdo,
        offset: 0,
        ..Default::default()
    };
    while sq.try_push(ioctl).is_err() {
        yield_now();
    }
    let _ = sq.notify_consumer(&signal_request);

    let mut ioctl_status = -1i32;
    let mut info = 0u64;
    let _ = drain_blocking(&mut cq, &wait_completion, |cqe: &SurtCqe| {
        if cqe.request_id == 2 {
            ioctl_status = cqe.status;
            info = cqe.detail0;
            false
        } else {
            true
        }
    });
    let magic = core::ptr::read_volatile(REP_DATA_VADDR as *const u32);
    check_client(
        b"surt_client_ioctl_ping",
        ioctl_status == STATUS_SUCCESS && info == 4 && magic == KMDF_PING_MAGIC,
        &mut passed,
    );

    let _ = ep_send_one(CT_RESULT, passed);

    // Crash-survival demo: deliberately fault (a wild write — the kind of bug that
    // bluescreens Windows). Because this driver runs in its OWN VSpace with a fault
    // endpoint routed to the NT kernel, the kernel catches the fault and survives;
    // only this isolated driver process dies. Control never returns from the write.
    print_str(b"    [surt-client] deliberately faulting (simulated driver crash)\n");
    core::ptr::write_volatile(0xDEAD_0000 as *mut u64, 0);
    park()
}
