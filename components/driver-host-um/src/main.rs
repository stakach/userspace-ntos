//! `ntos-driver-host-um` — an isolated, out-of-process driver component.
//!
//! A GENUINELY separate binary (its own ELF, its own private VSpace) that the
//! driver-host "NT kernel" loads via its ELF loader and spawns. It reaches the
//! device only over the SURT reflector ring — it has no access to the WDF runtime,
//! the Configuration Manager, or the device object. When it crashes (a simulated
//! driver bug), the kernel catches the fault on the supervisor endpoint instead of
//! going down. Shares nothing with the kernel binary except the [`nt_um_abi`] ABI.
//!
//! Alloc-free: no global allocator, fixed stack + volatile shared-frame I/O only.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use nt_um_abi::*;
use sel4_rt::*;
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, CPtr, Sel4Env, Sel4Notify};

/// SURT's wakeup contract: signal a notification / wait on it.
struct Env;
impl Sel4Env for Env {
    fn signal(&self, ntfn: CPtr) {
        // SAFETY: `ntfn` is a Notification cap; Send length 0 = seL4_Signal.
        unsafe {
            syscall5(SYS_SEND, ntfn, 0, 0, 0, 0);
        }
    }
    fn wait(&self, ntfn: CPtr) {
        // SAFETY: `ntfn` is a Notification cap; Recv = seL4_Wait.
        unsafe {
            let _ = ep_recv(ntfn);
        }
    }
}
static ENV: Env = Env;

fn park() -> ! {
    loop {
        yield_now();
    }
}

/// The isolated driver's entry. `arg0` (rdi) carries the supervisor's behavior
/// profile + attempt number (see [`nt_um_abi::make_arg`]).
///
/// # Safety
/// Entered by the kernel with the reflector rings mapped at the shared vaddrs and
/// the driver's caps seeded into its CNode.
#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(_arg0: u64) -> ! {
    print_str(b"    [um-driver] isolated driver process up (separate binary)\n");

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

    // Reach the device over the reflector ring: open its interface, then PING it.
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
    let mut fdo = 0u64;
    let mut open_status = -1i32;
    let _ = drain_blocking(&mut cq, &wait_completion, |cqe: &SurtCqe| {
        if cqe.request_id == 1 {
            open_status = cqe.status;
            fdo = cqe.detail0;
            false
        } else {
            true
        }
    });
    let mut passed = 0u64;
    if open_status == STATUS_SUCCESS && fdo != 0 {
        passed += 1;
        print_str(b"    [um-driver] opened device interface over ring\n");
    }

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
    let mut ping_status = -1i32;
    let _ = drain_blocking(&mut cq, &wait_completion, |cqe: &SurtCqe| {
        if cqe.request_id == 2 {
            ping_status = cqe.status;
            false
        } else {
            true
        }
    });
    let magic = core::ptr::read_volatile(REP_DATA_VADDR as *const u32);
    if ping_status == STATUS_SUCCESS && magic == KMDF_PING_MAGIC {
        passed += 1;
        print_str(b"    [um-driver] IOCTL ping over ring returned device magic\n");
    }

    // Report the verdict to the NT-kernel side, THEN crash.
    let _ = ep_send_one(CT_RESULT, passed);

    // Simulated driver bug: a wild write. Because this driver runs in its own
    // VSpace with a fault endpoint routed to the NT kernel, the kernel catches the
    // fault instead of bluescreening — only this isolated process dies.
    print_str(b"    [um-driver] crashing (simulated driver bug)\n");
    core::ptr::write_volatile(0xDEAD_0000 as *mut u64, 0);
    park()
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sel4_rt::debug_put_char(b'!');
    loop {
        yield_now();
    }
}
