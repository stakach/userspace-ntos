//! `ntos-root` — the userspace-ntos root task.
//!
//! The first user-space component the rust-micro microkernel hands control to.
//! Right now it is a boot smoke-test: read `BootInfo`, print it over the kernel
//! debug serial (via the shared `sel4-rt` ABI), and exit QEMU. It will grow into
//! the host for the **NT Object Manager** and the rest of the NT executive
//! personality.
//!
//! Build + boot:  `./scripts/run.sh`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// The kernel's user-space ABI (syscalls, invocation helpers, BootInfo), from the
// rust-micro submodule.
use sel4_rt::*;

#[no_mangle]
#[link_section = ".text._start"]
unsafe extern "C" fn _start(bootinfo: *const BootInfo) -> ! {
    let bi = &*bootinfo;

    print_str(b"[ntos] userspace-ntos root task alive on rust-micro\n");
    print_str(b"[ntos]   node ");
    print_u64(bi.node_id);
    print_str(b"/");
    print_u64(bi.num_nodes);
    print_str(b", first empty slot ");
    print_u64(bi.empty.start);
    print_str(b", ipc_buffer @ 0x");
    print_hex(bi.ipc_buffer as u64);
    print_str(b"\n");
    let n_untyped = bi.untyped.end - bi.untyped.start;
    print_str(b"[ntos]   ");
    print_u64(n_untyped);
    print_str(b" untyped(s), ");
    print_u64(bi.user_image_frames.end - bi.user_image_frames.start);
    print_str(b" image frame cap(s)\n");

    // TODO: NT Object Manager bootstrap — the root \ObjectDirectory, the type
    // objects (Directory, SymbolicLink, ...), and the object namespace go here.
    print_str(b"[ntos] boot smoke-test OK\n");

    // The kernel's serial exit hook watches for this exact sentinel to qemu_exit.
    print_str(b"[microtest done]\n");
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    debug_put_char(b'!');
    loop {
        yield_now();
    }
}
