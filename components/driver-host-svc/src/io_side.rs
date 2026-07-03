//! The io-side requester: sends `DH_OP_DISPATCH_IRP` requests over SURT to the
//! isolated Driver Host (running the real driver) and verifies the completions.

use nt_driver_abi::opcode::DH_OP_DISPATCH_IRP;
use surt_sel4::surt_core::surt_abi::{SurtCqe, SurtSqe};
use surt_sel4::surt_core::{Consumer, Producer};
use surt_sel4::{drain_blocking, Sel4Notify};

use crate::{
    ep_send_one, print_str, yield_now, KernelEnv, COMP_RING_VADDR, CT_N_COMP, CT_N_SUB, CT_RESULT,
    ENV, REP_DATA_VADDR, REQ_DATA_VADDR, RING_LEN, SUB_RING_VADDR,
};

/// Checks the io-side performs.
pub const CHECKS: u64 = 3;

struct Link<'a> {
    sq: Producer<SurtSqe>,
    cq: Consumer<SurtCqe>,
    signal: Sel4Notify<'a, KernelEnv>,
    wait: Sel4Notify<'a, KernelEnv>,
    next_id: u64,
}

impl Link<'_> {
    /// Send one IOCTL over SURT + return `(status, information, output[64])`.
    unsafe fn ioctl(&mut self, code: u32, input: &[u8], out_cap: u32) -> (i32, u64, [u8; 64]) {
        // Request frame: [major, _, code@4, in_len@8, out_len@12, input@16].
        let base = REQ_DATA_VADDR as *mut u8;
        core::ptr::write_volatile(base, 0x0e); // IRP_MJ_DEVICE_CONTROL
        core::ptr::write_unaligned(base.add(4) as *mut u32, code);
        core::ptr::write_unaligned(base.add(8) as *mut u32, input.len() as u32);
        core::ptr::write_unaligned(base.add(12) as *mut u32, out_cap);
        for (i, b) in input.iter().enumerate() {
            core::ptr::write_volatile(base.add(16 + i), *b);
        }

        let id = self.next_id;
        self.next_id += 1;
        let sqe = SurtSqe {
            opcode: DH_OP_DISPATCH_IRP as u16,
            len: (16 + input.len()) as u32,
            request_id: id,
            offset: 0,
            ..Default::default()
        };
        while self.sq.try_push(sqe).is_err() {
            yield_now();
        }
        let _ = self.sq.notify_consumer(&self.signal);

        let mut status = 0i32;
        let mut information = 0u64;
        let _ = drain_blocking(&mut self.cq, &self.wait, |cqe: &SurtCqe| {
            if cqe.request_id == id {
                status = cqe.status;
                information = cqe.information;
                false
            } else {
                true
            }
        });

        let mut out = [0u8; 64];
        let rep = REP_DATA_VADDR as *const u8;
        for (i, o) in out.iter_mut().enumerate().take((information as usize).min(64)) {
            *o = core::ptr::read_volatile(rep.add(i));
        }
        (status, information, out)
    }
}

fn check(name: &[u8], ok: bool, passed: &mut u64) {
    print_str(if ok { b"  PASS " } else { b"  FAIL " });
    print_str(name);
    print_str(b"\n");
    if ok {
        *passed += 1;
    }
}

fn park() -> ! {
    loop {
        yield_now();
    }
}

#[no_mangle]
#[link_section = ".text.io_side_entry"]
pub unsafe extern "C" fn io_side_entry() -> ! {
    let sq = match Producer::<SurtSqe>::attach(SUB_RING_VADDR as *mut u8, RING_LEN) {
        Ok(p) => p,
        Err(_) => park(),
    };
    let cq = match Consumer::<SurtCqe>::attach(COMP_RING_VADDR as *mut u8, RING_LEN) {
        Ok(c) => c,
        Err(_) => park(),
    };
    let mut link = Link {
        sq,
        cq,
        signal: Sel4Notify::new(&ENV, CT_N_SUB),
        wait: Sel4Notify::new(&ENV, CT_N_COMP),
        next_id: 1,
    };

    let mut passed = 0u64;

    // IOCTL_SURT_PING → 0x53555254 ("SURT"), Information = 4.
    let (st, info, out) = link.ioctl(0x0022_2000, &[], 8);
    let ping = core::ptr::read_unaligned(out.as_ptr() as *const u32);
    check(b"ioctl_ping", st == 0 && info == 4 && ping == 0x5355_5254, &mut passed);

    // IOCTL_SURT_GET_VERSION → { 0, 1, 0, 9 }, Information = 16.
    let (st, info, out) = link.ioctl(0x0022_2008, &[], 16);
    let v = |o: usize| core::ptr::read_unaligned(out.as_ptr().add(o) as *const u32);
    check(
        b"ioctl_get_version",
        st == 0 && info == 16 && v(0) == 0 && v(4) == 1 && v(8) == 0 && v(12) == 9,
        &mut passed,
    );

    // IOCTL_SURT_ECHO → METHOD_BUFFERED echo of "hello".
    let (st, info, out) = link.ioctl(0x0022_2004, b"hello", 8);
    check(b"ioctl_echo", st == 0 && info == 5 && &out[..5] == b"hello", &mut passed);

    let _ = ep_send_one(CT_RESULT, passed);
    park()
}
