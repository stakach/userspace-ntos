//! An isolated "driver host" ISR component (P1): a separate VSpace/CSpace whose
//! only job is to wait on a real device IRQ and report it — the seL4 analogue of a
//! driver's interrupt service routine. The executive (Tier 1) owns the IRQ-handler
//! cap; it hands this host only a cap to the bound notification, so the interrupt is
//! delivered straight into the isolated host without the executive in the wakeup path.

use crate::*;

#[no_mangle]
#[link_section = ".text.isr_entry"]
pub unsafe extern "C" fn isr_entry() -> ! {
    // Block on the IRQ notification — the kernel signals it when the real hardware
    // interrupt fires (the IRQ-handler cap the executive issued is bound to it).
    let _ = ep_recv(CT_IRQ_NTFN);
    // Report by signalling the (badged) result notification the executive polls.
    let _ = syscall5(SYS_SEND, CT_RESULT_NTFN, 0, 0, 0, 0);
    loop {
        yield_now();
    }
}
