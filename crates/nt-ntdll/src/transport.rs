//! The swappable syscall-transport seam.
//!
//! An `Nt*` stub takes an SSN + up to N register-width args and must deliver them to the servicing
//! side, returning an `NTSTATUS`. Because WE author the stub, the *how* is a free choice per-call
//! or per-surface (`ntdll_plan.md` win #2):
//!
//! - [`Backend::X86Trap`] — the classic `mov r10, rcx; mov eax, <ssn>; syscall`. On our kernel this
//!   faults as `UnknownSyscall` and round-trips through the fault EP to the executive. Kept for
//!   drop-in compat with any raw-syscall code. **Implemented** as a `cfg(target_arch="x86_64")`
//!   naked-asm layer ([`x86_trap_syscall`]).
//! - [`Backend::Sel4Call`] — a native seL4 `Call` to the servicing endpoint (the proper
//!   capability-based path: a real IPC channel, no fault-trap emulation → cleaner + faster). A
//!   **declared seam**; the real send lands in Step 6.
//! - [`Backend::SurtRing`] — io_uring-style SURT ring submission for the batchable/async surface. A
//!   **declared seam**.
//!
//! The **selection policy** ([`Backend::for_ssn`]) and the SSN plumbing are host-tested here; the
//! trap asm is target-only.

use crate::{NtStatus, STATUS_NOT_IMPLEMENTED};

/// A transport backend for an `Nt*` stub.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Classic `mov eax,SSN; syscall` x86 trap (faults as `UnknownSyscall` on our kernel).
    X86Trap,
    /// Native seL4 `Call` to the servicing endpoint (declared seam — Step 6).
    Sel4Call,
    /// SURT io_uring-style ring submission (declared seam).
    SurtRing,
}

impl Backend {
    /// The **default transport-selection policy** for a given SSN.
    ///
    /// Step 2a ships the drop-in-compatible default: every service uses [`Backend::X86Trap`], so
    /// our ntdll is behaviour-identical to the real one against the current executive (which
    /// services `UnknownSyscall` faults). Step 6 flips executive-serviced SSNs to
    /// [`Backend::Sel4Call`] once parity holds; batchable surfaces can opt into
    /// [`Backend::SurtRing`]. Keeping the policy in one function is the seam that makes that flip a
    /// one-place change.
    pub const fn for_ssn(_ssn: u32) -> Backend {
        Backend::X86Trap
    }

    /// Whether this backend is wired end-to-end today. `X86Trap` is (target-side); the seL4/SURT
    /// seams are declared but unimplemented until Step 6.
    pub const fn is_implemented(self) -> bool {
        matches!(self, Backend::X86Trap)
    }
}

/// Perform a syscall via the selected backend. Host builds (and the not-yet-wired seams) return
/// [`STATUS_NOT_IMPLEMENTED`]; the real `X86Trap` send is `cfg(target_arch="x86_64")`.
///
/// `args` are the register-width arguments in `r10, rdx, r8, r9, [stack…]` order (the x64 native
/// convention `SyscallRegisterAbi::x64()` describes).
pub fn syscall(backend: Backend, ssn: u32, args: &[u64]) -> NtStatus {
    match backend {
        Backend::X86Trap => x86_trap_dispatch(ssn, args),
        // The seL4/SURT backends must GATHER every arg (incl. the stack tail) into an IPC message /
        // ring entry before sending — unlike the trap, which leaves the tail on the caller's stack.
        // We marshal here (host-tested via `marshal`), then hit the honest send seam: the real IPC
        // send lands in Step 6. Marshalling-then-NOT_IMPLEMENTED never fabricates a result.
        Backend::Sel4Call => {
            let _msg = crate::marshal::marshal(ssn, args.len(), &crate::marshal::FlatArgSource(args));
            // Real seL4 `Call` to the servicing endpoint carrying `_msg` — Step 6.
            STATUS_NOT_IMPLEMENTED
        }
        Backend::SurtRing => {
            let _entry = crate::marshal::marshal(ssn, args.len(), &crate::marshal::FlatArgSource(args));
            // Real SURT ring submission carrying `_entry` — Step 6.
            STATUS_NOT_IMPLEMENTED
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn x86_trap_dispatch(ssn: u32, args: &[u64]) -> NtStatus {
    // Marshal up to 4 register args (r10, rdx, r8, r9); >4 args need a stack thunk (follow-on).
    let a0 = args.first().copied().unwrap_or(0);
    let a1 = args.get(1).copied().unwrap_or(0);
    let a2 = args.get(2).copied().unwrap_or(0);
    let a3 = args.get(3).copied().unwrap_or(0);
    // SAFETY: issues the x64 native syscall trap. Register-only (≤4 args); no memory is touched
    // here. On our kernel this faults as `UnknownSyscall` and is serviced via the fault EP.
    unsafe { x86_trap_syscall(ssn, a0, a1, a2, a3) }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn x86_trap_dispatch(_ssn: u32, _args: &[u64]) -> NtStatus {
    // Host (non-target) builds can't issue the trap; the transport policy + SSN plumbing are what
    // we host-test. Returning NOT_IMPLEMENTED keeps the surface callable in tests.
    STATUS_NOT_IMPLEMENTED
}

/// The classic x64 native-syscall stub: `mov r10, rcx; mov eax, ssn; syscall`.
///
/// # Safety
/// Issues a raw `syscall`. Register-only (up to 4 args in `r10, rdx, r8, r9`); the caller must pass
/// a valid SSN. On our kernel this faults as `UnknownSyscall` and round-trips through the fault EP.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn x86_trap_syscall(ssn: u32, a0: u64, a1: u64, a2: u64, a3: u64) -> NtStatus {
    let status: u64;
    // The native x64 convention: eax=SSN, r10=arg0 (rcx is clobbered by `syscall`), rdx=arg1,
    // r8=arg2, r9=arg3, rax=NTSTATUS on return.
    core::arch::asm!(
        "syscall",
        in("eax") ssn,
        in("r10") a0,
        in("rdx") a1,
        in("r8") a2,
        in("r9") a3,
        lateout("rax") status,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    status as NtStatus
}
