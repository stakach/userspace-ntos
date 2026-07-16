//! The **native seL4-Call transport** message layout (`ntdll_plan.md` Step 6.A).
//!
//! Instead of the classic x86 `mov eax,ssn; syscall` (which faults as `UnknownSyscall` and
//! round-trips through the fault EP), OUR ntdll's `Nt*` stubs issue a real native seL4 `Call` on the
//! service endpoint (the fault EP, cap slot [`CT_FAULT`] in the process's CSpace). Because OUR ntdll
//! owns EVERY syscall, the process never issues a raw Windows `syscall`, so the per-thread
//! `TCBSetHostedSyscalls` flag is simply left CLEAR and the native `Call` dispatches natively in the
//! kernel — **no kernel change** (see the recon in `ntdll_plan.md`).
//!
//! This module holds the wire-format CONSTANTS + the pure msginfo pack/unpack (host-tested). The
//! actual `seL4_Call` asm is target-only (in `nt-ntdll-dll::on_target` / the generated native stubs),
//! but keeping the layout here — one source of truth shared by the ntdll stub side AND cross-checked
//! against the executive's decode — is the discipline that keeps the two ends from drifting.
//!
//! ## REQUEST (ntdll → executive), msginfo label = [`NT_NATIVE_SYSCALL_LABEL`], length 6
//! | MR | contents |
//! |----|----------|
//! | 0  | SSN (Windows service number) |
//! | 1  | caller RSP (so the executive reads stack args 5+ AND writes stack out-params via its stack mirror — a native `Call` transfers no rsp/stack) |
//! | 2  | arg1 (RCX in the Windows ABI; `mov r10,rcx` on the trap path) |
//! | 3  | arg2 (RDX) |
//! | 4  | arg3 (R8) |
//! | 5  | arg4 (R9) |
//!
//! ## REPLY (executive → ntdll), length 1
//! | MR | contents |
//! |----|----------|
//! | 0  | NTSTATUS |
//!
//! ## Register/IPC-buffer mapping (matches the kernel's IPC ABI + the executive plumbing)
//! On the wire a `Call`/`Recv` carries: rsi = msginfo, r10 = MR0, r8 = MR1, r9 = MR2, r15 = MR3, and
//! the IPC buffer words `[4]`/`[5]` = MR4/MR5. The reply carries r10 = MR0 = NTSTATUS.

/// The msginfo LABEL that marks a REQUEST as an NT native-syscall (not a fault). ASCII `"NT"` (0x4E54)
/// — well clear of the kernel fault-type labels (`UnknownSyscall`=2, `UserException`=3, `VMFault`=6),
/// so the executive's recv loop can tell a native-syscall message from a fault message by `mi>>12`.
/// Re-exported from the shared `nt-syscall-abi` (the single source of truth ntdll ↔ executive share).
pub use nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL;

/// The CSpace slot (in the hosted process's CNode) holding the SEND cap to the service endpoint.
/// This is the SAME `CT_FAULT` slot the executive's `spawn_sec_image` already populates with a cap to
/// the fault EP — we reuse the fault EP as the service channel (no second endpoint, no extra grant).
pub const CT_FAULT: u64 = 6;

/// REQUEST message length in MRs (SSN + rsp + 4 register args).
pub const NT_REQUEST_LEN: u64 = 6;

/// REPLY message length in MRs (NTSTATUS).
pub const NT_REPLY_LEN: u64 = 1;

/// The native seL4 `SysCall` syscall number (`codegen/syscall.xml` → `SysCall = -1`), placed in RDX
/// by the `Call`. As a `u64` this is `0xFFFF_FFFF_FFFF_FFFF`.
pub const SYS_CALL: i64 = -1;

/// Pack a msginfo word: `label<<12 | (extraCaps<<9) | (capsUnwrapped<<7) | length`. For our
/// register-only messages (no caps) extraCaps/capsUnwrapped are 0, so it is just `label<<12 | length`.
#[inline]
pub const fn pack_msginfo(label: u64, length: u64) -> u64 {
    (label << 12) | (length & 0x7F)
}

/// Extract the label from a msginfo word (`mi >> 12`).
#[inline]
pub const fn msginfo_label(mi: u64) -> u64 {
    mi >> 12
}

/// Extract the length (MR count) from a msginfo word (`mi & 0x7F`).
#[inline]
pub const fn msginfo_length(mi: u64) -> u64 {
    mi & 0x7F
}

/// The REQUEST message register indices (documentation + a single source of truth for both ends).
pub mod req {
    /// MR0 — the SSN.
    pub const SSN: usize = 0;
    /// MR1 — the caller RSP.
    pub const RSP: usize = 1;
    /// MR2 — arg1.
    pub const ARG1: usize = 2;
    /// MR3 — arg2.
    pub const ARG2: usize = 3;
    /// MR4 — arg3.
    pub const ARG3: usize = 4;
    /// MR5 — arg4.
    pub const ARG4: usize = 5;
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn label_is_clear_of_fault_labels() {
        // The native-syscall label must not collide with the kernel fault-type discriminants the
        // executive routes on (2 = UnknownSyscall, 3 = UserException, 6 = VMFault).
        assert_ne!(NT_NATIVE_SYSCALL_LABEL, 2);
        assert_ne!(NT_NATIVE_SYSCALL_LABEL, 3);
        assert_ne!(NT_NATIVE_SYSCALL_LABEL, 6);
        // And it round-trips through the msginfo pack/unpack.
        let mi = pack_msginfo(NT_NATIVE_SYSCALL_LABEL, NT_REQUEST_LEN);
        assert_eq!(msginfo_label(mi), NT_NATIVE_SYSCALL_LABEL);
        assert_eq!(msginfo_length(mi), NT_REQUEST_LEN);
    }

    #[test]
    fn msginfo_roundtrip() {
        for &(label, len) in &[(0u64, 0u64), (2, 4), (NT_NATIVE_SYSCALL_LABEL, 6), (0xABCD, 0x7F)] {
            let mi = pack_msginfo(label, len);
            assert_eq!(msginfo_label(mi), label);
            assert_eq!(msginfo_length(mi), len);
        }
    }

    #[test]
    fn request_indices_are_contiguous() {
        assert_eq!(req::SSN, 0);
        assert_eq!(req::RSP, 1);
        assert_eq!(req::ARG1, 2);
        assert_eq!(req::ARG4, 5);
        // The declared length covers exactly MR0..=MR5.
        assert_eq!(NT_REQUEST_LEN, req::ARG4 as u64 + 1);
    }

    #[test]
    fn sys_call_is_negative_one() {
        assert_eq!(SYS_CALL, -1);
        assert_eq!(SYS_CALL as u64, u64::MAX);
    }
}
