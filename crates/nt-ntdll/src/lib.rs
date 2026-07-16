//! # `nt-ntdll` — our Rust `ntdll.dll` (skeleton)
//!
//! ntdll is not an application we host — it is the **userspace half of OUR kernel ABI**: the thing
//! that turns NT/Win32 API calls into *our* syscalls. We own the kernel, so owning ntdll is the
//! architecturally consistent choice (see `ntdll_plan.md`).
//!
//! This is the **Step 2a skeleton**: the pieces that de-risk the rest and are host-testable now.
//!
//! - [`transport`] — the **swappable syscall-transport seam** (`ntdll_plan.md` win #2). Because WE
//!   author the `Nt*` stubs, they don't *have* to emulate the x86 `syscall` trap; they can speak
//!   native seL4 IPC or SURT ring submission directly. Three backends are declared:
//!   [`transport::Backend::X86Trap`] (implemented target-side for drop-in compat),
//!   [`transport::Backend::Sel4Call`] (declared seam, Step 6), [`transport::Backend::SurtRing`]
//!   (declared seam). The **selection logic + SSN lookup are host-tested**; the trap asm itself is
//!   `cfg(target)`-gated (not host-tested — expected).
//! - [`stubs`] — the data-driven `Nt*` stub table, generated from the shared
//!   [`nt_syscall_abi`](nt_syscall_abi) SSN numbering (the single source of truth; SSN reuse of the
//!   ReactOS numbering is what makes the eventual cutover zero-churn on the executive).
//! - [`rtl`] — a proof-of-pattern `Rtl*` slice, reusing `nt-compat-exports::rtl`.
//!
//! Scope: the full 244 `Rtl` / 188 stub *bodies* / the loader are tracked follow-ons (Step
//! 2b/2c/Step 3). This crate lands the skeleton + a proven pattern.
//!
//! `no_std` + `alloc`.

#![no_std]

extern crate alloc;

pub use nt_syscall_abi as abi;

pub mod rtl;
pub mod stubs;
pub mod transport;

/// `NTSTATUS` — the 32-bit status every `Nt*` stub returns in `rax` (`STATUS_SUCCESS` = 0).
pub type NtStatus = u32;

/// `STATUS_SUCCESS`.
pub const STATUS_SUCCESS: NtStatus = 0x0000_0000;
/// `STATUS_NOT_IMPLEMENTED` — returned by a stub whose transport backend is a declared-but-
/// unimplemented seam (seL4-Call / SURT-ring, until Step 6).
pub const STATUS_NOT_IMPLEMENTED: NtStatus = 0xC000_0002;
/// `STATUS_INVALID_SYSTEM_SERVICE` — an unknown/unmapped `Nt*` name.
pub const STATUS_INVALID_SYSTEM_SERVICE: NtStatus = 0xC000_001C;

#[cfg(test)]
mod tests;
