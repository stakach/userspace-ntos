//! # `nt-ntdll` — our Rust `ntdll.dll` (skeleton)
//!
//! ntdll is not an application we host — it is the **userspace half of OUR kernel ABI**: the thing
//! that turns NT/Win32 API calls into *our* syscalls. We own the kernel, so owning ntdll is the
//! architecturally consistent choice (see `ntdll_plan.md`).
//!
//! **Step 2a** shipped the skeleton; **Step 2b** (this) lands the bulk of the library surface.
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
//! - [`rtl`] — **Category A** (Step 2b): the bulk pure/mechanical `Rtl*` surface — strings,
//!   NLS-driven charset conversion, integers/large-integers, time, GUID, DOS-path parsing,
//!   status/error mapping, random/CRC, and the bitmap primitives (reused from `nt-kernel-exec`).
//! - [`crt`] — **Category A'** (Step 2b): the C-runtime re-exports ntdll ships
//!   (`mem*`/`str*`/`wcs*`/`_snprintf`/`qsort`/`bsearch`) + the NLS data-export tags.
//! - [`heap`] — **Category B** (Step 2b): a **real** `RtlAllocateHeap`/`Free`/`ReAlloc`/`Size` heap
//!   (first-fit free-list + coalescing) over an abstract backing region, host-tested.
//! - [`sync`] — **Category C** (Step 2b): the `RTL_CRITICAL_SECTION`/`RTL_SRWLOCK`/`RTL_RUN_ONCE`
//!   layouts + **uncontended fast paths** (host-tested), with the **contended-blocking path an
//!   honest documented keyed-event seam** through [`transport`] — NOT faked (the root fix for the
//!   `RtlpWaitForCriticalSection` boot deadlock: correct by construction).
//!
//! Scope: the full 188 stub *bodies* (>4-arg stack thunk), `Csr*`/`Dbg*`/`Ki*`, and the loader are
//! tracked follow-ons (Step 2c / Step 3). See `ntdll_plan.md`.
//!
//! `no_std` + `alloc`.

#![no_std]

extern crate alloc;

pub use nt_syscall_abi as abi;

pub mod crt;
pub mod heap;
pub mod rtl;
pub mod stubs;
pub mod sync;
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
