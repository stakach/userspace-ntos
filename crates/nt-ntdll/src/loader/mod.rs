//! # The loader — `LdrpInitialize` (Step 3)
//!
//! The host-testable **graph engine** at the heart of `LdrpInitialize`: resolve imports (including
//! **forwarders**), order the modules for `DLL_PROCESS_ATTACH`, build the `PEB->Ldr` module lists,
//! and orchestrate the whole thing. The pure graph logic is host-tested over mock modules; the
//! parts that need a live process — mapping a module's pages, calling `DllMain`/TLS callbacks,
//! writing the gs-relative PEB/TEB, `NtContinue` to the entry — are **documented seams** behind the
//! [`host::LoaderHost`] trait (host tests use a mock; the real syscall impl is Step 4).
//!
//! ## Modules
//! - [`module`] — the loader's module model ([`module::LoadedModule`]) + the module set
//!   ([`module::LoaderState`]); forwarder-string detection lives here.
//! - [`resolve`] — import snap ([`resolve::snap_all`]) + recursive forwarder resolution with cycle
//!   detection (the `_vista` fix).
//! - [`order`] — dependency ordering for `DLL_PROCESS_ATTACH` (post-order DFS, cycle-tolerant).
//! - [`peb`] — `PEB->Ldr` construction: the three `LIST_ENTRY` module lists + the PEB/TEB fields.
//! - [`host`] — the [`host::LoaderHost`] seam (mock for host tests; real syscalls = Step 4).
//! - [`init`] — the [`init::ldrp_initialize`] orchestration tying it all together.
//!
//! ## The apphelp / SxS correctness note
//! Our loader loads the shim engine (`apphelp.dll`) **only if a shim database says so** — with no
//! DB, it does NOT load apphelp. That is the *correct* Windows behavior, and it replaces the
//! executive's ad-hoc apphelp denylist hack (`project_full_fs.md`): the loader controls whether the
//! shim engine loads, by policy, not by a name blocklist. See [`init::ShimPolicy`].

pub mod host;
pub mod init;
pub mod lifecycle;
pub mod lock;
pub mod module;
pub mod notification;
pub mod order;
pub mod peb;
pub mod resolve;
pub mod thread;
pub mod tls;

#[cfg(test)]
mod tests;
