//! The [`LoaderHost`] seam — the boundary between the host-testable loader **engine** and the
//! **live process** operations it can only perform on-target.
//!
//! The loader engine (import snap, forwarder resolution, init-ordering, `PEB->Ldr` construction) is
//! pure graph logic and runs identically on the host and on-target. But four operations *require* a
//! live process and cannot be host-tested honestly:
//!
//! 1. **Mapping a module's pages** — `NtAllocateVirtualMemory` + copy/relocate + `NtProtect` (or the
//!    demand-fault path). The engine decides *what* to map; the host *does* it.
//! 2. **Writing an IAT slot / the gs-relative PEB & TEB** — raw writes into the live address space.
//! 3. **Calling `DllMain` / TLS callbacks** — transferring control into target code.
//! 4. **`NtContinue` to the image entry** — the final hand-off (no return).
//!
//! Each is a [`LoaderHost`] method. **Host tests use [`MockHost`]**, which records the requests (so
//! the orchestration is fully testable) and returns success. The **real** impl (Step 4) issues the
//! syscalls. Crucially, the trait's *default* / off-target behavior returns
//! [`STATUS_NOT_IMPLEMENTED`] — it is **NEVER faked**: a caller can't proceed as if a page were
//! mapped or `DllMain` ran when it did not.

use alloc::vec::Vec;

use crate::{NtStatus, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};

/// The reason a module's entry point is being invoked (`DLL_PROCESS_ATTACH` etc.). Matches the
/// `fdwReason` a `DllMain` receives.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DllReason {
    /// `DLL_PROCESS_ATTACH` (1).
    ProcessAttach,
    /// `DLL_PROCESS_DETACH` (0).
    ProcessDetach,
    /// `DLL_THREAD_ATTACH` (2).
    ThreadAttach,
    /// `DLL_THREAD_DETACH` (3).
    ThreadDetach,
}

impl DllReason {
    /// The numeric `fdwReason` value.
    pub const fn as_u32(self) -> u32 {
        match self {
            DllReason::ProcessDetach => 0,
            DllReason::ProcessAttach => 1,
            DllReason::ThreadAttach => 2,
            DllReason::ThreadDetach => 3,
        }
    }
}

/// A request to map an image's pages (the "what to map" the engine computed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRequest {
    /// The module base name (diagnostics).
    pub name: alloc::string::String,
    /// The VA the image is to be mapped at.
    pub base: u64,
    /// The image's `SizeOfImage`.
    pub size_of_image: u32,
}

/// The live-process operations the loader engine delegates. Host tests mock these; Step 4 wires the
/// real syscalls. **No method may fabricate success off-target** — the honest-seam invariant.
pub trait LoaderHost {
    /// Map a module's pages into the address space (`NtAllocateVirtualMemory` + copy + relocate +
    /// `NtProtect`). Step 4 seam.
    fn map_image(&mut self, req: &MapRequest) -> NtStatus;

    /// Write a resolved import address into an IAT slot at `module_base + iat_slot_rva`. Step 4 seam.
    fn write_iat_slot(&mut self, module_base: u64, iat_slot_rva: u32, address: u64) -> NtStatus;

    /// Call a module's entry point (`DllMain`) with `fdwReason`. Returns the `DllMain` `BOOL` (a
    /// `FALSE` from `DLL_PROCESS_ATTACH` fails the load). Step 4 seam.
    fn call_dll_main(&mut self, module_base: u64, entry_rva: u32, reason: DllReason) -> NtStatus;

    /// Run a module's TLS callbacks (if it has a TLS directory), before/around `DLL_PROCESS_ATTACH`.
    /// Step 4 seam.
    fn run_tls_callbacks(&mut self, module_base: u64, reason: DllReason) -> NtStatus;

    /// Write the constructed PEB/TEB out to the live (gs-relative) control structures. Step 4 seam.
    fn commit_peb_teb(&mut self, peb_va: u64, teb_va: u64) -> NtStatus;

    /// Transfer control to the image entry point (no return; `NtContinue`-style). Step 4 seam.
    fn transfer_to_entry(&mut self, entry_va: u64, peb_va: u64) -> NtStatus;
}

/// A record of what the loader asked the host to do — the host-test observation surface. Each vector
/// captures the requests in order so an orchestration test can assert *exactly* what the loader
/// drove (e.g. "`DllMain` was called for these modules in this order").
#[derive(Clone, Debug, Default)]
pub struct MockHost {
    /// The `map_image` requests, in order.
    pub mapped: Vec<MapRequest>,
    /// The `(module_base, iat_slot_rva, address)` IAT writes, in order.
    pub iat_writes: Vec<(u64, u32, u64)>,
    /// The `(module_base, entry_rva, reason)` `DllMain` calls, in order.
    pub dll_main_calls: Vec<(u64, u32, DllReason)>,
    /// The `(module_base, reason)` TLS-callback runs, in order.
    pub tls_runs: Vec<(u64, DllReason)>,
    /// The `(peb_va, teb_va)` commit, if any.
    pub committed: Option<(u64, u64)>,
    /// The `(entry_va, peb_va)` transfer, if any.
    pub transferred: Option<(u64, u64)>,
    /// If set, `call_dll_main` returns this status for the given module base (to test the
    /// `DLL_PROCESS_ATTACH`-returns-FALSE failure path). Value is a "return FALSE" flag.
    pub dll_main_fail_base: Option<u64>,
}

impl MockHost {
    /// A fresh recording host.
    pub fn new() -> Self {
        MockHost::default()
    }
}

impl LoaderHost for MockHost {
    fn map_image(&mut self, req: &MapRequest) -> NtStatus {
        self.mapped.push(req.clone());
        STATUS_SUCCESS
    }

    fn write_iat_slot(&mut self, module_base: u64, iat_slot_rva: u32, address: u64) -> NtStatus {
        self.iat_writes.push((module_base, iat_slot_rva, address));
        STATUS_SUCCESS
    }

    fn call_dll_main(&mut self, module_base: u64, entry_rva: u32, reason: DllReason) -> NtStatus {
        self.dll_main_calls.push((module_base, entry_rva, reason));
        if self.dll_main_fail_base == Some(module_base) && reason == DllReason::ProcessAttach {
            // Model a DllMain returning FALSE → the loader must fail the process.
            return crate::loader::init::STATUS_DLL_INIT_FAILED;
        }
        STATUS_SUCCESS
    }

    fn run_tls_callbacks(&mut self, module_base: u64, reason: DllReason) -> NtStatus {
        self.tls_runs.push((module_base, reason));
        STATUS_SUCCESS
    }

    fn commit_peb_teb(&mut self, peb_va: u64, teb_va: u64) -> NtStatus {
        self.committed = Some((peb_va, teb_va));
        STATUS_SUCCESS
    }

    fn transfer_to_entry(&mut self, entry_va: u64, peb_va: u64) -> NtStatus {
        self.transferred = Some((entry_va, peb_va));
        STATUS_SUCCESS
    }
}

/// The **null host** — every live operation returns [`STATUS_NOT_IMPLEMENTED`]. This is what an
/// off-target / not-yet-wired build gets by default: proof that the engine never silently fakes a
/// live operation (a caller using `NullHost` cannot proceed past a required map/call). The real
/// on-target host (Step 4) replaces it.
#[derive(Copy, Clone, Debug, Default)]
pub struct NullHost;

impl LoaderHost for NullHost {
    fn map_image(&mut self, _req: &MapRequest) -> NtStatus {
        STATUS_NOT_IMPLEMENTED
    }
    fn write_iat_slot(&mut self, _b: u64, _r: u32, _a: u64) -> NtStatus {
        STATUS_NOT_IMPLEMENTED
    }
    fn call_dll_main(&mut self, _b: u64, _r: u32, _reason: DllReason) -> NtStatus {
        STATUS_NOT_IMPLEMENTED
    }
    fn run_tls_callbacks(&mut self, _b: u64, _reason: DllReason) -> NtStatus {
        STATUS_NOT_IMPLEMENTED
    }
    fn commit_peb_teb(&mut self, _p: u64, _t: u64) -> NtStatus {
        STATUS_NOT_IMPLEMENTED
    }
    fn transfer_to_entry(&mut self, _e: u64, _p: u64) -> NtStatus {
        STATUS_NOT_IMPLEMENTED
    }
}
