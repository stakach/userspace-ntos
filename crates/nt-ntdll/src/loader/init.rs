//! `LdrpInitialize` — the orchestration that ties the loader engine together.
//!
//! Given a set of loaded modules + the process parameters, [`ldrp_initialize`]:
//! 1. normalizes the process parameters ([`crate::rtl::environment::normalize_flags`]),
//! 2. computes the process cookie (the seed for `RtlEncodePointer`),
//! 3. resolves **all** imports incl. **forwarders** ([`super::resolve::snap_all`]) — writing each
//!    into its IAT slot via the [`super::host::LoaderHost`] seam,
//! 4. computes the `DLL_PROCESS_ATTACH` order ([`super::order::initialization_order`]),
//! 5. builds `PEB->Ldr` ([`super::peb::build_ldr`]) + commits the PEB/TEB (host seam),
//! 6. runs TLS callbacks + `DLL_PROCESS_ATTACH` in dependency order (host seam),
//! 7. transfers to the image entry (host seam).
//!
//! The **graph steps (1–5, ordering + resolution + PEB build) are fully host-tested** over a mock
//! module set + a [`super::host::MockHost`] that records the drive. The **live steps** — mapping,
//! IAT writes, `DllMain`/TLS calls, the gs-relative PEB/TEB commit, the entry transfer — go through
//! the `LoaderHost`; with [`super::host::NullHost`] they honestly return `STATUS_NOT_IMPLEMENTED`
//! (Step 4 wires the real impl). The engine never fabricates a live result.

use alloc::vec::Vec;

use crate::{NtStatus, STATUS_SUCCESS};

use super::host::{DllReason, LoaderHost, MapRequest};
use super::module::LoaderState;
use super::{order, peb, resolve};

/// `STATUS_DLL_INIT_FAILED` — a `DllMain(DLL_PROCESS_ATTACH)` returned `FALSE`.
pub const STATUS_DLL_INIT_FAILED: NtStatus = 0xC000_0142;
/// `STATUS_DLL_NOT_FOUND` — a required dependency module is not loaded (the honest miss, not a spin).
pub const STATUS_DLL_NOT_FOUND: NtStatus = 0xC000_0135;
/// `STATUS_ENTRYPOINT_NOT_FOUND` — a required imported export is not present.
pub const STATUS_ENTRYPOINT_NOT_FOUND: NtStatus = 0xC000_0139;
/// `STATUS_UNSUCCESSFUL` — a generic loader failure (e.g. a forwarder cycle).
pub const STATUS_UNSUCCESSFUL: NtStatus = 0xC000_0001;

/// The shim-engine (apphelp) load policy. Windows loads `apphelp.dll` only when a shim database
/// matches the process; with no DB the shim engine is NOT loaded. Owning the loader makes this a
/// *policy decision*, replacing the executive's ad-hoc apphelp denylist hack
/// (`project_full_fs.md`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ShimPolicy {
    /// No shim database matched → do NOT load `apphelp.dll` (the default, correct behavior).
    #[default]
    NoShims,
    /// A shim database matched → load the shim engine.
    LoadShimEngine,
}

impl ShimPolicy {
    /// Whether `apphelp.dll` (the shim engine) should be loaded under this policy.
    pub fn loads_apphelp(self) -> bool {
        matches!(self, ShimPolicy::LoadShimEngine)
    }
}

/// The parameters `LdrpInitialize` needs (the subset the engine actually consumes host-side).
#[derive(Clone, Debug)]
pub struct InitParams {
    /// The initial `RTL_USER_PROCESS_PARAMETERS.Flags` (the engine sets `NORMALIZED`).
    pub process_params_flags: u32,
    /// The name of the root module (the process EXE) — the init-order traversal root + the module
    /// whose entry the loader transfers to. Empty = "all modules as roots".
    pub root_module: alloc::string::String,
    /// A raw cookie seed (in the real process, mixed from `NtQuerySystemTime`/TSC/pid). Here it's an
    /// input so the cookie computation is deterministic + host-testable.
    pub cookie_seed: u64,
    /// The apphelp/SxS shim policy.
    pub shim_policy: ShimPolicy,
    /// Where to place the built `PEB->Ldr` structures (model VAs host-side; a scratch alloc live).
    pub ldr_layout: peb::LdrLayout,
    /// The VA the PEB occupies (for the commit + the entry transfer's PEB arg).
    pub peb_va: u64,
    /// The VA the TEB occupies (for the commit).
    pub teb_va: u64,
}

impl Default for InitParams {
    fn default() -> Self {
        InitParams {
            process_params_flags: 0,
            root_module: alloc::string::String::new(),
            cookie_seed: 0,
            shim_policy: ShimPolicy::NoShims,
            ldr_layout: peb::LdrLayout::default(),
            peb_va: 0x0000_0000_0200_0000,
            teb_va: 0x0000_0000_0201_0000,
        }
    }
}

/// The result of a successful `LdrpInitialize` (the state the process starts in). On failure the
/// error `NtStatus` is returned instead.
#[derive(Clone, Debug)]
pub struct InitResult {
    /// The normalized process-params flags.
    pub normalized_flags: u32,
    /// The computed process cookie (`RtlEncodePointer` seed).
    pub process_cookie: u32,
    /// The init order (module names, dependencies first).
    pub init_order: Vec<alloc::string::String>,
    /// The built `PEB->Ldr`.
    pub ldr: peb::BuiltLdr,
    /// The entry VA control was transferred to (the root module's entry).
    pub entry_va: u64,
    /// Whether the shim engine (`apphelp`) was requested to load.
    pub loaded_apphelp: bool,
}

/// Compute the process cookie the way ntdll does in spirit: mix the seed's halves. The real
/// `RtlpInitializeProcessCookie` mixes system time, TSC, pid, and a stack address; here we take a
/// seed input so it is deterministic + testable, and fold it to the 32-bit cookie ntdll stores.
pub fn compute_process_cookie(seed: u64) -> u32 {
    let mixed = seed ^ seed.rotate_left(21) ^ seed.rotate_right(13);
    // Fold to 32 bits; ensure non-zero (ntdll re-rolls a zero cookie).
    let c = (mixed as u32) ^ ((mixed >> 32) as u32);
    if c == 0 {
        0x0000_0001
    } else {
        c
    }
}

/// `LdrpInitialize` — the orchestration. Drives the graph engine + the [`LoaderHost`] seams in the
/// real Ldr order. Returns the [`InitResult`] on success, or the first failure's `NtStatus`.
pub fn ldrp_initialize<H: LoaderHost>(
    state: &mut LoaderState,
    params: &InitParams,
    host: &mut H,
) -> Result<InitResult, NtStatus> {
    // (1) Normalize process parameters (sets the NORMALIZED flag; the real call also rebases the
    // embedded UNICODE_STRING buffers — that pointer rebase is a live-PEB seam).
    let normalized_flags = crate::rtl::environment::normalize_flags(params.process_params_flags);

    // (2) Compute the process cookie (RtlEncodePointer's seed).
    let process_cookie = compute_process_cookie(params.cookie_seed);

    // (3) Map every module (the engine says WHAT; the host DOES it). A map failure aborts.
    for m in &state.modules {
        let st = host.map_image(&MapRequest {
            name: m.name.clone(),
            base: m.base,
            size_of_image: m.size_of_image,
        });
        if st != STATUS_SUCCESS {
            return Err(st);
        }
    }

    // (4) Resolve ALL imports incl. forwarders, writing each into its IAT slot (host seam). A
    // missing module/export/forwarder-cycle is a real STATUS — never a spin.
    let snapped = resolve::snap_all(state).map_err(map_resolve_error)?;
    for (importer, resolutions) in &snapped {
        let base = state.find(importer).map(|m| m.base).unwrap_or(0);
        for r in resolutions {
            let st = host.write_iat_slot(base, r.iat_slot_rva, r.address);
            if st != STATUS_SUCCESS {
                return Err(st);
            }
        }
    }

    // (5) Compute the DLL_PROCESS_ATTACH order (dependencies before dependents).
    let root_refs: Vec<&str> = if params.root_module.is_empty() {
        Vec::new()
    } else {
        alloc::vec![params.root_module.as_str()]
    };
    let init_idx = order::initialization_order(state, &root_refs);
    let init_order: Vec<alloc::string::String> = init_idx
        .iter()
        .map(|&i| state.modules[i].name.clone())
        .collect();

    // (6) Build PEB->Ldr (load order = the module set's load order; init order from (5)).
    let load_order: Vec<usize> = (0..state.modules.len()).collect();
    let built = peb::build_ldr(state, &load_order, &init_idx, params.ldr_layout);

    // Commit the PEB/TEB out to the live control structures (host seam).
    let st = host.commit_peb_teb(params.peb_va, params.teb_va);
    if st != STATUS_SUCCESS {
        return Err(st);
    }

    // (7) Run TLS callbacks + DLL_PROCESS_ATTACH as one rollback-capable transaction.
    attach_modules(state, &init_idx, Some(&params.root_module), host)?;

    // (8) Transfer to the root module's entry (host seam; no return on-target).
    let entry_va = root_entry_va(state, &params.root_module);
    let _ = host.transfer_to_entry(entry_va, params.peb_va);

    Ok(InitResult {
        normalized_flags,
        process_cookie,
        init_order,
        ldr: built,
        entry_va,
        loaded_apphelp: params.shim_policy.loads_apphelp(),
    })
}

/// Attach the not-yet-initialized modules in `init_idx`. On failure, detach exactly the modules this
/// transaction initialized, in reverse order, and restore their `initialized` flags.
pub fn attach_modules<H: LoaderHost>(
    state: &mut LoaderState,
    init_idx: &[usize],
    root_module: Option<&str>,
    host: &mut H,
) -> Result<Vec<usize>, NtStatus> {
    let normalized_root = root_module
        .filter(|root| !root.is_empty())
        .map(super::module::normalize_module_name);
    let mut attached = Vec::new();
    for &index in init_idx {
        if index >= state.modules.len() || state.modules[index].initialized {
            continue;
        }
        let module_name = super::module::normalize_module_name(&state.modules[index].name);
        if normalized_root.as_ref() == Some(&module_name) {
            continue;
        }
        let base = state.modules[index].base;
        let entry_rva = state.modules[index].entry_point_rva;
        let has_tls = state.modules[index].has_tls;
        let status = if has_tls {
            host.run_tls_callbacks(base, DllReason::ProcessAttach)
        } else {
            STATUS_SUCCESS
        };
        if status != STATUS_SUCCESS {
            rollback_attach(state, &attached, host);
            return Err(status);
        }
        if entry_rva != 0 {
            let status = host.call_dll_main(base, entry_rva, DllReason::ProcessAttach);
            if status != STATUS_SUCCESS {
                rollback_attach(state, &attached, host);
                return Err(STATUS_DLL_INIT_FAILED);
            }
        }
        state.modules[index].initialized = true;
        attached.push(index);
    }
    Ok(attached)
}

fn rollback_attach<H: LoaderHost>(state: &mut LoaderState, attached: &[usize], host: &mut H) {
    for &index in attached.iter().rev() {
        let module = &state.modules[index];
        if module.has_tls {
            let _ = host.run_tls_callbacks(module.base, DllReason::ProcessDetach);
        }
        if module.entry_point_rva != 0 {
            let _ = host.call_dll_main(
                module.base,
                module.entry_point_rva,
                DllReason::ProcessDetach,
            );
        }
        state.modules[index].initialized = false;
    }
}

/// The VA of the root module's entry (0 if no root / not found).
fn root_entry_va(state: &LoaderState, root: &str) -> u64 {
    if root.is_empty() {
        return 0;
    }
    state
        .find(root)
        .map(|m| {
            if m.entry_point_rva != 0 {
                m.base.wrapping_add(m.entry_point_rva as u64)
            } else {
                0
            }
        })
        .unwrap_or(0)
}

/// Map a [`resolve::ResolveError`] to the matching NT status (honest misses, never a spin).
fn map_resolve_error(e: resolve::ResolveError) -> NtStatus {
    match e {
        resolve::ResolveError::ModuleNotFound(_) => STATUS_DLL_NOT_FOUND,
        resolve::ResolveError::ExportNotFound { .. } => STATUS_ENTRYPOINT_NOT_FOUND,
        resolve::ResolveError::ForwarderCycle { .. } => STATUS_UNSUCCESSFUL,
    }
}
