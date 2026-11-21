//! Dependency ordering for `DLL_PROCESS_ATTACH` — the `InInitializationOrderModuleList` order.
//!
//! The real Ldr rule: a module's `DLL_PROCESS_ATTACH` runs **after** all the modules it depends on
//! (its imports) have been initialized — dependencies before dependents. We compute this with a
//! **post-order depth-first traversal** of the import graph: visiting a node emits it only after
//! recursing into its dependencies, so dependencies land earlier in the output.
//!
//! Real graphs contain **cycles** (e.g. `kernel32` ↔ `kernelbase`, or `ntdll` self-edges via
//! forwarders). A naive DFS would recurse forever; we track an on-stack "visiting" set and simply
//! **break** the back-edge (the standard cycle-tolerant post-order), so a cyclic dependency still
//! produces a total order — matching how the real Ldr handles circular DLL dependencies (it
//! initializes in load order within a cycle). The *entry* module (the process EXE) is initialized
//! last, so it is visited first / seeded as the traversal root.

use alloc::vec::Vec;

use super::module::{normalize_module_name, LoaderState};

/// Compute the `DLL_PROCESS_ATTACH` initialization order: a list of module indices (into
/// `state.modules`) with **dependencies before dependents**. Cycles are broken at the back-edge, so
/// the result is always a total order over the loaded set.
///
/// `roots` are the module names to seed the traversal from (typically the process EXE + any
/// explicitly-loaded modules); if empty, every module is used as a root (in load order), which still
/// yields a correct dependency order for the whole set.
pub fn initialization_order(state: &LoaderState, roots: &[&str]) -> Vec<usize> {
    let n = state.modules.len();
    let mut order = Vec::with_capacity(n);
    let mut visited = alloc::vec![false; n];
    let mut on_stack = alloc::vec![false; n];

    // Seed roots (explicit, else all-in-load-order).
    if roots.is_empty() {
        for i in 0..n {
            visit(state, i, &mut visited, &mut on_stack, &mut order);
        }
    } else {
        for r in roots {
            if let Some(i) = state.index_of(r) {
                visit(state, i, &mut visited, &mut on_stack, &mut order);
            }
        }
        // Any module unreachable from the roots still needs to be ordered (defensive).
        for i in 0..n {
            visit(state, i, &mut visited, &mut on_stack, &mut order);
        }
    }
    order
}

/// Post-order DFS visit: recurse into `module i`'s dependencies first, then emit `i`. Back-edges
/// (a dependency currently on the recursion stack — a cycle) are skipped.
fn visit(
    state: &LoaderState,
    i: usize,
    visited: &mut [bool],
    on_stack: &mut [bool],
    order: &mut Vec<usize>,
) {
    if visited[i] {
        return;
    }
    visited[i] = true;
    on_stack[i] = true;

    // Recurse into each imported (dependency) module that is loaded.
    for dll in &state.modules[i].imports {
        if let Some(dep) = state.index_of(&dll.name) {
            if dep == i {
                continue; // self-import (forwarder self-edge) — skip
            }
            if on_stack[dep] {
                continue; // back-edge: a cycle — break it (init in load order within the cycle)
            }
            if !visited[dep] {
                visit(state, dep, visited, on_stack, order);
            }
        }
    }

    on_stack[i] = false;
    order.push(i); // emit AFTER dependencies → dependencies-before-dependents
}

/// The module a Win32 GUI or console process loads before its EXE's imports, as its base name.
///
/// ReactOS `LdrpInitializeProcess` (ldrinit.c) calls `LdrLoadDll(kernel32.dll)` for an
/// `IMAGE_SUBSYSTEM_WINDOWS_GUI` or `_CUI` image before `LdrpWalkImportDescriptor` walks the EXE.
/// kernel32 and its dependency closure therefore finish loading, and enter
/// `InInitializationOrderModuleList`, first. Seeding the attach traversal from it gives the same
/// order inside the LiberNT kernel32 <-> kernelbase cycle: kernelbase initializes before kernel32,
/// whose DllMain calls `kernelbase!ConDllInitialize`.
pub fn win32_preloaded_module(subsystem: Option<u16>) -> Option<&'static str> {
    const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
    const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
    matches!(subsystem, Some(IMAGE_SUBSYSTEM_WINDOWS_GUI | IMAGE_SUBSYSTEM_WINDOWS_CUI))
        .then_some("kernel32")
}

/// Convenience: the init order as module **names** (for tests / diagnostics / `PEB->Ldr` build).
pub fn initialization_order_names(
    state: &LoaderState,
    roots: &[&str],
) -> Vec<alloc::string::String> {
    initialization_order(state, roots)
        .into_iter()
        .map(|i| state.modules[i].name.clone())
        .collect()
}

/// True if `dep` is a (direct) dependency of `importer` (a loaded imported module), by normalized
/// name — a small helper the ordering + diagnostics share.
pub fn depends_on(state: &LoaderState, importer: usize, dep_name: &str) -> bool {
    let want = normalize_module_name(dep_name);
    state.modules[importer]
        .imports
        .iter()
        .any(|d| normalize_module_name(&d.name) == want)
}
