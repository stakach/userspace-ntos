//! Import snap (`LdrpSnapThunk`) + **forwarder resolution** — the marquee win.
//!
//! For each import `(DLL, name/ordinal)` we find the target module in the [`LoaderState`], resolve
//! its export → a concrete address, and record the resolution (the live path writes it into the IAT
//! slot — a [`super::host::LoaderHost`] seam). The interesting part is **forwarders**: an export
//! whose value is a string `"TARGETDLL.func"` (Windows' way of re-homing an export to another DLL,
//! e.g. the `ntdll` → `ntdll_vista` forwarders). We resolve those **recursively** — following
//! chains `A→B→C` — with cycle detection so a self-referential forwarder returns a real error
//! instead of spinning.
//!
//! A missing dependency (unknown DLL, or an unresolvable export) is a structured [`ResolveError`] —
//! the honest behavior the executive's demand-load retry-loop got wrong (it spun).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use nt_pe_loader::ImportRef;

use super::module::{Export, ExportTarget, ForwardSelector, LoaderState};

/// The maximum forwarder-chain depth before we declare a cycle (defensive — real chains are ≤ 2–3).
const MAX_FORWARDER_DEPTH: usize = 16;

/// A structured import-resolution failure (never a spin, never a fabricated address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The imported (or forwarded-to) module is not loaded.
    ModuleNotFound(String),
    /// The module is loaded but does not export the requested symbol.
    ExportNotFound {
        /// The module searched.
        module: String,
        /// The symbol name (or `"#<ordinal>"`).
        symbol: String,
    },
    /// A forwarder chain exceeded [`MAX_FORWARDER_DEPTH`] — a cycle or pathological chain.
    ForwarderCycle {
        /// The forwarder chain that looped (for diagnostics).
        chain: Vec<String>,
    },
}

/// A single resolved import: the IAT slot RVA (where the address goes) + the resolved target
/// address. The live path writes `address` into `module_base + iat_slot_rva`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedImport {
    /// The IAT slot RVA in the importing module.
    pub iat_slot_rva: u32,
    /// The resolved target address.
    pub address: u64,
    /// The DLL the symbol was imported from (as written in the import descriptor).
    pub from_dll: String,
    /// The symbol (name or `"#<ordinal>"`), for diagnostics.
    pub symbol: String,
}

/// Resolve one export selector (by name or ordinal) in `module_name`, following forwarders to a
/// concrete address. `chain` accumulates the `"dll.func"` hops for cycle detection + diagnostics.
fn resolve_in_module(
    state: &LoaderState,
    module_name: &str,
    selector: &Selector,
    chain: &mut Vec<String>,
) -> Result<u64, ResolveError> {
    if chain.len() > MAX_FORWARDER_DEPTH {
        return Err(ResolveError::ForwarderCycle {
            chain: chain.clone(),
        });
    }
    let module = state
        .find(module_name)
        .ok_or_else(|| ResolveError::ModuleNotFound(module_name.to_string()))?;

    let export: &Export = match selector {
        Selector::Name(n) => module.find_export(n),
        Selector::Ordinal(o) => module.find_export_by_ordinal(*o),
    }
    .ok_or_else(|| ResolveError::ExportNotFound {
        module: module_name.to_string(),
        symbol: selector.display(),
    })?;

    match &export.target {
        ExportTarget::Address(addr) => Ok(*addr),
        ExportTarget::Forwarder { dll, func } => {
            // Record the hop; detect a repeat (cycle) explicitly, and bound the depth.
            let hop = forwarder_key(dll, func);
            if chain.contains(&hop) {
                chain.push(hop);
                return Err(ResolveError::ForwarderCycle {
                    chain: chain.clone(),
                });
            }
            chain.push(hop);
            let next = match func {
                ForwardSelector::Name(n) => Selector::Name(n.clone()),
                ForwardSelector::Ordinal(o) => Selector::Ordinal(*o),
            };
            resolve_in_module(state, dll, &next, chain)
        }
    }
}

/// A canonical `"dll!selector"` key for cycle detection.
fn forwarder_key(dll: &str, func: &ForwardSelector) -> String {
    let mut s = super::module::normalize_module_name(dll);
    s.push('!');
    match func {
        ForwardSelector::Name(n) => s.push_str(n),
        ForwardSelector::Ordinal(o) => {
            s.push('#');
            s.push_str(&o.to_string());
        }
    }
    s
}

/// An export selector (the query form — name or ordinal).
enum Selector {
    Name(String),
    Ordinal(u16),
}

impl Selector {
    fn display(&self) -> String {
        match self {
            Selector::Name(n) => n.clone(),
            Selector::Ordinal(o) => {
                let mut s = String::from("#");
                s.push_str(&o.to_string());
                s
            }
        }
    }
}

/// Resolve a single `(dll, name/ordinal)` import to a concrete address (following forwarders).
/// Public so callers can resolve an individual symbol (e.g. `GetProcAddress`-style).
pub fn resolve_symbol(
    state: &LoaderState,
    dll: &str,
    selector_name: Option<&str>,
    selector_ordinal: Option<u16>,
) -> Result<u64, ResolveError> {
    let selector = match (selector_name, selector_ordinal) {
        (Some(n), _) => Selector::Name(n.to_string()),
        (None, Some(o)) => Selector::Ordinal(o),
        (None, None) => {
            return Err(ResolveError::ExportNotFound {
                module: dll.to_string(),
                symbol: String::new(),
            })
        }
    };
    let mut chain = Vec::new();
    resolve_in_module(state, dll, &selector, &mut chain)
}

/// **Snap all imports** of the module named `importer` against the loaded set. Returns one
/// [`ResolvedImport`] per imported function (the live path writes each into its IAT slot). The first
/// unresolvable import is returned as a [`ResolveError`] — never spun on, never faked.
pub fn snap_module(
    state: &LoaderState,
    importer: &str,
) -> Result<Vec<ResolvedImport>, ResolveError> {
    let module = state
        .find(importer)
        .ok_or_else(|| ResolveError::ModuleNotFound(importer.to_string()))?;

    let mut out = Vec::new();
    for dll in &module.imports {
        for func in &dll.functions {
            let (name, ordinal): (Option<&str>, Option<u16>) = match func {
                ImportRef::ByName { name, .. } => (Some(name.as_str()), None),
                ImportRef::ByOrdinal { ordinal, .. } => (None, Some(*ordinal)),
            };
            let address = resolve_symbol(state, &dll.name, name, ordinal)?;
            out.push(ResolvedImport {
                iat_slot_rva: func.iat_slot_rva(),
                address,
                from_dll: dll.name.clone(),
                symbol: super::module::import_ref_name(func),
            });
        }
    }
    Ok(out)
}

/// Snap **every** module in the set (the full-graph import resolution the loader performs). Returns
/// the resolutions grouped by importing module (`(module_name, resolutions)`), or the first error.
pub fn snap_all(state: &LoaderState) -> Result<Vec<(String, Vec<ResolvedImport>)>, ResolveError> {
    let mut out = Vec::new();
    for m in &state.modules {
        let resolved = snap_module(state, &m.name)?;
        out.push((m.name.clone(), resolved));
    }
    Ok(out)
}
