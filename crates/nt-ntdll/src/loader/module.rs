//! The loader's module model + the module set (`LoaderState`).
//!
//! A [`LoadedModule`] is the loader's view of one DLL: its base VA, its parsed export table (name →
//! RVA, with forwarder strings detected), and its parsed import table (which modules + names it
//! needs). This is the graph node the import-snap ([`super::resolve`]), the init-ordering
//! ([`super::order`]), and the `PEB->Ldr` build ([`super::peb`]) all operate over.
//!
//! Modules are keyed by a **case-insensitive** base name (`"ntdll.dll"`), matching the real Ldr's
//! `LdrpFindLoadedDllByName` (Windows DLL names are case-insensitive). A `.dll` suffix is implied
//! when an import descriptor omits it (Windows appends `.dll` to a bare import name).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use nt_pe_loader::{ExportedSymbol, ImportRef, ImportedDll, PeError, PeFile};

/// A resolved export target: either a concrete address in a module, or a **forwarder** to another
/// module's export (the string form `"TARGETDLL.funcname"` / `"TARGETDLL.#ordinal"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportTarget {
    /// A concrete function address (`module_base + export_rva`).
    Address(u64),
    /// A forwarder: resolve `func` (a name, or `Ordinal(n)`) in `dll` (a bare module name, e.g.
    /// `"NTDLL"` — the loader appends `.dll`). The marquee case (`_vista` forwarders).
    Forwarder {
        /// The target DLL name as written in the forwarder string (no `.dll` suffix).
        dll: String,
        /// The target export selector.
        func: ForwardSelector,
    },
}

/// How a forwarder names its target export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardSelector {
    /// By name (`"foo.dll.Bar"` → `Name("Bar")`).
    Name(String),
    /// By ordinal (`"foo.dll.#3"` → `Ordinal(3)`).
    Ordinal(u16),
}

/// One export entry: its name/ordinal and its resolved [`ExportTarget`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    /// The export name.
    pub name: String,
    /// The export ordinal.
    pub ordinal: u16,
    /// Where the export points (a concrete address, or a forwarder).
    pub target: ExportTarget,
}

/// The loader's view of one loaded (or being-loaded) module.
#[derive(Clone, Debug)]
pub struct LoadedModule {
    /// Case-preserved base name (e.g. `"ntdll.dll"`).
    pub name: String,
    /// The base VA the image is (or will be) mapped at.
    pub base: u64,
    /// The image's `SizeOfImage`.
    pub size_of_image: u32,
    /// The image's entry-point RVA (`DllMain` / the exe entry).
    pub entry_point_rva: u32,
    /// The named exports, with forwarders detected.
    pub exports: Vec<Export>,
    /// The imported DLLs + functions (the dependency edges).
    pub imports: Vec<ImportedDll>,
    /// True once this module's `DLL_PROCESS_ATTACH` has run (init-order bookkeeping).
    pub initialized: bool,
    /// True if the module has a TLS directory (its callbacks run before/around ATTACH). The loader
    /// records this; the live callback invocation is a [`super::host::LoaderHost`] seam.
    pub has_tls: bool,
}

impl LoadedModule {
    /// Build a [`LoadedModule`] from a parsed PE image at `base` (RVAs resolved against `base`; the
    /// export directory range is used to detect forwarders). `name` is the module's base name.
    pub fn from_pe(name: &str, pe: &PeFile<'_>, base: u64) -> Result<Self, PeError> {
        let export_dir = pe
            .headers()
            .data_directory(nt_pe_loader::DIRECTORY_ENTRY_EXPORT);
        let (edir_start, edir_end) = (
            export_dir.virtual_address,
            export_dir.virtual_address.saturating_add(export_dir.size),
        );
        let raw = pe.exports()?;
        let exports = raw
            .into_iter()
            .map(|e| resolve_export_entry(pe, base, edir_start, edir_end, e))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LoadedModule {
            name: name.to_string(),
            base,
            size_of_image: pe.size_of_image(),
            entry_point_rva: pe.entry_point_rva(),
            exports,
            imports: pe.imports()?,
            initialized: false,
            has_tls: pe.has_tls_directory(),
        })
    }

    /// A synthetic module for host tests: given `(name, ordinal, target)` exports + import edges,
    /// build a [`LoadedModule`] without a real PE image. This is how the forwarder / ordering tests
    /// construct mock graphs.
    pub fn mock(name: &str, base: u64, exports: Vec<Export>, imports: Vec<ImportedDll>) -> Self {
        LoadedModule {
            name: name.to_string(),
            base,
            size_of_image: 0x1000,
            entry_point_rva: 0,
            exports,
            imports,
            initialized: false,
            has_tls: false,
        }
    }

    /// Look up an export by name (case-sensitive — export names are case-sensitive in the PE
    /// export table, unlike module names).
    pub fn find_export(&self, name: &str) -> Option<&Export> {
        self.exports.iter().find(|e| e.name == name)
    }

    /// Look up an export by ordinal.
    pub fn find_export_by_ordinal(&self, ordinal: u16) -> Option<&Export> {
        self.exports.iter().find(|e| e.ordinal == ordinal)
    }
}

/// Resolve a raw [`ExportedSymbol`] into an [`Export`], detecting the forwarder case (RVA inside the
/// export-directory range → the export "address" is actually a `"DLL.func"` string).
fn resolve_export_entry(
    pe: &PeFile<'_>,
    base: u64,
    edir_start: u32,
    edir_end: u32,
    sym: ExportedSymbol,
) -> Result<Export, PeError> {
    let is_forwarder = sym.rva >= edir_start && sym.rva < edir_end && edir_end != 0;
    let target = if is_forwarder {
        // The export value is a NUL-terminated ASCII forwarder string at this RVA.
        let s = pe.cstr_at_rva(sym.rva)?;
        parse_forwarder(&s)
    } else {
        ExportTarget::Address(base.wrapping_add(sym.rva as u64))
    };
    Ok(Export {
        name: sym.name,
        ordinal: sym.ordinal,
        target,
    })
}

/// Parse a forwarder string `"TARGETDLL.funcname"` or `"TARGETDLL.#ordinal"` into an
/// [`ExportTarget::Forwarder`]. The DLL part is everything up to the *last* `.` (a DLL name can
/// itself contain dots, e.g. `"api-ms-win-core-.."`), the func part is the remainder. A leading `#`
/// on the func selects by ordinal.
pub fn parse_forwarder(s: &str) -> ExportTarget {
    // Split on the LAST '.' — the export name never contains a '.', but api-set DLL names do.
    match s.rfind('.') {
        Some(dot) => {
            let dll = s[..dot].to_string();
            let func = &s[dot + 1..];
            let sel = if let Some(ord) = func.strip_prefix('#') {
                match ord.parse::<u16>() {
                    Ok(n) => ForwardSelector::Ordinal(n),
                    Err(_) => ForwardSelector::Name(func.to_string()),
                }
            } else {
                ForwardSelector::Name(func.to_string())
            };
            ExportTarget::Forwarder { dll, func: sel }
        }
        // Malformed (no dot): treat the whole thing as a name forward into an empty DLL — this can't
        // resolve and surfaces as a missing dependency (never a fake address).
        None => ExportTarget::Forwarder {
            dll: String::new(),
            func: ForwardSelector::Name(s.to_string()),
        },
    }
}

/// The set of loaded modules — the loader's working graph. Keyed by case-insensitive base name.
#[derive(Clone, Debug, Default)]
pub struct LoaderState {
    /// The loaded modules, in load order (the order they were added — `InLoadOrderModuleList`).
    pub modules: Vec<LoadedModule>,
}

impl LoaderState {
    /// A fresh, empty loader state.
    pub fn new() -> Self {
        LoaderState {
            modules: Vec::new(),
        }
    }

    /// Add a module (in load order). Duplicate base names are rejected (the caller must check
    /// [`Self::find`] first — this mirrors the real Ldr's already-loaded check).
    pub fn add(&mut self, module: LoadedModule) {
        self.modules.push(module);
    }

    /// Find a loaded module by base name, **case-insensitively**, tolerating a missing `.dll`
    /// suffix on either side (Windows appends `.dll` to a bare import/forwarder name).
    pub fn find(&self, name: &str) -> Option<&LoadedModule> {
        let idx = self.index_of(name)?;
        Some(&self.modules[idx])
    }

    /// Mutable [`Self::find`].
    pub fn find_mut(&mut self, name: &str) -> Option<&mut LoadedModule> {
        let idx = self.index_of(name)?;
        Some(&mut self.modules[idx])
    }

    /// The index of a module by (normalized) name.
    pub fn index_of(&self, name: &str) -> Option<usize> {
        let want = normalize_module_name(name);
        self.modules
            .iter()
            .position(|m| normalize_module_name(&m.name) == want)
    }

    /// True if a module with this (normalized) name is loaded.
    pub fn contains(&self, name: &str) -> bool {
        self.index_of(name).is_some()
    }
}

/// Normalize a module name for case-insensitive matching: lowercase, and append `.dll` if there is
/// no extension (a bare `"NTDLL"` import/forwarder → `"ntdll.dll"`).
pub fn normalize_module_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.contains('.') {
        lower
    } else {
        let mut s = lower;
        s.push_str(".dll");
        s
    }
}

/// The name of the DLL an [`ImportRef`] refers to is on the [`ImportedDll`]; this helper extracts a
/// display name for an import ref (for missing-dependency reporting).
pub fn import_ref_name(r: &ImportRef) -> String {
    match r {
        ImportRef::ByName { name, .. } => name.clone(),
        ImportRef::ByOrdinal { ordinal, .. } => {
            let mut s = String::from("#");
            s.push_str(&ordinal.to_string());
            s
        }
    }
}
