//! Driver-agnostic, registration-driven import resolution — the SHARED ntoskrnl
//! export surface any hosted `.sys` binds its IAT against.
//!
//! This generalizes the [`Win32kExportRegistry`](crate::Win32kExportRegistry)
//! shape (a `name -> trampoline-VA` map) so it is no longer win32k-
//! specific. Every hosted driver component — win32k.sys, npfs.sys (and future
//! FSDs like fastfat), KMDF drivers — resolves its `ntoskrnl.exe`/`hal.dll`
//! imports through ONE registry: the executive binds each of its machine-code
//! trampoline VAs by import name at load time, and the PE loader resolves each
//! IAT slot via [`lookup`](DriverExportRegistry::lookup).
//!
//! The registry uses growable metadata. The executive reserves its bootstrap
//! catalog before taking the service-loop heap checkpoint, so later drivers are
//! not constrained by an unrelated compile-time name count.
//!
//! This is the convergence target from `project_driver_model.md`: "the import
//! trampolines are a SHARED ntoskrnl surface, not per-driver → converge onto the
//! SINGLE nt-compat-exports registry that load_driver binds ANY driver's IAT
//! against." The trampoline IMPLS stay executive-image code (they run in the
//! component's isolated VSpace as shared code); this is the shared RESOLUTION
//! mechanism.

use alloc::vec::Vec;

/// Bootstrap reservation for the shared NT/HAL export catalog. This is an
/// allocation optimization, not an admission limit; the registry grows beyond it.
pub const DRIVER_EXPORT_INITIAL_RESERVE: usize = 384;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriverExportRegistryStats {
    pub bindings: usize,
    pub capacity: usize,
    pub growths: u64,
    pub allocation_failures: u64,
}

struct DriverExportBinding {
    name: &'static str,
    va: u64,
}

/// A registration-driven resolver for a hosted driver's `ntoskrnl.exe` imports.
/// Driver-agnostic: the executive owns one per driver class (or shares one) in a
/// `static`, binds each `s_*` trampoline VA by import name at load time, and the
/// loader resolves each IAT slot via [`lookup`](Self::lookup).
pub struct DriverExportRegistry {
    bindings: Vec<DriverExportBinding>,
    growths: u64,
    allocation_failures: u64,
}

impl DriverExportRegistry {
    /// An empty registry (usable in a `const`/`static` initializer — no heap).
    pub const fn new() -> Self {
        Self {
            bindings: Vec::new(),
            growths: 0,
            allocation_failures: 0,
        }
    }

    /// Reserve the expected bootstrap catalog without imposing a maximum size.
    pub fn reserve_initial(&mut self, bindings: usize) -> bool {
        if self.bindings.try_reserve(bindings).is_err() {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            false
        } else {
            true
        }
    }

    /// Register (or re-bind) the trampoline VA for `name`. Returns `false` only
    /// when storage for a new binding cannot be allocated.
    pub fn bind(&mut self, name: &'static str, va: u64) -> bool {
        if let Some(binding) = self
            .bindings
            .iter_mut()
            .find(|binding| binding.name == name)
        {
            binding.va = va;
            return true;
        }

        let old_capacity = self.bindings.capacity();
        if self.bindings.try_reserve(1).is_err() {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            return false;
        }
        if self.bindings.capacity() != old_capacity {
            self.growths = self.growths.saturating_add(1);
        }
        self.bindings.push(DriverExportBinding { name, va });
        true
    }

    /// The bound trampoline VA for `name`, if the executive registered one.
    pub fn lookup(&self, name: &str) -> Option<u64> {
        self.bindings
            .iter()
            .find(|binding| binding.name == name)
            .map(|binding| binding.va)
    }

    /// Check catalog readiness separately from resolving an image's individual IAT entries.
    /// Report every genuinely absent or zero binding, even after an allocation failure. A failed
    /// catalog does not make its already-bound names unresolved.
    pub fn check_required<'a>(
        &self,
        names: impl IntoIterator<Item = &'a str>,
        mut report_missing: impl FnMut(&'a str),
    ) -> bool {
        let mut complete = self.allocation_failures == 0;
        for name in names {
            if self.lookup(name).is_none_or(|address| address == 0) {
                report_missing(name);
                complete = false;
            }
        }
        complete
    }

    /// True if `name` has a registered trampoline (vs a fail-soft default).
    pub fn is_bound(&self, name: &str) -> bool {
        self.lookup(name).is_some()
    }

    /// Number of distinct names bound.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// True if no trampolines are bound.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    pub fn stats(&self) -> DriverExportRegistryStats {
        DriverExportRegistryStats {
            bindings: self.bindings.len(),
            capacity: self.bindings.capacity(),
            growths: self.growths,
            allocation_failures: self.allocation_failures,
        }
    }
}

impl Default for DriverExportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn bind_then_lookup() {
        let mut reg = DriverExportRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.lookup("IoCreateDevice"), None);
        assert!(reg.bind("IoCreateDevice", 0xDEAD_BEEF));
        assert_eq!(reg.lookup("IoCreateDevice"), Some(0xDEAD_BEEF));
        assert!(reg.is_bound("IoCreateDevice"));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn rebind_updates_in_place() {
        let mut reg = DriverExportRegistry::new();
        assert!(reg.bind("ExAllocatePoolWithTag", 0x1000));
        assert!(reg.bind("ExAllocatePoolWithTag", 0x2000));
        assert_eq!(reg.lookup("ExAllocatePoolWithTag"), Some(0x2000));
        assert_eq!(reg.len(), 1, "rebinding a name must not grow the table");
    }

    #[test]
    fn unknown_name_is_unbound() {
        let mut reg = DriverExportRegistry::new();
        reg.bind("IoCreateDevice", 1);
        assert_eq!(reg.lookup("TotallyMadeUp"), None);
    }

    #[test]
    fn incomplete_catalog_does_not_report_bound_first_image_import() {
        let mut reg = DriverExportRegistry::new();
        assert!(reg.bind("MmMapViewInSystemSpace", 0x1000));
        assert!(reg.bind("ZwCreateSection", 0));
        let required = ["MmMapViewInSystemSpace", "ZwCreateSection", "ZwReadFile"];
        let mut missing = Vec::new();
        assert!(!reg.check_required(required, |name| missing.push(name)));
        assert_eq!(missing, ["ZwCreateSection", "ZwReadFile"]);
        assert_eq!(reg.lookup(required[0]), Some(0x1000));

        missing.clear();
        assert!(!reg.check_required(required, |name| missing.push(name)));
        assert_eq!(missing, ["ZwCreateSection", "ZwReadFile"]);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn complete_catalog_allows_real_lookup_and_preserves_unknown_import_failure() {
        let mut reg = DriverExportRegistry::new();
        let required = ["MmMapViewInSystemSpace", "ZwCreateSection"];
        for (index, name) in required.iter().enumerate() {
            assert!(reg.bind(name, 0x1000 + index as u64));
        }
        assert!(reg.check_required(required, |_| panic!("complete catalog reported a miss")));
        assert_eq!(reg.lookup(required[0]), Some(0x1000));
        assert_eq!(reg.lookup("NotARequiredOrBoundImport"), None);
    }

    #[test]
    fn allocation_failure_rejects_catalog_without_inventing_missing_names() {
        let mut reg = DriverExportRegistry::new();
        assert!(reg.bind("MmMapViewInSystemSpace", 0x1000));
        assert!(!reg.reserve_initial(usize::MAX));
        assert!(!reg.check_required(["MmMapViewInSystemSpace"], |_| {
            panic!("allocation failure misreported a bound import")
        }));
        let mut missing = Vec::new();
        assert!(
            !reg.check_required(["MmMapViewInSystemSpace", "ZwReadFile"], |name| {
                missing.push(name)
            })
        );
        assert_eq!(missing, ["ZwReadFile"]);
        assert_eq!(reg.stats().allocation_failures, 1);
    }

    #[test]
    fn grows_beyond_initial_reservation() {
        const NAMES: &[&str] = &[
            "export-00",
            "export-01",
            "export-02",
            "export-03",
            "export-04",
            "export-05",
            "export-06",
            "export-07",
            "export-08",
            "export-09",
            "export-10",
            "export-11",
            "export-12",
            "export-13",
            "export-14",
            "export-15",
        ];
        let mut reg = DriverExportRegistry::new();
        assert!(reg.reserve_initial(8));
        let initial_capacity = reg.stats().capacity;
        assert!(initial_capacity < NAMES.len());
        for (index, name) in NAMES.iter().take(initial_capacity + 1).enumerate() {
            assert!(reg.bind(name, index as u64 + 1));
        }
        let stats = reg.stats();
        assert_eq!(stats.bindings, initial_capacity + 1);
        assert!(stats.capacity > initial_capacity);
        assert_eq!(stats.growths, 1);
        assert_eq!(stats.allocation_failures, 0);
    }
}
