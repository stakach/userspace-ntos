//! Driver-agnostic, registration-driven import resolution — the SHARED ntoskrnl
//! export surface any hosted `.sys` binds its IAT against.
//!
//! This generalizes the [`Win32kExportRegistry`](crate::Win32kExportRegistry)
//! shape (a heap-free `name -> trampoline-VA` map) so it is no longer win32k-
//! specific. Every hosted driver component — win32k.sys, npfs.sys (and future
//! FSDs like fastfat), KMDF drivers — resolves its `ntoskrnl.exe`/`hal.dll`
//! imports through ONE registry: the executive binds each of its machine-code
//! trampoline VAs by import name at load time, and the PE loader resolves each
//! IAT slot via [`lookup`](DriverExportRegistry::lookup).
//!
//! Heap-free by design: the executive's bump heap is exhausted by the time
//! drivers load (after smss/csrss), so the registry is a fixed-capacity array
//! that lives in a `static` — no `alloc`, unlike the Vec-backed
//! [`ExportRegistry`](crate::ExportRegistry) used by the host-side import tooling.
//!
//! This is the convergence target from `project_driver_model.md`: "the import
//! trampolines are a SHARED ntoskrnl surface, not per-driver → converge onto the
//! SINGLE nt-compat-exports registry that load_driver binds ANY driver's IAT
//! against." The trampoline IMPLS stay executive-image code (they run in the
//! component's isolated VSpace as shared code); this is the shared RESOLUTION
//! mechanism.

/// Capacity of the fixed name->VA binding array. Sized for the largest hosted
/// driver class: win32k.sys (the Subsystem class) registers ~110 distinct
/// trampolines + data cells; FSD drivers (npfs) register ~35. A generous cap
/// covers fastfat/ntfs + aliases too.
pub const DRIVER_TRAMPOLINE_CAP: usize = 160;

/// A heap-free, registration-driven resolver for a hosted driver's `ntoskrnl.exe`
/// imports. Driver-agnostic: the executive owns one per driver class (or shares
/// one) in a `static`, binds each `s_*` trampoline VA by import name at load time,
/// and the loader resolves each IAT slot via [`lookup`](Self::lookup).
pub struct DriverExportRegistry {
    names: [&'static str; DRIVER_TRAMPOLINE_CAP],
    vas: [u64; DRIVER_TRAMPOLINE_CAP],
    len: usize,
}

impl DriverExportRegistry {
    /// An empty registry (usable in a `const`/`static` initializer — no heap).
    pub const fn new() -> Self {
        Self {
            names: [""; DRIVER_TRAMPOLINE_CAP],
            vas: [0; DRIVER_TRAMPOLINE_CAP],
            len: 0,
        }
    }

    /// Register (or re-bind) the trampoline VA for `name`. Returns `false` only if
    /// the fixed capacity is exhausted while adding a new name.
    pub fn bind(&mut self, name: &'static str, va: u64) -> bool {
        for i in 0..self.len {
            if self.names[i] == name {
                self.vas[i] = va;
                return true;
            }
        }
        if self.len >= DRIVER_TRAMPOLINE_CAP {
            return false;
        }
        self.names[self.len] = name;
        self.vas[self.len] = va;
        self.len += 1;
        true
    }

    /// The bound trampoline VA for `name`, if the executive registered one.
    pub fn lookup(&self, name: &str) -> Option<u64> {
        for i in 0..self.len {
            if self.names[i] == name {
                return Some(self.vas[i]);
            }
        }
        None
    }

    /// True if `name` has a registered trampoline (vs a fail-soft default).
    pub fn is_bound(&self, name: &str) -> bool {
        self.lookup(name).is_some()
    }

    /// Number of distinct names bound.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if no trampolines are bound.
    pub fn is_empty(&self) -> bool {
        self.len == 0
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
    use std::boxed::Box;
    use std::vec::Vec;

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
    fn capacity_boundary() {
        // DRIVER_TRAMPOLINE_CAP distinct &'static names (leaked for the 'static bound).
        let names: Vec<&'static str> = (0..DRIVER_TRAMPOLINE_CAP)
            .map(|i| &*Box::leak(std::format!("a{i}").into_boxed_str()))
            .collect();
        let mut reg = DriverExportRegistry::new();
        for (i, name) in names.iter().enumerate() {
            assert!(reg.bind(name, i as u64 + 1));
        }
        assert_eq!(reg.len(), DRIVER_TRAMPOLINE_CAP);
        // A brand-new name past capacity is rejected.
        assert!(!reg.bind("overflow_name", 0xFFFF));
        // But re-binding an already-present name still works.
        assert!(reg.bind(names[0], 0x1234));
        assert_eq!(reg.lookup(names[0]), Some(0x1234));
    }
}
