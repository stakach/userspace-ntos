//! Registration-driven resolution for `win32k.sys`'s `ntoskrnl.exe` imports
//! (Workstream B: converge the executive's hardcoded `export_addr` match onto
//! the declared descriptor contract).
//!
//! The [`win32k`](crate::win32k) module declares *which* imports win32k names and
//! their [`ExportStatus`]. This module adds the missing half: a **heap-free,
//! registration-driven** map from import name → the executive's machine-code
//! trampoline VA. The executive binds each `s_*` trampoline by name via
//! [`Win32kExportRegistry::bind`] at win32k load time; the loader then resolves
//! win32k's IAT slots through [`Win32kExportRegistry::lookup`] instead of a
//! buried `match`.
//!
//! Heap-free by design: the executive's bump heap is exhausted by the time
//! win32k loads (after smss/csrss), so the registry is a fixed-capacity array
//! that lives in a `static` — no `alloc`, unlike the Vec-backed
//! [`ExportRegistry`](crate::ExportRegistry) used by the host-side driver-import
//! tooling.

use crate::{hal, ntoskrnl, win32k, ExportDescriptor};

/// Look up an export's static compatibility descriptor across the whole declared
/// contract (`ntoskrnl.exe` MVP + win32k's extra ntoskrnl surface + `hal.dll`).
/// Scans the `const` slices — no allocation. Symbol names are case-sensitive.
pub fn export_descriptor(name: &str) -> Option<&'static ExportDescriptor> {
    ntoskrnl::NTOSKRNL
        .iter()
        .chain(win32k::WIN32K_NTOSKRNL.iter())
        .chain(hal::HAL.iter())
        .find(|d| d.name == name)
}

/// Capacity of the fixed trampoline-binding array. Comfortably above the number
/// of distinct trampolines the executive registers (~41 today, aliases share a
/// VA); [`Win32kExportRegistry::bind`] returns `false` once exhausted.
pub const WIN32K_TRAMPOLINE_CAP: usize = 128;

/// A heap-free, registration-driven resolver for win32k's `ntoskrnl.exe` imports.
///
/// The executive owns one of these in a `static` and, at win32k load time, binds
/// each of its `s_*` machine-code trampoline VAs by import name. The win32k
/// loader resolves each IAT slot via [`lookup`](Self::lookup); unbound names fall
/// back to the executive's existing resolution (a benign zero stub or a data
/// cell) during migration.
pub struct Win32kExportRegistry {
    names: [&'static str; WIN32K_TRAMPOLINE_CAP],
    vas: [u64; WIN32K_TRAMPOLINE_CAP],
    len: usize,
}

impl Win32kExportRegistry {
    /// An empty registry (usable in a `const`/`static` initializer — no heap).
    pub const fn new() -> Self {
        Self {
            names: [""; WIN32K_TRAMPOLINE_CAP],
            vas: [0; WIN32K_TRAMPOLINE_CAP],
            len: 0,
        }
    }

    /// Register (or re-bind) the trampoline VA for `name`. Returns `false` only
    /// if the fixed capacity is exhausted while adding a new name.
    pub fn bind(&mut self, name: &'static str, va: u64) -> bool {
        for i in 0..self.len {
            if self.names[i] == name {
                self.vas[i] = va;
                return true;
            }
        }
        if self.len >= WIN32K_TRAMPOLINE_CAP {
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

    /// True if `name` has a registered trampoline.
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

impl Default for Win32kExportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::ExportStatus;

    /// The first batch migrated onto the registry (pool + RTL-atom + Ob groups).
    /// Every one must be a *declared* export backed by a real `nt-*` subsystem
    /// (never a load-blocking/trap import) — this is the contract the executive's
    /// `register_trampolines` binds by name.
    const FIRST_BATCH: &[&str] = &[
        // pool (Driver Host arena)
        "ExAllocatePoolWithTag",
        "ExAllocatePool",
        "ExAllocatePoolWithQuotaTag",
        "ExFreePoolWithTag",
        "ExFreePool",
        // RTL atom table (nt-kernel-exec::rtl_atom)
        "RtlCreateAtomTable",
        "RtlAddAtomToAtomTable",
        "RtlLookupAtomInAtomTable",
        "RtlDeleteAtomFromAtomTable",
        "RtlPinAtomInAtomTable",
        "RtlQueryAtomInAtomTable",
        "RtlDestroyAtomTable",
        // Ob object layer (nt-object-manager)
        "ObReferenceObjectByHandle",
        "ObOpenObjectByName",
        "ObCreateObject",
        "ObInsertObject",
    ];

    #[test]
    fn bind_then_lookup() {
        let mut reg = Win32kExportRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.lookup("ObCreateObject"), None);
        assert!(reg.bind("ObCreateObject", 0xDEAD_BEEF));
        assert_eq!(reg.lookup("ObCreateObject"), Some(0xDEAD_BEEF));
        assert!(reg.is_bound("ObCreateObject"));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn rebind_updates_in_place() {
        let mut reg = Win32kExportRegistry::new();
        assert!(reg.bind("ExAllocatePoolWithTag", 0x1000));
        assert!(reg.bind("ExAllocatePoolWithTag", 0x2000));
        assert_eq!(reg.lookup("ExAllocatePoolWithTag"), Some(0x2000));
        assert_eq!(reg.len(), 1, "rebinding a name must not grow the table");
    }

    #[test]
    fn unknown_name_is_unbound() {
        let mut reg = Win32kExportRegistry::new();
        reg.bind("ObCreateObject", 1);
        assert_eq!(reg.lookup("TotallyMadeUp"), None);
    }

    #[test]
    fn capacity_boundary() {
        // The executive binds ~41 distinct trampolines (aliases share a VA), well
        // under the cap. Exercise the boundary directly: fill to capacity from the
        // declared import surface, then confirm the next *new* name is rejected
        // while a re-bind of an existing name still succeeds.
        assert!(
            crate::WIN32K_NTOSKRNL_IMPORTS.len() > WIN32K_TRAMPOLINE_CAP,
            "need more distinct names than the cap to test the boundary"
        );
        let mut reg = Win32kExportRegistry::new();
        for (i, name) in crate::WIN32K_NTOSKRNL_IMPORTS
            .iter()
            .take(WIN32K_TRAMPOLINE_CAP)
            .enumerate()
        {
            assert!(reg.bind(name, i as u64 + 1));
        }
        assert_eq!(reg.len(), WIN32K_TRAMPOLINE_CAP);
        // A new name past capacity is rejected.
        let overflow = crate::WIN32K_NTOSKRNL_IMPORTS[WIN32K_TRAMPOLINE_CAP];
        assert!(!reg.bind(overflow, 0xFFFF));
        // But re-binding an already-present name still works (no growth needed).
        let existing = crate::WIN32K_NTOSKRNL_IMPORTS[0];
        assert!(reg.bind(existing, 0x1234));
        assert_eq!(reg.lookup(existing), Some(0x1234));
    }

    #[test]
    fn descriptor_lookup_spans_all_tables() {
        // ntoskrnl MVP table.
        assert_eq!(
            export_descriptor("ExAllocatePoolWithTag").map(|d| d.status),
            Some(ExportStatus::Implemented)
        );
        // win32k extra ntoskrnl surface.
        assert_eq!(
            export_descriptor("ObReferenceObjectByHandle").map(|d| d.status),
            Some(ExportStatus::Partial)
        );
        // hal.dll.
        assert!(export_descriptor("KeQueryPerformanceCounter").is_some());
        // unknown.
        assert!(export_descriptor("NopeNotReal").is_none());
    }

    #[test]
    fn first_batch_is_declared_and_real() {
        for name in FIRST_BATCH {
            let d = export_descriptor(name)
                .unwrap_or_else(|| panic!("first-batch import {name} is not declared"));
            // Real subsystem-backed: never a load-blocking or fail-loud import.
            assert!(
                matches!(
                    d.status,
                    ExportStatus::Implemented | ExportStatus::Partial
                ),
                "first-batch import {name} is {:?}, expected Implemented/Partial",
                d.status
            );
        }
    }

    #[test]
    fn first_batch_round_trips_through_registry() {
        let mut reg = Win32kExportRegistry::new();
        for (i, name) in FIRST_BATCH.iter().enumerate() {
            let va = 0x4000_0000 + i as u64 * 0x10;
            assert!(reg.bind(name, va));
            assert_eq!(reg.lookup(name), Some(va));
        }
        // Names outside the batch remain unbound (hybrid: they still resolve via
        // the executive's match during migration).
        assert_eq!(reg.lookup("KeAddSystemServiceTable"), None);
    }
}
