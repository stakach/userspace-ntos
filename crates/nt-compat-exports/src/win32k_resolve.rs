//! win32k-specific declared import CONTRACT: the descriptor lookup + the data-
//! export list win32k.sys dereferences at init.
//!
//! The RESOLUTION MECHANISM (name → trampoline VA) is the SHARED, driver-agnostic
//! [`DriverExportRegistry`](crate::DriverExportRegistry) — win32k binds its
//! trampolines into the very same registry type every hosted `.sys` uses (the
//! parallel `Win32kExportRegistry` was retired; [`Win32kExportRegistry`] is now a
//! thin alias). What stays win32k-specific here is only the *contract*: which
//! names win32k imports ([`export_descriptor`]) and which are the data-cell
//! exports it reads ([`WIN32K_DATA_EXPORTS`]).

use crate::{hal, ntoskrnl, win32k, DriverExportRegistry, ExportDescriptor, DRIVER_TRAMPOLINE_CAP};

/// Retained name for the shared [`DriverExportRegistry`] — win32k resolves its
/// `ntoskrnl.exe` imports through the SAME driver-agnostic registry mechanism as
/// every other hosted driver (FSD/KMDF). The parallel win32k-only registry struct
/// was retired; this alias keeps the win32k call sites readable.
pub type Win32kExportRegistry = DriverExportRegistry;

/// Retained alias for the shared trampoline-array capacity ([`DRIVER_TRAMPOLINE_CAP`]).
pub const WIN32K_TRAMPOLINE_CAP: usize = DRIVER_TRAMPOLINE_CAP;

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

/// The 11 `ntoskrnl.exe` **data exports** win32k dereferences at init, in cell-index order.
/// Each resolves to a data *cell* (not a code trampoline): the IAT slot points at the cell, which
/// holds the value (an object-type/Se/Nls placeholder pointer, or an architectural Mm boundary
/// constant). The executive folds these into the [`Win32kExportRegistry`] by binding each name to
/// its cell address; this list is the declared, host-tested contract of *which* names are data
/// exports and their order. The six object-type cells (`Ps*Type`, `Ex*ObjectType`,
/// `LpcPortObjectType`) now resolve to **real** `nt_object_manager::object_type` `OBJECT_TYPE`
/// statics (implement-for-real backlog item 1, done). `SeExports` (a security-export struct, the
/// Se->nt-security backlog item) and `NlsMbCodePageTag` (genuine Nls code-page data) remain
/// placeholder cells and are NOT object types.
pub const WIN32K_DATA_EXPORTS: &[&str] = &[
    "PsProcessType",
    "PsThreadType",
    "ExDesktopObjectType",
    "ExWindowStationObjectType",
    "ExEventObjectType",
    "LpcPortObjectType",
    "SeExports",
    "NlsMbCodePageTag",
    "MmSystemRangeStart",
    "MmUserProbeAddress",
    "MmHighestUserAddress",
];

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
    fn data_exports_are_declared_data_exports() {
        assert_eq!(WIN32K_DATA_EXPORTS.len(), 11);
        for name in WIN32K_DATA_EXPORTS {
            let d = export_descriptor(name)
                .unwrap_or_else(|| panic!("data export {name} is not declared"));
            assert!(
                d.notes.contains("data export"),
                "data export {name} descriptor notes do not mark it as a data export: {:?}",
                d.notes
            );
        }
        // No duplicates (cell indices must be unique).
        let mut seen = std::collections::BTreeSet::new();
        for n in WIN32K_DATA_EXPORTS {
            assert!(seen.insert(*n), "duplicate data export {n}");
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
