//! The export registry: lookup, resolution, trampoline binding, and import
//! checking (spec §7.3, §15).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{hal, ntoskrnl, win32k, ExportDescriptor, ExportStatus};

/// The outcome of resolving one imported symbol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Known export the loader can bind (the image loads).
    Available(ExportStatus),
    /// Known but unsupported — importing it blocks the load (fail-fast).
    Blocked,
    /// Not in the registry at all.
    Missing,
}

impl ImportOutcome {
    /// True if the import does not prevent loading.
    pub fn loads(self) -> bool {
        matches!(self, ImportOutcome::Available(_))
    }
}

struct Entry {
    desc: &'static ExportDescriptor,
    /// Trampoline address, bound by the Driver Host runtime (M5).
    trampoline: Option<u64>,
}

/// The `ntoskrnl.exe` + `hal.dll` export registry.
pub struct ExportRegistry {
    entries: Vec<Entry>,
}

impl ExportRegistry {
    /// Build the registry from the static `ntoskrnl` + `hal` tables.
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(
            ntoskrnl::NTOSKRNL.len() + win32k::WIN32K_NTOSKRNL.len() + hal::HAL.len(),
        );
        for d in ntoskrnl::NTOSKRNL
            .iter()
            .chain(win32k::WIN32K_NTOSKRNL.iter())
            .chain(hal::HAL.iter())
        {
            entries.push(Entry {
                desc: d,
                trampoline: None,
            });
        }
        ExportRegistry { entries }
    }

    fn find(&self, dll: &str, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.desc.name == name && e.desc.dll.eq_ignore_ascii_case(dll))
    }

    /// The descriptor for `dll!name`, if known.
    pub fn lookup(&self, dll: &str, name: &str) -> Option<&'static ExportDescriptor> {
        self.find(dll, name).map(|i| self.entries[i].desc)
    }

    /// Resolve `dll!name` to a load outcome.
    pub fn resolve(&self, dll: &str, name: &str) -> ImportOutcome {
        match self.find(dll, name) {
            Some(i) => {
                let status = self.entries[i].desc.status;
                if status.is_available() {
                    ImportOutcome::Available(status)
                } else {
                    ImportOutcome::Blocked
                }
            }
            None => ImportOutcome::Missing,
        }
    }

    /// Bind a trampoline address for `dll!name` (the Driver Host runtime, M5).
    /// Returns `false` if the export is unknown.
    pub fn set_trampoline(&mut self, dll: &str, name: &str, addr: u64) -> bool {
        match self.find(dll, name) {
            Some(i) => {
                self.entries[i].trampoline = Some(addr);
                true
            }
            None => false,
        }
    }

    /// The bound trampoline address for `dll!name`, if any.
    pub fn trampoline(&self, dll: &str, name: &str) -> Option<u64> {
        self.find(dll, name)
            .and_then(|i| self.entries[i].trampoline)
    }

    /// All known descriptors.
    pub fn descriptors(&self) -> impl Iterator<Item = &'static ExportDescriptor> + '_ {
        self.entries.iter().map(|e| e.desc)
    }

    /// Check a driver's imports (`(dll, name)` pairs) against the registry
    /// (spec §15).
    pub fn check<'a, I>(&self, imports: I) -> ImportReport
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let checks = imports
            .into_iter()
            .map(|(dll, name)| ImportCheck {
                dll: dll.to_string(),
                name: name.to_string(),
                outcome: self.resolve(dll, name),
            })
            .collect();
        ImportReport { checks }
    }
}

impl Default for ExportRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// One resolved import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportCheck {
    pub dll: String,
    pub name: String,
    pub outcome: ImportOutcome,
}

/// The result of checking all of a driver's imports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportReport {
    pub checks: Vec<ImportCheck>,
}

impl ImportReport {
    /// True if every import can be bound — the driver may be loaded.
    pub fn runnable(&self) -> bool {
        self.checks.iter().all(|c| c.outcome.loads())
    }

    /// The imports that block the load (unsupported or missing).
    pub fn blocking(&self) -> impl Iterator<Item = &ImportCheck> {
        self.checks.iter().filter(|c| !c.outcome.loads())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn resolves_known_exports() {
        let reg = ExportRegistry::new();
        assert_eq!(
            reg.resolve("ntoskrnl.exe", "IoCreateDevice"),
            ImportOutcome::Available(ExportStatus::Implemented)
        );
        assert_eq!(
            reg.resolve("ntoskrnl.exe", "KeRaiseIrql"),
            ImportOutcome::Available(ExportStatus::Partial)
        );
        // DLL name is case-insensitive.
        assert_eq!(
            reg.resolve("NTOSKRNL.EXE", "IoCreateDevice"),
            ImportOutcome::Available(ExportStatus::Implemented)
        );
        // hal.dll export.
        assert_eq!(
            reg.resolve("hal.dll", "KfRaiseIrql"),
            ImportOutcome::Available(ExportStatus::Partial)
        );
    }

    #[test]
    fn unsupported_blocks_and_unknown_is_missing() {
        let reg = ExportRegistry::new();
        assert_eq!(
            reg.resolve("ntoskrnl.exe", "IoConnectInterrupt"),
            ImportOutcome::Blocked
        );
        assert_eq!(
            reg.resolve("ntoskrnl.exe", "TotallyMadeUp"),
            ImportOutcome::Missing
        );
        // Symbol names are case-sensitive.
        assert_eq!(
            reg.resolve("ntoskrnl.exe", "iocreatedevice"),
            ImportOutcome::Missing
        );
    }

    #[test]
    fn every_partial_documents_deviations() {
        let reg = ExportRegistry::new();
        for d in reg.descriptors() {
            if d.status == ExportStatus::Partial {
                assert!(!d.notes.is_empty(), "Partial export {} lacks notes", d.name);
            }
        }
    }

    #[test]
    fn trampoline_binding() {
        let mut reg = ExportRegistry::new();
        assert_eq!(reg.trampoline("ntoskrnl.exe", "IoCreateDevice"), None);
        assert!(reg.set_trampoline("ntoskrnl.exe", "IoCreateDevice", 0xDEAD_BEEF));
        assert_eq!(
            reg.trampoline("ntoskrnl.exe", "IoCreateDevice"),
            Some(0xDEAD_BEEF)
        );
        // Unknown export cannot be bound.
        assert!(!reg.set_trampoline("ntoskrnl.exe", "Nope", 1));
    }

    #[test]
    fn win32k_full_import_surface_resolves_and_loads() {
        let reg = ExportRegistry::new();
        // Every ntoskrnl.exe import win32k.sys names must resolve to an
        // Available export (never Missing, never Blocked — the load must not
        // fail-fast on any of win32k's 224 ntoskrnl imports).
        let mut missing = std::vec::Vec::new();
        let mut blocked = std::vec::Vec::new();
        for name in crate::WIN32K_NTOSKRNL_IMPORTS {
            match reg.resolve("ntoskrnl.exe", name) {
                ImportOutcome::Available(_) => {}
                ImportOutcome::Missing => missing.push(*name),
                ImportOutcome::Blocked => blocked.push(*name),
            }
        }
        assert!(
            missing.is_empty(),
            "unresolved ntoskrnl imports: {missing:?}"
        );
        assert!(
            blocked.is_empty(),
            "load-blocking ntoskrnl imports: {blocked:?}"
        );

        // hal.dll import(s).
        for name in crate::WIN32K_HAL_IMPORTS {
            assert!(
                reg.resolve("hal.dll", name).loads(),
                "hal.dll import {name} does not resolve"
            );
        }

        // The whole (dll, name) set is runnable as a single report.
        let all: std::vec::Vec<(&str, &str)> = crate::WIN32K_NTOSKRNL_IMPORTS
            .iter()
            .map(|n| ("ntoskrnl.exe", *n))
            .chain(crate::WIN32K_HAL_IMPORTS.iter().map(|n| ("hal.dll", *n)))
            .collect();
        let report = reg.check(all);
        assert!(report.runnable(), "win32k import set is not runnable");
        assert_eq!(report.blocking().count(), 0);
    }

    #[test]
    fn win32k_import_lists_have_expected_counts() {
        assert_eq!(crate::WIN32K_NTOSKRNL_IMPORTS.len(), 224);
        assert_eq!(crate::WIN32K_HAL_IMPORTS.len(), 1);
        assert_eq!(crate::WIN32K_FTFD_IMPORTS.len(), 34);
        // No duplicate names within the ntoskrnl import list.
        let mut seen = std::collections::BTreeSet::new();
        for n in crate::WIN32K_NTOSKRNL_IMPORTS {
            assert!(seen.insert(*n), "duplicate win32k import {n}");
        }
    }

    #[test]
    fn import_report_verdicts() {
        let reg = ExportRegistry::new();
        // A driver that only imports supported exports is runnable.
        let ok = reg.check([
            ("ntoskrnl.exe", "IoCreateDevice"),
            ("ntoskrnl.exe", "IoCreateSymbolicLink"),
            ("ntoskrnl.exe", "IoCompleteRequest"),
            ("ntoskrnl.exe", "DbgPrint"),
        ]);
        assert!(ok.runnable());
        assert_eq!(ok.blocking().count(), 0);

        // One unsupported + one missing import blocks the load.
        let blocked = reg.check([
            ("ntoskrnl.exe", "IoCreateDevice"),
            ("ntoskrnl.exe", "IoConnectInterrupt"), // Unsupported
            ("ntoskrnl.exe", "MysteryRoutine"),     // Missing
        ]);
        assert!(!blocked.runnable());
        assert_eq!(blocked.blocking().count(), 2);
    }
}
