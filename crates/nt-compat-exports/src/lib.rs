//! # `nt-compat-exports` — the driver-visible NT export table
//!
//! The minimal `ntoskrnl.exe` / `hal.dll` symbol set a loaded WDM driver links
//! against (spec §7.3). Each export carries a [`ExportStatus`] (its v0.1
//! compatibility) and a trampoline slot the Driver Host runtime binds later
//! (M5). The registry resolves a driver's imports to a runnable/blocked verdict
//! **before** `DriverEntry` is called, and applies a fail-fast policy to
//! unsupported exports (no fake success for hardware/DMA/interrupt authority —
//! spec §19.4). `no_std` + `alloc`, no `unsafe`.

#![no_std]

extern crate alloc;

mod hal;
mod ntoskrnl;
mod registry;

pub use registry::{ExportRegistry, ImportCheck, ImportOutcome, ImportReport};

/// The v0.1 compatibility status of an export (spec §7.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExportStatus {
    /// A real implementation.
    Implemented,
    /// Implemented with documented deviations (see [`ExportDescriptor::notes`]).
    Partial,
    /// A stub that returns success without doing the work.
    StubSuccess,
    /// A stub that returns a failure status.
    StubFailure,
    /// Not provided — importing it blocks the load (fail-fast).
    Unsupported,
    /// Provided as a trampoline that traps if the driver actually calls it.
    TrapIfCalled,
}

impl ExportStatus {
    /// True if the loader can bind a trampoline for this export, so an image that
    /// imports it still loads. Only [`Unsupported`](ExportStatus::Unsupported)
    /// blocks the load.
    pub fn is_available(self) -> bool {
        !matches!(self, ExportStatus::Unsupported)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ExportStatus::Implemented => "Implemented",
            ExportStatus::Partial => "Partial",
            ExportStatus::StubSuccess => "StubSuccess",
            ExportStatus::StubFailure => "StubFailure",
            ExportStatus::Unsupported => "Unsupported",
            ExportStatus::TrapIfCalled => "TrapIfCalled",
        }
    }
}

/// A single export's static compatibility record.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExportDescriptor {
    /// The owning module (e.g. `"ntoskrnl.exe"`).
    pub dll: &'static str,
    /// The export symbol name.
    pub name: &'static str,
    pub status: ExportStatus,
    /// Known deviations (required for every [`Partial`](ExportStatus::Partial)).
    pub notes: &'static str,
}
