//! The `hal.dll` export table (spec §7.3, §14).

use crate::ExportStatus::*;
use crate::{ExportDescriptor, ExportStatus};

const fn e(name: &'static str, status: ExportStatus, notes: &'static str) -> ExportDescriptor {
    ExportDescriptor {
        dll: "hal.dll",
        name,
        status,
        notes,
    }
}

/// The MVP `hal.dll` exports + their v0.1 status.
pub const HAL: &[ExportDescriptor] = &[
    // IRQL fastcall variants (partial: simulated level).
    e(
        "KfRaiseIrql",
        Partial,
        "updates simulated IRQL; no preemption",
    ),
    e(
        "KfLowerIrql",
        Partial,
        "updates simulated IRQL; no preemption",
    ),
    // Timing (stub: no real timing source yet).
    e(
        "KeStallExecutionProcessor",
        StubSuccess,
        "busy-wait no-op; no real microsecond timing",
    ),
    e(
        "KeQueryPerformanceCounter",
        StubSuccess,
        "returns a monotonic-ish counter; frequency is nominal",
    ),
    // Bus/hardware access (fail-fast).
    e("HalGetBusData", Unsupported, ""),
    e("HalSetBusData", Unsupported, ""),
    e("READ_PORT_UCHAR", Unsupported, ""),
    e("WRITE_PORT_UCHAR", Unsupported, ""),
];
