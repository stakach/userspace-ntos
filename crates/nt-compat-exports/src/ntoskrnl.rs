//! The `ntoskrnl.exe` export table (spec §7.3).

use crate::ExportStatus::*;
use crate::{ExportDescriptor, ExportStatus};

const fn e(name: &'static str, status: ExportStatus, notes: &'static str) -> ExportDescriptor {
    ExportDescriptor {
        dll: "ntoskrnl.exe",
        name,
        status,
        notes,
    }
}

/// The MVP `ntoskrnl.exe` exports + their v0.1 status.
pub const NTOSKRNL: &[ExportDescriptor] = &[
    // --- device / symlink / IRP (implemented by the runtime, M6–M7) ---
    e("IoCreateDevice", Implemented, ""),
    e("IoDeleteDevice", Implemented, ""),
    e("IoCreateSymbolicLink", Implemented, ""),
    e("IoDeleteSymbolicLink", Implemented, ""),
    e("IoCompleteRequest", Implemented, ""),
    e("IofCompleteRequest", Implemented, ""),
    e("IoGetCurrentIrpStackLocation", Implemented, ""),
    e("IoGetNextIrpStackLocation", Implemented, ""),
    e("IoSkipCurrentIrpStackLocation", Implemented, ""),
    e("IoCopyCurrentIrpStackLocationToNext", Implemented, ""),
    // --- Rtl string helpers ---
    e("RtlInitUnicodeString", Implemented, ""),
    e("RtlCopyUnicodeString", Implemented, ""),
    e("RtlCompareUnicodeString", Implemented, ""),
    // --- pool (M4 driver-local arena) ---
    e("ExAllocatePoolWithTag", Implemented, ""),
    e("ExFreePoolWithTag", Implemented, ""),
    e("ExFreePool", Implemented, ""),
    // --- debug print (partial: limited format support) ---
    e(
        "DbgPrint",
        Partial,
        "format specifiers limited to %s/%d/%x/%p; no wide/floating",
    ),
    e(
        "DbgPrintEx",
        Partial,
        "component/level filter ignored; same format limits as DbgPrint",
    ),
    // --- events (partial: local state, no real wait/wakeup) ---
    e(
        "KeInitializeEvent",
        Partial,
        "local event state only; no dispatcher wait queue",
    ),
    e(
        "KeSetEvent",
        Partial,
        "returns previous state; wakes no waiters (no KeWaitForSingleObject)",
    ),
    e("KeClearEvent", Partial, "local event state only"),
    e(
        "KeResetEvent",
        Partial,
        "returns previous state; local only",
    ),
    // --- IRQL (partial: simulated single-CPU level) ---
    e("KeGetCurrentIrql", Partial, "simulated single-CPU IRQL"),
    e(
        "KeRaiseIrql",
        Partial,
        "updates simulated IRQL; no preemption",
    ),
    e(
        "KeLowerIrql",
        Partial,
        "updates simulated IRQL; no preemption",
    ),
    // --- spinlocks (partial: single-threaded, IRQL only) ---
    e(
        "KeAcquireSpinLock",
        Partial,
        "single-threaded host: raises IRQL, no real spin",
    ),
    e(
        "KeReleaseSpinLock",
        Partial,
        "single-threaded host: lowers IRQL, no real spin",
    ),
    // --- fail-fast: hardware / DMA / interrupts / stacking (spec §7.3, §19.4) ---
    e("IoConnectInterrupt", Unsupported, ""),
    e("IoDisconnectInterrupt", Unsupported, ""),
    e("MmMapIoSpace", Unsupported, ""),
    e("MmUnmapIoSpace", Unsupported, ""),
    e("MmGetPhysicalAddress", Unsupported, ""),
    e("IoAllocateMdl", Unsupported, ""),
    e("MmProbeAndLockPages", Unsupported, ""),
    e("MmUnlockPages", Unsupported, ""),
    e("IoBuildDeviceIoControlRequest", Unsupported, ""),
    e("IoCallDriver", Unsupported, ""),
    e("IoAttachDeviceToDeviceStack", Unsupported, ""),
    e("IoDetachDevice", Unsupported, ""),
    e("PoCallDriver", Unsupported, ""),
    e("IoRegisterDeviceInterface", Unsupported, ""),
    e("IoSetDeviceInterfaceState", Unsupported, ""),
    e("PsCreateSystemThread", Unsupported, ""),
];
