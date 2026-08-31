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
    e("IoCallDriver", Implemented, ""),
    e("IofCallDriver", Implemented, ""),
    e("IoAttachDeviceToDeviceStack", Implemented, ""),
    e("IoDetachDevice", Implemented, ""),
    // --- Rtl string helpers ---
    e("RtlInitUnicodeString", Implemented, ""),
    e("RtlCopyUnicodeString", Implemented, ""),
    e("RtlCompareUnicodeString", Implemented, ""),
    e("_stricmp", Implemented, "allocation-free ASCII CRT compare"),
    e("wcschr", Implemented, "bounded UTF-16 CRT search"),
    e(
        "KeFindConfigurationNextEntry",
        Implemented,
        "bounded traversal of the NT loader configuration tree",
    ),
    e(
        "KeLoaderBlock",
        Implemented,
        "NT 5.2 loader projection backed by the boot ACPI root",
    ),
    e(
        "_wcsicmp",
        Implemented,
        "bounded UTF-16 case-insensitive CRT compare",
    ),
    e("wcsicmp", Implemented, "alias of _wcsicmp"),
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
        "event state via nt-kernel-exec; hosted wait-broker wiring is executive-owned",
    ),
    e(
        "KeSetEvent",
        Partial,
        "returns previous state; hosted wait-broker wake wiring is executive-owned",
    ),
    e("KeClearEvent", Partial, "local event state only"),
    e(
        "KeResetEvent",
        Partial,
        "returns previous state; local only",
    ),
    e("KeInitializeTimer", Implemented, ""),
    e("KeCancelTimer", Implemented, ""),
    e("KeSetTimer", Implemented, ""),
    e("KeInitializeDpc", Implemented, ""),
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
    e(
        "MmMapIoSpace",
        Implemented,
        "assigned physical resources and existing nonpaged frame aliases",
    ),
    e(
        "MmUnmapIoSpace",
        Implemented,
        "mapping lifetime is owned by the isolated driver VSpace",
    ),
    e(
        "MmGetPhysicalAddress",
        Implemented,
        "isolated VSpace mappings and assigned MMIO projections",
    ),
    e("IoAllocateMdl", Unsupported, ""),
    e("MmProbeAndLockPages", Unsupported, ""),
    e("MmUnlockPages", Unsupported, ""),
    // win32k.sys imports this; soften from load-blocking to fail-loud so win32k
    // (and drivers) still load, trapping only if the IRP-build path is reached.
    e(
        "IoBuildDeviceIoControlRequest",
        TrapIfCalled,
        "IRP-building not modelled on the host; traps if called",
    ),
    e("PoCallDriver", Unsupported, ""),
    e("IoRegisterDeviceInterface", Unsupported, ""),
    e("IoSetDeviceInterfaceState", Unsupported, ""),
    e("PsCreateSystemThread", Unsupported, ""),
];
