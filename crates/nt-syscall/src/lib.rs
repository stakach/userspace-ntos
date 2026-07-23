//! # `nt-syscall` — native syscall dispatcher + userland ABI
//!
//! The kernel entry the official `ntdll.dll` reaches through (spec: NT Native Syscall + Official
//! Userland ABI): a per-[`UserlandAbiProfile`] [`NativeServiceTable`] mapping syscall numbers to
//! `Nt*` [`NativeService`]s, a [`NativeCallContext`], the [`SyscallRegisterAbi`] descriptor, a
//! [`NativeSyscallHandler`] trait the kernel-services layer implements, and a
//! [`NativeSyscallDispatcher`] that validates the service number + argument count, sets
//! `PreviousMode` (`Nt*` = `UserMode` / `Zw*` = `KernelMode`, spec §8.4), routes to the handler,
//! and rejects unknown services with `STATUS_INVALID_SYSTEM_SERVICE` (never silently succeeds,
//! spec §9.2) — plus user-buffer copyin/copyout helpers (spec §10). `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub mod system_information;
pub mod hard_error;

// NTSTATUS (spec §18)
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_INVALID_SYSTEM_SERVICE: u32 = 0xC000_001C;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;

/// The processor mode a service runs on behalf of (spec §8.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessorMode {
    KernelMode,
    UserMode,
}

/// A userland ABI compatibility profile (spec §6). v0.1 ships a deterministic `Test` profile.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UserlandAbiProfile {
    /// A stable, deterministic profile for tests (sequential service numbers).
    Test,
    /// Windows 7 SP1 (NT 6.1) — the v0.1 pinned target, numbers captured from its `ntdll`.
    Windows7,
    /// A Windows-11-shaped profile (numbers TBD from a captured ntdll).
    Windows11,
}

/// The required `Nt*` native services (spec §16). v0.1 covers the object/file/registry/memory/
/// process families the official userland needs early.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NativeService {
    // Object / handle (§16.1)
    NtClose,
    NtDuplicateObject,
    NtWaitForSingleObject,
    NtQueryObject,
    // Global atom table
    NtAddAtom,
    NtDeleteAtom,
    NtFindAtom,
    NtQueryInformationAtom,
    // File / I/O (§16.2)
    NtCreateFile,
    NtOpenFile,
    NtReadFile,
    NtWriteFile,
    NtDeviceIoControlFile,
    NtCreateNamedPipeFile,
    NtFsControlFile,
    NtQueryDirectoryFile,
    NtQueryInformationFile,
    NtSetInformationFile,
    NtFlushBuffersFile,
    NtCreateIoCompletion,
    NtOpenIoCompletion,
    NtQueryIoCompletion,
    NtRemoveIoCompletion,
    NtSetIoCompletion,
    // Registry (§16.3)
    NtOpenKey,
    NtCreateKey,
    NtQueryValueKey,
    NtSetValueKey,
    NtEnumerateKey,
    NtEnumerateValueKey,
    NtQueryKey,
    // Memory / section (§16.4)
    NtAllocateVirtualMemory,
    NtFreeVirtualMemory,
    NtCreateSection,
    NtMapViewOfSection,
    NtUnmapViewOfSection,
    // Process / thread (§16.5)
    NtCreateThreadEx,
    NtTerminateProcess,
    NtTerminateThread,
    NtQueryInformationProcess,
    NtResumeProcess,
    NtSuspendProcess,
    NtOpenProcess,
    NtOpenThread,
    NtQueryInformationThread,
    // Security / token (§16.7)
    NtOpenProcessToken,
    NtOpenProcessTokenEx,
    NtDuplicateToken,
    NtAccessCheck,
    // System information (§16.5, §7.1)
    NtQuerySystemInformation,
    NtQuerySystemTime,
    NtDelayExecution,
    NtGetPlugPlayEvent,
    NtPlugPlayControl,
    NtSetSystemPowerState,
    NtRaiseHardError,
    // Additional services the executive hosts for real binaries (smss/csrss). These are real
    // Win7-SP1 native services migrated off the executive's hand-wired dispatch ladder into this
    // registered table (Workstream A: converge all native dispatch onto the `NativeServiceTable`).
    NtProtectVirtualMemory,
    NtDisplayString,
    NtQueryDebugFilterState,
    NtSetDebugFilterState,
    NtOpenThreadToken,
    NtOpenThreadTokenEx,
    // Object-creation services the executive hands a fake handle for (SmpInit's \SmApiPort, the
    // SM/CSR worker threads, events/semaphores) — real LPC/thread objects are later work.
    NtCreatePort,
    NtCreateThread,
    NtCreateEvent,
    NtClearEvent,
    NtPulseEvent,
    NtQueryEvent,
    NtResetEvent,
    NtSetEvent,
    // NtOpenEvent — open an existing named event in \BaseNamedObjects (CreateEventW's
    // ERROR_ALREADY_EXISTS fallback + OpenEventW). Resolved against the executive object namespace.
    NtOpenEvent,
    // NtOpenEventPair — obsolete event-pair objects. Exported so legacy shell/debug imports resolve;
    // the executive currently returns an object-open failure because no event-pair type is modelled.
    NtOpenEventPair,
    NtCreateSemaphore,
    NtOpenSemaphore,
    NtQuerySemaphore,
    NtReleaseSemaphore,
    // NT LPC connection rendezvous (control plane) — routed to the isolated nt-lpc-server over
    // SURT. The message data plane (request/reply/receive) is served directly by the executive
    // against its cached connection, so those ops are NOT in this table (they never round-trip to
    // the server).
    NtConnectPort,
    NtSecureConnectPort,
    NtAcceptConnectPort,
    NtCompleteConnectPort,
    // The LPC message data plane (request/reply). Registered so the executive can service the CSR
    // API message exchange (kernel32's CsrClientCallServer → \Windows\ApiPort) via DIRECT cross-
    // badge delivery against the cached connection — it does NOT round-trip to the isolated broker.
    NtRequestWaitReplyPort,
    NtMakeTemporaryObject,
    // No-op-success services (the executive doesn't model these yet: bump allocator never frees,
    // no per-thread/process attribute sets, no per-object security).
    NtSetInformationThread,
    NtSetInformationProcess,
    NtTestAlert,
    NtFlushInstructionCache,
    NtCreateKeyedEvent,
    NtReleaseKeyedEvent,
    NtWaitForKeyedEvent,
    NtAdjustPrivilegesToken,
    NtDeleteValueKey,
    NtInitializeRegistry,
    NtSetSystemInformation,
    NtSetSecurityObject,
    NtResumeThread,
    NtSetInformationObject,
    NtSetUuidSeed,
    // Group B: query + object-namespace services (executive out-writes / obj_ns lookups).
    NtQueryVirtualMemory,
    NtQueryInformationToken,
    NtOpenDirectoryObject,
    NtCreateDirectoryObject,
    // NtQueryDirectoryObject — enumerate a directory object's entries (ntdll's named-object path
    // walks \BaseNamedObjects). Served from the executive object namespace.
    NtQueryDirectoryObject,
    NtCreateSymbolicLinkObject,
    NtOpenSymbolicLinkObject,
    // Group B2: out-writing query services whose out-ptr may be an arbitrary hosted VA (demand-
    // filled by the executive after dispatch via a queued-write side-channel).
    NtQueryPerformanceCounter,
    NtQueryVolumeInformationFile,
    // Group C: section/registry/spawn services entangled with the executive's fault-loop state.
    NtOpenSection,
    NtQueryAttributesFile,
    NtQuerySection,
    NtQueryDefaultLocale,
    NtSetDefaultLocale,
    NtCreateProcess,
}

impl NativeService {
    /// The canonical `Nt*` export name.
    pub fn name(self) -> &'static str {
        use NativeService::*;
        match self {
            NtClose => "NtClose",
            NtDuplicateObject => "NtDuplicateObject",
            NtWaitForSingleObject => "NtWaitForSingleObject",
            NtQueryObject => "NtQueryObject",
            NtAddAtom => "NtAddAtom",
            NtDeleteAtom => "NtDeleteAtom",
            NtFindAtom => "NtFindAtom",
            NtQueryInformationAtom => "NtQueryInformationAtom",
            NtCreateFile => "NtCreateFile",
            NtOpenFile => "NtOpenFile",
            NtReadFile => "NtReadFile",
            NtWriteFile => "NtWriteFile",
            NtDeviceIoControlFile => "NtDeviceIoControlFile",
            NtCreateNamedPipeFile => "NtCreateNamedPipeFile",
            NtFsControlFile => "NtFsControlFile",
            NtQueryDirectoryFile => "NtQueryDirectoryFile",
            NtQueryInformationFile => "NtQueryInformationFile",
            NtSetInformationFile => "NtSetInformationFile",
            NtFlushBuffersFile => "NtFlushBuffersFile",
            NtCreateIoCompletion => "NtCreateIoCompletion",
            NtOpenIoCompletion => "NtOpenIoCompletion",
            NtQueryIoCompletion => "NtQueryIoCompletion",
            NtRemoveIoCompletion => "NtRemoveIoCompletion",
            NtSetIoCompletion => "NtSetIoCompletion",
            NtOpenKey => "NtOpenKey",
            NtCreateKey => "NtCreateKey",
            NtQueryValueKey => "NtQueryValueKey",
            NtSetValueKey => "NtSetValueKey",
            NtEnumerateKey => "NtEnumerateKey",
            NtEnumerateValueKey => "NtEnumerateValueKey",
            NtQueryKey => "NtQueryKey",
            NtAllocateVirtualMemory => "NtAllocateVirtualMemory",
            NtFreeVirtualMemory => "NtFreeVirtualMemory",
            NtCreateSection => "NtCreateSection",
            NtMapViewOfSection => "NtMapViewOfSection",
            NtUnmapViewOfSection => "NtUnmapViewOfSection",
            NtCreateThreadEx => "NtCreateThreadEx",
            NtTerminateProcess => "NtTerminateProcess",
            NtTerminateThread => "NtTerminateThread",
            NtQueryInformationProcess => "NtQueryInformationProcess",
            NtResumeProcess => "NtResumeProcess",
            NtSuspendProcess => "NtSuspendProcess",
            NtOpenProcess => "NtOpenProcess",
            NtOpenThread => "NtOpenThread",
            NtQueryInformationThread => "NtQueryInformationThread",
            NtOpenProcessToken => "NtOpenProcessToken",
            NtOpenProcessTokenEx => "NtOpenProcessTokenEx",
            NtDuplicateToken => "NtDuplicateToken",
            NtAccessCheck => "NtAccessCheck",
            NtQuerySystemInformation => "NtQuerySystemInformation",
            NtQuerySystemTime => "NtQuerySystemTime",
            NtDelayExecution => "NtDelayExecution",
            NtGetPlugPlayEvent => "NtGetPlugPlayEvent",
            NtPlugPlayControl => "NtPlugPlayControl",
            NtSetSystemPowerState => "NtSetSystemPowerState",
            NtRaiseHardError => "NtRaiseHardError",
            NtProtectVirtualMemory => "NtProtectVirtualMemory",
            NtDisplayString => "NtDisplayString",
            NtQueryDebugFilterState => "NtQueryDebugFilterState",
            NtSetDebugFilterState => "NtSetDebugFilterState",
            NtOpenThreadToken => "NtOpenThreadToken",
            NtOpenThreadTokenEx => "NtOpenThreadTokenEx",
            NtCreatePort => "NtCreatePort",
            NtCreateThread => "NtCreateThread",
            NtCreateEvent => "NtCreateEvent",
            NtClearEvent => "NtClearEvent",
            NtPulseEvent => "NtPulseEvent",
            NtQueryEvent => "NtQueryEvent",
            NtResetEvent => "NtResetEvent",
            NtSetEvent => "NtSetEvent",
            NtOpenEvent => "NtOpenEvent",
            NtOpenEventPair => "NtOpenEventPair",
            NtCreateSemaphore => "NtCreateSemaphore",
            NtOpenSemaphore => "NtOpenSemaphore",
            NtQuerySemaphore => "NtQuerySemaphore",
            NtReleaseSemaphore => "NtReleaseSemaphore",
            NtConnectPort => "NtConnectPort",
            NtSecureConnectPort => "NtSecureConnectPort",
            NtAcceptConnectPort => "NtAcceptConnectPort",
            NtCompleteConnectPort => "NtCompleteConnectPort",
            NtRequestWaitReplyPort => "NtRequestWaitReplyPort",
            NtMakeTemporaryObject => "NtMakeTemporaryObject",
            NtSetInformationThread => "NtSetInformationThread",
            NtSetInformationProcess => "NtSetInformationProcess",
            NtTestAlert => "NtTestAlert",
            NtFlushInstructionCache => "NtFlushInstructionCache",
            NtCreateKeyedEvent => "NtCreateKeyedEvent",
            NtReleaseKeyedEvent => "NtReleaseKeyedEvent",
            NtWaitForKeyedEvent => "NtWaitForKeyedEvent",
            NtAdjustPrivilegesToken => "NtAdjustPrivilegesToken",
            NtDeleteValueKey => "NtDeleteValueKey",
            NtInitializeRegistry => "NtInitializeRegistry",
            NtSetSystemInformation => "NtSetSystemInformation",
            NtSetSecurityObject => "NtSetSecurityObject",
            NtResumeThread => "NtResumeThread",
            NtSetInformationObject => "NtSetInformationObject",
            NtSetUuidSeed => "NtSetUuidSeed",
            NtQueryVirtualMemory => "NtQueryVirtualMemory",
            NtQueryInformationToken => "NtQueryInformationToken",
            NtOpenDirectoryObject => "NtOpenDirectoryObject",
            NtCreateDirectoryObject => "NtCreateDirectoryObject",
            NtQueryDirectoryObject => "NtQueryDirectoryObject",
            NtCreateSymbolicLinkObject => "NtCreateSymbolicLinkObject",
            NtOpenSymbolicLinkObject => "NtOpenSymbolicLinkObject",
            NtQueryPerformanceCounter => "NtQueryPerformanceCounter",
            NtQueryVolumeInformationFile => "NtQueryVolumeInformationFile",
            NtOpenSection => "NtOpenSection",
            NtQueryAttributesFile => "NtQueryAttributesFile",
            NtQuerySection => "NtQuerySection",
            NtQueryDefaultLocale => "NtQueryDefaultLocale",
            NtSetDefaultLocale => "NtSetDefaultLocale",
            NtCreateProcess => "NtCreateProcess",
        }
    }

    /// The `(min, max)` argument count for the service (spec §9.1).
    pub fn arg_count(self) -> (u8, u8) {
        use NativeService::*;
        match self {
            NtClose | NtQuerySystemTime | NtDisplayString | NtDeleteAtom | NtClearEvent => (1, 1),
            NtResumeProcess | NtSuspendProcess | NtSetUuidSeed => (1, 1),
            NtTerminateProcess | NtTerminateThread | NtUnmapViewOfSection | NtDelayExecution
            | NtQueryDebugFilterState | NtPulseEvent | NtResetEvent | NtSetEvent => (2, 2),
            NtOpenKey | NtCreateKey | NtAddAtom | NtFindAtom | NtOpenIoCompletion
            | NtSetDebugFilterState | NtOpenEventPair | NtPlugPlayControl
            | NtSetSystemPowerState | NtOpenEvent | NtOpenSemaphore | NtReleaseSemaphore => (3, 3),
            NtGetPlugPlayEvent | NtOpenProcess | NtOpenThread => (4, 4),
            NtQueryValueKey => (4, 6),
            NtOpenThreadToken | NtOpenProcessTokenEx | NtSetInformationThread
            | NtCreateIoCompletion => (4, 4),
            NtOpenThreadTokenEx => (5, 5),
            NtProtectVirtualMemory | NtQueryInformationProcess | NtQueryInformationToken
            | NtQueryInformationThread
            | NtQueryObject | NtQueryVolumeInformationFile | NtQueryInformationAtom
            | NtQueryIoCompletion | NtRemoveIoCompletion | NtSetIoCompletion | NtQueryEvent
            | NtQuerySemaphore => {
                (5, 5)
            }
            NtWaitForSingleObject => (3, 3),
            NtCreateKeyedEvent | NtReleaseKeyedEvent | NtWaitForKeyedEvent => (4, 4),
            NtQueryPerformanceCounter => (2, 2),
            NtQueryVirtualMemory | NtAllocateVirtualMemory | NtDuplicateToken => (6, 6),
            NtRaiseHardError => (6, 6),
            NtOpenSection => (0, 4),
            // Group-C ladder migrations: these handlers read their register args via the executive's
            // IPC helpers (get_recv_mr) + stack args off the caller's SP directly, and use the arg
            // vector only for RDX (args[1]); cap at 4 register args (no stack-arg prefill needed).
            NtQueryAttributesFile | NtQuerySection | NtQueryDefaultLocale | NtSetDefaultLocale
            | NtCreateProcess | NtOpenFile | NtCreateSection | NtMapViewOfSection => (0, 4),
            NtOpenDirectoryObject | NtCreateDirectoryObject | NtCreateSymbolicLinkObject
            | NtOpenSymbolicLinkObject => (0, 4),
            // NtQueryDirectoryObject(Handle, Buffer, Length, ReturnSingleEntry, RestartScan,
            // *Context, *ReturnLength): the handler reads out-ptrs via register/stack helpers → cap.
            NtQueryDirectoryObject => (0, 4),
            NtEnumerateValueKey => (6, 6),
            NtQueryKey => (5, 5),
            NtQuerySystemInformation => (4, 4),
            NtReadFile | NtWriteFile => (5, 9),
            NtQueryInformationFile => (5, 5),
            NtCreateFile => (8, 11),
            // Group-A services the executive handles by reading registers directly (out-handle in
            // RCX/R8) or as pure no-ops — the handler ignores the arg vector, so cap max at 4
            // (register-only, no stack-arg reads) to keep dispatch side-effect-free for them.
            NtCreatePort | NtCreateThread
            | NtMakeTemporaryObject | NtOpenProcessToken | NtFreeVirtualMemory | NtSetValueKey
            | NtSetInformationProcess | NtTestAlert
            | NtFlushInstructionCache
            | NtDeleteValueKey | NtInitializeRegistry | NtSetSystemInformation
            | NtSetSecurityObject | NtResumeThread | NtSetInformationObject
            // CSR message plane: the handler reads Request/Reply message ptrs via the register
            // args + the winlogon stack mirror directly; cap at 4 register args (no stack prefill).
            | NtRequestWaitReplyPort
            // Named-pipe / device I/O: the handler writes out-params (FileHandle in R10,
            // IoStatusBlock in R9) via the executive's register/stack helpers; register-only cap.
            | NtCreateNamedPipeFile => (0, 4),
            NtAdjustPrivilegesToken => (6, 6),
            // NtCreateSemaphore is a real 5-arg ntdll call. The executive currently mints an opaque
            // closable handle, but ntdll must be allowed to pass the InitialCount stack arg.
            NtCreateSemaphore => (5, 5),
            NtCreateEvent => (5, 5),
            // The filesystem-control handler forwards all native buffer arguments to the FSD.
            NtFsControlFile => (10, 10),
            NtQueryDirectoryFile => (11, 11),
            _ => (0, 16), // permissive for the rest in v0.1
        }
    }

    /// The v0.1 service list, in a stable order (the `Test` profile numbers them sequentially).
    pub const ALL: &'static [NativeService] = &[
        NativeService::NtClose,
        NativeService::NtDuplicateObject,
        NativeService::NtWaitForSingleObject,
        NativeService::NtQueryObject,
        NativeService::NtAddAtom,
        NativeService::NtDeleteAtom,
        NativeService::NtFindAtom,
        NativeService::NtQueryInformationAtom,
        NativeService::NtCreateFile,
        NativeService::NtOpenFile,
        NativeService::NtReadFile,
        NativeService::NtWriteFile,
        NativeService::NtDeviceIoControlFile,
        NativeService::NtCreateNamedPipeFile,
        NativeService::NtFsControlFile,
        NativeService::NtQueryInformationFile,
        NativeService::NtSetInformationFile,
        NativeService::NtFlushBuffersFile,
        NativeService::NtCreateIoCompletion,
        NativeService::NtOpenIoCompletion,
        NativeService::NtQueryIoCompletion,
        NativeService::NtRemoveIoCompletion,
        NativeService::NtSetIoCompletion,
        NativeService::NtOpenKey,
        NativeService::NtCreateKey,
        NativeService::NtQueryValueKey,
        NativeService::NtSetValueKey,
        NativeService::NtEnumerateKey,
        NativeService::NtEnumerateValueKey,
        NativeService::NtAllocateVirtualMemory,
        NativeService::NtFreeVirtualMemory,
        NativeService::NtCreateSection,
        NativeService::NtMapViewOfSection,
        NativeService::NtUnmapViewOfSection,
        NativeService::NtCreateThreadEx,
        NativeService::NtTerminateProcess,
        NativeService::NtTerminateThread,
        NativeService::NtQueryInformationProcess,
        NativeService::NtResumeProcess,
        NativeService::NtSuspendProcess,
        NativeService::NtOpenProcessToken,
        NativeService::NtAccessCheck,
        NativeService::NtQuerySystemInformation,
        NativeService::NtQuerySystemTime,
        NativeService::NtDelayExecution,
        NativeService::NtGetPlugPlayEvent,
        NativeService::NtPlugPlayControl,
        NativeService::NtSetSystemPowerState,
        NativeService::NtRaiseHardError,
        NativeService::NtProtectVirtualMemory,
        NativeService::NtDisplayString,
        NativeService::NtQueryDebugFilterState,
        NativeService::NtSetDebugFilterState,
        NativeService::NtOpenThreadToken,
        NativeService::NtCreatePort,
        NativeService::NtCreateThread,
        NativeService::NtCreateEvent,
        NativeService::NtClearEvent,
        NativeService::NtOpenEvent,
        NativeService::NtOpenEventPair,
        NativeService::NtCreateSemaphore,
        NativeService::NtConnectPort,
        NativeService::NtSecureConnectPort,
        NativeService::NtAcceptConnectPort,
        NativeService::NtCompleteConnectPort,
        NativeService::NtRequestWaitReplyPort,
        NativeService::NtMakeTemporaryObject,
        NativeService::NtSetInformationThread,
        NativeService::NtSetInformationProcess,
        NativeService::NtTestAlert,
        NativeService::NtFlushInstructionCache,
        NativeService::NtCreateKeyedEvent,
        NativeService::NtReleaseKeyedEvent,
        NativeService::NtWaitForKeyedEvent,
        NativeService::NtAdjustPrivilegesToken,
        NativeService::NtDeleteValueKey,
        NativeService::NtInitializeRegistry,
        NativeService::NtSetSystemInformation,
        NativeService::NtSetSecurityObject,
        NativeService::NtResumeThread,
        NativeService::NtSetInformationObject,
        NativeService::NtSetUuidSeed,
        NativeService::NtQueryVirtualMemory,
        NativeService::NtQueryInformationToken,
        NativeService::NtOpenDirectoryObject,
        NativeService::NtCreateDirectoryObject,
        NativeService::NtQueryDirectoryObject,
        NativeService::NtCreateSymbolicLinkObject,
        NativeService::NtOpenSymbolicLinkObject,
        NativeService::NtQueryPerformanceCounter,
        NativeService::NtQueryVolumeInformationFile,
        NativeService::NtOpenSection,
        NativeService::NtQueryAttributesFile,
        NativeService::NtQuerySection,
        NativeService::NtQueryDefaultLocale,
        NativeService::NtSetDefaultLocale,
        NativeService::NtCreateProcess,
        // Append new services so the deterministic Test profile retains every established number.
        NativeService::NtPulseEvent,
        NativeService::NtQueryEvent,
        NativeService::NtResetEvent,
        NativeService::NtSetEvent,
        NativeService::NtOpenSemaphore,
        NativeService::NtQuerySemaphore,
        NativeService::NtReleaseSemaphore,
        NativeService::NtOpenProcessTokenEx,
        NativeService::NtDuplicateToken,
        NativeService::NtOpenThreadTokenEx,
        NativeService::NtQueryDirectoryFile,
        NativeService::NtOpenProcess,
        NativeService::NtOpenThread,
        NativeService::NtQueryInformationThread,
    ];
}

/// One entry in the service table (spec §9.1).
#[derive(Copy, Clone, Debug)]
pub struct NativeServiceEntry {
    pub number: u32,
    pub service: NativeService,
    pub min_args: u8,
    pub max_args: u8,
}

/// The per-profile system-service table (spec §9.1).
pub struct NativeServiceTable {
    pub profile: UserlandAbiProfile,
    by_number: BTreeMap<u32, NativeServiceEntry>,
    by_service: BTreeMap<NativeService, u32>,
}

impl NativeServiceTable {
    /// Build the `Test` profile: services numbered sequentially from 0 in [`NativeService::ALL`]
    /// order (deterministic, spec §6.4).
    pub fn test_profile() -> Self {
        let mut by_number = BTreeMap::new();
        let mut by_service = BTreeMap::new();
        for (i, &service) in NativeService::ALL.iter().enumerate() {
            let number = i as u32;
            let (min_args, max_args) = service.arg_count();
            by_number.insert(
                number,
                NativeServiceEntry {
                    number,
                    service,
                    min_args,
                    max_args,
                },
            );
            by_service.insert(service, number);
        }
        NativeServiceTable {
            profile: UserlandAbiProfile::Test,
            by_number,
            by_service,
        }
    }

    /// Build a table keyed by real syscall numbers (spec §3.3, §6.3) — e.g. the numbers extracted
    /// from a captured `ntdll`'s syscall stubs. Each `(service, number)` pair uses the service's
    /// own arg-count bounds. Later pairs overwrite earlier ones for the same number/service.
    pub fn from_numbers(profile: UserlandAbiProfile, pairs: &[(NativeService, u32)]) -> Self {
        let mut by_number = BTreeMap::new();
        let mut by_service = BTreeMap::new();
        for &(service, number) in pairs {
            let (min_args, max_args) = service.arg_count();
            by_number.insert(
                number,
                NativeServiceEntry {
                    number,
                    service,
                    min_args,
                    max_args,
                },
            );
            by_service.insert(service, number);
        }
        NativeServiceTable {
            profile,
            by_number,
            by_service,
        }
    }

    pub fn lookup(&self, number: u32) -> Option<NativeServiceEntry> {
        self.by_number.get(&number).copied()
    }
    /// The syscall number a service is exported at (the `ntdll` stub's immediate).
    pub fn number_of(&self, service: NativeService) -> Option<u32> {
        self.by_service.get(&service).copied()
    }
    pub fn len(&self) -> usize {
        self.by_number.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_number.is_empty()
    }
}

/// The context captured for a dispatched syscall (spec §9.4).
#[derive(Clone, Debug)]
pub struct NativeCallContext {
    pub profile: UserlandAbiProfile,
    pub process_id: u32,
    pub thread_id: u32,
    pub previous_mode: ProcessorMode,
    pub syscall_number: u32,
    pub service: NativeService,
    pub user_ip: u64,
    pub user_sp: u64,
}

/// The register ABI descriptor for a profile (spec §8.3) — x64 fastcall + `r10` syscall stub.
#[derive(Clone, Debug)]
pub struct SyscallRegisterAbi {
    pub service_number_register: &'static str,
    pub arg_registers: Vec<&'static str>,
    pub return_status_register: &'static str,
}

impl SyscallRegisterAbi {
    /// The x64 native-syscall convention: `eax`=service number, `r10, rdx, r8, r9`=first 4 args
    /// (stack for the rest), `rax`=NTSTATUS (spec §8.3).
    pub fn x64() -> Self {
        SyscallRegisterAbi {
            service_number_register: "eax",
            arg_registers: alloc::vec!["r10", "rdx", "r8", "r9"],
            return_status_register: "rax",
        }
    }
}

/// The kernel-services layer the dispatcher routes to (spec §9.3). The implementer owns the
/// subsystem managers (Object/File/Registry/Memory/Process/Security) and does the real work.
pub trait NativeSyscallHandler {
    /// Handle a validated syscall. `out` collects any bytes to copy back to user buffers.
    fn handle(&mut self, ctx: &NativeCallContext, args: &[u64], out: &mut Vec<u8>) -> u32;
}

/// The result of a dispatched syscall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyscallResult {
    pub status: u32,
    pub output: Vec<u8>,
}

/// The native syscall dispatcher (spec §9.3): validates the service number + argument count, sets
/// `PreviousMode`, and routes to the [`NativeSyscallHandler`].
pub struct NativeSyscallDispatcher {
    table: NativeServiceTable,
}

impl NativeSyscallDispatcher {
    pub fn new(table: NativeServiceTable) -> Self {
        NativeSyscallDispatcher { table }
    }
    pub fn table(&self) -> &NativeServiceTable {
        &self.table
    }

    /// Dispatch a syscall by number (spec §9.3). `origin.previous_mode` distinguishes an `Nt*`
    /// user call (`UserMode`) from a `Zw*` kernel call (`KernelMode`, spec §8.4). An unknown
    /// service number returns `STATUS_INVALID_SYSTEM_SERVICE` without invoking the handler
    /// (spec §9.2).
    pub fn dispatch<H: NativeSyscallHandler>(
        &self,
        syscall_number: u32,
        args: &[u64],
        origin: &SyscallOrigin,
        handler: &mut H,
    ) -> SyscallResult {
        let entry = match self.table.lookup(syscall_number) {
            Some(e) => e,
            None => {
                return SyscallResult {
                    status: STATUS_INVALID_SYSTEM_SERVICE,
                    output: Vec::new(),
                };
            }
        };
        if (args.len() as u8) < entry.min_args || (args.len() as u8) > entry.max_args {
            return SyscallResult {
                status: STATUS_INVALID_PARAMETER,
                output: Vec::new(),
            };
        }
        let ctx = NativeCallContext {
            profile: self.table.profile,
            process_id: origin.process_id,
            thread_id: origin.thread_id,
            previous_mode: origin.previous_mode,
            syscall_number,
            service: entry.service,
            user_ip: origin.user_ip,
            user_sp: origin.user_sp,
        };
        let mut output = Vec::new();
        let status = handler.handle(&ctx, args, &mut output);
        SyscallResult { status, output }
    }

    /// Dispatch a service by identity (what an `ntdll` stub resolves to its number first).
    pub fn dispatch_service<H: NativeSyscallHandler>(
        &self,
        service: NativeService,
        args: &[u64],
        origin: &SyscallOrigin,
        handler: &mut H,
    ) -> SyscallResult {
        match self.table.number_of(service) {
            Some(n) => self.dispatch(n, args, origin, handler),
            None => SyscallResult {
                status: STATUS_INVALID_SYSTEM_SERVICE,
                output: Vec::new(),
            },
        }
    }
}

/// Where a dispatched syscall came from — the captured caller context (spec §9.3).
#[derive(Copy, Clone, Debug)]
pub struct SyscallOrigin {
    pub process_id: u32,
    pub thread_id: u32,
    pub previous_mode: ProcessorMode,
    pub user_ip: u64,
    pub user_sp: u64,
}

impl SyscallOrigin {
    /// A caller origin for a thread at a given previous mode (IP/SP unset).
    pub fn new(process_id: u32, thread_id: u32, previous_mode: ProcessorMode) -> Self {
        SyscallOrigin {
            process_id,
            thread_id,
            previous_mode,
            user_ip: 0,
            user_sp: 0,
        }
    }
}

// --- user pointer probing + copyin/copyout (spec §10) ------------------------

/// A view over a user address space's committed byte ranges, for `ProbeForRead`/`ProbeForWrite`
/// + copyin/copyout (spec §10.2). v0.1 models the address space as `[base, base+len)` ranges.
#[derive(Default)]
pub struct UserProbe {
    ranges: Vec<(u64, u64, bool)>, // (base, len, writable)
}

impl UserProbe {
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a committed, readable (and optionally writable) user range.
    pub fn add_range(&mut self, base: u64, len: u64, writable: bool) {
        self.ranges.push((base, len, writable));
    }
    fn contains(&self, addr: u64, len: u64, need_write: bool) -> bool {
        let end = match addr.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        self.ranges
            .iter()
            .any(|&(base, rlen, w)| addr >= base && end <= base + rlen && (!need_write || w))
    }
    /// `ProbeForRead` (spec §10.2): validate a user range is readable.
    pub fn probe_for_read(&self, addr: u64, len: u64) -> Result<(), u32> {
        if self.contains(addr, len, false) {
            Ok(())
        } else {
            Err(STATUS_ACCESS_VIOLATION)
        }
    }
    /// `ProbeForWrite` (spec §10.2): validate a user range is writable.
    pub fn probe_for_write(&self, addr: u64, len: u64) -> Result<(), u32> {
        if self.contains(addr, len, true) {
            Ok(())
        } else {
            Err(STATUS_ACCESS_VIOLATION)
        }
    }
}

#[cfg(test)]
mod tests;
