//! # `nt-syscall-abi` — the shared Nt*/Zw* SSN ABI table
//!
//! The **single source of truth** for the mapping between an `Nt*`/`Zw*` export name and its
//! **system-service number (SSN)**, shared between our Rust ntdll ([`crate`] consumers in
//! `nt-ntdll`) and the NT executive that services the calls.
//!
//! ## Why this crate exists (the SSN-collision dissolution)
//!
//! Historically each Windows version's *own* `ntdll` baked in its *own* SSN table, and those
//! tables collide (Win7 `NtAlpcConnectPort` = 113 collides with ReactOS `NtMapViewOfSection`
//! = 113). Because import resolution against ntdll is **by name** (`NtCreateFile` resolves
//! through ntdll's export; the SSN is an *internal* detail of the stub), owning ntdll makes the
//! SSN **our** free choice. We fix it ONCE, here, and both ends agree.
//!
//! ## Ground truth: the ReactOS `sysfuncs.lst` numbering (do NOT renumber)
//!
//! The SSN numbering is **`references/reactos/ntoskrnl/sysfuncs.lst`-derived**: the SSN of an
//! `Nt*` service is its **0-based line index** in that file. This is *exactly* the numbering the
//! NT executive already dispatches on (`components/ntos-executive` `SSN_NT_*` consts). Reusing it
//! is what makes owning ntdll **zero-churn on the executive** — the executive keeps dispatching
//! unchanged. Verified anchors (asserted in the tests): `NtClose = 27`, `NtCreateFile = 39`,
//! `NtOpenFile = 122`, `NtProtectVirtualMemory = 143`, `NtAllocateVirtualMemory = 18`, …
//!
//! ## The ALPC seam (reserved, NOT assigned)
//!
//! ReactOS exports **no** `NtAlpc*` (ALPC is the Win7-only future surface; nothing in the
//! current hosted set imports it). ALPC is therefore the *one* place we are free to renumber —
//! but we do NOT assign numbers yet. See [`ALPC_SSN_BASE`] for the documented reserved range.
//!
//! `no_std`, pure data — every table is `const`; the whole thing is host-testable.

#![no_std]

/// A single `Nt*` service's ABI entry: its canonical export name and its SSN.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NtSyscall {
    /// The canonical `Nt*` export name (e.g. `"NtCreateFile"`).
    pub name: &'static str,
    /// The system-service number (the immediate baked into the ntdll stub's `mov eax, <ssn>`).
    /// = the 0-based line index of this service in ReactOS `ntoskrnl/sysfuncs.lst`.
    pub ssn: u32,
}

/// A `Zw*` export that is an alias of an `Nt*` service (same SSN, kernel-previous-mode semantics).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ZwAlias {
    /// The `Zw*` export name.
    pub zw_name: &'static str,
    /// The underlying `Nt*` service name it aliases.
    pub nt_name: &'static str,
    /// The shared SSN.
    pub ssn: u32,
}

/// The reserved base SSN for the (future, Win7-only) ALPC surface.
///
/// **RESERVED, NOT ASSIGNED.** ReactOS `sysfuncs.lst` tops out at SSN 295; the real Nt* range we
/// use is `0..=292`. When the Win7 pivot lands `NtAlpc*` we assign them from this base (well clear
/// of every ReactOS SSN), which is legal precisely because ntdll import-by-name lets us choose.
/// No entry uses this yet; it exists so the choice is documented at the ABI seam, not ad-hoc.
pub const ALPC_SSN_BASE: u32 = 0x1000;

/// ntdll_plan Step 6.A — the msginfo LABEL that marks a REQUEST as an NT native seL4-Call syscall
/// (our ntdll's `Nt*` stub → the executive over a real seL4 `Call`, NOT a Windows-`syscall`
/// UnknownSyscall trap). ASCII `"NT"` (0x4E54) — well clear of the kernel fault-type labels
/// (`UnknownSyscall`=2, `UserException`=3, `VMFault`=6), so the executive's service loop tells a
/// native-syscall message from a fault message by `mi>>12`. The single source of truth shared by OUR
/// ntdll (the stub side) and the executive (the recv side). See `nt_ntdll::native_call` for the full
/// wire layout (MR0=SSN, MR1=rsp, MR2..5=args; reply MR0=NTSTATUS).
pub const NT_NATIVE_SYSCALL_LABEL: u64 = 0x4E54;

/// TEB VA used by the SEC_IMAGE hosted-process main thread.
///
/// Native syscall stubs read this value through the standard x64 `gs:[0x30]` TEB self pointer.
pub const NT_NATIVE_SEC_IMAGE_MAIN_TEB_VA: u64 = 0x0000_0100_0051_0000;

/// TEB VA used by the older isolated-PE main-thread path.
pub const NT_NATIVE_PE_MAIN_TEB_VA: u64 = 0x0000_0100_0057_0000;

/// IPC-buffer VA shared by the two main-thread layouts (in their separate VSpaces).
pub const NT_NATIVE_MAIN_IPC_BUFFER_VA: u64 = 0x0000_0100_105F_B000;

/// Distance between a hosted worker's TEB and its dedicated IPC-buffer mapping.
pub const NT_NATIVE_WORKER_IPC_BUFFER_DELTA: u64 = 0x0001_0000;

/// Select the native seL4 IPC-buffer VA for the thread whose TEB is at `teb`.
///
/// The two historical main-thread layouts retain their fixed IPC-buffer VA. Runtime workers use
/// dedicated buffers one 64-KiB allocation unit below their TEB, so concurrent native calls cannot
/// overwrite another thread's MR4/MR5 spill words.
#[inline]
pub const fn native_ipc_buffer_va(teb: u64) -> u64 {
    if teb == NT_NATIVE_SEC_IMAGE_MAIN_TEB_VA || teb == NT_NATIVE_PE_MAIN_TEB_VA {
        NT_NATIVE_MAIN_IPC_BUFFER_VA
    } else {
        teb - NT_NATIVE_WORKER_IPC_BUFFER_DELTA
    }
}

/// The complete required `Nt*` SSN table: the hosted ReactOS x64 import set
/// (smss/csrss/winlogon/services/lsass + kernel32/user32/gdi32/advapi32/
/// rpcrt4/csrsrv/basesrv/winsrv/… — measured 2026-07-16, see `ntdll_plan.md` Step 1 Results),
/// plus ntdll-internal `NtSecureConnectPort` and `NtCallbackReturn`, each paired with its
/// `sysfuncs.lst`-derived SSN. Sorted by SSN.
pub const NT_SYSCALLS: &[NtSyscall] = &[
    n("NtAcceptConnectPort", 0),
    n("NtAccessCheck", 1),
    n("NtAccessCheckAndAuditAlarm", 2),
    n("NtAccessCheckByType", 3),
    n("NtAccessCheckByTypeResultList", 5),
    n("NtAddAtom", 8),
    n("NtAdjustGroupsToken", 11),
    n("NtAdjustPrivilegesToken", 12),
    n("NtAllocateLocallyUniqueId", 15),
    n("NtAllocateUserPhysicalPages", 16),
    n("NtAllocateVirtualMemory", 18),
    n("NtApphelpCacheControl", 19),
    n("NtAssignProcessToJobObject", 21),
    n("NtCallbackReturn", 22),
    n("NtCancelDeviceWakeupRequest", 23),
    n("NtCancelIoFile", 24),
    n("NtCancelTimer", 25),
    n("NtClearEvent", 26),
    n("NtClose", 27),
    n("NtCloseObjectAuditAlarm", 28),
    n("NtCompleteConnectPort", 31),
    n("NtConnectPort", 33),
    n("NtCreateDirectoryObject", 36),
    n("NtCreateEvent", 37),
    n("NtCreateFile", 39),
    n("NtCreateIoCompletion", 40),
    n("NtCreateJobObject", 41),
    n("NtCreateJobSet", 42),
    n("NtCreateKey", 43),
    n("NtCreateMailslotFile", 44),
    n("NtCreateMutant", 45),
    n("NtCreateNamedPipeFile", 46),
    n("NtCreatePagingFile", 47),
    n("NtCreatePort", 48),
    n("NtCreateProcess", 49),
    n("NtCreateProcessEx", 50),
    n("NtCreateSection", 52),
    n("NtCreateSemaphore", 53),
    n("NtCreateSymbolicLinkObject", 54),
    n("NtCreateThread", 55),
    n("NtCreateTimer", 56),
    n("NtCreateToken", 57),
    n("NtDelayExecution", 61),
    n("NtDeleteAtom", 62),
    n("NtDeleteKey", 66),
    n("NtDeleteObjectAuditAlarm", 67),
    n("NtDeleteValueKey", 68),
    n("NtDeviceIoControlFile", 69),
    n("NtDisplayString", 70),
    n("NtDuplicateObject", 71),
    n("NtDuplicateToken", 72),
    n("NtEnumerateKey", 75),
    n("NtEnumerateValueKey", 77),
    n("NtFilterToken", 79),
    n("NtFindAtom", 80),
    n("NtFlushBuffersFile", 81),
    n("NtFlushInstructionCache", 82),
    n("NtFlushKey", 83),
    n("NtFlushVirtualMemory", 84),
    n("NtFreeUserPhysicalPages", 86),
    n("NtFreeVirtualMemory", 87),
    n("NtFsControlFile", 88),
    n("NtGetContextThread", 89),
    n("NtGetDevicePowerState", 90),
    n("NtGetPlugPlayEvent", 91),
    n("NtGetWriteWatch", 92),
    n("NtImpersonateAnonymousToken", 93),
    n("NtImpersonateThread", 95),
    n("NtInitializeRegistry", 96),
    n("NtInitiatePowerAction", 97),
    n("NtIsProcessInJob", 98),
    n("NtIsSystemResumeAutomatic", 99),
    n("NtListenPort", 100),
    n("NtLoadDriver", 101),
    n("NtLoadKey", 102),
    n("NtLockFile", 105),
    n("NtLockVirtualMemory", 108),
    n("NtMakePermanentObject", 109),
    n("NtMakeTemporaryObject", 110),
    n("NtMapUserPhysicalPages", 111),
    n("NtMapUserPhysicalPagesScatter", 112),
    n("NtMapViewOfSection", 113),
    n("NtNotifyChangeDirectoryFile", 116),
    n("NtNotifyChangeKey", 117),
    n("NtOpenDirectoryObject", 119),
    n("NtOpenEvent", 120),
    n("NtOpenEventPair", 121),
    n("NtOpenFile", 122),
    n("NtOpenIoCompletion", 123),
    n("NtOpenJobObject", 124),
    n("NtOpenKey", 125),
    n("NtOpenMutant", 126),
    n("NtOpenObjectAuditAlarm", 127),
    n("NtOpenProcess", 128),
    n("NtOpenProcessToken", 129),
    n("NtOpenProcessTokenEx", 130),
    n("NtOpenSection", 131),
    n("NtOpenSemaphore", 132),
    n("NtOpenSymbolicLinkObject", 133),
    n("NtOpenThread", 134),
    n("NtOpenThreadToken", 135),
    n("NtOpenThreadTokenEx", 136),
    n("NtOpenTimer", 137),
    n("NtPlugPlayControl", 138),
    n("NtPowerInformation", 139),
    n("NtPrivilegeCheck", 140),
    n("NtPrivilegeObjectAuditAlarm", 141),
    n("NtPrivilegedServiceAuditAlarm", 142),
    n("NtProtectVirtualMemory", 143),
    n("NtPulseEvent", 144),
    n("NtQueryAttributesFile", 145),
    n("NtQueryDebugFilterState", 148),
    n("NtQueryDefaultLocale", 149),
    n("NtQueryDefaultUILanguage", 150),
    n("NtQueryDirectoryFile", 151),
    n("NtQueryDirectoryObject", 152),
    n("NtQueryEaFile", 154),
    n("NtQueryEvent", 155),
    n("NtQueryFullAttributesFile", 156),
    n("NtQueryInformationAtom", 157),
    n("NtQueryInformationFile", 158),
    n("NtQueryInformationJobObject", 159),
    n("NtQueryInformationProcess", 161),
    n("NtQueryInformationThread", 162),
    n("NtQueryInformationToken", 163),
    n("NtQueryInstallUILanguage", 164),
    n("NtQueryIoCompletion", 166),
    n("NtQueryKey", 167),
    n("NtQueryObject", 170),
    n("NtQueryPerformanceCounter", 173),
    n("NtQuerySection", 175),
    n("NtQuerySecurityObject", 176),
    n("NtQuerySemaphore", 177),
    n("NtQuerySymbolicLinkObject", 178),
    n("NtQuerySystemEnvironmentValueEx", 180),
    n("NtQuerySystemInformation", 181),
    n("NtQuerySystemTime", 182),
    n("NtQueryValueKey", 185),
    n("NtQueryVirtualMemory", 186),
    n("NtQueryVolumeInformationFile", 187),
    n("NtQueueApcThread", 188),
    n("NtRaiseHardError", 190),
    n("NtReadFile", 191),
    n("NtReadFileScatter", 192),
    n("NtReadVirtualMemory", 194),
    n("NtRegisterThreadTerminatePort", 195),
    n("NtReleaseMutant", 196),
    n("NtReleaseSemaphore", 197),
    n("NtRemoveIoCompletion", 198),
    n("NtReplaceKey", 201),
    n("NtReplyPort", 202),
    n("NtReplyWaitReceivePort", 203),
    n("NtRequestDeviceWakeup", 206),
    n("NtRequestWaitReplyPort", 208),
    n("NtRequestWakeupLatency", 209),
    n("NtResetEvent", 210),
    n("NtResetWriteWatch", 211),
    n("NtRestoreKey", 212),
    n("NtResumeProcess", 213),
    n("NtResumeThread", 214),
    n("NtSaveKey", 215),
    n("NtSecureConnectPort", 218),
    n("NtSetContextThread", 221),
    n("NtSetDebugFilterState", 222),
    n("NtSetDefaultHardErrorPort", 223),
    n("NtSetDefaultLocale", 224),
    n("NtSetEvent", 228),
    n("NtSetInformationDebugObject", 232),
    n("NtSetInformationFile", 233),
    n("NtSetInformationJobObject", 234),
    n("NtSetInformationObject", 236),
    n("NtSetInformationProcess", 237),
    n("NtSetInformationThread", 238),
    n("NtSetInformationToken", 239),
    n("NtSetIoCompletion", 241),
    n("NtSetSecurityObject", 246),
    n("NtSetSystemEnvironmentValueEx", 248),
    n("NtSetSystemInformation", 249),
    n("NtSetSystemPowerState", 250),
    n("NtSetSystemTime", 251),
    n("NtSetThreadExecutionState", 252),
    n("NtSetTimer", 253),
    n("NtSetUuidSeed", 255),
    n("NtSetValueKey", 256),
    n("NtSetVolumeInformationFile", 257),
    n("NtShutdownSystem", 258),
    n("NtSignalAndWaitForSingleObject", 259),
    n("NtSuspendProcess", 262),
    n("NtSuspendThread", 263),
    n("NtTerminateJobObject", 265),
    n("NtTerminateProcess", 266),
    n("NtTerminateThread", 267),
    n("NtTestAlert", 268),
    n("NtUnloadDriver", 271),
    n("NtUnloadKey", 272),
    n("NtUnlockFile", 275),
    n("NtUnlockVirtualMemory", 276),
    n("NtUnmapViewOfSection", 277),
    n("NtWaitForMultipleObjects", 280),
    n("NtWaitForSingleObject", 281),
    n("NtWriteFile", 284),
    n("NtWriteFileGather", 285),
    n("NtWriteVirtualMemory", 287),
    n("NtYieldExecution", 288),
    n("NtCreateKeyedEvent", 289),
    n("NtReleaseKeyedEvent", 291),
    n("NtWaitForKeyedEvent", 292),
];

/// The `Zw*` aliases for every `Nt*` service exported by our ntdll. Each is the
/// kernel-mode-previous-mode twin of an `Nt*` service and shares its SSN.
pub const ZW_ALIASES: &[ZwAlias] = &[
    z("ZwAcceptConnectPort", "NtAcceptConnectPort", 0),
    z("ZwAccessCheck", "NtAccessCheck", 1),
    z(
        "ZwAccessCheckAndAuditAlarm",
        "NtAccessCheckAndAuditAlarm",
        2,
    ),
    z("ZwAccessCheckByType", "NtAccessCheckByType", 3),
    z(
        "ZwAccessCheckByTypeResultList",
        "NtAccessCheckByTypeResultList",
        5,
    ),
    z("ZwAddAtom", "NtAddAtom", 8),
    z("ZwAdjustGroupsToken", "NtAdjustGroupsToken", 11),
    z("ZwAdjustPrivilegesToken", "NtAdjustPrivilegesToken", 12),
    z("ZwAllocateLocallyUniqueId", "NtAllocateLocallyUniqueId", 15),
    z(
        "ZwAllocateUserPhysicalPages",
        "NtAllocateUserPhysicalPages",
        16,
    ),
    z("ZwAllocateVirtualMemory", "NtAllocateVirtualMemory", 18),
    z("ZwApphelpCacheControl", "NtApphelpCacheControl", 19),
    z(
        "ZwAssignProcessToJobObject",
        "NtAssignProcessToJobObject",
        21,
    ),
    z("ZwCallbackReturn", "NtCallbackReturn", 22),
    z(
        "ZwCancelDeviceWakeupRequest",
        "NtCancelDeviceWakeupRequest",
        23,
    ),
    z("ZwCancelIoFile", "NtCancelIoFile", 24),
    z("ZwCancelTimer", "NtCancelTimer", 25),
    z("ZwClearEvent", "NtClearEvent", 26),
    z("ZwClose", "NtClose", 27),
    z("ZwCloseObjectAuditAlarm", "NtCloseObjectAuditAlarm", 28),
    z("ZwCompleteConnectPort", "NtCompleteConnectPort", 31),
    z("ZwConnectPort", "NtConnectPort", 33),
    z("ZwCreateDirectoryObject", "NtCreateDirectoryObject", 36),
    z("ZwCreateEvent", "NtCreateEvent", 37),
    z("ZwCreateFile", "NtCreateFile", 39),
    z("ZwCreateIoCompletion", "NtCreateIoCompletion", 40),
    z("ZwCreateJobObject", "NtCreateJobObject", 41),
    z("ZwCreateJobSet", "NtCreateJobSet", 42),
    z("ZwCreateKey", "NtCreateKey", 43),
    z("ZwCreateMailslotFile", "NtCreateMailslotFile", 44),
    z("ZwCreateMutant", "NtCreateMutant", 45),
    z("ZwCreateNamedPipeFile", "NtCreateNamedPipeFile", 46),
    z("ZwCreatePagingFile", "NtCreatePagingFile", 47),
    z("ZwCreatePort", "NtCreatePort", 48),
    z("ZwCreateProcess", "NtCreateProcess", 49),
    z("ZwCreateProcessEx", "NtCreateProcessEx", 50),
    z("ZwCreateSection", "NtCreateSection", 52),
    z("ZwCreateSemaphore", "NtCreateSemaphore", 53),
    z(
        "ZwCreateSymbolicLinkObject",
        "NtCreateSymbolicLinkObject",
        54,
    ),
    z("ZwCreateThread", "NtCreateThread", 55),
    z("ZwCreateTimer", "NtCreateTimer", 56),
    z("ZwCreateToken", "NtCreateToken", 57),
    z("ZwDelayExecution", "NtDelayExecution", 61),
    z("ZwDeleteAtom", "NtDeleteAtom", 62),
    z("ZwDeleteKey", "NtDeleteKey", 66),
    z("ZwDeleteObjectAuditAlarm", "NtDeleteObjectAuditAlarm", 67),
    z("ZwDeleteValueKey", "NtDeleteValueKey", 68),
    z("ZwDeviceIoControlFile", "NtDeviceIoControlFile", 69),
    z("ZwDisplayString", "NtDisplayString", 70),
    z("ZwDuplicateObject", "NtDuplicateObject", 71),
    z("ZwDuplicateToken", "NtDuplicateToken", 72),
    z("ZwEnumerateKey", "NtEnumerateKey", 75),
    z("ZwEnumerateValueKey", "NtEnumerateValueKey", 77),
    z("ZwFilterToken", "NtFilterToken", 79),
    z("ZwFindAtom", "NtFindAtom", 80),
    z("ZwFlushBuffersFile", "NtFlushBuffersFile", 81),
    z("ZwFlushInstructionCache", "NtFlushInstructionCache", 82),
    z("ZwFlushKey", "NtFlushKey", 83),
    z("ZwFlushVirtualMemory", "NtFlushVirtualMemory", 84),
    z("ZwFreeUserPhysicalPages", "NtFreeUserPhysicalPages", 86),
    z("ZwFreeVirtualMemory", "NtFreeVirtualMemory", 87),
    z("ZwFsControlFile", "NtFsControlFile", 88),
    z("ZwGetContextThread", "NtGetContextThread", 89),
    z("ZwGetDevicePowerState", "NtGetDevicePowerState", 90),
    z("ZwGetPlugPlayEvent", "NtGetPlugPlayEvent", 91),
    z("ZwGetWriteWatch", "NtGetWriteWatch", 92),
    z(
        "ZwImpersonateAnonymousToken",
        "NtImpersonateAnonymousToken",
        93,
    ),
    z("ZwImpersonateThread", "NtImpersonateThread", 95),
    z("ZwInitializeRegistry", "NtInitializeRegistry", 96),
    z("ZwInitiatePowerAction", "NtInitiatePowerAction", 97),
    z("ZwIsProcessInJob", "NtIsProcessInJob", 98),
    z("ZwIsSystemResumeAutomatic", "NtIsSystemResumeAutomatic", 99),
    z("ZwListenPort", "NtListenPort", 100),
    z("ZwLoadDriver", "NtLoadDriver", 101),
    z("ZwLoadKey", "NtLoadKey", 102),
    z("ZwLockFile", "NtLockFile", 105),
    z("ZwLockVirtualMemory", "NtLockVirtualMemory", 108),
    z("ZwMakePermanentObject", "NtMakePermanentObject", 109),
    z("ZwMakeTemporaryObject", "NtMakeTemporaryObject", 110),
    z("ZwMapUserPhysicalPages", "NtMapUserPhysicalPages", 111),
    z(
        "ZwMapUserPhysicalPagesScatter",
        "NtMapUserPhysicalPagesScatter",
        112,
    ),
    z("ZwMapViewOfSection", "NtMapViewOfSection", 113),
    z(
        "ZwNotifyChangeDirectoryFile",
        "NtNotifyChangeDirectoryFile",
        116,
    ),
    z("ZwNotifyChangeKey", "NtNotifyChangeKey", 117),
    z("ZwOpenDirectoryObject", "NtOpenDirectoryObject", 119),
    z("ZwOpenEvent", "NtOpenEvent", 120),
    z("ZwOpenEventPair", "NtOpenEventPair", 121),
    z("ZwOpenFile", "NtOpenFile", 122),
    z("ZwOpenIoCompletion", "NtOpenIoCompletion", 123),
    z("ZwOpenJobObject", "NtOpenJobObject", 124),
    z("ZwOpenKey", "NtOpenKey", 125),
    z("ZwOpenMutant", "NtOpenMutant", 126),
    z("ZwOpenObjectAuditAlarm", "NtOpenObjectAuditAlarm", 127),
    z("ZwOpenProcess", "NtOpenProcess", 128),
    z("ZwOpenProcessToken", "NtOpenProcessToken", 129),
    z("ZwOpenProcessTokenEx", "NtOpenProcessTokenEx", 130),
    z("ZwOpenSection", "NtOpenSection", 131),
    z("ZwOpenSemaphore", "NtOpenSemaphore", 132),
    z("ZwOpenSymbolicLinkObject", "NtOpenSymbolicLinkObject", 133),
    z("ZwOpenThread", "NtOpenThread", 134),
    z("ZwOpenThreadToken", "NtOpenThreadToken", 135),
    z("ZwOpenThreadTokenEx", "NtOpenThreadTokenEx", 136),
    z("ZwOpenTimer", "NtOpenTimer", 137),
    z("ZwPlugPlayControl", "NtPlugPlayControl", 138),
    z("ZwPowerInformation", "NtPowerInformation", 139),
    z("ZwPrivilegeCheck", "NtPrivilegeCheck", 140),
    z(
        "ZwPrivilegeObjectAuditAlarm",
        "NtPrivilegeObjectAuditAlarm",
        141,
    ),
    z(
        "ZwPrivilegedServiceAuditAlarm",
        "NtPrivilegedServiceAuditAlarm",
        142,
    ),
    z("ZwProtectVirtualMemory", "NtProtectVirtualMemory", 143),
    z("ZwPulseEvent", "NtPulseEvent", 144),
    z("ZwQueryAttributesFile", "NtQueryAttributesFile", 145),
    z("ZwQueryDebugFilterState", "NtQueryDebugFilterState", 148),
    z("ZwQueryDefaultLocale", "NtQueryDefaultLocale", 149),
    z("ZwQueryDefaultUILanguage", "NtQueryDefaultUILanguage", 150),
    z("ZwQueryDirectoryFile", "NtQueryDirectoryFile", 151),
    z("ZwQueryDirectoryObject", "NtQueryDirectoryObject", 152),
    z("ZwQueryEaFile", "NtQueryEaFile", 154),
    z("ZwQueryEvent", "NtQueryEvent", 155),
    z(
        "ZwQueryFullAttributesFile",
        "NtQueryFullAttributesFile",
        156,
    ),
    z("ZwQueryInformationAtom", "NtQueryInformationAtom", 157),
    z("ZwQueryInformationFile", "NtQueryInformationFile", 158),
    z(
        "ZwQueryInformationJobObject",
        "NtQueryInformationJobObject",
        159,
    ),
    z(
        "ZwQueryInformationProcess",
        "NtQueryInformationProcess",
        161,
    ),
    z("ZwQueryInformationThread", "NtQueryInformationThread", 162),
    z("ZwQueryInformationToken", "NtQueryInformationToken", 163),
    z("ZwQueryInstallUILanguage", "NtQueryInstallUILanguage", 164),
    z("ZwQueryIoCompletion", "NtQueryIoCompletion", 166),
    z("ZwQueryKey", "NtQueryKey", 167),
    z("ZwQueryObject", "NtQueryObject", 170),
    z(
        "ZwQueryPerformanceCounter",
        "NtQueryPerformanceCounter",
        173,
    ),
    z("ZwQuerySection", "NtQuerySection", 175),
    z("ZwQuerySecurityObject", "NtQuerySecurityObject", 176),
    z("ZwQuerySemaphore", "NtQuerySemaphore", 177),
    z(
        "ZwQuerySymbolicLinkObject",
        "NtQuerySymbolicLinkObject",
        178,
    ),
    z(
        "ZwQuerySystemEnvironmentValueEx",
        "NtQuerySystemEnvironmentValueEx",
        180,
    ),
    z("ZwQuerySystemInformation", "NtQuerySystemInformation", 181),
    z("ZwQuerySystemTime", "NtQuerySystemTime", 182),
    z("ZwQueryValueKey", "NtQueryValueKey", 185),
    z("ZwQueryVirtualMemory", "NtQueryVirtualMemory", 186),
    z(
        "ZwQueryVolumeInformationFile",
        "NtQueryVolumeInformationFile",
        187,
    ),
    z("ZwQueueApcThread", "NtQueueApcThread", 188),
    z("ZwRaiseHardError", "NtRaiseHardError", 190),
    z("ZwReadFile", "NtReadFile", 191),
    z("ZwReadFileScatter", "NtReadFileScatter", 192),
    z("ZwReadVirtualMemory", "NtReadVirtualMemory", 194),
    z(
        "ZwRegisterThreadTerminatePort",
        "NtRegisterThreadTerminatePort",
        195,
    ),
    z("ZwReleaseKeyedEvent", "NtReleaseKeyedEvent", 291),
    z("ZwReleaseMutant", "NtReleaseMutant", 196),
    z("ZwReleaseSemaphore", "NtReleaseSemaphore", 197),
    z("ZwRemoveIoCompletion", "NtRemoveIoCompletion", 198),
    z("ZwReplaceKey", "NtReplaceKey", 201),
    z("ZwReplyPort", "NtReplyPort", 202),
    z("ZwReplyWaitReceivePort", "NtReplyWaitReceivePort", 203),
    z("ZwRequestDeviceWakeup", "NtRequestDeviceWakeup", 206),
    z("ZwRequestWaitReplyPort", "NtRequestWaitReplyPort", 208),
    z("ZwRequestWakeupLatency", "NtRequestWakeupLatency", 209),
    z("ZwResetEvent", "NtResetEvent", 210),
    z("ZwResetWriteWatch", "NtResetWriteWatch", 211),
    z("ZwRestoreKey", "NtRestoreKey", 212),
    z("ZwResumeProcess", "NtResumeProcess", 213),
    z("ZwResumeThread", "NtResumeThread", 214),
    z("ZwSaveKey", "NtSaveKey", 215),
    z("ZwSecureConnectPort", "NtSecureConnectPort", 218),
    z("ZwSetContextThread", "NtSetContextThread", 221),
    z("ZwSetDebugFilterState", "NtSetDebugFilterState", 222),
    z(
        "ZwSetDefaultHardErrorPort",
        "NtSetDefaultHardErrorPort",
        223,
    ),
    z("ZwSetDefaultLocale", "NtSetDefaultLocale", 224),
    z("ZwSetEvent", "NtSetEvent", 228),
    z(
        "ZwSetInformationDebugObject",
        "NtSetInformationDebugObject",
        232,
    ),
    z("ZwSetInformationFile", "NtSetInformationFile", 233),
    z(
        "ZwSetInformationJobObject",
        "NtSetInformationJobObject",
        234,
    ),
    z("ZwSetInformationObject", "NtSetInformationObject", 236),
    z("ZwSetInformationProcess", "NtSetInformationProcess", 237),
    z("ZwSetInformationThread", "NtSetInformationThread", 238),
    z("ZwSetInformationToken", "NtSetInformationToken", 239),
    z("ZwSetIoCompletion", "NtSetIoCompletion", 241),
    z("ZwSetSecurityObject", "NtSetSecurityObject", 246),
    z(
        "ZwSetSystemEnvironmentValueEx",
        "NtSetSystemEnvironmentValueEx",
        248,
    ),
    z("ZwSetSystemInformation", "NtSetSystemInformation", 249),
    z("ZwSetSystemPowerState", "NtSetSystemPowerState", 250),
    z("ZwSetSystemTime", "NtSetSystemTime", 251),
    z(
        "ZwSetThreadExecutionState",
        "NtSetThreadExecutionState",
        252,
    ),
    z("ZwSetTimer", "NtSetTimer", 253),
    z("ZwSetUuidSeed", "NtSetUuidSeed", 255),
    z("ZwSetValueKey", "NtSetValueKey", 256),
    z(
        "ZwSetVolumeInformationFile",
        "NtSetVolumeInformationFile",
        257,
    ),
    z("ZwShutdownSystem", "NtShutdownSystem", 258),
    z(
        "ZwSignalAndWaitForSingleObject",
        "NtSignalAndWaitForSingleObject",
        259,
    ),
    z("ZwSuspendProcess", "NtSuspendProcess", 262),
    z("ZwSuspendThread", "NtSuspendThread", 263),
    z("ZwTerminateJobObject", "NtTerminateJobObject", 265),
    z("ZwTerminateProcess", "NtTerminateProcess", 266),
    z("ZwTerminateThread", "NtTerminateThread", 267),
    z("ZwTestAlert", "NtTestAlert", 268),
    z("ZwUnloadDriver", "NtUnloadDriver", 271),
    z("ZwUnloadKey", "NtUnloadKey", 272),
    z("ZwUnlockFile", "NtUnlockFile", 275),
    z("ZwUnlockVirtualMemory", "NtUnlockVirtualMemory", 276),
    z("ZwUnmapViewOfSection", "NtUnmapViewOfSection", 277),
    z("ZwWaitForKeyedEvent", "NtWaitForKeyedEvent", 292),
    z("ZwWaitForMultipleObjects", "NtWaitForMultipleObjects", 280),
    z("ZwWaitForSingleObject", "NtWaitForSingleObject", 281),
    z("ZwWriteFile", "NtWriteFile", 284),
    z("ZwWriteFileGather", "NtWriteFileGather", 285),
    z("ZwWriteVirtualMemory", "NtWriteVirtualMemory", 287),
    z("ZwYieldExecution", "NtYieldExecution", 288),
    z("ZwCreateKeyedEvent", "NtCreateKeyedEvent", 289),
];

/// The parameter count (number of register-width arguments) of each `Nt*` service.
///
/// The Nt* stub ABI passes the first four args in `r10, rdx, r8, r9` and the remainder on the
/// caller's stack; the *count* is what tells a non-trap transport (seL4 `Call` / SURT ring — which
/// must GATHER every argument into an IPC message, not leave the tail on the stack for the kernel to
/// read) how many stack args to marshal. Counts are the ReactOS `ntoskrnl/sysfuncs.lst` /
/// `ntdll.spec` prototype arities (the classic NT service signatures). Used by
/// [`crate::marshal`](../nt_ntdll/marshal/index.html)-style gatherers in `nt-ntdll`.
///
/// Names not present default to a conservative `MAX_STUB_ARGS` (all-register + full stack sweep)
/// via [`argc_of`]; the table below carries the exact arity for every entry in [`NT_SYSCALLS`].
pub const NT_ARGC: &[(&str, u8)] = &[
    ("NtAcceptConnectPort", 6),
    ("NtAccessCheck", 8),
    ("NtAccessCheckAndAuditAlarm", 11),
    ("NtAccessCheckByType", 11),
    ("NtAccessCheckByTypeResultList", 11),
    ("NtAddAtom", 3),
    ("NtAdjustGroupsToken", 6),
    ("NtAdjustPrivilegesToken", 6),
    ("NtAllocateLocallyUniqueId", 1),
    ("NtAllocateUserPhysicalPages", 3),
    ("NtAllocateVirtualMemory", 6),
    ("NtApphelpCacheControl", 2),
    ("NtAssignProcessToJobObject", 2),
    ("NtCallbackReturn", 3),
    ("NtCancelDeviceWakeupRequest", 1),
    ("NtCancelIoFile", 2),
    ("NtCancelTimer", 2),
    ("NtClearEvent", 1),
    ("NtClose", 1),
    ("NtCloseObjectAuditAlarm", 3),
    ("NtCompleteConnectPort", 1),
    ("NtConnectPort", 8),
    ("NtCreateDirectoryObject", 3),
    ("NtCreateEvent", 5),
    ("NtCreateFile", 11),
    ("NtCreateIoCompletion", 4),
    ("NtCreateJobObject", 3),
    ("NtCreateJobSet", 3),
    ("NtCreateKey", 7),
    ("NtCreateKeyedEvent", 4),
    ("NtCreateMailslotFile", 8),
    ("NtCreateMutant", 4),
    ("NtCreateNamedPipeFile", 14),
    ("NtCreatePagingFile", 4),
    ("NtCreatePort", 5),
    ("NtCreateProcess", 8),
    ("NtCreateProcessEx", 9),
    ("NtCreateSection", 7),
    ("NtCreateSemaphore", 5),
    ("NtCreateSymbolicLinkObject", 4),
    ("NtCreateThread", 8),
    ("NtCreateTimer", 4),
    ("NtCreateToken", 13),
    ("NtDelayExecution", 2),
    ("NtDeleteAtom", 1),
    ("NtDeleteKey", 1),
    ("NtDeleteObjectAuditAlarm", 3),
    ("NtDeleteValueKey", 2),
    ("NtDeviceIoControlFile", 10),
    ("NtDisplayString", 1),
    ("NtDuplicateObject", 7),
    ("NtDuplicateToken", 6),
    ("NtEnumerateKey", 6),
    ("NtEnumerateValueKey", 6),
    ("NtFilterToken", 6),
    ("NtFindAtom", 3),
    ("NtFlushBuffersFile", 2),
    ("NtFlushInstructionCache", 3),
    ("NtFlushKey", 1),
    ("NtFlushVirtualMemory", 4),
    ("NtFreeUserPhysicalPages", 3),
    ("NtFreeVirtualMemory", 4),
    ("NtFsControlFile", 10),
    ("NtGetContextThread", 2),
    ("NtGetDevicePowerState", 2),
    ("NtGetPlugPlayEvent", 4),
    ("NtGetWriteWatch", 7),
    ("NtImpersonateAnonymousToken", 1),
    ("NtImpersonateThread", 3),
    ("NtInitializeRegistry", 1),
    ("NtInitiatePowerAction", 4),
    ("NtIsProcessInJob", 2),
    ("NtIsSystemResumeAutomatic", 0),
    ("NtListenPort", 2),
    ("NtLoadDriver", 1),
    ("NtLoadKey", 2),
    ("NtLockFile", 10),
    ("NtLockVirtualMemory", 4),
    ("NtMakePermanentObject", 1),
    ("NtMakeTemporaryObject", 1),
    ("NtMapUserPhysicalPages", 3),
    ("NtMapUserPhysicalPagesScatter", 3),
    ("NtMapViewOfSection", 10),
    ("NtNotifyChangeDirectoryFile", 9),
    ("NtNotifyChangeKey", 10),
    ("NtOpenDirectoryObject", 3),
    ("NtOpenEvent", 3),
    ("NtOpenEventPair", 3),
    ("NtOpenFile", 6),
    ("NtOpenIoCompletion", 3),
    ("NtOpenJobObject", 3),
    ("NtOpenKey", 3),
    ("NtOpenMutant", 3),
    ("NtOpenObjectAuditAlarm", 12),
    ("NtOpenProcess", 4),
    ("NtOpenProcessToken", 3),
    ("NtOpenProcessTokenEx", 4),
    ("NtOpenSection", 3),
    ("NtOpenSemaphore", 3),
    ("NtOpenSymbolicLinkObject", 3),
    ("NtOpenThread", 4),
    ("NtOpenThreadToken", 4),
    ("NtOpenThreadTokenEx", 5),
    ("NtOpenTimer", 3),
    ("NtPlugPlayControl", 3),
    ("NtPowerInformation", 5),
    ("NtPrivilegeCheck", 3),
    ("NtPrivilegeObjectAuditAlarm", 6),
    ("NtPrivilegedServiceAuditAlarm", 5),
    ("NtProtectVirtualMemory", 5),
    ("NtPulseEvent", 2),
    ("NtQueryAttributesFile", 2),
    ("NtQueryDebugFilterState", 2),
    ("NtQueryDefaultLocale", 2),
    ("NtQueryDefaultUILanguage", 1),
    ("NtQueryDirectoryFile", 11),
    ("NtQueryDirectoryObject", 7),
    ("NtQueryEaFile", 9),
    ("NtQueryEvent", 5),
    ("NtQueryFullAttributesFile", 2),
    ("NtQueryInformationAtom", 5),
    ("NtQueryInformationFile", 5),
    ("NtQueryInformationJobObject", 5),
    ("NtQueryInformationProcess", 5),
    ("NtQueryInformationThread", 5),
    ("NtQueryInformationToken", 5),
    ("NtQueryInstallUILanguage", 1),
    ("NtQueryIoCompletion", 5),
    ("NtQueryKey", 5),
    ("NtQueryObject", 5),
    ("NtQueryPerformanceCounter", 2),
    ("NtQuerySection", 5),
    ("NtQuerySecurityObject", 5),
    ("NtQuerySemaphore", 5),
    ("NtQuerySymbolicLinkObject", 3),
    ("NtQuerySystemEnvironmentValueEx", 5),
    ("NtQuerySystemInformation", 4),
    ("NtQuerySystemTime", 1),
    ("NtQueryValueKey", 6),
    ("NtQueryVirtualMemory", 6),
    ("NtQueryVolumeInformationFile", 5),
    ("NtQueueApcThread", 5),
    ("NtRaiseHardError", 6),
    ("NtReadFile", 9),
    ("NtReadFileScatter", 9),
    ("NtReadVirtualMemory", 5),
    ("NtRegisterThreadTerminatePort", 1),
    ("NtReleaseKeyedEvent", 4),
    ("NtReleaseMutant", 2),
    ("NtReleaseSemaphore", 3),
    ("NtRemoveIoCompletion", 5),
    ("NtReplaceKey", 3),
    ("NtReplyPort", 2),
    ("NtReplyWaitReceivePort", 4),
    ("NtRequestDeviceWakeup", 1),
    ("NtRequestWaitReplyPort", 3),
    ("NtRequestWakeupLatency", 1),
    ("NtResetEvent", 2),
    ("NtResetWriteWatch", 3),
    ("NtRestoreKey", 3),
    ("NtResumeProcess", 1),
    ("NtResumeThread", 2),
    ("NtSaveKey", 2),
    ("NtSecureConnectPort", 9),
    ("NtSetContextThread", 2),
    ("NtSetDebugFilterState", 3),
    ("NtSetDefaultHardErrorPort", 1),
    ("NtSetDefaultLocale", 2),
    ("NtSetEvent", 2),
    ("NtSetInformationDebugObject", 5),
    ("NtSetInformationFile", 5),
    ("NtSetInformationJobObject", 4),
    ("NtSetInformationObject", 4),
    ("NtSetInformationProcess", 4),
    ("NtSetInformationThread", 4),
    ("NtSetInformationToken", 4),
    ("NtSetIoCompletion", 5),
    ("NtSetSecurityObject", 3),
    ("NtSetSystemEnvironmentValueEx", 5),
    ("NtSetSystemInformation", 3),
    ("NtSetSystemPowerState", 3),
    ("NtSetSystemTime", 2),
    ("NtSetThreadExecutionState", 2),
    ("NtSetTimer", 7),
    ("NtSetUuidSeed", 1),
    ("NtSetValueKey", 6),
    ("NtSetVolumeInformationFile", 5),
    ("NtShutdownSystem", 1),
    ("NtSignalAndWaitForSingleObject", 4),
    ("NtSuspendProcess", 1),
    ("NtSuspendThread", 2),
    ("NtTerminateJobObject", 2),
    ("NtTerminateProcess", 2),
    ("NtTerminateThread", 2),
    ("NtTestAlert", 0),
    ("NtUnloadDriver", 1),
    ("NtUnloadKey", 1),
    ("NtUnlockFile", 5),
    ("NtUnlockVirtualMemory", 4),
    ("NtUnmapViewOfSection", 2),
    ("NtWaitForKeyedEvent", 4),
    ("NtWaitForMultipleObjects", 5),
    ("NtWaitForSingleObject", 3),
    ("NtWriteFile", 9),
    ("NtWriteFileGather", 9),
    ("NtWriteVirtualMemory", 5),
    ("NtYieldExecution", 0),
];

/// The maximum stub-arg count our marshaller supports (the widest NT service, `NtCreateNamedPipeFile`
/// = 14). A gatherer that lacks an exact arity uses this as a conservative sweep bound.
pub const MAX_STUB_ARGS: u8 = 14;

/// The parameter count of an `Nt*`/`Zw*` service (register-width args). Falls back to
/// [`MAX_STUB_ARGS`] for an unknown name (conservative — sweep every possible arg). A `Zw*` name
/// resolves to the arity of its underlying `Nt*` service.
pub fn argc_of(name: &str) -> u8 {
    if let Some(&(_, c)) = NT_ARGC.iter().find(|(n, _)| *n == name) {
        return c;
    }
    if let Some(z) = ZW_ALIASES.iter().find(|z| z.zw_name == name) {
        if let Some(&(_, c)) = NT_ARGC.iter().find(|(n, _)| *n == z.nt_name) {
            return c;
        }
    }
    MAX_STUB_ARGS
}

/// `const` helper for [`NT_SYSCALLS`] rows.
const fn n(name: &'static str, ssn: u32) -> NtSyscall {
    NtSyscall { name, ssn }
}

/// `const` helper for [`ZW_ALIASES`] rows.
const fn z(zw_name: &'static str, nt_name: &'static str, ssn: u32) -> ZwAlias {
    ZwAlias {
        zw_name,
        nt_name,
        ssn,
    }
}

/// Look up an `Nt*` (or aliased `Zw*`) export's SSN by name. Returns `None` for an unknown name.
///
/// A `Zw*` name resolves to the same SSN as its underlying `Nt*` service (per [`ZW_ALIASES`]).
pub fn ssn_of(name: &str) -> Option<u32> {
    if let Some(e) = NT_SYSCALLS.iter().find(|e| e.name == name) {
        return Some(e.ssn);
    }
    ZW_ALIASES.iter().find(|z| z.zw_name == name).map(|z| z.ssn)
}

/// Reverse lookup: the canonical `Nt*` name for an SSN (first `Nt*` match). Returns `None` if no
/// `Nt*` service in the table uses that SSN.
pub fn name_of(ssn: u32) -> Option<&'static str> {
    NT_SYSCALLS.iter().find(|e| e.ssn == ssn).map(|e| e.name)
}

#[cfg(test)]
mod tests;
