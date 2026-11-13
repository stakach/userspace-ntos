//! Pinned LiberNT source declarations marked `-stub` and unused by installed PE imports.
//!
//! Each named entry raises an explicit unsupported status. They are kept as
//! source-level ABI declarations so the installed image can resolve its full
//! export table without pretending that an unimplemented operation succeeded.

const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

macro_rules! unsupported_export {
    ($symbol:ident, $name:literal) => {
        #[export_name = $name]
        pub unsafe extern "system" fn $symbol() -> ! {
            // SAFETY: this source declaration has no implementation in pinned LiberNT.
            unsafe { crate::exports::rtl_raise_status(STATUS_NOT_IMPLEMENTED) };
            loop {
                core::hint::spin_loop();
            }
        }
    };
}

unsupported_export!(source_stub_000, "ExpInterlockedPopEntrySListEnd8");
unsupported_export!(source_stub_001, "ExpInterlockedPopEntrySListFault8");
unsupported_export!(source_stub_002, "ExpInterlockedPopEntrySListResume8");
unsupported_export!(source_stub_003, "LdrGetKnownDllSectionHandle");
unsupported_export!(source_stub_004, "LdrHotPatchRoutine");
unsupported_export!(source_stub_005, "NtdllDefWindowProc_A");
unsupported_export!(source_stub_006, "NtdllDefWindowProc_W");
unsupported_export!(source_stub_007, "NtdllDialogWndProc_A");
unsupported_export!(source_stub_008, "NtdllDialogWndProc_W");
unsupported_export!(source_stub_009, "RtlAddCompoundAce");
unsupported_export!(source_stub_010, "RtlAllocateMemoryBlockLookaside");
unsupported_export!(source_stub_011, "RtlAllocateMemoryZone");
unsupported_export!(source_stub_012, "RtlBarrier");
unsupported_export!(source_stub_013, "RtlBarrierForDelete");
unsupported_export!(source_stub_014, "RtlCleanUpTEBLangLists");
unsupported_export!(source_stub_015, "RtlCloneUserProcess");
unsupported_export!(source_stub_016, "RtlCmDecodeMemIoResource");
unsupported_export!(source_stub_017, "RtlCmEncodeMemIoResource");
unsupported_export!(source_stub_018, "RtlCommitDebugInfo");
unsupported_export!(source_stub_019, "RtlCompareAltitudes");
unsupported_export!(source_stub_020, "RtlCompleteProcessCloning");
unsupported_export!(source_stub_021, "RtlConnectToSm");
unsupported_export!(source_stub_022, "RtlCreateEnvironmentEx");
unsupported_export!(source_stub_023, "RtlCreateMemoryBlockLookaside");
unsupported_export!(source_stub_024, "RtlCreateMemoryZone");
unsupported_export!(source_stub_025, "RtlDeCommitDebugInfo");
unsupported_export!(source_stub_026, "RtlDebugPrintTimes");
unsupported_export!(source_stub_027, "RtlDeleteBarrier");
unsupported_export!(source_stub_028, "RtlDeregisterSecureMemoryCacheCallback");
unsupported_export!(source_stub_029, "RtlDestroyMemoryBlockLookaside");
unsupported_export!(source_stub_030, "RtlDestroyMemoryZone");
unsupported_export!(
    source_stub_031,
    "RtlEnableEarlyCriticalSectionEventCreation"
);
unsupported_export!(source_stub_032, "RtlExtendMemoryBlockLookaside");
unsupported_export!(source_stub_033, "RtlExtendMemoryZone");
unsupported_export!(source_stub_034, "RtlFindClosestEncodableLength");
unsupported_export!(source_stub_035, "RtlFreeMemoryBlockLookaside");
unsupported_export!(source_stub_036, "RtlGetFileMUIPath");
unsupported_export!(source_stub_037, "RtlGetParentLocaleName");
unsupported_export!(source_stub_038, "RtlGetThreadLangIdByIndex");
unsupported_export!(source_stub_039, "RtlGetUILanguageInfo");
unsupported_export!(source_stub_040, "RtlHeapTrkInitialize");
unsupported_export!(source_stub_041, "RtlImpersonateSelfEx");
unsupported_export!(source_stub_042, "RtlInitBarrier");
unsupported_export!(source_stub_043, "RtlInitializeAtomPackage");
unsupported_export!(source_stub_044, "RtlIoDecodeMemIoResource");
unsupported_export!(source_stub_045, "RtlIoEncodeMemIoResource");
unsupported_export!(source_stub_046, "RtlLockCurrentThread");
unsupported_export!(source_stub_047, "RtlLockMemoryBlockLookaside");
unsupported_export!(source_stub_048, "RtlLockMemoryZone");
unsupported_export!(source_stub_049, "RtlLockModuleSection");
unsupported_export!(source_stub_050, "RtlLogStackBackTrace");
unsupported_export!(source_stub_051, "RtlNtdllName");
unsupported_export!(source_stub_052, "RtlPrepareForProcessCloning");
unsupported_export!(source_stub_053, "RtlQueryCriticalSectionOwner");
unsupported_export!(source_stub_054, "RtlQueryElevationFlags");
unsupported_export!(source_stub_055, "RtlQueryModuleInformation");
unsupported_export!(source_stub_056, "RtlQueryProcessBackTraceInformation");
unsupported_export!(source_stub_057, "RtlQueryProcessLockInformation");
unsupported_export!(source_stub_058, "RtlRegisterThreadWithCsrss");
unsupported_export!(source_stub_059, "RtlReportException");
unsupported_export!(source_stub_060, "RtlResetMemoryBlockLookaside");
unsupported_export!(source_stub_061, "RtlResetMemoryZone");
unsupported_export!(source_stub_062, "RtlSendMsgToSm");
unsupported_export!(source_stub_063, "RtlSetDynamicTimeZoneInformation");
unsupported_export!(source_stub_064, "RtlSetEnvironmentVar");
unsupported_export!(source_stub_065, "RtlSetProcessDebugInformation");
unsupported_export!(source_stub_066, "RtlSidHashInitialize");
unsupported_export!(source_stub_067, "RtlSidHashLookup");
unsupported_export!(source_stub_068, "RtlSidIsHigherLevel");
unsupported_export!(source_stub_069, "RtlUnlockCurrentThread");
unsupported_export!(source_stub_070, "RtlUnlockMemoryBlockLookaside");
unsupported_export!(source_stub_071, "RtlUnlockMemoryZone");
unsupported_export!(source_stub_072, "RtlUnlockModuleSection");
unsupported_export!(source_stub_073, "RtlUpdateClonedCriticalSection");
unsupported_export!(source_stub_074, "RtlUpdateClonedSRWLock");
unsupported_export!(source_stub_075, "RtlWerpReportException");
unsupported_export!(source_stub_076, "RtlWow64CallFunction64");
unsupported_export!(source_stub_077, "RtlWow64LogMessageInEventLogger");
unsupported_export!(source_stub_078, "RtlpCheckDynamicTimeZoneInformation");
unsupported_export!(source_stub_079, "RtlpCleanupRegistryKeys");
unsupported_export!(source_stub_080, "RtlpConvertCultureNamesToLCIDs");
unsupported_export!(source_stub_081, "RtlpConvertLCIDsToCultureNames");
unsupported_export!(source_stub_082, "RtlpCreateProcessRegistryInfo");
unsupported_export!(source_stub_083, "RtlpGetLCIDFromLangInfoNode");
unsupported_export!(source_stub_084, "RtlpGetNameFromLangInfoNode");
unsupported_export!(source_stub_085, "RtlpGetSystemDefaultUILanguage");
unsupported_export!(source_stub_086, "RtlpGetUserOrMachineUILanguage4NLS");
unsupported_export!(source_stub_087, "RtlpInitializeLangRegistryInfo");
unsupported_export!(source_stub_088, "RtlpIsQualifiedLanguage");
unsupported_export!(source_stub_089, "RtlpLoadMachineUIByPolicy");
unsupported_export!(source_stub_090, "RtlpLoadUserUIByPolicy");
unsupported_export!(source_stub_091, "RtlpMuiFreeLangRegistryInfo");
unsupported_export!(source_stub_092, "RtlpMuiRegCreateRegistryInfo");
unsupported_export!(source_stub_093, "RtlpMuiRegFreeRegistryInfo");
unsupported_export!(source_stub_094, "RtlpMuiRegLoadRegistryInfo");
unsupported_export!(source_stub_095, "RtlpQueryDefaultUILanguage");
unsupported_export!(source_stub_096, "RtlpQueryProcessDebugInformationFromWow64");
unsupported_export!(source_stub_097, "RtlpRefreshCachedUILanguage");
unsupported_export!(source_stub_098, "RtlpSetInstallLanguage");
unsupported_export!(source_stub_099, "RtlpSetPreferredUILanguages");
unsupported_export!(source_stub_100, "RtlpVerifyAndCommitUILanguageSettings");
unsupported_export!(source_stub_101, "TpCaptureCaller");
unsupported_export!(source_stub_102, "TpCheckTerminateWorker");
unsupported_export!(source_stub_103, "TpDbgDumpHeapUsage");
unsupported_export!(source_stub_104, "TpDbgSetLogRoutine");
unsupported_export!(source_stub_105, "WinSqmAddToStreamEx");
unsupported_export!(source_stub_106, "WinSqmSetDWORD");
unsupported_export!(source_stub_107, "_vswprintf");

#[used]
pub static SOURCE_STUB_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = source_stub_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn source_stub_export_anchor() {
    core::hint::black_box([
        source_stub_000 as *const () as usize,
        source_stub_001 as *const () as usize,
        source_stub_002 as *const () as usize,
        source_stub_003 as *const () as usize,
        source_stub_004 as *const () as usize,
        source_stub_005 as *const () as usize,
        source_stub_006 as *const () as usize,
        source_stub_007 as *const () as usize,
        source_stub_008 as *const () as usize,
        source_stub_009 as *const () as usize,
        source_stub_010 as *const () as usize,
        source_stub_011 as *const () as usize,
        source_stub_012 as *const () as usize,
        source_stub_013 as *const () as usize,
        source_stub_014 as *const () as usize,
        source_stub_015 as *const () as usize,
        source_stub_016 as *const () as usize,
        source_stub_017 as *const () as usize,
        source_stub_018 as *const () as usize,
        source_stub_019 as *const () as usize,
        source_stub_020 as *const () as usize,
        source_stub_021 as *const () as usize,
        source_stub_022 as *const () as usize,
        source_stub_023 as *const () as usize,
        source_stub_024 as *const () as usize,
        source_stub_025 as *const () as usize,
        source_stub_026 as *const () as usize,
        source_stub_027 as *const () as usize,
        source_stub_028 as *const () as usize,
        source_stub_029 as *const () as usize,
        source_stub_030 as *const () as usize,
        source_stub_031 as *const () as usize,
        source_stub_032 as *const () as usize,
        source_stub_033 as *const () as usize,
        source_stub_034 as *const () as usize,
        source_stub_035 as *const () as usize,
        source_stub_036 as *const () as usize,
        source_stub_037 as *const () as usize,
        source_stub_038 as *const () as usize,
        source_stub_039 as *const () as usize,
        source_stub_040 as *const () as usize,
        source_stub_041 as *const () as usize,
        source_stub_042 as *const () as usize,
        source_stub_043 as *const () as usize,
        source_stub_044 as *const () as usize,
        source_stub_045 as *const () as usize,
        source_stub_046 as *const () as usize,
        source_stub_047 as *const () as usize,
        source_stub_048 as *const () as usize,
        source_stub_049 as *const () as usize,
        source_stub_050 as *const () as usize,
        source_stub_051 as *const () as usize,
        source_stub_052 as *const () as usize,
        source_stub_053 as *const () as usize,
        source_stub_054 as *const () as usize,
        source_stub_055 as *const () as usize,
        source_stub_056 as *const () as usize,
        source_stub_057 as *const () as usize,
        source_stub_058 as *const () as usize,
        source_stub_059 as *const () as usize,
        source_stub_060 as *const () as usize,
        source_stub_061 as *const () as usize,
        source_stub_062 as *const () as usize,
        source_stub_063 as *const () as usize,
        source_stub_064 as *const () as usize,
        source_stub_065 as *const () as usize,
        source_stub_066 as *const () as usize,
        source_stub_067 as *const () as usize,
        source_stub_068 as *const () as usize,
        source_stub_069 as *const () as usize,
        source_stub_070 as *const () as usize,
        source_stub_071 as *const () as usize,
        source_stub_072 as *const () as usize,
        source_stub_073 as *const () as usize,
        source_stub_074 as *const () as usize,
        source_stub_075 as *const () as usize,
        source_stub_076 as *const () as usize,
        source_stub_077 as *const () as usize,
        source_stub_078 as *const () as usize,
        source_stub_079 as *const () as usize,
        source_stub_080 as *const () as usize,
        source_stub_081 as *const () as usize,
        source_stub_082 as *const () as usize,
        source_stub_083 as *const () as usize,
        source_stub_084 as *const () as usize,
        source_stub_085 as *const () as usize,
        source_stub_086 as *const () as usize,
        source_stub_087 as *const () as usize,
        source_stub_088 as *const () as usize,
        source_stub_089 as *const () as usize,
        source_stub_090 as *const () as usize,
        source_stub_091 as *const () as usize,
        source_stub_092 as *const () as usize,
        source_stub_093 as *const () as usize,
        source_stub_094 as *const () as usize,
        source_stub_095 as *const () as usize,
        source_stub_096 as *const () as usize,
        source_stub_097 as *const () as usize,
        source_stub_098 as *const () as usize,
        source_stub_099 as *const () as usize,
        source_stub_100 as *const () as usize,
        source_stub_101 as *const () as usize,
        source_stub_102 as *const () as usize,
        source_stub_103 as *const () as usize,
        source_stub_104 as *const () as usize,
        source_stub_105 as *const () as usize,
        source_stub_106 as *const () as usize,
        source_stub_107 as *const () as usize,
    ]);
}
