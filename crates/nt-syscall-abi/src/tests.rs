//! Host tests for the shared SSN ABI table.

use super::*;

#[test]
fn native_request_keeps_exact_arguments_when_nested_ipc_reuses_receive_buffer() {
    let mut receive_words = [0u64; NT_NATIVE_REQUEST_WORDS];
    receive_words[4] = 1; // KeyValueFullInformation
    receive_words[5] = 0x1000_1234; // output buffer
    receive_words[6] = 2048;
    receive_words[7] = 0x1000_5678; // result length
    let request = NativeSyscallRequest::capture(
        native_syscall_message_info(6),
        [77, 0x7000, 0xc, 14],
        |index| receive_words[index],
    )
    .unwrap();

    // A provider Call on the root TCB reuses the mutable IPC bank before NT dispatch.
    receive_words[4] = 0x24;
    receive_words[5..8].fill(u64::MAX);
    assert_eq!(request.length(), 8);
    assert_eq!(request.argument(0), Some(0xc));
    assert_eq!(request.argument(1), Some(14));
    assert_eq!(request.argument(2), Some(1));
    assert_eq!(request.argument(3), Some(0x1000_1234));
    assert_eq!(request.argument(4), Some(2048));
    assert_eq!(request.argument(5), Some(0x1000_5678));
    assert_eq!(request.argument(6), None);
    assert!(NativeSyscallRequest::capture(0, [77, 0, 0, 0], |_| unreachable!()).is_none());
}

/// The exact count of `Nt*` services in the shared table: the current hosted ReactOS import set,
/// ntdll-internal services (`NtSecureConnectPort`, `NtCallbackReturn`), and registry hive
/// load/unload variants that route to real executive CM functionality.
const REQUIRED_NT_COUNT: usize = 428;
const REQUIRED_ZW_COUNT: usize = 428;

#[test]
fn released_libernt_audit_exports_preserve_every_stack_argument() {
    // ReactOS sysfuncs.lst and ntifs.template.h specify 16, 16, and 17 arguments.
    // The final out-pointer must survive both the native Call capture and Zw aliasing.
    for (name, alias, ssn, argc) in [
        ("NtAccessCheckByTypeAndAuditAlarm", "ZwAccessCheckByTypeAndAuditAlarm", 4, 16),
        ("NtAccessCheckByTypeResultListAndAuditAlarm", "ZwAccessCheckByTypeResultListAndAuditAlarm", 6, 16),
        ("NtAccessCheckByTypeResultListAndAuditAlarmByHandle", "ZwAccessCheckByTypeResultListAndAuditAlarmByHandle", 7, 17),
    ] {
        assert_eq!(ssn_of(name), Some(ssn));
        assert_eq!(exact_argc_of(name), Some(argc));
        assert_eq!(ssn_of(alias), Some(ssn));
        assert_eq!(exact_argc_of(alias), Some(argc));
        let mut args = [0u64; 17];
        for (i, arg) in args.iter_mut().take(argc as usize).enumerate() {
            *arg = i as u64 + 0x100;
        }
        let mut words = [0u64; NT_NATIVE_REQUEST_WORDS];
        words[0] = ssn as u64;
        words[1] = 0x1234;
        words[2..2 + argc as usize].copy_from_slice(&args[..argc as usize]);
        let request = NativeSyscallRequest::capture(
            native_syscall_message_info(argc),
            words[..4].try_into().unwrap(),
            |index| words[index],
        ).unwrap();
        assert_eq!(request.length(), native_syscall_request_len(argc) as usize);
        for (index, arg) in args.iter().take(argc as usize).enumerate() {
            assert_eq!(request.argument(index), Some(*arg));
        }
    }
}

#[test]
fn released_libernt_native_export_extension_has_exact_bounds_and_arities() {
    // Pinned source: LiberNT 8e478a22 dll/ntdll/def/ntdll.spec.
    assert_eq!(LIBERNT_FULL_EXPORT_SSN_BASE, 0x400);
    assert_eq!(LIBERNT_FULL_EXPORT_SSN_BASE + 180, 0x4b4);
    assert!(LIBERNT_FULL_EXPORT_SSN_BASE > LIBERNT_BASE_SSN + 11);
    assert!(LIBERNT_FULL_EXPORT_SSN_BASE + 179 < 0x1000);
    let new_services = NT_SYSCALLS.iter().filter(|e| {
        (LIBERNT_FULL_EXPORT_SSN_BASE..LIBERNT_FULL_EXPORT_SSN_BASE + 180).contains(&e.ssn)
    });
    assert_eq!(new_services.clone().count(), 180);
    for service in new_services {
        assert!(exact_argc_of(service.name).is_some(), "{} lacks exact arity", service.name);
        let alias = ZW_ALIASES.iter().find(|alias| alias.nt_name == service.name)
            .unwrap_or_else(|| panic!("{} lacks Zw alias", service.name));
        assert_eq!(alias.ssn, service.ssn);
        assert_eq!(exact_argc_of(alias.zw_name), exact_argc_of(service.name));
    }
    for (name, arity) in [
        ("NtCreateThreadEx", 11),
        ("NtAllocateVirtualMemoryEx", 7),
        ("NtAlpcConnectPortEx", 11),
        ("NtWaitForWorkViaWorkerFactory", 2),
        ("NtQueryPortInformationProcess", 0),
    ] {
        assert_eq!(exact_argc_of(name), Some(arity), "{name}");
    }
}

/// Imports read from the pinned LiberNT 8e478a22 kernel32.dll and advapi32.dll. The
/// arities come from Wine ntdll.spec, except the private-namespace entries from the
/// ReactOS ntdll.spec and NtTraceEvent from ReactOS exfuncs.h.
#[test]
fn libernt_kernel32_and_advapi32_native_imports_have_exact_abi() {
    let services = [
        ("NtRenameKey", 200, 2),
        ("NtSetTimerResolution", 254, 3),
        ("NtTraceEvent", 269, 4),
        ("NtCancelIoFileEx", 0x300, 3),
        ("NtCompareObjects", 0x301, 2),
        ("NtCreateLowBoxToken", 0x302, 9),
        ("NtCreatePrivateNamespace", 0x303, 4),
        ("NtCreateUserProcess", 0x304, 11),
        ("NtDeletePrivateNamespace", 0x305, 1),
        ("NtGetNlsSectionPtr", 0x306, 5),
        ("NtOpenPrivateNamespace", 0x307, 4),
        ("NtQuerySystemInformationEx", 0x308, 6),
        ("NtRemoveIoCompletionEx", 0x309, 6),
        ("NtSetInformationVirtualMemory", 0x30a, 6),
        ("NtTraceControl", 0x30b, 6),
    ];
    for (name, ssn, argc) in services {
        assert_eq!(ssn_of(name), Some(ssn), "missing {name}");
        assert_eq!(exact_argc_of(name), Some(argc), "wrong arity for {name}");
        assert_eq!(name_of(ssn), Some(name), "wrong service at {ssn:#x}");
        let alias = ZW_ALIASES.iter().find(|alias| alias.nt_name == name)
            .unwrap_or_else(|| panic!("missing Zw alias for {name}"));
        assert!(alias.zw_name.starts_with("Zw"));
        assert_eq!(&alias.zw_name[2..], &name[2..]);
        assert_eq!(ssn_of(alias.zw_name), Some(ssn));
        assert_eq!(exact_argc_of(alias.zw_name), Some(argc));
    }
}

#[test]
fn libernt_private_native_numbers_cannot_enter_win32k_shadow_dispatch() {
    // The executive uses 0x1000 as its win32k shadow-table boundary even for
    // native-call messages after it normalizes them into UnknownSyscall frames.
    // ReactOS sysfuncs.lst occupies SSNs 0..=295.
    assert!(LIBERNT_BASE_SSN > 295);
    assert!(LIBERNT_BASE_SSN + 11 < 0x1000);
    let private = NT_SYSCALLS.iter().filter(|service| {
        (LIBERNT_BASE_SSN..LIBERNT_BASE_SSN + 12).contains(&service.ssn)
    });
    assert_eq!(private.clone().count(), 12);
    for service in private {
        assert!(service.ssn < 0x1000, "{} collides with win32k", service.name);
    }
}

#[test]
fn libernt_smss_alpc_imports_have_distinct_native_services() {
    let services = [
        ("NtAlpcAcceptConnectPort", ALPC_SSN_BASE, 9),
        ("NtAlpcConnectPort", ALPC_SSN_BASE + 1, 11),
        ("NtAlpcCreatePort", ALPC_SSN_BASE + 2, 3),
        ("NtAlpcSendWaitReceivePort", ALPC_SSN_BASE + 3, 8),
    ];
    for (name, ssn, argc) in services {
        assert_eq!(ssn_of(name), Some(ssn), "missing {name}");
        assert_eq!(exact_argc_of(name), Some(argc), "wrong arity for {name}");
        assert_eq!(name_of(ssn), Some(name), "wrong service at {ssn:#x}");
    }
}

#[test]
fn required_counts() {
    assert_eq!(NT_SYSCALLS.len(), REQUIRED_NT_COUNT);
    assert_eq!(ZW_ALIASES.len(), REQUIRED_ZW_COUNT);
}

#[test]
fn no_duplicate_ssns() {
    // No two Nt* services may share an SSN (a shared SSN would misdispatch).
    for (i, a) in NT_SYSCALLS.iter().enumerate() {
        for b in &NT_SYSCALLS[i + 1..] {
            assert_ne!(
                a.ssn, b.ssn,
                "duplicate SSN {}: {} / {}",
                a.ssn, a.name, b.name
            );
        }
    }
}

#[test]
fn no_duplicate_names() {
    for (i, a) in NT_SYSCALLS.iter().enumerate() {
        for b in &NT_SYSCALLS[i + 1..] {
            assert_ne!(a.name, b.name, "duplicate name {}", a.name);
        }
    }
}

#[test]
fn sorted_by_ssn() {
    // The table is maintained sorted by SSN (matches sysfuncs.lst order — easy diffing).
    for w in NT_SYSCALLS.windows(2) {
        assert!(
            w[0].ssn < w[1].ssn,
            "not sorted at {} / {}",
            w[0].name,
            w[1].name
        );
    }
}

#[test]
fn round_trip_name_ssn_name() {
    // name -> ssn -> name is the identity for every unique-SSN Nt* entry.
    for e in NT_SYSCALLS {
        let ssn = ssn_of(e.name).expect("name must resolve");
        assert_eq!(ssn, e.ssn);
        assert_eq!(name_of(ssn), Some(e.name));
    }
}

#[test]
fn zw_aliases_resolve_to_underlying_nt_ssn() {
    for z in ZW_ALIASES {
        // The Zw* export resolves to the same SSN as its underlying Nt* service.
        assert_eq!(ssn_of(z.zw_name), Some(z.ssn));
        // ...and where the underlying Nt* is itself in our required set, the SSNs agree.
        if let Some(nt) = NT_SYSCALLS.iter().find(|e| e.name == z.nt_name) {
            assert_eq!(nt.ssn, z.ssn, "Zw {} vs Nt {}", z.zw_name, z.nt_name);
        }
    }
}

#[test]
fn zw_aliases_cover_every_exported_nt_service() {
    assert_eq!(ZW_ALIASES.len(), NT_SYSCALLS.len());
    for nt in NT_SYSCALLS {
        let zw = ZW_ALIASES
            .iter()
            .find(|z| z.nt_name == nt.name)
            .unwrap_or_else(|| panic!("missing Zw alias for {}", nt.name));
        assert_eq!(zw.ssn, nt.ssn);
        assert_eq!(&zw.zw_name.as_bytes()[2..], &nt.name.as_bytes()[2..]);
    }
}

#[test]
fn unknown_name_is_none() {
    assert_eq!(ssn_of("NtNotARealService"), None);
    assert_eq!(ssn_of(""), None);
}

/// The load-bearing test: SSN anchors MUST match the ReactOS `sysfuncs.lst`-derived numbering the
/// NT executive already dispatches on (`components/ntos-executive` `SSN_NT_*` consts). If any of
/// these drift, owning ntdll stops being zero-churn on the executive. ~15 anchors spanning the
/// range; values cross-checked against both `sysfuncs.lst` (line index) and the executive consts.
#[test]
fn ssn_anchors_match_reactos_and_executive() {
    // (name, expected SSN, executive const it matches)
    let anchors: &[(&str, u32)] = &[
        ("NtAcceptConnectPort", 0),       // SSN_NT_ACCEPT_CONNECT_PORT = 0
        ("NtAddAtom", 8),                 // SSN_NT_ADD_ATOM = 8
        ("NtAdjustPrivilegesToken", 12),  // SSN_NT_ADJUST_PRIV_TOKEN = 12
        ("NtAllocateVirtualMemory", 18),  // SSN_NT_ALLOCATE_VM = 0x12
        ("NtCallbackReturn", 22),         // SSN_NT_CALLBACK_RETURN = 22
        ("NtClose", 27),                  // SSN_NT_CLOSE = 27
        ("NtContinue", 34),               // SSN_NT_CONTINUE = 34
        ("NtCreateFile", 39),             // SSN_NT_CREATE_FILE = 39
        ("NtCreatePort", 48),             // SSN_NT_CREATE_PORT = 48
        ("NtCreateSection", 52),          // SSN_NT_CREATE_SECTION = 52
        ("NtDelayExecution", 61),         // SSN_NT_DELAY_EXECUTION = 61
        ("NtFsControlFile", 88),          // SSN_NT_FS_CONTROL_FILE = 88
        ("NtGetPlugPlayEvent", 91),       // SSN_NT_GET_PLUG_PLAY_EVENT = 91
        ("NtOpenFile", 122),              // (loader hot path)
        ("NtOpenIoCompletion", 123),      // SSN_NT_OPEN_IO_COMPLETION = 123
        ("NtOpenKey", 125),               // SSN_NT_OPEN_KEY = 125
        ("NtLoadKey", 102),               // SSN_NT_LOAD_KEY = 102
        ("NtLoadKey2", 103),              // SSN_NT_LOAD_KEY2 = 103
        ("NtLoadKeyEx", 104),             // SSN_NT_LOAD_KEY_EX = 104
        ("NtPlugPlayControl", 138),       // SSN_NT_PLUG_PLAY_CONTROL = 138
        ("NtProtectVirtualMemory", 143),  // SSN_NT_PROTECT_VM = 143
        ("NtQueryDebugFilterState", 148), // SSN_NT_QUERY_DEBUG_FILTER_STATE = 148
        ("NtQueryIoCompletion", 166),     // SSN_NT_QUERY_IO_COMPLETION = 166
        ("NtQueryMutant", 169),           // SSN_NT_QUERY_MUTANT = 169
        ("NtQueryQuotaInformationFile", 174),
        ("NtQuerySystemInformation", 181), // SSN_NT_QUERY_SYSTEM_INFO = 0xb5
        ("NtQuerySystemTime", 182),        // SSN_NT_QUERY_SYSTEM_TIME_SVC = 182
        ("NtQueryTimer", 183),             // SSN_NT_QUERY_TIMER = 183
        ("NtResumeProcess", 213),          // SSN_NT_RESUME_PROCESS = 213
        ("NtQueryValueKey", 185),          // SSN_NT_QUERY_VALUE_KEY = 185
        ("NtRaiseException", 189),         // SSN_NT_RAISE_EXCEPTION = 189
        ("NtSetDebugFilterState", 222),    // SSN_NT_SET_DEBUG_FILTER_STATE = 222
        ("NtSetEaFile", 227),
        ("NtSetQuotaInformationFile", 245),
        ("NtSetSystemPowerState", 250), // SSN_NT_SET_SYSTEM_POWER_STATE = 250
        ("NtSetUuidSeed", 255),         // SSN_NT_SET_UUID_SEED = 255
        ("NtSetValueKey", 256),         // SSN_NT_SET_VALUE_KEY = 256
        ("NtSuspendProcess", 262),      // SSN_NT_SUSPEND_PROCESS = 262
        ("NtTerminateProcess", 266),    // SSN_NT_TERMINATE_PROCESS = 266
        ("NtUnloadKey", 272),           // SSN_NT_UNLOAD_KEY = 272
        ("NtUnloadKey2", 273),          // SSN_NT_UNLOAD_KEY2 = 273
        ("NtUnloadKeyEx", 274),         // SSN_NT_UNLOAD_KEY_EX = 274
        ("NtWaitForSingleObject", 281), // (core sync)
    ];
    for &(name, expect) in anchors {
        assert_eq!(ssn_of(name), Some(expect), "anchor {} SSN drifted", name);
    }
}

#[test]
fn every_service_has_an_exact_arity() {
    // The marshaller must know how many stack args each service carries; every entry in the SSN
    // table must have an EXACT arity (not the MAX_STUB_ARGS fallback), else a non-trap transport
    // would over- or under-gather.
    for e in NT_SYSCALLS {
        assert!(
            NT_ARGC.iter().any(|(n, _)| *n == e.name),
            "missing arity for {}",
            e.name
        );
        let c = argc_of(e.name);
        assert!(
            c <= MAX_STUB_ARGS,
            "arity of {} exceeds MAX_STUB_ARGS",
            e.name
        );
    }
    assert_eq!(NT_ARGC.len(), NT_SYSCALLS.len());
}

#[test]
fn arity_anchors_and_fallback() {
    assert_eq!(argc_of("NtClose"), 1);
    assert_eq!(argc_of("NtCallbackReturn"), 3);
    assert_eq!(argc_of("NtContinue"), 2);
    assert_eq!(argc_of("NtCreateFile"), 11);
    assert_eq!(argc_of("NtRaiseException"), 3);
    assert_eq!(argc_of("NtWaitForSingleObject"), 3);
    assert_eq!(argc_of("NtCreateNamedPipeFile"), 14); // the widest
    assert_eq!(exact_argc_of("NtCreateThreadEx"), Some(11));
    assert_eq!(argc_of("NtLoadKey"), 2);
    assert_eq!(argc_of("NtLoadKey2"), 3);
    assert_eq!(argc_of("NtLoadKeyEx"), 4);
    assert_eq!(argc_of("NtUnloadKey"), 1);
    assert_eq!(argc_of("NtUnloadKey2"), 2);
    assert_eq!(argc_of("NtUnloadKeyEx"), 2);
    assert_eq!(argc_of("NtQueryDefaultUILanguage"), 1);
    assert_eq!(argc_of("NtQueryInstallUILanguage"), 1);
    assert_eq!(argc_of("NtQueryMutant"), 5);
    assert_eq!(argc_of("NtQueryTimer"), 5);
    assert_eq!(argc_of("NtSetDefaultUILanguage"), 1);
    // Zw* inherits its underlying Nt*'s arity.
    assert_eq!(argc_of("ZwSetValueKey"), argc_of("NtSetValueKey"));
    assert_eq!(argc_of("ZwLoadKeyEx"), argc_of("NtLoadKeyEx"));
    assert_eq!(argc_of("ZwUnloadKey2"), argc_of("NtUnloadKey2"));
    // Unknown falls back conservatively to MAX_STUB_ARGS (never 0 → never silently drops args).
    assert_eq!(argc_of("NtNotARealService"), MAX_STUB_ARGS);
    assert_eq!(exact_argc_of("NtNotARealService"), None);
}

#[test]
fn no_duplicate_argc_names() {
    for (i, (a, _)) in NT_ARGC.iter().enumerate() {
        for (b, _) in &NT_ARGC[i + 1..] {
            assert_ne!(a, b, "duplicate argc entry {}", a);
        }
    }
}

#[test]
fn live_alpc_services_use_only_the_reserved_native_range() {
    assert_eq!(ALPC_SSN_BASE, 0x700);
    let live = NT_SYSCALLS.iter().filter(|e| {
        (ALPC_SSN_BASE..ALPC_SSN_BASE + 4).contains(&e.ssn)
    });
    assert_eq!(live.clone().count(), 4);
    for service in live {
        assert!(service.name.starts_with("NtAlpc"));
    }
    for service in NT_SYSCALLS.iter().filter(|e| {
        e.name.starts_with("NtAlpc") && !(ALPC_SSN_BASE..ALPC_SSN_BASE + 4).contains(&e.ssn)
    }) {
        assert!(
            (LIBERNT_FULL_EXPORT_SSN_BASE..LIBERNT_FULL_EXPORT_SSN_BASE + 180)
                .contains(&service.ssn),
            "{} escaped the LiberNT extension range",
            service.name
        );
    }
}

#[test]
fn native_alpc_create_route_requires_our_ntdll_transport_and_number() {
    use crate::NativeAlpcService;

    assert_eq!(
        NativeAlpcService::from_call(u64::from(ALPC_SSN_BASE + 2), true),
        Some(NativeAlpcService::CreatePort),
    );
    assert_eq!(NativeAlpcService::from_call(114, true), None);
    assert_eq!(NativeAlpcService::from_call(u64::from(ALPC_SSN_BASE + 2), false), None);
    assert_eq!(NativeAlpcService::from_call(u64::from(ALPC_SSN_BASE + 3), true),
        Some(NativeAlpcService::SendWaitReceivePort));
}

#[test]
fn native_alpc_ingress_precedes_dispatcher_table_lookup() {
    use crate::{NativeAlpcService, NativeIngressRoute};
    assert_eq!(
        NativeIngressRoute::select(u64::from(ALPC_SSN_BASE + 3), true, false),
        Some(NativeIngressRoute::Alpc(NativeAlpcService::SendWaitReceivePort)),
    );
    assert_eq!(
        NativeIngressRoute::select(u64::from(ALPC_SSN_BASE + 1), true, false),
        Some(NativeIngressRoute::Alpc(NativeAlpcService::ConnectPort)),
    );
    assert_eq!(NativeIngressRoute::select(u64::from(ALPC_SSN_BASE + 3), false, false), None);
    assert_eq!(NativeIngressRoute::select(0x32, true, true), Some(NativeIngressRoute::Table));
}

#[test]
fn released_libernt_raw_wait_for_alert_uses_registered_native_service() {
    let registered = u64::from(ssn_of("NtWaitForAlertByThreadId").unwrap());
    let alert_registered = u64::from(ssn_of("NtAlertThreadByThreadId").unwrap());
    assert_eq!(registered, 0x4ad);
    assert_eq!(alert_registered, 0x406);
    // The pinned LiberNT ntdll and ntdll_vista alert/wait stubs issue 0x16c/0x16d.
    // Only genuine UnknownSyscall ingress uses that external service numbering.
    assert_eq!(normalize_external_raw_ssn(0x16d, false), registered);
    assert_eq!(normalize_external_raw_ssn(0x16c, false), alert_registered);
    assert_eq!(normalize_external_raw_ssn(0x16d, true), 0x16d);
    assert_eq!(normalize_external_raw_ssn(0x16c, true), 0x16c);
    for unrelated in [0x16b, 0x16e] {
        assert_eq!(normalize_external_raw_ssn(unrelated, false), unrelated);
    }
    assert_eq!(normalize_external_raw_ssn(registered, false), registered);
    assert_eq!(normalize_external_raw_ssn(alert_registered, false), alert_registered);
}

#[test]
fn native_ipc_buffer_selects_main_and_worker_layouts() {
    assert_eq!(
        native_ipc_buffer_va(NT_NATIVE_SEC_IMAGE_MAIN_TEB_VA),
        NT_NATIVE_MAIN_IPC_BUFFER_VA
    );
    assert_eq!(
        native_ipc_buffer_va(NT_NATIVE_PE_MAIN_TEB_VA),
        NT_NATIVE_MAIN_IPC_BUFFER_VA
    );

    let worker_layouts = [
        (0x0000_0100_1049_0000, 0x0000_0100_1048_0000),
        (0x0000_0100_104F_0000, 0x0000_0100_104E_0000),
        (0x0000_0100_1055_0000, 0x0000_0100_1054_0000),
    ];
    for (teb, expected_ipc) in worker_layouts {
        let ipc = native_ipc_buffer_va(teb);
        assert_eq!(ipc, expected_ipc);
        assert_eq!(ipc & 0xFFF, 0, "worker IPC buffer must be page aligned");
    }
}

#[test]
fn native_worker_ipc_buffers_are_distinct() {
    let worker_tebs = [
        0x0000_0100_1049_0000,
        0x0000_0100_104F_0000,
        0x0000_0100_1055_0000,
    ];
    let ipc = worker_tebs.map(native_ipc_buffer_va);
    for (index, left) in ipc.iter().enumerate() {
        for right in &ipc[index + 1..] {
            assert_ne!(left, right);
        }
    }
}

#[test]
fn native_retry_reply_cannot_alias_an_ntstatus() {
    assert!(NT_NATIVE_RETRY_REPLY > u32::MAX as u64);
    assert_ne!(NT_NATIVE_RETRY_REPLY >> 32, 0);
}

#[test]
fn parked_unknown_syscall_retains_only_resume_metadata() {
    let parked = ParkedSyscallReply::unknown_syscall(0xaaaa, 0xbbbb, 0xcccc);
    assert_eq!(parked.resume_ip(), 0xaaaa);
    assert_eq!(parked.resume_sp(), 0xbbbb);
    assert_eq!(parked.resume_flags(), 0xcccc);
    assert_eq!(core::mem::size_of::<ParkedSyscallReply>(), 24);
}

#[test]
fn legacy_native_call_has_no_application_resume_metadata() {
    let parked = ParkedSyscallReply::native_call();
    assert_eq!(parked.resume_ip(), 0);
    assert_eq!(parked.resume_sp(), 0);
    assert_eq!(parked.resume_flags(), 0);
}
