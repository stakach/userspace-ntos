//! Host tests for the shared SSN ABI table.

use super::*;

/// The exact count of `Nt*` exports the current hosted ReactOS set imports (Step 1 measurement = 188)
/// plus `NtSecureConnectPort` (SSN 218), which ntdll's own `CsrpConnectToServer` calls internally (it
/// isn't an *import* of any hosted binary, but IS an ntdll-internal syscall → it must be in the table).
const REQUIRED_NT_COUNT: usize = 189;
const REQUIRED_ZW_COUNT: usize = 7;

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
            assert_ne!(a.ssn, b.ssn, "duplicate SSN {}: {} / {}", a.ssn, a.name, b.name);
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
        assert!(w[0].ssn < w[1].ssn, "not sorted at {} / {}", w[0].name, w[1].name);
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
        ("NtAcceptConnectPort", 0),        // SSN_NT_ACCEPT_CONNECT_PORT = 0
        ("NtAddAtom", 8),                  // SSN_NT_ADD_ATOM = 8
        ("NtAdjustPrivilegesToken", 12),   // SSN_NT_ADJUST_PRIV_TOKEN = 12
        ("NtAllocateVirtualMemory", 18),   // SSN_NT_ALLOCATE_VM = 0x12
        ("NtClose", 27),                   // SSN_NT_CLOSE = 27
        ("NtCreateFile", 39),              // SSN_NT_CREATE_FILE = 39
        ("NtCreatePort", 48),              // SSN_NT_CREATE_PORT = 48
        ("NtCreateSection", 52),           // SSN_NT_CREATE_SECTION = 52
        ("NtDelayExecution", 61),          // SSN_NT_DELAY_EXECUTION = 61
        ("NtFsControlFile", 88),           // SSN_NT_FS_CONTROL_FILE = 88
        ("NtOpenFile", 122),               // (loader hot path)
        ("NtOpenKey", 125),                // SSN_NT_OPEN_KEY = 125
        ("NtProtectVirtualMemory", 143),   // SSN_NT_PROTECT_VM = 143
        ("NtQuerySystemInformation", 181), // SSN_NT_QUERY_SYSTEM_INFO = 0xb5
        ("NtQuerySystemTime", 182),        // SSN_NT_QUERY_SYSTEM_TIME_SVC = 182
        ("NtQueryValueKey", 185),          // SSN_NT_QUERY_VALUE_KEY = 185
        ("NtSetValueKey", 256),            // SSN_NT_SET_VALUE_KEY = 256
        ("NtTerminateProcess", 266),       // SSN_NT_TERMINATE_PROCESS = 266
        ("NtWaitForSingleObject", 281),    // (core sync)
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
        assert!(c <= MAX_STUB_ARGS, "arity of {} exceeds MAX_STUB_ARGS", e.name);
    }
    assert_eq!(NT_ARGC.len(), NT_SYSCALLS.len());
}

#[test]
fn arity_anchors_and_fallback() {
    assert_eq!(argc_of("NtClose"), 1);
    assert_eq!(argc_of("NtCreateFile"), 11);
    assert_eq!(argc_of("NtWaitForSingleObject"), 3);
    assert_eq!(argc_of("NtCreateNamedPipeFile"), 14); // the widest
    // Zw* inherits its underlying Nt*'s arity.
    assert_eq!(argc_of("ZwSetValueKey"), argc_of("NtSetValueKey"));
    // Unknown falls back conservatively to MAX_STUB_ARGS (never 0 → never silently drops args).
    assert_eq!(argc_of("NtNotARealService"), MAX_STUB_ARGS);
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
fn alpc_seam_is_reserved_above_the_reactos_range() {
    // ALPC is documented-but-unassigned; its reserved base is well clear of every real SSN.
    let max = NT_SYSCALLS.iter().map(|e| e.ssn).max().unwrap();
    assert!(ALPC_SSN_BASE > max, "ALPC base must not collide with real SSNs");
    // Nothing in the current table sits in the ALPC reserved space.
    assert!(NT_SYSCALLS.iter().all(|e| e.ssn < ALPC_SSN_BASE));
}
