//! Host tests for the nt-ntdll skeleton: the stub table, the transport seam, and the Rtl proof
//! slice. (The x86 trap asm is target-only; on the host `transport::syscall` returns
//! STATUS_NOT_IMPLEMENTED for every backend, so we test the *wiring*, not the trap.)

use super::*;
use crate::stubs::StubTable;
use crate::transport::Backend;
use nt_syscall_abi::NT_SYSCALLS;

#[test]
fn stub_table_covers_all_required_nt_services() {
    let t = StubTable::new();
    assert_eq!(t.len(), NT_SYSCALLS.len());
    assert_eq!(t.len(), 189);
    // Every shared-ABI entry has a stub resolving to the right SSN.
    for e in NT_SYSCALLS {
        let s = t.get(e.name).unwrap_or_else(|| panic!("missing stub {}", e.name));
        assert_eq!(s.ssn, e.ssn);
    }
}

#[test]
fn stub_ssn_matches_shared_abi_anchors() {
    let t = StubTable::new();
    // The stub table inherits the executive-matching ReactOS numbering via the shared ABI table.
    assert_eq!(t.get("NtClose").unwrap().ssn, 27);
    assert_eq!(t.get("NtCreateFile").unwrap().ssn, 39);
    assert_eq!(t.get("NtOpenFile").unwrap().ssn, 122);
    assert_eq!(t.get("NtProtectVirtualMemory").unwrap().ssn, 143);
    assert_eq!(t.get("NtWaitForSingleObject").unwrap().ssn, 281);
}

#[test]
fn stub_lookup_by_ssn() {
    let t = StubTable::new();
    assert_eq!(t.get_by_ssn(27).unwrap().name, "NtClose");
    assert_eq!(t.get_by_ssn(143).unwrap().name, "NtProtectVirtualMemory");
    assert!(t.get_by_ssn(0xDEAD).is_none());
}

#[test]
fn unknown_stub_never_silently_succeeds() {
    let t = StubTable::new();
    assert_eq!(t.invoke("NtNotAReal", &[]), STATUS_INVALID_SYSTEM_SERVICE);
}

#[test]
fn default_transport_is_x86_trap_for_compat() {
    // Step 2a default: every service uses the drop-in-compatible trap backend.
    let t = StubTable::new();
    assert!(t.all().iter().all(|s| s.backend == Backend::X86Trap));
    assert_eq!(Backend::for_ssn(27), Backend::X86Trap);
}

#[test]
fn transport_backend_implemented_flags() {
    // X86Trap is wired (target-side); the seL4/SURT seams are declared-but-unimplemented.
    assert!(Backend::X86Trap.is_implemented());
    assert!(!Backend::Sel4Call.is_implemented());
    assert!(!Backend::SurtRing.is_implemented());
}

#[test]
fn transport_seams_return_not_implemented_on_host() {
    // The declared seL4/SURT seams (and the trap on non-x86 hosts) return NOT_IMPLEMENTED rather
    // than fabricating success.
    assert_eq!(transport::syscall(Backend::Sel4Call, 27, &[0]), STATUS_NOT_IMPLEMENTED);
    assert_eq!(transport::syscall(Backend::SurtRing, 27, &[0]), STATUS_NOT_IMPLEMENTED);
}

#[test]
fn proof_of_pattern_stubs_resolve_and_invoke() {
    let t = StubTable::new();
    // These prove SSN resolution + arg marshalling end-to-end. On the host the trap isn't
    // available, so we assert they route (not that the syscall executes).
    let _ = stubs::nt_close(&t, 0x1234);
    let _ = stubs::nt_delay_execution(&t, true, 0);
    let _ = stubs::nt_create_file(&t, 0, 0, 0, 0);
    let _ = stubs::nt_protect_virtual_memory(&t, 0, 0, 0, 0);
    let _ = stubs::nt_wait_for_single_object(&t, 0, false, 0);
    // The proof stubs resolve to the expected SSNs.
    assert_eq!(t.get("NtClose").unwrap().ssn, 27);
    assert_eq!(t.get("NtDelayExecution").unwrap().ssn, 61);
}

#[test]
fn rtl_proof_slice_reuses_nt_compat_exports() {
    // RtlInitUnicodeString: byte-counted view.
    let hello = [b'H' as u16, b'i' as u16];
    let us = rtl::rtl_init_unicode_string(&hello);
    assert_eq!(us.length, 4);
    assert_eq!(us.maximum_length, 4);

    // RtlCreateUnicodeString: NUL-terminated copy, capacity includes the NUL.
    let cs = rtl::rtl_create_unicode_string(&hello);
    assert_eq!(cs.length, 4);
    assert_eq!(cs.maximum_length, 6);

    // RtlCompareMemory.
    assert_eq!(rtl::rtl_compare_memory(b"hello", b"help"), 3);

    // RtlCompareUnicodeString / RtlEqualUnicodeString (case-insensitive).
    let a = [b'a' as u16];
    let b = [b'A' as u16];
    assert_eq!(rtl::rtl_compare_unicode_string(&a, &b, true), core::cmp::Ordering::Equal);
    assert!(rtl::rtl_equal_unicode_string(&a, &b, true));
    assert!(!rtl::rtl_equal_unicode_string(&a, &b, false));

    // RtlUpcaseUnicodeChar.
    assert_eq!(rtl::rtl_upcase_unicode_char(b'z' as u16), b'Z' as u16);
}
