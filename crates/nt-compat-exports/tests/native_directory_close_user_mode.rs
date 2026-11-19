//! A user-mode NtClose of a directory handle needs no access right (#413).
//!
//! Boot 44463332736 logged `[native-directory-close-failed] stage=reserve status=0xc0000022` for
//! smss's `\KnownDlls` directory, and smss asserted at sminit.c:1786. The reserve stage took a
//! kernel-only requestor reference, which refuses every user-mode caller with
//! STATUS_ACCESS_DENIED. NT's NtClose refuses only a protect-from-close handle.

const EXEC: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");

#[test]
fn directory_close_and_permanence_reserve_the_syscall_requestor() {
    let reserve = EXEC
        .split_once("fn reserve_native_directory_effect(")
        .unwrap()
        .1
        .split_once("\n    }\n")
        .unwrap()
        .0;
    assert!(reserve.contains("self.pm.reference_native_syscall_requestor(caller)?"));
    assert!(!reserve.contains("reference_native_requestor(caller)"),
        "a kernel-only requestor reference refuses user-mode NtClose");
    let close = reserve.find("EffectKind::Close {\n            0").unwrap();
    assert!(close > 0, "NtClose requires no granted access");
}
