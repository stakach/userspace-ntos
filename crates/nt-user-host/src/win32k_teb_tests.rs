use crate::win32k_teb::{purpose_for_win32k_syscall, select_dispatch_teb, DispatchTebCandidates, DispatchTebPurpose,
    DispatchTebError};

#[test]
fn system_thread_dispatch_uses_teb_that_owns_threadinfo_client_info() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        compatibility_teb: 0x3000_0000,
        thread_client_info: 0x1000_0800,
    };
    assert_eq!(select_dispatch_teb(DispatchTebPurpose::ThreadInfo, candidates),
        Ok(candidates.callout_teb));
    assert_eq!(select_dispatch_teb(DispatchTebPurpose::UserObjectName, candidates),
        Ok(candidates.client_teb), "native OA name capture still reads the guest TEB");

    let stale = DispatchTebCandidates { thread_client_info: 0x4000_0800, ..candidates };
    assert_eq!(select_dispatch_teb(DispatchTebPurpose::ThreadInfo, stale),
        Err(DispatchTebError::ClientInfoMismatch),
        "a CSRSS system thread may not assert through an unrelated TEB");
}

#[test]
fn switch_desktop_dispatch_uses_threadinfo_teb_without_changing_name_capture() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        compatibility_teb: 0x3000_0000,
        thread_client_info: 0x1000_0800,
    };
    let switch_purpose = purpose_for_win32k_syscall(0x1288, 0);
    assert_eq!(switch_purpose, DispatchTebPurpose::ThreadInfo);
    assert_eq!(select_dispatch_teb(switch_purpose, candidates), Ok(candidates.callout_teb));
    assert_eq!(purpose_for_win32k_syscall(0x122d, 0), DispatchTebPurpose::UserObjectName,
        "desktop object names still need the client TEB");
    assert_eq!(purpose_for_win32k_syscall(0x1002, 0x22), DispatchTebPurpose::ThreadInfo);
    let cursor_create_purpose = purpose_for_win32k_syscall(0x1002, 0x21);
    assert_eq!(cursor_create_purpose, DispatchTebPurpose::ThreadInfo,
        "LiberNT CreateEmptyCurObject calls GetW32ThreadInfo, which asserts the TEB client-info link");
    assert_eq!(select_dispatch_teb(cursor_create_purpose, candidates), Ok(candidates.callout_teb));
    assert_eq!(purpose_for_win32k_syscall(0x1002, 0x23), DispatchTebPurpose::Compatibility,
        "unproven one-parameter routines retain their prior TEB selection");
}

#[test]
fn cursor_icon_data_dispatch_preserves_threadinfo_client_info_identity() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        compatibility_teb: 0x3000_0000,
        thread_client_info: 0x1000_0800,
    };
    let purpose = purpose_for_win32k_syscall(0x10a8, 0);
    assert_eq!(purpose, DispatchTebPurpose::ThreadInfo,
        "LiberNT cursoricon data accesses GetW32ThreadInfo and checks pti->pClientInfo");
    assert_eq!(select_dispatch_teb(purpose, candidates), Ok(candidates.callout_teb));
    let foreign = DispatchTebCandidates { thread_client_info: 0x2000_0800, ..candidates };
    assert_eq!(select_dispatch_teb(purpose, foreign), Err(DispatchTebError::ClientInfoMismatch));
}

#[test]
fn keyboard_layout_activation_uses_threadinfo_client_info_identity() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        compatibility_teb: 0x3000_0000,
        thread_client_info: 0x1000_0800,
    };
    let purpose = purpose_for_win32k_syscall(0x125c, 0);
    assert_eq!(purpose, DispatchTebPurpose::ThreadInfo,
        "LiberNT keyboard layout activation calls GetW32ThreadInfo after optional user callbacks");
    assert_eq!(select_dispatch_teb(purpose, candidates), Ok(candidates.callout_teb));
    let foreign = DispatchTebCandidates { thread_client_info: 0x2000_0800, ..candidates };
    assert_eq!(select_dispatch_teb(purpose, foreign), Err(DispatchTebError::ClientInfoMismatch));
}
