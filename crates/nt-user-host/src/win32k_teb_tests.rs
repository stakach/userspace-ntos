use crate::win32k_teb::{purpose_for_win32k_syscall, select_dispatch_teb, DispatchTebCandidates, DispatchTebPurpose,
    DispatchTebError};

#[test]
fn system_thread_dispatch_uses_teb_that_owns_threadinfo_client_info() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
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
        thread_client_info: 0x1000_0800,
    };
    let switch_purpose = purpose_for_win32k_syscall(0x1288);
    assert_eq!(switch_purpose, DispatchTebPurpose::ThreadInfo);
    assert_eq!(select_dispatch_teb(switch_purpose, candidates), Ok(candidates.callout_teb));
    assert_eq!(purpose_for_win32k_syscall(0x122d), DispatchTebPurpose::UserObjectName,
        "desktop object names still need the client TEB");
    let cursor_create_purpose = purpose_for_win32k_syscall(0x1002);
    assert_eq!(cursor_create_purpose, DispatchTebPurpose::ThreadInfo,
        "LiberNT CreateEmptyCurObject calls GetW32ThreadInfo, which asserts the TEB client-info link");
    assert_eq!(select_dispatch_teb(cursor_create_purpose, candidates), Ok(candidates.callout_teb));
}

#[test]
fn cursor_icon_data_dispatch_preserves_threadinfo_client_info_identity() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        thread_client_info: 0x1000_0800,
    };
    let purpose = purpose_for_win32k_syscall(0x10a8);
    assert_eq!(purpose, DispatchTebPurpose::ThreadInfo,
        "LiberNT cursoricon data accesses GetW32ThreadInfo and checks pti->pClientInfo");
    assert_eq!(select_dispatch_teb(purpose, candidates), Ok(candidates.callout_teb));
    let foreign = DispatchTebCandidates { thread_client_info: 0x2000_0800, ..candidates };
    assert_eq!(select_dispatch_teb(purpose, foreign), Err(DispatchTebError::ClientInfoMismatch));
}

#[test]
fn find_existing_cursor_icon_uses_threadinfo_client_info_identity() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        thread_client_info: 0x1000_0800,
    };
    let purpose = purpose_for_win32k_syscall(0x103d);
    assert_eq!(purpose, DispatchTebPurpose::ThreadInfo,
        "LiberNT NtUserFindExistingCursorIcon calls GetW32ThreadInfo");
    assert_eq!(select_dispatch_teb(purpose, candidates), Ok(candidates.callout_teb));
    let foreign = DispatchTebCandidates { thread_client_info: 0x2000_0800, ..candidates };
    assert_eq!(select_dispatch_teb(purpose, foreign), Err(DispatchTebError::ClientInfoMismatch));
}

#[test]
fn register_class_dispatch_uses_threadinfo_client_info_identity() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        thread_client_info: 0x1000_0800,
    };
    let purpose = purpose_for_win32k_syscall(0x10b4);
    assert_eq!(purpose, DispatchTebPurpose::ThreadInfo,
        "NtUserRegisterClassExWOW reaches UserRegisterClass/GetW32ThreadInfo");
    assert_eq!(select_dispatch_teb(purpose, candidates), Ok(candidates.callout_teb));
}

#[test]
fn create_window_dispatch_uses_threadinfo_client_info_identity() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        thread_client_info: 0x1000_0800,
    };
    let purpose = purpose_for_win32k_syscall(0x1077);
    assert_eq!(purpose, DispatchTebPurpose::ThreadInfo,
        "NtUserCreateWindowEx reaches co_UserCreateWindowEx/GetW32ThreadInfo");
    assert_eq!(select_dispatch_teb(purpose, candidates), Ok(candidates.callout_teb));
}

#[test]
fn nested_get_dc_dispatch_uses_threadinfo_client_info_identity() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        thread_client_info: 0x1000_0800,
    };
    let purpose = purpose_for_win32k_syscall(0x100a);
    assert_eq!(purpose, DispatchTebPurpose::ThreadInfo,
        "NtUserGetDC can run inside a window creation callback and uses GetW32ThreadInfo");
    assert_eq!(select_dispatch_teb(purpose, candidates), Ok(candidates.callout_teb));
}

#[test]
fn keyboard_layout_activation_uses_threadinfo_client_info_identity() {
    let candidates = DispatchTebCandidates {
        callout_teb: 0x1000_0000,
        client_teb: 0x2000_0000,
        thread_client_info: 0x1000_0800,
    };
    let purpose = purpose_for_win32k_syscall(0x125c);
    assert_eq!(purpose, DispatchTebPurpose::ThreadInfo,
        "LiberNT keyboard layout activation calls GetW32ThreadInfo after optional user callbacks");
    assert_eq!(select_dispatch_teb(purpose, candidates), Ok(candidates.callout_teb));
    let foreign = DispatchTebCandidates { thread_client_info: 0x2000_0800, ..candidates };
    assert_eq!(select_dispatch_teb(purpose, foreign), Err(DispatchTebError::ClientInfoMismatch));
}
