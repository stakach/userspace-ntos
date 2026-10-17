use crate::win32k_teb::{select_dispatch_teb, DispatchTebCandidates, DispatchTebPurpose,
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
