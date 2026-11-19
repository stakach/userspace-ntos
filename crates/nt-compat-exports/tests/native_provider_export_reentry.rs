//! A dependent re-entering a provider whose primary lane is running uses a worker lane.
//!
//! Boot 44463332736: ndis.sys ran NdisIPnPStartDevice on its primary lane and called E1000's
//! MiniportInitialize; E1000's NdisAllocateMemoryWithTag export call found that lane's Reply in
//! use (`reply-aliased`, BUSY), became 0xc0000001, and StartDevice failed with 0xc000009a.

#[test]
fn reentrant_exports_select_a_worker_lane_when_the_primary_cannot_admit() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let body = launch
        .split("let dxg_callback = matches!(policy.side_effect,")
        .nth(1)
        .expect("reentry policy")
        .split("let provider_shared = reentrant")
        .next()
        .unwrap();
    let admits = body.find("ready_for_admission(route)").expect("primary admission observed");
    let policy = body.find("hosted_provider_export_needs_worker(").expect("shared policy");
    let select = body.find("hosted_provider_export_lane::select(").expect("worker selection");
    assert!(admits < policy && policy < select);
}
