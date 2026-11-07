//! A target-device report must own its source notification and PDO until every callback ends.

#[test]
fn target_device_report_has_a_real_owned_async_route() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let notification = include_str!("../../../components/ntos-executive/src/hosted_driver_pnp_notification.rs");
    assert!(launch.contains("\"IoReportTargetDeviceChangeAsynchronous\""));
    assert!(notification.contains("CustomTargetNotification::parse("));
    assert!(notification.contains("EVENT_CATEGORY_TARGET_DEVICE_CHANGE"));
    assert!(notification.contains("retain_hosted_device_projection_reference("));
    assert!(notification.contains("release_hosted_device_projection_reference("));
    assert!(notification.contains("FileReference"));
    assert!(notification.contains("HostedFilePublicationLease"));
    assert!(notification.contains("EventState::Executing"));
    assert!(notification.contains("FSD_DISPATCH_PNP_NOTIFICATION"));
}
