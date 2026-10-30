use nt_exe_image::{
    HostedImageRoot, HostedProcessRole, OwnedHostedImageCatalog, OwnedHostedProcessImage,
    SpawnTarget, SERVICES_TOP_BADGE,
};

#[test]
fn historical_service_image_observation_cannot_own_installer_work() {
    let mut images = OwnedHostedImageCatalog::<3>::new();
    let bootstrap = OwnedHostedProcessImage::new(
        3,
        SERVICES_TOP_BADGE,
        1,
        b"services.exe",
        b"services.exe",
        HostedProcessRole::ServiceControlManager,
        b"\\SystemRoot\\System32\\services.exe",
        b"services.exe",
        HostedImageRoot::System32,
        b"services",
    ).unwrap();
    images.register(bootstrap).unwrap();
    let target = SpawnTarget::from_image(images.get_by_pi(3).unwrap());
    let observation = images.capture_image_observation(target).unwrap();

    let dynamic_pi = images.admit_dynamic_executable_observed(
        b"services.exe",
        HostedProcessRole::Application,
        b"\\SystemRoot\\System32\\services.exe",
        b"services.exe",
        HostedImageRoot::System32,
        Some(observation),
        24,
    ).unwrap();
    let dynamic = images.get_by_pi(dynamic_pi).unwrap();
    assert_eq!(dynamic.observation_role(), HostedProcessRole::ServiceControlManager);
    assert!(!dynamic.can_own_installer_service_work());

    let registered = images.get_by_pi(3).unwrap();
    assert!(registered.can_own_installer_service_work());

    let service_pi = images.admit_dynamic_executable(
        b"service-host.exe",
        HostedProcessRole::NonInteractiveService,
        b"\\SystemRoot\\System32\\service-host.exe",
        b"service-host.exe",
        HostedImageRoot::System32,
        24,
    ).unwrap();
    let service = images.get_by_pi(service_pi).unwrap();
    assert!(service.can_own_installer_service_work());
}
