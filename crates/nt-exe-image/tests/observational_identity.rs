use nt_exe_image::{HostedImageRoot, HostedProcessRole, OwnedHostedImageCatalog,
    OwnedHostedProcessImage, SpawnTarget};

fn catalog() -> (OwnedHostedImageCatalog<8>, SpawnTarget) {
    let mut catalog = OwnedHostedImageCatalog::new();
    let image = OwnedHostedProcessImage::new(5, 9, 1, b"registered.exe",
        b"registered", HostedProcessRole::InteractiveShell,
        b"\\SystemRoot\\registered.exe", b"registered.exe",
        HostedImageRoot::SystemRoot, b"registered.exe").unwrap();
    catalog.register(image).unwrap();
    let target = SpawnTarget::from_image(catalog.get_by_pi(5).unwrap());
    (catalog, target)
}

#[test]
fn exact_registration_observes_shell_without_changing_generic_execution() {
    let (mut catalog, target) = catalog();
    let proof = catalog.capture_image_observation(target).unwrap();
    assert_eq!(proof.target(), target);
    let pi = catalog.admit_dynamic_executable_observed(b"captured.exe",
        HostedProcessRole::Application, b"\\SystemRoot\\captured.exe", b"captured.exe",
        HostedImageRoot::SystemRoot, Some(proof), 128).unwrap();
    let image = catalog.get_by_pi(pi).unwrap();
    assert_eq!(image.role, HostedProcessRole::Application);
    assert_eq!(image.observation_role(), HostedProcessRole::InteractiveShell);
    assert_eq!(image.observation_target(), Some(target));
}

#[test]
fn unassociated_native_image_remains_generic() {
    let (mut catalog, _) = catalog();
    let pi = catalog.admit_dynamic_executable_observed(b"registered.exe",
        HostedProcessRole::NativeApplication, b"\\SystemRoot\\registered.exe", b"registered.exe",
        HostedImageRoot::SystemRoot, None, 128).unwrap();
    let image = catalog.get_by_pi(pi).unwrap();
    assert_eq!(image.role, HostedProcessRole::NativeApplication);
    assert_eq!(image.observation_role(), HostedProcessRole::NativeApplication);
    assert_eq!(image.observation_target(), None);
}

#[test]
fn stale_or_changed_observation_identity_does_not_gate_generic_admission() {
    let (mut catalog, target) = catalog();
    for invalid in [SpawnTarget { generation: target.generation + 1, ..target },
        SpawnTarget { role: HostedProcessRole::InteractiveLogon, ..target },
        SpawnTarget { top_badge: target.top_badge + 1, ..target }] {
        let proof = catalog.capture_image_observation(invalid);
        assert!(proof.is_none());
        let pi = catalog.admit_dynamic_executable_observed(b"captured.exe",
            HostedProcessRole::Application, b"\\SystemRoot\\captured.exe", b"captured.exe",
            HostedImageRoot::SystemRoot, proof, 128).unwrap();
        let image = catalog.get_by_pi(pi).unwrap();
        assert_eq!(image.role, HostedProcessRole::Application);
        assert_eq!(image.observation_role(), HostedProcessRole::Application);
        assert_eq!(image.observation_target(), None);
        assert_eq!(image.nt_image_path, b"\\SystemRoot\\captured.exe");
    }
}

#[test]
fn file_close_registration_retirement_and_reuse_cannot_reject_retained_section_image() {
    let mut catalog = OwnedHostedImageCatalog::<8>::new();
    let pi = catalog.admit_dynamic_executable(b"registered.exe",
        HostedProcessRole::InteractiveShell, b"\\SystemRoot\\registered.exe", b"registered.exe",
        HostedImageRoot::SystemRoot, 128).unwrap();
    // Section creation retained this exact observation before File close retired its target.
    let captured = SpawnTarget::from_image(catalog.get_by_pi(pi).unwrap());
    let proof = catalog.capture_image_observation(captured).unwrap();
    catalog.retire_dynamic_target(captured).unwrap();
    assert!(catalog.capture_image_observation(captured).is_none());
    let replacement = catalog.admit_dynamic_executable(b"replacement.exe",
        HostedProcessRole::InteractiveShellBootstrap, b"\\SystemRoot\\replacement.exe",
        b"replacement.exe", HostedImageRoot::SystemRoot, 128).unwrap();
    assert_eq!(replacement, pi);
    assert_ne!(catalog.get_by_pi(replacement).unwrap().generation, captured.generation);
    let child = catalog.admit_dynamic_executable_observed(b"captured.exe",
        HostedProcessRole::Application, b"\\SystemRoot\\captured.exe", b"captured.exe",
        HostedImageRoot::SystemRoot, Some(proof), 128).unwrap();
    let image = catalog.get_by_pi(child).unwrap();
    assert_eq!(image.role, HostedProcessRole::Application);
    assert_eq!(image.observation_target(), Some(captured));
    assert_eq!(image.observation_role(), HostedProcessRole::InteractiveShell);
    assert_eq!(image.leaf, b"captured.exe");
    assert_eq!(image.nt_image_path, b"\\SystemRoot\\captured.exe");
}
