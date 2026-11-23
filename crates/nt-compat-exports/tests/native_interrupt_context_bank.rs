//! The root interrupt broker must select the retained dispatch for its authenticated bank.

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn nested_interrupt_contexts_select_the_exact_bank() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/driver_launch.rs"),
    )
    .expect("root driver source");
    let selector = source
        .split("#[derive(Clone, Copy)]\nenum HostedProjectionBindingRejection")
        .nth(1)
        .expect("projection binding selector")
        .split("const EMPTY_HOSTED_DEVICE_BINDING")
        .next()
        .unwrap();
    let fixture = format!(
        "{}\n#[derive(Clone, Copy)]\nenum HostedProjectionBindingRejection{}\n{}",
        include_str!("native_interrupt_context_bank_fixture.rs.txt"),
        selector,
        r#"
#[test]
fn active_context_is_selected_by_physical_request_bank() {
    unsafe {
        HOSTED_DEVICE_DISPATCH_CONTEXTS = Some(Contexts(vec![
            HostedDeviceDispatchContext { instance: 2, binding: BINDING_A,
                projection_shared_va: Some(0xA000) },
            HostedDeviceDispatchContext { instance: 2, binding: BINDING_B,
                projection_shared_va: Some(0xB000) },
        ]));
    }
    assert_eq!(current_hosted_device_dispatch_binding_for_projection(2, 0xA000).ok().expect("A"), BINDING_A);
    assert_eq!(current_hosted_device_dispatch_binding_for_projection(2, 0xB000).ok().expect("B"), BINDING_B);
    assert!(current_hosted_device_dispatch_binding_for_projection(2, 0xC000).is_err());
    unsafe {
        HOSTED_DEVICE_DISPATCH_CONTEXTS = Some(Contexts(vec![
            HostedDeviceDispatchContext { instance: 2, binding: BINDING_A,
                projection_shared_va: Some(0xA000) },
            HostedDeviceDispatchContext { instance: 2, binding: BINDING_B,
                projection_shared_va: None },
        ]));
    }
    assert_eq!(current_hosted_device_dispatch_binding_for_projection(2, 0xA000).ok().expect("A retained"), BINDING_A);
    assert!(current_hosted_device_dispatch_binding_for_projection(2, 0xB000).is_err(),
        "an unbound setup context cannot authorize an interrupt");
}

"#
    );
    let temp = std::env::temp_dir().join(format!(
        "nt-interrupt-context-bank-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    fs::create_dir(&temp).unwrap();
    let fixture_path = temp.join("fixture.rs");
    let binary = temp.join("fixture");
    fs::write(&fixture_path, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&fixture_path)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "production selector fixture: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let run = Command::new(&binary).output().unwrap();
    assert!(
        run.status.success(),
        "production selector behavior: {}",
        String::from_utf8_lossy(&run.stdout)
    );
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn interrupt_service_uses_the_channel_bank_after_physical_authentication() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/driver_launch.rs"),
    )
    .expect("root driver source");
    let service = source
        .split("pub(crate) fn service_hosted_driver_interrupt(")
        .nth(1)
        .unwrap()
        .split("fn service_hosted_irp_bank_pull(")
        .next()
        .unwrap();
    let compact: String = service.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(
        compact.contains(
            "current_hosted_device_dispatch_binding_for_projection(instance_index,ch.shared_va,"
        ),
        "the authenticated channel bank must select its own retained context"
    );
}

#[test]
fn provider_export_worker_retains_its_exact_bank_context() {
    let source = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/driver_launch.rs"),
    )
    .expect("root driver source");
    let export = source
        .split("unsafe fn service_hosted_provider_export_with_dispatch<F>(")
        .nth(1)
        .expect("provider export service")
        .split("unsafe fn service_hosted_provider_export_returning<F>(")
        .next()
        .unwrap();
    let projection = export
        .find("project_provider_resource_state(")
        .expect("provider resource projection");
    let guard = export
        .find("HostedDeviceDispatchContextGuard::enter(")
        .expect("worker must retain an exact device context");
    let dispatch = export
        .find("let dispatched = dispatch(")
        .expect("provider export invocation");
    assert!(
        guard < projection && projection < dispatch,
        "the worker must retain its bank before resource projection and provider execution"
    );
    assert!(
        export.contains("guard.bind_projection_shared(provider_shared)"),
        "worker context must be tied to its selected bank"
    );
    assert!(
        export.contains("_device_dispatch_context"),
        "kept provider export must retain its device context"
    );
}
