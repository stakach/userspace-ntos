//! Exercise the native transport's readiness and irreversible fault transitions.

use std::process::Command;

#[test]
fn launching_driver_does_not_fault_before_add_device() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let ready_start = source.find("fn register_instance_ready(").unwrap();
    let ready_end = source[ready_start..].find("\nunsafe fn release_driver_component_mechanism").unwrap();
    let fault_start = source.find("fn hosted_driver_backend_faulted(").unwrap();
    let fault_end = source[fault_start..].find("\nstruct HostedRootBusBackend;").unwrap();
    let harness = format!(
        "{PORTS}\n{}\n{}\n{CASES}",
        &source[ready_start..ready_start + ready_end],
        &source[fault_start..fault_start + fault_end]
    );
    let directory = std::env::temp_dir().join(format!(
        "nt-source-driver-fault-readiness-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native readiness fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native readiness regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
#[derive(Clone, Copy)]
struct DriverInstance { ready: bool, faulted: bool, used: bool }
static mut INSTANCES: [DriverInstance; 1] = [DriverInstance { ready: false, faulted: false, used: true }];
unsafe fn driver_instances_mut() -> &'static mut [DriverInstance] { &mut INSTANCES }
"#;

const CASES: &str = r#"
#[test]
fn launch_readiness_is_distinct_from_transport_fault() {
    let starting = unsafe { INSTANCES[0] };
    assert!(!starting.ready);
    assert!(!hosted_driver_backend_faulted(Some(starting)));
    register_instance_ready(0, true);
    let ready = unsafe { INSTANCES[0] };
    assert!(ready.ready);
    assert!(!hosted_driver_backend_faulted(Some(ready)));
    register_instance_ready(0, false);
    let failed = unsafe { INSTANCES[0] };
    assert!(!failed.ready);
    assert!(hosted_driver_backend_faulted(Some(failed)));
    register_instance_ready(0, true);
    let after_fault = unsafe { INSTANCES[0] };
    assert!(!after_fault.ready);
    assert!(hosted_driver_backend_faulted(Some(after_fault)));
    assert!(hosted_driver_backend_faulted(None));
}
"#;
