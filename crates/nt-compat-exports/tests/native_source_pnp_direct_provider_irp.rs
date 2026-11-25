//! Exercise the native accepted-PDO IRP identity guard for lower and direct START paths.

use std::process::Command;

#[test]
fn direct_provider_accepts_its_exact_outer_irp_without_weakening_lower_identity() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source
        .find("fn hosted_accepted_provider_irp_matches(")
        .expect("native accepted-PDO IRP identity guard");
    let end = source[start..]
        .find("\nunsafe fn advance_hosted_accepted_pdo_provider_stage(")
        .expect("following provider stage transition");
    let body = &source[start..start + end];
    syn::parse_file(body).expect("complete native accepted-PDO IRP guard");
    let fixture = format!("{PORTS}\n{body}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-native-direct-provider-irp-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&input, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "native provider identity guard must compile in fixture:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).arg("--test-threads=1").output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "native provider identity guard regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

const PORTS: &str = r#"
#[derive(Clone, Copy, Eq, PartialEq)]
struct IrpId(u64);
#[derive(Clone, Copy, Eq, PartialEq)]
enum HostedAcceptedPdoProviderMode {
    Lower,
    Direct { provider_irp: IrpId },
}
"#;

const CASES: &str = r#"
#[test]
fn lower_provider_requires_distinct_exact_irp() {
    assert!(hosted_accepted_provider_irp_matches(
        HostedAcceptedPdoProviderMode::Lower, IrpId(12), IrpId(12), IrpId(11),
    ));
    assert!(!hosted_accepted_provider_irp_matches(
        HostedAcceptedPdoProviderMode::Lower, IrpId(11), IrpId(11), IrpId(11),
    ));
    assert!(!hosted_accepted_provider_irp_matches(
        HostedAcceptedPdoProviderMode::Lower, IrpId(12), IrpId(13), IrpId(11),
    ));
}
#[test]
fn direct_provider_requires_exact_captured_irp_even_when_it_is_outer() {
    assert!(hosted_accepted_provider_irp_matches(
        HostedAcceptedPdoProviderMode::Direct { provider_irp: IrpId(11) },
        IrpId(11), IrpId(11), IrpId(11),
    ));
    assert!(!hosted_accepted_provider_irp_matches(
        HostedAcceptedPdoProviderMode::Direct { provider_irp: IrpId(11) },
        IrpId(11), IrpId(12), IrpId(11),
    ));
    assert!(!hosted_accepted_provider_irp_matches(
        HostedAcceptedPdoProviderMode::Direct { provider_irp: IrpId(12) },
        IrpId(11), IrpId(11), IrpId(11),
    ));
}
"#;
