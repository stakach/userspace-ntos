//! A retained interface registration may retry for a bounded boot without flooding serial.

use std::process::Command;

#[test]
fn interface_retry_trace_is_bounded_and_keeps_the_failure_status() {
    let source = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let start = source.find("fn trace_interface_retry_at(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 2;
    let policy = &source[start..end];
    syn::parse_str::<syn::ItemFn>(policy).expect("native retry trace policy");
    let harness = format!(r#"
{policy}
#[test] fn bounded() {{
    for count in [1, 2, 4, 8, 16, 64, 1024] {{ assert!(trace_interface_retry_at(count)); }}
    for count in [0, 3, 5, 7, 9, 31, 1023] {{ assert!(!trace_interface_retry_at(count)); }}
}}
"#);
    let directory = std::env::temp_dir().join(format!("nt-registry-retry-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let fixture = directory.join("fixture.rs");
    let binary = directory.join("fixture-tests");
    std::fs::write(&fixture, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&fixture).arg("-o").arg(&binary).output().unwrap();
    assert!(compiled.status.success(), "native trace policy: {}",
        String::from_utf8_lossy(&compiled.stderr));
    let run = Command::new(&binary).output().unwrap();
    assert!(run.status.success(), "bounded retry behavior: {}",
        String::from_utf8_lossy(&run.stdout));

    let diagnostic = &source[source.find("fn trace_interface_retry(work:").unwrap()..
        source.find("/// Includes work retained across").unwrap()];
    assert!(diagnostic.contains("ProviderAdmission::InterfaceRegister(admission)"));
    assert!(diagnostic.contains("print_hex_u64(error as u32 as u64)"));
    assert!(diagnostic.contains("LAST_INTERFACE_RETRY_PHASE.swap"));
    let redrive = &source[source.find("unsafe fn redrive_inner(").unwrap()..
        source.find("unsafe fn caller_cancelled(").unwrap()];
    assert!(redrive.contains("Err(status) => {")
        && redrive.contains("trace_interface_retry(&work, status, admit_retry_substage);"));
}

#[test]
fn interface_busy_trace_names_the_exact_admit_substage_and_retained_storage_owner() {
    let source = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let diagnostic = &source[source.find("fn trace_interface_retry(work:").unwrap()..
        source.find("/// Includes work retained across").unwrap()];
    assert!(diagnostic.contains("admit-substage=")
        && diagnostic.contains("storage-owner=")
        && diagnostic.contains("admission_recheck_id()"),
        "a BUSY retry must show the physical storage owner and any retained recheck id");
    let admit = &source[source.find("        Phase::Admit => {").unwrap()..
        source.find("        Phase::Durable => {").unwrap()];
    let validate = admit.find("cm_mutation_transport::validate_storage(prepared)").unwrap();
    let validate_stage = admit.find("*admit_retry_substage = AdmitRetrySubstage::ValidateStorage").unwrap();
    let persistence = admit.find("work.persistence.admit(prepared, bytes)").unwrap();
    let persistence_stage = admit.find("*admit_retry_substage = AdmitRetrySubstage::PersistenceAdmit").unwrap();
    assert!(validate < validate_stage && validate_stage < persistence && persistence < persistence_stage,
        "the two BUSY returns need distinct caller-owned stages without changing either effect");
}
