//! The dormant initial thread owns a TCB for its exact Win32k process-create callout.
//! Ordinary executable lookup remains closed until creation finishes (#432).

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn initial_win32k_client_uses_the_retained_target_tcb() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../components/ntos-executive/src");
    let initial =
        fs::read_to_string(root.join("initial_thread_creation.rs")).expect("initial thread source");
    let capture = initial
        .split("unsafe fn capture_initial_win32k_client(")
        .nth(1)
        .expect("initial Win32k client capture")
        .split("/// The initial TCB is deliberately closed")
        .next()
        .unwrap();
    let compact: String = capture.chars().filter(|ch| !ch.is_whitespace()).collect();
    let client = compact
        .find("win32k_lifecycle_client_for_tcb(binding.tid,handler,role,binding.tcb,")
        .expect("the dormant target's retained TCB must enter its Win32k client");
    let compact_proof = compact
        .find("precommit_initial_win32k_role(handler,binding)?")
        .expect("exact retained owner proof");
    assert!(
        compact_proof < client,
        "owner proof must precede target TCB projection"
    );

    let constructor =
        fs::read_to_string(root.join("main.rs")).expect("Win32k lifecycle client source");
    let ordinary = constructor
        .split("fn win32k_lifecycle_client(")
        .nth(1)
        .expect("ordinary Win32k client")
        .split("fn win32k_lifecycle_client_for_tcb(")
        .next()
        .expect("separate explicit TCB constructor");
    assert!(
        ordinary.contains("handler.hosted_thread_tcb(tid)?"),
        "ordinary client construction must retain its executable gate"
    );
    let explicit = constructor
        .split("fn win32k_lifecycle_client_for_tcb(")
        .nth(1)
        .expect("explicit TCB constructor")
        .split("unsafe fn release_hosted_thread_win32_context(")
        .next()
        .unwrap();
    assert!(
        !explicit.contains("handler.hosted_thread_tcb(tid)"),
        "the exact initial caller must not be rechecked through the ordinary gate"
    );
}

#[test]
fn dormant_target_constructs_a_client_without_opening_ordinary_lookup() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../components/ntos-executive/src");
    let source = fs::read_to_string(root.join("main.rs")).expect("Win32k constructor source");
    let constructors = source
        .split("fn win32k_lifecycle_client(")
        .nth(1)
        .expect("ordinary Win32k client")
        .split("unsafe fn release_hosted_thread_win32_context(")
        .next()
        .unwrap();
    let fixture = format!(
        "{}\nfn win32k_lifecycle_client({}\n{}",
        include_str!("native_initial_win32k_owner_tcb_fixture.rs.txt"),
        constructors,
        r#"
#[test]
fn dormant_initial_client() {
    let handler = ExecNtHandler { thread_runtime: ThreadRuntime, pm: ProcessManager };
    assert!(handler.hosted_thread_tcb(7).is_none(), "ordinary ingress stays closed");
    assert!(win32k_lifecycle_client(7, &handler, None).is_none());
    let client = win32k_lifecycle_client_for_tcb(7, &handler, None, 42)
        .expect("exact retained target can supply its TCB");
    assert_eq!((client.tid, client.badge, client.tcb, client.generation), (7, 9, 42, 3));
    assert_eq!(client.logical_caller, Some(42));
    assert!(win32k_lifecycle_client_for_tcb(7, &handler, None, 43).is_none(),
        "a different TCB has no client authority");
    assert!(win32k_lifecycle_client_for_tcb(7, &handler, None, 1).is_none(),
        "a non-TCB capability cannot enter the client");
}
"#
    );
    let temp = std::env::temp_dir().join(format!(
        "nt-initial-win32k-tcb-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    fs::create_dir(&temp).unwrap();
    let source_path = temp.join("fixture.rs");
    let binary = temp.join("fixture");
    fs::write(&source_path, fixture).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test", "-Awarnings"])
        .arg(&source_path)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "production constructor fixture: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let run = Command::new(&binary).output().unwrap();
    assert!(
        run.status.success(),
        "production constructor behavior: {}",
        String::from_utf8_lossy(&run.stdout)
    );
    fs::remove_dir_all(temp).unwrap();
}
