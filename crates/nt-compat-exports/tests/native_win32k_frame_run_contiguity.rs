//! A win32k frame run must reserve consecutive root CSpace slots even when slots are recycled.

use std::process::Command;

#[test]
fn win32k_frame_runs_do_not_derive_a_run_from_scalar_allocations() {
    let source = include_str!("../../../components/ntos-executive/src/main.rs");
    let phase = source
        .split_once("// --- Phase 2b (graphics):")
        .expect("win32k startup phase")
        .1
        .split_once("// Parse + copy sections + relocate + patch IAT.")
        .expect("end of win32k frame-run allocation phase")
        .0;
    let scalar = extract_function(source, "fn try_alloc_slot() -> Option<u64> {", "\nfn alloc_slot()");
    let run = extract_function(
        source,
        "fn try_alloc_slot_run(count: u64) -> Option<u64> {",
        "\nfn root_slot_bit(",
    );
    let fixture = format!("{PORTS}\n{scalar}\n{run}\n{CASES}");
    let directory = std::env::temp_dir().join(format!(
        "nt-win32k-frame-run-{}",
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
        "native slot-policy fixture must compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    let _ = std::fs::remove_dir_all(directory);
    assert!(
        result.status.success(),
        "recycled-slot and contiguous-run regression:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let storage = source
        .split_once("// Shared storage run:")
        .expect("storage host frame-run startup")
        .1
        .split_once("// Spawn the isolated storage host")
        .expect("end of storage host frame-run startup")
        .0;
    for base in [
        "shared_start",
        "fb_start",
        "srvbuf_start",
        "win32buf_start",
        "win32kbuf_start",
        "winlogonbuf_start",
        "hivebuf_start",
    ] {
        assert!(
            !storage.contains(&format!("let {base} = alloc_frame();")),
            "{base} is indexed as base + frame but scalar allocation may reuse nonconsecutive slots"
        );
    }
    assert!(
        !storage.contains("let start = alloc_frame();"),
        "font, NLS, and hive frame runs may reuse nonconsecutive slots"
    );
    for base in [
        "code_base",
        "seh_base",
        "pool_base",
        "data_base",
        "arg_base",
        "lpc_request_base",
        "job_atom_base",
        "registry_request_base",
        "heap_base",
    ] {
        assert!(
            !phase.contains(&format!("let {base} = alloc_frame();")),
            "{base} is later indexed as base + frame, but scalar alloc_frame may return recycled nonconsecutive slots"
        );
    }
}

fn extract_function<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("actual native allocation function");
    let end = source[start..].find(end).expect("end of native allocation function") + start;
    let function = &source[start..end];
    syn::parse_str::<syn::ItemFn>(function).expect("complete native allocation function");
    function
}

const PORTS: &str = r#"
use std::sync::atomic::{AtomicU64, Ordering};
static ROOT_CSPACE_END: AtomicU64 = AtomicU64::new(200);
static NEXT_SLOT: AtomicU64 = AtomicU64::new(100);
static RECYCLED: AtomicU64 = AtomicU64::new(2);
fn try_recycled_root_slot() -> Option<u64> {
    match RECYCLED.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1)) {
        Ok(2) => Some(17),
        Ok(1) => Some(9),
        _ => None,
    }
}
unsafe fn root_slot_mark_live(_slot: u64) -> bool { true }
"#;

const CASES: &str = r#"
#[test]
fn scalar_allocations_can_be_nonconsecutive_while_run_reservation_is_consecutive() {
    assert_eq!(try_alloc_slot(), Some(17));
    assert_eq!(try_alloc_slot(), Some(9));
    assert_eq!(try_alloc_slot_run(4), Some(100));
    assert_eq!(NEXT_SLOT.load(Ordering::Relaxed), 104);
    assert_eq!(try_alloc_slot(), Some(104));
}
"#;
