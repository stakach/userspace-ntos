//! A returning hosted executable entry must settle through the source-built ntdll.

const SPAWN: &str = include_str!("../../../components/ntos-executive/src/img_spawn.rs");

#[test]
fn live_spawn_uses_checked_startup_emitter_before_allocating_native_resources() {
    let function = SPAWN
        .split("pub(crate) unsafe fn spawn_sec_image(")
        .nth(1)
        .unwrap();
    let preflight = function
        .split("trace_spawn_phase(pi, b\"begin\")")
        .next()
        .unwrap();
    assert!(preflight.contains("export_rva_by_name(\"RtlExitUserThread\")"));
    assert!(preflight.contains("StartupTrampoline::emit("));
    assert!(!preflight.contains("alloc_slot()"));
}

#[test]
fn live_spawn_writes_the_checked_emitter_and_has_no_return_spin() {
    let trampoline = SPAWN
        .split("// Trampoline:")
        .nth(1)
        .unwrap()
        .split("let tramp_client =")
        .next()
        .unwrap();
    assert!(trampoline.contains("startup.bytes().iter().enumerate()"));
    assert!(!trampoline.contains("[0xEB, 0xFE]"));
}
