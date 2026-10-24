//! The native debugger diagnostic uses the live process manager, including provider callbacks.

use std::fs;
use std::path::PathBuf;

#[test]
fn remote_breakin_fixture_delivers_process_exit_callbacks_before_ps_retirement() {
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("components/ntos-executive/src/service_sec_image.rs"),
    )
    .expect("executive native self-test source");
    let fixture = source
        .split("// === Dbgk REMOTE BREAK-IN SELF-TEST")
        .nth(1)
        .expect("remote break-in diagnostic fixture")
        .split("// Path 1b COUNTED SPEC")
        .next()
        .expect("end of remote break-in diagnostic fixture");

    let admission = fixture
        .find("has_process_exit_notify_registrations()")
        .expect("synthetic debugger fixture checks for live provider exit callbacks");
    let target_created = fixture
        .find("create_process(\"dbgk-breakin.exe\"")
        .expect("synthetic debugger fixture creates its target");
    assert!(admission < target_created, "callback admission must precede synthetic target creation");

    let terminated = fixture
        .find("nt_handler.pm.terminate_process(target, nt_process::STATUS_SUCCESS)")
        .expect("fixture terminates its throwaway target");
    let drained = fixture
        .find("process_terminal_receipt::drain_hosted_process_exit_notifications(&mut nt_handler)")
        .expect("fixture delivers and acknowledges live provider process-exit callbacks");
    let retired = fixture
        .find("nt_handler.pm.withdraw_process_object_if_unreferenced(target)")
        .expect("fixture withdraws its canonical Ps object");
    assert!(terminated < drained && drained < retired);
}
