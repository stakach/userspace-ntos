//! The source-built ntdll bounds `KiUserCallbackDispatcher` by the pinned callback count.
//!
//! `nt-ntdll-dll` is its own workspace and cannot link `nt-user-callback`, so the two crates
//! each state the count. They must agree, or the dispatcher refuses an index the executive
//! delivers (it refused 20, `USER32_CALLBACK_MONITORENUMPROC`, while the count read 20).

use std::fs;
use std::path::PathBuf;

#[test]
fn the_dispatcher_bound_is_the_delivered_callback_count() {
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../nt-ntdll-dll/src/exports.rs"),
    )
    .expect("ntdll exports");
    let declared = format!(
        "const USER32_CALLBACK_COUNT: u32 = {};",
        nt_user_callback::USER32_CALLBACK_COUNT
    );
    assert!(source.contains(&declared), "ntdll must declare `{declared}`");
    assert!(source.contains("\"cmp r8d, {callback_count}\","));
    assert!(source.contains("callback_count = const USER32_CALLBACK_COUNT,"));
}
