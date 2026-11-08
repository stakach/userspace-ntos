//! A displaced Win32k shared page must be captured from one stable physical owner.

#[path = "../../../components/ntos-executive/src/win32k_shared_request_owner.rs"]
mod shared_request_owner;

use shared_request_owner::{RequestOwner, WORDS};

fn owner() -> RequestOwner {
    RequestOwner {
        ssn: 0x122f, pid: 96, pi: 8, tid: 100, generation: 3,
        token_auth: 0x1234, token_sid_len: 12, token_sid_ptr: 0x4000,
    }
}

#[test]
fn physical_request_identity_is_checked_before_canonicalization() {
    let expected = owner();
    let mut words = [0u64; WORDS];
    shared_request_owner::canonicalize(&mut words, expected);
    assert!(shared_request_owner::matches(&words, expected));
    for index in [0, 20, 22, 25, 29, 30, 31, 37] {
        let mut changed = words;
        changed[index] = changed[index].wrapping_add(1);
        assert!(!shared_request_owner::matches(&changed, expected), "owner word {index}");
    }
}

#[test]
fn native_capture_reads_stable_header_and_request_before_building_snapshot() {
    let source = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../components/ntos-executive/src/win32k_pending_dispatch.rs"),
    ).unwrap();
    let start = source.find("fn try_capture_exact_shared_resume_snapshot(")
        .expect("fallible exact shared capture exists");
    let end = source[start..].find("pub(crate) unsafe fn capture_shared_resume_snapshot(")
        .expect("existing capture follows exact helper") + start;
    let body = &source[start..end];
    assert!(body.contains("header_before") && body.contains("header_after"));
    assert!(body.contains("request != confirm_request"));
    assert!(body.contains("confirm_published"));
    assert!(body.contains("shared_request_owner::matches(&request, owner)"));
    assert!(body.contains("snapshot.lease_snapshot(client)"));
    assert!(source.contains("pub(crate) fn lease_snapshot("));
    assert!(!body.contains("canonicalize("), "capture cannot invent request identity");
    assert!(!body.contains("assert!("), "uncertain capture must be fallible");
}
