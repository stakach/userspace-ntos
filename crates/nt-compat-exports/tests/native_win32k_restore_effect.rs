//! A native page restore must distinguish refusal before any write from an
//! acknowledged full publication. The existing bool API remains a caller adapter.

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/win32k_pending_dispatch.rs");

fn function(name: &str) -> &str {
    let start = SOURCE.find(name).expect("native restore function exists");
    let end = SOURCE[start + name.len()..].find("\n}\n")
        .map(|offset| start + name.len() + offset + 2)
        .expect("native restore function has a body");
    &SOURCE[start..end]
}

#[test]
fn typed_restore_refuses_before_the_first_page_write() {
    let restore = function("unsafe fn restore_shared_resume_snapshot_effect(");
    let refusal = restore.find("SharedResumeRestoreEffect::NoPageWrite")
        .expect("pre-write validation reports no page effect");
    let first_write = restore.find("core::ptr::write_volatile(")
        .expect("the native request writer remains explicit");
    assert!(refusal < first_write);
    assert!(restore.contains("SharedResumeRestoreEffect::Applied(snapshot)"),
        "a completed restore returns its exact source snapshot");
    assert!(restore.find("(*frame).header), snapshot.header")
        .expect("callback header is published")
        < restore.rfind("SharedResumeRestoreEffect::Applied(snapshot)")
            .expect("full publication is acknowledged last"));
}

#[test]
fn bool_callers_accept_only_applied_restore() {
    let adapter = function("pub(crate) unsafe fn restore_shared_resume_snapshot(");
    assert!(adapter.contains("restore_shared_resume_snapshot_effect("));
    assert!(adapter.contains("SharedResumeRestoreEffect::Applied(_)")
        || adapter.contains("SharedResumeRestoreEffect::Applied(snapshot)"));
    assert!(SOURCE.contains("Uncertain"),
        "future partial writes must have an explicit non-success result");
}
