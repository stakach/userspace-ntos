//! A failed, exactly acknowledged snapshot command is an owner failure, not a lost claim.

const BLOCK: &str = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
const SNAPSHOT: &str = include_str!("../../../components/ntos-executive/src/writable_fs/native_snapshot_io.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let tail = &source[source.find(start).expect("start marker")..];
    &tail[..tail.find(end).expect("end marker")]
}

#[test]
fn exactly_acknowledged_snapshot_failure_is_not_a_lost_claim() {
    let settle = section(BLOCK, "fn settle(", "unsafe fn poll_pending(");
    assert!(settle.contains("complete_physical"));
    let poll = section(BLOCK, "unsafe fn poll_pending(", "unsafe fn dispatch_claim(");
    assert!(poll.find("acknowledge_completed_irp_strict").unwrap() < poll.find("settle(pending, terminal)").unwrap());

    let complete = section(BLOCK, "    fn complete(self, result: Result<&[u8], nt_status::NtStatus>)", "    fn complete_physical(");
    assert!(complete.contains("complete_native_snapshot_io(claim, result)"));
    assert!(!complete.contains(".expect(\"acknowledged snapshot claim lost\")"),
        "owner completion may report a physical I/O failure after the exact ACK");
    assert!(SNAPSHOT.contains("pub(crate) enum SnapshotCompletion")
        && SNAPSHOT.contains("Failed(u32)")
        && complete.contains("Ok(SnapshotCompletion::Failed(status))"),
        "snapshot owner completion must distinguish a retained failure from a lost claim");
}

#[test]
fn snapshot_terminal_diagnostic_keeps_owner_kind_and_provider_status() {
    let complete = section(BLOCK, "    fn complete(self, result: Result<&[u8], nt_status::NtStatus>)", "    fn complete_physical(");
    assert!(complete.contains("claim.owner_kind()"));
    assert!(complete.contains("result.err()"));
}
