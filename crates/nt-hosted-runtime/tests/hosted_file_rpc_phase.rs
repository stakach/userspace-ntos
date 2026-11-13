use nt_hosted_runtime::{HostedFileRpcDiagnostic, HostedFileRpcIdentity, HostedFileRpcMarks};

const READ: u8 = 3;
const IRP_GEN_1: u64 = (1u64 << 40) | 0x17;
const IRP_GEN_2: u64 = (2u64 << 40) | 0x17;

fn identity(irp_id: u64) -> HostedFileRpcIdentity {
    HostedFileRpcIdentity { irp_id, major: READ }
}

#[test]
fn exact_dispatch_partitions_nested_pump_and_bank_without_counting_pending_wait() {
    let mut diagnostic = HostedFileRpcDiagnostic::new();
    let marks = HostedFileRpcMarks {
        entered: 10, invoked: 20, returned: 50, terminal: 55,
        pump_ticks: 24, bank_ticks: 7,
    };
    let durations = diagnostic.record(identity(IRP_GEN_1), identity(IRP_GEN_1), marks)
        .expect("exact ordered dispatch");
    assert_eq!((durations.prepare, durations.pump, durations.invoke_other,
        durations.terminal, durations.bank, durations.total), (10, 24, 6, 5, 7, 45));
    assert_eq!(durations.prepare + durations.pump + durations.invoke_other
        + durations.terminal, durations.total);
    // A synchronous pending completion can arrive much later; its wait is a separate interval.
    let pending_completion_at = 300;
    assert!(pending_completion_at > marks.terminal);
    assert_eq!(diagnostic.counts().total_ticks, 45);
    assert_eq!(diagnostic.counts().calls, 1);

    assert!(diagnostic.record(identity(IRP_GEN_1), identity(IRP_GEN_2), marks).is_none());
    assert!(diagnostic.record(identity(IRP_GEN_1), identity(IRP_GEN_1),
        HostedFileRpcMarks { bank_ticks: 25, ..marks }).is_none());
    assert!(diagnostic.record(identity(IRP_GEN_1), identity(IRP_GEN_1),
        HostedFileRpcMarks { pump_ticks: 31, ..marks }).is_none());
    assert!(diagnostic.record(identity(IRP_GEN_1), identity(IRP_GEN_1),
        HostedFileRpcMarks { returned: 19, ..marks }).is_none());
    assert_eq!(diagnostic.counts().calls, 1);
    assert_eq!(diagnostic.counts().rejected, 4);
}
