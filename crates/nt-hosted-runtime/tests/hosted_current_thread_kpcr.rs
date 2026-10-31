use nt_hosted_runtime::HostedCurrentThreadKpcr;

const PRIMARY_STACK: u64 = 0x1000_0000;
const PRIMARY_KPCR: u64 = 0x1004_1000;
const WORKERS: u64 = 0x1100_0000;
const STRIDE: u64 = 0x20_0000;
const WORKER_KPCR_OFFSET: u64 = 0x4_3000;

fn layout() -> HostedCurrentThreadKpcr {
    HostedCurrentThreadKpcr::new(
        PRIMARY_STACK,
        32 * 0x1000,
        PRIMARY_KPCR,
        WORKERS,
        STRIDE,
        32 * 0x1000,
        WORKER_KPCR_OFFSET,
    )
    .unwrap()
}

#[test]
fn primary_and_worker_return_their_own_projected_thread() {
    let layout = layout();
    assert_eq!(
        layout.expected_kpcr(PRIMARY_STACK + 0x100),
        Some(PRIMARY_KPCR)
    );
    assert_eq!(
        layout.projected_thread(PRIMARY_STACK + 0x100, PRIMARY_KPCR, 0x4000),
        Some(0x4000)
    );

    // Slot zero belongs to the IRQ lane; hosted workers start at slot one.
    let worker_stack = WORKERS + STRIDE + 0x200;
    let worker_kpcr = WORKERS + STRIDE + WORKER_KPCR_OFFSET;
    assert_eq!(layout.expected_kpcr(worker_stack), Some(worker_kpcr));
    assert_eq!(
        layout.projected_thread(worker_stack, worker_kpcr, 0x8000),
        Some(0x8000)
    );
    assert_eq!(
        layout.projected_thread(worker_stack, PRIMARY_KPCR, 0x4000),
        None
    );
}

#[test]
fn irq_unknown_and_stale_projection_require_broker_fallback() {
    let layout = layout();
    assert_eq!(layout.expected_kpcr(WORKERS + 0x100), None); // IRQ lane, slot zero.
    assert_eq!(layout.expected_kpcr(PRIMARY_STACK - 1), None);
    assert_eq!(layout.expected_kpcr(PRIMARY_STACK + 32 * 0x1000), None);
    assert_eq!(layout.expected_kpcr(WORKERS + STRIDE + 32 * 0x1000), None);
    assert_eq!(layout.expected_kpcr(u64::MAX), None);
    assert_eq!(
        layout.projected_thread(PRIMARY_STACK + 0x100, PRIMARY_KPCR, 0),
        None
    );
    assert_eq!(
        layout.projected_thread(PRIMARY_STACK + 0x100, WORKERS + WORKER_KPCR_OFFSET, 0x4000),
        None
    );
}

#[test]
fn gs_is_read_only_after_stack_admission_and_thread_only_after_self_match() {
    let layout = layout();
    let mut reads = Vec::new();
    assert_eq!(
        layout.read_projected_thread(WORKERS + 0x100, |offset| {
            reads.push(offset);
            0
        }),
        None
    );
    assert!(
        reads.is_empty(),
        "IRQ fallback must not inspect a foreign GS layout"
    );

    assert_eq!(
        layout.read_projected_thread(PRIMARY_STACK + 0x100, |offset| {
            reads.push(offset);
            0
        }),
        None
    );
    assert_eq!(reads, [0x18]);

    reads.clear();
    assert_eq!(
        layout.read_projected_thread(PRIMARY_STACK + 0x100, |offset| {
            reads.push(offset);
            if offset == 0x18 {
                PRIMARY_KPCR
            } else {
                0x4000
            }
        }),
        Some(0x4000)
    );
    assert_eq!(reads, [0x18, 0x188]);
}
