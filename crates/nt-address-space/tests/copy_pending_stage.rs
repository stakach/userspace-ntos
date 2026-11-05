use nt_address_space::copy::VmCopyContinuation;

#[test]
fn pending_destination_probe_keeps_first_source_chunk_and_probe_cursor() {
    // The destination crosses a page after eight bytes. The source must be captured before
    // probing either destination page, and a Pending page-in must retain that exact capture.
    let caller = 11u64;
    let target = 17u64;
    let mut copy = VmCopyContinuation::<u64, u64, u64, u64>::new(
        caller, target, 0x1ff0, 0x2ff8, 0x30, 0x8ff8,
    );
    let staged = [0xa5; 8];
    assert_eq!(copy.next_offset(caller, target), Some(0));
    assert!(copy.stage_source(caller, target, 0, &staged));
    assert_eq!(copy.next_probe_address(caller, target), Some(0x2ff8));
    assert!(copy.begin_pending(caller, target, 0, 23, 29));
    assert!(!copy.stage_source(caller, target, 0, &[0; 8]),
        "a suspended source read cannot replace the retained first chunk");
    assert_eq!(copy.staged_source(caller, target, 0), Some(staged.as_slice()));
    assert!(!copy.resume_pending(caller, target, 0, 23, 29));
    assert!(copy.acknowledge_pending(caller, target, 0, 23, 29));
    assert!(copy.resume_pending(caller, target, 0, 23, 29));
    assert_eq!(copy.next_probe_address(caller, target), Some(0x2ff8));
    assert!(copy.enter_probe_page(caller, target, 0x2ff8));
    assert_eq!(copy.next_probe_address(caller, target), None,
        "an entered probe has an uncertain effect until completion");
    assert!(!copy.enter_probe_page(caller, target, 0x2ff8),
        "an uncertain self-write probe cannot be re-entered");
    assert!(copy.probe_page_completed(caller, target, 0x2ff8));
    assert!(!copy.probe_page_completed(caller, target, 0x2ff8),
        "a completed self-write probe cannot be replayed");
    assert_eq!(copy.next_probe_address(caller, target), Some(0x3000));
    assert!(copy.enter_probe_page(caller, target, 0x3000));
    assert!(copy.probe_page_completed(caller, target, 0x3000));
    assert_eq!(copy.next_probe_address(caller, target), None);
    assert_eq!(copy.staged_source(caller, target, 0), Some(staged.as_slice()));
    assert!(copy.commit_copied(caller, target, 0, 8));
    assert_eq!(copy.staged_source(caller, target, 0), None);
    assert_eq!(copy.next_offset(caller, target), Some(8));
}
