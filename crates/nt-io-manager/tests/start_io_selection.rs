use core::sync::atomic::{AtomicU64, Ordering};
use nt_io_manager::start_io_selection::StartIoSelectionClaim;

const GENERATION: u64 = 0x500;
const PENDING: u64 = GENERATION | 3;
const SELECTING: u64 = GENERATION | 19;

#[test]
fn exact_generation_claim_blocks_completion_and_cancel_then_restores_pending() {
    let state = AtomicU64::new(PENDING);
    let claim = StartIoSelectionClaim::claim(&state, PENDING, SELECTING)
        .expect("exact pending node may be selected");
    assert_eq!(state.load(Ordering::Acquire), SELECTING);
    assert!(state.compare_exchange(PENDING, GENERATION | 6,
        Ordering::AcqRel, Ordering::Acquire).is_err(),
        "completion cannot claim this node during WDM selection");
    assert!(state.compare_exchange(PENDING, GENERATION | 12,
        Ordering::AcqRel, Ordering::Acquire).is_err(),
        "cancel cannot claim this node during WDM selection");
    drop(claim);
    assert_eq!(state.load(Ordering::Acquire), PENDING);
    assert!(state.compare_exchange(PENDING, GENERATION | 6,
        Ordering::AcqRel, Ordering::Acquire).is_ok());
}

#[test]
fn stale_generation_and_terminal_phase_refuse_without_effect() {
    for current in [0x600 | 3, GENERATION | 7, GENERATION | 6] {
        let state = AtomicU64::new(current);
        assert!(StartIoSelectionClaim::claim(&state, PENDING, SELECTING).is_none());
        assert_eq!(state.load(Ordering::Acquire), current);
    }
}

#[test]
fn committed_queue_effect_stays_claimed_until_durable_publication() {
    let state = AtomicU64::new(PENDING);
    let mut claim = StartIoSelectionClaim::claim(&state, PENDING, SELECTING).unwrap();
    claim.effect_committed();
    drop(claim);
    assert_eq!(state.load(Ordering::Acquire), SELECTING);

    // The native adapter's retained owner may reconstruct the exact claim only by its
    // recorded transaction; a lost post-effect claim must never silently roll back.
    assert!(state.compare_exchange(SELECTING, PENDING,
        Ordering::AcqRel, Ordering::Acquire).is_ok());
}
