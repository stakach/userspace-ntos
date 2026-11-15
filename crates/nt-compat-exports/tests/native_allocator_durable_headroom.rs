//! Durable heap headroom counts what the heap can still commit, not only what is mapped now.

#[path = "../../../components/ntos-executive/src/allocator_headroom.rs"]
mod allocator_headroom;

use allocator_headroom::DurableExtent;

const PAGE: usize = 0x1000;
/// Allocator metadata ahead of the first allocation (`allocator::DATA - HEAP_BASE`).
const METADATA: usize = 152;
/// `EXECUTIVE_DURABLE_HEAP_FRAMES` in the logged runs: the 88 MiB root reservation of the time
/// less its transient lane.
const RESERVATION: usize = 21504 * PAGE;
/// `BOOT_HIVE_FLUSH_POST_CHECKPOINT_HEADROOM`.
const PRESERVE: usize = 0x18_0000;

/// The extent behind a `[cm-flush] ... insufficient-headroom heap-headroom=N` line: `N` was the
/// committed bytes above the bump mark while `committed_frames` were mapped.
fn logged(committed_frames: usize, logged_headroom: usize) -> DurableExtent {
    let committed_end = committed_frames * PAGE;
    DurableExtent {
        bump_end: committed_end - logged_headroom,
        committed_end,
        reservation_end: RESERVATION,
        backing_free: usize::MAX,
    }
}

/// KVM run 43554476320, both refusals: 15872 of 21504 frames were committed, so more than
/// 22 MiB of the reservation was still uncommitted when `NtFlushKey` on SOFTWARE was refused.
#[test]
fn the_logged_software_hive_refusals_had_room_in_the_reservation() {
    for (logged_headroom, required) in [(3_658_272, 4_623_969), (2_095_952, 4_624_207)] {
        let extent = logged(15872, logged_headroom);
        assert_eq!(extent.committed_free(), logged_headroom);
        assert!(extent.committed_free() < required, "the old comparison refused");
        assert_eq!(extent.growable(), (21504 - 15872) * PAGE);
        assert!(extent.obtainable() >= required, "obtainable={}", extent.obtainable());
    }
}

#[test]
fn a_reservation_that_cannot_cover_the_image_is_still_refused() {
    let image = 3 * 1024 * 1024;
    let required = image + PRESERVE;
    // Fully committed, with less than the image and its preserved reserve left.
    let full = DurableExtent {
        bump_end: RESERVATION - required + 1,
        committed_end: RESERVATION,
        reservation_end: RESERVATION,
        backing_free: usize::MAX,
    };
    assert_eq!(full.growable(), 0);
    assert!(full.obtainable() < required);
    // Uncommitted pages count, but only up to the reservation.
    let nearly = DurableExtent {
        bump_end: RESERVATION - required + 1,
        committed_end: RESERVATION - 512 * PAGE,
        reservation_end: RESERVATION,
        backing_free: usize::MAX,
    };
    assert_eq!(nearly.obtainable(), required - 1);
    let exact = DurableExtent { bump_end: RESERVATION - required, ..nearly };
    assert_eq!(exact.obtainable(), required);
}

/// A spawned component's heap is mapped whole: its reservation is its commitment.
#[test]
fn an_eagerly_mapped_heap_has_nothing_to_grow() {
    let extent = DurableExtent {
        bump_end: METADATA + 4096,
        committed_end: 128 * PAGE,
        reservation_end: 128 * PAGE,
        backing_free: 0,
    };
    assert_eq!(extent.growable(), 0);
    assert_eq!(extent.obtainable(), extent.committed_free());
}

/// A reservation is address space. With 22 MiB of it uncommitted but 1 MiB of Untyped memory
/// left, a 4.6 MiB image cannot be built, and admission must say so before the commitment fails.
#[test]
fn uncommitted_reservation_counts_only_as_far_as_memory_can_back_it() {
    let extent = DurableExtent { backing_free: 1 << 20, ..logged(15872, 2_095_952) };
    assert_eq!(extent.growable(), 1 << 20);
    assert_eq!(extent.obtainable(), 2_095_952 + (1 << 20));
    assert!(extent.obtainable() < 4_624_207);
    let exhausted = DurableExtent { backing_free: 0, ..extent };
    assert_eq!(exhausted.obtainable(), exhausted.committed_free());
    // Memory beyond the reservation does not enlarge it.
    let plentiful = DurableExtent { backing_free: 1 << 30, ..extent };
    assert_eq!(plentiful.growable(), (21504 - 15872) * PAGE);
}

/// When a 2 MiB commitment step cannot be backed, the pages the allocation needs still may be.
#[test]
fn the_commit_floor_is_the_requested_page_count_inside_the_reservation() {
    use allocator_headroom::commit_floor;
    let (current, reserved) = (21_000u64, 21_504u64);
    let committed = current as usize * PAGE;
    assert_eq!(commit_floor(current, committed, reserved), None, "already committed");
    assert_eq!(commit_floor(current, committed + 1, reserved), Some(current + 1));
    assert_eq!(commit_floor(current, committed + 3 * PAGE + 1, reserved), Some(current + 4));
    assert_eq!(commit_floor(current, RESERVATION, reserved), Some(reserved));
    assert_eq!(commit_floor(current, RESERVATION + 1, reserved), None, "past the reservation");
}

/// A refused commitment fails the allocation that needed it; it must not stop the executive.
#[test]
fn a_refused_root_heap_commitment_is_an_allocation_failure() {
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let commit = main
        .split("unsafe fn map_own_heap_frames(").nth(1).unwrap()
        .split("\nunsafe fn ").next().unwrap();
    assert!(!commit.contains("panic!"), "commitment refusal must return false");
    assert!(commit.contains("cnode_delete_recycle_r(slot)"), "a refused run returns its frames");
    let allocator = include_str!("../../../components/ntos-executive/src/allocator.rs");
    assert!(allocator.contains("crate::root_untyped_free_bytes()"));
}

/// The hive checkpoint admission asks for what the heap can obtain.
#[test]
fn hive_checkpoint_admission_reads_obtainable_headroom() {
    let handler = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let admission = handler
        .split("fn checkpoint_non_system_boot_mutable_hive_preserving_headroom(").nth(1).unwrap()
        .split("\n    fn ").next().unwrap();
    assert!(admission.contains("crate::allocator::obtainable()"));
    assert!(!admission.contains("crate::allocator::remaining()"));
}
