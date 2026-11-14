//! Durable heap headroom counts what the heap can still commit, not only what is mapped now.

#[path = "../../../components/ntos-executive/src/allocator_headroom.rs"]
mod allocator_headroom;

use allocator_headroom::DurableExtent;

const PAGE: usize = 0x1000;
/// Allocator metadata ahead of the first allocation (`allocator::DATA - HEAP_BASE`).
const METADATA: usize = 152;
/// `EXECUTIVE_DURABLE_HEAP_FRAMES`: the root reservation less its transient lane.
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
    };
    assert_eq!(full.growable(), 0);
    assert!(full.obtainable() < required);
    // Uncommitted pages count, but only up to the reservation.
    let nearly = DurableExtent {
        bump_end: RESERVATION - required + 1,
        committed_end: RESERVATION - 512 * PAGE,
        reservation_end: RESERVATION,
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
    };
    assert_eq!(extent.growable(), 0);
    assert_eq!(extent.obtainable(), extent.committed_free());
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
