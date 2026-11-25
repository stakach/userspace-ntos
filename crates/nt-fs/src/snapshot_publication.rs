//! Dirty volume bytes and the snapshot publication epoch they belong to.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A snapshot owner clears dirty before capture and publishes only after exact durability.
/// The physical reserve serializes captures; mutations after capture may mark dirty again.
pub struct SnapshotPublicationState {
    dirty: AtomicBool,
    begun: AtomicU64,
    published: AtomicU64,
}

impl SnapshotPublicationState {
    pub const fn new() -> Self {
        Self { dirty: AtomicBool::new(false), begun: AtomicU64::new(0),
            published: AtomicU64::new(0) }
    }

    pub fn is_dirty(&self) -> bool { self.dirty.load(Ordering::Acquire) }
    pub fn mark_dirty(&self) { self.dirty.store(true, Ordering::Release); }
    pub fn clear_dirty(&self) { self.dirty.store(false, Ordering::Release); }
    pub fn take_dirty(&self) -> bool { self.dirty.swap(false, Ordering::AcqRel) }
    pub fn epochs(&self) -> (u64, u64) {
        (self.begun.load(Ordering::Acquire), self.published.load(Ordering::Acquire))
    }

    /// Call only after the dirty bit was cleared under the exclusive snapshot reserve.
    pub fn record_begun(&self) { self.begun.fetch_add(1, Ordering::AcqRel); }

    /// Call only after this owner's snapshot reached its exact durable completion.
    pub fn publish_current(&self) {
        self.published.store(self.begun.load(Ordering::Acquire), Ordering::Release);
    }

    /// The fold's capture boundary, under the same exclusive reserve as ordinary checkpoints.
    /// A later mutation re-dirties the volume while this image is in flight.
    pub fn begin_fold_capture(&self) {
        self.clear_dirty();
        self.record_begun();
    }

    /// The fold's exact terminal publication boundary: both slots, CM ACK, and shared install.
    pub fn complete_fold(&self) { self.publish_current(); }

    /// Retain dirty work when the fold did not publish.
    pub fn fail_fold(&self) { self.mark_dirty(); }

    /// A read-only checkpoint recheck was refused before any snapshot write entered.
    /// The existing begun epoch stays unpublished and its bytes must be retried.
    pub fn abort_unwritten_checkpoint(&self) { self.mark_dirty(); }
}

impl Default for SnapshotPublicationState {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::SnapshotPublicationState;

    #[test]
    fn folded_capture_publishes_owed_epoch_without_third_snapshot() {
        let publication = SnapshotPublicationState::new();
        publication.mark_dirty();
        let required_after = publication.epochs().0;
        publication.begin_fold_capture();
        publication.complete_fold();
        assert!(!publication.is_dirty(), "the folded image already includes prior writes");
        let (begun, published) = publication.epochs();
        assert!(begun > required_after && published >= begun,
            "the retained caller's publication target must be covered by the fold");
    }

    #[test]
    fn mutation_after_fold_capture_remains_dirty_after_publication() {
        let publication = SnapshotPublicationState::new();
        publication.mark_dirty();
        publication.begin_fold_capture();
        let folded_epoch = publication.epochs().0;
        publication.mark_dirty();
        publication.complete_fold();
        assert_eq!(publication.epochs(), (folded_epoch, folded_epoch));
        assert!(publication.is_dirty(), "later bytes still require another checkpoint");
    }

    #[test]
    fn failed_fold_keeps_dirty_and_cannot_satisfy_publication_target() {
        let publication = SnapshotPublicationState::new();
        publication.mark_dirty();
        let required_after = publication.epochs().0;
        publication.begin_fold_capture();
        publication.fail_fold();
        let (begun, published) = publication.epochs();
        assert!(begun > required_after);
        assert!(published < begun, "failure cannot acknowledge the caller's target");
        assert!(publication.is_dirty());
    }
}
