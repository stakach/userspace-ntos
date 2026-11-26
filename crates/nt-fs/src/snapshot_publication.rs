//! Dirty volume bytes and the snapshot publication epoch they belong to.

use core::sync::atomic::{AtomicU64, Ordering};

const DIRTY: u64 = 1 << 63;
const EPOCH_MASK: u64 = !DIRTY;

/// A capture exhausted the publication counter. Reusing an epoch would certify old bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotPublicationError { EpochExhausted, CrossedCapture }

/// One exact capture, tied to the publication state that issued it.
/// A failed or abandoned capture leaves its volume dirty.
#[must_use = "publish the exact durable capture or retain its owner"]
pub struct SnapshotCaptureEpoch<'a> {
    publication: &'a SnapshotPublicationState,
    epoch: u64,
    pending: bool,
}

impl SnapshotCaptureEpoch<'_> {
    pub fn epoch(&self) -> u64 { self.epoch }

    /// Call only after the snapshot's exact durable terminal and any paired CM acknowledgement,
    /// while still holding the same exclusive physical reserve used to mint this ticket.
    pub fn publish(mut self) -> Result<(), SnapshotPublicationError> {
        // The physical reserve excludes another capture while this owner is live. Check the
        // identity anyway: a crossed owner must not certify bytes from an older image.
        if self.publication.state.load(Ordering::Acquire) & EPOCH_MASK != self.epoch {
            return Err(SnapshotPublicationError::CrossedCapture);
        }
        let prior = self.publication.published.load(Ordering::Acquire);
        if prior >= self.epoch || self.publication.published.compare_exchange(
            prior, self.epoch, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(SnapshotPublicationError::CrossedCapture);
        }
        self.pending = false;
        Ok(())
    }
}

impl Drop for SnapshotCaptureEpoch<'_> {
    fn drop(&mut self) {
        if self.pending { self.publication.mark_dirty(); }
    }
}

/// A snapshot owner clears dirty before capture and publishes only after exact durability.
/// The physical reserve serializes captures; mutations after capture may mark dirty again.
pub struct SnapshotPublicationState {
    /// Dirty and begun move together at capture admission. No observer can see a clean old epoch.
    state: AtomicU64,
    published: AtomicU64,
}

impl SnapshotPublicationState {
    pub const fn new() -> Self {
        Self { state: AtomicU64::new(0), published: AtomicU64::new(0) }
    }

    pub fn is_dirty(&self) -> bool { self.state.load(Ordering::Acquire) & DIRTY != 0 }
    pub fn mark_dirty(&self) { self.state.fetch_or(DIRTY, Ordering::AcqRel); }
    pub fn epochs(&self) -> (u64, u64) {
        (self.state.load(Ordering::Acquire) & EPOCH_MASK,
            self.published.load(Ordering::Acquire))
    }

    /// A lower bound for prior dirty bytes, not a physical lease or WAL append authority.
    /// The caller must serialize its observation with admission of earlier volume mutations.
    pub fn observed_baseline_target(&self) -> Option<u64> {
        let published = self.published.load(Ordering::Acquire);
        let state = self.state.load(Ordering::Acquire);
        let begun = state & EPOCH_MASK;
        if state & DIRTY != 0 { begun.checked_add(1).filter(|epoch| *epoch <= EPOCH_MASK) }
        else { Some(begun.max(published)) }
    }

    /// Atomically consume dirty work and mint its capture epoch under the exclusive reserve.
    /// Retain that reserve until the ticket is published or abandoned.
    /// Native header recheck can defer image capture to a later service turn. Any mutation after
    /// this transition re-dirties the volume, even if the eventual image also contains it.
    /// The executive serializes each in-memory mutation and its dirty mark, and serializes
    /// immutable image capture within one service turn before native writes can reenter.
    pub fn begin_dirty_capture(&self)
        -> Result<Option<SnapshotCaptureEpoch<'_>>, SnapshotPublicationError>
    {
        self.begin_capture(false)
    }

    /// A fold also captures a CM image when ordinary volume bytes were already clean.
    /// The caller holds the exclusive physical reserve through publication or abandonment.
    pub fn begin_fold_capture(&self)
        -> Result<SnapshotCaptureEpoch<'_>, SnapshotPublicationError>
    {
        self.begin_capture(true)?.ok_or(SnapshotPublicationError::EpochExhausted)
    }

    fn begin_capture(&self, force: bool)
        -> Result<Option<SnapshotCaptureEpoch<'_>>, SnapshotPublicationError>
    {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if !force && state & DIRTY == 0 { return Ok(None); }
            let next = (state & EPOCH_MASK).checked_add(1)
                .filter(|epoch| *epoch <= EPOCH_MASK)
                .ok_or(SnapshotPublicationError::EpochExhausted)?;
            match self.state.compare_exchange_weak(state, next,
                Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(Some(SnapshotCaptureEpoch {
                    publication: self, epoch: next, pending: true,
                })),
                Err(observed) => state = observed,
            }
        }
    }

    /// Legacy snapshot-journal retirement owns the entire FileSystem and physical reserve.
    /// It does not mint a WAL baseline target. Only that legacy owner may discard its dirty bit.
    pub fn clear_after_legacy_journal(&self) {
        self.state.fetch_and(EPOCH_MASK, Ordering::AcqRel);
    }

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
        let capture = publication.begin_fold_capture().unwrap();
        capture.publish().unwrap();
        assert!(!publication.is_dirty(), "the folded image already includes prior writes");
        let (begun, published) = publication.epochs();
        assert!(begun > required_after && published >= begun,
            "the retained caller's publication target must be covered by the fold");
    }

    #[test]
    fn mutation_after_fold_capture_remains_dirty_after_publication() {
        let publication = SnapshotPublicationState::new();
        publication.mark_dirty();
        let capture = publication.begin_fold_capture().unwrap();
        let folded_epoch = publication.epochs().0;
        publication.mark_dirty();
        capture.publish().unwrap();
        assert_eq!(publication.epochs(), (folded_epoch, folded_epoch));
        assert!(publication.is_dirty(), "later bytes still require another checkpoint");
    }

    #[test]
    fn failed_fold_keeps_dirty_and_cannot_satisfy_publication_target() {
        let publication = SnapshotPublicationState::new();
        publication.mark_dirty();
        let required_after = publication.epochs().0;
        let capture = publication.begin_fold_capture().unwrap();
        publication.fail_fold();
        drop(capture);
        let (begun, published) = publication.epochs();
        assert!(begun > required_after);
        assert!(published < begun, "failure cannot acknowledge the caller's target");
        assert!(publication.is_dirty());
    }

    #[test]
    fn dirty_equal_epochs_cannot_certify_the_old_publication() {
        let publication = SnapshotPublicationState::new();
        publication.mark_dirty();
        let old_published = publication.epochs().1;
        let required = publication.observed_baseline_target().unwrap();
        assert!(required > old_published);
        let capture = publication.begin_dirty_capture().unwrap().unwrap();
        assert_eq!(capture.epoch(), required);
        assert_eq!(publication.observed_baseline_target(), Some(required));
        capture.publish().unwrap();
        assert_eq!(publication.epochs().1, required);
    }

    #[test]
    fn mutation_after_capture_is_owed_to_the_next_epoch() {
        let publication = SnapshotPublicationState::new();
        publication.mark_dirty();
        let first = publication.begin_dirty_capture().unwrap().unwrap();
        let first_epoch = first.epoch();
        publication.mark_dirty();
        let owed = publication.observed_baseline_target().unwrap();
        assert!(owed > first_epoch);
        first.publish().unwrap();
        assert_eq!(publication.epochs().1, first_epoch);
        assert_eq!(publication.observed_baseline_target(), Some(owed));
        let second = publication.begin_dirty_capture().unwrap().unwrap();
        assert_eq!(second.epoch(), owed);
        second.publish().unwrap();
        assert_eq!(publication.epochs().1, owed);
        assert!(!publication.is_dirty());
    }

    #[test]
    fn crossed_capture_cannot_publish_an_old_epoch() {
        let publication = SnapshotPublicationState::new();
        publication.mark_dirty();
        let first = publication.begin_dirty_capture().unwrap().unwrap();
        let second = publication.begin_fold_capture().unwrap();
        assert_eq!(first.publish(), Err(super::SnapshotPublicationError::CrossedCapture));
        assert_eq!(publication.epochs(), (2, 0));
        second.publish().unwrap();
        assert!(publication.is_dirty(), "refused first owner remains owed");
    }
}
