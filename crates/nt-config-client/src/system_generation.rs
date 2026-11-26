//! Which SYSTEM generations a reader may accept from CM.
//!
//! CM publishes a mutation when it executes COMMIT. The executive advances its durable
//! generation only after the commit marker is stable, which takes storage I/O and therefore
//! service-loop turns in which other callers run. A read issued in that interval observes the
//! generation CM has already published.

/// The executive's observations of the mounted SYSTEM generation.
///
/// `durable` is the last generation whose commit marker is stable. `published` is the latest
/// generation CM acknowledged as committed, including a suffix awaiting a durability barrier.
/// `commit_entered` is the generation of the latest COMMIT the executive issued.
/// A COMMIT that has been entered may already be published by CM, whether or not its reply
/// has been received, and is never rolled back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemGenerationView {
    durable: u64,
    published: u64,
    commit_entered: u64,
}

impl SystemGenerationView {
    pub const fn new(durable: u64, published: u64, commit_entered: u64) -> Self {
        Self { durable, published, commit_entered }
    }

    /// A read may observe any published generation, or the one entered COMMIT ahead of it.
    /// Registry reads in NT observe published state; durability is the writer's concern.
    /// Any other generation is a different mount history and stays refused.
    pub const fn admits_read(self, observed: u64) -> bool {
        if self.durable == 0 || self.published < self.durable {
            return false;
        }
        if observed >= self.durable && observed <= self.published {
            return true;
        }
        match self.published.checked_add(1) {
            Some(successor) => observed == successor && successor == self.commit_entered,
            None => false,
        }
    }

    /// The generation to validate a read against: `observed` when admitted, else the latest
    /// known generation. An invalid or unmounted view has no generation to validate against.
    pub const fn read_generation(self, observed: u64) -> u64 {
        if self.durable == 0 || self.published < self.durable {
            return 0;
        }
        if self.admits_read(observed) {
            observed
        } else {
            self.published
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SystemGenerationView;

    #[test]
    fn durable_generation_is_readable() {
        let view = SystemGenerationView::new(34, 34, 34);
        assert!(view.admits_read(34));
        assert_eq!(view.read_generation(34), 34);
    }

    /// KVM run 43658485489: lsass opened a SYSTEM key while services.exe's mutation was
    /// between CM COMMIT and its durable marker, and received STATUS_DEVICE_NOT_READY.
    #[test]
    fn entered_commit_generation_is_readable_before_its_marker_is_durable() {
        let view = SystemGenerationView::new(34, 34, 35);
        assert!(view.admits_read(35));
        assert_eq!(view.read_generation(35), 35);
        // The COMMIT may not have taken effect yet; CM then still reports the durable one.
        assert!(view.admits_read(34));
    }

    #[test]
    fn unrelated_generations_stay_refused() {
        let view = SystemGenerationView::new(34, 34, 35);
        assert!(!view.admits_read(33));
        assert!(!view.admits_read(36));
        assert!(!view.admits_read(0));
        assert_eq!(view.read_generation(36), 34);
    }

    #[test]
    fn stale_entered_generation_grants_nothing() {
        // An earlier mount's entered COMMIT is not the successor of this durable generation.
        assert!(!SystemGenerationView::new(7, 7, 35).admits_read(35));
        assert!(!SystemGenerationView::new(34, 34, 12).admits_read(12));
        // Once the marker is durable the two agree and only that generation is readable.
        let settled = SystemGenerationView::new(35, 35, 35);
        assert!(settled.admits_read(35));
        assert!(!settled.admits_read(36));
    }

    #[test]
    fn unmounted_system_hive_admits_no_read() {
        assert!(!SystemGenerationView::new(0, 0, 0).admits_read(0));
        assert!(!SystemGenerationView::new(0, 0, 1).admits_read(1));
    }

    #[test]
    fn several_published_generations_remain_readable_before_the_batch_is_durable() {
        let view = SystemGenerationView::new(34, 36, 37);
        for generation in 34..=37 {
            assert!(view.admits_read(generation));
            assert_eq!(view.read_generation(generation), generation);
        }
        assert!(!view.admits_read(33));
        assert!(!view.admits_read(38));
        assert_eq!(view.read_generation(38), 36);
    }

    #[test]
    fn entered_commit_cannot_skip_the_published_high_water_or_wrap_it() {
        let skipped = SystemGenerationView::new(34, 36, 39);
        assert!(!skipped.admits_read(39));
        assert_eq!(skipped.read_generation(39), 36);

        let exhausted = SystemGenerationView::new(u64::MAX - 1, u64::MAX, 0);
        assert!(exhausted.admits_read(u64::MAX));
        assert!(!exhausted.admits_read(0));
    }

    #[test]
    fn an_unmounted_or_regressed_published_range_grants_no_read() {
        assert!(!SystemGenerationView::new(0, 2, 3).admits_read(2));
        assert!(!SystemGenerationView::new(34, 33, 34).admits_read(34));
        assert_eq!(SystemGenerationView::new(0, 2, 3).read_generation(2), 0);
        assert_eq!(SystemGenerationView::new(34, 33, 34).read_generation(34), 0);
    }
}
