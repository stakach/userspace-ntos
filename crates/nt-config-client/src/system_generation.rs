//! Which SYSTEM generations a reader may accept from CM.
//!
//! CM publishes a mutation when it executes COMMIT. The executive advances its durable
//! generation only after the commit marker is stable, which takes storage I/O and therefore
//! service-loop turns in which other callers run. A read issued in that interval observes the
//! generation CM has already published.

/// The executive's two observations of the mounted SYSTEM generation.
///
/// `durable` is the last generation whose commit marker is stable; mutations are admitted
/// against it. `commit_entered` is the generation of the latest COMMIT the executive issued.
/// A COMMIT that has been entered may already be published by CM, whether or not its reply
/// has been received, and is never rolled back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemGenerationView {
    durable: u64,
    commit_entered: u64,
}

impl SystemGenerationView {
    pub const fn new(durable: u64, commit_entered: u64) -> Self {
        Self { durable, commit_entered }
    }

    /// A read may observe the durable generation or the one entered COMMIT ahead of it.
    /// Registry reads in NT observe published state; durability is the writer's concern.
    /// Any other generation is a different mount history and stays refused.
    pub const fn admits_read(self, observed: u64) -> bool {
        if self.durable == 0 {
            return false;
        }
        if observed == self.durable {
            return true;
        }
        match self.durable.checked_add(1) {
            Some(successor) => observed == successor && successor == self.commit_entered,
            None => false,
        }
    }

    /// The generation to validate a read against: `observed` when admitted, else `durable`.
    pub const fn read_generation(self, observed: u64) -> u64 {
        if self.admits_read(observed) {
            observed
        } else {
            self.durable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SystemGenerationView;

    #[test]
    fn durable_generation_is_readable() {
        let view = SystemGenerationView::new(34, 34);
        assert!(view.admits_read(34));
        assert_eq!(view.read_generation(34), 34);
    }

    /// KVM run 43658485489: lsass opened a SYSTEM key while services.exe's mutation was
    /// between CM COMMIT and its durable marker, and received STATUS_DEVICE_NOT_READY.
    #[test]
    fn entered_commit_generation_is_readable_before_its_marker_is_durable() {
        let view = SystemGenerationView::new(34, 35);
        assert!(view.admits_read(35));
        assert_eq!(view.read_generation(35), 35);
        // The COMMIT may not have taken effect yet; CM then still reports the durable one.
        assert!(view.admits_read(34));
    }

    #[test]
    fn unrelated_generations_stay_refused() {
        let view = SystemGenerationView::new(34, 35);
        assert!(!view.admits_read(33));
        assert!(!view.admits_read(36));
        assert!(!view.admits_read(0));
        assert_eq!(view.read_generation(36), 34);
    }

    #[test]
    fn stale_entered_generation_grants_nothing() {
        // An earlier mount's entered COMMIT is not the successor of this durable generation.
        assert!(!SystemGenerationView::new(7, 35).admits_read(35));
        assert!(!SystemGenerationView::new(34, 12).admits_read(12));
        // Once the marker is durable the two agree and only that generation is readable.
        let settled = SystemGenerationView::new(35, 35);
        assert!(settled.admits_read(35));
        assert!(!settled.admits_read(36));
    }

    #[test]
    fn unmounted_system_hive_admits_no_read() {
        assert!(!SystemGenerationView::new(0, 0).admits_read(0));
        assert!(!SystemGenerationView::new(0, 1).admits_read(1));
    }
}
