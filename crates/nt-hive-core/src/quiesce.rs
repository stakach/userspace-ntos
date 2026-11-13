//! Durability decision for a v2 hive whose primary image may lag its acknowledged WAL.

/// Evidence about the exact hive edit at the quiesce boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiveJournalEvidence {
    /// No edit is pending, or every published edit crossed its paired WAL anchor ACK.
    Acknowledged,
    /// The exact edit or its provider completion is still owned by the native executor.
    Pending,
    /// An entered effect has an unresolved outcome; no new durability claim is possible.
    Uncertain,
}

/// State of a separate volume snapshot needed for non-journaled file changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeSnapshotEvidence {
    NotRequired,
    Required,
    Pending,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiveQuiesceDecision {
    Durable,
    BeginSnapshot,
    WaitForOwner,
    RefuseUncertain,
}

/// Dirty cells request later primary-image compaction; they are not evidence of lost WAL data.
/// The caller must derive `Acknowledged` only from a publication that followed exact WAL and
/// paired-anchor provider completion. This contract never turns an owner into an ACK.
pub const fn v2_hive_quiesce_decision(
    _dirty_cells: usize,
    journal: HiveJournalEvidence,
    snapshot: VolumeSnapshotEvidence,
) -> HiveQuiesceDecision {
    use HiveJournalEvidence as Journal;
    use HiveQuiesceDecision as Decision;
    use VolumeSnapshotEvidence as Snapshot;
    match journal {
        Journal::Uncertain => Decision::RefuseUncertain,
        Journal::Pending => Decision::WaitForOwner,
        Journal::Acknowledged => match snapshot {
            Snapshot::NotRequired => Decision::Durable,
            Snapshot::Required => Decision::BeginSnapshot,
            Snapshot::Pending => Decision::WaitForOwner,
            Snapshot::Uncertain => Decision::RefuseUncertain,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_acknowledged_hive_is_durable_without_rewriting_primary_image() {
        for dirty_cells in [0, 1, 96, usize::MAX] {
            assert_eq!(v2_hive_quiesce_decision(dirty_cells,
                HiveJournalEvidence::Acknowledged, VolumeSnapshotEvidence::NotRequired),
                HiveQuiesceDecision::Durable);
        }
    }

    #[test]
    fn retained_or_uncertain_journal_cannot_cross_quiesce_even_if_snapshot_is_clean() {
        for snapshot in [VolumeSnapshotEvidence::NotRequired,
            VolumeSnapshotEvidence::Required, VolumeSnapshotEvidence::Pending] {
            assert_eq!(v2_hive_quiesce_decision(96,
                HiveJournalEvidence::Pending, snapshot), HiveQuiesceDecision::WaitForOwner);
            assert_eq!(v2_hive_quiesce_decision(96,
                HiveJournalEvidence::Uncertain, snapshot), HiveQuiesceDecision::RefuseUncertain);
        }
    }

    #[test]
    fn snapshot_owner_needs_its_own_provider_ack() {
        let journal = HiveJournalEvidence::Acknowledged;
        assert_eq!(v2_hive_quiesce_decision(96, journal,
            VolumeSnapshotEvidence::Required), HiveQuiesceDecision::BeginSnapshot);
        assert_eq!(v2_hive_quiesce_decision(96, journal,
            VolumeSnapshotEvidence::Pending), HiveQuiesceDecision::WaitForOwner);
        assert_eq!(v2_hive_quiesce_decision(96, journal,
            VolumeSnapshotEvidence::Uncertain), HiveQuiesceDecision::RefuseUncertain);
        assert_eq!(v2_hive_quiesce_decision(96, journal,
            VolumeSnapshotEvidence::NotRequired), HiveQuiesceDecision::Durable);
    }
}
