//! Exact value-log ownership retained across ambiguous provider effects.
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HiveValueJournalPhase {
    AppendEntered,
    FlushEntered,
}

#[derive(Clone)]
pub(crate) struct PendingHiveValueJournal {
    pub(crate) sequence: u64,
    pub(crate) phase: HiveValueJournalPhase,
    pub(crate) record: Vec<u8>,
}

/// Read-only observation, not permission to replay or retire a pending publication.
#[derive(Clone, Copy, Debug)]
pub struct RetainedHiveValueJournal<'a> {
    pub sequence: u64,
    pub phase: HiveValueJournalPhase,
    pub record: &'a [u8],
}

impl super::Hive {
    pub fn retained_value_journal(&self) -> Option<RetainedHiveValueJournal<'_>> {
        self.pending_value_journal
            .as_ref()
            .map(|pending| RetainedHiveValueJournal {
                sequence: pending.sequence,
                phase: pending.phase,
                record: &pending.record,
            })
    }
}
