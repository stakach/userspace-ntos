//! Order of committed volume mutations in one physical WAL incarnation.

/// The first record may follow a prefix already folded into the selected snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VolumeWalReplayCursor {
    last: Option<u64>,
}

impl VolumeWalReplayCursor {
    pub fn new() -> Self { Self::default() }

    pub fn last_applied(&self) -> Option<u64> { self.last }

    pub(crate) fn admits(&self, sequence: u64) -> bool {
        match self.last {
            None => sequence != 0,
            Some(last) => last.checked_add(1) == Some(sequence),
        }
    }

    pub(crate) fn advance(&mut self, sequence: u64) {
        self.last = Some(sequence);
    }
}
