//! When the service loop's process-retirement drain has work to look for.
//!
//! The drain retries unstarted-process abandonment, rediscovers signaled processes whose
//! deletion row was never queued, deletes queued candidates and retires failed thread spawns.
//! Each of those inputs is created at a known point: the Process Manager advances its
//! deletion-demand epoch when a process becomes signaled or an abandonment is requested,
//! candidates are counted by their own table, and a retained failed spawn marks this demand.
//! A pass that leaves any of its work unfinished keeps the demand, so retained work is still
//! retried at every boundary exactly as before; only a pass with nothing new to find is skipped.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessDeletionDemand {
    seen_epoch: Option<u64>,
    marked: bool,
    retained: bool,
}

/// One admitted drain pass; [`ProcessDeletionDemand::finish`] consumes it.
#[must_use = "finish the admitted pass with whether it left work behind"]
pub(crate) struct DeletionPass(());

impl ProcessDeletionDemand {
    /// No pass has run yet, so the first boundary looks.
    pub(crate) const fn new() -> Self {
        Self { seen_epoch: None, marked: false, retained: false }
    }

    /// New work the Process Manager epoch does not cover: a retained failed thread spawn.
    pub(crate) fn mark(&mut self) {
        self.marked = true;
    }

    /// Admit a pass when anything may need it. `epoch` is sampled now, so a change made while
    /// the pass runs is seen by the next boundary.
    pub(crate) fn begin(&mut self, epoch: u64, candidates_live: bool) -> Option<DeletionPass> {
        if !(self.marked || self.retained || candidates_live || self.seen_epoch != Some(epoch)) {
            return None;
        }
        self.marked = false;
        self.seen_epoch = Some(epoch);
        Some(DeletionPass(()))
    }

    /// `retained`: the pass found work it could not finish.
    pub(crate) fn finish(&mut self, _pass: DeletionPass, retained: bool) {
        self.retained = retained;
    }
}
