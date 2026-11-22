//! One root pass over retained rows that advance one phase per step (#420).
//!
//! A row whose step makes it ready for its next phase (a directory publication that has just
//! reached its Reply) can act at once. Leaving that phase to a later pass hands it to whatever
//! event happens to run the pass next. A parked AddDevice turn then sees no ready child while
//! its provider waits on this very Reply, and the root goes idle with the Reply never sent
//! (boot 44975664572: `[directory-redrive] #4 ... phase=ready-reply`, then nothing).

/// What one pass did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedrivePass {
    /// The first step made no progress.
    Idle,
    /// Rows progressed, and the last step found nothing more to do now.
    Settled,
    /// The bound was reached while rows were still progressing. The caller keeps its rows due
    /// now, so the next pass continues without waiting for a retry delay.
    Exhausted,
}

impl RedrivePass {
    pub fn progressed(self) -> bool {
        self != Self::Idle
    }
}

/// Step until a step makes no progress, at most `bound` steps.
pub fn drive_until_settled(bound: usize, mut step: impl FnMut() -> bool) -> RedrivePass {
    let mut progressed = false;
    for _ in 0..bound {
        if !step() {
            return if progressed { RedrivePass::Settled } else { RedrivePass::Idle };
        }
        progressed = true;
    }
    if progressed { RedrivePass::Exhausted } else { RedrivePass::Idle }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider directory publication, one phase per step, as the executive broker drives it.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Phase { CanonicalPending, ReadyReply, ReplyEntered }

    struct Row { phase: Phase, canonical_terminal: bool }

    impl Row {
        fn step(&mut self) -> bool {
            match self.phase {
                Phase::CanonicalPending if self.canonical_terminal => {
                    self.phase = Phase::ReadyReply;
                    true
                }
                Phase::ReadyReply => {
                    self.phase = Phase::ReplyEntered;
                    true
                }
                // Waits on the provider's transport ACK, a later event.
                Phase::CanonicalPending | Phase::ReplyEntered => false,
            }
        }
    }

    #[test]
    fn a_row_that_becomes_ready_in_a_pass_is_replied_in_that_pass() {
        let mut row = Row { phase: Phase::CanonicalPending, canonical_terminal: false };
        assert_eq!(drive_until_settled(8, || row.step()), RedrivePass::Idle);
        assert_eq!(row.phase, Phase::CanonicalPending);

        row.canonical_terminal = true;
        assert_eq!(drive_until_settled(8, || row.step()), RedrivePass::Settled);
        assert_eq!(row.phase, Phase::ReplyEntered,
            "the ready Reply is sent in the pass that observed the canonical terminal, not \
             left for an unrelated later event");
    }

    #[test]
    fn a_pass_stopped_by_its_bound_says_so() {
        let mut steps = 0;
        assert_eq!(drive_until_settled(3, || { steps += 1; true }), RedrivePass::Exhausted);
        assert_eq!(steps, 3);
        assert!(RedrivePass::Exhausted.progressed());
        assert_eq!(drive_until_settled(0, || true), RedrivePass::Idle);
    }
}
