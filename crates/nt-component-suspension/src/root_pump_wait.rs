//! A root-level caller of an unfinished pump (#420).
//!
//! At root level no lane X waits for a reply, so the caller itself owns the kept pump. It
//! drives the pump between root progress passes until the dispatch finishes, and returns
//! that true outcome. Only a pump that entered an uncertain effect ends the wait without one.

use crate::PumpProgress;

/// How a root wait ended.
#[derive(Debug, Eq, PartialEq)]
pub enum RootPumpWait<P, O> {
    /// The dispatch finished; this is its true outcome.
    Finished(O),
    /// The pump entered an uncertain effect. It is fenced, never replayed.
    Fenced(P),
    /// The root could not run its pass here (a refusal, not an effect). The pump is still
    /// owned and unchanged; the caller's retained owner continues it from a later root turn.
    Retained(P),
}

/// One root progress pass, as the waiter sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootPass {
    Ran,
    /// The pass stopped before its receive; the owner of that step keeps its entered state.
    Refused,
}

/// Drive `pump` once per root progress pass. `pass` runs the root's own work (scheduler
/// service, root restores, receive) between attempts.
pub fn await_root_pump<P, O>(
    mut pump: P,
    mut pass: impl FnMut(),
    mut progress: impl FnMut(P) -> PumpProgress<P, O>,
) -> RootPumpWait<P, O> {
    // No pass budget: running out of passes is not evidence that the dispatch failed.
    loop {
        pass();
        match progress(pump) {
            PumpProgress::Finished(outcome) => return RootPumpWait::Finished(outcome),
            PumpProgress::Fenced(fenced) => return RootPumpWait::Fenced(fenced),
            PumpProgress::Unfinished(next) => pump = next,
        }
    }
}

/// [`await_root_pump`] for a pass that may be refused. A refused pass drives nothing: the pump
/// is handed back as [`RootPumpWait::Retained`] for a later root turn.
pub fn await_root_pump_refusable<P, O>(
    mut pump: P,
    mut pass: impl FnMut() -> RootPass,
    mut progress: impl FnMut(P) -> PumpProgress<P, O>,
) -> RootPumpWait<P, O> {
    loop {
        if pass() == RootPass::Refused { return RootPumpWait::Retained(pump); }
        match progress(pump) {
            PumpProgress::Finished(outcome) => return RootPumpWait::Finished(outcome),
            PumpProgress::Fenced(fenced) => return RootPumpWait::Fenced(fenced),
            PumpProgress::Unfinished(next) => pump = next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn countdown(pump: u32) -> PumpProgress<u32, i32> {
        if pump == 0 { PumpProgress::Finished(7) } else { PumpProgress::Unfinished(pump - 1) }
    }

    #[test]
    fn a_slow_pump_still_returns_its_true_outcome() {
        // A dispatch that needs many root passes is not uncertain: the caller waits for it.
        let mut passes = 0;
        assert_eq!(await_root_pump(500u32, || passes += 1, countdown), RootPumpWait::Finished(7));
        assert_eq!(passes, 501);
    }

    #[test]
    fn only_an_uncertain_pump_ends_the_wait_without_an_outcome() {
        let mut driven = 0;
        let wait = await_root_pump(3u32, || {}, |pump| {
            driven += 1;
            if pump == 2 { PumpProgress::Fenced(pump) } else { countdown(pump) }
        });
        assert_eq!(wait, RootPumpWait::<u32, i32>::Fenced(2));
        assert_eq!(driven, 2, "a fenced pump is never driven again");
    }

    #[test]
    fn a_refused_root_pass_retains_the_pump_for_a_later_turn() {
        // A pass refused before its receive (an owner keeps its entered transport state, or the
        // boot owner refuses a receive transition) is a refusal, not an uncertain effect: the
        // pump stays owned and unchanged, and a later root turn continues it.
        let mut passes = 0;
        let wait = await_root_pump_refusable(4u32, || {
            passes += 1;
            if passes == 2 { RootPass::Refused } else { RootPass::Ran }
        }, countdown);
        assert_eq!(wait, RootPumpWait::Retained(3));
        assert_eq!(passes, 2);
        let resumed = await_root_pump_refusable(3u32, || RootPass::Ran, countdown);
        assert_eq!(resumed, RootPumpWait::Finished(7), "the next turn gets the true outcome");
    }

    #[test]
    fn root_work_runs_before_every_attempt() {
        let mut log = alloc::vec::Vec::new();
        let log_ptr = core::cell::RefCell::new(&mut log);
        let _ = await_root_pump(1u32, || log_ptr.borrow_mut().push("pass"),
            |pump| { log_ptr.borrow_mut().push("drive"); countdown(pump) });
        assert_eq!(log, ["pass", "drive", "pass", "drive"]);
    }
}
