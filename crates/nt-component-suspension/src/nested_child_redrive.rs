//! The outcome of one nested child redrive while its parent invocation is parked (#427).

/// What one nested child redrive achieved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedChildRedrive {
    /// A child made progress.
    Progressed,
    /// No child progressed because no lane could admit its request yet. Nothing reached a
    /// driver, so nothing is uncertain; it is retried when a lane becomes idle.
    Waiting,
    /// A child was ready but neither progressed nor was refused admission: its effect is
    /// uncertain.
    Uncertain,
}

/// What the parked parent does next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedChildDecision {
    RestoreParent,
    Quarantine,
}

/// Classify a redrive of a ready child from whether it progressed and whether a request was
/// refused admission (not entered) during it.
pub const fn nested_child_redrive(progressed: bool, refused_admission: bool) -> NestedChildRedrive {
    if progressed {
        NestedChildRedrive::Progressed
    } else if refused_admission {
        NestedChildRedrive::Waiting
    } else {
        NestedChildRedrive::Uncertain
    }
}

impl NestedChildRedrive {
    pub const fn decision(self) -> NestedChildDecision {
        match self {
            Self::Progressed | Self::Waiting => NestedChildDecision::RestoreParent,
            Self::Uncertain => NestedChildDecision::Quarantine,
        }
    }
}

/// Fold one runner's redrive into a pass. Any progress is progress (an uncertain runner's work
/// stays retained); otherwise one uncertain runner makes the pass uncertain, and only a pass in
/// which every tried runner was refused admission is waiting.
pub const fn fold_nested_child_redrive(
    pass: Option<NestedChildRedrive>,
    runner: NestedChildRedrive,
) -> Option<NestedChildRedrive> {
    Some(match (pass, runner) {
        (Some(NestedChildRedrive::Progressed), _) | (_, NestedChildRedrive::Progressed) =>
            NestedChildRedrive::Progressed,
        (Some(NestedChildRedrive::Uncertain), _) | (_, NestedChildRedrive::Uncertain) =>
            NestedChildRedrive::Uncertain,
        _ => NestedChildRedrive::Waiting,
    })
}

/// The outcome of a pass over the runners it tried; a ready pass that tried none is uncertain.
pub fn combine_nested_child_redrives(tried: &[NestedChildRedrive]) -> NestedChildRedrive {
    tried.iter().fold(None, |pass, runner| fold_nested_child_redrive(pass, *runner))
        .unwrap_or(NestedChildRedrive::Uncertain)
}

/// Dispatch admission counters sampled around one row attempt (#427).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdmissionCounts {
    /// Dispatches refused admission by every lane, with nothing entered.
    pub refusals: u64,
    /// Admitted dispatches that returned or yielded from their provider.
    pub admitted: u64,
}

/// One runner's pass over up to `attempts` retained rows, classifying each row attempt by its
/// own admission (#427). A row attempt advances one row by one stage, so it makes at most one
/// dispatch. A refused dispatch is decided before anything enters, so nothing nests inside it:
/// the attempt was refused only if a refusal was counted and no admitted dispatch returned.
/// A refusal on one row never excuses another row, and a refusal nested inside an admitted
/// dispatch is not that row's own. Stops at the first progressed row. `None` means no row was
/// attempted.
pub fn nested_rows_pass(
    attempts: usize,
    counts: impl Fn() -> AdmissionCounts,
    mut redrive_one: impl FnMut() -> bool,
) -> (bool, Option<NestedChildRedrive>) {
    let mut pass = None;
    for _ in 0..attempts {
        let before = counts();
        let progressed = redrive_one();
        let after = counts();
        let refused = after.refusals != before.refusals && after.admitted == before.admitted;
        pass = fold_nested_child_redrive(pass, nested_child_redrive(progressed, refused));
        if progressed { return (true, pass); }
    }
    (false, pass)
}
