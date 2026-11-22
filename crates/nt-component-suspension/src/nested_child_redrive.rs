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
