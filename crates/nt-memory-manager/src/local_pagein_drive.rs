//! Bounded drive policy for a retained routed page-in.
//!
//! A caller reports only proven local progress. Pending provider work and an entered Reply
//! yield; neither effect may be retried merely because a local drive budget remains.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveStep { LocalProgress, AwaitExternal, ReplyEntered, Done }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveDecision { Continue, RetryNow, RetryLater, Complete }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveBoundary { Local, External, ReplyEntered, Uncertain }

/// A phase change is not enough to authorize another step: an entered Reply,
/// uncertain effect or pending provider still owns the next transition.
pub fn classify_drive_step(done: bool, boundary: DriveBoundary, progressed: bool) -> DriveStep {
    if done { return DriveStep::Done; }
    match boundary {
        DriveBoundary::Local if progressed => DriveStep::LocalProgress,
        DriveBoundary::ReplyEntered => DriveStep::ReplyEntered,
        DriveBoundary::Local | DriveBoundary::External | DriveBoundary::Uncertain =>
            DriveStep::AwaitExternal,
    }
}

pub struct LocalDriveBudget { remaining: usize }

impl LocalDriveBudget {
    pub const fn new(limit: usize) -> Self { Self { remaining: limit } }

    pub fn observe(&mut self, step: DriveStep) -> DriveDecision {
        match step {
            DriveStep::Done => DriveDecision::Complete,
            DriveStep::AwaitExternal | DriveStep::ReplyEntered => DriveDecision::RetryLater,
            DriveStep::LocalProgress => {
                self.remaining = self.remaining.saturating_sub(1);
                if self.remaining == 0 { DriveDecision::RetryNow }
                else { DriveDecision::Continue }
            }
        }
    }

    /// Consume only locally proven progress in one drive. The caller classifies
    /// a provider wait, uncertain effect, or entered Reply as a yield boundary.
    pub fn drive_while_local(mut self, mut advance: impl FnMut() -> DriveStep) -> DriveDecision {
        loop {
            match self.observe(advance()) {
                DriveDecision::Continue => {}
                boundary => return boundary,
            }
        }
    }
}
