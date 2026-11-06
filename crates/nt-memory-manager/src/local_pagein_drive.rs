//! Bounded drive policy for a retained image page-in.
//!
//! A caller reports only proven local progress. Pending provider work and an entered Reply
//! yield; neither effect may be retried merely because a local drive budget remains.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveStep { LocalProgress, AwaitExternal, ReplyEntered, Done }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveDecision { Continue, RetryNow, RetryLater, Complete }

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
}
