//! Source Reply/callback admission for a foreign lower POWER request.
//!
//! A source-visible Reply is not proof that its native completion callback returned. The
//! forwarding pin stays live across that interval even if the source service is cancelled.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowerForwardProgress {
    pub cancelled: bool,
    pub reply_entered: bool,
    pub source_published: bool,
    pub native_completed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerForwardDecision {
    MayDispatch,
    RetainLiveCallback,
    RetireStoppedSource,
    RetireAfterNativeCompletion,
}

pub const fn decision(progress: PowerForwardProgress) -> PowerForwardDecision {
    if !progress.cancelled {
        return PowerForwardDecision::MayDispatch;
    }
    if progress.reply_entered && progress.source_published && !progress.native_completed {
        return PowerForwardDecision::RetainLiveCallback;
    }
    if progress.native_completed {
        PowerForwardDecision::RetireAfterNativeCompletion
    } else {
        PowerForwardDecision::RetireStoppedSource
    }
}
