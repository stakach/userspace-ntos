//! Bounded logical cache completions before a single physical block attempt.

/// A completed copied-sector claim permits another logical claim in this turn.
/// Every other outcome ends the turn, including an unentered refusal or an
/// uncertain physical effect with zero reported progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheClaimStep {
    Cached,
    Stop(usize),
}

impl CacheClaimStep {
    pub const fn progress(self) -> usize {
        match self {
            Self::Cached => 1,
            Self::Stop(progress) => progress,
        }
    }
}

/// Select and complete at most `limit` exact cached claims in one owner turn.
/// `next` retains the caller's scheduling order. `dispatch` must return `Cached`
/// only after the retained logical claim has been completed from a verified copy;
/// it returns `Stop` for every physical, deferred, refused or uncertain attempt.
pub fn drain_cached_claims<Claim, Next, Dispatch>(
    limit: usize, mut next: Next, mut dispatch: Dispatch,
) -> usize
where
    Next: FnMut() -> Option<Claim>,
    Dispatch: FnMut(Claim) -> CacheClaimStep,
{
    let mut progress = 0usize;
    for _ in 0..limit {
        let Some(claim) = next() else { break; };
        match dispatch(claim) {
            CacheClaimStep::Cached => progress = progress.saturating_add(1),
            CacheClaimStep::Stop(stop_progress) =>
                return progress.saturating_add(stop_progress),
        }
    }
    progress
}
