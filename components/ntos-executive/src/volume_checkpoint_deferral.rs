//! Policy for a mounted-volume checkpoint attempt that reports busy.
//!
//! A checkpoint that returns `STATUS_DEVICE_BUSY` has consumed nothing: either its own retained
//! native commit is still writing, or another owner holds the snapshot reserve. Busy is never
//! an answer in its own right. A service boundary keeps the durable requirement and retries on
//! a later turn. A caller NT completes only once its data is durable waits, and is satisfied
//! only by a checkpoint begun after its bytes were written. An owner that reports busy without
//! advancing for `MAX_STALLED_100NS` is a failure with its own name, not an endless retry.

const STATUS_SUCCESS: u32 = 0;
pub(crate) const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;

/// What a caller sees when the busy owner stalled: its data is not durable, and it is not busy.
pub(crate) const STATUS_IO_TIMEOUT: u32 = 0xC000_00B5;

/// Longest a busy checkpoint may go without its owner advancing.
pub(crate) const MAX_STALLED_100NS: u64 = 120 * 10_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Nothing was owed, or the owed snapshot is durable. `deferrals` counts the busy attempts
    /// this publication waited through, over `waited_100ns`.
    Settled { episode: u64, deferrals: u64, waited_100ns: u64 },
    /// Busy within the bound: the durable requirement stays owed and the next boundary retries.
    /// `first` marks the attempt that opened this episode.
    Deferred { episode: u64, first: bool },
    /// Busy with no owner progress for the whole bound.
    Stalled { status: u32, deferrals: u64, stalled_100ns: u64 },
    /// The attempt was refused; the service boundary reports this status.
    Failed(u32),
}

/// What a caller that is kept until its data is durable does after one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallerStep {
    /// The attempt is in flight: keep the caller and attempt again on a later turn.
    Wait,
    /// Complete the caller with this status.
    Complete(u32),
}

impl Outcome {
    /// The caller's view of one attempt. It never completes with the busy status.
    pub(crate) fn caller_step(self) -> CallerStep {
        match self {
            Outcome::Settled { .. } => CallerStep::Complete(STATUS_SUCCESS),
            Outcome::Deferred { .. } => CallerStep::Wait,
            Outcome::Stalled { .. } => CallerStep::Complete(STATUS_IO_TIMEOUT),
            Outcome::Failed(status) => CallerStep::Complete(status),
        }
    }
}

/// The publication one caller needs. Checkpoints are counted as they begin, and a checkpoint
/// captures the volume after it begins, so the first one begun after the caller's bytes were
/// written is the first that is certain to hold them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicationTarget {
    need: u64,
}

/// One checkpoint attempt, as the caller holding a [`PublicationTarget`] sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Publication {
    /// The caller's bytes are durable. `settled` is false when a later checkpoint is still in
    /// flight for other bytes, whose requirement stays owed.
    Durable { settled: bool },
    /// This attempt consumed a publication that may predate the caller's bytes: attempt again.
    Again,
    /// A checkpoint that can cover the caller's bytes has not published yet.
    InFlight,
    /// The checkpoint was refused.
    Failed(u32),
}

impl PublicationTarget {
    /// `begun` is the count of checkpoints begun when the caller's bytes were written.
    pub(crate) const fn after(begun: u64) -> Self {
        Self { need: begun + 1 }
    }

    /// `attempt` is the checkpoint's answer (`Ok(true)` published, `Ok(false)` already clean);
    /// `published` is the count of the latest checkpoint to publish, read after the attempt.
    pub(crate) fn classify(self, attempt: Result<bool, u32>, published: u64) -> Publication {
        match attempt {
            Ok(false) => Publication::Durable { settled: true },
            Ok(true) if published >= self.need => Publication::Durable { settled: true },
            Ok(true) => Publication::Again,
            Err(STATUS_DEVICE_BUSY) if published >= self.need => {
                Publication::Durable { settled: false }
            }
            Err(STATUS_DEVICE_BUSY) => Publication::InFlight,
            Err(status) => Publication::Failed(status),
        }
    }
}

struct Episode<P> {
    opened_100ns: u64,
    advanced_100ns: u64,
    progress: P,
    deferrals: u64,
}

/// One volume's deferred checkpoint. `P` is the busy owner's progress observation: any change
/// between two attempts proves the owner advanced.
pub(crate) struct Deferral<P> {
    episode: Option<Episode<P>>,
    episodes: u64,
}

impl<P: PartialEq> Deferral<P> {
    pub(crate) const fn new() -> Self {
        Self { episode: None, episodes: 0 }
    }

    /// Classify one attempt. The clock and the owner's progress are read only for a busy attempt
    /// or to close an open episode, so an ordinary clean boundary costs neither.
    pub(crate) fn observe(
        &mut self,
        status: u32,
        progress: impl FnOnce() -> P,
        now: impl FnOnce() -> u64,
    ) -> Outcome {
        match status {
            STATUS_SUCCESS => match self.episode.take() {
                None => Outcome::Settled { episode: self.episodes, deferrals: 0, waited_100ns: 0 },
                Some(episode) => Outcome::Settled {
                    episode: self.episodes,
                    deferrals: episode.deferrals,
                    waited_100ns: now().saturating_sub(episode.opened_100ns),
                },
            },
            STATUS_DEVICE_BUSY => {
                let (now, progress) = (now(), progress());
                let Some(episode) = self.episode.as_mut() else {
                    self.episodes += 1;
                    self.episode = Some(Episode {
                        opened_100ns: now,
                        advanced_100ns: now,
                        progress,
                        deferrals: 1,
                    });
                    return Outcome::Deferred { episode: self.episodes, first: true };
                };
                episode.deferrals += 1;
                if episode.progress != progress {
                    episode.progress = progress;
                    episode.advanced_100ns = now;
                }
                let stalled_100ns = now.saturating_sub(episode.advanced_100ns);
                if stalled_100ns >= MAX_STALLED_100NS {
                    Outcome::Stalled { status, deferrals: episode.deferrals, stalled_100ns }
                } else {
                    Outcome::Deferred { episode: self.episodes, first: false }
                }
            }
            status => {
                self.episode = None;
                Outcome::Failed(status)
            }
        }
    }
}
