//! Service-boundary policy for a mounted-volume checkpoint attempt that reports busy.
//!
//! A checkpoint that returns `STATUS_DEVICE_BUSY` has consumed nothing: either its own retained
//! native commit is still writing, or another owner holds the snapshot reserve. The boundary
//! keeps the durable requirement and retries on a later turn. An owner that reports busy without
//! advancing for `MAX_STALLED_100NS` is a failure with its own name, not an endless retry.

const STATUS_SUCCESS: u32 = 0;
pub(crate) const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;

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
