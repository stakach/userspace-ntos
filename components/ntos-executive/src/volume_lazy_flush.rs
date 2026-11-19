//! Lazy publication of a dirty mounted volume, after NT's lazy writer and `CmpLazyFlush`.
//!
//! NT does not leave modified file data or registry hives dirty until shutdown: the cache
//! manager's lazy writer and the configuration manager's lazy flush write them out a few seconds
//! after they change. The mounted volume's snapshot is this executive's durable image of both.
//! A write that no caller asked to make durable is published once the volume has stayed dirty
//! for [`LAZY_FLUSH_DELAY_100NS`], while the service loop that delivers its I/O completions is
//! still running, so a later quiesce or shutdown finds a clean volume.

/// `CmpLazyFlush`'s default delay after a registry change.
pub(crate) const LAZY_FLUSH_DELAY_100NS: u64 = 5 * 10_000_000;

/// When the volume was first observed dirty with no checkpoint begun since.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LazyFlush {
    dirty_since: Option<u64>,
}

impl LazyFlush {
    pub(crate) const fn new() -> Self {
        Self { dirty_since: None }
    }

    pub(crate) const fn from_raw(raw: u64) -> Self {
        Self { dirty_since: if raw == 0 { None } else { Some(raw) } }
    }

    pub(crate) const fn into_raw(self) -> u64 {
        match self.dirty_since {
            Some(at) => at,
            None => 0,
        }
    }

    /// Observe the volume at a service boundary. A clean volume (including one whose
    /// checkpoint has begun) ends the interval. Returns true once a checkpoint is owed; the
    /// interval then restarts, so a refused checkpoint is retried one delay later rather than
    /// rearming an overdue wake.
    pub(crate) fn observe(&mut self, dirty: bool, now_100ns: u64) -> bool {
        if !dirty {
            self.dirty_since = None;
            return false;
        }
        let now = now_100ns.max(1);
        let since = *self.dirty_since.get_or_insert(now);
        let due = now.saturating_sub(since) >= LAZY_FLUSH_DELAY_100NS;
        if due {
            self.dirty_since = Some(now);
        }
        due
    }

    /// The wake deadline for an open interval.
    pub(crate) fn deadline(self) -> Option<u64> {
        self.dirty_since.map(|since| since.saturating_add(LAZY_FLUSH_DELAY_100NS))
    }
}

/// Checkpoint episodes that get a trace line: every one of the first 16, then powers of two,
/// so a long interactive run (where the lazy flush keeps publishing) still shows publications.
pub(crate) const fn episode_traced(episode: u64) -> bool {
    episode <= 16 || episode.is_power_of_two()
}

/// Whether the mounted volume's storage path can serve a checkpoint now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoragePath {
    /// No writable volume is mounted.
    Unmounted,
    /// An uncertain snapshot write blocked the mount until boot recovery.
    Blocked,
    /// The boot block source serves snapshot I/O synchronously.
    Boot,
    /// The boot source is draining to the native disk stack and admits no new snapshot I/O.
    Draining,
    /// The native disk stack serves snapshot I/O asynchronously.
    Native,
}

impl StoragePath {
    /// A lazy flush is attempted only where the storage path can serve it; elsewhere the
    /// dirty interval waits, exactly as NT's lazy writer leaves pages dirty for its next scan.
    pub(crate) const fn serves_checkpoint(self) -> bool {
        matches!(self, Self::Boot | Self::Native)
    }
}

/// What the service boundary does with a failed checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailedCheckpoint {
    /// Only the lazy flush owed it and the volume stays writable: retry one delay later.
    RetryLazily,
    /// A caller is waiting for durability, or the mount is now blocked: a durability fault.
    Refuse,
}

pub(crate) const fn classify_failed_checkpoint(
    caller_required: bool,
    mount_blocked: bool,
) -> FailedCheckpoint {
    if caller_required || mount_blocked {
        FailedCheckpoint::Refuse
    } else {
        FailedCheckpoint::RetryLazily
    }
}
