//! Finite boot-frontier observations, sealed after genuine Explorer paint completion.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy)]
pub(crate) enum BootProgress {
    ImageActivated,
    PageMappingPublished,
    DurableRegistryPublication,
    CredentialRetrieved,
    DialogModalCompleted,
    DialogModalDrained,
    UserShellImageAttempted,
    ExplorerMessageRegistrationObserved,
    ExplorerDirectDrawObserved,
    ExplorerBeginPaintObserved,
    ExplorerEndPaintObserved,
    ExplorerGdiBatchObserved,
}

impl BootProgress {
    const fn one_shot_bit(self) -> u64 {
        match self {
            Self::ImageActivated
            | Self::PageMappingPublished
            | Self::DurableRegistryPublication
            | Self::CredentialRetrieved => 0,
            Self::UserShellImageAttempted => 1 << 0,
            Self::ExplorerMessageRegistrationObserved => 1 << 1,
            Self::ExplorerDirectDrawObserved => 1 << 2,
            Self::ExplorerBeginPaintObserved => 1 << 3,
            Self::ExplorerEndPaintObserved => 1 << 4,
            Self::ExplorerGdiBatchObserved => 1 << 5,
            Self::DialogModalCompleted => 1 << 6,
            Self::DialogModalDrained => 1 << 7,
        }
    }
}

pub(super) struct LocalBootProgressObserver {
    epoch: AtomicU64,
    milestones: AtomicU64,
    sealed: AtomicBool,
}

impl LocalBootProgressObserver {
    pub(super) const fn new() -> Self {
        Self {
            epoch: AtomicU64::new(0),
            milestones: AtomicU64::new(0),
            sealed: AtomicBool::new(false),
        }
    }

    /// Returns true only for the first acknowledged seal transition.
    pub(super) fn note(&self, progress: BootProgress, explorer_completed: bool) -> bool {
        if self.sealed.load(Ordering::Acquire) {
            return false;
        }
        let bit = progress.one_shot_bit();
        if bit != 0 && self.milestones.fetch_or(bit, Ordering::AcqRel) & bit != 0 {
            return false;
        }
        self.epoch.fetch_add(1, Ordering::Relaxed);
        explorer_completed
            && self.sealed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    pub(super) fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }
}

static BOOT_PROGRESS: LocalBootProgressObserver = LocalBootProgressObserver::new();

/// Only acknowledged state publications belong here, never polling, wakes, or IPC churn.
#[inline]
pub(crate) fn note_boot_progress(progress: BootProgress) {
    if BOOT_PROGRESS.note(progress, crate::explorer_chrome_runtime_milestones_reached()) {
        crate::print_str(b"[quiesce] Explorer runtime paint milestones complete; boot-progress epoch sealed\n");
    }
}

#[inline]
pub(crate) fn boot_progress_epoch() -> u64 {
    BOOT_PROGRESS.epoch()
}
