//! Bounded idle scheduling for executive-owned video File projection retirement.

use core::sync::atomic::{AtomicU64, Ordering};

use super::video_projection_owners;

const RETRY_INTERVAL_100NS: u64 = 10_000_000;
static NEXT_RETRY: AtomicU64 = AtomicU64::new(0);
static RETRY_READY: AtomicU64 = AtomicU64::new(0);
static DRAIN_ACTIVE: AtomicU64 = AtomicU64::new(0);

struct DrainGuard;

impl DrainGuard {
    fn enter() -> Option<Self> {
        DRAIN_ACTIVE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for DrainGuard {
    fn drop(&mut self) {
        DRAIN_ACTIVE.store(0, Ordering::Release);
    }
}

fn clear_retry() {
    NEXT_RETRY.store(0, Ordering::Release);
    RETRY_READY.store(0, Ordering::Release);
}

fn postpone(now: u64) {
    NEXT_RETRY.store(now.saturating_add(RETRY_INTERVAL_100NS), Ordering::Release);
}

pub(crate) fn deadline() -> Option<u64> {
    if !unsafe { video_projection_owners::has_pending() } {
        clear_retry();
        return None;
    }
    let next = NEXT_RETRY.load(Ordering::Acquire);
    if next != 0 {
        return Some(next);
    }
    let next = crate::monotonic_time_100ns().saturating_add(RETRY_INTERVAL_100NS);
    match NEXT_RETRY.compare_exchange(0, next, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(next),
        Err(existing) => Some(existing),
    }
}

/// Latch scheduler work only: a timer can arrive while a hosted component still owns dispatch.
pub(crate) fn wake_due(now: u64) -> u64 {
    if deadline().is_some_and(|deadline| deadline <= now) {
        postpone(now);
        return u64::from(RETRY_READY.swap(1, Ordering::AcqRel) == 0);
    }
    0
}

pub(crate) unsafe fn drain() -> u64 {
    if crate::driver_launch::hosted_component_dispatch_active() {
        return 0;
    }
    let Some(_drain) = DrainGuard::enter() else {
        return 0;
    };
    if !video_projection_owners::has_pending() {
        clear_retry();
        return 0;
    }
    let now = crate::monotonic_time_100ns();
    let ready = RETRY_READY.swap(0, Ordering::AcqRel) != 0;
    let next = NEXT_RETRY.load(Ordering::Acquire);
    if !ready && next != 0 && now < next {
        return 0;
    }
    postpone(now);
    let freed = video_projection_owners::drain() as u64;
    if !video_projection_owners::has_pending() {
        clear_retry();
    }
    freed
}
