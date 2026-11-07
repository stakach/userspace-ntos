//! Small, host-testable ownership state for queued threadpool work.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// Fail an unavailable object family without handing its caller a fabricated live object.
///
/// # Safety
/// `out`, when non-null, points to a writable output pointer.
pub unsafe fn reject_object_allocation(out: *mut *mut c_void) -> u32 {
    if out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe { *out = core::ptr::null_mut() };
    STATUS_NOT_SUPPORTED
}

pub struct WorkState {
    next_sequence: AtomicU64,
    cancel_through: AtomicU64,
    outstanding: AtomicU32,
    closing: AtomicBool,
}

impl WorkState {
    pub const fn new() -> Self {
        Self {
            next_sequence: AtomicU64::new(0),
            cancel_through: AtomicU64::new(0),
            outstanding: AtomicU32::new(0),
            closing: AtomicBool::new(false),
        }
    }

    pub fn reserve(&self) -> Option<u64> {
        if self.closing.load(Ordering::Acquire) {
            return None;
        }
        self.outstanding
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()?;
        if self.closing.load(Ordering::Acquire) {
            self.finish();
            return None;
        }
        let sequence = self
            .next_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map(|previous| previous + 1);
        if sequence.is_err() {
            self.finish();
        }
        sequence.ok()
    }

    pub fn cancel_pending(&self) {
        let last = self.next_sequence.load(Ordering::Acquire);
        self.cancel_through.fetch_max(last, Ordering::AcqRel);
    }

    pub fn should_run(&self, sequence: u64) -> bool {
        sequence > self.cancel_through.load(Ordering::Acquire)
    }

    pub fn finish(&self) -> bool {
        self.outstanding.fetch_sub(1, Ordering::AcqRel) == 1
    }

    pub fn outstanding(&self) -> u32 {
        self.outstanding.load(Ordering::Acquire)
    }

    pub fn outstanding_address(&self) -> *const AtomicU32 {
        &self.outstanding
    }

    pub fn close(&self) {
        self.closing.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        reject_object_allocation, WorkState, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    };
    use core::ffi::c_void;

    #[test]
    fn cancellation_only_skips_work_reserved_before_the_snapshot() {
        let work = WorkState::new();
        let first = work.reserve().unwrap();
        let second = work.reserve().unwrap();
        work.cancel_pending();
        assert!(!work.should_run(first));
        assert!(!work.should_run(second));
        let later = work.reserve().unwrap();
        assert!(work.should_run(later));
        assert!(!work.finish());
        assert!(!work.finish());
        assert!(work.finish());
    }

    #[test]
    fn closing_prevents_new_posts_without_discarding_outstanding_callbacks() {
        let work = WorkState::new();
        let posted = work.reserve().unwrap();
        work.close();
        assert!(work.reserve().is_none());
        assert!(work.should_run(posted));
        assert_eq!(work.outstanding(), 1);
        assert!(work.finish());
    }

    #[test]
    fn unavailable_object_allocation_clears_output_and_fails_closed() {
        let mut out = 1usize as *mut c_void;
        assert_eq!(
            unsafe { reject_object_allocation(&mut out) },
            STATUS_NOT_SUPPORTED
        );
        assert!(out.is_null());
        assert_eq!(
            unsafe { reject_object_allocation(core::ptr::null_mut()) },
            STATUS_INVALID_PARAMETER
        );
    }
}
