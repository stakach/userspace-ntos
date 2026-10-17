//! Physical win32k lanes each own their KPCR projection.
//!
//! A native call can retain a FAST_MUTEX while another lane runs a nested dispatch. The
//! current-thread field used by both ReactOS and our mutex checks must therefore be selected
//! from the physical lane's GS base, not from a shared process-wide KPCR page.

use core::sync::atomic::AtomicU64;

/// Rust-side current selection and Ps Win32 compatibility cells for one physical lane.
pub struct LaneCurrentIds {
    pub process_id: AtomicU64,
    pub thread_id: AtomicU64,
    pub client_pi: AtomicU64,
    pub w32process: AtomicU64,
    pub w32thread: AtomicU64,
}

impl LaneCurrentIds {
    pub const fn new(unselected_pi: u64) -> Self {
        Self {
            process_id: AtomicU64::new(0),
            thread_id: AtomicU64::new(0),
            client_pi: AtomicU64::new(unselected_pi),
            w32process: AtomicU64::new(0),
            w32thread: AtomicU64::new(0),
        }
    }
}

/// Address layout for the primary KPCR and one KPCR page per additional physical lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalKpcrLayout {
    pub primary: u64,
    pub worker_arena: u64,
    pub worker_stride: u64,
    pub worker_offset: u64,
    pub worker_capacity: usize,
}

impl PhysicalKpcrLayout {
    /// Physical ordinal zero is the primary lane; ordinals 1..=capacity are workers.
    pub const fn address(self, physical_ordinal: usize) -> Option<u64> {
        if physical_ordinal == 0 {
            return Some(self.primary);
        }
        if physical_ordinal > self.worker_capacity {
            return None;
        }
        let worker_index = (physical_ordinal - 1) as u64;
        let offset = match worker_index.checked_mul(self.worker_stride) {
            Some(value) => value,
            None => return None,
        };
        let base = match self.worker_arena.checked_add(offset) {
            Some(value) => value,
            None => return None,
        };
        base.checked_add(self.worker_offset)
    }

    pub const fn ordinal(self, kpcr: u64) -> Option<usize> {
        if kpcr == self.primary {
            return Some(0);
        }
        let Some(first) = self.worker_arena.checked_add(self.worker_offset) else {
            return None;
        };
        let Some(delta) = kpcr.checked_sub(first) else {
            return None;
        };
        if self.worker_stride == 0 || delta % self.worker_stride != 0 {
            return None;
        }
        let index = delta / self.worker_stride;
        if index >= self.worker_capacity as u64 {
            return None;
        }
        Some(index as usize + 1)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::executive_sync::{
        acquire_fast_mutex_unsafe, fast_mutex_layout, initialize_fast_mutex,
        release_fast_mutex_unsafe, AcquireResult, ExecutiveSyncError,
    };
    use core::sync::atomic::Ordering;

    #[repr(align(8))]
    struct Page([u8; 4096]);

    #[test]
    fn interleaved_system_lane_cannot_change_client_fast_mutex_owner() {
        let layout = PhysicalKpcrLayout {
            primary: 0x1000_0710_2000,
            worker_arena: 0x1000_0d20_0000,
            worker_stride: 0x40_000,
            worker_offset: 0x21_000,
            worker_capacity: 48,
        };
        assert_ne!(layout.address(0), layout.address(1));
        assert_ne!(layout.address(1), layout.address(2));
        assert_eq!(layout.address(49), None);
        assert_eq!(layout.ordinal(layout.address(0).unwrap()), Some(0));
        assert_eq!(layout.ordinal(layout.address(1).unwrap()), Some(1));
        assert_eq!(layout.ordinal(layout.address(2).unwrap()), Some(2));

        let mut client_kpcr = Page([0; 4096]);
        let mut system_kpcr = Page([0; 4096]);
        let mut mutex = Page([0; 4096]);
        let client_ethread = 0x4080_0000_7000u64;
        let system_ethread = 0x100_0109_2000u64;
        unsafe {
            let client_current = client_kpcr.0.as_mut_ptr().add(0x188) as *mut u64;
            let system_current = system_kpcr.0.as_mut_ptr().add(0x188) as *mut u64;
            core::ptr::write_unaligned(client_current, client_ethread);
            initialize_fast_mutex(mutex.0.as_mut_ptr()).unwrap();
            assert_eq!(
                acquire_fast_mutex_unsafe(mutex.0.as_mut_ptr(), core::ptr::read_unaligned(client_current)),
                Ok(AcquireResult::Acquired)
            );

            // A second physical lane enters System work before the first one resumes.
            core::ptr::write_unaligned(system_current, system_ethread);
            assert_eq!(core::ptr::read_unaligned(client_current), client_ethread);
            assert_eq!(
                release_fast_mutex_unsafe(mutex.0.as_mut_ptr(), core::ptr::read_unaligned(system_current)),
                Err(ExecutiveSyncError::NotOwned)
            );
            release_fast_mutex_unsafe(mutex.0.as_mut_ptr(), core::ptr::read_unaligned(client_current))
                .unwrap();
            assert_eq!(
                core::ptr::read_unaligned(mutex.0.as_ptr().add(fast_mutex_layout::COUNT) as *const i32),
                1
            );
        }
    }

    #[test]
    fn concurrent_callout_slots_do_not_replace_another_lane_result() {
        let client = LaneCurrentIds::new(usize::MAX as u64);
        let system = LaneCurrentIds::new(usize::MAX as u64);
        client.w32process.store(0x1110, Ordering::Relaxed);
        client.w32thread.store(0x2220, Ordering::Relaxed);
        system.w32process.store(0x3330, Ordering::Relaxed);
        system.w32thread.store(0, Ordering::Relaxed);
        assert_eq!(client.w32process.load(Ordering::Relaxed), 0x1110);
        assert_eq!(client.w32thread.load(Ordering::Relaxed), 0x2220);
        assert_eq!(system.w32process.load(Ordering::Relaxed), 0x3330);
        assert_eq!(system.w32thread.load(Ordering::Relaxed), 0);
    }
}
