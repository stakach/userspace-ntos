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

/// The exact Ps projection suspended by a kernel-owned provider wait. A nested dispatch may
/// select another caller on the same physical lane before the wait resumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PsProviderWaitTarget {
    pub client_pi: u64,
    pub process_id: u64,
    pub thread_id: u64,
    pub process_generation: u64,
    pub eprocess: u64,
    pub ethread: u64,
    pub teb: u64,
    pub selected_process: u64,
    pub w32process: u64,
    pub w32thread: u64,
    /// A provider process-exit callout can execute after its GUI thread record has retired.
    pub thread_recorded: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PsProviderWaitIdentity {
    pub client_pi: u64,
    pub process_id: u64,
    pub thread_id: u64,
    pub process_generation: u64,
    pub eprocess: u64,
    pub ethread: u64,
}

impl PsProviderWaitTarget {
    pub fn capture(self, live: PsProviderWaitIdentity) -> Option<Self> {
        self.permits_restore(live).then_some(self)
    }

    pub fn permits_restore(self, live: PsProviderWaitIdentity) -> bool {
        self.process_id != 0
            && self.thread_id != 0
            && self.process_generation != 0
            && self.eprocess != 0
            && self.ethread != 0
            && self.teb != 0
            && self.selected_process != 0
            && self.client_pi == live.client_pi
            && self.process_id == live.process_id
            && self.thread_id == live.thread_id
            && self.process_generation == live.process_generation
            && self.eprocess == live.eprocess
            && self.ethread == live.ethread
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
        release_fast_mutex_unsafe, AcquireResult, ExecutiveResourceStore, ExecutiveSyncError,
        ResourceMode,
    };
    use core::sync::atomic::Ordering;

    fn ps_wait_target() -> PsProviderWaitTarget {
        PsProviderWaitTarget {
            client_pi: 8,
            process_id: 76,
            thread_id: 164,
            process_generation: 3,
            eprocess: 0x4080_0001_0000,
            ethread: 0x4080_0200_0000,
            teb: 0x7fff_0000,
            selected_process: 0x4080_0001_0000,
            w32process: 0x1000_2000,
            w32thread: 0x1000_3000,
            thread_recorded: true,
        }
    }

    fn ps_wait_identity(target: PsProviderWaitTarget) -> PsProviderWaitIdentity {
        PsProviderWaitIdentity {
            client_pi: target.client_pi,
            process_id: target.process_id,
            thread_id: target.thread_id,
            process_generation: target.process_generation,
            eprocess: target.eprocess,
            ethread: target.ethread,
        }
    }

    #[test]
    fn nested_dispatch_restores_the_exact_ps_target_after_wait() {
        let target = ps_wait_target();
        let live = ps_wait_identity(target);
        let captured = target
            .capture(live)
            .expect("current Ps target must be capturable");
        let mut resource = Page([0; 4096]);
        let mut store = ExecutiveResourceStore::new();
        let resource_ptr = resource.0.as_mut_ptr();
        let mut selected_ethread = target.ethread;
        unsafe {
            store.initialize(resource_ptr).unwrap();
            assert_eq!(
                store.acquire(resource_ptr, selected_ethread, ResourceMode::Exclusive),
                Ok(AcquireResult::Acquired)
            );
        }

        // The nested dispatch selects System on the same lane. Releasing under that selection
        // reproduces the native ExReleaseResourceLite failure after the wait was granted.
        selected_ethread = 0x1000_10ab_000;
        unsafe {
            assert_eq!(
                store.release(resource_ptr, selected_ethread),
                Err(ExecutiveSyncError::NotOwned)
            );
        }
        assert!(captured.permits_restore(live));
        selected_ethread = captured.ethread;
        unsafe {
            store.release(resource_ptr, selected_ethread).unwrap();
        }
        assert_eq!(
            store
                .ownership_snapshot(resource_ptr as u64)
                .unwrap()
                .owner_count,
            0
        );
    }

    #[test]
    fn ps_wait_target_rejects_recycled_generation_or_thread() {
        let target = ps_wait_target();
        let live = ps_wait_identity(target);
        assert!(target
            .capture(PsProviderWaitIdentity {
                process_generation: 4,
                ..live
            })
            .is_none());
        assert!(target
            .capture(PsProviderWaitIdentity {
                ethread: 0x4080_0300_0000,
                ..live
            })
            .is_none());
        assert!(!target.permits_restore(PsProviderWaitIdentity {
            process_generation: 4,
            ..live
        }));
        assert!(!target.permits_restore(PsProviderWaitIdentity {
            ethread: 0x4080_0300_0000,
            ..live
        }));
    }

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
                acquire_fast_mutex_unsafe(
                    mutex.0.as_mut_ptr(),
                    core::ptr::read_unaligned(client_current)
                ),
                Ok(AcquireResult::Acquired)
            );

            // A second physical lane enters System work before the first one resumes.
            core::ptr::write_unaligned(system_current, system_ethread);
            assert_eq!(core::ptr::read_unaligned(client_current), client_ethread);
            assert_eq!(
                release_fast_mutex_unsafe(
                    mutex.0.as_mut_ptr(),
                    core::ptr::read_unaligned(system_current)
                ),
                Err(ExecutiveSyncError::NotOwned)
            );
            release_fast_mutex_unsafe(
                mutex.0.as_mut_ptr(),
                core::ptr::read_unaligned(client_current),
            )
            .unwrap();
            assert_eq!(
                core::ptr::read_unaligned(
                    mutex.0.as_ptr().add(fast_mutex_layout::COUNT) as *const i32
                ),
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
