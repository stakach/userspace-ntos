//! Counting semaphore dispatcher state.

use alloc::vec::Vec;

/// x64 `KSEMAPHORE` / `DISPATCHER_HEADER` field offsets.
pub mod ksemaphore_layout {
    /// `UCHAR Type` — `SemaphoreObject` (5).
    pub const TYPE: usize = 0x00;
    /// `UCHAR Size` — the object size in `ULONG`s.
    pub const SIZE: usize = 0x02;
    /// `LONG SignalState` — current count.
    pub const SIGNAL_STATE: usize = 0x04;
    /// `LIST_ENTRY WaitListHead` — empty == self-linked.
    pub const WAIT_LIST_HEAD: usize = 0x08;
    /// `LONG Limit`.
    pub const LIMIT: usize = 0x18;
    /// Total aligned `KSEMAPHORE` storage size on x64.
    pub const SIZE_OF: usize = 0x20;
}

/// `DISPATCHER_HEADER.Type` for `SemaphoreObject`.
pub const SEMAPHORE_OBJECT: u8 = 5;
const KSEMAPHORE_SIZE_IN_DWORDS: u8 = (ksemaphore_layout::SIZE_OF / 4) as u8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SemaphoreError {
    InvalidCount,
    LimitExceeded,
    NotFound,
}

/// `KeInitializeSemaphore` over caller-owned `KSEMAPHORE` storage.
///
/// # Safety
/// `sem` must point to at least [`ksemaphore_layout::SIZE_OF`] writable bytes.
pub unsafe fn init_ksemaphore(
    sem: *mut u8,
    initial: i32,
    limit: i32,
) -> Result<(), SemaphoreError> {
    if limit <= 0 || initial < 0 || initial > limit {
        return Err(SemaphoreError::InvalidCount);
    }
    use ksemaphore_layout as o;
    core::ptr::write_unaligned(sem.add(o::TYPE), SEMAPHORE_OBJECT);
    core::ptr::write_unaligned(sem.add(o::SIZE), KSEMAPHORE_SIZE_IN_DWORDS);
    core::ptr::write_unaligned(sem.add(o::SIGNAL_STATE) as *mut i32, initial);
    let head = sem.add(o::WAIT_LIST_HEAD) as u64;
    core::ptr::write_unaligned(sem.add(o::WAIT_LIST_HEAD) as *mut u64, head);
    core::ptr::write_unaligned(sem.add(o::WAIT_LIST_HEAD + 8) as *mut u64, head);
    core::ptr::write_unaligned(sem.add(o::LIMIT) as *mut i32, limit);
    Ok(())
}

/// `KeReadStateSemaphore` — return the current count.
///
/// # Safety
/// `sem` must be a valid `KSEMAPHORE`.
pub unsafe fn ksemaphore_read_state(sem: *const u8) -> i32 {
    core::ptr::read_unaligned(sem.add(ksemaphore_layout::SIGNAL_STATE) as *const i32)
}

/// Consume one semaphore token if available.
///
/// # Safety
/// `sem` must be a valid `KSEMAPHORE`.
pub unsafe fn ksemaphore_try_wait(sem: *mut u8) -> bool {
    let current = ksemaphore_read_state(sem);
    if current <= 0 {
        return false;
    }
    core::ptr::write_unaligned(
        sem.add(ksemaphore_layout::SIGNAL_STATE) as *mut i32,
        current - 1,
    );
    true
}

/// `KeReleaseSemaphore` count update. Returns the previous count.
///
/// # Safety
/// `sem` must be a valid `KSEMAPHORE`.
pub unsafe fn ksemaphore_release(sem: *mut u8, adjustment: i32) -> Result<i32, SemaphoreError> {
    if adjustment <= 0 {
        return Err(SemaphoreError::InvalidCount);
    }
    let current = ksemaphore_read_state(sem);
    let limit = core::ptr::read_unaligned(sem.add(ksemaphore_layout::LIMIT) as *const i32);
    let next = current
        .checked_add(adjustment)
        .ok_or(SemaphoreError::LimitExceeded)?;
    if next > limit || next < current {
        return Err(SemaphoreError::LimitExceeded);
    }
    core::ptr::write_unaligned(sem.add(ksemaphore_layout::SIGNAL_STATE) as *mut i32, next);
    Ok(current)
}

pub fn map_semaphore_access(mut access: u32) -> u32 {
    const QUERY_STATE: u32 = 0x0001;
    const MODIFY_STATE: u32 = 0x0002;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const ALL_ACCESS: u32 = 0x001F_0003;
    if access & 0x8000_0000 != 0 {
        access |= 0x0002_0000 | QUERY_STATE;
    }
    if access & 0x4000_0000 != 0 {
        access |= 0x0002_0000 | MODIFY_STATE;
    }
    if access & 0x2000_0000 != 0 {
        access |= 0x0002_0000 | SYNCHRONIZE;
    }
    if access & (0x1000_0000 | 0x0200_0000) != 0 {
        access |= ALL_ACCESS;
    }
    access & !(0xF000_0000 | 0x0200_0000)
}

struct Semaphore {
    identity: u64,
    current: i32,
    maximum: i32,
}

#[derive(Default)]
pub struct SemaphoreStore {
    semaphores: Vec<Semaphore>,
}

impl SemaphoreStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            semaphores: Vec::with_capacity(capacity),
        }
    }

    pub fn initialize(
        &mut self,
        identity: u64,
        initial: i32,
        maximum: i32,
    ) -> Result<(), SemaphoreError> {
        if maximum <= 0 || initial < 0 || initial > maximum {
            return Err(SemaphoreError::InvalidCount);
        }
        if let Some(semaphore) = self
            .semaphores
            .iter_mut()
            .find(|semaphore| semaphore.identity == identity)
        {
            semaphore.current = initial;
            semaphore.maximum = maximum;
        } else {
            self.semaphores.push(Semaphore {
                identity,
                current: initial,
                maximum,
            });
        }
        Ok(())
    }

    pub fn contains(&self, identity: u64) -> bool {
        self.semaphores
            .iter()
            .any(|semaphore| semaphore.identity == identity)
    }

    pub fn query(&self, identity: u64) -> Option<(i32, i32)> {
        self.semaphores
            .iter()
            .find(|semaphore| semaphore.identity == identity)
            .map(|semaphore| (semaphore.current, semaphore.maximum))
    }

    /// Consume one token. `Some(false)` means the object exists but is unsignaled.
    pub fn try_wait(&mut self, identity: u64) -> Option<bool> {
        let semaphore = self
            .semaphores
            .iter_mut()
            .find(|semaphore| semaphore.identity == identity)?;
        if semaphore.current == 0 {
            return Some(false);
        }
        semaphore.current -= 1;
        Some(true)
    }

    pub fn release(&mut self, identity: u64, count: i32) -> Result<i32, SemaphoreError> {
        if count <= 0 {
            return Err(SemaphoreError::InvalidCount);
        }
        let semaphore = self
            .semaphores
            .iter_mut()
            .find(|semaphore| semaphore.identity == identity)
            .ok_or(SemaphoreError::NotFound)?;
        let next = semaphore
            .current
            .checked_add(count)
            .ok_or(SemaphoreError::LimitExceeded)?;
        if next > semaphore.maximum {
            return Err(SemaphoreError::LimitExceeded);
        }
        let previous = semaphore.current;
        semaphore.current = next;
        Ok(previous)
    }

    pub fn remove(&mut self, identity: u64) -> bool {
        let Some(index) = self
            .semaphores
            .iter()
            .position(|semaphore| semaphore.identity == identity)
        else {
            return false;
        };
        self.semaphores.remove(index);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_initial_and_maximum_counts() {
        let mut store = SemaphoreStore::new();
        assert_eq!(
            store.initialize(1, -1, 1),
            Err(SemaphoreError::InvalidCount)
        );
        assert_eq!(store.initialize(1, 2, 1), Err(SemaphoreError::InvalidCount));
        assert_eq!(store.initialize(1, 0, 0), Err(SemaphoreError::InvalidCount));
        assert_eq!(store.initialize(1, 1, 2), Ok(()));
    }

    #[test]
    fn waits_consume_one_token() {
        let mut store = SemaphoreStore::new();
        store.initialize(7, 2, 3).unwrap();
        assert_eq!(store.try_wait(7), Some(true));
        assert_eq!(store.query(7), Some((1, 3)));
        assert_eq!(store.try_wait(7), Some(true));
        assert_eq!(store.try_wait(7), Some(false));
        assert_eq!(store.try_wait(99), None);
    }

    #[test]
    fn release_reports_previous_and_limit_failure_is_atomic() {
        let mut store = SemaphoreStore::new();
        store.initialize(8, 0, 3).unwrap();
        assert_eq!(store.release(8, 2), Ok(0));
        assert_eq!(store.release(8, 1), Ok(2));
        assert_eq!(store.release(8, 1), Err(SemaphoreError::LimitExceeded));
        assert_eq!(store.query(8), Some((3, 3)));
        assert_eq!(store.release(8, 0), Err(SemaphoreError::InvalidCount));
        assert_eq!(store.release(99, 1), Err(SemaphoreError::NotFound));
    }

    #[test]
    fn removal_forgets_only_requested_identity() {
        let mut store = SemaphoreStore::new();
        store.initialize(10, 0, 1).unwrap();
        store.initialize(11, 1, 1).unwrap();
        assert!(store.remove(10));
        assert!(!store.contains(10));
        assert!(store.contains(11));
        assert!(!store.remove(10));
    }

    #[test]
    fn generic_access_maps_to_native_rights() {
        assert_eq!(map_semaphore_access(0x8000_0000) & 1, 1);
        assert_eq!(map_semaphore_access(0x4000_0000) & 2, 2);
        assert_eq!(map_semaphore_access(0x2000_0000) & 0x0010_0000, 0x0010_0000);
        assert_eq!(map_semaphore_access(0x1000_0000), 0x001F_0003);
    }

    #[test]
    fn lays_out_raw_ksemaphore_header_and_limit() {
        let mut buf = [0xAAu8; ksemaphore_layout::SIZE_OF];
        let sem = buf.as_mut_ptr();
        unsafe {
            init_ksemaphore(sem, 2, 5).unwrap();
        }
        let r8 = |off: usize| buf[off];
        let r32 = |off: usize| i32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let r64 = |off: usize| u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        assert_eq!(r8(ksemaphore_layout::TYPE), SEMAPHORE_OBJECT);
        assert_eq!(
            r8(ksemaphore_layout::SIZE),
            (ksemaphore_layout::SIZE_OF / 4) as u8
        );
        assert_eq!(r32(ksemaphore_layout::SIGNAL_STATE), 2);
        assert_eq!(r32(ksemaphore_layout::LIMIT), 5);
        let head = sem as u64 + ksemaphore_layout::WAIT_LIST_HEAD as u64;
        assert_eq!(r64(ksemaphore_layout::WAIT_LIST_HEAD), head);
        assert_eq!(r64(ksemaphore_layout::WAIT_LIST_HEAD + 8), head);
    }

    #[test]
    fn raw_ksemaphore_wait_and_release_respect_limit() {
        let mut buf = [0u8; ksemaphore_layout::SIZE_OF];
        let sem = buf.as_mut_ptr();
        unsafe {
            init_ksemaphore(sem, 1, 2).unwrap();
            assert_eq!(ksemaphore_read_state(sem), 1);
            assert!(ksemaphore_try_wait(sem));
            assert_eq!(ksemaphore_read_state(sem), 0);
            assert!(!ksemaphore_try_wait(sem));
            assert_eq!(ksemaphore_release(sem, 2), Ok(0));
            assert_eq!(ksemaphore_read_state(sem), 2);
            assert_eq!(
                ksemaphore_release(sem, 1),
                Err(SemaphoreError::LimitExceeded)
            );
        }
    }
}
