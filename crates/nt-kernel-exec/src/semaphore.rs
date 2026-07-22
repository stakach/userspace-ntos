//! Counting semaphore dispatcher state.

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SemaphoreError {
    InvalidCount,
    LimitExceeded,
    NotFound,
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
}
