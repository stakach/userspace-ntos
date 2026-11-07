//! Capacity owner for directory handles that may be removed during process rundown.

use alloc::vec::Vec;

/// One credit is acquired before each canonical directory lease can become a native handle.
/// It guarantees a retired handle can enter the cleanup queue without allocating after removal.
pub struct DirectoryCleanupCredits<T> {
    live: usize,
    detached: Vec<T>,
}

impl<T> DirectoryCleanupCredits<T> {
    pub const fn new() -> Self { Self { live: 0, detached: Vec::new() } }

    pub fn reserve(&mut self) -> Result<(), ()> {
        let next_live = self.live.checked_add(1).ok_or(())?;
        let required = self.detached.len().checked_add(next_live).ok_or(())?;
        if self.detached.capacity() < required {
            self.detached.try_reserve_exact(required - self.detached.len())
                .map_err(|_| ())?;
        }
        self.live = next_live;
        Ok(())
    }

    pub fn cancel(&mut self) {
        assert!(self.live > 0);
        self.live -= 1;
    }

    pub fn detach(&mut self, item: T) {
        assert!(self.live > 0);
        assert!(self.detached.len() < self.detached.capacity());
        self.live -= 1;
        self.detached.push(item);
    }

    pub fn first_mut(&mut self) -> Option<&mut T> { self.detached.first_mut() }

    /// Inspect one retained obligation without moving another owner.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> { self.detached.get_mut(index) }

    /// Retire only the completed obligation; uncertain neighbours stay retained.
    pub fn retire(&mut self, index: usize) -> Option<T> {
        if index >= self.detached.len() { None } else { Some(self.detached.remove(index)) }
    }

    pub fn retire_first(&mut self) -> Option<T> {
        self.retire(0)
    }

    pub fn outstanding(&self) -> bool { self.live != 0 || !self.detached.is_empty() }
    pub fn live(&self) -> usize { self.live }
    pub fn detached_len(&self) -> usize { self.detached.len() }
    pub fn capacity(&self) -> usize { self.detached.capacity() }
}

#[cfg(test)]
mod tests {
    use super::DirectoryCleanupCredits;

    #[test]
    fn all_live_directory_handles_can_detach_without_allocation_after_removal() {
        let mut credits = DirectoryCleanupCredits::new();
        for _ in 0..17 { credits.reserve().unwrap(); }
        assert!(credits.capacity() >= 17, "every published lease needs a cleanup slot");
        let capacity_before_removal = credits.capacity();
        for identity in 0..17 { credits.detach(identity); }
        assert_eq!(credits.capacity(), capacity_before_removal);
        assert_eq!(credits.live(), 0);
        assert_eq!(credits.detached_len(), 17);
        for identity in 0..17 { assert_eq!(credits.retire_first(), Some(identity)); }
        assert!(!credits.outstanding());
    }

    #[test]
    fn failed_publication_returns_its_credit_without_consuming_queue_space() {
        let mut credits = DirectoryCleanupCredits::<u64>::new();
        credits.reserve().unwrap();
        credits.reserve().unwrap();
        credits.cancel();
        credits.detach(42);
        assert_eq!(credits.retire_first(), Some(42));
        assert!(!credits.outstanding());
    }

    #[test]
    fn terminal_neighbour_can_retire_while_an_uncertain_owner_stays_in_queue() {
        let mut credits = DirectoryCleanupCredits::new();
        credits.reserve().unwrap();
        credits.reserve().unwrap();
        credits.detach(41);
        credits.detach(42);
        assert_eq!(credits.retire(1), Some(42));
        assert_eq!(credits.detached_len(), 1);
        assert_eq!(credits.get_mut(0).map(|identity| *identity), Some(41));
        assert!(credits.outstanding());
    }
}
