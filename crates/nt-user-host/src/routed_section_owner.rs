//! Non-Copy routed FILE_OBJECT ownership before and after section publication.

use alloc::vec::Vec;
use nt_memory_manager::{RoutedSectionLease, SectionIdentity};

struct Owner<T> {
    lease: RoutedSectionLease,
    section: Option<SectionIdentity>,
    value: T,
}

pub struct RoutedSectionOwners<T> {
    next_lease: u64,
    owners: Vec<Owner<T>>,
}

impl<T> RoutedSectionOwners<T> {
    pub const fn new() -> Self {
        Self {
            next_lease: 0,
            owners: Vec::new(),
        }
    }

    /// Reserve storage and a never-reused lease before any section or handle is published.
    pub fn reserve(&mut self, value: T) -> Result<RoutedSectionLease, T> {
        let Some(next) = self.next_lease.checked_add(1) else {
            return Err(value);
        };
        if self.owners.try_reserve(1).is_err() {
            return Err(value);
        }
        let lease = RoutedSectionLease::new(next).expect("nonzero checked successor");
        self.next_lease = next;
        self.owners.push(Owner {
            lease,
            section: None,
            value,
        });
        Ok(lease)
    }

    /// Associate an admitted section with its already-reserved owner, without allocation.
    pub fn bind(&mut self, lease: RoutedSectionLease, section: SectionIdentity) -> bool {
        if self
            .owners
            .iter()
            .any(|owner| owner.section == Some(section))
        {
            return false;
        }
        let Some(owner) = self
            .owners
            .iter_mut()
            .find(|owner| owner.lease == lease && owner.section.is_none())
        else {
            return false;
        };
        owner.section = Some(section);
        true
    }

    pub fn get(&self, lease: RoutedSectionLease, section: SectionIdentity) -> Option<&T> {
        self.owners
            .iter()
            .find(|owner| owner.lease == lease && owner.section == Some(section))
            .map(|owner| &owner.value)
    }

    /// Undo an unpublished creation. Bound owners must retire through their section instead.
    pub fn cancel_unbound(&mut self, lease: RoutedSectionLease) -> Option<T> {
        let index = self
            .owners
            .iter()
            .position(|owner| owner.lease == lease && owner.section.is_none())?;
        Some(self.owners.swap_remove(index).value)
    }

    /// Transfer the exact owner to the checked file-reference retirement mechanism.
    pub fn release(&mut self, lease: RoutedSectionLease, section: SectionIdentity) -> Option<T> {
        let index = self
            .owners
            .iter()
            .position(|owner| owner.lease == lease && owner.section == Some(section))?;
        Some(self.owners.swap_remove(index).value)
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }
}

impl<T> Default for RoutedSectionOwners<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use nt_memory_manager::{
        GenericSectionBacking, GenericSectionTable, PAGE_READONLY, SECTION_ATTR_SEC_COMMIT,
    };

    fn section(table: &mut GenericSectionTable, handle: u64) -> (usize, SectionIdentity) {
        let index = table
            .create(
                1,
                handle,
                0x1000,
                PAGE_READONLY,
                SECTION_ATTR_SEC_COMMIT,
                GenericSectionBacking::anonymous(),
            )
            .unwrap();
        (index, table.section_identity(index).unwrap())
    }

    #[test]
    fn bound_owner_requires_both_lease_and_section_incarnation() {
        let mut table = GenericSectionTable::new();
        let (_, first) = section(&mut table, 0x40);
        let (_, second) = section(&mut table, 0x44);
        let mut owners = RoutedSectionOwners::new();
        let first_lease = owners.reserve(Box::new(11)).unwrap();
        let second_lease = owners.reserve(Box::new(12)).unwrap();
        assert_eq!(first_lease.value(), 1);
        assert_eq!(second_lease.value(), 2);
        assert!(owners.bind(first_lease, first));
        assert!(!owners.bind(first_lease, second));
        assert!(!owners.bind(second_lease, first));
        assert!(owners.bind(second_lease, second));
        assert_eq!(
            owners.get(first_lease, first).map(|owner| **owner),
            Some(11)
        );
        assert!(owners.get(first_lease, second).is_none());
        assert!(owners.get(second_lease, first).is_none());
        assert!(owners.cancel_unbound(first_lease).is_none());
        assert!(owners.release(first_lease, second).is_none());
        assert_eq!(
            owners.release(first_lease, first).map(|owner| *owner),
            Some(11)
        );
        assert!(owners.release(first_lease, first).is_none());
        assert_eq!(
            owners.release(second_lease, second).map(|owner| *owner),
            Some(12)
        );
        assert!(owners.is_empty());
    }

    #[test]
    fn cancellation_burns_token_and_stale_identity_cannot_take_reused_slot() {
        let mut table = GenericSectionTable::new();
        let (index, old) = section(&mut table, 0x40);
        let mut owners = RoutedSectionOwners::new();
        let cancelled = owners.reserve(Box::new(10)).unwrap();
        assert_eq!(
            owners.cancel_unbound(cancelled).map(|owner| *owner),
            Some(10)
        );
        let old_lease = owners.reserve(Box::new(11)).unwrap();
        assert_eq!(old_lease.value(), 2);
        assert!(owners.bind(old_lease, old));
        assert!(table.release_handle(index));
        let ticket = table.next_retirement().unwrap();
        assert!(table.complete_retirement(ticket));
        let (reused_index, new) = section(&mut table, 0x44);
        assert_eq!(reused_index, index);
        assert_ne!(old, new);
        let new_lease = owners.reserve(Box::new(12)).unwrap();
        assert!(owners.bind(new_lease, new));
        assert!(owners.get(old_lease, new).is_none());
        assert!(owners.release(old_lease, new).is_none());
        assert!(owners.release(new_lease, old).is_none());
        assert_eq!(owners.release(old_lease, old).map(|owner| *owner), Some(11));
        assert_eq!(owners.release(new_lease, new).map(|owner| *owner), Some(12));
    }

    #[test]
    fn exhausted_lease_space_returns_non_copy_owner() {
        let mut owners = RoutedSectionOwners::new();
        owners.next_lease = u64::MAX;
        let owner = Box::new(7);
        assert_eq!(owners.reserve(owner).map_err(|owner| *owner), Err(7));
        assert!(owners.is_empty());
    }
}
