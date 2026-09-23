//! Exact-owner snapshots for streamed native directory queries.

use alloc::vec::Vec;

/// Identity supplied only after the adapter authenticates the physical route and caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryQueryOwner<R, D, C> {
    pub route: R,
    pub dispatch: D,
    pub caller: C,
    pub token: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryQueryError {
    RouteOccupied,
    WrongOwner,
    AlreadyAcknowledged,
    NoMemory,
}

struct Entry<R, D, C, T> {
    owner: DirectoryQueryOwner<R, D, C>,
    snapshot: Option<T>,
}

/// A physical dispatch may hold multiple query tokens until canonical completion.
/// ACK consumes a snapshot but retains its identity to prevent replay.
pub struct DirectoryQuerySnapshots<R, D, C, T> {
    entries: Vec<Entry<R, D, C, T>>,
}

impl<R: Copy + Eq, D: Copy + Eq, C: Copy + Eq, T> DirectoryQuerySnapshots<R, D, C, T> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn begin(
        &mut self,
        owner: DirectoryQueryOwner<R, D, C>,
        snapshot: T,
    ) -> Result<(), DirectoryQueryError> {
        if self.entries.iter().any(|entry| {
            entry.owner.route == owner.route
                && (entry.owner.dispatch != owner.dispatch
                    || entry.owner.caller != owner.caller
                    || entry.owner.token == owner.token)
        }) {
            return Err(DirectoryQueryError::RouteOccupied);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| DirectoryQueryError::NoMemory)?;
        self.entries.push(Entry {
            owner,
            snapshot: Some(snapshot),
        });
        Ok(())
    }

    pub fn get(&self, owner: DirectoryQueryOwner<R, D, C>) -> Result<&T, DirectoryQueryError> {
        self.entry(owner)?
            .snapshot
            .as_ref()
            .ok_or(DirectoryQueryError::AlreadyAcknowledged)
    }

    pub fn get_mut(
        &mut self,
        owner: DirectoryQueryOwner<R, D, C>,
    ) -> Result<&mut T, DirectoryQueryError> {
        self.entry_mut(owner)?
            .snapshot
            .as_mut()
            .ok_or(DirectoryQueryError::AlreadyAcknowledged)
    }

    pub fn ack(&mut self, owner: DirectoryQueryOwner<R, D, C>) -> Result<T, DirectoryQueryError> {
        self.entry_mut(owner)?
            .snapshot
            .take()
            .ok_or(DirectoryQueryError::AlreadyAcknowledged)
    }

    /// The adapter calls this only for a canonically completed physical dispatch.
    pub fn retire_matching(
        &mut self,
        mut matches: impl FnMut(DirectoryQueryOwner<R, D, C>) -> bool,
    ) {
        self.entries.retain(|entry| !matches(entry.owner));
    }

    fn entry(
        &self,
        owner: DirectoryQueryOwner<R, D, C>,
    ) -> Result<&Entry<R, D, C, T>, DirectoryQueryError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.owner.route == owner.route && entry.owner.token == owner.token)
            .ok_or(DirectoryQueryError::WrongOwner)?;
        if entry.owner != owner {
            return Err(DirectoryQueryError::WrongOwner);
        }
        Ok(entry)
    }

    fn entry_mut(
        &mut self,
        owner: DirectoryQueryOwner<R, D, C>,
    ) -> Result<&mut Entry<R, D, C, T>, DirectoryQueryError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.owner.route == owner.route && entry.owner.token == owner.token)
            .ok_or(DirectoryQueryError::WrongOwner)?;
        if entry.owner != owner {
            return Err(DirectoryQueryError::WrongOwner);
        }
        Ok(entry)
    }
}

#[cfg(test)]
#[path = "provider_directory_query_tests.rs"]
mod tests;
