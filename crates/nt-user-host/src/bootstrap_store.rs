//! One-time ownership transfer from early initialization to the runtime owner.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapStoreError {
    Uninitialized,
    AlreadyOwned,
    Transferred,
}

enum Phase<T> {
    Uninitialized,
    Owned(T),
    Transferred,
}

/// The original store moves once; callbacks cannot return references into its temporary borrow.
///
/// ```compile_fail
/// use nt_user_host::bootstrap_store::BootstrapStore;
/// let mut store = BootstrapStore::new();
/// store.initialize(1u32).unwrap();
/// let escaped = store.with_mut(|value| value).unwrap();
/// *escaped = 2;
/// ```
pub struct BootstrapStore<T> {
    phase: Phase<T>,
}

impl<T> BootstrapStore<T> {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Uninitialized,
        }
    }

    pub fn is_uninitialized(&self) -> bool {
        matches!(self.phase, Phase::Uninitialized)
    }

    pub fn is_owned(&self) -> bool {
        matches!(self.phase, Phase::Owned(_))
    }

    /// A rejected initialization returns the offered store without replacing the original.
    pub fn initialize(&mut self, value: T) -> Result<(), (BootstrapStoreError, T)> {
        match self.phase {
            Phase::Uninitialized => {
                self.phase = Phase::Owned(value);
                Ok(())
            }
            Phase::Owned(_) => Err((BootstrapStoreError::AlreadyOwned, value)),
            Phase::Transferred => Err((BootstrapStoreError::Transferred, value)),
        }
    }

    pub fn with_ref<R>(&self, operation: impl FnOnce(&T) -> R) -> Result<R, BootstrapStoreError> {
        match &self.phase {
            Phase::Owned(value) => Ok(operation(value)),
            Phase::Uninitialized => Err(BootstrapStoreError::Uninitialized),
            Phase::Transferred => Err(BootstrapStoreError::Transferred),
        }
    }

    pub fn with_mut<R>(
        &mut self,
        operation: impl FnOnce(&mut T) -> R,
    ) -> Result<R, BootstrapStoreError> {
        match &mut self.phase {
            Phase::Owned(value) => Ok(operation(value)),
            Phase::Uninitialized => Err(BootstrapStoreError::Uninitialized),
            Phase::Transferred => Err(BootstrapStoreError::Transferred),
        }
    }

    /// Failed transfers leave the lifecycle unchanged; success moves the original allocation.
    pub fn take(&mut self) -> Result<T, BootstrapStoreError> {
        match self.phase {
            Phase::Uninitialized => return Err(BootstrapStoreError::Uninitialized),
            Phase::Transferred => return Err(BootstrapStoreError::Transferred),
            Phase::Owned(_) => {}
        }
        let Phase::Owned(value) = core::mem::replace(&mut self.phase, Phase::Transferred) else {
            unreachable!()
        };
        Ok(value)
    }
}

impl<T> Default for BootstrapStore<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec};

    #[test]
    fn transfer_preserves_allocation_and_mutations_without_reopening_access() {
        let mut store = BootstrapStore::new();
        let value = Box::new(vec![1, 2]);
        let allocation = &*value as *const _;
        store.initialize(value).unwrap();
        store.with_mut(|value| value.push(3)).unwrap();
        assert_eq!(store.with_ref(|value| &**value as *const _), Ok(allocation));
        let transferred = store.take().unwrap();
        assert_eq!(&*transferred as *const _, allocation);
        assert_eq!(*transferred, vec![1, 2, 3]);
        assert!(!store.is_owned());
        assert!(!store.is_uninitialized());
        assert_eq!(
            store.with_ref(|_| panic!("retired access")),
            Err::<(), _>(BootstrapStoreError::Transferred)
        );
        assert_eq!(
            store.with_mut(|_| panic!("retired mutation")),
            Err::<(), _>(BootstrapStoreError::Transferred)
        );
        assert_eq!(store.take(), Err(BootstrapStoreError::Transferred));
        let (_, rejected) = store.initialize(Box::new(vec![9])).unwrap_err();
        assert_eq!(*rejected, vec![9]);
    }

    #[test]
    fn failed_access_and_transfer_do_not_prevent_initialization() {
        let mut store = BootstrapStore::new();
        assert_eq!(
            store.take(),
            Err::<u32, _>(BootstrapStoreError::Uninitialized)
        );
        assert_eq!(
            store.with_ref(|_| panic!("early access")),
            Err::<(), _>(BootstrapStoreError::Uninitialized)
        );
        assert_eq!(
            store.with_mut(|_| panic!("early mutation")),
            Err::<(), _>(BootstrapStoreError::Uninitialized)
        );
        assert!(store.is_uninitialized());
        store.initialize(7).unwrap();
        assert_eq!(
            store.initialize(9),
            Err((BootstrapStoreError::AlreadyOwned, 9))
        );
        assert_eq!(store.take(), Ok(7));
    }
}
