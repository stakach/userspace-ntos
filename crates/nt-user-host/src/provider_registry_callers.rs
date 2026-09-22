//! Retained native registry callers for exact physical provider jobs.

use alloc::vec::Vec;
use nt_process::{
    native_handle::{NativeHandleCaller, NativeThreadProcessReference},
    ProcessManager, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE,
};

struct Entry<R, D> {
    route: R,
    dispatch: Option<D>,
    address_space: u64,
    caller: NativeHandleCaller,
    reference: NativeThreadProcessReference,
}

/// Native adapters authenticate their physical route and currently executing dispatch before
/// calling this owner. Neither generic identity is itself an IPC credential. Missing dispatch
/// is admitted only by the adapter's explicit bootstrap path and binds on its first real Call.
#[must_use = "provider jobs retain requestor references until exact terminal retirement"]
pub struct RegistryCallerOwners<R, D> {
    entries: Vec<Entry<R, D>>,
}

impl<R: Copy + Eq, D: Copy + Eq> RegistryCallerOwners<R, D> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The root supplies the caller explicitly. A parked/uncertain job excludes replacement even
    /// if a new dispatch ID appears for the same route; it never implicitly releases references.
    pub fn capture(
        &mut self,
        pm: &mut ProcessManager,
        route: R,
        dispatch: Option<D>,
        address_space: u64,
        caller: NativeHandleCaller,
    ) -> Result<(), u32> {
        if address_space == 0 || self.entries.iter().any(|entry| entry.route == route) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let reference = pm.reference_native_requestor(caller)?;
        self.entries.push(Entry {
            route,
            dispatch,
            address_space,
            caller,
            reference,
        });
        Ok(())
    }

    pub fn resolve(
        &mut self,
        pm: &ProcessManager,
        route: R,
        dispatch: D,
        address_space: u64,
    ) -> Result<NativeHandleCaller, u32> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| {
                entry.route == route
                    && entry.address_space == address_space
                    && entry.dispatch.is_none_or(|held| held == dispatch)
            })
            .ok_or(STATUS_INVALID_HANDLE)?;
        entry.reference.validate(pm)?;
        pm.validate_native_handle_caller(entry.caller)?;
        entry.dispatch = Some(dispatch);
        Ok(entry.caller)
    }

    /// Only the canonical receiver's authenticated final completion may call this. Thread exit
    /// does not prevent cleanup, and a failed release retains the original row and references.
    pub fn retire(&mut self, pm: &mut ProcessManager, route: R, dispatch: D) -> Result<bool, u32> {
        let Some(index) = self.entries.iter().position(|entry| {
            entry.route == route && entry.dispatch.is_none_or(|held| held == dispatch)
        }) else {
            return Ok(false);
        };
        self.entries[index].reference.release(pm)?;
        self.entries.swap_remove(index);
        Ok(true)
    }
}

impl<R: Copy + Eq, D: Copy + Eq> Default for RegistryCallerOwners<R, D> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "provider_registry_callers_tests.rs"]
mod tests;
