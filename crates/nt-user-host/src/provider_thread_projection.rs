//! Retained KPCR ownership for physical provider executors.

use alloc::vec::Vec;
use nt_process::{native_handle::{NativeHandleCaller, NativeThreadProcessReference},
    ProcessManager, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadProjection {
    pub executor: u64,
    pub address_space: u64,
    pub component_kpcr: u64,
    pub executive_kpcr: u64,
    pub thread_body: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Running, Held, ReleaseEntered }

struct Entry<R, D> {
    route: R,
    dispatch: Option<D>,
    caller: NativeHandleCaller,
    reference: NativeThreadProcessReference,
    projection: ThreadProjection,
    phase: Phase,
}

/// Native callers authenticate routes and hold physical execution before changing projections.
/// No scope exit retires these entries: parked or uncertain work retains both body references.
pub struct ProjectionOwners<R, D> { entries: Vec<Entry<R, D>> }

impl<R: Copy + Eq, D: Copy + Eq> ProjectionOwners<R, D> {
    pub const fn new() -> Self { Self { entries: Vec::new() } }

    pub fn contains(&self, route: R) -> bool {
        self.entries.iter().any(|entry| entry.route == route)
    }

    pub fn capture(&mut self, pm: &mut ProcessManager, route: R, dispatch: Option<D>,
        caller: NativeHandleCaller, projection: ThreadProjection) -> Result<(), u32> {
        if projection.executor == 0 || projection.address_space == 0
            || projection.component_kpcr == 0 || projection.executive_kpcr == 0
            || projection.thread_body == 0
            || self.entries.iter().any(|entry| entry.route == route
                || entry.projection.executor == projection.executor
                || entry.projection.executive_kpcr == projection.executive_kpcr
                || (entry.projection.address_space == projection.address_space
                    && entry.projection.component_kpcr == projection.component_kpcr))
            || pm.thread_kernel_object(caller.original_thread().thread_id())
                != Some(projection.thread_body)
        { return Err(STATUS_INVALID_HANDLE); }
        self.entries.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let reference = pm.reference_native_requestor(caller)?;
        self.entries.push(Entry { route, dispatch, caller, reference, projection, phase: Phase::Running });
        Ok(())
    }

    /// Bootstrap ownership is installed before Resume and binds once to the admitted epoch.
    pub fn bind(&mut self, pm: &ProcessManager, route: R, dispatch: D,
        caller: NativeHandleCaller, projection: ThreadProjection) -> Result<(), u32> {
        let entry = self.entries.iter_mut().find(|entry| entry.route == route)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if entry.dispatch.is_some_and(|held| held != dispatch) || entry.caller != caller
            || entry.projection != projection || entry.phase != Phase::Running
        { return Err(STATUS_INVALID_HANDLE); }
        entry.reference.validate(pm)?;
        pm.validate_native_handle_caller(caller)?;
        entry.dispatch = Some(dispatch);
        Ok(())
    }

    pub fn hold(&mut self, route: R, dispatch: D) -> Result<bool, u32> {
        let Some(entry) = self.entries.iter_mut().find(|entry| entry.route == route) else { return Ok(false); };
        if entry.dispatch != Some(dispatch) || entry.phase != Phase::Running { return Err(STATUS_INVALID_HANDLE); }
        entry.phase = Phase::Held;
        Ok(true)
    }

    /// The physical hold is still owned. A failed release must not replay this transition.
    pub fn begin_restore(&mut self, pm: &ProcessManager, route: R, dispatch: D)
        -> Result<Option<ThreadProjection>, u32> {
        let Some(entry) = self.entries.iter_mut().find(|entry| entry.route == route) else { return Ok(None); };
        if entry.dispatch != Some(dispatch) || entry.phase != Phase::Held { return Err(STATUS_INVALID_HANDLE); }
        entry.reference.validate(pm)?;
        pm.validate_native_handle_caller(entry.caller)?;
        entry.phase = Phase::ReleaseEntered;
        Ok(Some(entry.projection))
    }

    pub fn restored(&mut self, route: R, dispatch: D) -> Result<(), u32> {
        let Some(entry) = self.entries.iter_mut().find(|entry| entry.route == route) else { return Ok(()); };
        if entry.dispatch != Some(dispatch) || entry.phase != Phase::ReleaseEntered { return Err(STATUS_INVALID_HANDLE); }
        entry.phase = Phase::Running;
        Ok(())
    }

    pub fn completing(&self, route: R, dispatch: D) -> Result<Option<ThreadProjection>, u32> {
        let Some(entry) = self.entries.iter().find(|entry| entry.route == route) else { return Ok(None); };
        if entry.dispatch != Some(dispatch) || entry.phase != Phase::Running { return Err(STATUS_INVALID_HANDLE); }
        Ok(Some(entry.projection))
    }

    /// Called after authenticated completion, while the TCB remains blocked and CurrentThread
    /// has been cleared. Release failure keeps the entry and its exact physical exclusion.
    pub fn retire(&mut self, pm: &mut ProcessManager, route: R, dispatch: D) -> Result<(), u32> {
        self.completing(route, dispatch)?;
        if let Some(index) = self.entries.iter().position(|entry| entry.route == route) {
            self.entries[index].reference.release(pm)?;
            self.entries.swap_remove(index);
        }
        Ok(())
    }

    /// Terminal adapter only: the exact executor has stopped and its ingress has drained.
    pub fn stopped_projection(&self, route: R, executor: u64, address_space: u64)
        -> Result<Option<ThreadProjection>, u32> {
        let Some(entry) = self.entries.iter().find(|entry| entry.route == route) else { return Ok(None); };
        if entry.projection.executor != executor || entry.projection.address_space != address_space {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(Some(entry.projection))
    }

    pub fn retire_stopped(&mut self, pm: &mut ProcessManager, route: R, executor: u64,
        address_space: u64) -> Result<(), u32> {
        self.stopped_projection(route, executor, address_space)?;
        if let Some(index) = self.entries.iter().position(|entry| entry.route == route) {
            self.entries[index].reference.release(pm)?;
            self.entries.swap_remove(index);
        }
        Ok(())
    }
}

impl<R: Copy + Eq, D: Copy + Eq> Default for ProjectionOwners<R, D> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
#[path = "provider_thread_projection_tests.rs"]
mod tests;
