//! Retained physical execution exclusion for an exact component dispatch.
//!
//! The canonical lane transition belongs to the caller. This record owns the microkernel hold
//! and driver projection across that transition, including uncertain native outcomes. Dropping
//! it never releases either effect.

use super::*;
use nt_component_suspension::LaneDispatchIdentity;
use nt_user_host::physical_execution_restore::{PhysicalExecutionRestore, RestoreStep};

pub(crate) struct PhysicalExecutionHold {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    hold: Option<u64>,
    restore: PhysicalExecutionRestore<PeerRoute, LaneDispatchIdentity>,
}

impl PhysicalExecutionHold {
    pub(crate) const fn new(route: PeerRoute, dispatch: LaneDispatchIdentity) -> Self {
        Self { route, dispatch, hold: None,
            restore: PhysicalExecutionRestore::new(route, dispatch) }
    }

    pub(crate) const fn route(&self) -> PeerRoute { self.route }

    pub(crate) const fn held(&self) -> bool { self.hold.is_some() }

    pub(crate) fn restore_step(&self) -> Result<RestoreStep, Error> {
        self.restore.next(self.route, self.dispatch).map_err(|_| Error::Admission)
    }

    pub(crate) fn canonical_pending(&self) -> bool {
        self.restore_step().is_ok_and(|step| step == RestoreStep::Canonical)
    }

    pub(crate) fn canonical_restored(&mut self) -> Result<(), Error> {
        self.restore.acknowledge_canonical(self.route, self.dispatch)
            .map_err(|_| Error::Admission)
    }

    /// The owner row must exist before this call. Retain a successful hold even if projection
    /// admission later fails, because a failed native result does not prove no effects.
    pub(crate) unsafe fn acquire(&mut self) -> Result<(), Error> {
        if self.hold.is_some() || self.restore_step()? != RestoreStep::Canonical {
            return Err(Error::Admission);
        }
        let hold = sel4_rt::execution_hold::acquire(self.route.identity().executor)
            .map_err(|_| Error::Admission)?;
        self.hold = Some(hold);
        crate::driver_launch::driver_thread_projection::hold(self.route, self.dispatch)
            .map_err(|_| Error::Admission)
    }

    /// Called only after canonical restoration has acknowledged the exact dispatch.
    pub(crate) unsafe fn restore_projection(&mut self) -> Result<(), Error> {
        if self.hold.is_none() || self.restore_step()? != RestoreStep::Projection {
            return Err(Error::Admission);
        }
        crate::driver_launch::driver_thread_projection::restore(self.route, self.dispatch)
            .map_err(|_| Error::Admission)?;
        self.restore.acknowledge_projection(self.route, self.dispatch)
            .map_err(|_| Error::Admission)
    }

    /// Once release may have entered, a failure retains this record and forbids replay.
    pub(crate) unsafe fn release(&mut self) -> Result<(), Error> {
        let hold = self.hold.ok_or(Error::Admission)?;
        self.restore.enter_release(self.route, self.dispatch)
            .map_err(|_| Error::Admission)?;
        sel4_rt::execution_hold::release(self.route.identity().executor, hold)
            .map_err(|_| Error::Admission)?;
        self.restore.acknowledge_release(self.route, self.dispatch)
            .map_err(|_| Error::Admission)
    }

    pub(crate) unsafe fn projection_restored(&mut self) -> Result<(), Error> {
        if self.restore_step()? != RestoreStep::Finalize { return Err(Error::Admission); }
        crate::driver_launch::driver_thread_projection::restored(self.route, self.dispatch)
            .map_err(|_| Error::Admission)?;
        self.restore.acknowledge_finalization(self.route, self.dispatch)
            .map_err(|_| Error::Admission)
    }
}
