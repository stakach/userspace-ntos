//! Retained physical execution exclusion for an exact component dispatch.
//!
//! The canonical lane transition belongs to the caller. This record owns the microkernel hold
//! and driver projection across that transition, including uncertain native outcomes. Dropping
//! it never releases either effect.

use super::*;
use nt_component_suspension::LaneDispatchIdentity;
use nt_user_host::physical_execution_restore::{
    AcquireStep, PhysicalExecutionAcquire, PhysicalExecutionRestore, RestoreStep,
};

pub(crate) struct PhysicalExecutionHold {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    hold: Option<u64>,
    projection_reservation: Option<crate::driver_launch::driver_thread_projection::HoldReservation>,
    acquire: PhysicalExecutionAcquire<PeerRoute, LaneDispatchIdentity>,
    restore: PhysicalExecutionRestore<PeerRoute, LaneDispatchIdentity>,
}

impl PhysicalExecutionHold {
    pub(crate) const fn new(route: PeerRoute, dispatch: LaneDispatchIdentity) -> Self {
        Self { route, dispatch, hold: None, projection_reservation: None,
            acquire: PhysicalExecutionAcquire::new(route, dispatch),
            restore: PhysicalExecutionRestore::new(route, dispatch) }
    }

    pub(crate) const fn route(&self) -> PeerRoute { self.route }

    pub(crate) fn held(&self) -> bool {
        self.hold.is_some()
            && self.acquire_step().is_ok_and(|step| step == AcquireStep::ProjectionHeld)
    }

    pub(crate) fn acquire_step(&self) -> Result<AcquireStep, Error> {
        self.acquire.next(self.route, self.dispatch).map_err(|_| Error::Admission)
    }

    pub(crate) fn acquire_has_no_effects(&self) -> bool {
        self.hold.is_none() && self.projection_reservation.is_none()
            && self.acquire_step().is_ok_and(|step| step == AcquireStep::Ready)
    }

    pub(crate) fn restore_step(&self) -> Result<RestoreStep, Error> {
        self.restore.next(self.route, self.dispatch).map_err(|_| Error::Admission)
    }

    pub(crate) fn canonical_pending(&self) -> bool {
        self.restore_step().is_ok_and(|step| step == RestoreStep::Canonical)
    }

    /// Scope admission failed after the physical hold acknowledged. The semantic lane is still
    /// Running, so there is no canonical nested scope to resume. Enter the checked abort path
    /// before any projection or microkernel release is attempted.
    pub(crate) fn begin_abort_after_failed_scope(&mut self) -> Result<(), Error> {
        if self.hold.is_none() || self.projection_reservation.is_some() {
            return Err(Error::Admission);
        }
        self.restore.begin_abort_after_failed_scope(
            &self.acquire, self.route, self.dispatch,
        ).map_err(|_| Error::Admission)
    }

    /// Retry only unentered cleanup stages. An uncertain seL4 release remains fenced.
    pub(crate) unsafe fn abort_after_failed_scope(&mut self) -> Result<(), Error> {
        match self.restore_step()? {
            RestoreStep::Projection => self.restore_projection()?,
            RestoreStep::Release | RestoreStep::Finalize | RestoreStep::Done => {},
            _ => return Err(Error::Admission),
        }
        if self.restore_step()? == RestoreStep::Release {
            self.release()?;
        }
        if self.restore_step()? == RestoreStep::Finalize {
            self.projection_restored()?;
        }
        (self.restore_step()? == RestoreStep::Done)
            .then_some(()).ok_or(Error::Admission)
    }

    pub(crate) fn canonical_restored(&mut self) -> Result<(), Error> {
        self.restore.acknowledge_canonical(self.route, self.dispatch)
            .map_err(|_| Error::Admission)
    }

    /// The owner row must exist before this call. Record possible seL4 entry first and never
    /// reacquire after a malformed result. Projection admission happens before the native effect;
    /// its exact move-only reservation remains in this owner until the result is settled.
    pub(crate) unsafe fn acquire(&mut self) -> Result<(), Error> {
        if self.restore_step()? != RestoreStep::Canonical {
            return Err(Error::Admission);
        }
        match self.acquire_step()? {
            AcquireStep::Ready => {
                self.projection_reservation =
                    crate::driver_launch::driver_thread_projection::prepare_hold(
                        self.route, self.dispatch,
                    ).map_err(|_| Error::Admission)?;
                if self.acquire.enter(self.route, self.dispatch).is_err() {
                    if let Some(reservation) = self.projection_reservation.take() {
                        if let Err((_, reservation)) =
                            crate::driver_launch::driver_thread_projection::cancel_hold_no_effects(reservation)
                        {
                            self.projection_reservation = Some(reservation);
                        }
                    }
                    return Err(Error::Admission);
                }
                match sel4_rt::execution_hold::acquire(self.route.identity().executor) {
                    Ok(hold) => {
                        self.hold = Some(hold);
                        self.acquire.acknowledge_hold(self.route, self.dispatch)
                            .map_err(|_| Error::Admission)?;
                    }
                    // The rust-micro acquire invocation returns kernel errors only before it
                    // allocates a generation or sets execution_hold. This is a no-effects refusal.
                    Err(sel4_rt::execution_hold::Error::Kernel(_)) => {
                        if let Some(reservation) = self.projection_reservation.take() {
                            if let Err((_, reservation)) =
                                crate::driver_launch::driver_thread_projection::cancel_hold_no_effects(reservation)
                            {
                                self.projection_reservation = Some(reservation);
                                return Err(Error::Admission);
                            }
                        }
                        self.acquire.refuse_no_effects(self.route, self.dispatch)
                            .map_err(|_| Error::Admission)?;
                        return Err(Error::Admission);
                    }
                    Err(sel4_rt::execution_hold::Error::MalformedReply) => {
                        return Err(Error::Admission);
                    }
                }
            }
            AcquireStep::Held if self.hold.is_some() => {}
            _ => return Err(Error::Admission),
        }
        if let Some(reservation) = self.projection_reservation.take() {
            if let Err((_, reservation)) =
                crate::driver_launch::driver_thread_projection::acknowledge_hold(reservation)
            {
                self.projection_reservation = Some(reservation);
                return Err(Error::Admission);
            }
        }
        self.acquire.begin_projection(self.route, self.dispatch)
            .map_err(|_| Error::Admission)?;
        self.acquire.acknowledge_projection(self.route, self.dispatch)
            .map_err(|_| Error::Admission)
    }

    /// Called only after canonical restoration has acknowledged the exact dispatch.
    pub(crate) unsafe fn restore_projection(&mut self) -> Result<(), Error> {
        if !self.held() || self.restore_step()? != RestoreStep::Projection {
            return Err(Error::Admission);
        }
        self.restore.enter_projection(self.route, self.dispatch)
            .map_err(|_| Error::Admission)?;
        // This adapter returns Err only from owner preflight, before mutating its projection
        // or writing KPCR bytes. An acknowledged call advances below; any later failure keeps
        // ProjectionEntered fenced and forbids replay of the physical write.
        if crate::driver_launch::driver_thread_projection::restore(self.route, self.dispatch)
            .is_err()
        {
            self.restore.refuse_projection_no_effects(self.route, self.dispatch)
                .map_err(|_| Error::Admission)?;
            return Err(Error::Admission);
        }
        self.restore.acknowledge_projection(self.route, self.dispatch)
            .map_err(|_| Error::Admission)
    }

    /// Once release may have entered, a failure retains this record and forbids replay.
    pub(crate) unsafe fn release(&mut self) -> Result<(), Error> {
        if !self.held() { return Err(Error::Admission); }
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
