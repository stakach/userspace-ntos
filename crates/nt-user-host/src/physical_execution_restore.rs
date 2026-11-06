//! Exact, retained stages for acquiring and restoring a physically held component dispatch.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcquireStep {
    Ready,
    /// The seL4 invocation may have entered; never issue another acquire without a certified
    /// no-effects result from the kernel.
    EnteredUnknown,
    Held,
    ProjectionEntered,
    ProjectionHeld,
}

/// Acquisition authority is independent of the later restore stages. Both are bound to the
/// same route and dispatch generation, and neither advances on an uncertain native outcome.
pub struct PhysicalExecutionAcquire<R, D> {
    route: R,
    dispatch: D,
    step: AcquireStep,
}

impl<R: Copy + Eq, D: Copy + Eq> PhysicalExecutionAcquire<R, D> {
    pub const fn new(route: R, dispatch: D) -> Self {
        Self { route, dispatch, step: AcquireStep::Ready }
    }

    fn validate(&self, route: R, dispatch: D) -> Result<(), RestoreError> {
        if self.route != route || self.dispatch != dispatch {
            return Err(RestoreError::WrongOwner);
        }
        Ok(())
    }

    pub fn next(&self, route: R, dispatch: D) -> Result<AcquireStep, RestoreError> {
        self.validate(route, dispatch)?;
        Ok(self.step)
    }

    /// Persist entry before invoking seL4. A malformed reply leaves this stage unchanged.
    pub fn enter(&mut self, route: R, dispatch: D) -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != AcquireStep::Ready { return Err(RestoreError::InvalidPhase); }
        self.step = AcquireStep::EnteredUnknown;
        Ok(())
    }

    /// Only a kernel refusal known to precede effects may reopen the physical attempt.
    pub fn refuse_no_effects(&mut self, route: R, dispatch: D) -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != AcquireStep::EnteredUnknown { return Err(RestoreError::InvalidPhase); }
        self.step = AcquireStep::Ready;
        Ok(())
    }

    pub fn acknowledge_hold(&mut self, route: R, dispatch: D) -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != AcquireStep::EnteredUnknown { return Err(RestoreError::InvalidPhase); }
        self.step = AcquireStep::Held;
        Ok(())
    }

    /// Projection hold is an executive-local state transition after the physical hold exists.
    pub fn begin_projection(&mut self, route: R, dispatch: D) -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != AcquireStep::Held { return Err(RestoreError::InvalidPhase); }
        self.step = AcquireStep::ProjectionEntered;
        Ok(())
    }

    /// The projection adapter certifies that a refused preflight made no changes.
    pub fn refuse_projection_no_effects(&mut self, route: R, dispatch: D)
        -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != AcquireStep::ProjectionEntered {
            return Err(RestoreError::InvalidPhase);
        }
        self.step = AcquireStep::Held;
        Ok(())
    }

    pub fn acknowledge_projection(&mut self, route: R, dispatch: D)
        -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != AcquireStep::ProjectionEntered {
            return Err(RestoreError::InvalidPhase);
        }
        self.step = AcquireStep::ProjectionHeld;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreStep {
    Canonical,
    Projection,
    Release,
    UncertainRelease,
    Finalize,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreError {
    WrongOwner,
    InvalidPhase,
}

pub struct PhysicalExecutionRestore<R, D> {
    route: R,
    dispatch: D,
    step: RestoreStep,
}

impl<R: Copy + Eq, D: Copy + Eq> PhysicalExecutionRestore<R, D> {
    pub const fn new(route: R, dispatch: D) -> Self {
        Self { route, dispatch, step: RestoreStep::Canonical }
    }

    fn validate(&self, route: R, dispatch: D) -> Result<(), RestoreError> {
        if self.route != route || self.dispatch != dispatch {
            return Err(RestoreError::WrongOwner);
        }
        Ok(())
    }

    pub fn next(&self, route: R, dispatch: D) -> Result<RestoreStep, RestoreError> {
        self.validate(route, dispatch)?;
        Ok(self.step)
    }

    pub fn acknowledge_canonical(&mut self, route: R, dispatch: D) -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != RestoreStep::Canonical { return Err(RestoreError::InvalidPhase); }
        self.step = RestoreStep::Projection;
        Ok(())
    }

    pub fn acknowledge_projection(&mut self, route: R, dispatch: D) -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != RestoreStep::Projection { return Err(RestoreError::InvalidPhase); }
        self.step = RestoreStep::Release;
        Ok(())
    }

    /// Record native entry before invoking seL4. An uncertain result remains here and cannot
    /// issue another release for the same hold generation.
    pub fn enter_release(&mut self, route: R, dispatch: D) -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != RestoreStep::Release { return Err(RestoreError::InvalidPhase); }
        self.step = RestoreStep::UncertainRelease;
        Ok(())
    }

    pub fn acknowledge_release(&mut self, route: R, dispatch: D) -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != RestoreStep::UncertainRelease { return Err(RestoreError::InvalidPhase); }
        self.step = RestoreStep::Finalize;
        Ok(())
    }

    pub fn acknowledge_finalization(&mut self, route: R, dispatch: D) -> Result<(), RestoreError> {
        self.validate(route, dispatch)?;
        if self.step != RestoreStep::Finalize { return Err(RestoreError::InvalidPhase); }
        self.step = RestoreStep::Done;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertain_acquire_cannot_reenter_without_certified_no_effects() {
        let mut acquire = PhysicalExecutionAcquire::new(7u64, 11u64);
        assert_eq!(acquire.next(7, 11), Ok(AcquireStep::Ready));
        assert_eq!(acquire.enter(7, 12), Err(RestoreError::WrongOwner));
        acquire.enter(7, 11).unwrap();
        assert_eq!(acquire.next(7, 11), Ok(AcquireStep::EnteredUnknown));
        assert_eq!(acquire.enter(7, 11), Err(RestoreError::InvalidPhase));
        assert_eq!(acquire.acknowledge_hold(8, 11), Err(RestoreError::WrongOwner));
        // A verified kernel refusal before effect may reopen the same exact attempt.
        assert_eq!(acquire.refuse_no_effects(8, 11), Err(RestoreError::WrongOwner));
        acquire.refuse_no_effects(7, 11).unwrap();
        assert_eq!(acquire.next(7, 11), Ok(AcquireStep::Ready));
        acquire.enter(7, 11).unwrap();
        // A malformed native reply remains uncertain until independent evidence resolves it.
        assert_eq!(acquire.next(7, 11), Ok(AcquireStep::EnteredUnknown));
        assert_eq!(acquire.enter(7, 11), Err(RestoreError::InvalidPhase));
    }

    #[test]
    fn projection_refusal_retries_without_reacquiring_physical_hold() {
        let mut acquire = PhysicalExecutionAcquire::new(3u64, 5u64);
        acquire.enter(3, 5).unwrap();
        acquire.acknowledge_hold(3, 5).unwrap();
        assert_eq!(acquire.next(3, 5), Ok(AcquireStep::Held));
        assert_eq!(acquire.enter(3, 5), Err(RestoreError::InvalidPhase));
        acquire.begin_projection(3, 5).unwrap();
        assert_eq!(acquire.next(3, 5), Ok(AcquireStep::ProjectionEntered));
        acquire.refuse_projection_no_effects(3, 5).unwrap();
        assert_eq!(acquire.next(3, 5), Ok(AcquireStep::Held));
        acquire.begin_projection(3, 5).unwrap();
        acquire.acknowledge_projection(3, 5).unwrap();
        assert_eq!(acquire.next(3, 5), Ok(AcquireStep::ProjectionHeld));
        assert_eq!(acquire.enter(3, 5), Err(RestoreError::InvalidPhase));
    }

    #[test]
    fn resumed_canonical_dispatch_retries_only_unentered_stages() {
        let mut restore = PhysicalExecutionRestore::new(7u64, 11u64);
        assert_eq!(restore.next(7, 11), Ok(RestoreStep::Canonical));
        assert_eq!(restore.next(8, 11), Err(RestoreError::WrongOwner));
        assert_eq!(restore.acknowledge_canonical(7, 12), Err(RestoreError::WrongOwner));
        restore.acknowledge_canonical(7, 11).unwrap();

        // A projection preflight refusal has no effects. A later pass must continue at the
        // projection, without replaying the consumed canonical resume.
        assert_eq!(restore.next(7, 11), Ok(RestoreStep::Projection));
        assert_eq!(restore.next(7, 11), Ok(RestoreStep::Projection));
        restore.acknowledge_projection(7, 11).unwrap();
        assert_eq!(restore.next(7, 11), Ok(RestoreStep::Release));

        // Entering the seL4 release is one-way until its result is known. A malformed result
        // must retain the exact owner and must never select a second physical release.
        restore.enter_release(7, 11).unwrap();
        assert_eq!(restore.next(7, 11), Ok(RestoreStep::UncertainRelease));
        assert_eq!(restore.enter_release(7, 11), Err(RestoreError::InvalidPhase));
        assert_eq!(restore.acknowledge_release(8, 11), Err(RestoreError::WrongOwner));
        restore.acknowledge_release(7, 11).unwrap();

        // A proven release can finish the projection later without issuing release again.
        assert_eq!(restore.next(7, 11), Ok(RestoreStep::Finalize));
        assert_eq!(restore.next(7, 11), Ok(RestoreStep::Finalize));
        restore.acknowledge_finalization(7, 11).unwrap();
        assert_eq!(restore.next(7, 11), Ok(RestoreStep::Done));
        assert_eq!(restore.enter_release(7, 11), Err(RestoreError::InvalidPhase));
    }

    #[test]
    fn uncertain_release_without_ack_keeps_the_owner_and_excludes_replay() {
        let mut restore = PhysicalExecutionRestore::new(3u64, 5u64);
        restore.acknowledge_canonical(3, 5).unwrap();
        restore.acknowledge_projection(3, 5).unwrap();
        restore.enter_release(3, 5).unwrap();
        assert_eq!(restore.next(3, 5), Ok(RestoreStep::UncertainRelease));
        assert_eq!(restore.enter_release(3, 5), Err(RestoreError::InvalidPhase));
        assert_eq!(restore.acknowledge_finalization(3, 5), Err(RestoreError::InvalidPhase));
    }
}
