//! Exact, retained stage selection for restoring a physically held component dispatch.

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
