//! Retained scheduling-context construction and retirement, independent of thread publication.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Allocate,
    Retype,
    Configure,
    Bind,
    Bound,
    Delete,
    Recycle,
    Retired,
    Transferred,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidState,
    Backend { stage: Stage, status: u64 },
}

pub trait SchedContextIo {
    /// Return one exclusively owned empty slot; an error must allocate nothing.
    fn allocate_slot(&mut self) -> Result<u64, u64>;
    /// Error leaves the slot empty. Success creates the sole SC capability in it.
    fn retype(&mut self, slot: u64) -> Result<(), u64>;
    fn configure(&mut self, cap: u64, budget: u64, period: u64) -> Result<(), u64>;
    /// Error must leave the SC unbound. A successful bind is the final construction operation.
    fn bind(&mut self, cap: u64, tcb: u64) -> Result<(), u64>;
    /// Delete the unbound object only, without recycling its root slot.
    fn delete(&mut self, cap: u64) -> Result<(), u64>;
    /// Publish an empty slot back to the allocator. Reserve/check free-list capacity before
    /// changing ownership/accounting. Error retains the allocated empty slot for retry.
    fn recycle_slot(&mut self, slot: u64) -> Result<(), u64>;
}

/// Store this non-cloneable owner before allocating a slot. Failure is sticky retirement: the
/// target TCB is forgotten and never used again, since its caller may immediately delete/reuse it.
/// Drop does not perform cleanup. A successful bound cap transfers once to the caller's owner.
#[must_use = "retain the SC owner until checked retirement or successful cap transfer"]
pub struct SchedContextConstruction {
    stage: Stage,
    slot: Option<u64>,
    target: Option<u64>,
    budget: u64,
    period: u64,
    failure: Option<Error>,
}

impl SchedContextConstruction {
    pub fn new(tcb: u64, budget: u64, period: u64) -> Option<Self> {
        if tcb <= 1 || budget == 0 || budget > period {
            return None;
        }
        Some(Self {
            stage: Stage::Allocate,
            slot: None,
            target: Some(tcb),
            budget,
            period,
            failure: None,
        })
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn slot(&self) -> Option<u64> {
        self.slot
    }

    pub fn construct(&mut self, io: &mut impl SchedContextIo) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        loop {
            let stage = self.stage;
            let result = match stage {
                Stage::Allocate => io.allocate_slot().map(|slot| {
                    self.slot = Some(slot);
                    self.stage = Stage::Retype;
                }),
                Stage::Retype => io
                    .retype(self.slot.unwrap())
                    .map(|()| self.stage = Stage::Configure),
                Stage::Configure => io
                    .configure(self.slot.unwrap(), self.budget, self.period)
                    .map(|()| self.stage = Stage::Bind),
                Stage::Bind => io.bind(self.slot.unwrap(), self.target.unwrap()).map(|()| {
                    self.stage = Stage::Bound;
                    self.target = None;
                }),
                Stage::Bound => return Ok(()),
                _ => return Err(Error::InvalidState),
            };
            if let Err(status) = result {
                let error = Error::Backend { stage, status };
                self.failure = Some(error);
                self.target = None;
                self.stage = match stage {
                    Stage::Allocate => Stage::Retired,
                    Stage::Retype => Stage::Recycle,
                    Stage::Configure | Stage::Bind => Stage::Delete,
                    _ => unreachable!("only construction invokes fallible backend operations"),
                };
                return Err(error);
            }
        }
    }

    /// Retry retirement only. Successful deletion is acknowledged before potentially failing
    /// slot recycling, so a later retry can never delete a newly reused capability.
    pub fn retire(&mut self, io: &mut impl SchedContextIo) -> Result<(), Error> {
        loop {
            let stage = self.stage;
            match stage {
                Stage::Delete => {
                    io.delete(self.slot.unwrap())
                        .map_err(|status| Error::Backend { stage, status })?;
                    self.stage = Stage::Recycle;
                }
                Stage::Recycle => {
                    io.recycle_slot(self.slot.unwrap())
                        .map_err(|status| Error::Backend { stage, status })?;
                    self.slot = None;
                    self.stage = Stage::Retired;
                }
                Stage::Retired => return Ok(()),
                _ => return Err(Error::InvalidState),
            }
        }
    }

    pub fn take_bound(&mut self) -> Option<u64> {
        if self.stage != Stage::Bound {
            return None;
        }
        self.stage = Stage::Transferred;
        self.slot.take()
    }
}

#[cfg(test)]
#[path = "sched_context_tests.rs"]
mod tests;
