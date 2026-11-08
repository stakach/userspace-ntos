//! Retained scheduling-context construction and retirement, independent of thread publication.

use nt_process::STATUS_INVALID_PARAMETER;

pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

fn validate_online_affinity(requested_mask: u64, active_processor_count: u64) -> Result<(), u32> {
    if !(1..=64).contains(&active_processor_count) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let active_mask = u64::MAX >> (64 - active_processor_count);
    if requested_mask == 0 || requested_mask & !active_mask != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// Validate a requested NT affinity against the boot topology and the target thread's actual
/// bound SC core before a native affinity setter changes Ps policy. This does not migrate the SC.
pub fn validate_hosted_thread_affinity(
    requested_mask: u64,
    active_processor_count: u64,
    bound_core: u8,
) -> Result<(), u32> {
    validate_online_affinity(requested_mask, active_processor_count)?;
    if u64::from(bound_core) >= active_processor_count
        || requested_mask & (1u64 << bound_core) == 0
    {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok(())
}

/// Select a configured core from the thread's inherited online affinity before creating its SC.
/// NT client IDs advance by `CLIENT_ID_GRANULARITY`, so the ordinal must remove that stride
/// before cycling through the allowed cores. The returned core is only a proposal until native
/// SchedControl configuration succeeds and the exact runtime owner publishes it.
pub fn select_guest_worker_core(
    inherited_mask: u64,
    active_processor_count: u64,
    tid: u64,
) -> Result<u8, u32> {
    validate_online_affinity(inherited_mask, active_processor_count)?;
    let granularity = u64::from(nt_process::CLIENT_ID_GRANULARITY);
    if tid == 0 || tid % granularity != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let ordinal = tid / granularity - 1;
    let rank = ordinal % u64::from(inherited_mask.count_ones());
    let mut eligible = inherited_mask;
    for _ in 0..rank {
        eligible &= eligible - 1;
    }
    Ok(eligible.trailing_zeros() as u8)
}

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
