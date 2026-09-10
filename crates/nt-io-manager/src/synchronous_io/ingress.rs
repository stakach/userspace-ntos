//! Retained adoption of an acknowledged File grant across native argument validation.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynchronousFileIngressPhase {
    Claimed,
    Adopting { attempt: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SynchronousFileIngressError {
    WrongIdentity,
    InvalidPhase,
    MetadataMismatch,
    CancellationRequested,
    Exhausted,
}

/// A claim does not transfer the grant or reference out of the table.
///
/// ```compile_fail
/// use nt_io_manager::SynchronousFileIngress;
/// fn duplicate(claim: SynchronousFileIngress) { let _ = claim.clone(); }
/// ```
#[derive(Debug)]
pub struct SynchronousFileIngress {
    identity: SynchronousFileWaitIdentity,
    waiter: SynchronousFileWaiter,
    consumed: bool,
}

impl SynchronousFileIngress {
    pub const fn identity(&self) -> SynchronousFileWaitIdentity {
        self.identity
    }
    pub const fn waiter(&self) -> SynchronousFileWaiter {
        self.waiter
    }

    /// A retried syscall cannot turn its retained grant into a new handle acquisition.
    pub const fn matches_handle(&self, handle: u64) -> bool {
        handle == self.waiter.handle as u64
    }
}

/// Entered before the pure canonical grant adoption. Dropping this ticket retains an invoking
/// owner; neither a second adoption nor cancellation may guess whether Busy was transferred.
#[derive(Debug)]
pub struct SynchronousFileAdoptionAttempt {
    identity: SynchronousFileWaitIdentity,
    waiter: SynchronousFileWaiter,
    attempt: u64,
    consumed: bool,
}

impl SynchronousFileAdoptionAttempt {
    pub const fn identity(&self) -> SynchronousFileWaitIdentity {
        self.identity
    }
    pub const fn waiter(&self) -> SynchronousFileWaiter {
        self.waiter
    }
}

/// Successful exact adoption transfers the existing reference and Busy owner, never a new one.
/// The adapter must publish them on the current syscall before making any reentrant call.
#[derive(Debug)]
pub struct SynchronousFileAdoptedOwner {
    waiter: SynchronousFileWaiter,
    cancellation_requested: bool,
}

impl SynchronousFileAdoptedOwner {
    pub const fn waiter(&self) -> SynchronousFileWaiter {
        self.waiter
    }
    pub const fn cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }
}

impl SynchronousFileWaitTable {
    fn ingress_record(
        &self,
        identity: SynchronousFileWaitIdentity,
    ) -> Result<&WaitRecord, SynchronousFileIngressError> {
        if identity.table == 0 || identity.table != self.identity {
            return Err(SynchronousFileIngressError::WrongIdentity);
        }
        self.record(identity.slot)
            .filter(|record| record.waiter.sequence == identity.sequence)
            .ok_or(SynchronousFileIngressError::WrongIdentity)
    }

    /// Claim only the fully acknowledged, capability-retired retry for this exact native call.
    /// A retained same-thread owner is an error, not permission to admit a fresh operation.
    pub fn begin_ingress(
        &mut self,
        pi: u32,
        tid: u64,
        badge: u64,
        service_number: u32,
    ) -> Result<Option<SynchronousFileIngress>, SynchronousFileIngressError> {
        let Some((slot, record)) = self.records().find(|(_, record)| record.waiter.tid == tid)
        else {
            return Ok(None);
        };
        let waiter = record.waiter;
        if waiter.pi != pi || waiter.badge != badge || waiter.service_number != service_number {
            return Err(SynchronousFileIngressError::MetadataMismatch);
        }
        if record.cancellation.is_some() {
            return Err(SynchronousFileIngressError::CancellationRequested);
        }
        if record.ingress.is_some()
            || waiter.state != SynchronousFileWaitState::Promoted
            || waiter.reply_cap != 0
            || record.retry != Some(SynchronousFileRetryPhase::Retired)
        {
            return Err(SynchronousFileIngressError::InvalidPhase);
        }
        let identity = SynchronousFileWaitIdentity {
            table: self.identity,
            slot,
            sequence: waiter.sequence,
        };
        self.record_mut(slot).unwrap().ingress = Some(SynchronousFileIngressPhase::Claimed);
        Ok(Some(SynchronousFileIngress {
            identity,
            waiter,
            consumed: false,
        }))
    }

    pub fn has_ingress_for_thread(&self, tid: u64) -> bool {
        self.records()
            .any(|(_, record)| record.waiter.tid == tid && record.ingress.is_some())
    }

    pub fn has_ingress_for_pi(&self, pi: u32) -> bool {
        self.records()
            .any(|(_, record)| record.waiter.pi == pi && record.ingress.is_some())
    }

    pub fn begin_adoption(
        &mut self,
        ingress: &mut SynchronousFileIngress,
    ) -> Result<SynchronousFileAdoptionAttempt, SynchronousFileIngressError> {
        let record = self.ingress_record(ingress.identity)?;
        if ingress.consumed || record.ingress != Some(SynchronousFileIngressPhase::Claimed) {
            return Err(SynchronousFileIngressError::InvalidPhase);
        }
        if record.cancellation.is_some() {
            return Err(SynchronousFileIngressError::CancellationRequested);
        }
        let next = record
            .next_attempt
            .checked_add(1)
            .ok_or(SynchronousFileIngressError::Exhausted)?;
        let record = self.record_mut(ingress.identity.slot).unwrap();
        let attempt = record.next_attempt;
        record.next_attempt = next;
        record.ingress = Some(SynchronousFileIngressPhase::Adopting { attempt });
        ingress.consumed = true;
        Ok(SynchronousFileAdoptionAttempt {
            identity: ingress.identity,
            waiter: ingress.waiter,
            attempt,
            consumed: false,
        })
    }

    /// The receipt must come from a checked, pure adopt operation: failure may not acquire idle
    /// Busy or enqueue another waiter. No callback may occur between that effect and this record.
    pub fn record_adoption(
        &mut self,
        attempt: &mut SynchronousFileAdoptionAttempt,
        result: Result<(), u32>,
    ) -> Result<Option<SynchronousFileAdoptedOwner>, SynchronousFileIngressError> {
        let record = self.ingress_record(attempt.identity)?;
        if attempt.consumed
            || record.ingress
                != Some(SynchronousFileIngressPhase::Adopting {
                    attempt: attempt.attempt,
                })
        {
            return Err(SynchronousFileIngressError::InvalidPhase);
        }
        attempt.consumed = true;
        match result {
            Ok(()) => {
                let record = self.slots[attempt.identity.slot]
                    .take()
                    .unwrap()
                    .into_record()
                    .unwrap();
                Ok(Some(SynchronousFileAdoptedOwner {
                    waiter: record.waiter,
                    cancellation_requested: record.cancellation.is_some(),
                }))
            }
            Err(status) => {
                self.record_mut(attempt.identity.slot).unwrap().ingress = None;
                self.request_cancellation(attempt.identity)
                    .map_err(|_| SynchronousFileIngressError::WrongIdentity)?;
                self.record_mut(attempt.identity.slot)
                    .unwrap()
                    .activate_deferred_cancellation();
                self.record_ingress_rejection(attempt.identity, status);
                Ok(None)
            }
        }
    }

    pub fn reject_ingress(
        &mut self,
        ingress: &mut SynchronousFileIngress,
        status: u32,
    ) -> Result<SynchronousFileCancelIdentity, SynchronousFileIngressError> {
        let record = self.ingress_record(ingress.identity)?;
        if ingress.consumed || record.ingress != Some(SynchronousFileIngressPhase::Claimed) {
            return Err(SynchronousFileIngressError::InvalidPhase);
        }
        ingress.consumed = true;
        self.record_mut(ingress.identity.slot).unwrap().ingress = None;
        self.request_cancellation(ingress.identity)
            .map_err(|_| SynchronousFileIngressError::WrongIdentity)?;
        self.record_ingress_rejection(ingress.identity, status);
        Ok(ingress.identity)
    }

    fn record_ingress_rejection(&mut self, identity: SynchronousFileWaitIdentity, status: u32) {
        let cancel = self
            .record_mut(identity.slot)
            .unwrap()
            .cancellation
            .as_mut()
            .unwrap();
        if let SynchronousFileCancelPhase::Ready { effect, .. } = cancel.phase {
            cancel.phase = SynchronousFileCancelPhase::Ready {
                effect,
                last_error: Some(status),
            };
        }
    }
}

#[cfg(test)]
#[path = "ingress/tests.rs"]
mod tests;
