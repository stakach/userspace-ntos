use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SynchronousFileRetryPhase {
    Ready { last_error: Option<u32> },
    Invoking { attempt: u64 },
    Acknowledged { local_error: Option<u32> },
    Indeterminate { status: u32 },
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SynchronousFileRetryError {
    WrongIdentity,
    InvalidPhase,
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SynchronousFileRetryOutcome {
    Acknowledged,
    /// The adapter proves the reply mechanism was not entered.
    NotEntered(u32),
    /// A failed or abandoned invocation is not proof that the client remained blocked.
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SynchronousFileRetryIdentity {
    table: u64,
    slot: usize,
    sequence: u64,
}

/// Exact single-use authority for a retained reply attempt. Dropping it leaves Invoking intact.
///
/// ```compile_fail
/// use nt_io_manager::SynchronousFileRetryAttempt;
/// fn duplicate(attempt: SynchronousFileRetryAttempt) { let _copy = attempt.clone(); }
/// ```
#[derive(Debug)]
pub struct SynchronousFileRetryAttempt {
    identity: SynchronousFileRetryIdentity,
    attempt: u64,
    waiter: SynchronousFileWaiter,
    consumed: bool,
}

impl SynchronousFileRetryAttempt {
    pub const fn identity(&self) -> SynchronousFileRetryIdentity {
        self.identity
    }

    /// Copied mechanism input, not authority to acknowledge or retire this delivery.
    pub const fn waiter(&self) -> SynchronousFileWaiter {
        self.waiter
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SynchronousFileRetryView<'a> {
    pub waiter: &'a SynchronousFileWaiter,
    pub phase: SynchronousFileRetryPhase,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SynchronousFileRetryStats {
    pub waiting: usize,
    pub ready: usize,
    pub invoking: usize,
    pub acknowledged: usize,
    pub indeterminate: usize,
    pub retired_grants: usize,
}

impl SynchronousFileWaitTable {
    pub fn retry_identity(
        &self,
        slot: usize,
        key: FileIoWaitKey,
        tid: u64,
    ) -> Option<SynchronousFileRetryIdentity> {
        let record = self.record(slot)?;
        (record.waiter.key() == key && record.waiter.tid == tid && record.retry.is_some())
            .then_some(self.retry_record_identity(slot, record))
    }

    fn retry_record_identity(
        &self,
        slot: usize,
        record: &WaitRecord,
    ) -> SynchronousFileRetryIdentity {
        SynchronousFileRetryIdentity {
            table: self.identity,
            slot,
            sequence: record.waiter.sequence,
        }
    }

    fn retry_record(
        &self,
        identity: SynchronousFileRetryIdentity,
    ) -> Result<&WaitRecord, SynchronousFileRetryError> {
        if identity.table == 0 || identity.table != self.identity {
            return Err(SynchronousFileRetryError::WrongIdentity);
        }
        self.record(identity.slot)
            .filter(|record| record.waiter.sequence == identity.sequence && record.retry.is_some())
            .ok_or(SynchronousFileRetryError::WrongIdentity)
    }

    pub fn retry_delivery(
        &self,
        identity: SynchronousFileRetryIdentity,
    ) -> Result<SynchronousFileRetryView<'_>, SynchronousFileRetryError> {
        let record = self.retry_record(identity)?;
        Ok(SynchronousFileRetryView {
            waiter: &record.waiter,
            phase: record.retry.unwrap(),
        })
    }

    pub fn next_retry_for_file(&self, key: FileIoWaitKey) -> Option<SynchronousFileRetryIdentity> {
        self.records()
            .filter_map(|(slot, record)| {
                (record.waiter.key() == key
                    && matches!(
                        record.retry,
                        Some(
                            SynchronousFileRetryPhase::Ready { .. }
                                | SynchronousFileRetryPhase::Acknowledged { .. }
                        )
                    )
                    && (record.cancellation.is_none()
                        || matches!(
                            record.retry,
                            Some(SynchronousFileRetryPhase::Acknowledged { .. })
                        )))
                .then_some((record.queue_order, self.retry_record_identity(slot, record)))
            })
            .min_by_key(|(sequence, _)| *sequence)
            .map(|(_, identity)| identity)
    }

    /// Ordered reply-cap retirement scan. A failed earlier retirement need not starve another File.
    pub fn next_acknowledged_retry_after(
        &self,
        previous_key: Option<FileIoWaitKey>,
    ) -> Option<SynchronousFileRetryIdentity> {
        self.records()
            .filter_map(|(slot, record)| {
                (previous_key.is_none_or(|previous| record.waiter.key() > previous)
                    && matches!(
                        record.retry,
                        Some(SynchronousFileRetryPhase::Acknowledged { .. })
                    ))
                .then_some((
                    record.waiter.key(),
                    self.retry_record_identity(slot, record),
                ))
            })
            .min_by_key(|(file_id, _)| *file_id)
            .map(|(_, identity)| identity)
    }

    pub fn has_waiter_for_pi(&self, pi: u32) -> bool {
        self.records().any(|(_, record)| record.waiter.pi == pi)
    }

    pub fn has_promoted_for_file(&self, key: FileIoWaitKey) -> bool {
        self.records().any(|(_, record)| {
            record.waiter.key() == key
                && record.waiter.state == SynchronousFileWaitState::Promoted
                && record.cancellation.is_none()
        })
    }

    pub fn has_retry_delivery_matching(
        &self,
        mut matches: impl FnMut(&SynchronousFileWaiter) -> bool,
    ) -> bool {
        self.records()
            .any(|(_, record)| record.delivery_retained() && matches(&record.waiter))
    }

    pub fn has_retry_delivery_for_thread(&self, tid: u64) -> bool {
        self.has_retry_delivery_matching(|waiter| waiter.tid == tid)
    }

    pub fn has_retry_delivery_for_pi(&self, pi: u32) -> bool {
        self.has_retry_delivery_matching(|waiter| waiter.pi == pi)
    }

    pub fn has_retry_delivery_for_file(&self, key: FileIoWaitKey) -> bool {
        self.has_retry_delivery_matching(|waiter| waiter.key() == key)
    }

    pub fn retry_stats(&self) -> SynchronousFileRetryStats {
        let mut stats = SynchronousFileRetryStats::default();
        for (_, record) in self.records() {
            match record.retry {
                None => stats.waiting += 1,
                Some(SynchronousFileRetryPhase::Ready { .. }) => stats.ready += 1,
                Some(SynchronousFileRetryPhase::Invoking { .. }) => stats.invoking += 1,
                Some(SynchronousFileRetryPhase::Acknowledged { .. }) => stats.acknowledged += 1,
                Some(SynchronousFileRetryPhase::Indeterminate { .. }) => stats.indeterminate += 1,
                Some(SynchronousFileRetryPhase::Retired) => stats.retired_grants += 1,
            }
        }
        stats
    }

    /// Retain the entered proposal before the adapter releases this borrow and invokes Reply.
    pub fn begin_retry(
        &mut self,
        identity: SynchronousFileRetryIdentity,
    ) -> Result<SynchronousFileRetryAttempt, SynchronousFileRetryError> {
        let record = self.retry_record(identity)?;
        if record.cancellation.is_some()
            || !matches!(record.retry, Some(SynchronousFileRetryPhase::Ready { .. }))
        {
            return Err(SynchronousFileRetryError::InvalidPhase);
        }
        let attempt = record.next_attempt;
        let next = attempt
            .checked_add(1)
            .ok_or(SynchronousFileRetryError::Exhausted)?;
        let ticket = SynchronousFileRetryAttempt {
            identity,
            attempt,
            waiter: record.waiter,
            consumed: false,
        };
        let record = self.record_mut(identity.slot).unwrap();
        record.next_attempt = next;
        record.retry = Some(SynchronousFileRetryPhase::Invoking { attempt });
        Ok(ticket)
    }

    pub fn record_retry(
        &mut self,
        ticket: &mut SynchronousFileRetryAttempt,
        outcome: SynchronousFileRetryOutcome,
    ) -> Result<(), SynchronousFileRetryError> {
        let record = self.retry_record(ticket.identity)?;
        if ticket.consumed
            || record.waiter != ticket.waiter
            || record.retry
                != Some(SynchronousFileRetryPhase::Invoking {
                    attempt: ticket.attempt,
                })
        {
            return Err(SynchronousFileRetryError::InvalidPhase);
        }
        let record = self.record_mut(ticket.identity.slot).unwrap();
        record.retry = Some(match outcome {
            SynchronousFileRetryOutcome::Acknowledged => {
                SynchronousFileRetryPhase::Acknowledged { local_error: None }
            }
            SynchronousFileRetryOutcome::NotEntered(status) => SynchronousFileRetryPhase::Ready {
                last_error: Some(status),
            },
            SynchronousFileRetryOutcome::Indeterminate(status) => {
                SynchronousFileRetryPhase::Indeterminate { status }
            }
        });
        record.activate_deferred_cancellation();
        ticket.consumed = true;
        Ok(())
    }

    /// A successful local reply-cap retirement enables retry ingress, but retains the File grant.
    /// Local failure does not replay Reply or remove its acknowledged owner.
    pub fn finish_retry(
        &mut self,
        identity: SynchronousFileRetryIdentity,
        local_retirement: Result<(), u32>,
    ) -> Result<bool, SynchronousFileRetryError> {
        let record = self.retry_record(identity)?;
        if !matches!(
            record.retry,
            Some(SynchronousFileRetryPhase::Acknowledged { .. })
        ) {
            return Err(SynchronousFileRetryError::InvalidPhase);
        }
        let record = self.record_mut(identity.slot).unwrap();
        if let Err(status) = local_retirement {
            record.retry = Some(SynchronousFileRetryPhase::Acknowledged {
                local_error: Some(status),
            });
            return Ok(false);
        }
        record.waiter.reply_cap = 0;
        record.retry = Some(SynchronousFileRetryPhase::Retired);
        record.activate_deferred_cancellation();
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
