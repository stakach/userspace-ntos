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
    pub const fn identity(&self) -> SynchronousFileRetryIdentity { self.identity }

    /// Copied mechanism input, not authority to acknowledge or retire this delivery.
    pub const fn waiter(&self) -> SynchronousFileWaiter { self.waiter }
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
    pub fn retry_identity(&self, slot: usize, file_id: u64, tid: u64)
        -> Option<SynchronousFileRetryIdentity>
    {
        let record = self.slots.get(slot)?.as_ref()?;
        (record.waiter.file_id == file_id && record.waiter.tid == tid && record.retry.is_some())
            .then_some(self.retry_record_identity(slot, record))
    }

    fn retry_record_identity(&self, slot: usize, record: &WaitRecord) -> SynchronousFileRetryIdentity {
        SynchronousFileRetryIdentity { table: self.identity, slot, sequence: record.waiter.sequence }
    }

    fn retry_record(&self, identity: SynchronousFileRetryIdentity)
        -> Result<&WaitRecord, SynchronousFileRetryError>
    {
        if identity.table == 0 || identity.table != self.identity {
            return Err(SynchronousFileRetryError::WrongIdentity);
        }
        self.slots.get(identity.slot).and_then(Option::as_ref)
            .filter(|record| record.waiter.sequence == identity.sequence && record.retry.is_some())
            .ok_or(SynchronousFileRetryError::WrongIdentity)
    }

    pub fn retry_delivery(&self, identity: SynchronousFileRetryIdentity)
        -> Result<SynchronousFileRetryView<'_>, SynchronousFileRetryError>
    {
        let record = self.retry_record(identity)?;
        Ok(SynchronousFileRetryView { waiter: &record.waiter, phase: record.retry.unwrap() })
    }

    pub fn next_retry_for_file(&self, file_id: u64) -> Option<SynchronousFileRetryIdentity> {
        self.slots.iter().enumerate().filter_map(|(slot, record)| {
            let record = record.as_ref()?;
            (record.waiter.file_id == file_id && matches!(record.retry,
                Some(SynchronousFileRetryPhase::Ready { .. } | SynchronousFileRetryPhase::Acknowledged { .. })))
                .then_some((record.waiter.sequence, self.retry_record_identity(slot, record)))
        }).min_by_key(|(sequence, _)| *sequence).map(|(_, identity)| identity)
    }

    /// Ordered local-only retry scan. A failed earlier retirement need not starve another File.
    pub fn next_acknowledged_retry_after(&self, previous_file_id: Option<u64>)
        -> Option<SynchronousFileRetryIdentity>
    {
        self.slots.iter().enumerate().filter_map(|(slot, record)| {
            let record = record.as_ref()?;
            (previous_file_id.is_none_or(|previous| record.waiter.file_id > previous)
                && matches!(record.retry, Some(SynchronousFileRetryPhase::Acknowledged { .. })))
                .then_some((record.waiter.file_id, self.retry_record_identity(slot, record)))
        }).min_by_key(|(file_id, _)| *file_id).map(|(_, identity)| identity)
    }

    pub fn has_waiter_for_pi(&self, pi: u32) -> bool {
        self.slots.iter().flatten().any(|record| record.waiter.pi == pi)
    }

    pub fn has_promoted_for_file(&self, file_id: u64) -> bool {
        self.slots.iter().flatten().any(|record|
            record.waiter.file_id == file_id && record.waiter.state == SynchronousFileWaitState::Promoted)
    }

    pub fn has_retry_delivery_matching(&self, mut matches: impl FnMut(&SynchronousFileWaiter) -> bool) -> bool {
        self.slots.iter().flatten().any(|record| record.delivery_retained() && matches(&record.waiter))
    }

    pub fn has_retry_delivery_for_thread(&self, tid: u64) -> bool {
        self.has_retry_delivery_matching(|waiter| waiter.tid == tid)
    }

    pub fn has_retry_delivery_for_pi(&self, pi: u32) -> bool {
        self.has_retry_delivery_matching(|waiter| waiter.pi == pi)
    }

    pub fn has_retry_delivery_for_file(&self, file_id: u64) -> bool {
        self.has_retry_delivery_matching(|waiter| waiter.file_id == file_id)
    }

    pub fn retry_stats(&self) -> SynchronousFileRetryStats {
        let mut stats = SynchronousFileRetryStats::default();
        for record in self.slots.iter().flatten() {
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
    pub fn begin_retry(&mut self, identity: SynchronousFileRetryIdentity)
        -> Result<SynchronousFileRetryAttempt, SynchronousFileRetryError>
    {
        let record = self.retry_record(identity)?;
        if !matches!(record.retry, Some(SynchronousFileRetryPhase::Ready { .. })) {
            return Err(SynchronousFileRetryError::InvalidPhase);
        }
        let attempt = record.next_attempt;
        let next = attempt.checked_add(1).ok_or(SynchronousFileRetryError::Exhausted)?;
        let ticket = SynchronousFileRetryAttempt { identity, attempt, waiter: record.waiter, consumed: false };
        let record = self.slots[identity.slot].as_mut().unwrap();
        record.next_attempt = next;
        record.retry = Some(SynchronousFileRetryPhase::Invoking { attempt });
        Ok(ticket)
    }

    pub fn record_retry(&mut self, ticket: &mut SynchronousFileRetryAttempt, outcome: SynchronousFileRetryOutcome)
        -> Result<(), SynchronousFileRetryError>
    {
        let record = self.retry_record(ticket.identity)?;
        if ticket.consumed || record.waiter != ticket.waiter
            || record.retry != Some(SynchronousFileRetryPhase::Invoking { attempt: ticket.attempt })
        {
            return Err(SynchronousFileRetryError::InvalidPhase);
        }
        self.slots[ticket.identity.slot].as_mut().unwrap().retry = Some(match outcome {
            SynchronousFileRetryOutcome::Acknowledged => SynchronousFileRetryPhase::Acknowledged { local_error: None },
            SynchronousFileRetryOutcome::NotEntered(status) => SynchronousFileRetryPhase::Ready { last_error: Some(status) },
            SynchronousFileRetryOutcome::Indeterminate(status) => SynchronousFileRetryPhase::Indeterminate { status },
        });
        ticket.consumed = true;
        Ok(())
    }

    /// A successful local reply-cap retirement enables retry ingress, but retains the File grant.
    /// Local failure does not replay Reply or remove its acknowledged owner.
    pub fn finish_retry(&mut self, identity: SynchronousFileRetryIdentity, local_retirement: Result<(), u32>)
        -> Result<bool, SynchronousFileRetryError>
    {
        let record = self.retry_record(identity)?;
        if !matches!(record.retry, Some(SynchronousFileRetryPhase::Acknowledged { .. })) {
            return Err(SynchronousFileRetryError::InvalidPhase);
        }
        let record = self.slots[identity.slot].as_mut().unwrap();
        if let Err(status) = local_retirement {
            record.retry = Some(SynchronousFileRetryPhase::Acknowledged { local_error: Some(status) });
            return Ok(false);
        }
        record.waiter.reply_cap = 0;
        record.retry = Some(SynchronousFileRetryPhase::Retired);
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
