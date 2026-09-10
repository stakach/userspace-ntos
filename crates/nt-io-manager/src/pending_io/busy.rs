//! Checked File Busy retirement. Releasing Busy and waking its FIFO are separate effects;
//! a failed wake must never authorize a second release of an already-consumed owner.

use super::*;
use crate::FileIoWaitKey;
use nt_io_completion::FileIoMode;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BusyIdentity {
    table: u64,
    generation: u64,
}

impl BusyIdentity {
    const fn is_published(self) -> bool {
        self.table != 0 && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIoBusyOwner {
    pub key: FileIoWaitKey,
    pub tid: u64,
    pub mode: FileIoMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFileBusyPhase {
    ReleaseReady {
        last_error: Option<u32>,
    },
    Releasing {
        attempt: u64,
    },
    WakeReady {
        waiters: u32,
        last_error: Option<u32>,
    },
    Waking {
        attempt: u64,
        waiters: u32,
    },
    Settled {
        waiters: u32,
    },
}

/// An unpublished owner may be copied as input. Only the table can mint its live identity or
/// advance its retirement state; copying a published observation cannot create another owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingFileBusy {
    owner: FileIoBusyOwner,
    identity: BusyIdentity,
    next_attempt: u64,
    phase: PendingFileBusyPhase,
}

impl PendingFileBusy {
    pub const fn new(owner: FileIoBusyOwner) -> Self {
        Self {
            owner,
            identity: BusyIdentity {
                table: 0,
                generation: 0,
            },
            next_attempt: 1,
            phase: PendingFileBusyPhase::ReleaseReady { last_error: None },
        }
    }

    pub const fn owner(self) -> FileIoBusyOwner {
        self.owner
    }

    pub const fn phase(self) -> PendingFileBusyPhase {
        self.phase
    }

    pub const fn is_settled(self) -> bool {
        matches!(self.phase, PendingFileBusyPhase::Settled { .. })
    }

    pub const fn release_pending(self) -> bool {
        matches!(self.phase, PendingFileBusyPhase::ReleaseReady { .. })
    }

    pub(super) fn release_unstarted(self) -> bool {
        self.next_attempt == 1 && self.release_pending()
    }

    pub(super) fn valid_unpublished_owner(self, pending: PendingFileIo) -> bool {
        self.identity == BusyIdentity::default()
            && self.release_unstarted()
            && self.owner.tid != 0
            && self.owner.tid != u64::MAX
            && self.owner.tid == pending.tid
            && pending.hosted_file_id().map(FileIoWaitKey::Hosted) == Some(self.owner.key)
            && matches!(
                self.owner.mode,
                FileIoMode::SynchronousAlertable | FileIoMode::SynchronousNonAlertable
            )
            && !pending.is_local()
            && !matches!(pending.operation, PendingFileIoOperation::Create(_))
    }

    pub(super) fn publish_reserved_identity(&mut self, reservation: PendingFileIoReservation) {
        self.identity = BusyIdentity {
            table: reservation.table,
            generation: reservation.generation,
        };
    }
}

impl PendingFileIo {
    pub(super) fn busy_is_settled(self) -> bool {
        self.busy.is_none_or(PendingFileBusy::is_settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingFileBusyError {
    WrongIdentity,
    InvalidPhase,
    UnsettledSurfaces,
    Exhausted,
}

#[derive(Debug)]
struct BusyAttempt {
    slot: usize,
    irp_id: u64,
    identity: BusyIdentity,
    owner: FileIoBusyOwner,
    attempt: u64,
    consumed: bool,
}

/// Single-use receipt authority. Dropping an entered attempt leaves it retained, not retryable.
///
/// ```compile_fail
/// use nt_io_manager::PendingFileBusyReleaseAttempt;
/// fn duplicate(attempt: PendingFileBusyReleaseAttempt) { let _copy = attempt.clone(); }
/// ```
#[derive(Debug)]
pub struct PendingFileBusyReleaseAttempt(BusyAttempt);

impl PendingFileBusyReleaseAttempt {
    pub const fn owner(&self) -> FileIoBusyOwner {
        self.0.owner
    }
}

/// A wake is authorized independently from the already-committed File Busy release.
///
/// ```compile_fail
/// use nt_io_manager::PendingFileBusyWakeAttempt;
/// fn duplicate(attempt: PendingFileBusyWakeAttempt) { let _copy = attempt.clone(); }
/// ```
#[derive(Debug)]
pub struct PendingFileBusyWakeAttempt {
    attempt: BusyAttempt,
    waiters: u32,
}

impl PendingFileBusyWakeAttempt {
    pub const fn owner(&self) -> FileIoBusyOwner {
        self.attempt.owner
    }
    pub const fn waiters(&self) -> u32 {
        self.waiters
    }
}

impl PendingFileIoTable {
    fn busy_for_attempt(
        &self,
        attempt: &BusyAttempt,
    ) -> Result<PendingFileBusy, PendingFileBusyError> {
        let pending = self
            .get(attempt.slot)
            .ok_or(PendingFileBusyError::WrongIdentity)?;
        let busy = pending.busy.ok_or(PendingFileBusyError::WrongIdentity)?;
        if pending.irp_id != attempt.irp_id
            || !busy.identity.is_published()
            || busy.identity != attempt.identity
            || busy.owner != attempt.owner
        {
            return Err(PendingFileBusyError::WrongIdentity);
        }
        if attempt.consumed {
            return Err(PendingFileBusyError::InvalidPhase);
        }
        Ok(busy)
    }

    pub fn begin_busy_release_exact(
        &mut self,
        slot: usize,
        irp_id: u64,
    ) -> Result<PendingFileBusyReleaseAttempt, PendingFileBusyError> {
        let pending = self.get(slot).ok_or(PendingFileBusyError::WrongIdentity)?;
        let busy = pending.busy.ok_or(PendingFileBusyError::WrongIdentity)?;
        if pending.irp_id != irp_id || !busy.identity.is_published() {
            return Err(PendingFileBusyError::WrongIdentity);
        }
        if !busy.release_pending() {
            return Err(PendingFileBusyError::InvalidPhase);
        }
        let before_reply = Self::required_delivery_state(pending)
            & !(IO_DELIVERY_BACKEND_ACKED
                | IO_DELIVERY_FILE_LOCK_RELEASED
                | IO_DELIVERY_REPLY_CLAIMED
                | IO_DELIVERY_REPLY_PUBLISHED);
        if pending.delivery_state & before_reply != before_reply {
            return Err(PendingFileBusyError::UnsettledSurfaces);
        }
        let next = busy
            .next_attempt
            .checked_add(1)
            .ok_or(PendingFileBusyError::Exhausted)?;
        let ticket = PendingFileBusyReleaseAttempt(BusyAttempt {
            slot,
            irp_id,
            identity: busy.identity,
            owner: busy.owner,
            attempt: busy.next_attempt,
            consumed: false,
        });
        let busy = self.slots[slot].as_mut().unwrap().busy.as_mut().unwrap();
        busy.phase = PendingFileBusyPhase::Releasing {
            attempt: busy.next_attempt,
        };
        busy.next_attempt = next;
        Ok(ticket)
    }

    /// `Err` is a definite rejection before Busy changed, not an uncertain invocation or a later
    /// FIFO-wake error. Accepted release publishes its receipt before any reentrant wake work.
    pub fn record_busy_release(
        &mut self,
        ticket: &mut PendingFileBusyReleaseAttempt,
        result: Result<u32, u32>,
    ) -> Result<u16, PendingFileBusyError> {
        let busy = self.busy_for_attempt(&ticket.0)?;
        if busy.phase
            != (PendingFileBusyPhase::Releasing {
                attempt: ticket.0.attempt,
            })
        {
            return Err(PendingFileBusyError::InvalidPhase);
        }
        let pending = self.slots[ticket.0.slot].as_mut().unwrap();
        pending.busy.as_mut().unwrap().phase = match result {
            Ok(waiters) => {
                pending.delivery_state |= IO_DELIVERY_FILE_LOCK_RELEASED;
                PendingFileBusyPhase::WakeReady {
                    waiters,
                    last_error: None,
                }
            }
            Err(status) => PendingFileBusyPhase::ReleaseReady {
                last_error: Some(status),
            },
        };
        ticket.0.consumed = true;
        Ok(pending.delivery_state)
    }

    /// One pass visits each slot at most once. Entered wake attempts are excluded on reentry.
    pub fn next_busy_wake_after(&self, after: Option<usize>) -> Option<(usize, PendingFileIo)> {
        self.slots.iter().enumerate().find_map(|(slot, pending)| {
            if after.is_some_and(|after| slot <= after) {
                return None;
            }
            let pending = pending.as_ref()?;
            matches!(pending.busy?.phase, PendingFileBusyPhase::WakeReady { .. })
                .then_some((slot, *pending))
        })
    }

    pub fn begin_busy_wake_exact(
        &mut self,
        slot: usize,
        irp_id: u64,
    ) -> Result<PendingFileBusyWakeAttempt, PendingFileBusyError> {
        let pending = self.get(slot).ok_or(PendingFileBusyError::WrongIdentity)?;
        let busy = pending.busy.ok_or(PendingFileBusyError::WrongIdentity)?;
        if pending.irp_id != irp_id || !busy.identity.is_published() {
            return Err(PendingFileBusyError::WrongIdentity);
        }
        let PendingFileBusyPhase::WakeReady { waiters, .. } = busy.phase else {
            return Err(PendingFileBusyError::InvalidPhase);
        };
        let next = busy
            .next_attempt
            .checked_add(1)
            .ok_or(PendingFileBusyError::Exhausted)?;
        let ticket = PendingFileBusyWakeAttempt {
            attempt: BusyAttempt {
                slot,
                irp_id,
                identity: busy.identity,
                owner: busy.owner,
                attempt: busy.next_attempt,
                consumed: false,
            },
            waiters,
        };
        let busy = self.slots[slot].as_mut().unwrap().busy.as_mut().unwrap();
        busy.phase = PendingFileBusyPhase::Waking {
            attempt: busy.next_attempt,
            waiters,
        };
        busy.next_attempt = next;
        Ok(ticket)
    }

    /// Failure retains wake work only; the successful release receipt can never be rolled back.
    pub fn record_busy_wake(
        &mut self,
        ticket: &mut PendingFileBusyWakeAttempt,
        result: Result<(), u32>,
    ) -> Result<u16, PendingFileBusyError> {
        let busy = self.busy_for_attempt(&ticket.attempt)?;
        if busy.phase
            != (PendingFileBusyPhase::Waking {
                attempt: ticket.attempt.attempt,
                waiters: ticket.waiters,
            })
        {
            return Err(PendingFileBusyError::InvalidPhase);
        }
        let pending = self.slots[ticket.attempt.slot].as_mut().unwrap();
        pending.busy.as_mut().unwrap().phase = match result {
            Ok(()) => PendingFileBusyPhase::Settled {
                waiters: ticket.waiters,
            },
            Err(status) => PendingFileBusyPhase::WakeReady {
                waiters: ticket.waiters,
                last_error: Some(status),
            },
        };
        ticket.attempt.consumed = true;
        Ok(pending.delivery_state)
    }
}

#[cfg(test)]
#[path = "busy/tests.rs"]
mod tests;
