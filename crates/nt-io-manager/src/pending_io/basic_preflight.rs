//! Retained FileBasic SET admission while a preceding volume baseline is being published.
//! This is an owner correlation, not a snapshot durability proof or WAL append authority.

use super::{
    PendingFileIoIdentity, PendingFileIoOperation, PendingFileIoTable, PendingOwnedInline,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BaselinePhase {
    Ready { next_attempt: u64 },
    InFlight { attempt: u64, next_attempt: u64 },
    Observed { published_epoch: u64 },
    Uncertain { attempt: u64 },
}

/// A parked Basic SET retains File identity, Busy and Reply while earlier unjournaled work drains.
/// The native File reference, prepared metadata and physical snapshot reserve belong to a
/// separate move-only owner. An observed epoch never authorizes a WAL marker without its lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingOwnedBasicPreflight {
    required_epoch: u64,
    phase: BaselinePhase,
}

impl PendingOwnedBasicPreflight {
    pub const fn new(required_epoch: u64) -> Self {
        Self {
            required_epoch,
            phase: BaselinePhase::Ready { next_attempt: 1 },
        }
    }

    pub const fn required_epoch(self) -> u64 {
        self.required_epoch
    }
}

/// Correlates one baseline attempt to an exact pending row generation. It carries no storage
/// capability. A physical publication result must be obtained by the caller under its reserve.
#[derive(Debug, PartialEq, Eq)]
pub struct PendingBasicBaselineTicket {
    identity: PendingFileIoIdentity,
    irp_id: u64,
    attempt: u64,
    consumed: bool,
}

impl PendingFileIoTable {
    /// Only a Ready row has no entered baseline I/O. Cancellation of an in-flight or uncertain
    /// attempt must wait for its exact physical owner instead of manufacturing a terminal result.
    pub fn cancel_unentered_owned_basic_exact(
        &mut self,
        identity: PendingFileIoIdentity,
        irp_id: u64,
    ) -> Option<()> {
        let pending = self.get_exact(identity)?;
        if pending.irp_id != irp_id
            || pending.delivery_state != 0
            || self.apc_owned_slot(identity.slot)
            || self.delivery_attempts[identity.slot] != 0
        {
            return None;
        }
        let PendingFileIoOperation::OwnedBasicPreflight(basic) = pending.operation else {
            return None;
        };
        if !matches!(basic.phase, BaselinePhase::Ready { .. }) {
            return None;
        }
        let row = self.slots[identity.slot].as_mut()?;
        row.operation = PendingFileIoOperation::OwnedInline(PendingOwnedInline {
            status: nt_status::NtStatus::CANCELLED.raw() as u32,
            information: 0,
        });
        Some(())
    }

    /// Record ownership before entering any checkpoint/fold I/O. A BUSY refusal returns the row
    /// to Ready; entered or uncertain I/O retains the same ticket and forbids replay.
    pub fn begin_owned_basic_baseline_exact(
        &mut self,
        identity: PendingFileIoIdentity,
        irp_id: u64,
    ) -> Option<PendingBasicBaselineTicket> {
        let pending = self.get_exact(identity)?;
        if pending.irp_id != irp_id
            || pending.delivery_state != 0
            || pending.consumer_abandoned
            || self.apc_owned_slot(identity.slot)
            || self.delivery_attempts[identity.slot] != 0
        {
            return None;
        }
        let PendingFileIoOperation::OwnedBasicPreflight(mut basic) = pending.operation else {
            return None;
        };
        let BaselinePhase::Ready { next_attempt } = basic.phase else {
            return None;
        };
        let following = next_attempt.checked_add(1)?;
        basic.phase = BaselinePhase::InFlight {
            attempt: next_attempt,
            next_attempt: following,
        };
        self.slots[identity.slot].as_mut()?.operation =
            PendingFileIoOperation::OwnedBasicPreflight(basic);
        Some(PendingBasicBaselineTicket {
            identity,
            irp_id,
            attempt: next_attempt,
            consumed: false,
        })
    }

    fn basic_attempt(
        &self,
        ticket: &PendingBasicBaselineTicket,
    ) -> Option<PendingOwnedBasicPreflight> {
        if ticket.consumed {
            return None;
        }
        let pending = self.get_exact(ticket.identity)?;
        if pending.irp_id != ticket.irp_id || pending.delivery_state != 0 {
            return None;
        }
        let PendingFileIoOperation::OwnedBasicPreflight(basic) = pending.operation else {
            return None;
        };
        matches!(basic.phase, BaselinePhase::InFlight { attempt, .. }
            if attempt == ticket.attempt)
        .then_some(basic)
    }

    fn put_basic(
        &mut self,
        ticket: &mut PendingBasicBaselineTicket,
        basic: PendingOwnedBasicPreflight,
    ) -> Option<()> {
        self.slots
            .get_mut(ticket.identity.slot)?
            .as_mut()?
            .operation = PendingFileIoOperation::OwnedBasicPreflight(basic);
        ticket.consumed = true;
        Some(())
    }

    /// Definite pre-entry BUSY is retryable; a crossed or already consumed attempt is refused.
    pub fn record_owned_basic_baseline_busy(
        &mut self,
        ticket: &mut PendingBasicBaselineTicket,
    ) -> Option<()> {
        let mut basic = self.basic_attempt(ticket)?;
        let BaselinePhase::InFlight { next_attempt, .. } = basic.phase else {
            return None;
        };
        basic.phase = BaselinePhase::Ready { next_attempt };
        self.put_basic(ticket, basic)
    }

    /// Retain uncertain entered I/O indefinitely. Neither failure nor cancellation may cause a
    /// second attempt or synthesize an IOSB/Reply terminal result.
    pub fn record_owned_basic_baseline_uncertain(
        &mut self,
        ticket: &mut PendingBasicBaselineTicket,
    ) -> Option<()> {
        let mut basic = self.basic_attempt(ticket)?;
        basic.phase = BaselinePhase::Uncertain {
            attempt: ticket.attempt,
        };
        self.put_basic(ticket, basic)
    }

    /// Observe the matching publication epoch after the physical owner completed its work. This
    /// remains nonterminal and does not transfer the physical reserve or permit a WAL append.
    pub fn record_owned_basic_baseline_published(
        &mut self,
        ticket: &mut PendingBasicBaselineTicket,
        published_epoch: u64,
    ) -> Option<()> {
        let mut basic = self.basic_attempt(ticket)?;
        if published_epoch < basic.required_epoch {
            return None;
        }
        basic.phase = BaselinePhase::Observed { published_epoch };
        self.put_basic(ticket, basic)
    }
}
