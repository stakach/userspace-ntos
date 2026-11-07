//! Exact page progress for an owned virtual-memory lock request.

use crate::{VmResidencyRangePlan, PAGE_SIZE};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Phase<Source, Irp> {
    Ready,
    Pending { source: Source, irp: Irp, acknowledged: bool, cancel_requested: bool },
    Complete,
    Cancelled,
    Quarantined,
}

/// A residency traversal that cannot publish the lock while a page read is pending.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmLockPageContinuation<Owner, Source, Irp> {
    owner: Owner,
    range: VmResidencyRangePlan,
    page: u64,
    phase: Phase<Source, Irp>,
}

impl<Owner: Copy + Eq, Source: Copy + Eq, Irp: Copy + Eq>
    VmLockPageContinuation<Owner, Source, Irp>
{
    pub fn new(owner: Owner, range: VmResidencyRangePlan) -> Self {
        Self { owner, range, page: range.base, phase: Phase::Ready }
    }

    pub fn next_page(&self, owner: Owner) -> Option<u64> {
        (self.owner == owner && matches!(self.phase, Phase::Ready)).then_some(self.page)
    }

    fn advance(&mut self) {
        self.page += PAGE_SIZE;
        self.phase = if self.page == self.range.base + self.range.size {
            Phase::Complete
        } else { Phase::Ready };
    }

    pub fn mark_inline_resident(&mut self, owner: Owner, page: u64) -> bool {
        if owner != self.owner || page != self.page || !matches!(self.phase, Phase::Ready) {
            return false;
        }
        self.advance();
        true
    }

    pub fn begin_pending(&mut self, owner: Owner, page: u64, source: Source, irp: Irp) -> bool {
        if owner != self.owner || page != self.page || !matches!(self.phase, Phase::Ready) {
            return false;
        }
        self.phase = Phase::Pending { source, irp, acknowledged: false, cancel_requested: false };
        true
    }

    pub fn acknowledge_pending(&mut self, owner: Owner, page: u64, source: Source, irp: Irp) -> bool {
        if owner != self.owner || page != self.page { return false; }
        let Phase::Pending { source: expected, irp: expected_irp, acknowledged, .. } =
            &mut self.phase else { return false; };
        if *expected != source || *expected_irp != irp || *acknowledged { return false; }
        *acknowledged = true;
        true
    }

    pub fn mark_pending_resident(&mut self, owner: Owner, page: u64, source: Source, irp: Irp) -> bool {
        if owner != self.owner || page != self.page { return false; }
        let Phase::Pending { source: expected, irp: expected_irp, acknowledged, cancel_requested } =
            self.phase else { return false; };
        if expected != source || expected_irp != irp || !acknowledged || cancel_requested { return false; }
        self.advance();
        true
    }

    pub fn request_cancel(&mut self, owner: Owner) -> bool {
        if owner != self.owner { return false; }
        match &mut self.phase {
            Phase::Ready => { self.phase = Phase::Cancelled; true }
            Phase::Pending { cancel_requested, .. } if !*cancel_requested => {
                *cancel_requested = true; true
            }
            _ => false,
        }
    }

    pub fn retire_cancelled_pending(&mut self, owner: Owner, page: u64, source: Source, irp: Irp) -> bool {
        if owner != self.owner || page != self.page { return false; }
        let Phase::Pending { source: expected, irp: expected_irp, acknowledged: true,
            cancel_requested: true } = self.phase else { return false; };
        if expected != source || expected_irp != irp { return false; }
        self.phase = Phase::Cancelled;
        true
    }

    pub fn quarantine(&mut self, owner: Owner, page: u64, source: Source, irp: Irp) -> bool {
        if owner != self.owner || page != self.page { return false; }
        let Phase::Pending { source: expected, irp: expected_irp, .. } = self.phase else { return false; };
        if expected != source || expected_irp != irp { return false; }
        self.phase = Phase::Quarantined;
        true
    }

    pub fn ready_to_commit(&self, owner: Owner) -> bool {
        owner == self.owner && matches!(self.phase, Phase::Complete)
    }
}
