//! Exact primary-process activation after a required shared page is installed.
//!
//! Native cap ownership stays with the executive. This value-only state admits
//! one retry after a definitive failure and never replays an uncertain effect.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AliasRetryDisposition { Retry, Retain }

/// Only exhaustion of the committed-range table can be retried without a
/// change in layout. A conflict or invalid range needs a corrected owner.
pub const fn classify_alias_registration_status(status: u32) -> AliasRetryDisposition {
    if status == nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32 {
        AliasRetryDisposition::Retry
    } else {
        AliasRetryDisposition::Retain
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimaryAliasOwner {
    pub process_index: usize,
    pub process_generation: u64,
    pub tcb: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimaryAliasPhase {
    Ready,
    RetryAt(u64),
    ParkedUncertain,
    Started,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimaryAliasActivation {
    owner: PrimaryAliasOwner,
    phase: PrimaryAliasPhase,
}

impl PrimaryAliasActivation {
    pub const fn new(owner: PrimaryAliasOwner) -> Option<Self> {
        if owner.process_generation == 0 || owner.tcb == 0 { return None; }
        Some(Self { owner, phase: PrimaryAliasPhase::Ready })
    }

    pub const fn owner(&self) -> PrimaryAliasOwner { self.owner }
    pub const fn phase(&self) -> PrimaryAliasPhase { self.phase }

    pub const fn ready(&self, owner: PrimaryAliasOwner) -> bool {
        self.owner.process_index == owner.process_index
            && self.owner.process_generation == owner.process_generation
            && self.owner.tcb == owner.tcb
            && matches!(self.phase, PrimaryAliasPhase::Ready)
    }

    pub const fn next_deadline(&self) -> Option<u64> {
        match self.phase {
            PrimaryAliasPhase::RetryAt(deadline) => Some(deadline),
            _ => None,
        }
    }

    /// A known failed effect may be attempted once after a positive delay.
    pub fn fail_definitive(&mut self, owner: PrimaryAliasOwner, now: u64,
        delay_100ns: u64) -> Option<u64> {
        if !self.ready(owner) || delay_100ns == 0 { return None; }
        let deadline = now.saturating_add(delay_100ns);
        self.phase = PrimaryAliasPhase::RetryAt(deadline);
        Some(deadline)
    }

    /// Admit the exact owner for one attempt when its retained deadline is due.
    pub fn wake_due(&mut self, owner: PrimaryAliasOwner, now: u64) -> bool {
        if self.owner != owner { return false; }
        let PrimaryAliasPhase::RetryAt(deadline) = self.phase else { return false; };
        if now < deadline { return false; }
        self.phase = PrimaryAliasPhase::Ready;
        true
    }

    /// An uncertain native effect parks this activation without a replay path.
    pub fn fail_uncertain(&mut self, owner: PrimaryAliasOwner) -> bool {
        if !self.ready(owner) { return false; }
        self.phase = PrimaryAliasPhase::ParkedUncertain;
        true
    }

    /// Starting the primary is terminal for this exact owner.
    pub fn start(&mut self, owner: PrimaryAliasOwner) -> bool {
        if !self.ready(owner) { return false; }
        self.phase = PrimaryAliasPhase::Started;
        true
    }
}
