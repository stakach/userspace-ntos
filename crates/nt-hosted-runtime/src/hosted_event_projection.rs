//! Identity for an Event body projected into one native driver VSpace.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedEventProjectionKey {
    domain_id: u64,
    domain_cookie: u64,
    pml4: u64,
    event_id: u64,
    body: u64,
    allocation_generation: u64,
}

impl HostedEventProjectionKey {
    pub const fn new(domain_id: u64, domain_cookie: u64, pml4: u64,
        event_id: u64, body: u64, allocation_generation: u64) -> Option<Self>
    {
        if domain_id == 0 || domain_cookie == 0 || pml4 == 0 || event_id == 0
            || body == 0 || allocation_generation == 0
        { return None; }
        Some(Self { domain_id, domain_cookie, pml4,
            event_id, body, allocation_generation })
    }

    pub const fn matches(self, domain_id: u64, domain_cookie: u64, pml4: u64,
        event_id: u64, body: u64, allocation_generation: u64) -> bool
    {
        self.domain_id == domain_id && self.domain_cookie == domain_cookie
            && self.pml4 == pml4 && self.event_id == event_id
            && self.body == body && self.allocation_generation == allocation_generation
    }
}

/// A body remains owned through projected waits and dereference receipts.
/// Native effects may retire storage only after all three counts reach zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedEventProjectionLifetime {
    references: u32,
    waits: u32,
    pending_acknowledgements: u32,
}

impl HostedEventProjectionLifetime {
    pub const fn new() -> Option<Self> {
        Some(Self { references: 1, waits: 0, pending_acknowledgements: 0 })
    }

    pub const fn references(self) -> u32 { self.references }
    pub const fn waits(self) -> u32 { self.waits }
    pub const fn pending_acknowledgements(self) -> u32 {
        self.pending_acknowledgements
    }
    pub const fn retirable(self) -> bool {
        self.references == 0 && self.waits == 0 && self.pending_acknowledgements == 0
    }

    pub fn retain_reference(&mut self) -> bool {
        if self.references == u32::MAX
            || (self.references == 0
                && (self.waits == 0 || self.pending_acknowledgements != 0))
        { return false; }
        self.references += 1;
        true
    }

    pub fn begin_dereference(&mut self) -> bool {
        if self.references == 0 || self.pending_acknowledgements == u32::MAX {
            return false;
        }
        self.references -= 1;
        self.pending_acknowledgements += 1;
        true
    }

    pub fn acknowledge_dereference(&mut self) -> bool {
        if self.pending_acknowledgements == 0 { return false; }
        self.pending_acknowledgements -= 1;
        true
    }

    /// Report the current count after this exact receipt, since other references may have
    /// changed between the original DEREFERENCE Reply and its acknowledgement.
    pub fn complete_dereference_ack(&mut self) -> Option<u32> {
        if !self.acknowledge_dereference() { return None; }
        Some(self.references)
    }

    pub fn retain_wait(&mut self) -> bool {
        if self.references == 0 || self.waits == u32::MAX { return false; }
        self.waits += 1;
        true
    }

    pub fn release_wait(&mut self) -> bool {
        if self.waits == 0 { return false; }
        self.waits -= 1;
        true
    }
}

/// A selected wait owns its Reply through a single send and exact ACK reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedEventWaitDelivery {
    phase: HostedEventWaitDeliveryPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostedEventWaitDeliveryPhase { Pending, Selected, ReplyEntered, Acknowledged, Cancelled }

impl HostedEventWaitDelivery {
    pub const fn new() -> Self {
        Self { phase: HostedEventWaitDeliveryPhase::Pending }
    }

    pub fn select(&mut self) -> bool {
        if self.phase != HostedEventWaitDeliveryPhase::Pending { return false; }
        self.phase = HostedEventWaitDeliveryPhase::Selected;
        true
    }

    pub fn enter_reply(&mut self) -> bool {
        if self.phase != HostedEventWaitDeliveryPhase::Selected { return false; }
        self.phase = HostedEventWaitDeliveryPhase::ReplyEntered;
        true
    }

    pub const fn reply_entered(self) -> bool {
        matches!(self.phase, HostedEventWaitDeliveryPhase::ReplyEntered)
    }

    pub fn reconcile(&mut self, acknowledged: bool) -> bool {
        if self.phase != HostedEventWaitDeliveryPhase::ReplyEntered || !acknowledged {
            return false;
        }
        self.phase = HostedEventWaitDeliveryPhase::Acknowledged;
        true
    }

    /// A sealed broker stop proves the component cannot use this projected body again.
    pub fn cancel(&mut self, broker_stopped: bool) -> bool {
        if !broker_stopped
            || !matches!(self.phase,
                HostedEventWaitDeliveryPhase::Selected | HostedEventWaitDeliveryPhase::ReplyEntered)
        { return false; }
        self.phase = HostedEventWaitDeliveryPhase::Cancelled;
        true
    }

    pub const fn retirable(self) -> bool {
        matches!(self.phase,
            HostedEventWaitDeliveryPhase::Acknowledged | HostedEventWaitDeliveryPhase::Cancelled)
    }
}
