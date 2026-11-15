//! The handoff of one returned win32k pump to its retained owner.
//!
//! A provider lane has one outstanding suspension at a time, and the root learns of it from
//! the pump that just returned: either the dispatch issued a user callback, or it published
//! exactly one yield record (a receive boundary, a service wait, a provider wait or an LPC
//! wait). The record belongs to the dispatch that published it. A handoff admits only the
//! record of the dispatch it is handing off, against that dispatch's caller.
//!
//! A record left behind by another dispatch is not this caller's obligation. Admitting it
//! would park the wrong Reply under a foreign continuation, so it is fenced: taken out of the
//! pending set, never admitted and never replayed. Two suspensions claimed by the same
//! dispatch cannot both be true, so neither is acted on and that dispatch is fenced.

/// The yield records a fresh dispatch can publish for its handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YieldKind {
    Receive,
    ServiceWait,
    ProviderWait,
    LpcWait,
}

pub const YIELD_KINDS: usize = 4;

impl YieldKind {
    pub const ALL: [Self; YIELD_KINDS] =
        [Self::Receive, Self::ServiceWait, Self::ProviderWait, Self::LpcWait];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::ServiceWait => "service-wait",
            Self::ProviderWait => "provider-wait",
            Self::LpcWait => "lpc-wait",
        }
    }

    const fn slot(self) -> usize {
        match self {
            Self::Receive => 0,
            Self::ServiceWait => 1,
            Self::ProviderWait => 2,
            Self::LpcWait => 3,
        }
    }
}

/// One published record and the dispatch that published it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedYield {
    pub kind: YieldKind,
    pub dispatch_id: u64,
}

/// What the root can see when a pump returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffObservation {
    /// The dispatch being handed off. `None` when the caller ran a provider callout whose
    /// dispatch it cannot name; ownership of a record is then not checkable.
    pub current_dispatch: Option<u64>,
    /// The returned pump left its lane suspended in a user callback.
    pub callback_suspended: bool,
    published: [Option<u64>; YIELD_KINDS],
}

impl HandoffObservation {
    pub const fn new(current_dispatch: Option<u64>, callback_suspended: bool) -> Self {
        Self { current_dispatch, callback_suspended, published: [None; YIELD_KINDS] }
    }

    /// Record that a yield of `kind` is pending, published by `dispatch_id`.
    pub const fn with(mut self, kind: YieldKind, dispatch_id: u64) -> Self {
        self.published[kind.slot()] = Some(dispatch_id);
        self
    }
}

/// Why a record, or the dispatch being handed off, was fenced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffViolation {
    /// The record was published by a dispatch other than the one being handed off.
    ForeignRecord,
    /// The dispatch being handed off claims more than one suspension.
    DoubleSuspension,
}

impl HandoffViolation {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ForeignRecord => "foreign-yield-record",
            Self::DoubleSuspension => "double-suspension",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FencedYield {
    pub record: PublishedYield,
    pub violation: HandoffViolation,
}

/// What the handoff does with the observation. Every pending record is either the single
/// admitted one or fenced, so no record outlives the handoff that saw it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffPlan {
    /// The current dispatch's own yield record, to admit against its caller.
    pub admit: Option<YieldKind>,
    /// The current dispatch's user callback may be delivered to its client.
    pub callback: bool,
    /// The current dispatch claimed more than one suspension: it gets neither a result nor
    /// a continuation, and its caller's Reply is retained unanswered.
    pub current_fenced: bool,
    fenced: [Option<FencedYield>; YIELD_KINDS],
}

impl HandoffPlan {
    /// Records to take out of the pending set without admitting them.
    pub fn fenced(&self) -> impl Iterator<Item = FencedYield> + '_ {
        self.fenced.iter().flatten().copied()
    }
}

pub fn plan(observation: HandoffObservation) -> HandoffPlan {
    let mut fenced = [None; YIELD_KINDS];
    let mut own = [None; YIELD_KINDS];
    let mut own_count = 0usize;
    for kind in YieldKind::ALL {
        let Some(dispatch_id) = observation.published[kind.slot()] else { continue };
        let record = PublishedYield { kind, dispatch_id };
        if observation.current_dispatch.is_some_and(|current| current != dispatch_id) {
            fenced[kind.slot()] =
                Some(FencedYield { record, violation: HandoffViolation::ForeignRecord });
        } else {
            own[kind.slot()] = Some(record);
            own_count += 1;
        }
    }
    let suspensions = own_count + usize::from(observation.callback_suspended);
    if suspensions > 1 {
        for record in own.into_iter().flatten() {
            fenced[record.kind.slot()] =
                Some(FencedYield { record, violation: HandoffViolation::DoubleSuspension });
        }
        return HandoffPlan { admit: None, callback: false, current_fenced: true, fenced };
    }
    HandoffPlan {
        admit: own.into_iter().flatten().next().map(|record| record.kind),
        callback: observation.callback_suspended,
        current_fenced: false,
        fenced,
    }
}
