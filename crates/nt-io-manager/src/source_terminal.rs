//! Two-phase source completion. Publication is not permission to release pins.

#[cfg(test)]
#[path = "source_terminal_commit_progress_tests.rs"]
mod commit_progress_tests;

/// Private terminal IPC result: no origin resources were extracted and no payload was written.
pub const TERMINAL_NOT_READY: i32 = 0xc0e9_0001u32 as i32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalDelivery { Inline = 1, Pending = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginCallPhase { Calling, Armed(u64), Indeterminate }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalAdmission { Ready, NotReady, Rejected }

/// Local progress of one retained origin command. The native owner keeps its exact packet,
/// immutable command snapshot and signal sequence until packet retirement succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginCommitPhase {
    CaptureBefore,
    PublishCommand,
    DispatchOrigin,
    ReadAck,
    RetirePacket,
    Complete,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginCommitObservation {
    BusyNoEffect,
    CapturedBefore,
    CommandPublished,
    NotEntered,
    ReturnedSuccess,
    Uncertain,
    AckValidated,
    InvalidAck,
    PacketRetired,
}

impl OriginCommitPhase {
    /// ACK validation uses the existing exact identity and immutable packet contracts; this
    /// state machine orders effects but does not mint authority from a successful IPC reply.
    pub fn observe(self, observation: OriginCommitObservation) -> Option<Self> {
        use OriginCommitObservation as Event;
        match (self, observation) {
            (Self::CaptureBefore | Self::PublishCommand | Self::ReadAck | Self::RetirePacket,
                Event::BusyNoEffect) => Some(self),
            (Self::CaptureBefore, Event::CapturedBefore) => Some(Self::PublishCommand),
            (Self::PublishCommand, Event::CommandPublished) => Some(Self::DispatchOrigin),
            (Self::DispatchOrigin, Event::NotEntered) => Some(Self::DispatchOrigin),
            (Self::DispatchOrigin, Event::ReturnedSuccess) => Some(Self::ReadAck),
            (Self::DispatchOrigin, Event::Uncertain) | (Self::ReadAck, Event::InvalidAck) =>
                Some(Self::Indeterminate),
            (Self::ReadAck, Event::AckValidated) => Some(Self::RetirePacket),
            (Self::RetirePacket, Event::PacketRetired) => Some(Self::Complete),
            _ => None,
        }
    }
}

impl TerminalDelivery {
    pub fn decode(raw: u32) -> Option<Self> {
        match raw { 1 => Some(Self::Inline), 2 => Some(Self::Pending), _ => None }
    }

    pub fn admit(self, phase: OriginCallPhase, token: u64) -> TerminalAdmission {
        if token == 0 { return TerminalAdmission::Rejected; }
        match (self, phase) {
            (Self::Inline, OriginCallPhase::Calling) => TerminalAdmission::Ready,
            (Self::Pending, OriginCallPhase::Calling) => TerminalAdmission::NotReady,
            (Self::Pending, OriginCallPhase::Armed(found)) if found == token => TerminalAdmission::Ready,
            _ => TerminalAdmission::Rejected,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalPublication {
    Published,
    Failed(u32),
    CommitRequested,
    Committed,
    DiscardRequested,
    Discarded,
}

impl TerminalPublication {
    pub fn decode(stage: u32, status: u32) -> Option<Self> {
        match (stage, status) {
            (1, 0) => Some(Self::Published),
            (2, status) if status != 0 => Some(Self::Failed(status)),
            (3, 0) => Some(Self::CommitRequested),
            (4, 0) => Some(Self::Committed),
            (5, 0) => Some(Self::DiscardRequested),
            (6, 0) => Some(Self::Discarded),
            _ => None,
        }
    }

    pub fn words(self) -> (u32, u32) {
        match self {
            Self::Published => (1, 0),
            Self::Failed(status) => (2, status),
            Self::CommitRequested => (3, 0),
            Self::Committed => (4, 0),
            Self::DiscardRequested => (5, 0),
            Self::Discarded => (6, 0),
        }
    }

    /// Reject duplicates and phase skips; native uncertainty is handled by the owner.
    pub fn can_follow(self, previous: Option<Self>) -> bool {
        matches!(
            (previous, self),
            (None, Self::Published | Self::DiscardRequested)
                | (None, Self::Failed(1..=u32::MAX))
                | (Some(Self::Published), Self::CommitRequested)
                | (Some(Self::Published), Self::DiscardRequested)
                | (Some(Self::CommitRequested), Self::Committed)
                | (Some(Self::DiscardRequested), Self::Discarded)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalPacketIdentity {
    pub address: u64,
    pub length: u64,
    pub allocation_id: u64,
    pub allocation_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparedTerminal {
    pub packet: TerminalPacketIdentity,
    pub token: u64,
    pub status: u32,
    pub information: u64,
    pub inline: bool,
}

/// The retained source Work row, including its physical provider route and allocation epoch.
/// A Vec slot or packet address alone can be reused and is not a child identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NestedSourceWorkKey<R, D> {
    pub route: R,
    pub dispatch: D,
    pub reply: u64,
    pub nonce: u64,
    pub token: u64,
    pub source_address: u64,
    pub source_ticket: u64,
    pub source_generation: u64,
}

impl<R, D> NestedSourceWorkKey<R, D> {
    pub fn new(
        route: R, dispatch: D, reply: u64, nonce: u64, token: u64,
        source_address: u64, source_ticket: u64, source_generation: u64,
    ) -> Option<Self> {
        if reply == 0 || nonce == 0 || token == 0 || source_address == 0
            || source_ticket == 0 || source_generation == 0
        { return None; }
        Some(Self { route, dispatch, reply, nonce, token, source_address,
            source_ticket, source_generation })
    }
}

/// Move-only preselection. The native owner must redrive this exact row after parking its parent.
#[must_use = "redrive only the exact retained source child or keep the selection"]
pub struct NestedSourceSelection<R, D> {
    key: NestedSourceWorkKey<R, D>,
}

impl<R: Copy + Eq, D: Copy + Eq> NestedSourceSelection<R, D> {
    pub fn new(key: NestedSourceWorkKey<R, D>) -> Self { Self { key } }
    pub fn key(&self) -> NestedSourceWorkKey<R, D> { self.key }
    pub fn matches(&self, actual: NestedSourceWorkKey<R, D>) -> bool { self.key == actual }
}

/// This describes only native dispatch entry. `ReturnedSuccessNeedsAck` is not a terminal
/// completion receipt; the source owner must validate the exact packet ACK separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NestedSourceDispatchEffect {
    NotEntered,
    ReturnedNotReady,
    ReturnedSuccessNeedsAck,
    Indeterminate,
}

impl NestedSourceDispatchEffect {
    pub fn from_returned(status: i32) -> Self {
        match status {
            TERMINAL_NOT_READY => Self::ReturnedNotReady,
            0 => Self::ReturnedSuccessNeedsAck,
            _ => Self::Indeterminate,
        }
    }
}

/// A source terminal pump return. A retained physical owner has no status that the work
/// owner may classify as retryable; its exact ticket must move to the work record.
#[derive(Debug)]
pub enum SourceTerminalDispatch<Ticket> {
    NotEntered(i32),
    Indeterminate(i32),
    Returned(i32),
    Retained(Ticket),
}

impl<Ticket> SourceTerminalDispatch<Ticket> {
    pub fn into_effect(self) -> Result<NestedSourceDispatchEffect, Ticket> {
        match self {
            Self::NotEntered(_) => Ok(NestedSourceDispatchEffect::NotEntered),
            Self::Indeterminate(_) => Ok(NestedSourceDispatchEffect::Indeterminate),
            Self::Returned(status) => Ok(NestedSourceDispatchEffect::from_returned(status)),
            Self::Retained(ticket) => Err(ticket),
        }
    }
}

/// The source Work owns an uncertain physical return in its preparation state. Once retained,
/// neither dispatch retry nor packet retirement can run, and a second return cannot replace it.
pub enum TerminalPreparePhase<Owner> {
    Publish,
    Dispatch,
    ReadAck,
    Published,
    Indeterminate,
    Retained(Owner),
}

impl<Owner> TerminalPreparePhase<Owner> {
    pub fn is_publish(&self) -> bool { matches!(self, Self::Publish) }
    pub fn needs_lane(&self) -> bool { matches!(self, Self::Dispatch) }
    pub fn is_read_ack(&self) -> bool { matches!(self, Self::ReadAck) }
    pub fn can_retire(&self) -> bool { matches!(self, Self::Published) }
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, Self::Indeterminate | Self::Retained(_))
    }
    pub fn retained(&self) -> Option<&Owner> {
        match self { Self::Retained(owner) => Some(owner), _ => None }
    }
    pub fn progress_code(&self) -> u64 {
        match self {
            Self::Publish => 0, Self::Dispatch => 1, Self::ReadAck => 2,
            Self::Published => 3, Self::Indeterminate => 4, Self::Retained(_) => 5,
        }
    }
}

impl PreparedTerminal {
    pub fn matches(
        self,
        packet: TerminalPacketIdentity,
        token: u64,
        status: u32,
        information: u64,
    ) -> bool {
        self.packet == packet
            && self.token == token
            && self.status == status
            && self.information == information
    }
}

pub fn same_terminal_packet(prepared: &[u8], current: &[u8], phase_offset: usize) -> bool {
    let Some(end) = phase_offset.checked_add(16) else {
        return false;
    };
    prepared.len() == current.len()
        && end <= current.len()
        && prepared[..phase_offset] == current[..phase_offset]
        && prepared[end..] == current[end..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_reply_acknowledgement_is_not_origin_acceptance() {
        assert_eq!(TerminalDelivery::Pending.admit(OriginCallPhase::Calling, 41), TerminalAdmission::NotReady);
        assert_eq!(TerminalDelivery::Inline.admit(OriginCallPhase::Calling, 41), TerminalAdmission::Ready);
        assert_eq!(TerminalDelivery::Pending.admit(OriginCallPhase::Armed(41), 41), TerminalAdmission::Ready);
        assert_eq!(TerminalDelivery::Pending.admit(OriginCallPhase::Armed(42), 41), TerminalAdmission::Rejected);
        assert_eq!(TerminalDelivery::Inline.admit(OriginCallPhase::Armed(41), 41), TerminalAdmission::Rejected);
        assert_eq!(TerminalDelivery::Pending.admit(OriginCallPhase::Indeterminate, 41), TerminalAdmission::Rejected);
        assert_eq!(TerminalDelivery::Pending.admit(OriginCallPhase::Calling, 0), TerminalAdmission::Rejected);
    }

    #[test]
    fn terminal_delivery_is_part_of_immutable_packet_identity() {
        let before = [0u8; 40];
        let mut changed = before;
        changed[4] = 1;
        assert!(!same_terminal_packet(&before, &changed, 16));
        assert_eq!(TerminalDelivery::decode(0), None);
        assert_eq!(TerminalDelivery::decode(1), Some(TerminalDelivery::Inline));
        assert_eq!(TerminalDelivery::decode(2), Some(TerminalDelivery::Pending));
    }

    #[test]
    fn publication_requires_a_second_authenticated_commit() {
        assert!(TerminalPublication::Published.can_follow(None));
        assert!(!TerminalPublication::Committed.can_follow(None));
        assert!(!TerminalPublication::Committed.can_follow(Some(TerminalPublication::Published)));
        assert!(
            TerminalPublication::CommitRequested.can_follow(Some(TerminalPublication::Published))
        );
        assert!(
            TerminalPublication::Committed.can_follow(Some(TerminalPublication::CommitRequested))
        );
        assert!(!TerminalPublication::CommitRequested
            .can_follow(Some(TerminalPublication::CommitRequested)));
        assert!(!TerminalPublication::Committed.can_follow(Some(TerminalPublication::Committed)));
    }

    #[test]
    fn stopped_owner_discard_has_no_publication_or_signal_phase() {
        assert!(TerminalPublication::DiscardRequested.can_follow(None));
        assert!(
            TerminalPublication::Discarded.can_follow(Some(TerminalPublication::DiscardRequested))
        );
        assert!(!TerminalPublication::Discarded.can_follow(Some(TerminalPublication::Published)));
        assert_eq!(TerminalPublication::decode(2, 0), None);
    }

    #[test]
    fn nested_source_selection_keeps_exact_child_across_cursor_changes() {
        let first = NestedSourceWorkKey::new(11u64, 21u64, 31, 41, 51, 61, 71, 81).unwrap();
        let reused_row = NestedSourceWorkKey::new(11u64, 21u64, 31, 41, 51, 61, 71, 82).unwrap();
        let other_child = NestedSourceWorkKey::new(12u64, 22u64, 32, 42, 52, 62, 72, 83).unwrap();
        let selected = NestedSourceSelection::new(first);
        assert!(selected.matches(first));
        assert!(!selected.matches(reused_row));
        assert!(!selected.matches(other_child));
        assert_eq!(selected.key(), first);
    }

    #[test]
    fn nested_source_dispatch_distinguishes_no_entry_returned_retry_and_uncertain() {
        assert_eq!(NestedSourceDispatchEffect::from_returned(TERMINAL_NOT_READY),
            NestedSourceDispatchEffect::ReturnedNotReady);
        assert_eq!(NestedSourceDispatchEffect::from_returned(0),
            NestedSourceDispatchEffect::ReturnedSuccessNeedsAck);
        assert_eq!(NestedSourceDispatchEffect::from_returned(0xc000_0001u32 as i32),
            NestedSourceDispatchEffect::Indeterminate);
        assert_ne!(NestedSourceDispatchEffect::NotEntered,
            NestedSourceDispatchEffect::ReturnedNotReady);
        assert!(NestedSourceWorkKey::new(11u64, 21u64, 0, 41, 51, 61, 71, 81).is_none());
    }

    #[test]
    fn retained_source_dispatch_moves_exact_owner_without_retry_classification() {
        #[derive(Debug)]
        struct Ticket { attempt: u64 }
        let ticket = Ticket { attempt: 37 };
        let observed = SourceTerminalDispatch::Retained(ticket);
        let retained = observed.into_effect().expect_err("retained pump has no status effect");
        assert_eq!(retained.attempt, 37);
        assert_eq!(SourceTerminalDispatch::<Ticket>::NotEntered(0xc000_0001u32 as i32)
            .into_effect().unwrap(), NestedSourceDispatchEffect::NotEntered);
        assert_eq!(SourceTerminalDispatch::<Ticket>::Returned(TERMINAL_NOT_READY)
            .into_effect().unwrap(), NestedSourceDispatchEffect::ReturnedNotReady);
    }

    #[test]
    fn source_work_retains_uncertain_return_and_blocks_retry_and_retirement() {
        let owner = alloc::boxed::Box::new(0xabcdu64);
        let address = &*owner as *const u64;
        let phase = TerminalPreparePhase::Retained(owner);
        assert!(phase.is_indeterminate());
        assert!(!phase.needs_lane());
        assert!(!phase.can_retire());
        assert!(core::ptr::eq(&**phase.retained().unwrap(), address));
        assert!(core::ptr::eq(&**phase.retained().unwrap(), address));
    }

    #[test]
    fn commit_binds_physical_packet_and_terminal_identity() {
        let packet = TerminalPacketIdentity {
            address: 1,
            length: 128,
            allocation_id: 3,
            allocation_generation: 4,
        };
        let prepared = PreparedTerminal {
            packet,
            token: 5,
            status: 0,
            information: 8,
            inline: false,
        };
        assert!(prepared.matches(packet, 5, 0, 8));
        assert!(!prepared.matches(
            TerminalPacketIdentity {
                allocation_generation: 9,
                ..packet
            },
            5,
            0,
            8
        ));
        assert!(!prepared.matches(packet, 6, 0, 8));
        assert!(!prepared.matches(packet, 5, 0, 9));
    }

    #[test]
    fn immutable_payload_must_match_and_phase_words_are_separate() {
        let before = [0u8; 32];
        let mut after = before;
        after[8] = 3;
        assert!(same_terminal_packet(&before, &after, 8));
        after[24] = 1;
        assert!(!same_terminal_packet(&before, &after, 8));
        assert!(!same_terminal_packet(&before, &after, 30));
    }
}
