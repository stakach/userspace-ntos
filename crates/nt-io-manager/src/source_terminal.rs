//! Two-phase source completion. Publication is not permission to release pins.

/// Private terminal IPC result: no origin resources were extracted and no payload was written.
pub const TERMINAL_NOT_READY: i32 = 0xc0e9_0001u32 as i32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalDelivery { Inline = 1, Pending = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginCallPhase { Calling, Armed(u64), Indeterminate }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalAdmission { Ready, NotReady, Rejected }

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
