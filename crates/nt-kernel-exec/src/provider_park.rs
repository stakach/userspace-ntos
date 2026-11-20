//! A provider lane that cannot continue safely, stopped where the root can see and own it (#394).
//!
//! The lane used to park by yielding forever. The root running it then saw only a lane that
//! never sent again, and stayed confined in its receive loop with nothing to attribute or act
//! on. Now the lane parks in an unreplied labelled Call naming its site. The root records it
//! here as a typed parked state and walls the pump, so the lane uses no processor and its Reply
//! is owned. The root can then wake it (reply; the fail-closed site parks again, as a new
//! generation) or tear it down (the record is taken and the caller suspends the lane).

pub use crate::provider_bugcheck::ProviderChannel;

pub const PARK_LABEL: u64 = 0x7e2;
/// Two words: the site's line and a stable identity of its file.
pub const PARK_MESSAGE_INFO: u64 = (PARK_LABEL << 12) | 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParkError {
    InvalidChannel,
    WrongSender,
    InvalidMessage,
    /// Every row holds a different parked lane.
    Full,
}

/// The site a lane parked at. Identity comes from the receiver's channel, never its words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParkSite {
    pub line: u32,
    pub file: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParkedLane {
    pub channel: ProviderChannel,
    pub site: ParkSite,
    /// How many times this lane has parked; a wake followed by a re-park is a new generation.
    pub generation: u64,
}

impl ParkSite {
    /// Accept only the exact park message from the retained channel's own sender.
    pub fn decode(
        channel: ProviderChannel,
        badge: u64,
        message_info: u64,
        words: [u64; 2],
    ) -> Result<Self, ParkError> {
        if channel.endpoint == 0 || channel.tcb == 0 || channel.vspace == 0
            || channel.reply_object == 0
        {
            return Err(ParkError::InvalidChannel);
        }
        if badge != channel.expected_badge { return Err(ParkError::WrongSender); }
        if message_info != PARK_MESSAGE_INFO || words[0] > u64::from(u32::MAX) {
            return Err(ParkError::InvalidMessage);
        }
        Ok(Self { line: words[0] as u32, file: words[1] })
    }
}

/// The root's parked lanes, one row per executor TCB.
pub struct ParkedLanes<const N: usize> {
    rows: [Option<ParkedLane>; N],
    /// Generations survive a wake, so a re-park is distinguishable from the first.
    generations: [(u64, u64); N],
}

impl<const N: usize> ParkedLanes<N> {
    pub const fn new() -> Self { Self { rows: [None; N], generations: [(0, 0); N] } }

    /// Record a lane that parked. It holds its Call unreplied; the row owns that Reply.
    pub fn record(&mut self, channel: ProviderChannel, site: ParkSite) -> Result<ParkedLane, ParkError> {
        if self.rows.iter().flatten().any(|row| row.channel.tcb == channel.tcb) {
            // A lane blocked in its park Call cannot send another without a wake.
            return Err(ParkError::InvalidMessage);
        }
        let generation = self.next_generation(channel.tcb).ok_or(ParkError::Full)?;
        let slot = self.rows.iter().position(Option::is_none).ok_or(ParkError::Full)?;
        let lane = ParkedLane { channel, site, generation };
        self.rows[slot] = Some(lane);
        Ok(lane)
    }

    fn next_generation(&mut self, tcb: u64) -> Option<u64> {
        if let Some(entry) = self.generations.iter_mut().find(|(owner, _)| *owner == tcb) {
            entry.1 += 1;
            return Some(entry.1);
        }
        let entry = self.generations.iter_mut().find(|(owner, _)| *owner == 0)?;
        *entry = (tcb, 1);
        Some(1)
    }

    pub fn parked(&self, tcb: u64) -> Option<ParkedLane> {
        self.rows.iter().flatten().copied().find(|row| row.channel.tcb == tcb)
    }

    pub fn len(&self) -> usize { self.rows.iter().flatten().count() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Release the lane's row to reply to it. A fail-closed site parks again on its own.
    pub fn wake(&mut self, tcb: u64) -> Option<ParkedLane> { self.take(tcb) }

    /// Take the lane's row for teardown; the caller suspends and retires the lane.
    pub fn tear_down(&mut self, tcb: u64) -> Option<ParkedLane> { self.take(tcb) }

    /// Every lane parked in one provider VSpace, for that provider's retirement.
    pub fn tear_down_vspace(&mut self, vspace: u64) -> impl Iterator<Item = ParkedLane> + '_ {
        self.rows.iter_mut().filter_map(move |row| {
            row.take_if(|lane| lane.channel.vspace == vspace)
        })
    }

    fn take(&mut self, tcb: u64) -> Option<ParkedLane> {
        self.rows.iter_mut().find_map(|row| row.take_if(|lane| lane.channel.tcb == tcb))
    }
}

impl<const N: usize> Default for ParkedLanes<N> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(tcb: u64, vspace: u64) -> ProviderChannel {
        ProviderChannel { endpoint: 9, tcb, vspace, reply_object: 11, expected_badge: 0x40 }
    }

    #[test]
    fn a_park_is_accepted_only_from_its_own_channel() {
        let ch = channel(5, 7);
        assert_eq!(ParkSite::decode(ch, 0x41, PARK_MESSAGE_INFO, [10, 3]), Err(ParkError::WrongSender));
        assert_eq!(ParkSite::decode(ch, 0x40, PARK_MESSAGE_INFO | 1, [10, 3]),
            Err(ParkError::InvalidMessage));
        assert_eq!(ParkSite::decode(ch, 0x40, PARK_MESSAGE_INFO, [u64::MAX, 3]),
            Err(ParkError::InvalidMessage));
        assert_eq!(ParkSite::decode(ProviderChannel { reply_object: 0, ..ch }, 0x40,
            PARK_MESSAGE_INFO, [10, 3]), Err(ParkError::InvalidChannel));
        assert_eq!(ParkSite::decode(ch, 0x40, PARK_MESSAGE_INFO, [10, 3]),
            Ok(ParkSite { line: 10, file: 3 }));
    }

    #[test]
    fn a_parked_lane_is_a_typed_state_the_root_owns() {
        let mut lanes = ParkedLanes::<4>::new();
        let site = ParkSite { line: 6747, file: 1 };
        let parked = lanes.record(channel(5, 7), site).unwrap();
        assert_eq!(parked.generation, 1);
        assert_eq!(lanes.parked(5), Some(parked), "the root can see which lane parked where");
        assert_eq!(lanes.record(channel(5, 7), site), Err(ParkError::InvalidMessage),
            "a lane blocked in its park Call cannot park twice");
    }

    #[test]
    fn a_woken_lane_that_parks_again_is_a_new_generation() {
        let mut lanes = ParkedLanes::<4>::new();
        let site = ParkSite { line: 1, file: 1 };
        lanes.record(channel(5, 7), site).unwrap();
        assert!(lanes.wake(5).is_some());
        assert_eq!(lanes.parked(5), None);
        assert_eq!(lanes.record(channel(5, 7), site).unwrap().generation, 2);
    }

    #[test]
    fn teardown_takes_the_lane_and_a_retired_vspace_takes_all_of_its_lanes() {
        let mut lanes = ParkedLanes::<4>::new();
        let site = ParkSite { line: 1, file: 1 };
        lanes.record(channel(5, 7), site).unwrap();
        lanes.record(channel(6, 7), site).unwrap();
        lanes.record(channel(8, 9), site).unwrap();
        assert_eq!(lanes.tear_down(8).map(|lane| lane.channel.tcb), Some(8));
        assert_eq!(lanes.tear_down(8), None, "a torn-down lane is never released twice");
        let retired: alloc::vec::Vec<u64> = lanes.tear_down_vspace(7)
            .map(|lane| lane.channel.tcb).collect();
        assert_eq!(retired, [5, 6]);
        assert!(lanes.is_empty());
    }

    #[test]
    fn a_full_table_refuses_instead_of_dropping_a_lane() {
        let mut lanes = ParkedLanes::<1>::new();
        let site = ParkSite { line: 1, file: 1 };
        lanes.record(channel(5, 7), site).unwrap();
        assert_eq!(lanes.record(channel(6, 7), site), Err(ParkError::Full));
        assert_eq!(lanes.parked(5).map(|lane| lane.channel.tcb), Some(5));
    }
}
