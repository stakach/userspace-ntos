//! The last dispatcher wait a provider lane issued, as the lane itself recorded it.
//!
//! Evidence only. The lane writes its own page without synchronization and root copies the
//! value into a census. It names where a lane that stopped talking to root last blocked; it is
//! never authority for a wait, a resume or a release.

/// The kernel primitive that issued the wait.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitPrimitive {
    WaitForSingleObject = 1,
    WaitForMultipleObjects = 2,
    AcquireResource = 3,
    DelayExecutionThread = 4,
    AcquireFastMutex = 5,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderLaneStampPhase {
    /// The lane sent the wait request and is, or was, parked in its rendezvous.
    Submitted = 1,
    /// The wait result was delivered and the lane is executing again.
    Resumed = 2,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLaneStamp {
    pub phase: u32,
    pub primitive: u32,
    pub wait_id: u64,
    /// How many stamps this lane has recorded, so an unchanged census row is recognisable.
    pub sequence: u64,
}

impl ProviderLaneStamp {
    pub const EMPTY: Self = Self { phase: 0, primitive: 0, wait_id: 0, sequence: 0 };

    /// The stamp that follows `self` on the same lane.
    pub const fn next(
        self,
        phase: ProviderLaneStampPhase,
        primitive: ProviderWaitPrimitive,
        wait_id: u64,
    ) -> Self {
        Self {
            phase: phase as u32,
            primitive: primitive as u32,
            wait_id,
            sequence: self.sequence.wrapping_add(1),
        }
    }

    pub const fn phase_name(self) -> &'static str {
        match self.phase {
            0 => "none",
            1 => "wait-submitted",
            2 => "wait-resumed",
            _ => "invalid",
        }
    }

    pub const fn primitive_name(self) -> &'static str {
        match self.primitive {
            0 => "none",
            1 => "KeWaitForSingleObject",
            2 => "KeWaitForMultipleObjects",
            3 => "ExAcquireResourceLite",
            4 => "KeDelayExecutionThread",
            5 => "ExAcquireFastMutex",
            _ => "invalid",
        }
    }
}

const _: () = assert!(core::mem::size_of::<ProviderLaneStamp>() == 24);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_stamp_replaces_the_previous_one_and_advances_the_sequence() {
        let submitted = ProviderLaneStamp::EMPTY.next(
            ProviderLaneStampPhase::Submitted, ProviderWaitPrimitive::DelayExecutionThread, 0x1b7e);
        assert_eq!(submitted.phase_name(), "wait-submitted");
        assert_eq!(submitted.primitive_name(), "KeDelayExecutionThread");
        assert_eq!((submitted.wait_id, submitted.sequence), (0x1b7e, 1));
        let resumed = submitted.next(
            ProviderLaneStampPhase::Resumed, ProviderWaitPrimitive::DelayExecutionThread, 0x1b7e);
        assert_eq!(resumed.phase_name(), "wait-resumed");
        assert_eq!((resumed.wait_id, resumed.sequence), (0x1b7e, 2));
    }

    #[test]
    fn an_unwritten_or_corrupt_stamp_is_named_as_such() {
        assert_eq!(ProviderLaneStamp::EMPTY.phase_name(), "none");
        assert_eq!(ProviderLaneStamp::EMPTY.primitive_name(), "none");
        let corrupt = ProviderLaneStamp { phase: 9, primitive: 9, ..ProviderLaneStamp::EMPTY };
        assert_eq!((corrupt.phase_name(), corrupt.primitive_name()), ("invalid", "invalid"));
        assert_eq!(crate::ProviderWaitSharedPage::empty().stamp, ProviderLaneStamp::EMPTY);
    }
}
