use super::*;
use alloc::{collections::VecDeque, vec, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Cache,
    Reserve,
    Retype(u64),
    Recycle(u64),
    Unmap(u64),
    Zero(u64),
}

struct Io {
    calls: Vec<Call>,
    cached: VecDeque<u64>,
    next_slot: u64,
    failure: Option<(Call, u32)>,
}

impl Default for Io {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            cached: VecDeque::new(),
            next_slot: 100,
            failure: None,
        }
    }
}

impl Io {
    fn call(&mut self, call: Call) -> Result<(), u32> {
        self.calls.push(call);
        if let Some((expected, status)) = self.failure {
            if call == expected {
                self.failure = None;
                return Err(status);
            }
        }
        Ok(())
    }
}

impl FrameAcquisitionIo for Io {
    fn acquire_cached(&mut self) -> Option<u64> {
        self.calls.push(Call::Cache);
        self.cached.pop_front()
    }
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        self.call(Call::Reserve)?;
        let slot = self.next_slot;
        self.next_slot += 1;
        Ok(slot)
    }
    fn retype_frame(&mut self, slot: u64) -> Result<(), u32> {
        self.call(Call::Retype(slot))
    }
    fn recycle_empty(&mut self, slot: u64) -> Result<(), u32> {
        self.call(Call::Recycle(slot))
    }
    fn unmap_cached(&mut self, frame: u64) -> Result<(), u32> {
        self.call(Call::Unmap(frame))
    }
    fn zero_cached(&mut self, frame: u64) -> Result<(), u32> {
        self.call(Call::Zero(frame))
    }
}

#[test]
fn new_owner_has_no_pending_resource() {
    for owner in [FrameAcquisition::new(), FrameAcquisition::default()] {
        assert_eq!(owner.pending(), None);
        assert!(!owner.owns_root_cap(0));
        assert!(!owner.owns_root_cap(100));
    }
}

#[test]
fn cached_frame_transfers_only_after_zero_and_cleanup_acknowledgement() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io::default();
    io.cached.push_back(20);
    assert_eq!(owner.acquire(&mut io), Ok(20));
    assert_eq!(io.calls, vec![Call::Cache, Call::Unmap(20), Call::Zero(20)]);
    assert_eq!(owner.pending(), None);
    assert!(!owner.owns_root_cap(20));
}

#[test]
fn cached_frame_survives_repeated_zero_failures_without_reacquisition() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io::default();
    io.cached.push_back(20);
    io.failure = Some((Call::Zero(20), 17));
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(17))
    );
    assert_eq!(
        owner.pending(),
        Some(PendingFrameAcquisition::CachedFrame {
            frame: 20,
            owner_unmapped: true
        })
    );
    assert!(owner.owns_root_cap(20));
    assert!(!owner.owns_root_cap(21));
    io.cached.push_back(21);
    io.calls.clear();
    io.failure = Some((Call::Zero(20), 18));
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(18))
    );
    assert_eq!(io.calls, vec![Call::Zero(20)]);
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(20));
    assert_eq!(io.calls, vec![Call::Zero(20)]);
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(21));
    assert_eq!(io.calls, vec![Call::Cache, Call::Unmap(21), Call::Zero(21)]);
}

#[test]
fn fresh_retyped_frame_uses_backend_zero_guarantee_and_transfers_once() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io::default();
    assert_eq!(owner.acquire(&mut io), Ok(100));
    assert_eq!(
        io.calls,
        vec![Call::Cache, Call::Reserve, Call::Retype(100)]
    );
    assert_eq!(owner.pending(), None);
    assert!(!owner.owns_root_cap(100));
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(101));
    assert_eq!(
        io.calls,
        vec![Call::Cache, Call::Reserve, Call::Retype(101)]
    );
}

#[test]
fn reservation_failure_acquires_nothing_and_preserves_backend_status() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io {
        failure: Some((Call::Reserve, 23)),
        ..Io::default()
    };
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(23))
    );
    assert_eq!(owner.pending(), None);
    assert_eq!(io.calls, vec![Call::Cache, Call::Reserve]);
    io.cached.push_back(20);
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(20));
    assert_eq!(io.calls, vec![Call::Cache, Call::Unmap(20), Call::Zero(20)]);
}

#[test]
fn failed_retype_retains_empty_slot_and_returns_original_failure() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io {
        failure: Some((Call::Retype(100), 29)),
        ..Io::default()
    };
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(29))
    );
    assert_eq!(
        owner.pending(),
        Some(PendingFrameAcquisition::EmptySlot(100))
    );
    assert!(owner.owns_root_cap(100));
    assert_eq!(
        io.calls,
        vec![Call::Cache, Call::Reserve, Call::Retype(100)]
    );
}

#[test]
fn empty_slot_recycle_failure_blocks_every_new_acquisition() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io {
        failure: Some((Call::Retype(100), 29)),
        ..Io::default()
    };
    assert!(owner.acquire(&mut io).is_err());
    io.cached.push_back(20);
    io.calls.clear();
    io.failure = Some((Call::Recycle(100), 31));
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(31))
    );
    assert_eq!(
        owner.pending(),
        Some(PendingFrameAcquisition::EmptySlot(100))
    );
    assert_eq!(io.calls, vec![Call::Recycle(100)]);
    assert_eq!(io.cached.front(), Some(&20));
}

#[test]
fn retry_reconsiders_refilled_cache_after_recycling_failed_retype_destination() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io {
        failure: Some((Call::Retype(100), 29)),
        ..Io::default()
    };
    assert!(owner.acquire(&mut io).is_err());
    io.cached.push_back(20);
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(20));
    assert_eq!(
        io.calls,
        vec![
            Call::Recycle(100),
            Call::Cache,
            Call::Unmap(20),
            Call::Zero(20)
        ]
    );
    assert_eq!(owner.pending(), None);
    assert!(!owner.owns_root_cap(100));
}

#[test]
fn completed_empty_recycling_is_not_replayed_after_cached_zero_failure() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io {
        failure: Some((Call::Retype(100), 29)),
        ..Io::default()
    };
    assert!(owner.acquire(&mut io).is_err());
    io.cached.push_back(20);
    io.calls.clear();
    io.failure = Some((Call::Zero(20), 37));
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(37))
    );
    assert_eq!(
        owner.pending(),
        Some(PendingFrameAcquisition::CachedFrame {
            frame: 20,
            owner_unmapped: true
        })
    );
    assert!(!owner.owns_root_cap(100));
    assert!(owner.owns_root_cap(20));
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(20));
    assert_eq!(io.calls, vec![Call::Zero(20)]);
}

#[test]
fn each_failed_fresh_attempt_retains_only_its_current_empty_slot() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io {
        failure: Some((Call::Retype(100), 29)),
        ..Io::default()
    };
    assert!(owner.acquire(&mut io).is_err());
    io.calls.clear();
    io.failure = Some((Call::Retype(101), 41));
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(41))
    );
    assert_eq!(
        io.calls,
        vec![
            Call::Recycle(100),
            Call::Cache,
            Call::Reserve,
            Call::Retype(101)
        ]
    );
    assert_eq!(
        owner.pending(),
        Some(PendingFrameAcquisition::EmptySlot(101))
    );
    assert!(!owner.owns_root_cap(100));
    assert!(owner.owns_root_cap(101));
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(102));
    assert_eq!(
        io.calls,
        vec![
            Call::Recycle(101),
            Call::Cache,
            Call::Reserve,
            Call::Retype(102)
        ]
    );
}

#[test]
fn successful_recycling_is_not_replayed_after_a_new_reservation_failure() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io {
        failure: Some((Call::Retype(100), 29)),
        ..Io::default()
    };
    assert!(owner.acquire(&mut io).is_err());
    io.calls.clear();
    io.failure = Some((Call::Reserve, 43));
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(43))
    );
    assert_eq!(
        io.calls,
        vec![Call::Recycle(100), Call::Cache, Call::Reserve]
    );
    assert_eq!(owner.pending(), None);
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(101));
    assert_eq!(
        io.calls,
        vec![Call::Cache, Call::Reserve, Call::Retype(101)]
    );
}

#[test]
fn null_cache_entry_fails_without_zeroing_or_fresh_fallback() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io::default();
    io.cached.push_back(0);
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::InvalidCapability)
    );
    assert_eq!(io.calls, vec![Call::Cache]);
    assert_eq!(owner.pending(), None);
    assert!(!owner.owns_root_cap(0));
}

#[test]
fn null_successful_reservation_fails_without_retype_or_recycling() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io {
        next_slot: 0,
        ..Io::default()
    };
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::InvalidCapability)
    );
    assert_eq!(io.calls, vec![Call::Cache, Call::Reserve]);
    assert_eq!(owner.pending(), None);
    assert!(!owner.owns_root_cap(0));
}

#[test]
fn failed_cached_unmap_retains_owner_without_zeroing_or_acquiring_another_frame() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io::default();
    io.cached.push_back(20);
    io.failure = Some((Call::Unmap(20), 47));
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(47))
    );
    assert_eq!(
        owner.pending(),
        Some(PendingFrameAcquisition::CachedFrame {
            frame: 20,
            owner_unmapped: false
        })
    );
    assert!(owner.owns_root_cap(20));
    assert_eq!(io.calls, vec![Call::Cache, Call::Unmap(20)]);
    io.cached.push_back(21);
    io.calls.clear();
    io.failure = Some((Call::Unmap(20), 48));
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(48))
    );
    assert_eq!(io.calls, vec![Call::Unmap(20)]);
    assert_eq!(io.cached.front(), Some(&21));
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(20));
    assert_eq!(io.calls, vec![Call::Unmap(20), Call::Zero(20)]);
    assert_eq!(owner.pending(), None);
}

#[test]
fn successful_unmap_acknowledgement_survives_zeroing_failure_after_unmap_retry() {
    let mut owner = FrameAcquisition::new();
    let mut io = Io::default();
    io.cached.push_back(20);
    io.failure = Some((Call::Unmap(20), 47));
    assert!(owner.acquire(&mut io).is_err());
    io.calls.clear();
    io.failure = Some((Call::Zero(20), 49));
    assert_eq!(
        owner.acquire(&mut io),
        Err(FrameAcquisitionError::Backend(49))
    );
    assert_eq!(io.calls, vec![Call::Unmap(20), Call::Zero(20)]);
    assert_eq!(
        owner.pending(),
        Some(PendingFrameAcquisition::CachedFrame {
            frame: 20,
            owner_unmapped: true
        })
    );
    io.calls.clear();
    assert_eq!(owner.acquire(&mut io), Ok(20));
    assert_eq!(io.calls, vec![Call::Zero(20)]);
}
