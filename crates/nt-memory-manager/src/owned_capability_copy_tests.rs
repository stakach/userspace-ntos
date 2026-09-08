use super::*;
use alloc::vec::Vec;

#[derive(Debug, PartialEq, Eq)]
struct Descriptor {
    source: u64,
    lifetime: u64,
}

fn descriptor() -> Descriptor {
    Descriptor {
        source: 12,
        lifetime: 93,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Reserve,
    Copy,
    Delete,
    Recycle,
}

struct Io {
    calls: Vec<Op>,
    fail: Option<Op>,
    slot: u64,
    allocated: bool,
    populated: bool,
    lifetime: u64,
}

impl Io {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            fail: None,
            slot: 41,
            allocated: false,
            populated: false,
            lifetime: 93,
        }
    }
    fn call(&mut self, op: Op) -> Result<(), u32> {
        self.calls.push(op);
        if self.fail == Some(op) {
            Err(73)
        } else {
            Ok(())
        }
    }
    fn count(&self, op: Op) -> usize {
        self.calls.iter().filter(|&&c| c == op).count()
    }
    fn check(&self, slot: u64) {
        assert_eq!(slot, self.slot);
        assert!(self.allocated);
    }
}

impl CapabilityCopyIo<Descriptor> for Io {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        assert!(!self.allocated);
        self.call(Op::Reserve)?;
        self.allocated = self.slot != 0;
        Ok(self.slot)
    }
    fn copy_into(&mut self, slot: u64, desc: &Descriptor) -> Result<(), u32> {
        self.check(slot);
        assert!(!self.populated);
        assert_eq!(desc.source, 12);
        self.call(Op::Copy)?;
        if desc.lifetime != self.lifetime {
            return Err(91);
        }
        self.populated = true;
        Ok(())
    }
    fn delete(&mut self, slot: u64) -> Result<(), u32> {
        self.check(slot);
        assert!(self.populated);
        self.call(Op::Delete)?;
        self.populated = false;
        Ok(())
    }
    fn recycle_unretyped(&mut self, slot: u64) -> Result<(), u32> {
        self.check(slot);
        assert!(!self.populated);
        self.call(Op::Recycle)?;
        self.allocated = false;
        Ok(())
    }
}

#[test]
fn construction_and_retirement_are_idempotent() {
    let mut owner = OwnedCapabilityCopy::new(descriptor());
    let mut io = Io::new();
    assert_eq!(owner.descriptor(), &descriptor());
    assert_eq!(owner.copied_cap(), None);
    owner.construct(&mut io).unwrap();
    owner.construct(&mut io).unwrap();
    assert_eq!(owner.copied_cap(), Some(41));
    assert!(owner.owns_cap(41));
    assert!(!owner.owns_cap(0) && !owner.owns_cap(42));
    assert_eq!(io.count(Op::Reserve), 1);
    assert_eq!(io.count(Op::Copy), 1);
    owner.retire(&mut io).unwrap();
    owner.retire(&mut io).unwrap();
    assert!(owner.is_released());
    assert_eq!(owner.copied_cap(), None);
    assert!(!owner.owns_cap(41));
    assert_eq!(io.count(Op::Delete), 1);
    assert_eq!(io.count(Op::Recycle), 1);
    assert_eq!(
        owner.construct(&mut io),
        Err(CapabilityCopyError::RetiringOrReleased)
    );
}

#[test]
fn reserve_failure_and_invalid_zero_leave_vacant_owner() {
    for zero in [false, true] {
        let mut owner = OwnedCapabilityCopy::new(descriptor());
        let mut io = Io::new();
        if zero {
            io.slot = 0;
        } else {
            io.fail = Some(Op::Reserve);
        }
        assert_eq!(
            owner.construct(&mut io),
            Err(if zero {
                CapabilityCopyError::InvalidCapability
            } else {
                CapabilityCopyError::Backend(73)
            })
        );
        assert_eq!(owner.snapshot().phase(), CapabilityCopyPhase::Vacant);
        assert_eq!(owner.snapshot().capability(), None);
        assert!(!io.allocated);
        io.slot = 41;
        io.fail = None;
        owner.construct(&mut io).unwrap();
        assert_eq!(owner.copied_cap(), Some(41));
    }
}

#[test]
fn failed_copy_keeps_empty_slot_and_retries_without_reserving_again() {
    let mut owner = OwnedCapabilityCopy::new(descriptor());
    let mut io = Io::new();
    io.fail = Some(Op::Copy);
    assert_eq!(
        owner.construct(&mut io),
        Err(CapabilityCopyError::Backend(73))
    );
    assert_eq!(owner.snapshot().phase(), CapabilityCopyPhase::Reserved);
    assert!(owner.owns_cap(41));
    assert_eq!(owner.copied_cap(), None);
    assert!(io.allocated && !io.populated);
    io.fail = None;
    owner.construct(&mut io).unwrap();
    assert_eq!(io.count(Op::Reserve), 1);
    assert_eq!(io.count(Op::Copy), 2);
}

#[test]
fn stale_source_rejects_copy_without_losing_reserved_slot() {
    let mut owner = OwnedCapabilityCopy::new(descriptor());
    let mut io = Io::new();
    io.lifetime += 1;
    assert_eq!(
        owner.construct(&mut io),
        Err(CapabilityCopyError::Backend(91))
    );
    assert!(owner.owns_cap(41));
    assert_eq!(owner.descriptor().lifetime, 93);
    owner.retire(&mut io).unwrap();
    assert_eq!(io.count(Op::Delete), 0);
    assert_eq!(io.count(Op::Recycle), 1);
}

#[test]
fn abort_failed_copy_recycles_without_deleting_and_retains_failed_recycle() {
    let mut owner = OwnedCapabilityCopy::new(descriptor());
    let mut io = Io::new();
    io.fail = Some(Op::Copy);
    owner.construct(&mut io).unwrap_err();
    io.fail = Some(Op::Recycle);
    assert_eq!(owner.retire(&mut io), Err(CapabilityCopyError::Backend(73)));
    assert_eq!(owner.snapshot().phase(), CapabilityCopyPhase::RetiringEmpty);
    assert!(owner.owns_cap(41));
    assert_eq!(
        owner.construct(&mut io),
        Err(CapabilityCopyError::RetiringOrReleased)
    );
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(io.count(Op::Delete), 0);
    assert!(owner.is_released());
}

#[test]
fn failed_delete_withdraws_admission_but_retains_live_copy() {
    let mut owner = OwnedCapabilityCopy::new(descriptor());
    let mut io = Io::new();
    owner.construct(&mut io).unwrap();
    io.fail = Some(Op::Delete);
    assert_eq!(owner.retire(&mut io), Err(CapabilityCopyError::Backend(73)));
    assert_eq!(
        owner.snapshot().phase(),
        CapabilityCopyPhase::RetiringCopied
    );
    assert!(owner.owns_cap(41) && io.populated);
    assert_eq!(owner.copied_cap(), None);
    assert_eq!(io.count(Op::Recycle), 0);
    assert_eq!(
        owner.construct(&mut io),
        Err(CapabilityCopyError::RetiringOrReleased)
    );
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(io.count(Op::Copy), 1);
    assert_eq!(io.count(Op::Delete), 2);
}

#[test]
fn successful_delete_is_not_replayed_after_recycle_failure() {
    let mut owner = OwnedCapabilityCopy::new(descriptor());
    let mut io = Io::new();
    owner.construct(&mut io).unwrap();
    io.fail = Some(Op::Recycle);
    owner.retire(&mut io).unwrap_err();
    assert_eq!(owner.snapshot().phase(), CapabilityCopyPhase::RetiringEmpty);
    assert!(owner.owns_cap(41) && io.allocated && !io.populated);
    assert_eq!(owner.copied_cap(), None);
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(io.count(Op::Delete), 1);
    assert_eq!(io.count(Op::Recycle), 2);
    assert!(!owner.owns_cap(41));
}

#[test]
fn vacant_retirement_has_no_backend_effects_and_cannot_be_reopened() {
    let mut owner = OwnedCapabilityCopy::new(descriptor());
    let mut io = Io::new();
    owner.retire(&mut io).unwrap();
    assert!(owner.is_released());
    assert!(io.calls.is_empty());
    assert_eq!(
        owner.construct(&mut io),
        Err(CapabilityCopyError::RetiringOrReleased)
    );
    assert!(io.calls.is_empty());
}

#[test]
fn moving_owner_preserves_descriptor_and_retained_capability() {
    let mut owner = OwnedCapabilityCopy::new(descriptor());
    let mut io = Io::new();
    owner.construct(&mut io).unwrap();
    let mut moved = alloc::boxed::Box::new(owner);
    assert_eq!(moved.descriptor(), &descriptor());
    assert_eq!(moved.copied_cap(), Some(41));
    moved.retire(&mut io).unwrap();
    assert_eq!(io.count(Op::Copy), 1);
}
