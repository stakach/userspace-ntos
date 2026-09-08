use super::*;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, PartialEq, Eq)]
struct Descriptor {
    vspace: u64,
    base: u64,
    level: u8,
}

fn descriptor() -> Descriptor {
    Descriptor {
        vspace: 17,
        base: 0x4080_0000_0000,
        level: 3,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Reserve,
    Retype,
    Map,
    Unmap,
    Delete,
    RecycleRetyped,
    RecycleUnretyped,
}

struct Io {
    calls: Vec<Op>,
    fail: Option<Op>,
    slot: u64,
    allocated: bool,
    retyped: bool,
    populated: bool,
    mapped: bool,
}

impl Io {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            fail: None,
            slot: 41,
            allocated: false,
            retyped: false,
            populated: false,
            mapped: false,
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

    fn check(&self, slot: u64) {
        assert_eq!(slot, self.slot);
        assert!(self.allocated);
    }

    fn count(&self, op: Op) -> usize {
        self.calls.iter().filter(|&&call| call == op).count()
    }
}

impl PagingStructureIo<Descriptor> for Io {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        assert!(!self.allocated);
        self.call(Op::Reserve)?;
        self.allocated = self.slot != 0;
        Ok(self.slot)
    }

    fn retype(&mut self, slot: u64, desc: &Descriptor) -> Result<(), u32> {
        self.check(slot);
        assert_eq!(*desc, descriptor());
        assert!(!self.retyped && !self.populated && !self.mapped);
        self.call(Op::Retype)?;
        self.retyped = true;
        self.populated = true;
        Ok(())
    }

    fn map(&mut self, slot: u64, desc: &Descriptor) -> Result<(), u32> {
        self.check(slot);
        assert_eq!(*desc, descriptor());
        assert!(self.retyped && self.populated && !self.mapped);
        self.call(Op::Map)?;
        self.mapped = true;
        Ok(())
    }

    fn unmap(&mut self, slot: u64, desc: &Descriptor) -> Result<(), u32> {
        self.check(slot);
        assert_eq!(*desc, descriptor());
        assert!(self.retyped && self.populated && self.mapped);
        self.call(Op::Unmap)?;
        self.mapped = false;
        Ok(())
    }

    fn delete(&mut self, slot: u64) -> Result<(), u32> {
        self.check(slot);
        assert!(self.retyped && self.populated && !self.mapped);
        self.call(Op::Delete)?;
        self.populated = false;
        Ok(())
    }

    fn recycle_retyped(&mut self, slot: u64) -> Result<(), u32> {
        self.check(slot);
        assert!(self.retyped && !self.populated && !self.mapped);
        self.call(Op::RecycleRetyped)?;
        self.retyped = false;
        self.allocated = false;
        Ok(())
    }

    fn recycle_unretyped(&mut self, slot: u64) -> Result<(), u32> {
        self.check(slot);
        assert!(!self.retyped && !self.populated && !self.mapped);
        self.call(Op::RecycleUnretyped)?;
        self.allocated = false;
        Ok(())
    }
}

fn error() -> Result<(), PagingStructureError> {
    Err(PagingStructureError::Backend(73))
}

#[test]
fn successful_construction_and_retirement_preserve_descriptor_and_order() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    assert_eq!(owner.descriptor(), &descriptor());
    assert_eq!(owner.snapshot().phase(), PagingStructurePhase::Vacant);
    assert!(!owner.owns_cap(0));
    owner.construct(&mut io).unwrap();
    assert_eq!(owner.mapped_cap(), Some(41));
    assert!(owner.owns_cap(41));
    assert!(owner.snapshot().owns_retype_accounting());
    owner.construct(&mut io).unwrap();
    owner.retire(&mut io).unwrap();
    owner.retire(&mut io).unwrap();
    assert!(owner.is_released());
    assert_eq!(owner.snapshot().capability(), None);
    assert!(!owner.owns_cap(41));
    assert!(!owner.snapshot().owns_retype_accounting());
    assert_eq!(
        io.calls,
        vec![
            Op::Reserve,
            Op::Retype,
            Op::Map,
            Op::Unmap,
            Op::Delete,
            Op::RecycleRetyped
        ]
    );
}

#[test]
fn allocation_failure_has_no_hidden_slot_and_can_retry() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    io.fail = Some(Op::Reserve);
    assert_eq!(owner.construct(&mut io), error());
    assert_eq!(owner.snapshot().phase(), PagingStructurePhase::Vacant);
    assert_eq!(owner.snapshot().capability(), None);
    io.fail = None;
    owner.construct(&mut io).unwrap();
    assert_eq!(io.count(Op::Reserve), 2);
    assert_eq!(io.count(Op::Retype), 1);
}

#[test]
fn null_slot_is_rejected_before_retype_or_map() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    io.slot = 0;
    assert_eq!(
        owner.construct(&mut io),
        Err(PagingStructureError::InvalidCapability)
    );
    assert_eq!(owner.snapshot().phase(), PagingStructurePhase::Vacant);
    owner.retire(&mut io).unwrap();
    assert_eq!(io.calls, vec![Op::Reserve]);
}

#[test]
fn retype_failure_keeps_reserved_slot_and_retry_never_reallocates() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    io.fail = Some(Op::Retype);
    for _ in 0..3 {
        assert_eq!(owner.construct(&mut io), error());
        assert_eq!(owner.snapshot().phase(), PagingStructurePhase::Reserved);
        assert!(owner.owns_cap(41));
        assert!(!owner.snapshot().owns_retype_accounting());
        assert_eq!(owner.mapped_cap(), None);
    }
    io.fail = None;
    owner.construct(&mut io).unwrap();
    assert_eq!(io.count(Op::Reserve), 1);
    assert_eq!(io.count(Op::Retype), 4);
    assert_eq!(io.count(Op::Map), 1);
}

#[test]
fn map_failure_retains_table_without_retype_or_adoption() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    io.fail = Some(Op::Map);
    for _ in 0..3 {
        assert_eq!(owner.construct(&mut io), error());
        assert_eq!(owner.snapshot().phase(), PagingStructurePhase::Retyped);
        assert!(owner.snapshot().owns_retype_accounting());
        assert_eq!(owner.mapped_cap(), None);
    }
    io.fail = None;
    owner.construct(&mut io).unwrap();
    assert_eq!(io.count(Op::Reserve), 1);
    assert_eq!(io.count(Op::Retype), 1);
    assert_eq!(io.count(Op::Map), 4);
}

#[test]
fn retirement_of_failed_retype_only_recycles_unretyped_slot() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    io.fail = Some(Op::Retype);
    assert_eq!(owner.construct(&mut io), error());
    io.fail = Some(Op::RecycleUnretyped);
    for _ in 0..3 {
        assert_eq!(owner.retire(&mut io), error());
        assert_eq!(
            owner.snapshot().phase(),
            PagingStructurePhase::RetiringEmpty
        );
        assert!(owner.owns_cap(41));
        assert!(!owner.snapshot().owns_retype_accounting());
    }
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert!(owner.is_released());
    assert_eq!(io.count(Op::Delete), 0);
    assert_eq!(io.count(Op::Unmap), 0);
    assert_eq!(io.count(Op::RecycleRetyped), 0);
    assert_eq!(io.count(Op::RecycleUnretyped), 4);
}

#[test]
fn retirement_of_unmapped_table_deletes_then_recycles_retype_accounting() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    io.fail = Some(Op::Map);
    assert_eq!(owner.construct(&mut io), error());
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(
        io.calls,
        vec![
            Op::Reserve,
            Op::Retype,
            Op::Map,
            Op::Delete,
            Op::RecycleRetyped
        ]
    );
}

#[test]
fn unmap_failure_withdraws_admission_and_retains_mapped_cap() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    owner.construct(&mut io).unwrap();
    io.fail = Some(Op::Unmap);
    assert_eq!(owner.retire(&mut io), error());
    assert_eq!(
        owner.snapshot().phase(),
        PagingStructurePhase::RetiringMapped
    );
    assert_eq!(owner.mapped_cap(), None);
    assert!(owner.owns_cap(41));
    assert_eq!(io.count(Op::Delete), 0);
    assert_eq!(
        owner.construct(&mut io),
        Err(PagingStructureError::RetiringOrReleased)
    );
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(io.count(Op::Unmap), 2);
}

#[test]
fn delete_failure_never_replays_successful_unmap() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    owner.construct(&mut io).unwrap();
    io.fail = Some(Op::Delete);
    for _ in 0..3 {
        assert_eq!(owner.retire(&mut io), error());
        assert_eq!(
            owner.snapshot().phase(),
            PagingStructurePhase::RetiringRetyped
        );
        assert!(owner.owns_cap(41));
    }
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(io.count(Op::Unmap), 1);
    assert_eq!(io.count(Op::Delete), 4);
    assert_eq!(io.count(Op::RecycleRetyped), 1);
}

#[test]
fn deleted_slot_stays_owned_with_retype_accounting_until_recycle_succeeds() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    owner.construct(&mut io).unwrap();
    io.fail = Some(Op::RecycleRetyped);
    for _ in 0..3 {
        assert_eq!(owner.retire(&mut io), error());
        assert_eq!(
            owner.snapshot().phase(),
            PagingStructurePhase::RetiringDeleted
        );
        assert!(owner.owns_cap(41));
        assert!(owner.snapshot().owns_retype_accounting());
    }
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(io.count(Op::Unmap), 1);
    assert_eq!(io.count(Op::Delete), 1);
    assert_eq!(io.count(Op::RecycleRetyped), 4);
    assert_eq!(io.count(Op::RecycleUnretyped), 0);
}

#[test]
fn retiring_empty_owner_and_released_owner_never_construct_again() {
    let mut owner = OwnedPagingStructure::new(descriptor());
    let mut io = Io::new();
    owner.retire(&mut io).unwrap();
    assert!(owner.is_released());
    assert_eq!(
        owner.construct(&mut io),
        Err(PagingStructureError::RetiringOrReleased)
    );
    owner.retire(&mut io).unwrap();
    assert!(io.calls.is_empty());
}
