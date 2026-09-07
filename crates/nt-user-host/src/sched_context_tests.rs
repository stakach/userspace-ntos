use super::*;
use alloc::vec::Vec;

struct Backend {
    calls: Vec<Stage>,
    fail: Option<Stage>,
    failure_status: u64,
    allocated: bool,
    object: bool,
    configured: bool,
    bound: bool,
    target: u64,
}

impl Backend {
    fn new() -> Self {
        Self {
            calls: Vec::new(),
            fail: None,
            failure_status: 7,
            allocated: false,
            object: false,
            configured: false,
            bound: false,
            target: 400,
        }
    }
    fn call(&mut self, stage: Stage) -> Result<(), u64> {
        if self.fail == Some(stage) {
            return Err(self.failure_status);
        }
        self.calls.push(stage);
        Ok(())
    }
}

impl SchedContextIo for Backend {
    fn allocate_slot(&mut self) -> Result<u64, u64> {
        assert!(!self.allocated);
        self.call(Stage::Allocate)?;
        self.allocated = true;
        Ok(100)
    }
    fn retype(&mut self, slot: u64) -> Result<(), u64> {
        assert_eq!(slot, 100);
        assert!(self.allocated && !self.object);
        self.call(Stage::Retype)?;
        self.object = true;
        Ok(())
    }
    fn configure(&mut self, cap: u64, budget: u64, period: u64) -> Result<(), u64> {
        assert_eq!((cap, budget, period), (100, 10, 10));
        assert!(self.object && !self.configured && !self.bound);
        self.call(Stage::Configure)?;
        self.configured = true;
        Ok(())
    }
    fn bind(&mut self, cap: u64, tcb: u64) -> Result<(), u64> {
        assert_eq!((cap, tcb), (100, self.target));
        assert!(self.object && self.configured && !self.bound);
        self.call(Stage::Bind)?;
        self.bound = true;
        Ok(())
    }
    fn delete(&mut self, cap: u64) -> Result<(), u64> {
        assert_eq!(cap, 100);
        assert!(self.allocated && self.object && !self.bound);
        self.call(Stage::Delete)?;
        self.object = false;
        Ok(())
    }
    fn recycle_slot(&mut self, slot: u64) -> Result<(), u64> {
        assert_eq!(slot, 100);
        assert!(self.allocated && !self.object && !self.bound);
        self.call(Stage::Recycle)?;
        self.allocated = false;
        Ok(())
    }
}

fn owner() -> SchedContextConstruction {
    SchedContextConstruction::new(400, 10, 10).unwrap()
}

#[test]
fn admission_refuses_fake_tcbs_and_invalid_budget_without_backend_effects() {
    for tcb in [0, 1] {
        assert!(SchedContextConstruction::new(tcb, 10, 10).is_none());
    }
    for (budget, period) in [(0, 10), (10, 0), (11, 10)] {
        assert!(SchedContextConstruction::new(400, budget, period).is_none());
    }
    let owner = owner();
    assert_eq!(owner.slot(), None);
    assert_eq!(owner.stage(), Stage::Allocate);
}

#[test]
fn successful_binding_transfers_cap_once_and_never_retires_it() {
    let mut owner = owner();
    let mut io = Backend::new();
    assert_eq!(owner.take_bound(), None);
    owner.construct(&mut io).unwrap();
    owner.construct(&mut io).unwrap();
    assert_eq!(owner.stage(), Stage::Bound);
    assert_eq!(owner.slot(), Some(100));
    assert_eq!(owner.retire(&mut io), Err(Error::InvalidState));
    assert_eq!(owner.take_bound(), Some(100));
    assert_eq!(owner.take_bound(), None);
    assert_eq!(owner.slot(), None);
    assert_eq!(owner.stage(), Stage::Transferred);
    assert_eq!(owner.construct(&mut io), Err(Error::InvalidState));
    assert_eq!(owner.retire(&mut io), Err(Error::InvalidState));
    assert_eq!(
        io.calls,
        [
            Stage::Allocate,
            Stage::Retype,
            Stage::Configure,
            Stage::Bind
        ]
    );
    assert!(io.bound && io.object && io.allocated);
}

#[test]
fn allocation_failure_retains_no_fake_slot_and_repeats_no_operations() {
    let mut owner = owner();
    let mut io = Backend::new();
    io.fail = Some(Stage::Allocate);
    let error = Error::Backend {
        stage: Stage::Allocate,
        status: 7,
    };
    assert_eq!(owner.construct(&mut io), Err(error));
    assert_eq!(owner.slot(), None);
    io.fail = None;
    assert_eq!(owner.construct(&mut io), Err(error));
    owner.retire(&mut io).unwrap();
    owner.retire(&mut io).unwrap();
    assert!(io.calls.is_empty());
    assert_eq!(owner.stage(), Stage::Retired);
}

#[test]
fn failed_retype_recycles_empty_slot_without_deleting_an_object() {
    let mut owner = owner();
    let mut io = Backend::new();
    io.fail = Some(Stage::Retype);
    assert!(owner.construct(&mut io).is_err());
    assert_eq!(owner.slot(), Some(100));
    assert_eq!(owner.stage(), Stage::Recycle);
    assert!(!io.object && io.allocated);
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(io.calls, [Stage::Allocate, Stage::Recycle]);
    assert_eq!(owner.slot(), None);
}

#[test]
fn failed_configuration_or_binding_is_sticky_retirement_after_target_reuse() {
    for stage in [Stage::Configure, Stage::Bind] {
        let mut owner = owner();
        let mut io = Backend::new();
        io.fail = Some(stage);
        let error = Error::Backend { stage, status: 7 };
        assert_eq!(owner.construct(&mut io), Err(error));
        assert_eq!(owner.stage(), Stage::Delete);
        assert_eq!(owner.target, None);
        assert!(io.object && !io.bound);
        io.target = 999;
        io.fail = None;
        let calls = io.calls.len();
        assert_eq!(owner.construct(&mut io), Err(error));
        assert_eq!(io.calls.len(), calls);
        assert_eq!(owner.take_bound(), None);
        owner.retire(&mut io).unwrap();
        assert_eq!(io.calls[calls..], [Stage::Delete, Stage::Recycle]);
        assert_eq!(owner.stage(), Stage::Retired);
        assert_eq!(owner.construct(&mut io), Err(error));
    }
}

#[test]
fn failed_delete_retains_exact_object_and_blocks_slot_reuse() {
    let mut owner = owner();
    let mut io = Backend::new();
    io.fail = Some(Stage::Configure);
    assert!(owner.construct(&mut io).is_err());
    io.fail = Some(Stage::Delete);
    for _ in 0..3 {
        assert_eq!(
            owner.retire(&mut io),
            Err(Error::Backend {
                stage: Stage::Delete,
                status: 7
            })
        );
        assert_eq!(owner.stage(), Stage::Delete);
        assert_eq!(owner.slot(), Some(100));
        assert!(io.object && io.allocated);
    }
    io.fail = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(
        io.calls,
        [
            Stage::Allocate,
            Stage::Retype,
            Stage::Delete,
            Stage::Recycle
        ]
    );
}

#[test]
fn recycle_failure_preserves_empty_slot_without_replaying_delete() {
    for failure in [Stage::Retype, Stage::Configure, Stage::Bind] {
        let mut owner = owner();
        let mut io = Backend::new();
        io.fail = Some(failure);
        let original = owner.construct(&mut io).unwrap_err();
        io.failure_status = 13;
        io.fail = Some(Stage::Recycle);
        for _ in 0..3 {
            assert_eq!(
                owner.retire(&mut io),
                Err(Error::Backend {
                    stage: Stage::Recycle,
                    status: 13
                })
            );
            assert_eq!(owner.stage(), Stage::Recycle);
            assert_eq!(owner.slot(), Some(100));
            assert!(io.allocated && !io.object);
            assert_eq!(owner.construct(&mut io), Err(original));
        }
        assert_eq!(
            io.calls
                .iter()
                .filter(|&&stage| stage == Stage::Delete)
                .count(),
            if failure == Stage::Retype { 0 } else { 1 }
        );
        io.fail = None;
        owner.retire(&mut io).unwrap();
        let calls = io.calls.len();
        owner.retire(&mut io).unwrap();
        assert_eq!(io.calls.len(), calls);
        assert!(!io.allocated && !io.object);
        assert_eq!(owner.slot(), None);
    }
}

#[test]
fn dropping_an_owner_does_not_silently_delete_or_recycle() {
    let mut owner = owner();
    let mut io = Backend::new();
    io.fail = Some(Stage::Bind);
    assert!(owner.construct(&mut io).is_err());
    let calls = io.calls.len();
    drop(owner);
    assert_eq!(io.calls.len(), calls);
    assert!(io.object && io.allocated && !io.bound);
}

#[test]
fn retirement_cannot_cancel_in_progress_construction() {
    let mut owner = owner();
    let mut io = Backend::new();
    assert_eq!(owner.retire(&mut io), Err(Error::InvalidState));
    assert!(io.calls.is_empty());
    owner.construct(&mut io).unwrap();
    assert_eq!(owner.take_bound(), Some(100));
}
