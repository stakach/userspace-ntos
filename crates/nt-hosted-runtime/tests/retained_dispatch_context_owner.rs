//! A kept native pump must carry its exact device context across an unwound root slice.
//! File IRPs and video FindAdapter use the same owner transition; neither may reconstruct a
//! binding from the current device singleton when the provider resumes.

use nt_hosted_runtime::retained_dispatch_context::{
    RetainedContextBinding, RetainedContextOwner,
};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    generation: u64,
    bank: u64,
}

#[derive(Default)]
struct Lease {
    published: Option<Identity>,
    bound: Option<Identity>,
    maps: usize,
    deny_suspend: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Refusal { Stale, NotTop }

struct Active {
    identity: Identity,
    lease: Rc<RefCell<Lease>>,
}

struct Suspended {
    identity: Identity,
    lease: Rc<RefCell<Lease>>,
}

impl RetainedContextBinding for Active {
    type Suspended = Suspended;
    type Error = Refusal;

    fn suspend(self) -> Result<Suspended, (Refusal, Self)> {
        let may_unbind = {
            let lease = self.lease.borrow();
            !lease.deny_suspend && lease.bound == Some(self.identity)
        };
        if !may_unbind {
            return Err((Refusal::NotTop, self));
        }
        self.lease.borrow_mut().bound = None;
        Ok(Suspended { identity: self.identity, lease: self.lease })
    }

    fn resume(ticket: Suspended) -> Result<Self, (Refusal, Suspended)> {
        let may_bind = {
            let lease = ticket.lease.borrow();
            lease.published == Some(ticket.identity) && lease.bound.is_none()
        };
        if !may_bind {
            return Err((Refusal::Stale, ticket));
        }
        ticket.lease.borrow_mut().bound = Some(ticket.identity);
        Ok(Self { identity: ticket.identity, lease: ticket.lease })
    }
}

impl Active {
    fn map_assigned_bar(&self, device: u64, bank: u64) -> bool {
        let mut lease = self.lease.borrow_mut();
        if lease.published != Some(self.identity)
            || lease.bound != Some(self.identity)
            || self.identity.device != device
            || self.identity.bank != bank
        {
            return false;
        }
        lease.maps += 1;
        true
    }
}

fn entered(identity: Identity) -> (RetainedContextOwner<Active>, Rc<RefCell<Lease>>) {
    let lease = Rc::new(RefCell::new(Lease {
        published: Some(identity),
        bound: Some(identity),
        ..Lease::default()
    }));
    (RetainedContextOwner::active(Active { identity, lease: lease.clone() }), lease)
}

const VIDEO: Identity = Identity { device: 0x4e, generation: 7, bank: 0x810a_2000 };

#[test]
fn pending_video_pump_rebinds_the_same_bar_owner_before_retry() {
    let (owner, lease) = entered(VIDEO);
    let owner = owner.suspend().unwrap_or_else(|(error, _)| panic!("suspend: {error:?}"));
    assert!(lease.borrow().bound.is_none(), "no active selector leaks across the root yield");
    let owner = owner.resume().unwrap_or_else(|(error, _)| panic!("resume: {error:?}"));
    assert!(owner.active_ref().unwrap().map_assigned_bar(VIDEO.device, VIDEO.bank));
    assert_eq!(lease.borrow().maps, 1, "the real assigned map records one use");
}

#[test]
fn sibling_device_and_bank_cannot_use_a_kept_video_context() {
    let (owner, lease) = entered(VIDEO);
    let owner = owner.suspend().unwrap_or_else(|(error, _)| panic!("suspend: {error:?}"));
    lease.borrow_mut().published = Some(Identity { device: 0x50, bank: VIDEO.bank, ..VIDEO });
    let (error, owner) = owner.resume().err().expect("a sibling cannot acquire the old ticket");
    assert_eq!(error, Refusal::Stale);
    assert!(owner.active_ref().is_none());
    assert_eq!(lease.borrow().maps, 0);
    // The same numeric BAR is not authority for the old StartDevice once its publication moved.
    assert_eq!(lease.borrow().published.unwrap().device, 0x50);
}

#[test]
fn a_recycled_generation_refuses_resume_and_keeps_the_original_ticket() {
    let (owner, lease) = entered(VIDEO);
    let owner = owner.suspend().unwrap_or_else(|(error, _)| panic!("suspend: {error:?}"));
    lease.borrow_mut().published = Some(Identity { generation: VIDEO.generation + 1, ..VIDEO });
    let (error, owner) = owner.resume().err().expect("recycled generation must refuse");
    assert_eq!(error, Refusal::Stale);
    assert!(owner.active_ref().is_none());
    assert_eq!(lease.borrow().maps, 0);
    let (again, _) = owner.resume().err().expect("refusal retains the old ticket for quarantine");
    assert_eq!(again, Refusal::Stale);
}

#[test]
fn failed_unbind_returns_the_active_owner_without_dropping_its_binding() {
    let (owner, lease) = entered(VIDEO);
    lease.borrow_mut().deny_suspend = true;
    let (error, owner) = owner.suspend().err().expect("failed unbind must return its guard");
    assert_eq!(error, Refusal::NotTop);
    assert_eq!(lease.borrow().bound, Some(VIDEO));
    assert!(owner.active_ref().unwrap().map_assigned_bar(VIDEO.device, VIDEO.bank));
}
