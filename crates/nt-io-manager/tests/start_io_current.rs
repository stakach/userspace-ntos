use nt_io_manager::{start_io, start_io_current, HostedDevicePointerRegistration, HostedDomainIdentity};

use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_ledger::{
    SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpLedger, SourceIrpOwner,
};
use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceType, IoManager, MockDriverBackend, MockObjectPort,
};
use nt_types::NtPath;
use start_io::CurrentPacketRelation;
use start_io_current::{CompletionObservation, CurrentPhase, CurrentReceipt, Error, LivePacket};
use std::cell::RefCell;
use std::rc::Rc;

struct DeviceFixture {
    _io: IoManager<MockObjectPort>,
    registration: HostedDevicePointerRegistration,
}

impl DeviceFixture {
    fn new() -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\StartIoCurrent").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let device = io
            .create_device(
                driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::empty(),
                0,
            )
            .unwrap();
        let domain = io.register_hosted_domain();
        let registration = io
            .bind_hosted_device_pointer(domain, 0x600000, device)
            .unwrap();
        Self {
            _io: io,
            registration,
        }
    }
}

#[derive(Debug)]
struct Owner {
    id: u64,
    drops: Rc<RefCell<Vec<u64>>>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.drops.borrow_mut().push(self.id);
    }
}

fn owner(id: u64, drops: &Rc<RefCell<Vec<u64>>>) -> Owner {
    Owner {
        id,
        drops: drops.clone(),
    }
}

fn identity(
    device: HostedDevicePointerRegistration,
    address: u64,
    generation: u64,
) -> SourceIrpForwardIdentity {
    identity_in_domain(device.domain(), address, generation)
}

fn identity_in_domain(
    domain: HostedDomainIdentity,
    address: u64,
    generation: u64,
) -> SourceIrpForwardIdentity {
    let allocation = SourceIrpAllocation {
        owner: SourceIrpOwner::HostedDriver(3),
        domain,
        component_address: address,
        bytes: 0x128,
        stack_count: 2,
        pool_generation: generation,
    };
    SourceIrpForwardIdentity::new(
        SourceIrpTicket::new(allocation.domain, generation, generation).unwrap(),
        allocation,
    )
    .unwrap()
}

fn packet(
    identity: SourceIrpForwardIdentity,
    id: u64,
    drops: &Rc<RefCell<Vec<u64>>>,
) -> LivePacket<Owner> {
    LivePacket::new(identity, owner(id, drops))
}

#[test]
fn empty_and_live_classification_uses_exact_packet_lifetimes() {
    let device = DeviceFixture::new();
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(
        device.registration,
        device.registration.domain(),
        owner(1, &drops),
    );
    let a = identity(device.registration, 0x2000, 1);
    let probe = packet(a, 2, &drops);
    assert_eq!(
        current.classify(device.registration, 0, &probe),
        Ok(CurrentPacketRelation::Empty)
    );
    assert_eq!(
        current.classify(device.registration, 0x2000, &probe),
        Err(Error::WrongCurrent)
    );
    assert!(current
        .prepare_update(device.registration, 0, Some(probe))
        .unwrap()
        .commit()
        .is_none());
    let duplicate = packet(a, 3, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &duplicate),
        Ok(CurrentPacketRelation::LiveSame)
    );
    let other = packet(identity(device.registration, 0x3000, 2), 4, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &other),
        Ok(CurrentPacketRelation::LiveOther)
    );
    let reused = packet(identity(device.registration, 0x2000, 2), 5, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &reused),
        Err(Error::WrongPacket)
    );
    assert!(drops.borrow().is_empty());
}

#[test]
fn genuine_completion_releases_packet_owner_but_keeps_completed_current_before_next() {
    let device = DeviceFixture::new();
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(
        device.registration,
        device.registration.domain(),
        owner(1, &drops),
    );
    let a = identity(device.registration, 0x2000, 1);
    let mut ledger = SourceIrpLedger::new();
    // The real source allocation may be retired while DeviceObject.CurrentIrp still names it.
    let source_ticket = ledger.register(a.allocation()).unwrap();
    current
        .prepare_update(device.registration, 0, Some(packet(a, 2, &drops)))
        .unwrap()
        .commit();
    let returned = current
        .observe_completion(device.registration, a, CompletionObservation::Acknowledged)
        .unwrap()
        .unwrap();
    assert_eq!(returned.identity(), a);
    assert_eq!(current.snapshot().phase, CurrentPhase::Completed);
    assert_eq!(current.snapshot().packet, Some(a));
    drop(returned.into_owner());
    ledger.retire(source_ticket, a.allocation()).unwrap();
    assert_eq!(&*drops.borrow(), &[2]);
    let b = identity(device.registration, 0x2000, 2);
    ledger.register(b.allocation()).unwrap();
    let incoming = packet(b, 3, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &incoming),
        Ok(CurrentPacketRelation::Completed)
    );
    let changed_ticket_only = SourceIrpForwardIdentity::new(b.ticket(), a.allocation()).unwrap();
    let same_allocation = packet(changed_ticket_only, 4, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &same_allocation),
        Err(Error::WrongPacket),
        "a new ticket does not prove a new physical pool lifetime"
    );
    let changed_allocation_only =
        SourceIrpForwardIdentity::new(a.ticket(), b.allocation()).unwrap();
    let same_ticket = packet(changed_allocation_only, 5, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &same_ticket),
        Err(Error::WrongPacket),
        "a reused source ticket cannot identify a new source lifetime"
    );
    assert!(current
        .prepare_update(device.registration, 0x2000, Some(incoming))
        .unwrap()
        .commit()
        .is_none());
    assert_eq!(current.snapshot().phase, CurrentPhase::Live);
    assert_eq!(current.snapshot().packet, Some(b));
    assert_eq!(
        &*drops.borrow(),
        &[2],
        "device lifetime remains retained after source free"
    );
}

#[test]
fn callback_return_has_no_completion_transition_and_uncertainty_preserves_owners() {
    let device = DeviceFixture::new();
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(
        device.registration,
        device.registration.domain(),
        owner(1, &drops),
    );
    let a = identity(device.registration, 0x2000, 1);
    current
        .prepare_update(device.registration, 0, Some(packet(a, 2, &drops)))
        .unwrap()
        .commit();
    let before = current.snapshot();
    // No operation represents callback return: it conveys no terminal ownership evidence.
    assert_eq!(current.snapshot(), before);
    assert!(current
        .observe_completion(device.registration, a, CompletionObservation::Uncertain)
        .unwrap()
        .is_none());
    assert_eq!(current.snapshot(), before);
    assert!(drops.borrow().is_empty());
    let incoming = packet(identity(device.registration, 0x2000, 2), 3, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &incoming),
        Err(Error::WrongPacket)
    );
    assert!(drops.borrow().is_empty());
}

#[test]
fn reminted_device_registration_and_foreign_source_domain_refuse_without_owner_loss() {
    let mut device = DeviceFixture::new();
    let old = device.registration;
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(old, old.domain(), owner(1, &drops));
    let a = identity(old, 0x2000, 1);
    current
        .prepare_update(old, 0, Some(packet(a, 2, &drops)))
        .unwrap()
        .commit();
    let before = current.snapshot();
    // Host fixture can retire its unpinned projection. A native adapter must hold a real fence;
    // this test verifies stale/new scalar observations cannot substitute for that exact owner.
    device._io.retire_hosted_device_pointer(old).unwrap();
    let reminted = device
        ._io
        .bind_hosted_device_pointer(old.domain(), old.address(), old.device_id())
        .unwrap();
    assert_ne!(reminted.generation(), old.generation());
    let probe = packet(a, 3, &drops);
    assert_eq!(
        current.classify(reminted, 0x2000, &probe),
        Err(Error::WrongDevice)
    );
    assert!(matches!(
        current.observe_completion(reminted, a, CompletionObservation::Acknowledged),
        Err(Error::WrongDevice)
    ));
    let foreign_domain = device._io.register_hosted_domain();
    let foreign_allocation = SourceIrpAllocation {
        domain: foreign_domain,
        ..a.allocation()
    };
    let foreign_identity = SourceIrpForwardIdentity::new(
        SourceIrpTicket::new(foreign_domain, 9, 9).unwrap(),
        foreign_allocation,
    )
    .unwrap();
    let incoming = packet(foreign_identity, 4, &drops);
    assert_eq!(
        current.classify(old, 0x2000, &incoming),
        Err(Error::WrongPacket)
    );
    let refusal = match current.prepare_update(old, 0x2000, Some(incoming)) {
        Err(refusal) => refusal,
        Ok(_) => panic!("foreign physical source must refuse"),
    };
    assert_eq!(refusal.error, Error::WrongPacket);
    assert_eq!(
        refusal.incoming.as_ref().unwrap().identity(),
        foreign_identity
    );
    assert!(matches!(
        current.observe_completion(old, foreign_identity, CompletionObservation::Acknowledged),
        Err(Error::WrongPacket)
    ));
    assert_eq!(current.snapshot(), before);
    assert!(drops.borrow().is_empty());
}

#[test]
fn completion_requires_whole_device_registration_and_all_source_identity_dimensions() {
    let device = DeviceFixture::new();
    let foreign = DeviceFixture::new();
    assert_eq!(
        device.registration.address(),
        foreign.registration.address()
    );
    assert_eq!(device.registration.domain(), foreign.registration.domain());
    assert_eq!(
        device.registration.device_id(),
        foreign.registration.device_id()
    );
    assert_eq!(
        device.registration.generation(),
        foreign.registration.generation()
    );
    assert_ne!(
        device.registration, foreign.registration,
        "private manager identity differs"
    );
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(
        device.registration,
        device.registration.domain(),
        owner(1, &drops),
    );
    let a = identity(device.registration, 0x2000, 1);
    current
        .prepare_update(device.registration, 0, Some(packet(a, 2, &drops)))
        .unwrap()
        .commit();
    let before = current.snapshot();
    assert!(matches!(
        current.observe_completion(foreign.registration, a, CompletionObservation::Acknowledged),
        Err(Error::WrongDevice)
    ));
    let allocation = a.allocation();
    let changed_allocations = [
        SourceIrpAllocation {
            owner: SourceIrpOwner::HostedCaller(3),
            ..allocation
        },
        SourceIrpAllocation {
            pool_generation: 2,
            ..allocation
        },
        SourceIrpAllocation {
            component_address: 0x3000,
            ..allocation
        },
        SourceIrpAllocation {
            bytes: allocation.bytes + 8,
            ..allocation
        },
        SourceIrpAllocation {
            stack_count: 3,
            ..allocation
        },
    ];
    for allocation in changed_allocations {
        let changed = SourceIrpForwardIdentity::new(a.ticket(), allocation).unwrap();
        assert!(matches!(
            current.observe_completion(
                device.registration,
                changed,
                CompletionObservation::Acknowledged
            ),
            Err(Error::WrongPacket)
        ));
        assert_eq!(current.snapshot(), before);
    }
    let changed_ticket = SourceIrpForwardIdentity::new(
        SourceIrpTicket::new(a.ticket().domain, 9, 9).unwrap(),
        a.allocation(),
    )
    .unwrap();
    assert!(matches!(
        current.observe_completion(
            device.registration,
            changed_ticket,
            CompletionObservation::Acknowledged
        ),
        Err(Error::WrongPacket)
    ));
    assert_eq!(current.snapshot(), before);
    assert!(drops.borrow().is_empty());
}

#[test]
fn completion_ack_is_one_shot_and_completed_generation_cannot_be_readmitted() {
    let device = DeviceFixture::new();
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(
        device.registration,
        device.registration.domain(),
        owner(1, &drops),
    );
    let a = identity(device.registration, 0x2000, 1);
    current
        .prepare_update(device.registration, 0, Some(packet(a, 2, &drops)))
        .unwrap()
        .commit();
    let returned = current
        .observe_completion(device.registration, a, CompletionObservation::Acknowledged)
        .unwrap()
        .unwrap();
    let before = current.snapshot();
    assert!(matches!(
        current.observe_completion(device.registration, a, CompletionObservation::Acknowledged),
        Err(Error::WrongPhase)
    ));
    assert!(matches!(
        current.observe_completion(device.registration, a, CompletionObservation::Uncertain),
        Err(Error::WrongPhase)
    ));
    let stale = packet(a, 3, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &stale),
        Err(Error::WrongPacket)
    );
    let refusal = match current.prepare_update(device.registration, 0x2000, Some(stale)) {
        Err(refusal) => refusal,
        Ok(_) => panic!("completed lifetime must not be republished"),
    };
    assert_eq!(refusal.error, Error::WrongPacket);
    assert_eq!(refusal.incoming.as_ref().unwrap().identity(), a);
    assert_eq!(current.snapshot(), before);
    assert!(drops.borrow().is_empty());
    drop(returned);
    drop(refusal);
    assert_eq!(&*drops.borrow(), &[2, 3]);
}

#[test]
fn preparation_abort_and_refusal_preserve_incoming_and_current_owners() {
    let device = DeviceFixture::new();
    let foreign = DeviceFixture::new();
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(
        device.registration,
        device.registration.domain(),
        owner(1, &drops),
    );
    let a = identity(device.registration, 0x2000, 1);
    current
        .prepare_update(device.registration, 0, Some(packet(a, 2, &drops)))
        .unwrap()
        .commit();
    let before = current.snapshot();
    let incoming = packet(identity(device.registration, 0x3000, 2), 3, &drops);
    let pending = current
        .prepare_update(device.registration, 0x2000, Some(incoming))
        .unwrap();
    let incoming = pending.abort().unwrap();
    assert_eq!(current.snapshot(), before);
    assert!(drops.borrow().is_empty());
    let refusal = match current.prepare_update(foreign.registration, 0x2000, Some(incoming)) {
        Err(refusal) => refusal,
        Ok(_) => panic!("foreign device must refuse"),
    };
    assert_eq!(refusal.error, Error::WrongDevice);
    let incoming = refusal.incoming.unwrap();
    let refusal = match current.prepare_update(device.registration, 0x4000, Some(incoming)) {
        Err(refusal) => refusal,
        Ok(_) => panic!("raw current mismatch must refuse"),
    };
    assert_eq!(refusal.error, Error::WrongCurrent);
    assert_eq!(
        refusal
            .incoming
            .as_ref()
            .unwrap()
            .identity()
            .allocation()
            .component_address,
        0x3000
    );
    assert_eq!(current.snapshot(), before);
    assert!(drops.borrow().is_empty());
}

#[test]
fn successful_next_replacement_returns_displaced_live_owner_not_fake_completion() {
    let device = DeviceFixture::new();
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(
        device.registration,
        device.registration.domain(),
        owner(1, &drops),
    );
    let a = identity(device.registration, 0x2000, 1);
    let b = identity(device.registration, 0x3000, 2);
    current
        .prepare_update(device.registration, 0, Some(packet(a, 2, &drops)))
        .unwrap()
        .commit();
    // Native performs the already-prevalidated actual start_next commit before settling this edit.
    let displaced = current
        .prepare_update(device.registration, 0x2000, Some(packet(b, 3, &drops)))
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(displaced.identity(), a);
    assert_eq!(current.snapshot().packet, Some(b));
    assert_eq!(current.snapshot().phase, CurrentPhase::Live);
    assert!(
        drops.borrow().is_empty(),
        "displaced live ownership must transfer, not drop"
    );
    assert!(matches!(
        current.observe_completion(device.registration, a, CompletionObservation::Acknowledged),
        Err(Error::WrongPacket)
    ));
    let displaced_b = current
        .prepare_update(device.registration, 0x3000, None)
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(displaced_b.identity(), b);
    assert_eq!(current.snapshot().phase, CurrentPhase::Empty);
    assert!(drops.borrow().is_empty());
    drop(displaced.into_owner());
    drop(displaced_b.into_owner());
    assert_eq!(&*drops.borrow(), &[2, 3]);
}

#[test]
fn duplicate_live_update_returns_incoming_owner_without_changing_current() {
    let device = DeviceFixture::new();
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(
        device.registration,
        device.registration.domain(),
        owner(1, &drops),
    );
    let a = identity(device.registration, 0x2000, 1);
    current
        .prepare_update(device.registration, 0, Some(packet(a, 2, &drops)))
        .unwrap()
        .commit();
    let before = current.snapshot();
    let refusal =
        match current.prepare_update(device.registration, 0x2000, Some(packet(a, 3, &drops))) {
            Err(refusal) => refusal,
            Ok(_) => panic!("duplicate live publication must refuse"),
        };
    assert_eq!(refusal.error, Error::DuplicateCurrent);
    assert_eq!(refusal.incoming.as_ref().unwrap().identity(), a);
    assert_eq!(current.snapshot(), before);
    assert!(drops.borrow().is_empty());
}

#[test]
fn completed_clear_keeps_device_projection_owner_until_receipt_retirement() {
    let device = DeviceFixture::new();
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(
        device.registration,
        device.registration.domain(),
        owner(1, &drops),
    );
    let a = identity(device.registration, 0x2000, 1);
    current
        .prepare_update(device.registration, 0, Some(packet(a, 2, &drops)))
        .unwrap()
        .commit();
    let completed = current
        .observe_completion(device.registration, a, CompletionObservation::Acknowledged)
        .unwrap()
        .unwrap();
    drop(completed);
    assert!(current
        .prepare_update(device.registration, 0x2000, None)
        .unwrap()
        .commit()
        .is_none());
    assert_eq!(current.snapshot().phase, CurrentPhase::Empty);
    assert_eq!(current.snapshot().packet, None);
    assert_eq!(&*drops.borrow(), &[2]);
    drop(current);
    assert_eq!(&*drops.borrow(), &[2, 1]);
}

#[test]
fn distinct_projection_and_authenticated_packet_domains_are_independent() {
    let mut device = DeviceFixture::new();
    let physical = device._io.register_hosted_domain();
    assert_ne!(physical, device.registration.domain());
    let drops = Rc::new(RefCell::new(Vec::new()));
    let mut current = CurrentReceipt::new(device.registration, physical, owner(1, &drops));
    let a = identity_in_domain(physical, 0x2000, 1);
    let incoming = packet(a, 2, &drops);
    assert_eq!(
        current.classify(device.registration, 0, &incoming),
        Ok(CurrentPacketRelation::Empty)
    );
    assert!(current
        .prepare_update(device.registration, 0, Some(incoming))
        .unwrap()
        .commit()
        .is_none());
    let before = current.snapshot();
    let wrong = packet(identity(device.registration, 0x3000, 2), 3, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &wrong),
        Err(Error::WrongPacket)
    );
    let refusal = match current.prepare_update(device.registration, 0x2000, Some(wrong)) {
        Err(refusal) => refusal,
        Ok(_) => panic!("projection domain cannot substitute for physical packet authority"),
    };
    assert_eq!(refusal.error, Error::WrongPacket);
    assert!(refusal.incoming.is_some());
    assert_eq!(current.snapshot(), before);
    let completed = current
        .observe_completion(device.registration, a, CompletionObservation::Acknowledged)
        .unwrap()
        .unwrap();
    let reused = packet(identity_in_domain(physical, 0x2000, 2), 4, &drops);
    assert_eq!(
        current.classify(device.registration, 0x2000, &reused),
        Ok(CurrentPacketRelation::Completed)
    );
    assert!(drops.borrow().is_empty());
    assert_eq!(completed.identity(), a);
}

#[test]
fn one_source_ticket_cannot_describe_contradictory_allocations_live_or_completed() {
    for completed in [false, true] {
        let device = DeviceFixture::new();
        let drops = Rc::new(RefCell::new(Vec::new()));
        let mut current = CurrentReceipt::new(
            device.registration,
            device.registration.domain(),
            owner(1, &drops),
        );
        let a = identity(device.registration, 0x2000, 1);
        current
            .prepare_update(device.registration, 0, Some(packet(a, 2, &drops)))
            .unwrap()
            .commit();
        let _terminal_owner = if completed {
            current
                .observe_completion(device.registration, a, CompletionObservation::Acknowledged)
                .unwrap()
        } else {
            None
        };
        let before = current.snapshot();
        for allocation in [
            SourceIrpAllocation {
                component_address: 0x3000,
                ..a.allocation()
            },
            SourceIrpAllocation {
                component_address: 0x3000,
                pool_generation: 2,
                ..a.allocation()
            },
            SourceIrpAllocation {
                bytes: 0x130,
                ..a.allocation()
            },
        ] {
            let contradictory = SourceIrpForwardIdentity::new(a.ticket(), allocation).unwrap();
            let incoming = packet(contradictory, 3, &drops);
            assert_eq!(
                current.classify(device.registration, 0x2000, &incoming),
                Err(Error::WrongPacket)
            );
            let refusal = match current.prepare_update(device.registration, 0x2000, Some(incoming))
            {
                Err(refusal) => refusal,
                Ok(_) => panic!("same ticket cannot establish a different source allocation"),
            };
            assert_eq!(refusal.error, Error::WrongPacket);
            assert_eq!(refusal.incoming.as_ref().unwrap().identity(), contradictory);
            assert_eq!(current.snapshot(), before);
            assert!(drops.borrow().is_empty());
            drop(refusal);
            drops.borrow_mut().clear();
        }
    }
}
