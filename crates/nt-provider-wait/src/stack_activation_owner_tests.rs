use super::*;
use crate::{LaneHandle, ProviderWaitSharedPage, SuspensionCaller, SuspensionHostedClient};

const PROVIDER: ProviderDomainIdentity = ProviderDomainIdentity {
    domain: 7,
    generation: 3,
};

fn owner(index: u32, epoch: u64) -> ProviderWaitOwner {
    ProviderWaitOwner {
        provider_domain: PROVIDER.domain,
        provider_generation: PROVIDER.generation,
        dispatch_id: epoch,
        caller: SuspensionCaller::Kernel {
            lane: LaneHandle {
                index,
                generation: 19,
            },
        },
    }
}

fn descriptor(index: u32, epoch: u64) -> KernelProviderActivationDescriptor {
    KernelProviderActivationDescriptor::new(owner(index, epoch)).unwrap()
}

fn fixture() -> (ProviderStackActivationCatalog, ProviderStackLaneHandle) {
    let mut catalog = ProviderStackActivationCatalog::new(3, 4).unwrap();
    let lane = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
    (catalog, lane)
}

#[test]
fn descriptor_layout_and_kernel_only_shape_are_exact() {
    assert_eq!(
        core::mem::size_of::<KernelProviderActivationDescriptor>(),
        64
    );
    assert_eq!(
        core::mem::align_of::<KernelProviderActivationDescriptor>(),
        8
    );
    assert_eq!(
        core::mem::offset_of!(KernelProviderActivationDescriptor, provider_domain),
        8
    );
    assert_eq!(
        core::mem::offset_of!(KernelProviderActivationDescriptor, lane_index),
        24
    );
    assert_eq!(
        core::mem::offset_of!(KernelProviderActivationDescriptor, lane_generation),
        32
    );
    assert_eq!(
        core::mem::offset_of!(KernelProviderActivationDescriptor, dispatch_epoch),
        40
    );
    assert_eq!(
        core::mem::offset_of!(KernelProviderActivationDescriptor, reserved),
        48
    );
    assert_eq!(descriptor(0, 12).validate(PROVIDER), Ok(owner(0, 12)));
    let mut hosted = owner(0, 12);
    hosted.caller = SuspensionCaller::Hosted(SuspensionHostedClient {
        client_pi: 0,
        client_generation: 1,
        client_tid: 2,
        client_badge: 3,
    });
    assert_eq!(
        KernelProviderActivationDescriptor::new(hosted),
        Err(KernelProviderActivationError::NotKernel)
    );
    assert_eq!(
        ProviderWaitSharedPage::empty().kernel_activation,
        KernelProviderActivationDescriptor::EMPTY
    );
}

#[test]
fn malformed_or_foreign_handoff_never_binds_or_changes_irql() {
    let (mut catalog, lane) = fixture();
    let outer = catalog.begin(lane, 1).unwrap();
    catalog.raise_irql(outer, 2).unwrap();
    let valid = descriptor(50, 20);
    let mut cases = Vec::new();
    let mut invalid = valid;
    invalid.magic ^= 1;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.version += 1;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.size -= 1;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.reserved0 = 1;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.reserved[0] = 1;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.reserved[1] = 1;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.provider_domain = 0;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.provider_generation = 0;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.provider_domain += 1;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.provider_generation += 1;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.lane_generation = 0;
    cases.push(invalid);
    let mut invalid = valid;
    invalid.dispatch_epoch = 0;
    cases.push(invalid);
    for invalid in cases {
        assert!(matches!(
            catalog.begin_kernel_for_stack_pointer(0x1800, PROVIDER, invalid),
            Err(ProviderStackActivationError::InvalidKernelDescriptor(_))
        ));
        assert_eq!(catalog.active(lane), Ok(outer));
        assert_eq!(catalog.owner(outer), Ok(None));
        assert_eq!(catalog.current_irql(outer), Ok(2));
    }
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x3000, PROVIDER, valid),
        Err(ProviderStackActivationError::AddressOutsideLane)
    );
    catalog.lower_irql(outer, 0).unwrap();
    catalog.finish(outer).unwrap();
    let kernel = catalog
        .begin_kernel_for_stack_pointer(0x1800, PROVIDER, valid)
        .unwrap();
    assert_eq!(catalog.owner(kernel), Ok(Some(owner(50, 20))));
}

#[test]
fn nested_unbound_activation_cannot_inherit_outer_owner_and_restores_outer_irql() {
    let (mut catalog, lane) = fixture();
    let outer = catalog
        .begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 20))
        .unwrap();
    assert_eq!(outer.dispatch_id, 20);
    assert_eq!(outer.lane_id, 1);
    catalog.raise_irql(outer, 1).unwrap();
    let inner = catalog.begin(lane, 99).unwrap();
    assert_eq!(catalog.owner(inner), Ok(None));
    assert_eq!(catalog.current_irql(inner), Ok(0));
    assert_eq!(
        catalog.owner(outer),
        Err(ProviderStackActivationError::NotTop)
    );
    catalog.finish(inner).unwrap();
    assert_eq!(catalog.owner(outer), Ok(Some(owner(50, 20))));
    assert_eq!(catalog.current_irql(outer), Ok(1));
    catalog.lower_irql(outer, 0).unwrap();
    catalog.finish(outer).unwrap();
    assert_eq!(
        catalog.owner(outer),
        Err(ProviderStackActivationError::NotTop)
    );
}

#[test]
fn epochs_are_nonreplayable_and_live_root_dispatch_cannot_be_overlapped() {
    let (mut catalog, lane) = fixture();
    let first = catalog
        .begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 20))
        .unwrap();
    for epoch in [19, 20] {
        assert_eq!(
            catalog.begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, epoch)),
            Err(ProviderStackActivationError::StaleKernelDispatch)
        );
    }
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 21)),
        Err(ProviderStackActivationError::KernelDispatchActive)
    );
    catalog.finish(first).unwrap();
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 20)),
        Err(ProviderStackActivationError::StaleKernelDispatch)
    );
    let next = catalog
        .begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 21))
        .unwrap();
    assert_eq!(catalog.owner(next), Ok(Some(owner(50, 21))));
    catalog.finish(next).unwrap();
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(51, 22)),
        Err(ProviderStackActivationError::KernelBindingMismatch)
    );
    let mut changed_generation = descriptor(50, 22);
    changed_generation.lane_generation += 1;
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x1800, PROVIDER, changed_generation),
        Err(ProviderStackActivationError::KernelBindingMismatch)
    );
    assert_eq!(
        catalog.active(lane),
        Err(ProviderStackActivationError::NoActiveActivation)
    );
}

#[test]
fn independent_root_lanes_are_distinct_from_local_ordinals() {
    let (mut catalog, first) = fixture();
    let second = catalog.register_lane(2, 0x3000, 0x1000).unwrap();
    let outer = catalog
        .begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 20))
        .unwrap();
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x3800, PROVIDER, descriptor(50, 20)),
        Err(ProviderStackActivationError::KernelLaneAlreadyBound)
    );
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x3800, PROVIDER, descriptor(50, 21)),
        Err(ProviderStackActivationError::KernelLaneAlreadyBound)
    );
    let other_provider = ProviderDomainIdentity {
        domain: 8,
        generation: 4,
    };
    let mut foreign = descriptor(50, 21);
    foreign.provider_domain = other_provider.domain;
    foreign.provider_generation = other_provider.generation;
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x3800, other_provider, foreign),
        Err(ProviderStackActivationError::KernelLaneAlreadyBound)
    );
    let sibling = catalog
        .begin_kernel_for_stack_pointer(0x3800, PROVIDER, descriptor(60, 21))
        .unwrap();
    catalog.raise_irql(sibling, 2).unwrap();
    catalog.finish(outer).unwrap();
    assert_eq!(catalog.owner(sibling), Ok(Some(owner(60, 21))));
    assert_eq!(catalog.current_irql(sibling), Ok(2));
    catalog.lower_irql(sibling, 0).unwrap();
    catalog.finish(sibling).unwrap();
    catalog.unregister_lane(first).unwrap();
    let fresh = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
    assert_ne!(first, fresh);
    let new = catalog
        .begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(70, 22))
        .unwrap();
    assert_eq!(
        catalog.owner(outer),
        Err(ProviderStackActivationError::StaleLane)
    );
    assert_eq!(catalog.owner(new), Ok(Some(owner(70, 22))));
    assert_eq!(
        catalog.active(second),
        Err(ProviderStackActivationError::NoActiveActivation)
    );
}

#[test]
fn capacity_failure_does_not_bind_a_lane_or_burn_its_epoch_fence() {
    let mut catalog = ProviderStackActivationCatalog::new(1, 1).unwrap();
    let lane = catalog.register_lane(1, 0x1000, 0x1000).unwrap();
    let unbound = catalog.begin(lane, 99).unwrap();
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 20)),
        Err(ProviderStackActivationError::NoCapacity)
    );
    assert_eq!(catalog.owner(unbound), Ok(None));
    catalog.finish(unbound).unwrap();
    let first = catalog
        .begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 20))
        .unwrap();
    catalog.finish(first).unwrap();
    let unbound = catalog.begin(lane, 100).unwrap();
    assert_eq!(
        catalog.begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 21)),
        Err(ProviderStackActivationError::NoCapacity)
    );
    catalog.finish(unbound).unwrap();
    let next = catalog
        .begin_kernel_for_stack_pointer(0x1800, PROVIDER, descriptor(50, 21))
        .unwrap();
    assert_eq!(catalog.owner(next), Ok(Some(owner(50, 21))));
}
