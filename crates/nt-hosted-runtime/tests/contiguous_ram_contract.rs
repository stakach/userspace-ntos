use nt_hosted_runtime::{ContiguousRamLayout, ContiguousRamOwner, ContiguousRamReceipt,
    ContiguousRamPrepareTable, ContiguousRamLeaseBank, ContiguousRamLeaseSource};

const PAGE: u64 = 4096;

#[test]
fn softgpu_request_uses_a_separate_64_mib_child_and_checked_aperture() {
    let plan = ContiguousRamLayout::for_request(37_748_736, 0x100_2000_0000, 64 << 20)
        .expect("36 MiB SoftGpu allocation fits a 64 MiB child");
    assert_eq!(plan.frames(), 9_216);
    assert_eq!(plan.batch_count(), 36);
    assert_eq!(plan.batch(35), Some((8_960, 256)));
    assert_eq!(plan.batch(36), None);
    assert_eq!(plan.end(), 0x100_2000_0000 + 9_216 * PAGE);
    assert!(ContiguousRamLayout::for_request(37_748_736, 0x100_5000_0000, 8 << 20).is_none());
}

#[test]
fn small_contiguous_request_fits_a_small_child_after_softgpu_framebuffer() {
    let framebuffer = ContiguousRamLayout::for_request(37_748_736, 0x100_2000_0000, 64 << 20)
        .expect("36 MiB framebuffer needs a 64 MiB child");
    assert_eq!(framebuffer.frames(), 9_216);
    let metadata = ContiguousRamLayout::for_request(64 << 10, 0x100_2400_0000, 64 << 10)
        .expect("64 KiB metadata must not carve another 64 MiB child");
    assert_eq!(metadata.frames(), 16);
    assert_eq!(metadata.child_bytes(), 64 << 10);
    assert_eq!(ContiguousRamLayout::minimum_child_bytes(37_748_736), Some(64 << 20));
    assert_eq!(ContiguousRamLayout::minimum_child_bytes(64 << 10), Some(64 << 10));
    assert_eq!(ContiguousRamLayout::minimum_child_bytes((64 << 10) + 1), Some(128 << 10));
    assert!(ContiguousRamLayout::for_request((64 << 10) + 1, 0x100_2400_0000,
        64 << 10).is_none());
}

#[test]
fn every_frame_address_and_nt_range_must_match_before_publication() {
    let plan = ContiguousRamLayout::for_request(3 * PAGE, 0x100_2000_0000, 64 << 20).unwrap();
    let owner = ContiguousRamOwner { instance: 7, generation: 19, domain: 23 };
    let mut receipt = ContiguousRamReceipt::new(owner, plan, 0x9000).unwrap();
    assert!(receipt.record_frame(owner, 0, 0x9001, 0x20_0000).is_ok());
    assert!(receipt.record_frame(owner, 1, 0x9002, 0x20_2000).is_err());
    assert!(receipt.record_frame(owner, 1, 0x9002, 0x20_1000).is_ok());
    assert!(receipt.record_frame(owner, 2, 0x9003, 0x20_2000).is_ok());
    for index in 0..3 {
        receipt.begin_map(owner, index).unwrap();
        receipt.record_map_result(owner, index, Ok(())).unwrap();
    }
    assert!(receipt.publish(owner, 0x20_0000, 0x20_2fff, 0).is_ok());
    assert!(receipt.publish(ContiguousRamOwner { generation: 20, ..owner }, 0, u64::MAX, 0).is_err());
}

#[test]
fn uncertain_map_cannot_release_caps_or_reuse_aperture() {
    let plan = ContiguousRamLayout::for_request(PAGE, 0x100_2000_0000, 64 << 20).unwrap();
    let owner = ContiguousRamOwner { instance: 7, generation: 19, domain: 23 };
    let mut receipt = ContiguousRamReceipt::new(owner, plan, 0x9000).unwrap();
    receipt.record_frame(owner, 0, 0x9001, 0x20_0000).unwrap();
    receipt.begin_map(owner, 0).unwrap();
    assert!(!receipt.can_release(owner));
    assert!(receipt.record_map_result(owner, 0, Err(())).is_err());
    assert!(!receipt.can_release(owner));
}

#[test]
fn prepare_ticket_is_exact_single_use_and_expires_without_native_effects() {
    let owner = ContiguousRamOwner { instance: 7, generation: 19, domain: 23 };
    let stale = ContiguousRamOwner { generation: 20, ..owner };
    let mut table = ContiguousRamPrepareTable::new();
    let ticket = table.prepare(owner, 0x444, 37_748_736, 0, 0xffff_ffff).unwrap();
    assert!(table.commit(stale, 0x444, ticket, 0, 1).is_err());
    assert!(table.commit(owner, 0x445, ticket, 0, 1).is_err());
    assert!(table.commit(owner, 0x444, ticket + 1, 0, 1).is_err());
    let request = table.commit(owner, 0x444, ticket, 0, 1).unwrap();
    assert_eq!((request.length, request.low, request.high, request.boundary, request.cache),
        (37_748_736, 0, 0xffff_ffff, 0, 1));
    assert!(table.commit(owner, 0x444, ticket, 0, 1).is_err());
    let obsolete = table.prepare(owner, 0x444, PAGE, 0, u64::MAX).unwrap();
    table.expire(owner, 0x444, obsolete).unwrap();
    assert!(table.commit(owner, 0x444, obsolete, 0, 1).is_err());
    let replacement = table.prepare(owner, 0x444, 2 * PAGE, PAGE, 3 * PAGE - 1).unwrap();
    assert_ne!(replacement, obsolete);
    assert!(table.commit(owner, 0x444, obsolete, 0, 1).is_err());
    let replacement_request = table.commit(owner, 0x444, replacement, 0, 1).unwrap();
    assert_eq!(replacement_request.length, 2 * PAGE);
}

#[test]
fn definite_prepublication_failures_reuse_one_child_and_cap_run() {
    let mut bank = ContiguousRamLeaseBank::new();
    let owner = ContiguousRamOwner { instance: 7, generation: 19, domain: 23 };
    let next = ContiguousRamOwner { instance: 8, generation: 20, domain: 24 };
    let first = bank.reserve(owner, 16_384).unwrap();
    assert_eq!(first.source, ContiguousRamLeaseSource::Fresh);
    bank.attach_resources(owner, first.slot, 0x9000, 0xa000, 16_384).unwrap();
    for _ in 0..9 {
        bank.confirm_clean(owner, first.slot).unwrap();
        let retry = bank.reserve(owner, 16_384).unwrap();
        assert_eq!(retry.slot, first.slot);
        assert_eq!(retry.source, ContiguousRamLeaseSource::Reuse {
            child: 0x9000, cap_base: 0xa000, capacity_frames: 16_384,
        });
    }
    bank.confirm_clean(owner, first.slot).unwrap();
    let other_domain = bank.reserve(next, 16_384).unwrap();
    assert_eq!(other_domain.slot, first.slot);
    assert_eq!(other_domain.source, ContiguousRamLeaseSource::Reuse {
        child: 0x9000, cap_base: 0xa000, capacity_frames: 16_384,
    });
    assert!(bank.confirm_clean(owner, first.slot).is_err());
    assert_eq!(bank.owned_child_count(), 1);
}

#[test]
fn uncertain_native_effect_quarantines_child_and_aperture() {
    let mut bank = ContiguousRamLeaseBank::new();
    let owner = ContiguousRamOwner { instance: 7, generation: 19, domain: 23 };
    let first = bank.reserve(owner, 16_384).unwrap();
    bank.attach_resources(owner, first.slot, 0x9000, 0xa000, 16_384).unwrap();
    bank.quarantine(owner, first.slot).unwrap();
    assert!(bank.confirm_clean(owner, first.slot).is_err());
    let next = bank.reserve(owner, 16_384).unwrap();
    assert_ne!(next.slot, first.slot);
    assert_eq!(next.source, ContiguousRamLeaseSource::Fresh);
}

#[test]
fn confirmed_child_retype_failures_keep_one_empty_cap_run() {
    let mut bank = ContiguousRamLeaseBank::new();
    let owner = ContiguousRamOwner { instance: 7, generation: 19, domain: 23 };
    let first = bank.reserve(owner, 16_384).unwrap();
    bank.attach_frame_slots(owner, first.slot, 0xa000, 16_384).unwrap();
    for _ in 0..9 {
        bank.confirm_clean(owner, first.slot).unwrap();
        let retry = bank.reserve(owner, 16_384).unwrap();
        assert_eq!(retry.slot, first.slot);
        assert_eq!(retry.source, ContiguousRamLeaseSource::SlotsOnly {
            cap_base: 0xa000, capacity_frames: 16_384,
        });
    }
    bank.attach_resources(owner, first.slot, 0x9000, 0xa000, 16_384).unwrap();
    bank.confirm_clean(owner, first.slot).unwrap();
    let ready = bank.reserve(owner, 16_384).unwrap();
    assert_eq!(ready.source, ContiguousRamLeaseSource::Reuse {
        child: 0x9000, cap_base: 0xa000, capacity_frames: 16_384,
    });
}

#[test]
fn clean_children_are_reused_only_at_their_exact_capacity() {
    let owner = ContiguousRamOwner { instance: 7, generation: 19, domain: 23 };
    let mut bank = ContiguousRamLeaseBank::new();
    let large = bank.reserve(owner, 16_384).unwrap();
    bank.attach_resources(owner, large.slot, 0x9000, 0xa000, 16_384).unwrap();
    bank.confirm_clean(owner, large.slot).unwrap();

    let small = bank.reserve(owner, 16).unwrap();
    assert_ne!(small.slot, large.slot);
    assert_eq!(small.source, ContiguousRamLeaseSource::Fresh);
    assert!(bank.attach_frame_slots(owner, small.slot, 0xc000, 16_384).is_err());
    bank.attach_resources(owner, small.slot, 0xb000, 0xc000, 16).unwrap();
    bank.confirm_clean(owner, small.slot).unwrap();

    let reused_small = bank.reserve(owner, 16).unwrap();
    assert_eq!(reused_small.slot, small.slot);
    assert_eq!(reused_small.source, ContiguousRamLeaseSource::Reuse {
        child: 0xb000, cap_base: 0xc000, capacity_frames: 16,
    });
    bank.confirm_clean(owner, reused_small.slot).unwrap();
    let reused_large = bank.reserve(owner, 16_384).unwrap();
    assert_eq!(reused_large.slot, large.slot);
    assert_eq!(reused_large.source, ContiguousRamLeaseSource::Reuse {
        child: 0x9000, cap_base: 0xa000, capacity_frames: 16_384,
    });
}
