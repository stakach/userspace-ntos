//! StartDevice must accept an exact assigned MMIO use that the driver finished before returning.
//! Run the production publication policy against the real per-call ledger, with the resource
//! manager represented only by its exact mapping identity query.

use nt_hosted_runtime::{
    MmioRequest, MmioRequestAuthority, MmioRequestBacking, MmioRequestLedger, MmioRequestOwner,
    MmioRequestPhase,
};
use nt_pnp_context::{ContextLeaseIdentity, ContextRegistry};
use nt_status::NtStatus;

const SH_RESOURCE_ADDRESS_KIND_MEMORY: u8 = 1;
const PHYS: u64 = 0x7fb7_d0e8;
const LEN: u64 = 36;
const VA: u64 = 0x7000_00e8;
const RESOURCE_ID: u64 = 61;
const MAPPING_ID: u64 = 101;

struct SharedAddressResource {
    kind: u8,
    resource_index: u8,
}

#[path = "../../../components/ntos-executive/src/hosted_mmio_publication_policy.rs"]
mod hosted_mmio_publication_policy;

fn lease() -> ContextLeaseIdentity {
    let mut registry = ContextRegistry::new();
    registry.publish((), ()).unwrap();
    registry.acquire_active().unwrap().identity()
}

fn owner(
    domain_cookie: u64,
    device_id: u64,
    context_lease: ContextLeaseIdentity,
) -> MmioRequestOwner {
    MmioRequestOwner {
        domain_id: 7,
        domain_cookie,
        authority: MmioRequestAuthority::Pnp {
            device_id,
            context_lease,
        },
    }
}

fn request(owner: MmioRequestOwner, physical_start: u64) -> MmioRequest {
    MmioRequest {
        owner,
        physical_start,
        length: LEN,
        cache: 0,
    }
}

fn mapped(ledger: &mut MmioRequestLedger, owner: MmioRequestOwner, physical_start: u64, va: u64) {
    let receipt = ledger.prepare(request(owner, physical_start)).unwrap();
    ledger
        .complete(
            receipt,
            va,
            MmioRequestBacking::Assigned {
                resource_id: RESOURCE_ID,
                mapping_id: MAPPING_ID,
            },
        )
        .unwrap();
}

fn publication(
    ledger: Option<&MmioRequestLedger>,
    owner: MmioRequestOwner,
    mapping_info: impl FnMut(u64) -> Option<(u64, u64, u64)>,
) -> Result<(), NtStatus> {
    publication_for_resources(
        &[SharedAddressResource {
            kind: SH_RESOURCE_ADDRESS_KIND_MEMORY,
            resource_index: 0,
        }],
        ledger,
        owner,
        mapping_info,
    )
}

fn publication_for_resources(
    resources: &[SharedAddressResource],
    ledger: Option<&MmioRequestLedger>,
    owner: MmioRequestOwner,
    mapping_info: impl FnMut(u64) -> Option<(u64, u64, u64)>,
) -> Result<(), NtStatus> {
    hosted_mmio_publication_policy::validate_receipts(
        resources,
        ledger,
        owner,
        mapping_info,
        |index| (index < 2).then_some(RESOURCE_ID + u64::from(index)),
    )
}

#[test]
fn exact_map_and_acknowledged_unmap_still_prove_startdevice_use() {
    let owner = owner(11, 23, lease());
    let mut ledger = MmioRequestLedger::new();
    assert_eq!(
        publication(Some(&ledger), owner, |_| None),
        Err(NtStatus::DEVICE_BUSY),
        "an assigned descriptor without any per-call use cannot publish"
    );

    mapped(&mut ledger, owner, PHYS, VA);
    assert_eq!(
        publication(Some(&ledger), owner, |mapping_id| {
            (mapping_id == MAPPING_ID).then_some((RESOURCE_ID, PHYS, LEN))
        }),
        Ok(()),
        "the exact live mapping is sufficient"
    );

    let (receipt, backing) = ledger.begin_unmap(owner, VA, LEN).unwrap();
    assert_eq!(
        backing,
        MmioRequestBacking::Assigned {
            resource_id: RESOURCE_ID,
            mapping_id: MAPPING_ID,
        }
    );
    ledger.acknowledge_unmap(receipt).unwrap();
    assert_eq!(
        ledger.live_count(),
        0,
        "unmap must retire the live resource-manager mapping"
    );
    assert_eq!(
        ledger.phase(receipt),
        Some(MmioRequestPhase::CompletedUse),
        "the completed-use evidence retains this exact call receipt"
    );
    assert!(
        ledger.begin_unmap(owner, VA, LEN).is_err(),
        "publication evidence cannot authorize a replayed unmap"
    );

    assert_eq!(
        publication(Some(&ledger), owner, |_| None),
        Ok(()),
        "this exact owner completed a real assigned map and unmap before StartDevice returned"
    );

    ledger.retire_completed_pnp_owner(MmioRequestOwner {
        domain_cookie: 12,
        ..owner
    });
    assert_eq!(
        ledger.phase(receipt),
        Some(MmioRequestPhase::CompletedUse),
        "a stale generation cannot retire this owner's publication proof"
    );
    ledger.retire_completed_pnp_owner(owner);
    assert_eq!(
        ledger.phase(receipt),
        None,
        "the exact device retirement releases completed-use evidence"
    );
    assert_eq!(
        publication(Some(&ledger), owner, |_| None),
        Err(NtStatus::DEVICE_BUSY)
    );
}

#[test]
fn foreign_stale_and_uncertain_requests_cannot_supply_completed_use() {
    let context = lease();
    let binding_owner = owner(11, 23, context);
    let mut ledger = MmioRequestLedger::new();
    mapped(&mut ledger, binding_owner, PHYS, VA);
    let (receipt, _) = ledger.begin_unmap(binding_owner, VA, LEN).unwrap();
    ledger.acknowledge_unmap(receipt).unwrap();

    for foreign in [
        owner(12, 23, context),
        owner(11, 24, context),
        owner(11, 23, lease()),
    ] {
        assert_eq!(
            publication(Some(&ledger), foreign, |_| None),
            Err(NtStatus::DEVICE_BUSY),
            "another generation, device, or context authority cannot borrow the completed use"
        );
    }

    let pending = ledger
        .prepare(request(binding_owner, PHYS + 0x1000))
        .unwrap();
    ledger.mark_map_uncertain(pending).unwrap();
    assert_eq!(
        publication(Some(&ledger), binding_owner, |_| None),
        Err(NtStatus::DEVICE_BUSY),
        "a completed use cannot hide a later uncertain native map effect"
    );
    assert!(
        ledger
            .prepare(request(binding_owner, PHYS + 0x1000))
            .is_err(),
        "the uncertain request must remain owned and fence replay"
    );

    let mut unmap_uncertain = MmioRequestLedger::new();
    mapped(&mut unmap_uncertain, binding_owner, PHYS, VA);
    let (receipt, _) = unmap_uncertain.begin_unmap(binding_owner, VA, LEN).unwrap();
    unmap_uncertain.mark_unmap_uncertain(receipt).unwrap();
    assert_eq!(
        publication(Some(&unmap_uncertain), binding_owner, |_| None),
        Err(NtStatus::DEVICE_BUSY)
    );
    assert!(
        unmap_uncertain.begin_unmap(binding_owner, VA, LEN).is_err(),
        "an uncertain unmap cannot be replayed to manufacture completed use"
    );
}

#[test]
fn duplicate_calls_keep_distinct_evidence_and_other_resources_do_not_satisfy_publication() {
    let owner = owner(11, 23, lease());
    let resources = [
        SharedAddressResource {
            kind: SH_RESOURCE_ADDRESS_KIND_MEMORY,
            resource_index: 0,
        },
        SharedAddressResource {
            kind: SH_RESOURCE_ADDRESS_KIND_MEMORY,
            resource_index: 1,
        },
    ];
    let mut ledger = MmioRequestLedger::new();
    let first = ledger.prepare(request(owner, PHYS)).unwrap();
    ledger
        .complete(
            first,
            VA,
            MmioRequestBacking::Assigned {
                resource_id: RESOURCE_ID,
                mapping_id: 101,
            },
        )
        .unwrap();
    let second = ledger.prepare(request(owner, PHYS)).unwrap();
    ledger
        .complete(
            second,
            VA,
            MmioRequestBacking::Assigned {
                resource_id: RESOURCE_ID,
                mapping_id: 102,
            },
        )
        .unwrap();
    let (selected, backing) = ledger.begin_unmap(owner, VA, LEN).unwrap();
    assert_eq!(selected, second);
    assert_eq!(
        backing,
        MmioRequestBacking::Assigned {
            resource_id: RESOURCE_ID,
            mapping_id: 102,
        }
    );
    ledger.acknowledge_unmap(selected).unwrap();
    assert_eq!(ledger.phase(first), Some(MmioRequestPhase::Ready));
    assert_eq!(ledger.phase(second), Some(MmioRequestPhase::CompletedUse));
    assert_eq!(
        publication_for_resources(&resources, Some(&ledger), owner, |id| {
            (id == 101).then_some((RESOURCE_ID, PHYS, LEN))
        }),
        Ok(())
    );
    let (selected, _) = ledger.begin_unmap(owner, VA, LEN).unwrap();
    assert_eq!(selected, first);
    ledger.acknowledge_unmap(selected).unwrap();
    assert_eq!(ledger.live_count(), 0);
    assert_eq!(
        publication_for_resources(&resources, Some(&ledger), owner, |_| None),
        Ok(())
    );
    assert_eq!(
        publication_for_resources(&resources[1..], Some(&ledger), owner, |_| None),
        Err(NtStatus::DEVICE_BUSY),
        "completed use of resource 0 cannot prove a different resource assignment"
    );

    let unrelated = ledger.prepare(request(owner, PHYS + 0x2000)).unwrap();
    ledger
        .complete(
            unrelated,
            VA + 0x2000,
            MmioRequestBacking::Assigned {
                resource_id: 63,
                mapping_id: 103,
            },
        )
        .unwrap();
    assert_eq!(
        publication_for_resources(&resources, Some(&ledger), owner, |id| {
            (id == 103).then_some((63, PHYS + 0x2000, LEN))
        }),
        Err(NtStatus::DEVICE_BUSY),
        "a live map of an unassigned resource must block even with valid completed evidence"
    );
}
