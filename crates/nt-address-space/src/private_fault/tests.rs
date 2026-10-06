use super::*;
use crate::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, PAGE_SIZE,
    STATUS_NOT_COMMITTED,
};

fn committed_private() -> VmBasicInformation {
    VmBasicInformation {
        base_address: 0x10_000,
        allocation_base: 0x10_000,
        allocation_protect: PAGE_READWRITE,
        region_size: PAGE_SIZE * 4,
        state: MEM_COMMIT,
        protect: PAGE_READWRITE,
        type_: MEM_PRIVATE,
    }
}

fn plan(
    info: VmBasicInformation,
    backing: PrivateFaultBacking<u64>,
) -> Result<PrivateReadFaultPlan<u64>, u32> {
    plan_private_read_fault(
        0x11_000,
        info,
        FaultAccess::Read,
        ImageFaultObservation::NotPresent,
        backing,
    )
}

#[test]
fn committed_private_demand_zero_requires_explicit_available_source() {
    let PrivateReadFaultPlan::DemandZero(page) =
        plan(committed_private(), PrivateFaultBacking::DemandZero).unwrap()
    else {
        panic!("new committed private backing must use demand zero");
    };
    assert_eq!(page.page, 0x11_000);
    assert_eq!(page.access, FaultAccess::Read);
    assert_eq!(page.source, VmResidencySource::Private);
    assert_eq!(page.map_protection, PAGE_READWRITE);
    assert_eq!(
        plan(committed_private(), PrivateFaultBacking::Unavailable),
        Err(STATUS_ACCESS_VIOLATION)
    );
}

#[test]
fn resident_private_backing_is_preserved_not_reclassified_as_zero() {
    let original_backing = 0x1234_5678;
    let PrivateReadFaultPlan::Revalidate { page, backing } = plan(
        committed_private(),
        PrivateFaultBacking::Resident(original_backing),
    )
    .unwrap() else {
        panic!("resident private contents must never be initialized again");
    };
    assert_eq!(backing, original_backing);
    assert_eq!(page.page, 0x11_000);
    assert_eq!(page.protection, PAGE_READWRITE);
}

#[test]
fn private_read_fault_rejects_guard_noaccess_and_copy_on_write() {
    for protect in [
        PAGE_NOACCESS,
        PAGE_EXECUTE,
        PAGE_READWRITE | PAGE_GUARD,
        PAGE_READONLY | PAGE_GUARD,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_WRITECOPY,
    ] {
        for backing in [
            PrivateFaultBacking::DemandZero,
            PrivateFaultBacking::Resident(17),
        ] {
            assert_eq!(
                plan(
                    VmBasicInformation {
                        protect,
                        ..committed_private()
                    },
                    backing
                ),
                Err(STATUS_ACCESS_VIOLATION),
                "protection 0x{protect:x} needs its own transaction"
            );
        }
    }
}

#[test]
fn private_read_fault_preserves_valid_read_protection_and_modifiers() {
    for protect in [
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_EXECUTE_READ,
        PAGE_READWRITE | PAGE_NOCACHE,
    ] {
        let PrivateReadFaultPlan::DemandZero(page) = plan(
            VmBasicInformation {
                protect,
                ..committed_private()
            },
            PrivateFaultBacking::DemandZero,
        )
        .unwrap() else {
            panic!("valid committed private read");
        };
        assert_eq!(page.map_protection, protect);
    }
}

#[test]
fn private_read_fault_rejects_uncommitted_and_other_mapping_sources() {
    for state in [MEM_RESERVE, MEM_FREE] {
        assert_eq!(
            plan(
                VmBasicInformation {
                    state,
                    ..committed_private()
                },
                PrivateFaultBacking::DemandZero
            ),
            Err(STATUS_NOT_COMMITTED)
        );
    }
    for type_ in [MEM_IMAGE, MEM_MAPPED, 0] {
        assert_eq!(
            plan(
                VmBasicInformation {
                    type_,
                    ..committed_private()
                },
                PrivateFaultBacking::DemandZero
            ),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
}

#[test]
fn private_read_fault_rejects_nonread_and_nonpresent_provenance() {
    for access in [FaultAccess::Write, FaultAccess::Execute, FaultAccess::Lock] {
        assert_eq!(
            plan_private_read_fault::<u64>(
                0x11_000,
                committed_private(),
                access,
                ImageFaultObservation::NotPresent,
                PrivateFaultBacking::DemandZero,
            ),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
    for observation in [
        ImageFaultObservation::Protection,
        ImageFaultObservation::CopyAccess,
    ] {
        assert_eq!(
            plan_private_read_fault::<u64>(
                0x11_000,
                committed_private(),
                FaultAccess::Read,
                observation,
                PrivateFaultBacking::Resident(17),
            ),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
    assert_eq!(
        ImageFaultObservation::from_x86_error(4),
        ImageFaultObservation::NotPresent
    );
    for error in [5, 12, 13] {
        assert_eq!(
            plan_private_read_fault::<u64>(
                0x11_000,
                committed_private(),
                FaultAccess::Read,
                ImageFaultObservation::from_x86_error(error),
                PrivateFaultBacking::DemandZero,
            ),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
}

#[test]
fn private_read_fault_rejects_unaligned_outside_or_overflowing_region() {
    for page in [0x11_001, 0x0f_000, 0x14_000] {
        assert_eq!(
            plan_private_read_fault::<u64>(
                page,
                committed_private(),
                FaultAccess::Read,
                ImageFaultObservation::NotPresent,
                PrivateFaultBacking::DemandZero,
            ),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
    for info in [
        VmBasicInformation {
            region_size: 0,
            ..committed_private()
        },
        VmBasicInformation {
            base_address: 0x10_001,
            ..committed_private()
        },
        VmBasicInformation {
            region_size: u64::MAX,
            ..committed_private()
        },
    ] {
        assert_eq!(
            plan(info, PrivateFaultBacking::DemandZero),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
}
