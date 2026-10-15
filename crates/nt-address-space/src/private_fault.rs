//! Allocation-free private read-fault policy; native backing authority stays with its owner.

use crate::{
    vm_access_page_plan, FaultAccess, ImageFaultObservation, VmBasicInformation,
    VmResidencyPagePlan, VmResidencySource, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_WRITECOPY,
    STATUS_ACCESS_VIOLATION,
};

/// Classify only after querying the exact current backing owners. `DemandZero` is not a
/// fallback for a missing cap: the committed allocation must have no preserved, transitioning,
/// pagefile or uncertain backing. Resident metadata describes backing retained elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateFaultBacking<B: Copy> {
    DemandZero,
    Resident(B),
    /// Includes pagefile restoration, retained transitions and uncertain native ownership.
    Unavailable,
}

/// A policy decision, not capability authority or an acknowledgment that the fault was serviced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateReadFaultPlan<B: Copy> {
    DemandZero(VmResidencyPagePlan),
    Revalidate {
        page: VmResidencyPagePlan,
        backing: B,
    },
}

/// Prepare only ordinary not-present reads. Guard consumption, protection repair, COW and
/// restoration remain separate transactions. The native caller must revalidate process/VAD,
/// backing lifetime and no-eviction admission before using this plan.
pub fn plan_private_read_fault<B: Copy>(
    page: u64,
    info: VmBasicInformation,
    access: FaultAccess,
    observation: ImageFaultObservation,
    backing: PrivateFaultBacking<B>,
) -> Result<PrivateReadFaultPlan<B>, u32> {
    if access != FaultAccess::Read
        || observation != ImageFaultObservation::NotPresent
        || info.protect & PAGE_GUARD != 0
        || matches!(info.protect & 0xff, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)
    {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let page = vm_access_page_plan(page, info, access)?;
    if page.source != VmResidencySource::Private {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    match backing {
        PrivateFaultBacking::DemandZero => Ok(PrivateReadFaultPlan::DemandZero(page)),
        PrivateFaultBacking::Resident(backing) => {
            Ok(PrivateReadFaultPlan::Revalidate { page, backing })
        }
        PrivateFaultBacking::Unavailable => Err(STATUS_ACCESS_VIOLATION),
    }
}

#[cfg(test)]
mod tests;
