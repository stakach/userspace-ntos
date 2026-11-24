//! Decide whether an assigned device needs a retained per-binding MMIO receipt at StartDevice.

use super::*;

pub(super) fn assigned_memory_requires_receipt(resources: &[SharedAddressResource]) -> bool {
    resources
        .iter()
        .any(|resource| resource.kind == SH_RESOURCE_ADDRESS_KIND_MEMORY)
}

/// Check exact per-call evidence for this PnP binding before StartDevice publication.
/// The caller supplies assigned resource IDs and resource-manager mapping identity for live maps.
pub(super) fn validate_receipts(
    resources: &[SharedAddressResource],
    ledger: Option<&nt_hosted_runtime::MmioRequestLedger>,
    owner: nt_hosted_runtime::MmioRequestOwner,
    mut mapping_info: impl FnMut(u64) -> Option<(u64, u64, u64)>,
    mut resource_id_for_index: impl FnMut(u8) -> Option<u64>,
) -> Result<(), nt_status::NtStatus> {
    let mut has_use = false;
    if let Some(ledger) = ledger {
        for resource in resources
            .iter()
            .filter(|r| r.kind == SH_RESOURCE_ADDRESS_KIND_MEMORY)
        {
            if let Some(resource_id) = resource_id_for_index(resource.resource_index) {
                has_use |= ledger.has_completed_assigned_use(owner, resource_id);
            }
        }
        for (request, va, backing, phase) in ledger.owner_rows(owner) {
            let Some(nt_hosted_runtime::MmioRequestBacking::Assigned {
                resource_id,
                mapping_id,
            }) = backing
            else {
                return Err(nt_status::NtStatus::DEVICE_BUSY);
            };
            if phase != nt_hosted_runtime::MmioRequestPhase::Ready
                || va.is_none()
                || !resources.iter().any(|resource| {
                    resource.kind == SH_RESOURCE_ADDRESS_KIND_MEMORY
                        && resource_id_for_index(resource.resource_index) == Some(resource_id)
                })
                || mapping_info(mapping_id)
                    != Some((resource_id, request.physical_start, request.length))
            {
                return Err(nt_status::NtStatus::DEVICE_BUSY);
            }
            has_use = true;
        }
    }
    if assigned_memory_requires_receipt(resources) && !has_use {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    Ok(())
}
