//! Decide whether an assigned device needs a retained per-binding MMIO receipt at StartDevice.

use super::*;

pub(super) fn assigned_memory_requires_receipt(resources: &[SharedAddressResource]) -> bool {
    resources
        .iter()
        .any(|resource| resource.kind == SH_RESOURCE_ADDRESS_KIND_MEMORY)
}
