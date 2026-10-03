//! Win32k-owned DEVICE_RELATIONS allocation and transfer.

use super::*;

#[must_use = "transfer the relation to the caller or abort its exact allocation"]
pub(crate) struct SourceRelationAllocationLease {
    buffer: Option<PinnedSystemBuffer>,
}

impl SourceRelationAllocationLease {
    pub(crate) fn address(&self) -> u64 {
        self.buffer.as_ref().unwrap().address
    }

    pub(crate) fn catalog_snapshot(&self) -> ProviderAllocationSnapshot {
        self.buffer.as_ref().unwrap().snapshot
    }

    pub(crate) fn native_identity(&self) -> shared_pool::AllocationIdentity {
        self.buffer.as_ref().unwrap().native
    }

    pub(crate) unsafe fn validate(&self) -> bool {
        self.buffer.as_ref().is_some_and(|buffer| system_buffer_live(buffer))
    }

    pub(crate) unsafe fn with_bytes<R>(
        &self,
        f: impl FnOnce(&mut [u8]) -> R,
    ) -> Option<R> {
        if !self.validate() {
            return None;
        }
        Some(f(core::slice::from_raw_parts_mut(
            self.address() as *mut u8,
            nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES,
        )))
    }

    /// The destination allocation and its eventual PDO reference become caller-owned.
    pub(crate) unsafe fn transfer_to_caller(&mut self) -> bool {
        let Some(buffer) = self.buffer.as_ref() else { return false };
        if !system_buffer_live(buffer) {
            return false;
        }
        let address = buffer.address;
        let buffer = self.buffer.take().unwrap();
        if !release_system_buffer(buffer) {
            crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 37]);
        }
        true
    }

    pub(crate) unsafe fn abort(&mut self) -> bool {
        let Some(buffer) = self.buffer.as_ref() else { return false };
        if !system_buffer_live(buffer) {
            return false;
        }
        let address = buffer.address;
        let buffer = self.buffer.take().unwrap();
        if !release_system_buffer(buffer) || !provider_pool_free(address) {
            crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 38]);
        }
        true
    }
}

pub(crate) unsafe fn allocate_target_relation() -> Option<SourceRelationAllocationLease> {
    let address = pool_alloc(nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES as u64);
    if address == 0 {
        return None;
    }
    let Some(buffer) = pin_system_buffer(
        address,
        nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES as u64,
    ) else {
        if !provider_pool_free(address) {
            crate::provider_bugcheck::report(0xc4, [0x57495250, address, 0, 39]);
        }
        return None;
    };
    Some(SourceRelationAllocationLease { buffer: Some(buffer) })
}
