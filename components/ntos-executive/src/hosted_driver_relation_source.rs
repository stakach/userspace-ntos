//! Exact native ownership of a hosted driver's DEVICE_RELATIONS allocation.

use super::*;

/// Driver completion transfers this allocation to the IRP caller. Native pool identity is
/// rechecked before each publication step and before the one final free.
pub(super) struct DriverRelationSource {
    inst: DriverInstance,
    pointer: u64,
    generation: u64,
    bytes: [u8; nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES],
}

impl DriverRelationSource {
    pub(super) unsafe fn capture(
        completion_driver: DriverId,
        pointer: u64,
    ) -> Option<Self> {
        let index = hosted_relation_allocation_instance(completion_driver)?;
        let inst = instance(index)?;
        let _guard = hosted_instance_pool_lock(inst.exec_pool_va)?;
        let (mapped, capacity) = hosted_pool_allocation_exec_range(inst.exec_pool_va, pointer)?;
        if capacity < nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES as u64
            || hosted_instance_pool_allocation_is_free_unlocked(inst, pointer) != Some(false)
        {
            return None;
        }
        let generation = read_volatile((mapped - 8) as *const u64);
        if generation == 0 {
            return None;
        }
        let mut bytes = [0; nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES];
        core::ptr::copy_nonoverlapping(mapped as *const u8, bytes.as_mut_ptr(), bytes.len());
        Some(Self { inst, pointer, generation, bytes })
    }

    pub(super) const fn address(&self) -> u64 { self.pointer }
    pub(super) const fn generation(&self) -> u64 { self.generation }
    pub(super) const fn bytes(&self) -> &[u8; nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES] {
        &self.bytes
    }
    pub(super) fn domain(&self) -> Option<HostedDomainIdentity> {
        instance_domain_identity(self.inst)
    }

    pub(super) unsafe fn validate(&self) -> bool {
        let Some(_guard) = hosted_instance_pool_lock(self.inst.exec_pool_va) else { return false };
        let Some((mapped, capacity)) =
            hosted_pool_allocation_exec_range(self.inst.exec_pool_va, self.pointer)
        else { return false };
        capacity >= self.bytes.len() as u64
            && hosted_instance_pool_allocation_is_free_unlocked(self.inst, self.pointer)
                == Some(false)
            && read_volatile((mapped - 8) as *const u64) == self.generation
            && core::slice::from_raw_parts(mapped as *const u8, self.bytes.len())
                == self.bytes.as_slice()
    }

    /// Only after canonical ACK and after transferring the caller's independent PDO reference.
    pub(super) unsafe fn retire(self) -> bool {
        let Some(_guard) = hosted_instance_pool_lock(self.inst.exec_pool_va) else { return false };
        let Some((mapped, capacity)) =
            hosted_pool_allocation_exec_range(self.inst.exec_pool_va, self.pointer)
        else { return false };
        if capacity < self.bytes.len() as u64
            || hosted_instance_pool_allocation_is_free_unlocked(self.inst, self.pointer)
                != Some(false)
            || read_volatile((mapped - 8) as *const u64) != self.generation
        {
            return false;
        }
        hosted_instance_pool_free_unlocked(self.inst, self.pointer)
    }
}
