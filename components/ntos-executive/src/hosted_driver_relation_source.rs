//! Exact native ownership of a hosted driver's DEVICE_RELATIONS allocation.

use super::*;

/// Driver completion transfers this allocation to the IRP caller. Native pool identity is
/// rechecked before each publication step and before the one final free.
pub(super) struct DriverRelationSource {
    inst: DriverInstance,
    pointer: u64,
    generation: u64,
    bytes: [u8; nt_pnp_manager::TARGET_DEVICE_RELATIONS_X64_BYTES],
    video_reference: Option<hosted_video_target_relation::SourceReference>,
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
        let video_reference = hosted_video_target_relation::claim(
            completion_driver, index, pointer, generation,
        );
        Some(Self { inst, pointer, generation, bytes, video_reference })
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

    /// Transfer the already-owned VideoPort result, rather than consuming an unrelated projected
    /// caller count. Native driver results without this owner still use their returned caller ref.
    pub(super) unsafe fn take_owned_reference(
        &mut self,
        registration: nt_io_manager::HostedDevicePointerRegistration,
    ) -> Result<Option<nt_io_manager::HostedDevicePointerReference>, nt_status::NtStatus> {
        if !self.validate() || self.domain() != Some(registration.domain())
            || io_manager_mut().hosted_device_pointer_registration(
                registration.domain(), registration.address(),
            ) != Some(registration)
        {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        let objects = nt_pnp_manager::copy_device_relations_x64(&self.bytes)
            .map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
        if objects.as_slice() != [registration.address()]
            || self.video_reference.as_ref().is_some_and(|reference| {
                reference.device_id() != registration.device_id()
            })
        {
            return Err(nt_status::NtStatus::INVALID_PARAMETER);
        }
        Ok(self.video_reference.take().map(|reference| reference.into_reference()))
    }

    /// Only after canonical ACK and after transferring the caller's independent PDO reference.
    pub(super) unsafe fn retire(mut self) -> bool {
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
        if !hosted_instance_pool_free_unlocked(self.inst, self.pointer) {
            return false;
        }
        drop(_guard);
        self.video_reference.take().is_none_or(|reference| reference.release())
    }
}
