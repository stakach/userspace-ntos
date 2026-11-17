//! win32k's Mm imports acting on the client process it is attached to.
//!
//! `ZwAllocateVirtualMemory`/`ZwFreeVirtualMemory(NtCurrentProcess())` from win32k run the same
//! private-VAD effect as the native system calls against that client, so the bits returned by
//! `EngAllocUserMem` and the GDI attribute pools are the client's own committed memory.
//! `MmSecureVirtualMemory` then validates exactly those VADs.

use super::*;

impl ExecNtHandler {
    pub(crate) unsafe fn service_win32k_allocate_virtual_memory(
        &mut self,
        target_pi: usize,
        base: u64,
        size: u64,
        allocation_type: u32,
        protection: u32,
    ) -> Result<(u64, u64), u32> {
        nt_address_space::validate_allocate_parameters(0, allocation_type, protection)?;
        check_private_allocate_range(base, size)?;
        let pid = self
            .pm_pid_for_pi(target_pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        // win32k runs in kernel mode, where NT does not check SeLockMemoryPrivilege.
        self.allocate_private_virtual_memory(
            pid,
            target_pi,
            base,
            size,
            0,
            allocation_type,
            protection,
            true,
        )
        .map(|(plan, _)| (plan.base, plan.size))
    }

    pub(crate) unsafe fn service_win32k_free_virtual_memory(
        &mut self,
        target_pi: usize,
        base: u64,
        size: u64,
        free_type: u32,
    ) -> Result<(u64, u64), u32> {
        check_free_type(free_type)?;
        check_free_range(base, size)?;
        let pid = self
            .pm_pid_for_pi(target_pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        self.free_private_virtual_memory(pid, target_pi, base, size, free_type)
            .map(|plan| (plan.base, plan.size))
    }

    pub(crate) unsafe fn service_win32k_secure_virtual_memory(
        &mut self,
        target_pi: usize,
        address: u64,
        size: u64,
        protection: u32,
    ) -> Result<u64, u32> {
        let access = nt_address_space::secure_range::secure_access_for_protection(protection)?;
        let pid = self
            .pm_pid_for_pi(target_pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        nt_address_space::secure_range::validate_secure_range(
            address,
            size,
            access,
            USER_ADDRESS_LIMIT,
            |va| self.query_memory_basic_information(target_pi, va),
        )?;
        self.secured_virtual_memory
            .secure(u64::from(pid), address, size, access)
    }

    pub(crate) fn service_win32k_unsecure_virtual_memory(
        &mut self,
        target_pi: usize,
        handle: u64,
    ) -> Result<(), u32> {
        let pid = self
            .pm_pid_for_pi(target_pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        self.secured_virtual_memory
            .unsecure(u64::from(pid), handle)
            .map(|_| ())
    }
}
