//! Native virtual-memory copies through the same backing owners as user page faults.

use super::*;
use nt_address_space::copy::{
    copy_page_plan, copy_virtual_memory, probe_write_range, probe_write_u64, CopyPagePlan,
    VirtualMemoryCopy, WriteProbeMemory, STATUS_GUARD_PAGE_VIOLATION,
};
use nt_address_space::{FaultAccess, PAGE_SIZE};

struct ProcessMemoryCopy<'a> {
    handler: &'a mut ExecNtHandler,
    source_pi: usize,
    destination_pi: usize,
}

struct ProcessWriteProbe<'a> {
    handler: &'a mut ExecNtHandler,
    pi: usize,
}

impl WriteProbeMemory for ProcessWriteProbe<'_> {
    fn read_byte(&mut self, address: u64) -> Result<u8, u32> {
        let mut byte = [0];
        unsafe {
            self.handler.copy_read_page(self.pi, address, &mut byte)?;
        }
        Ok(byte[0])
    }

    fn write_byte(&mut self, address: u64, value: u8) -> Result<(), u32> {
        unsafe { self.handler.copy_write_page(self.pi, address, &[value]) }
    }
}

impl VirtualMemoryCopy for ProcessMemoryCopy<'_> {
    fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), u32> {
        unsafe { self.handler.copy_read_page(self.source_pi, address, output) }
    }

    fn probe_write(&mut self, address: u64, length: u64) -> Result<(), u32> {
        unsafe {
            self.handler
                .probe_copy_output(self.destination_pi, address, length)
        }
    }

    fn write(&mut self, address: u64, input: &[u8]) -> Result<(), u32> {
        unsafe {
            self.handler
                .copy_write_page(self.destination_pi, address, input)
        }
    }
}

impl ExecNtHandler {
    unsafe fn prepare_copy_page(
        &mut self,
        pi: usize,
        address: u64,
        access: FaultAccess,
    ) -> Result<(), u32> {
        let page = address & !(PAGE_SIZE - 1);
        let info = self.query_memory_basic_information(pi, page)?;
        let plan = copy_page_plan(page, info, access, pi != self.pi).map_err(|status| {
            if status == nt_address_space::STATUS_NOT_COMMITTED {
                STATUS_ACCESS_VIOLATION
            } else {
                status
            }
        })?;
        match plan {
            CopyPagePlan::Resident(plan) => self.ensure_residency_page(pi, plan),
            CopyPagePlan::ConsumeGuard(plan) => {
                self.consume_copy_guard(pi, info, plan)?;
                Err(STATUS_GUARD_PAGE_VIOLATION)
            }
        }
    }

    unsafe fn consume_copy_guard(
        &mut self,
        pi: usize,
        old: nt_address_space::VmBasicInformation,
        plan: nt_address_space::VmResidencyPagePlan,
    ) -> Result<(), u32> {
        let ctx = self.loop_ctx.ok_or(STATUS_INVALID_HANDLE)?;
        let target = (&*ctx.procs)
            .get(pi)
            .copied()
            .filter(|target| target.pml4 != 0 && target.scratch_base != 0)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let page = plan.page;
        let pagefile = &mut *core::ptr::addr_of_mut!(PROCESS_PAGEFILE);
        // Transition records own private frames, including already-promoted write-copy pages.
        // Use current metadata rather than retaining protection from an earlier trim.
        let transition_protection = nt_address_space::private_backing_protection(plan.protection);
        let transition = pagefile.prepare_protection(pi as u64, page, transition_protection)?;

        if process_committed_mapping_basic_information(pi as u64, page).is_some() {
            let before = &mut *core::ptr::addr_of_mut!(COMMITTED_MAP_BEFORE);
            let after = &mut *core::ptr::addr_of_mut!(COMMITTED_MAP_AFTER);
            *before = process_committed_mapping_snapshot(pi as u64).ok_or(STATUS_INVALID_HANDLE)?;
            *after = *before;
            after.protect(page, PAGE_SIZE, plan.protection)?;
            let mut new = old;
            new.protect = plan.protection;
            let old_rights = committed_mapping_effective_page_protection(old);
            let new_rights = committed_mapping_effective_page_protection(new);
            if old.type_ == nt_address_space::MEM_IMAGE {
                vm_reprotect_resident_image_page(
                    pi,
                    page,
                    old_rights,
                    new_rights,
                    target.pml4,
                    target.scratch_base,
                )?;
            } else if csrss_frame_get_exact(pi as u64, page).0 != 0 {
                vm_reprotect_private_page(pi, page, old_rights, new_rights, target.pml4)?;
            }
            assert!(
                process_committed_mapping_replace(pi as u64, *after),
                "guard consumption retains its committed mapping owner"
            );
        } else {
            let map = process_vm_region_map_mut(pi).ok_or(STATUS_INVALID_HANDLE)?;
            let after = &mut *core::ptr::addr_of_mut!(VM_MAP_AFTER);
            *after = *map;
            after.protect(page, PAGE_SIZE, plan.protection)?;
            if csrss_frame_get_exact(pi as u64, page).0 != 0 {
                vm_reprotect_private_page(pi, page, old.protect, plan.protection, target.pml4)?;
            }
            *map = *after;
        }
        if let Some(transition) = transition {
            pagefile
                .commit_protection(transition)
                .expect("serialized guard consumption retains its prepared transition generation");
        }
        Ok(())
    }

    unsafe fn probe_copy_output(
        &mut self,
        pi: usize,
        address: u64,
        length: u64,
    ) -> Result<(), u32> {
        address
            .checked_add(length)
            .filter(|end| *end <= USER_ADDRESS_LIMIT)
            .ok_or(STATUS_ACCESS_VIOLATION)?;
        probe_write_range(
            &mut ProcessWriteProbe { handler: self, pi },
            address,
            length,
        )
    }

    unsafe fn probe_copy_count(&mut self, address: u64) -> Result<(), u32> {
        address
            .checked_add(8)
            .filter(|end| *end <= USER_ADDRESS_LIMIT)
            .ok_or(STATUS_ACCESS_VIOLATION)?;
        let pi = self.pi;
        probe_write_u64(&mut ProcessWriteProbe { handler: self, pi }, address)
    }

    unsafe fn copy_read_page(
        &mut self,
        pi: usize,
        address: u64,
        output: &mut [u8],
    ) -> Result<(), u32> {
        if output.is_empty() {
            return Ok(());
        }
        if output.len() as u64 > PAGE_SIZE - address % PAGE_SIZE {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        self.prepare_copy_page(pi, address, FaultAccess::Read)?;
        if address & !(PAGE_SIZE - 1) == KUSER_VA {
            let alias = kuser_page_alias_get(pi);
            if alias == 0 {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            core::ptr::copy_nonoverlapping(
                (alias + address % PAGE_SIZE) as *const u8,
                output.as_mut_ptr(),
                output.len(),
            );
            return Ok(());
        }
        // Residency may change counters or retire COW aliases. Resolve them only afterwards.
        let ctx = self.loop_ctx.ok_or(STATUS_INVALID_HANDLE)?;
        let target = (&*ctx.procs).get(pi).ok_or(STATUS_INVALID_HANDLE)?;
        let (filled, faults) = if pi == self.pi {
            (&*ctx.filled_pages, *ctx.faults as usize)
        } else {
            (&(*ctx.pfilled)[pi], target.faults as usize)
        };
        if client_copyin_process_mapped(
            pi as u64,
            address,
            output,
            filled,
            faults,
            target.scratch_base,
            false,
        ) {
            Ok(())
        } else {
            Err(STATUS_ACCESS_VIOLATION)
        }
    }

    unsafe fn copy_write_page(&mut self, pi: usize, address: u64, input: &[u8]) -> Result<(), u32> {
        if input.is_empty() {
            return Ok(());
        }
        if input.len() as u64 > PAGE_SIZE - address % PAGE_SIZE {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        self.prepare_copy_page(pi, address, FaultAccess::Write)?;
        let ctx = self.loop_ctx.ok_or(STATUS_INVALID_HANDLE)?;
        let target = (&*ctx.procs).get(pi).ok_or(STATUS_INVALID_HANDLE)?;
        let (filled, faults) = if pi == self.pi {
            (&*ctx.filled_pages, *ctx.faults as usize)
        } else {
            (&(*ctx.pfilled)[pi], target.faults as usize)
        };
        if client_copyout_mapped(
            pi as u64,
            address,
            input,
            filled,
            faults,
            target.scratch_base,
        ) {
            Ok(())
        } else {
            Err(STATUS_ACCESS_VIOLATION)
        }
    }

    unsafe fn store_copy_count(&mut self, address: u64, count: u64) {
        if address == 0 {
            return;
        }
        let bytes = count.to_le_bytes();
        let Some(chunks) = nt_address_space::page_chunks(address, bytes.len()) else {
            return;
        };
        let mut offset = 0;
        for chunk in chunks {
            let length = chunk.length;
            if self
                .copy_write_page(
                    self.pi,
                    address + offset as u64,
                    &bytes[offset..offset + length],
                )
                .is_err()
            {
                return;
            }
            offset += length;
        }
    }

    pub(super) unsafe fn nt_copy_virtual_memory(&mut self, args: &[u64], read: bool) -> u32 {
        const PROCESS_VM_READ: u32 = 0x0010;
        const PROCESS_VM_WRITE: u32 = 0x0020;

        let remote = args[1];
        let local = args[2];
        let length = args[3];
        let count_ptr = args[4];
        let valid_range = |base: u64| {
            base.checked_add(length)
                .is_some_and(|end| end <= USER_ADDRESS_LIMIT)
        };
        if !valid_range(remote) || !valid_range(local) {
            return STATUS_ACCESS_VIOLATION;
        }
        if count_ptr != 0 {
            if let Err(status) = self.probe_copy_count(count_ptr) {
                return status;
            }
        }
        if length == 0 {
            self.store_copy_count(count_ptr, 0);
            return 0;
        }
        let required_access = if read {
            PROCESS_VM_READ
        } else {
            PROCESS_VM_WRITE
        };
        let (target_pid, target_pi) =
            match self.resolve_process_for_access(args[0], required_access) {
                Ok(target) => target,
                Err(status) => {
                    self.store_copy_count(count_ptr, 0);
                    return status;
                }
            };
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            self.store_copy_count(count_ptr, 0);
            return nt_process::STATUS_PROCESS_IS_TERMINATING;
        }
        let (source_pi, source, destination_pi, destination) = if read {
            (target_pi, remote, self.pi, local)
        } else {
            (self.pi, local, target_pi, remote)
        };
        let result = copy_virtual_memory(
            &mut ProcessMemoryCopy {
                handler: self,
                source_pi,
                destination_pi,
            },
            source,
            destination,
            length,
        );
        self.store_copy_count(count_ptr, result.transferred);
        result.status
    }
}
