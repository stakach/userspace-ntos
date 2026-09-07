//! Virtual-memory protection changes without forcing committed pages into the working set.

use super::*;

struct ProtectionTarget {
    pi: usize,
    pml4: u64,
    mapping_type: u32,
}

impl ProtectionTarget {
    unsafe fn remap(&self, page: u64, old: u32, new: u32) -> Result<(), u32> {
        let record = csrss_frame_get_exact_record(self.pi as u64, page);
        let owned = record.is_some_and(|record| record.owns_frame);
        let effective = |protection| {
            nt_address_space::resident_backing_protection(self.mapping_type, protection, owned)
        };
        if self.mapping_type == nt_address_space::MEM_IMAGE {
            vm_reprotect_resident_image_page(
                self.pi,
                page,
                effective(old),
                effective(new),
                self.pml4,
            )
        } else if record.is_some() {
            vm_reprotect_private_page(self.pi, page, effective(old), effective(new), self.pml4)
        } else {
            Ok(())
        }
    }

    unsafe fn prepare_and_apply(
        &self,
        base: u64,
        size: u64,
        new_protection: u32,
        old_protection: impl Fn(u64) -> Result<u32, u32>,
    ) -> Result<Option<nt_memory_manager::PagefileProtectionPlan>, u32> {
        hosted_thread_memory_access(self.pi as u64, base, size)?;
        let transition = (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).prepare_protection_range(
            self.pi as u64,
            base,
            size,
            nt_address_space::private_backing_protection(new_protection),
        )?;
        nt_address_space::protection::apply_protection_range(
            base,
            size,
            new_protection,
            old_protection,
            |page, old, new| self.remap(page, old, new),
        )
        .map_err(|failure| {
            assert!(
                failure.rollback_status.is_none(),
                "failed to restore resident protection after a rejected range change"
            );
            failure.status
        })?;
        Ok(transition)
    }
}

unsafe fn commit_transition_protection(plan: Option<nt_memory_manager::PagefileProtectionPlan>) {
    if let Some(plan) = plan {
        (&mut *core::ptr::addr_of_mut!(PROCESS_PAGEFILE))
            .commit_protection(plan)
            .expect("serialized protection publication retains its prepared transition generation");
    }
}

impl ExecNtHandler {
    pub(crate) unsafe fn nt_protect_virtual_memory_with_user_memory(
        &mut self,
        args: &[u64],
        memory: SyscallUserMemory,
    ) -> u32 {
        const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const HIGHEST_USER_ADDRESS: u64 = 0x0000_07ff_fffe_ffff;
        let base_ptr = args[1];
        let size_ptr = args[2];
        let new_protection = nt_ulong_arg(args[3]);
        let oldprot_ptr = args[4];
        if let Err(status) = nt_address_space::validate_protect_parameters(new_protection) {
            return status;
        }
        let output = nt_address_space::native_output::VmRangeOutput {
            base_pointer: base_ptr,
            size_pointer: size_ptr,
        };
        let (base, size) =
            match self.capture_vm_range(memory, base_ptr, size_ptr, Some(oldprot_ptr)) {
                Ok(range) => range,
                Err(status) => return status,
            };
        if base > HIGHEST_USER_ADDRESS {
            return nt_address_space::STATUS_INVALID_PARAMETER_2;
        }
        if HIGHEST_USER_ADDRESS - base < size || size == 0 {
            return STATUS_INVALID_PARAMETER_3;
        }

        let (target_pid, target_pi) =
            match self.resolve_process_for_access(args[0], PROCESS_VM_OPERATION) {
                Ok(target) => target,
                Err(status) => return status,
            };
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            return nt_process::STATUS_PROCESS_IS_TERMINATING;
        }
        let Some(ctx) = self.loop_ctx else {
            return nt_process::STATUS_INVALID_HANDLE;
        };
        let Some(target) = (&*ctx.procs).get(target_pi).copied() else {
            return nt_process::STATUS_INVALID_HANDLE;
        };
        if target.pml4 == 0 || target.scratch_base == 0 {
            return nt_process::STATUS_INVALID_HANDLE;
        }
        if process_committed_mapping_basic_information(target_pi as u64, base).is_some() {
            let before_committed = &mut *core::ptr::addr_of_mut!(COMMITTED_MAP_BEFORE);
            let after_committed = &mut *core::ptr::addr_of_mut!(COMMITTED_MAP_AFTER);
            let Some(snapshot) = process_committed_mapping_snapshot(target_pi as u64) else {
                return nt_process::STATUS_INVALID_HANDLE;
            };
            *before_committed = snapshot;
            *after_committed = *before_committed;
            let plan = match after_committed.protect(base, size, new_protection) {
                Ok(plan) => plan,
                Err(status) => return status,
            };
            if let Err(status) = hosted_thread_memory_access(target_pi as u64, plan.base, plan.size) {
                return status;
            }
            let new_protection = plan.new_protection;
            let first = before_committed
                .query_basic(plan.base)
                .expect("validated protection range retains its first page");
            let old_protection = virtual_memory_query::native_page_protection(target_pi, first);
            if !self.secured_virtual_memory.permits_protection(
                u64::from(target_pid),
                plan.base,
                plan.size,
                new_protection,
            ) {
                return nt_address_space::STATUS_INVALID_PAGE_PROTECTION;
            }
            let before_commit = before_committed.process_commit_bytes_with_private_pages(
                process_private_backing_pages(target_pi as u64),
            );
            let after_commit = after_committed.process_commit_bytes_with_private_pages(
                process_private_backing_pages(target_pi as u64),
            );
            let added_commit = after_commit.saturating_sub(before_commit);
            let released_commit = before_commit.saturating_sub(after_commit);
            let prepared_commit =
                match self.prepare_process_commit_charge(target_pid, target_pi, added_commit) {
                    Ok(prepared) => prepared,
                    Err(status) => return status,
                };
            if released_commit != 0 {
                if let Err(status) = self.ensure_process_commit_owner(target_pid, target_pi) {
                    self.drain_job_notifications();
                    return status;
                }
            }
            let mapping_type = first.type_;
            let transition = match (ProtectionTarget {
                pi: target_pi,
                pml4: target.pml4,
                mapping_type,
            })
            .prepare_and_apply(plan.base, plan.size, new_protection, |page| {
                before_committed
                    .query_basic(page)
                    .map(|info| info.protect)
                    .ok_or(nt_address_space::STATUS_NOT_COMMITTED)
            }) {
                Ok(transition) => transition,
                Err(status) => return status,
            };
            assert!(
                process_committed_mapping_replace(target_pi as u64, *after_committed),
                "validated process mapping table remains present through protection publication"
            );
            commit_transition_protection(transition);
            self.commit_process_commit_charge(prepared_commit);
            self.release_process_commit(target_pid, released_commit);
            loader_trace_record(
                self.pi,
                LoaderOp::ProtectVirtualMemory,
                0,
                None,
                plan.base,
                plan.size,
                b"",
            );
            // Output faults do not undo the protection change or replace its successful status.
            let _ = self.publish_vm_range(
                memory,
                output,
                plan.base,
                plan.size,
                Some((oldprot_ptr, old_protection)),
            );
            return 0;
        }
        let Some(vm_map) = process_vm_region_map_mut(target_pi) else {
            return nt_process::STATUS_INVALID_HANDLE;
        };
        let before = &mut *core::ptr::addr_of_mut!(VM_MAP_BEFORE);
        let after = &mut *core::ptr::addr_of_mut!(VM_MAP_AFTER);
        *before = *vm_map;
        *after = *before;
        let plan = match after.protect(base, size, new_protection) {
            Ok(plan) => plan,
            Err(status) => return status,
        };
        if let Err(status) = hosted_thread_memory_access(target_pi as u64, plan.base, plan.size) {
            return status;
        }
        if !self.secured_virtual_memory.permits_protection(
            u64::from(target_pid),
            plan.base,
            plan.size,
            new_protection,
        ) {
            return nt_address_space::STATUS_INVALID_PAGE_PROTECTION;
        }
        crate::note_high_water(&crate::VM_REGION_HW, after.extent_count() as u64);
        crate::note_high_water(
            &crate::VM_PROTECTION_OVERRIDE_HW,
            after.protection_override_count() as u64,
        );
        let transition = match (ProtectionTarget {
            pi: target_pi,
            pml4: target.pml4,
            mapping_type: nt_address_space::MEM_PRIVATE,
        })
        .prepare_and_apply(plan.base, plan.size, new_protection, |page| {
            before
                .protection_at(page)
                .ok_or(nt_address_space::STATUS_NOT_COMMITTED)
        }) {
            Ok(transition) => transition,
            Err(status) => return status,
        };
        *vm_map = *after;
        commit_transition_protection(transition);
        let registry_slot = self.loop_ctx.and_then(|ctx| {
            (&*ctx.reg)
                .dll_for_page(target_pi, plan.base)
                .map(|(slot, _)| slot)
        });
        loader_trace_record(
            self.pi,
            LoaderOp::ProtectVirtualMemory,
            0,
            registry_slot,
            plan.base,
            plan.size,
            b"",
        );
        let _ = self.publish_vm_range(
            memory,
            output,
            plan.base,
            plan.size,
            Some((oldprot_ptr, plan.old_protection)),
        );
        0
    }
}
